"""Follow a whole-root session across its soft-reboots, for the NixOS test driver.

``nails activate``, ``nails deactivate`` and ``nails emergency`` end by
enqueueing ``soft-reboot.target``: PID 1 stops every userspace process (the
driver's backdoor shell included), switches root and starts a fresh userspace,
which starts the backdoor again. The driver's ``wait_for_console_text`` reads
one queued console line per second and a soft-reboot prints a few hundred, so
these helpers poll the driver's full console log instead (appended directly by
its reader thread), fail at once if the new userspace lands in emergency mode or
PID 1 freezes, if the trigger failed without enqueueing the switch or if QEMU
exits, and reconnect when the new backdoor announces itself. This is the
mechanism the soft-reboot spike (now ``soft-reboot-mechanics``) proved. A
switch or a power-off that never ends is reported with what PID 1 waits on and
the SysRq dumps (:mod:`nails_e2e.stall`).
"""

from __future__ import annotations

import re
import shlex
import signal
import time
from collections.abc import Callable
from typing import Any, Protocol, TypedDict

from . import stall

#: Console lines that mean the new userspace will never start the backdoor.
STUCK_MARKERS = (
    "Reached target Emergency Mode",
    "Started Emergency Shell",
    "Reached target Rescue Mode",
    "Freezing execution",
    "Switch root target contains no usable init",
)

#: The new backdoor's announcement on the console.
BACKDOOR_MARKER = "connecting to host"

#: Written to the serial console when the trigger returns, with its exit
#: status and, when that is not 0, the service manager's state.
TRIGGER_EXIT_MARKER = "nails-trigger-exit="

#: The states ``systemctl is-system-running`` reports.
SYSTEM_STATES = frozenset(
    {
        "initializing",
        "starting",
        "running",
        "degraded",
        "maintenance",
        "stopping",
        "offline",
        "unknown",
    }
)

#: The report after the marker: the status, then a space and the state.
_REPORT = re.compile(r"(\d+)(?: ([a-z]+))?")

#: The serial console, the one console the test driver records (the backdoor
#: writes its stderr there). The VM tests boot x86_64 guests only, whose first
#: serial port this is. /dev/console is no substitute: it is the last
#: ``console=`` on the kernel command line, which the NixOS test VMs set to
#: tty0, a screen nothing reads.
SERIAL_CONSOLE = "/dev/ttyS0"

#: Where the hidden root's upper lives with the suite's hidden volume.
DEFAULT_UPPER = "/mnt/data/root/upper"


class Machine(Protocol):
    """The slice of the driver's machine object these helpers use."""

    connected: bool
    full_console_log: list[str]
    process: Any
    qmp_client: Any

    def succeed(self, *commands: str, timeout: int | None = None) -> str: ...

    def execute(
        self,
        command: str,
        check_return: bool = True,
        check_output: bool = True,
        timeout: int | None = 900,
    ) -> tuple[int, str]: ...

    def connect(self) -> None: ...

    def log(self, msg: str) -> None: ...

    def wait_for_unit(
        self, unit: str, user: str | None = None, timeout: int = 900
    ) -> Any: ...

    def wait_for_shutdown(self) -> None: ...

    def get_console_log(self) -> str: ...


class Timings(TypedDict):
    """In-guest timings of one soft-reboot, from PID 1's own timestamps."""

    label: str
    shutdown_phase: float | None
    startup_phase: float | None
    grey_out: float | None
    trigger_to_backdoor: float
    trigger_to_settled: float


class _ReconnectTimeout(Exception):
    pass


def _alarm(_signum: int, _frame: object) -> None:
    raise _ReconnectTimeout()


def guest_uptime(machine: Machine) -> float:
    """The guest's uptime in seconds."""
    return float(machine.succeed("cut -d' ' -f1 /proc/uptime").strip())


def stuck_lines(lines: list[str]) -> list[str]:
    """The console lines that show a userspace that will never come up."""
    return [line for line in lines if any(marker in line for marker in STUCK_MARKERS)]


def trigger_failure(lines: list[str]) -> str | None:
    """Why the trigger will never switch, from the report it left on the console.

    A trigger that exits non-zero while the system is not stopping (an
    activation refused or rolled back) never soft-reboots. A non-zero exit
    with the switch already enqueued is no failure: an activation with
    warnings exits 9, an emergency that left mounts behind 7, and the
    switch's own stop may end a trigger before it returns.

    Only a whole report counts. The kernel writes its own lines to the serial
    port between the pieces of a line that a process sends there, so a report
    can arrive cut in two, its status or its state broken off by a kernel
    line: such a line, like the report's own command line, decides nothing.
    """
    for line in lines:
        _, marker, report = line.partition(TRIGGER_EXIT_MARKER)
        if not marker:
            continue
        report = report.rstrip()
        whole = _REPORT.match(report)
        if whole is None:
            continue
        status, state = whole.group(1), whole.group(2)
        if state is None and whole.end() != len(report):
            continue  # cut off after the status
        if state is not None and state not in SYSTEM_STATES:
            continue  # the state cut short
        if status != "0" and state != "stopping":
            seen = state or "in an unknown state"
            return f"exit status {status} while the system was {seen}"
    return None


def parse_pid1_timestamps(text: str) -> dict[str, float]:
    """``systemctl show`` output of monotonic timestamps, in seconds."""
    values: dict[str, float] = {}
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if value.strip().isdigit():
            values[key] = int(value.strip()) / 1e6
    return values


def follow_soft_reboot(
    machine: Machine,
    trigger: str,
    label: str,
    deadline_s: float = 600.0,
    start: Callable[[], None] | None = None,
) -> Timings:
    """Run ``trigger`` (a shell command that enqueues a soft-reboot) and follow
    the switch until the new userspace's backdoor is connected and settled.

    The trigger runs in the background with its output discarded: the backdoor
    that runs it dies with the old userspace. Callers that need the command's
    output redirect it themselves to a place that survives (the hidden volume)
    or copy it to :data:`SERIAL_CONSOLE`. When the trigger returns, its exit
    status lands on the serial console, and a failure while nothing is
    stopping fails the wait at once (:func:`trigger_failure`), as does a
    machine that powers off or reboots instead, which ends QEMU. ``start``, when
    given, starts the soft-reboot instead (for example typed keystrokes on a
    tty) and ``trigger`` is only logged; a typed command reports its own
    failure the same way.
    """
    trigger_uptime = guest_uptime(machine)
    console_index = len(machine.full_console_log)
    if start is None:
        # The exit status goes to the serial console, with the system's
        # state when it is not 0: a trigger that fails while nothing is
        # stopping never soft-reboots, and the wait below stops at once
        # instead of running out its deadline. The driver runs every command
        # under `set -euo pipefail`. The trigger keeps it; the subshell around
        # it turns errexit off, or a failed trigger would end it before it
        # reports.
        machine.execute(
            f"(set +e; (set -e; {trigger}) </dev/null >/dev/null 2>&1; status=$?; "
            'state=; [ "$status" = 0 ] || '
            "state=$(systemctl is-system-running 2>/dev/null); "
            f'echo "{TRIGGER_EXIT_MARKER}$status $state" > {SERIAL_CONSOLE}) &',
            check_return=False,
            check_output=False,
        )
    else:
        machine.log(f"{label}: starting: {trigger}")
        start()
    machine.connected = False
    deadline = time.monotonic() + deadline_s
    while True:
        lines = machine.full_console_log[console_index:]
        stuck = stuck_lines(lines)
        if stuck:
            causes = [
                line
                for line in lines
                if any(
                    k in line
                    for k in (
                        "Timed out",
                        "timed out",
                        "Dependency failed",
                        "Failed to",
                    )
                )
            ]
            machine.log(f"{label}: causes on the console:\n" + "\n".join(causes[-60:]))
            machine.log(f"{label}: last console lines:\n" + "\n".join(lines[-150:]))
            raise AssertionError(f"{label}: the new userspace is stuck: {stuck[0]}")
        failed = trigger_failure(lines)
        if failed is not None:
            machine.log(f"{label}: last console lines:\n" + "\n".join(lines[-150:]))
            raise AssertionError(
                f"{label}: the trigger failed ({failed}) and never soft-rebooted"
            )
        if any(BACKDOOR_MARKER in line for line in lines):
            break
        # A power-off, a full reboot or a kernel panic instead of the switch
        # ends QEMU (the suite starts every machine with the driver's
        # -no-reboot): no backdoor will come, and the stall report needs a
        # running machine.
        exited = machine.process.poll() if machine.process is not None else None
        if exited is not None:
            machine.log(f"{label}: last console lines:\n" + "\n".join(lines[-150:]))
            machine.wait_for_shutdown()
            raise AssertionError(
                f"{label}: QEMU exited (status {exited}) before the new userspace "
                "came up"
            )
        if time.monotonic() > deadline:
            machine.log(f"{label}: last console lines:\n" + "\n".join(lines[-150:]))
            why = stall.report(machine, label)
            raise AssertionError(
                f"{label}: no backdoor {deadline_s:.0f} s after the soft-reboot ({why})"
            )
        time.sleep(
            0.5
        )  # sync-lint: allow sleep -- polls the console log under the deadline above
    previous = signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(120)
    try:
        machine.connect()
    except _ReconnectTimeout:
        raise AssertionError(
            f"{label}: the backdoor announced itself but never connected"
        ) from None
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    backdoor = guest_uptime(machine)
    machine.wait_for_unit("multi-user.target")
    machine.execute("timeout 300 systemctl is-system-running --wait || true")
    settled = guest_uptime(machine)
    values = parse_pid1_timestamps(
        machine.succeed(
            "systemctl show -p ShutdownStartTimestampMonotonic "
            "-p UserspaceTimestampMonotonic -p FinishTimestampMonotonic"
        )
    )
    shutdown = values.get("ShutdownStartTimestampMonotonic", 0.0)
    userspace = values.get("UserspaceTimestampMonotonic", 0.0)
    finish = values.get("FinishTimestampMonotonic", 0.0)
    timings: Timings = {
        "label": label,
        "shutdown_phase": userspace - shutdown if shutdown and userspace else None,
        "startup_phase": finish - userspace if finish and userspace else None,
        "grey_out": finish - shutdown if finish and shutdown else None,
        "trigger_to_backdoor": backdoor - trigger_uptime,
        "trigger_to_settled": settled - trigger_uptime,
    }
    machine.log(f"TIMING: {timings}")
    return timings


def root_fstype(machine: Machine) -> str:
    """The filesystem type of ``/``."""
    return machine.succeed("findmnt -no FSTYPE /").strip()


def assert_hidden_root(machine: Machine, upper: str = DEFAULT_UPPER) -> None:
    """``/`` is the root overlay with its upper on the hidden volume."""
    options = machine.succeed("findmnt -no FSTYPE,OPTIONS /").strip()
    assert options.startswith("overlay"), f"/ is not an overlay: {options}"
    assert f"upperdir={upper}" in options, f"/ is not the hidden root: {options}"


def leftover_overlays(findmnt_lines: str) -> list[str]:
    """The overlays in ``findmnt -ln -t overlay -o TARGET,OPTIONS`` output that
    are not the VM's own Nix store. The store is an overlay with its upper in
    ``/nix/.rw-store``; the VM's initrd mounts it twice, so it may be stacked.
    The initrd mounts it before the switch to the real root, so the kernel
    may report the layer paths with the initrd's ``/sysroot`` prefix."""
    leftover = []
    for line in findmnt_lines.splitlines():
        target, _, options = line.strip().partition(" ")
        options = options.strip()
        if target == "/nix/store" and (
            "upperdir=/nix/.rw-store/" in options
            or "upperdir=/sysroot/nix/.rw-store/" in options
        ):
            continue
        if line.strip():
            leftover.append(line.strip())
    return leftover


def assert_decoy_root(machine: Machine) -> None:
    """``/`` is the plain decoy root, with no next root, no overlay but the
    VM's store and no mount that reaches into a hidden layer."""
    fstype = root_fstype(machine)
    assert fstype != "overlay", "/ is still an overlay"
    machine.succeed("! grep -q ' /run/nextroot' /proc/self/mountinfo")
    overlays = machine.succeed("findmnt -ln -t overlay -o TARGET,OPTIONS || true")
    leftover = leftover_overlays(overlays)
    assert not leftover, f"overlay mounts left on the decoy: {leftover}"
    # No overlay layered on a hidden upper, no bind the session carried, and
    # nothing in the runtime directory. (A test may mount its own scratch
    # filesystem on the hidden volume; that is not a session leftover.)
    machine.succeed(
        "! grep -qE "
        "'dir=[^ ,]*/root/(upper|work|mounts)|/root/decoy/|/overlay-runtime/' "
        "/proc/self/mountinfo"
    )


def run_entries(machine: Machine) -> set[str]:
    """``/run`` two levels deep, the way the scrub's snapshot sees it."""
    out = machine.succeed(
        "find /run -xdev -mindepth 1 -maxdepth 2 \\( -path /run/udev "
        "-o -path /run/credentials -o -path /run/nextroot \\) -prune -o -print"
    )
    return set(out.splitlines())


def wall_clock(machine: Machine) -> str:
    """The guest's wall clock in seconds since the epoch."""
    return machine.succeed("date +%s").strip()


def carried_run_residue(
    machine: Machine, before: set[str], since_wall: str
) -> list[str]:
    """``/run`` entries two levels deep that were carried over a soft-reboot
    (inode change time before ``since_wall``) but were not there before
    entering: what the hidden session left behind. Sockets are carried by
    design and never listed."""
    carried = set(
        machine.succeed(
            "find /run -xdev -mindepth 1 -maxdepth 2 \\( -path /run/udev "
            "-o -path /run/credentials \\) -prune "
            f"-o ! -type s ! -newerct @{shlex.quote(since_wall)} -print"
        ).splitlines()
    )
    return sorted(carried - before - {"/run/nextroot"})


def backend_open(machine: Machine, name: str = "data") -> bool:
    """Whether the device-mapper device ``name`` exists."""
    rc, _ = machine.execute(f"test -e /dev/mapper/{shlex.quote(name)}")
    return rc == 0


def wait_for_power_off(machine: Machine, timeout: float = 300.0) -> None:
    """Wait, bounded, for the VM to power off after a power-off was enqueued
    (the driver's ``wait_for_shutdown`` has no deadline), then reset the
    driver's state so the machine can be started again."""
    import subprocess

    machine.connected = False
    if machine.process is not None:
        try:
            machine.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            tail = "\n".join(machine.get_console_log().splitlines()[-100:])
            why = stall.report(machine, "power-off")
            raise AssertionError(
                f"the VM did not power off within {timeout:.0f} s ({why})\n{tail}"
            ) from None
    machine.wait_for_shutdown()
