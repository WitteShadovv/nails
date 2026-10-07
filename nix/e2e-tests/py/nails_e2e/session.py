"""Follow a whole-root session across its soft-reboots, for the NixOS test driver.

``nails activate``, ``nails deactivate`` and ``nails emergency`` end by
enqueueing ``soft-reboot.target``: PID 1 stops every userspace process (the
driver's backdoor shell included), switches root and starts a fresh userspace,
which starts the backdoor again. The driver's ``wait_for_console_text`` reads
one queued console line per second and a soft-reboot prints a few hundred, so
these helpers poll the driver's full console log instead (appended directly by
its reader thread), fail at once if the new userspace lands in emergency mode or
PID 1 freezes, and reconnect when the new backdoor announces itself. This is
the mechanism the soft-reboot spike (ADR 0008) proved.
"""

from __future__ import annotations

import shlex
import signal
import time
from collections.abc import Callable
from typing import Any, Protocol, TypedDict

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

#: Written to the console with the trigger's exit status when it returns.
TRIGGER_EXIT_MARKER = "nails-trigger-exit="

#: Where the hidden root's upper lives with the suite's hidden volume.
DEFAULT_UPPER = "/mnt/data/root/upper"


class Machine(Protocol):
    """The slice of the driver's machine object these helpers use."""

    connected: bool
    full_console_log: list[str]
    process: Any

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
    """The trigger's non-zero exit status from the console, if it reported one."""
    for line in lines:
        _, marker, status = line.partition(TRIGGER_EXIT_MARKER)
        status = status.strip()
        if marker and status and status != "0":
            return f"exit status {status}"
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
    output redirect it themselves to a place that survives (the hidden volume).
    ``start``, when given, starts the soft-reboot instead (for example typed
    keystrokes on a tty) and ``trigger`` is only logged.
    """
    trigger_uptime = guest_uptime(machine)
    console_index = len(machine.full_console_log)
    if start is None:
        # The exit status goes to the console: a trigger that fails (an
        # activation refused or rolled back) never soft-reboots, and the wait
        # below stops at once instead of running out its deadline.
        machine.execute(
            f"(({trigger}) </dev/null >/dev/null 2>&1; "
            f'echo "{TRIGGER_EXIT_MARKER}$?" > /dev/console) &',
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
        if time.monotonic() > deadline:
            machine.log(f"{label}: last console lines:\n" + "\n".join(lines[-150:]))
            raise AssertionError(
                f"{label}: no backdoor {deadline_s:.0f} s after the soft-reboot"
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
    machine.succeed(
        "! grep -qE '/root/(upper|work|mounts|decoy)|/overlay-runtime/' "
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
            raise AssertionError(
                f"the VM did not power off within {timeout:.0f} s\n{tail}"
            ) from None
    machine.wait_for_shutdown()
