"""End a hidden session on a distribution VM with its power-off, and boot the
same disk again.

A hidden session never goes back to the decoy: ``nails deactivate``, ``nails
emergency`` and the watcher's automatic emergency power the machine off.
nix-vm-test boots its image under QEMU ``-snapshot`` (lib/distro-vm.nix), so a
QEMU that exits takes every guest write with it, and the next start boots the
pristine image again. A scenario that checks the decoy disk after a session,
or runs another session on the same disk, therefore tells QEMU (QMP
``set-action``) to pause on the guest's power-off instead of exiting, as the
oracle images do: the guest powers off as a real machine does, with the
kernel's ``reboot: Power down`` on the console, its disk stays as the
power-off left it, :func:`image_paused_disk` can copy that disk whole, and
:func:`boot_again` boots it cold (``system_reset`` and ``cont``: a fresh
kernel, an empty ``/run``, every mount and the 9p share gone).

:func:`follow_power_off` fails at once when a new userspace's backdoor
announces itself instead (the machine switched or rebooted), when a userspace
is stuck, when the trigger failed without ending anything, when the kernel
rebooted or panicked instead of powering off, and when QEMU exited (the pause
was not set). The pure parts are unit-tested in tests/test_power_off.py.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import time
from collections.abc import Sequence
from typing import Any, Protocol

#: What the kernel prints right before it cuts the power.
POWER_DOWN_MARKER = "reboot: Power down"
#: What the kernel prints right before it resets the machine.
RESTART_MARKER = "reboot: Restarting system"
#: What the kernel prints when it panics.
PANIC_MARKER = "Kernel panic"
#: The new backdoor's announcement on the console.
BACKDOOR_MARKER = "connecting to host"
#: Console lines that mean a new userspace will never start the backdoor.
STUCK_MARKERS = (
    "Reached target Emergency Mode",
    "Started Emergency Shell",
    "Reached target Rescue Mode",
    "Freezing execution",
    "Switch root target contains no usable init",
)
#: Written to the serial console when the trigger returns, with its exit
#: status and, when that is not 0, the service manager's state.
TRIGGER_EXIT_MARKER = "nails-power-off-trigger-exit="
#: How long to wait, once QEMU paused, for the reader thread to hand over the
#: guest's last console lines.
SETTLE_S = 10.0
#: The serial console the driver records (x86_64 guests only).
SERIAL_CONSOLE = "/dev/ttyS0"

_REPORT = re.compile(r"(\d+)(?: ([a-z]+))?$")


class Machine(Protocol):
    """The slice of the driver's machine object these helpers use."""

    connected: bool
    full_console_log: list[str]
    process: Any
    qmp_client: Any

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


def qmp(vm: Machine, command: str, arguments: dict[str, Any] | None = None) -> Any:
    """Send one QMP command and return its result."""
    client = vm.qmp_client
    assert client is not None, "the QMP socket is not connected"
    reply: Any = client.send(command, arguments or {})
    assert "return" in reply, f"QMP {command} failed: {reply}"
    return reply["return"]


def trigger_command(trigger: str) -> str:
    """The shell line that runs ``trigger`` in the background, with its output
    discarded and its exit status (and, when not 0, the system's state) on the
    serial console: the backdoor that runs it dies with the session."""
    return (
        f"(set +e; (set -e; {trigger}) </dev/null >/dev/null 2>&1; status=$?; "
        'state=; [ "$status" = 0 ] || '
        "state=$(systemctl is-system-running 2>/dev/null); "
        f'echo "{TRIGGER_EXIT_MARKER}$status $state" > {SERIAL_CONSOLE}) &'
    )


def trigger_failure(lines: Sequence[str]) -> str | None:
    """Why the trigger will never power off, from its report: a non-zero exit
    while the system is not stopping. A non-zero exit with the system
    stopping is no failure (the power-off's own stop may end the trigger)."""
    for line in lines:
        _, marker, report = line.partition(TRIGGER_EXIT_MARKER)
        if not marker:
            continue
        whole = _REPORT.match(report.strip())
        if whole is None:
            continue  # a report cut by a kernel line decides nothing
        status, state = whole.group(1), whole.group(2)
        if status != "0" and state != "stopping":
            seen = state or "in an unknown state"
            return f"exit status {status} while the system was {seen}"
    return None


def running_problem(lines: Sequence[str]) -> str | None:
    """What, in the console since the trigger, already shows the machine will
    not power off: a new userspace, a stuck one, or a failed trigger."""
    if any(BACKDOOR_MARKER in line for line in lines):
        return "a new userspace came up instead"
    stuck = [line for line in lines if any(m in line for m in STUCK_MARKERS)]
    if stuck:
        return f"a userspace is stuck: {stuck[0]}"
    failed = trigger_failure(lines)
    if failed is not None:
        return f"the trigger failed ({failed}) and never powered off"
    return None


def stopped_problem(lines: Sequence[str]) -> str | None:
    """Once QEMU paused: None when the kernel said it powered off, else what
    it did instead."""
    text = "\n".join(lines)
    if PANIC_MARKER in text:
        return "the kernel panicked"
    if RESTART_MARKER in text:
        return "the machine rebooted"
    if POWER_DOWN_MARKER in text:
        return None
    return "the kernel never said it powered off"


def _tail(lines: Sequence[str]) -> str:
    return "\n".join(lines[-150:])


def follow_power_off(
    vm: Machine,
    trigger: str | None,
    label: str,
    deadline_s: float = 600.0,
    console_index: int | None = None,
) -> None:
    """Run ``trigger`` (a shell command that ends the hidden session) and follow
    the machine until it powered off and QEMU paused, with the disk kept.

    ``trigger=None`` waits for an ending something else starts;
    ``console_index`` then names where in the console log to start looking.
    """
    if console_index is None:
        console_index = len(vm.full_console_log)
    qmp(vm, "set-action", {"shutdown": "pause"})
    if trigger is not None:
        vm.execute(trigger_command(trigger), check_return=False, check_output=False)
    vm.connected = False
    deadline = time.monotonic() + deadline_s
    while True:
        lines = vm.full_console_log[console_index:]
        problem = running_problem(lines)
        if problem is not None:
            vm.log(f"{label}: last console lines:\n{_tail(lines)}")
            raise AssertionError(f"{label}: the machine did not power off: {problem}")
        if vm.process is not None and vm.process.poll() is not None:
            vm.log(f"{label}: last console lines:\n{_tail(lines)}")
            raise AssertionError(
                f"{label}: QEMU exited instead of pausing at the power-off, so the "
                "disk is gone"
            )
        if qmp(vm, "query-status")["status"] == "shutdown":
            break
        if time.monotonic() > deadline:
            vm.log(f"{label}: last console lines:\n{_tail(lines)}")
            raise AssertionError(
                f"{label}: the machine did not power off {deadline_s:.0f} s after "
                "the trigger"
            )
        time.sleep(0.5)
    # The reader thread may still hold the last lines the guest wrote.
    settle = time.monotonic() + SETTLE_S
    while (
        stopped_problem(vm.full_console_log[console_index:]) is not None
        and time.monotonic() < settle
    ):
        time.sleep(0.5)
    lines = vm.full_console_log[console_index:]
    problem = stopped_problem(lines)
    if problem is not None:
        vm.log(f"{label}: last console lines:\n{_tail(lines)}")
        raise AssertionError(
            f"{label}: QEMU stopped, but not from a power-off: {problem}"
        )
    vm.log(f"{label}: the machine powered off")


class _ConnectTimeout(Exception):
    pass


def _alarm(_signum: int, _frame: object) -> None:
    raise _ConnectTimeout()


def boot_again(vm: Machine, label: str, deadline_s: float = 600.0) -> None:
    """Boot the powered-off machine cold from the disk the power-off left, as
    its owner switching it on again does, and reconnect to the new backdoor.
    QEMU exits again on a later power-off."""
    console_index = len(vm.full_console_log)
    qmp(vm, "system_reset")
    reset_deadline = time.monotonic() + 60
    while qmp(vm, "query-status")["status"] == "shutdown":
        assert time.monotonic() < reset_deadline, (
            f"{label}: the reset never left the shutdown state"
        )
        time.sleep(0.5)
    qmp(vm, "set-action", {"shutdown": "poweroff"})
    qmp(vm, "cont")
    deadline = time.monotonic() + deadline_s
    while True:
        lines = vm.full_console_log[console_index:]
        if any(BACKDOOR_MARKER in line for line in lines):
            break
        stuck = [line for line in lines if any(m in line for m in STUCK_MARKERS)]
        if stuck:
            vm.log(f"{label}: last console lines:\n{_tail(lines)}")
            raise AssertionError(f"{label}: the cold boot is stuck: {stuck[0]}")
        if vm.process is not None and vm.process.poll() is not None:
            raise AssertionError(f"{label}: QEMU exited during the cold boot")
        if time.monotonic() > deadline:
            vm.log(f"{label}: last console lines:\n{_tail(lines)}")
            raise AssertionError(
                f"{label}: no backdoor {deadline_s:.0f} s after the reset"
            )
        time.sleep(0.5)
    previous = signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(120)
    try:
        vm.connect()
    except _ConnectTimeout:
        raise AssertionError(
            f"{label}: the backdoor announced itself but never connected"
        ) from None
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    vm.wait_for_unit("multi-user.target")


def root_drive(vm: Machine) -> tuple[str, int]:
    """The root drive's QMP device name and its virtual size."""
    roots = [
        block
        for block in qmp(vm, "query-block")
        if block.get("inserted") and not block.get("removable", False)
    ]
    assert len(roots) == 1, f"cannot identify the root drive: {roots}"
    return roots[0]["device"], int(roots[0]["inserted"]["image"]["virtual-size"])


def image_paused_disk(vm: Machine, target: str, cp: str = "cp") -> str:
    """Copy the disk of the powered-off, paused machine whole into ``target``,
    a raw image made sparse afterwards (``cp`` names coreutils' cp), and
    return ``target``. The guest writes nothing meanwhile: it is off."""
    status = qmp(vm, "query-status")["status"]
    assert status == "shutdown", f"the machine is {status}, not powered off"
    device, size = root_drive(vm)
    full = f"{target}.full"
    with open(full, "wb") as handle:
        handle.truncate(size)
    job = f"power-off-{time.monotonic_ns()}"
    qmp(
        vm,
        "blockdev-add",
        {
            "driver": "raw",
            "node-name": job,
            "file": {"driver": "file", "filename": full},
        },
    )
    qmp(
        vm,
        "blockdev-backup",
        {
            "job-id": job,
            "device": device,
            "target": job,
            "sync": "full",
            "auto-dismiss": False,
        },
    )
    deadline = time.monotonic() + 900
    while True:
        jobs = [entry for entry in qmp(vm, "query-jobs") if entry["id"] == job]
        assert jobs, f"the backup job {job} is gone"
        if jobs[0]["status"] == "concluded":
            break
        assert time.monotonic() < deadline, f"the backup of {device} did not finish"
        time.sleep(1)
    assert "error" not in jobs[0], f"the backup of {device} failed: {jobs[0]}"
    qmp(vm, "job-dismiss", {"id": job})
    qmp(vm, "blockdev-del", {"node-name": job})
    subprocess.run([cp, "--sparse=always", full, target], check=True)
    os.remove(full)
    return target
