"""What a guest that stopped answering waits on, for the NixOS test driver.

When a soft-reboot never brings the backdoor back, or a power-off never ends,
the guest's shell is gone, and only its keyboard and its serial console are
left. :func:`report` uses both, through QMP, in this order:

- The SysRq dumps of the blocked tasks and of every task tell whether PID 1
  is idle or stuck in the kernel. The VMs boot with ``sysrq_always_enabled``.
  They come first, while nothing has touched PID 1 yet.
- Alt+ArrowUp makes PID 1 start ``kbrequest.target``. The suite's VMs
  (``nix/e2e-tests/lib/vm-config.nix``) hang a unit on it that prints PID 1's
  job queue, each job with the jobs it waits for and the jobs it holds up,
  those units, the mount units' order against the local filesystems and the
  unmount, libmount's utab and the mount table to the serial console. Nothing
  of it loads or runs before the key is pressed, so a passing run never sees
  it, and neither unit has default dependencies, so it also runs while a
  startup or a shutdown waits.

A job that waits with no job left to wait for is how a lost ordering shows:
PID 1 never runs it again. A PID 1 that sleeps in ``epoll_wait`` with no task
blocked, and moves on as soon as the key is pressed, missed a wakeup instead:
the key reaches it as SIGWINCH, which wakes its event loop, so the stall ends
there and the job queue shows the switch moving again. The dumps taken before
the key are what show such a stall.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any, Protocol

#: The keys that make PID 1 start kbrequest.target.
REPORT_KEYS = ("alt", "up")
#: The guest's report is written between these two lines.
REPORT_BEGIN = "pid1-jobs-report-begin"
REPORT_END = "pid1-jobs-report-end"
#: How long the report may take to appear.
REPORT_TIMEOUT_S = 30.0
#: The SysRq dumps, in order: the blocked tasks, then every task with its stack.
SYSRQ_DUMPS = ("w", "t")
#: A dump has ended once the console has been quiet this long...
QUIET_S = 3.0
#: ...or after this long.
DUMP_TIMEOUT_S = 60.0

#: A job of ``systemctl list-jobs``: its ID, unit, type and state.
JOB_ROW = re.compile(r"^\s*(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$")


class Machine(Protocol):
    """The slice of the driver's machine object the report uses."""

    full_console_log: list[str]
    qmp_client: Any

    def log(self, msg: str) -> None: ...


def press(machine: Machine, *keys: str) -> None:
    """Press ``keys`` together on the guest's keyboard, through QMP."""
    if machine.qmp_client is None:
        raise RuntimeError("QMP is not connected")
    machine.qmp_client.send(
        "send-key", {"keys": [{"type": "qcode", "data": key} for key in keys]}
    )


def _wait(
    machine: Machine, start: int, done: Callable[[list[str]], bool], timeout: float
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not done(machine.full_console_log[start:]):
        time.sleep(
            0.2
        )  # sync-lint: allow sleep -- polls the console log under the deadline above


def _wait_until_quiet(machine: Machine, quiet: float, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    seen, since = len(machine.full_console_log), time.monotonic()
    while time.monotonic() < deadline:
        now = len(machine.full_console_log)
        if now != seen:
            seen, since = now, time.monotonic()
        elif time.monotonic() - since >= quiet:
            return
        time.sleep(
            0.2
        )  # sync-lint: allow sleep -- polls the console log under the deadline above


def report_lines(lines: list[str]) -> list[str]:
    """The lines of the guest's report among the console ``lines``."""
    begin = next((i for i, line in enumerate(lines) if REPORT_BEGIN in line), None)
    if begin is None:
        return []
    end = next(
        (i for i in range(begin, len(lines)) if REPORT_END in lines[i]), len(lines)
    )
    return lines[begin + 1 : end]


def waiting_for_nothing(lines: list[str]) -> list[str]:
    """The jobs of the report among the console ``lines`` that wait with no
    job to wait for, as ``unit/type``."""
    jobs: list[tuple[str, str, bool]] = []
    for line in report_lines(lines):
        row = JOB_ROW.match(line)
        if row:
            jobs.append((f"{row[2]}/{row[3]}", row[4], False))
        elif jobs and "waiting for job" in line:
            name, state, _ = jobs[-1]
            jobs[-1] = (name, state, True)
    return [name for name, state, waits in jobs if state == "waiting" and not waits]


def report(machine: Machine, label: str) -> str:
    """Make the guest print the SysRq dumps, then what PID 1 waits on, log all
    of it, and return one line for the failure message. The dumps come first,
    since the key press that asks PID 1 for its jobs also wakes it. Never
    raises: the stall it explains matters more than a report that went
    wrong."""
    start = len(machine.full_console_log)
    problems = []
    for key in SYSRQ_DUMPS:
        try:
            press(machine, "alt", "sysrq", key)
            _wait_until_quiet(machine, QUIET_S, DUMP_TIMEOUT_S)
        except Exception as e:  # never hide the stall behind a broken report
            problems.append(f"SysRq {key} failed: {e}")
    try:
        press(machine, *REPORT_KEYS)
        _wait(
            machine,
            start,
            lambda lines: any(REPORT_END in line for line in lines),
            REPORT_TIMEOUT_S,
        )
    except Exception as e:  # as above
        problems.append(f"Alt+ArrowUp failed: {e}")
    lines = machine.full_console_log[start:]
    machine.log(
        f"{label}: what PID 1 waits on, and the SysRq dumps:\n" + "\n".join(lines)
    )
    if not any(REPORT_END in line for line in lines):
        found = "no report of PID 1's jobs"
    else:
        stuck = waiting_for_nothing(lines)
        found = (
            "PID 1 holds jobs that wait for no job: " + ", ".join(stuck)
            if stuck
            else "no job of PID 1 waits for nothing"
        )
    return "; ".join([found, *problems])
