"""Run one test binary of the in-diff mutation lane so that no mutant outlasts it.

`just mutants-in-diff` makes this module cargo's target runner: cargo runs each
test binary through it and passes the binary and its arguments. A mutant can
turn a loop of the code under test into one that never ends, and two things
then outlast the mutant's test run unless they are stopped here:

- Its memory. Such a loop that pushes to a vector can take gigabytes a
  second, and a runner that runs out of memory is lost with its shard: the
  job ends with "The runner has received a shutdown signal", or with no log at
  all, and the shard's report never uploads. On 29 October 2026 six shards of
  three pull requests were lost so, and each held a mutant whose test binary,
  run again under the cap below, aborted at it, all but one within seven
  seconds. The binary runs here with its data segment capped (RLIMIT_DATA,
  which counts what a process allocates), so the allocation that would pass
  the cap fails, the binary aborts and its tests fail: the mutant is caught.
  The cap holds for each process on its own: the binary and every process it
  starts, such as the nails binary that the nails-cli tests run, may each
  allocate that much. One runaway cannot fill a runner, several at once still
  could.
- The binary. cargo-mutants ends a test run that passes its --timeout with
  SIGTERM to the run's process group. A test binary in which a test installed
  the SIGTERM handler of nails-base's cancel module (the nails-base tests do)
  only sets a flag and runs on, beside the mutants after it, which then build
  and test slower. The binary runs here as the leader of a process group of
  its own, and a SIGTERM, SIGINT or SIGHUP is passed on to that group. The
  group is killed if the binary has not ended GRACE_SECONDS later. Once the
  binary has ended, whatever ended it (a signal, a failing test, the abort at
  the cap), every process it started is killed: what is left of its group,
  and what left the group for one or a session of its own, as the
  workspace's process runner and some tests start their children. Such a
  process gets none of the signals passed on while the binary runs, but the
  guard is the subreaper of everything the binary starts, so it finds such a
  process at the end even when the one that started it has ended.

The binary's exit code is passed back, and 128 plus the signal for a binary
that a signal ended, as a shell reports it.

Usage: python3 -I ci/mutants_guard.py [--memory BYTES] [--grace SECONDS]
       BINARY [ARGUMENT ...]
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import os
import resource
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from types import FrameType

# The most each process of a test run may allocate. A test binary of the
# workspace takes a few hundred megabytes at most, and a hosted runner has
# 16 GiB.
MEMORY_BYTES = 4 * 1024**3
# How long a test binary has to end after a signal is passed on to it.
GRACE_SECONDS = 2.0
# The signals passed on: those cargo-mutants, GitHub and a terminal end a run
# with.
PASSED_ON = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
# How long to wait for the binary between looks at the signals received.
POLL_SECONDS = 0.05
# prctl(2): the process that orphaned descendants are given to.
PR_SET_CHILD_SUBREAPER = 36
# How long the guard keeps killing what the binary left, at most.
SWEEP_SECONDS = 5.0


def cap_memory(limit: int) -> None:
    """Cap the data segment of this process, and so of every process it starts."""
    _, hard = resource.getrlimit(resource.RLIMIT_DATA)
    if hard != resource.RLIM_INFINITY:
        limit = min(limit, hard)
    resource.setrlimit(resource.RLIMIT_DATA, (limit, limit))


def become_subreaper() -> None:
    """Have the processes below this one that lose their parent given to it.

    Best effort: where the kernel refuses, such a process goes to init, and
    the sweep at the end no longer finds it.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)


def signal_group(child: subprocess.Popen[bytes], signum: int) -> None:
    """Send ``signum`` to the process group that ``child`` leads."""
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(child.pid, signum)


def descendants(root: int) -> list[int]:
    """The processes below ``root`` that still run (zombies left out)."""
    children: dict[int, list[int]] = {}
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            stat = Path("/proc", entry, "stat").read_text(encoding="utf-8")
        except OSError:
            continue  # Ended meanwhile.
        state, parent = stat.rsplit(")", 1)[1].split()[:2]
        if state != "Z":
            children.setdefault(int(parent), []).append(int(entry))
    found: list[int] = []
    below = [root]
    while below:
        for pid in children.get(below.pop(), []):
            found.append(pid)
            below.append(pid)
    return found


def reap() -> None:
    """Collect every child of this process that has ended."""
    with contextlib.suppress(ChildProcessError):
        while os.waitpid(-1, os.WNOHANG)[0]:
            pass


def sweep(seconds: float = SWEEP_SECONDS) -> None:
    """Kill every process below this one, until none is left or time is up.

    Run once the binary has ended and been waited for, so the reaping here
    takes no status that subprocess waits for.
    """
    deadline = time.monotonic() + seconds
    while True:
        reap()
        left = descendants(os.getpid())
        if not left or time.monotonic() >= deadline:
            return
        for pid in left:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(pid, signal.SIGKILL)
        time.sleep(0.01)


def run(command: Sequence[str], grace: float = GRACE_SECONDS) -> int:
    """Run ``command`` as a process group's leader; return its exit status.

    A signal of PASSED_ON is passed on to the group, which is killed when the
    command has not ended ``grace`` seconds after the first. Once the command
    has ended, every process it started is killed. The status is the
    command's exit code, or 128 plus the signal that ended it, and 127 when it
    cannot start.
    """
    received: list[int] = []

    def receive(signum: int, frame: FrameType | None) -> None:
        received.append(signum)

    # Before the start, so no signal falls between the start and the
    # handlers. The command starts with the signals' default actions.
    for signum in PASSED_ON:
        signal.signal(signum, receive)
    become_subreaper()
    try:
        child = subprocess.Popen(command, process_group=0)
    except OSError as error:
        # The binary cannot start; an error once it runs is the guard's own.
        print(f"{command[0]}: {error}", file=sys.stderr)
        return 127
    passed = 0
    kill_at: float | None = None
    while True:
        try:
            status = child.wait(timeout=POLL_SECONDS)
            break
        except subprocess.TimeoutExpired:
            pass
        for arrived in received[passed:]:
            signal_group(child, arrived)
            passed += 1
            if kill_at is None:
                kill_at = time.monotonic() + grace
        if kill_at is not None and time.monotonic() >= kill_at:
            signal_group(child, signal.SIGKILL)
    # Nothing the binary started outlives it, in its group or out of it.
    signal_group(child, signal.SIGKILL)
    sweep()
    return status if status >= 0 else 128 - status


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -I ci/mutants_guard.py",
        description="Run a test binary of a mutation run, capped and killable.",
    )
    parser.add_argument(
        "--memory",
        type=int,
        default=MEMORY_BYTES,
        help="the most each process may allocate, in bytes",
    )
    parser.add_argument(
        "--grace",
        type=float,
        default=GRACE_SECONDS,
        help="how long the binary has to end after a signal, in seconds",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="the binary")
    args = parser.parse_args(argv)
    if not args.command:
        parser.error("no binary to run")
    cap_memory(args.memory)
    return run(args.command, args.grace)


if __name__ == "__main__":
    sys.exit(main())
