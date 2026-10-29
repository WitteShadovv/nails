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
  which counts what it allocates), so the allocation that would pass the cap
  fails, the binary aborts and its tests fail: the mutant is caught.
- The binary. cargo-mutants ends a test run that passes its --timeout with
  SIGTERM to the run's process group. A test binary in which a test installed
  the SIGTERM handler of nails-base's cancel module (the nails-base tests do)
  only sets a flag and runs on, beside the mutants after it, which then build
  and test slower. A SIGTERM, SIGINT or SIGHUP is passed on to the binary here,
  and the binary is killed if it has not ended GRACE_SECONDS later.

The binary's exit code is passed back, and 128 plus the signal for a binary
that a signal ended, as a shell reports it.

Usage: python3 -I ci/mutants_guard.py [--memory BYTES] [--grace SECONDS]
       BINARY [ARGUMENT ...]
"""

from __future__ import annotations

import argparse
import resource
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from types import FrameType

# The most a test binary may allocate. A test binary of the workspace takes a
# few hundred megabytes at most, and a hosted runner has 16 GiB.
MEMORY_BYTES = 4 * 1024**3
# How long a test binary has to end after a signal is passed on to it.
GRACE_SECONDS = 2.0
# The signals passed on: those cargo-mutants, GitHub and a terminal end a run
# with.
PASSED_ON = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
# How long to wait for the binary between looks at the signals received.
POLL_SECONDS = 0.05


def cap_memory(limit: int) -> None:
    """Cap the data segment of this process, and so of every process it starts."""
    _, hard = resource.getrlimit(resource.RLIMIT_DATA)
    if hard != resource.RLIM_INFINITY:
        limit = min(limit, hard)
    resource.setrlimit(resource.RLIMIT_DATA, (limit, limit))


def run(command: Sequence[str], grace: float = GRACE_SECONDS) -> int:
    """Run ``command``; return its exit status as a shell reports it.

    A signal of PASSED_ON is passed on to the command, which is killed when it
    has not ended ``grace`` seconds after the first.
    """
    received: list[int] = []

    def receive(signum: int, frame: FrameType | None) -> None:
        received.append(signum)

    # Before the start, so no signal falls between the start and the
    # handlers. The command starts with the signals' default actions.
    for signum in PASSED_ON:
        signal.signal(signum, receive)
    try:
        child = subprocess.Popen(command)
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
            child.send_signal(arrived)
            passed += 1
            if kill_at is None:
                kill_at = time.monotonic() + grace
        if kill_at is not None and time.monotonic() >= kill_at:
            child.kill()
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
        help="the most the binary may allocate, in bytes",
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
