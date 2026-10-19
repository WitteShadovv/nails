"""Evaluate E2E test attributes in batches that run side by side.

Every test evaluates a NixOS system of its own, and the Nix evaluator keeps
all of that memory until it exits: one process grows by about 250 MiB a test,
so the 65 tests of the suite took 16 GiB in one, about all a hosted runner
has, and evaluating a whole group in the process that builds it is what ran a
15 GB host out of memory. Tests are therefore evaluated in batches, each in a
short-lived ``nix eval`` process, and since the evaluator works on one core,
the batches run at once, as many as the host's cores and memory allow. On
four cores of a build server in October 2026, the 65 tests took 104 s in one
process and 48 s in batches of 8, four processes at a time, which together
peaked at 8 GiB.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Test names are pasted into a Nix expression, so only plain names pass.
TEST_NAME = re.compile(r"[A-Za-z0-9_-]+")
# A batch never holds more tests than this, so one process stays small
# however many tests a run selects.
MAX_BATCH = 8
# Host memory one `nix eval` process of MAX_BATCH tests can take (measured:
# 2.3 to 2.5 GiB).
GIB_PER_PROCESS = 2.5
# Host memory kept free for the Nix daemon, the desktop and the page cache.
RESERVED_GIB = 3.0


class EvalError(Exception):
    """A test name cannot be evaluated safely."""


def auto_workers(meminfo: Path = Path("/proc/meminfo"), cpus: int | None = None) -> int:
    """How many ``nix eval`` processes fit on this host at once.

    One per core this process may run on, and no more than fit in RAM next to
    the reserve. A hosted runner (4 cores, 16 GB) gets 4; an unreadable
    meminfo gets 1.
    """
    total_kib = 0
    try:
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                total_kib = int(line.split()[1])
                break
    except (OSError, ValueError, IndexError):
        total_kib = 0
    by_memory = int((total_kib / (1024 * 1024) - RESERVED_GIB) // GIB_PER_PROCESS)
    cores = cpus if cpus is not None else _usable_cores()
    return max(1, min(cores, by_memory))


def _usable_cores() -> int:
    """The cores this process may run on, where the system can tell."""
    affinity = getattr(os, "sched_getaffinity", None)
    if affinity is not None:
        return len(affinity(0))
    return os.cpu_count() or 1


def split(
    tests: Sequence[str], workers: int, batch_size: int | None = None
) -> list[list[str]]:
    """Split ``tests`` into batches, keeping their order.

    With ``batch_size``, every batch but the last holds that many tests.
    Without it, the tests are spread evenly over one batch per worker, so
    that every process has work and none waits for a straggler, or over more
    batches where one would hold more than MAX_BATCH tests.
    """
    if workers < 1 or (batch_size is not None and batch_size < 1):
        raise ValueError("workers and batch_size must be at least 1")
    if not tests:
        return []
    if batch_size is None:
        count = max(workers, -(-len(tests) // MAX_BATCH))
        count = min(count, len(tests))
        base, extra = divmod(len(tests), count)
        sizes = [base + (1 if index < extra else 0) for index in range(count)]
    else:
        sizes = [batch_size] * (-(-len(tests) // batch_size))
    batches: list[list[str]] = []
    start = 0
    for size in sizes:
        batches.append(list(tests[start : start + size]))
        start += size
    return [batch for batch in batches if batch]


def _expression(tests: Sequence[str], value: str, skip_missing: bool) -> str:
    names = f"builtins.fromJSON ''{json.dumps(list(tests))}''"
    if skip_missing:
        names = f"builtins.filter (n: builtins.hasAttr n e) ({names})"
    pair = f"{{ name = n; value = ({value}) e.${{n}}; }}"
    return f"e: builtins.listToAttrs (map (n: {pair}) ({names}))"


def _eval_batch(
    attr: str, tests: Sequence[str], value: str, skip_missing: bool
) -> dict[str, object]:
    completed = subprocess.run(
        [
            "nix",
            "eval",
            "--json",
            attr,
            "--apply",
            _expression(tests, value, skip_missing),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(completed.stdout)
    if not isinstance(payload, Mapping):
        raise EvalError(f"nix eval of {attr} returned no attribute set")
    return {str(name): result for name, result in payload.items()}


def evaluate(
    attr: str,
    tests: Sequence[str],
    value: str,
    *,
    workers: int,
    batch_size: int | None = None,
    skip_missing: bool = False,
) -> dict[str, object]:
    """Apply the Nix function ``value`` to each test of the set at ``attr``.

    ``attr`` names the attribute set of tests (a flake reference with its
    attribute path), and ``value`` a function of one test, such as
    ``t: t.drvPath``. The batches of :func:`split` run in at most ``workers``
    ``nix eval`` processes at once. Returns the results in the order of
    ``tests``. A test missing from the set is left out with ``skip_missing``
    and fails the evaluation without it. The first failing batch raises its
    ``CalledProcessError`` once the running ones have finished; batches that
    had not started yet are dropped.
    """
    for test in tests:
        if not TEST_NAME.fullmatch(test):
            raise EvalError(f"refusing to evaluate odd test name {test!r}")
    batches = split(tests, workers, batch_size)
    results: dict[str, object] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(batches)))) as pool:
        futures = [
            pool.submit(_eval_batch, attr, batch, value, skip_missing)
            for batch in batches
        ]
        try:
            for future in futures:
                results.update(future.result())
        except BaseException:
            for future in futures:
                future.cancel()
            raise
    return {test: results[test] for test in tests if test in results}
