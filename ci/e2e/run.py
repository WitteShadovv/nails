"""Run resolved E2E tests in one ``nix build`` and record their durations.

A single ``nix build --keep-going -L`` builds every resolved attribute at once,
so VMs that do not share a dependency run in parallel and one failure does not
abandon the rest. The ``--log-format internal-json`` stream gives one build
activity per test; its wall-clock span, timed against a monotonic clock, is the
test's duration. Durations are written as the same ``{"test","result","seconds"}``
JSON lines the weight tools read.
"""

from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

# nix activity type for a derivation build (`Logger::Fields`, actBuild).
ACT_BUILD = 105
_NIX_PREFIX = "@nix "


@dataclass
class TestOutcome:
    result: str
    seconds: int


def _drv_from_fields(payload: Mapping[str, object]) -> str | None:
    fields = payload.get("fields")
    if isinstance(fields, list) and fields and isinstance(fields[0], str):
        candidate = fields[0]
        if candidate.endswith(".drv"):
            return candidate
    text = payload.get("text")
    if isinstance(text, str):
        start = text.find("/nix/store/")
        end = text.find(".drv", start)
        if start != -1 and end != -1:
            return text[start : end + len(".drv")]
    return None


def durations_from_internal_json(
    lines: Iterable[str],
    drv_to_test: Mapping[str, str],
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, TestOutcome]:
    """Derive each test's outcome from a ``--log-format internal-json`` stream.

    A test that starts and stops a build is a timed ``pass``; one that starts
    without stopping (killed or failed build) is a ``fail``; a test with no
    build activity was served from the store and is a zero-second ``pass``.
    """
    started: dict[int, tuple[str, float]] = {}
    outcomes: dict[str, TestOutcome] = {}
    for line in lines:
        if not line.startswith(_NIX_PREFIX):
            continue
        try:
            payload = json.loads(line[len(_NIX_PREFIX) :])
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        action = payload.get("action")
        if action == "start" and payload.get("type") == ACT_BUILD:
            drv = _drv_from_fields(payload)
            test = drv_to_test.get(drv) if drv is not None else None
            activity_id = payload.get("id")
            if test is not None and isinstance(activity_id, int):
                started[activity_id] = (test, clock())
        elif action == "stop":
            activity_id = payload.get("id")
            if isinstance(activity_id, int) and activity_id in started:
                test, start_time = started.pop(activity_id)
                outcomes[test] = TestOutcome("pass", round(clock() - start_time))
    for test, _start in started.values():
        outcomes.setdefault(test, TestOutcome("fail", 0))
    return outcomes


def write_durations(
    path: Path, tests: Sequence[str], outcomes: Mapping[str, TestOutcome]
) -> None:
    """Write one JSON line per resolved test, in run order.

    A test with no recorded outcome was served from the Nix store, so it counts
    as a zero-second pass rather than being dropped.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for test in tests:
            outcome = outcomes.get(test, TestOutcome("pass", 0))
            handle.write(
                json.dumps(
                    {
                        "test": test,
                        "result": outcome.result,
                        "seconds": outcome.seconds,
                    }
                )
                + "\n"
            )


def build_attrs(tests: Sequence[str], attr_prefix: str) -> list[str]:
    return [f"{attr_prefix}.{test}" for test in tests]


def run_build(
    tests: Sequence[str],
    attr_prefix: str = ".#legacyPackages.x86_64-linux.e2e",
    jobs: int | None = None,
    durations_out: Path | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    """Build every resolved test in one ``nix build`` and record durations.

    Returns the ``nix build`` exit status. Nix is required; this is reached
    only through the ``run`` subcommand.
    """
    if not tests:
        return 0
    drv_to_test: dict[str, str] = {}
    for test in tests:
        drv = subprocess.run(
            ["nix", "eval", "--raw", f"{attr_prefix}.{test}.drvPath"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        drv_to_test[drv] = test

    command = ["nix", "build", "--keep-going", "-L", "--log-format", "internal-json"]
    if jobs is not None:
        command += ["--jobs", str(jobs)]
    command += build_attrs(tests, attr_prefix)

    lines: list[str] = []
    with subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    ) as process:
        assert process.stderr is not None
        for line in process.stderr:
            lines.append(line.rstrip("\n"))
        status = process.wait()

    if durations_out is not None:
        outcomes = durations_from_internal_json(lines, drv_to_test, clock)
        write_durations(durations_out, tests, outcomes)
    return status
