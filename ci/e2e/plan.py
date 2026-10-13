"""Shard weights: plan, validate, regenerate and monitor them.

The full E2E suite is split into shards by a greedy longest-first allocator
fed with per-test weights in seconds from ``nix/e2e-tests/shard-durations.json``.
A weight that captured a hang (one test once weighed 3609 s, just above the
driver's one-hour timeout) skews every shard, so weights are checked against
each test's effective timeout from the E2E metadata:

* a weight at or above the test's timeout is always rejected;
* a weight must lie in ``[MIN_WEIGHT, timeout / TIMEOUT_HEADROOM]``, every
  weight must belong to a leaf test, and every leaf test should have a weight.

The runner records one JSON line per test (``{"test", "result", "seconds"}``).
Only passing runs of at least ``MIN_WEIGHT`` seconds count as samples; anything
shorter did not boot a VM and was served from the Nix store.
"""

from __future__ import annotations

import json
import statistics
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

# No VM test boots and passes faster than this; shorter timings are cached
# results or bogus entries.
MIN_WEIGHT = 30
# A test's timeout must be at least this multiple of its weight, so slower
# runners still finish well inside the deadline.
TIMEOUT_HEADROOM = 2
# Relative deviation from a weight (after the run's speed factor) that is
# reported as drift.
DRIFT_THRESHOLD = 0.25
# Below this many weighted samples a run's speed factor is too noisy to
# normalise by, and raw durations are compared instead.
MIN_TESTS_FOR_SPEED_FACTOR = 5
# Weighted test seconds one CI shard should hold when the shard count is
# derived. Setting up a runner (Nix, the VM closure) costs a few minutes on
# top, so a shard of this size finishes in about 20 minutes.
SHARD_SECONDS = 900
# A shard's job timeout is this multiple of its weighted load plus the setup
# allowance, so one retried test or a slower runner still fits, while a hung
# shard is stopped long before GitHub's six-hour limit.
SHARD_TIMEOUT_FACTOR = 1.5
SHARD_SETUP_MINUTES = 15
MIN_SHARD_TIMEOUT_MINUTES = 30


class InputError(Exception):
    """An input file is missing, unreadable or malformed."""


@dataclass
class Findings:
    """Problems found in a weights file.

    ``errors`` make a weight unusable. ``issues`` are hygiene problems: fatal
    for ``check``, warnings when planning so a cosmetic problem never blocks a
    run.
    """

    errors: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)


@dataclass
class ShardSplit:
    shards: list[list[str]]
    loads: list[int]


@dataclass
class DriftRow:
    test: str
    weight: int
    measured: int
    drift: float


@dataclass
class DriftReport:
    speed_factor: float | None
    compared: int
    flagged: list[DriftRow]
    unweighted: list[str]
    threshold: float

    @property
    def suite_drifted(self) -> bool:
        return (
            self.speed_factor is not None
            and abs(self.speed_factor - 1) > self.threshold
        )


def _seconds(value: object) -> int | None:
    """Return value if it is a positive whole number of seconds, else None."""
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def _median_int(values: Iterable[int]) -> int:
    return round(statistics.median(values))


def _read_json(path: Path | str, stdin: TextIO | None = None) -> Any:
    try:
        if str(path) == "-":
            text = (stdin or sys.stdin).read()
            name = "<stdin>"
        else:
            text = Path(path).read_text(encoding="utf-8")
            name = str(path)
    except OSError as exc:
        raise InputError(f"{path}: {exc.strerror or exc}") from None
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise InputError(f"{name}: invalid JSON: {exc}") from None


def load_weights(path: Path) -> dict[str, object] | None:
    """Return the raw weights, or None when the file does not exist."""
    if not path.is_file():
        return None
    payload = _read_json(path)
    if not isinstance(payload, dict):
        raise InputError(f"{path}: expected a JSON object of test name to seconds")
    return payload


def load_timeouts(path: Path | str, stdin: TextIO | None = None) -> dict[str, int]:
    """Return each leaf test's effective timeout, in leaf test order."""
    payload = _read_json(path, stdin)
    name = "<stdin>" if str(path) == "-" else str(path)
    if not isinstance(payload, dict):
        raise InputError(f"{name}: expected the E2E metadata object")
    leaf_tests = payload.get("leafTests")
    timeouts = payload.get("timeouts")
    if not isinstance(leaf_tests, list) or not all(
        isinstance(test, str) for test in leaf_tests
    ):
        raise InputError(f"{name}: leafTests must be a list of test names")
    if not isinstance(timeouts, dict):
        raise InputError(f"{name}: timeouts must map test names to seconds")
    result: dict[str, int] = {}
    for test in leaf_tests:
        timeout = _seconds(timeouts.get(test))
        if timeout is None:
            raise InputError(f"{name}: no valid timeout for leaf test {test}")
        result[test] = timeout
    return result


def load_samples(paths: Iterable[Path]) -> dict[str, list[int]]:
    """Collect boot-verified durations per test from runner JSONL files."""
    samples: dict[str, list[int]] = {}
    for path in paths:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise InputError(f"{path}: {exc.strerror or exc}") from None
        for number, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            where = f"{path}:{number}"
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"{where}: invalid JSON: {exc}") from None
            if not isinstance(record, dict):
                raise InputError(f"{where}: expected a JSON object")
            test = record.get("test")
            result = record.get("result")
            seconds = record.get("seconds")
            if not isinstance(test, str) or not test:
                raise InputError(f"{where}: missing test name")
            if result not in ("pass", "fail"):
                raise InputError(f"{where}: result must be 'pass' or 'fail'")
            if not isinstance(seconds, int) or isinstance(seconds, bool) or seconds < 0:
                raise InputError(f"{where}: seconds must be a non-negative integer")
            if result == "pass" and seconds >= MIN_WEIGHT:
                samples.setdefault(test, []).append(seconds)
    return samples


def validate(weights: Mapping[str, object], timeouts: Mapping[str, int]) -> Findings:
    findings = Findings()
    for test, raw in sorted(weights.items()):
        value = _seconds(raw)
        if value is None:
            findings.errors.append(
                f"{test}: weight {raw!r} is not a positive whole number of seconds"
            )
            continue
        timeout = timeouts.get(test)
        if timeout is None:
            findings.issues.append(
                f"{test}: not a leaf E2E test; remove its stale weight"
            )
            continue
        if value >= timeout:
            findings.errors.append(
                f"{test}: weight {value}s is at or above the test's {timeout}s "
                "timeout, so the recorded run probably hung"
            )
        elif value * TIMEOUT_HEADROOM > timeout:
            findings.issues.append(
                f"{test}: weight {value}s exceeds 1/{TIMEOUT_HEADROOM} of the "
                f"test's {timeout}s timeout; raise its globalTimeout or fix "
                "the weight"
            )
        if value < MIN_WEIGHT:
            findings.issues.append(
                f"{test}: weight {value}s is below {MIN_WEIGHT}s, faster than "
                "a VM test can boot, so it was not measured"
            )
    for test in sorted(set(timeouts) - set(weights)):
        findings.issues.append(f"{test}: no weight; planning assumes the median")
    return findings


def _usable_weight(raw: object, timeout: int) -> int | None:
    value = _seconds(raw)
    if value is None or value < MIN_WEIGHT or value * TIMEOUT_HEADROOM > timeout:
        return None
    return value


def allocate(
    tests: Sequence[str], weights: Mapping[str, int] | None, shard_count: int
) -> ShardSplit:
    """Split tests into shard_count shards, each kept in the original order.

    Longest tests are placed first, each on the currently lightest shard
    (ties: fewest tests, then lowest index), so equal inputs always give the
    same shards. Without weights the tests are dealt round-robin.
    """
    if shard_count < 1:
        raise ValueError("shard_count must be at least 1")
    members: list[list[int]] = [[] for _ in range(shard_count)]
    loads = [0] * shard_count
    if not weights:
        for index in range(len(tests)):
            members[index % shard_count].append(index)
    else:
        default = _median_int(weights.values())

        def weight_of(index: int) -> int:
            return weights.get(tests[index], default)

        order = sorted(range(len(tests)), key=lambda index: (-weight_of(index), index))
        for index in order:
            target = min(
                range(shard_count),
                key=lambda shard: (loads[shard], len(members[shard]), shard),
            )
            members[target].append(index)
            loads[target] += weight_of(index)
    return ShardSplit(
        shards=[[tests[index] for index in sorted(shard)] for shard in members],
        loads=loads,
    )


def shard_count(
    tests: Sequence[str],
    weights: Mapping[str, int] | None,
    max_shards: int,
    shard_seconds: int = SHARD_SECONDS,
) -> int:
    """How many shards ``tests`` need to hold about ``shard_seconds`` each.

    The count never exceeds ``max_shards`` or the number of tests, so no shard
    is empty, and is at least one. Without weights the duration is unknown and
    every test gets a shard of its own, up to ``max_shards``.
    """
    if max_shards < 1 or shard_seconds < 1:
        raise ValueError("max_shards and shard_seconds must be at least 1")
    ceiling = max(1, min(max_shards, len(tests)))
    if not weights:
        return ceiling
    default = _median_int(weights.values())
    total = sum(weights.get(test, default) for test in tests)
    needed = -(-total // shard_seconds)
    return max(1, min(ceiling, needed))


def shard_timeout_minutes(load: int) -> int:
    """Job timeout in minutes for a shard of ``load`` weighted seconds."""
    minutes = -(-round(load * SHARD_TIMEOUT_FACTOR) // 60) + SHARD_SETUP_MINUTES
    return max(MIN_SHARD_TIMEOUT_MINUTES, minutes)


def usable_weights(
    raw: Mapping[str, object], timeouts: Mapping[str, int]
) -> dict[str, int]:
    """Return the weights that are valid positive seconds, rejecting hangs.

    A weight at or above its test's timeout is an error, never a silent drop,
    so a corrupted hang-weight cannot pass planning unnoticed.
    """
    findings = validate(raw, timeouts)
    if findings.errors:
        raise InputError("; ".join(findings.errors))
    return {
        test: value
        for test, raw_value in raw.items()
        if (value := _seconds(raw_value)) is not None and test in timeouts
    }


def regen(
    weights: Mapping[str, object],
    samples: Mapping[str, list[int]],
    timeouts: Mapping[str, int],
) -> tuple[dict[str, int], list[str]]:
    """Return new weights from samples, plus notes on every judgement call."""
    result: dict[str, int] = {}
    notes: list[str] = []
    for test in sorted(timeouts):
        timeout = timeouts[test]
        cap = timeout // TIMEOUT_HEADROOM
        if samples.get(test):
            measured = _median_int(samples[test])
            if measured > cap:
                notes.append(
                    f"{test}: measured {measured}s, clamped to {cap}s; raise its "
                    "globalTimeout to keep the measured value"
                )
                measured = cap
            result[test] = measured
        elif test in weights:
            previous = _usable_weight(weights[test], timeout)
            if previous is not None:
                result[test] = previous
            else:
                notes.append(
                    f"{test}: no samples and the old weight {weights[test]!r} is "
                    "not usable; dropped"
                )
        else:
            notes.append(f"{test}: no samples and no previous weight")
    for test in sorted(set(weights) - set(timeouts)):
        notes.append(f"{test}: not a leaf E2E test; dropped")
    return result, notes


def format_weights(weights: Mapping[str, int]) -> str:
    return json.dumps(dict(sorted(weights.items())), indent=2) + "\n"


def drift(
    weights: Mapping[str, int],
    samples: Mapping[str, list[int]],
    threshold: float = DRIFT_THRESHOLD,
) -> DriftReport:
    """Compare recorded durations with weights.

    Runners differ in speed, so each test's duration is first divided by the
    run's speed factor (the median of duration / weight). Only what remains,
    the change relative to the other tests, counts as a test's drift.
    """
    measured = {test: _median_int(values) for test, values in samples.items() if values}
    compared = sorted(test for test in measured if test in weights)
    factor: float | None = None
    if len(compared) >= MIN_TESTS_FOR_SPEED_FACTOR:
        factor = statistics.median(measured[test] / weights[test] for test in compared)
    normaliser = 1.0 if factor is None else factor
    flagged = []
    for test in compared:
        relative = measured[test] / (weights[test] * normaliser) - 1
        if abs(relative) > threshold:
            flagged.append(DriftRow(test, weights[test], measured[test], relative))
    return DriftReport(
        speed_factor=factor,
        compared=len(compared),
        flagged=flagged,
        unweighted=sorted(test for test in measured if test not in weights),
        threshold=threshold,
    )


def format_drift_markdown(report: DriftReport, heading: str) -> str:
    lines = [f"## {heading}", ""]
    if report.compared == 0 and not report.unweighted:
        lines += ["No boot-verified durations were recorded.", ""]
        return "\n".join(lines) + "\n"
    if report.speed_factor is None:
        lines.append(
            f"Compared {report.compared} test(s) against their weights without a "
            f"speed factor (fewer than {MIN_TESTS_FOR_SPEED_FACTOR} weighted samples)."
        )
    else:
        lines.append(
            f"Tests in this run took {report.speed_factor:.2f}x their checked-in "
            f"weights (median over {report.compared} tests); the drift below is "
            "relative to that speed factor."
        )
        if report.suite_drifted:
            lines.append("")
            lines.append(
                f"The whole run is more than {report.threshold:.0%} off the weights; "
                "check the runner type before regenerating them."
            )
    lines.append("")
    if report.flagged:
        lines += [
            f"{len(report.flagged)} of {report.compared} test(s) drifted more than "
            f"{report.threshold:.0%}:",
            "",
            "| Test | Weight (s) | Measured (s) | Drift |",
            "|---|---:|---:|---:|",
        ]
        lines += [
            f"| `{row.test}` | {row.weight} | {row.measured} | {row.drift:+.0%} |"
            for row in report.flagged
        ]
        lines.append("")
    else:
        lines += [
            f"All {report.compared} test(s) are within {report.threshold:.0%} of "
            "their weights.",
            "",
        ]
    if report.unweighted:
        lines.append(
            "Tests without a weight: "
            + ", ".join(f"`{test}`" for test in report.unweighted)
        )
        lines.append("")
    lines.append(
        'To refresh the weights, see "Timeouts and shard weights" in '
        "`nix/e2e-tests/README.md`."
    )
    return "\n".join(lines) + "\n"


def _escape_annotation(message: str) -> str:
    return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def format_drift_annotations(report: DriftReport) -> list[str]:
    title = "title=E2E shard weight drift"
    annotations = []
    if report.suite_drifted:
        assert report.speed_factor is not None
        annotations.append(
            f"::warning {title}::"
            + _escape_annotation(
                f"tests in this run took {report.speed_factor:.2f}x their "
                "checked-in weights"
            )
        )
    for row in report.flagged:
        annotations.append(
            f"::warning {title}::"
            + _escape_annotation(
                f"{row.test}: measured {row.measured}s against a weight of "
                f"{row.weight}s ({row.drift:+.0%})"
            )
        )
    for test in report.unweighted:
        annotations.append(
            f"::warning {title}::" + _escape_annotation(f"{test}: no weight")
        )
    return annotations


def print_findings(findings: Findings, *, strict: bool) -> None:
    for error in findings.errors:
        print(f"error: {error}", file=sys.stderr)
    label = "error" if strict else "warning"
    for issue in findings.issues:
        print(f"{label}: {issue}", file=sys.stderr)
