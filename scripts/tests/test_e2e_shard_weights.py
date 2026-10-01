"""Tests for scripts/e2e_shard_weights.py and its use by run-e2e-tests.sh.

The effective test timeouts normally come from `nix eval` of the E2E
metadata. Nix is not needed here: `scan_nix_metadata` reads the same values
from the test files (`name = "..."`, optional `globalTimeout = N;`) and from
`defaultGlobalTimeout` in nix/e2e-tests/default.nix, relying on nixfmt layout.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SCRIPTS_DIR.parent
sys.path.insert(0, str(SCRIPTS_DIR))

import e2e_shard_weights as weights_tool  # noqa: E402

WEIGHTS_FILE = REPO_ROOT / "nix" / "e2e-tests" / "shard-durations.json"
TOOL = SCRIPTS_DIR / "e2e_shard_weights.py"
RUNNER = SCRIPTS_DIR / "run-e2e-tests.sh"


def scan_nix_metadata() -> dict[str, Any]:
    """Build the parts of the E2E metadata the planner uses from the sources."""
    default_nix = (REPO_ROOT / "nix" / "e2e-tests" / "default.nix").read_text(
        encoding="utf-8"
    )
    default_match = re.search(r"^  defaultGlobalTimeout = (\d+);$", default_nix, re.M)
    if default_match is None:
        raise AssertionError("defaultGlobalTimeout not found in default.nix")
    default_timeout = int(default_match.group(1))
    timeouts: dict[str, int] = {}
    for path in sorted((REPO_ROOT / "nix" / "e2e-tests" / "tests").rglob("*.nix")):
        text = path.read_text(encoding="utf-8")
        names = re.findall(r'^  name = "([^"]+)";$', text, re.M)
        if len(names) != 1:
            raise AssertionError(f"{path}: expected exactly one top-level name")
        override = re.search(r"^  globalTimeout = (\d+);$", text, re.M)
        timeouts[names[0]] = int(override.group(1)) if override else default_timeout
    leaf_tests = sorted(timeouts)
    return {
        "availableTargets": leaf_tests + ["all"],
        "leafTests": leaf_tests,
        "groups": {"all": leaf_tests},
        "nodeCounts": {name: 1 for name in leaf_tests},
        "timeouts": timeouts,
    }


def legacy_allocate(
    tests: list[str], weights: dict[str, int], shard_index: int, shard_count: int
) -> list[str]:
    """The allocator previously embedded in run-e2e-tests.sh, kept verbatim."""
    default_weight = 120
    shard_loads = [0] * shard_count
    shard_members: list[list[tuple[int, str]]] = [[] for _ in range(shard_count)]
    weighted_tests = [
        (-int(weights.get(name, default_weight)), original_index, name)
        for original_index, name in enumerate(tests)
    ]
    for negative_weight, original_index, name in sorted(weighted_tests):
        weight = -negative_weight
        target_shard = min(
            range(shard_count),
            key=lambda shard: (shard_loads[shard], len(shard_members[shard]), shard),
        )
        shard_members[target_shard].append((original_index, name))
        shard_loads[target_shard] += weight
    return [name for _, name in sorted(shard_members[shard_index - 1])]


def real_weights() -> dict[str, int]:
    return json.loads(WEIGHTS_FILE.read_text(encoding="utf-8"))


def write_jsonl(directory: Path, name: str, records: list[Any]) -> Path:
    path = directory / name
    path.write_text(
        "".join(
            (record if isinstance(record, str) else json.dumps(record)) + "\n"
            for record in records
        ),
        encoding="utf-8",
    )
    return path


class TempDirTestCase(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)


class CheckedInWeightsTest(unittest.TestCase):
    def test_weights_match_tests_and_timeouts(self) -> None:
        timeouts = scan_nix_metadata()["timeouts"]
        findings = weights_tool.validate(real_weights(), timeouts)
        self.assertEqual(findings.errors, [])
        self.assertEqual(findings.issues, [])

    def test_four_shards_are_balanced_within_fifteen_percent(self) -> None:
        metadata = scan_nix_metadata()
        plan = weights_tool.allocate(metadata["leafTests"], real_weights(), 4)
        self.assertLessEqual(max(plan.loads) / min(plan.loads), 1.15, plan.loads)

    def test_long_tests_declare_a_matching_timeout(self) -> None:
        timeouts = scan_nix_metadata()["timeouts"]
        for test, weight in real_weights().items():
            with self.subTest(test=test):
                self.assertLessEqual(
                    weight * weights_tool.TIMEOUT_HEADROOM, timeouts[test]
                )


class AllocateTest(unittest.TestCase):
    def test_matches_the_previous_allocator(self) -> None:
        cases = [
            (["a", "b", "c", "d", "e"], {"a": 50, "b": 50, "c": 50, "d": 50, "e": 50}),
            (
                ["a", "b", "c", "d", "e", "f"],
                {"a": 10, "b": 300, "c": 40, "d": 300, "e": 90, "f": 5},
            ),
            (list(real_weights()), real_weights()),
            (sorted(real_weights()), real_weights()),
        ]
        for tests, weights in cases:
            for shard_count in range(1, 7):
                plan = weights_tool.allocate(tests, weights, shard_count)
                for shard_index in range(1, shard_count + 1):
                    with self.subTest(
                        tests=tests[:3], count=shard_count, index=shard_index
                    ):
                        self.assertEqual(
                            plan.shards[shard_index - 1],
                            legacy_allocate(tests, weights, shard_index, shard_count),
                        )

    def test_shards_partition_tests_and_keep_run_order(self) -> None:
        tests = [f"t{index}" for index in range(10)]
        weights = {name: 30 + 17 * index % 7 for index, name in enumerate(tests)}
        plan = weights_tool.allocate(tests, weights, 3)
        self.assertEqual(sorted(sum(plan.shards, [])), sorted(tests))
        for shard in plan.shards:
            self.assertEqual(shard, sorted(shard, key=tests.index))
        self.assertEqual(sum(plan.loads), sum(weights.values()))

    def test_round_robin_without_weights(self) -> None:
        plan = weights_tool.allocate(["a", "b", "c", "d", "e"], None, 2)
        self.assertEqual(plan.shards, [["a", "c", "e"], ["b", "d"]])
        self.assertEqual(
            weights_tool.allocate(["a", "b"], {}, 2).shards, [["a"], ["b"]]
        )

    def test_unweighted_tests_count_as_the_median(self) -> None:
        weights = {"a": 100, "b": 40, "c": 60}
        plan = weights_tool.allocate(["a", "b", "c", "new"], weights, 2)
        self.assertEqual(sum(plan.loads), 100 + 40 + 60 + 60)

    def test_rejects_zero_shards(self) -> None:
        with self.assertRaises(ValueError):
            weights_tool.allocate(["a"], None, 0)


class ValidateTest(unittest.TestCase):
    timeouts = {"short": 900, "long": 1500}

    def test_weight_at_or_above_timeout_is_an_error(self) -> None:
        for weight in (900, 3609):
            findings = weights_tool.validate(
                {"short": weight, "long": 100}, self.timeouts
            )
            self.assertEqual(len(findings.errors), 1, findings)
            self.assertIn("at or above the test's 900s timeout", findings.errors[0])

    def test_weight_above_half_the_timeout_is_an_issue(self) -> None:
        findings = weights_tool.validate({"short": 451, "long": 750}, self.timeouts)
        self.assertEqual(findings.errors, [])
        self.assertEqual(len(findings.issues), 1)
        self.assertIn("short: weight 451s exceeds 1/2", findings.issues[0])

    def test_weight_below_minimum_is_an_issue(self) -> None:
        findings = weights_tool.validate({"short": 10, "long": 30}, self.timeouts)
        self.assertEqual(findings.errors, [])
        self.assertEqual(len(findings.issues), 1)
        self.assertIn("short: weight 10s is below 30s", findings.issues[0])

    def test_stale_and_missing_weights_are_issues(self) -> None:
        findings = weights_tool.validate({"short": 100, "gone": 100}, self.timeouts)
        self.assertEqual(findings.errors, [])
        self.assertEqual(
            findings.issues,
            [
                "gone: not a leaf E2E test; remove its stale weight",
                "long: no weight; planning assumes the median",
            ],
        )

    def test_values_that_are_not_positive_integers_are_errors(self) -> None:
        for value in ("100", 100.0, True, 0, -5, None):
            with self.subTest(value=value):
                findings = weights_tool.validate(
                    {"short": value, "long": 100}, self.timeouts
                )
                self.assertEqual(len(findings.errors), 1)
                self.assertIn("not a positive whole number", findings.errors[0])


class LoadSamplesTest(TempDirTestCase):
    def test_keeps_only_boot_verified_passes(self) -> None:
        first = write_jsonl(
            self.tmp,
            "shard-1.jsonl",
            [
                {"test": "a", "result": "pass", "seconds": 120},
                {"test": "b", "result": "fail", "seconds": 300},
                {"test": "c", "result": "pass", "seconds": 4},
                "",
                {"test": "a", "result": "pass", "seconds": 30},
            ],
        )
        second = write_jsonl(
            self.tmp, "shard-2.jsonl", [{"test": "a", "result": "pass", "seconds": 90}]
        )
        self.assertEqual(
            weights_tool.load_samples([first, second]), {"a": [120, 30, 90]}
        )

    def test_malformed_line_names_file_and_line(self) -> None:
        path = write_jsonl(
            self.tmp,
            "broken.jsonl",
            [{"test": "a", "result": "pass", "seconds": 120}, "{not json"],
        )
        with self.assertRaisesRegex(
            weights_tool.InputError, r"broken\.jsonl:2: invalid JSON"
        ):
            weights_tool.load_samples([path])

    def test_invalid_records_are_rejected(self) -> None:
        records = [
            ["[1, 2]", "expected a JSON object"],
            [{"result": "pass", "seconds": 1}, "missing test name"],
            [{"test": "a", "result": "skip", "seconds": 1}, "result must be"],
            [{"test": "a", "result": "pass", "seconds": "60"}, "non-negative integer"],
            [{"test": "a", "result": "pass", "seconds": -1}, "non-negative integer"],
            [{"test": "a", "result": "pass", "seconds": True}, "non-negative integer"],
        ]
        for record, message in records:
            with self.subTest(record=record):
                path = write_jsonl(self.tmp, "bad.jsonl", [record])
                with self.assertRaisesRegex(weights_tool.InputError, message):
                    weights_tool.load_samples([path])

    def test_missing_file_is_an_input_error(self) -> None:
        with self.assertRaises(weights_tool.InputError):
            weights_tool.load_samples([self.tmp / "absent.jsonl"])


class RegenTest(unittest.TestCase):
    timeouts = {"a": 900, "b": 900, "c": 900, "d": 1500, "e": 900}

    def test_regenerates_from_samples(self) -> None:
        new, notes = weights_tool.regen(
            {"a": 3609, "b": 200, "c": 10, "gone": 50},
            {"a": [140, 150, 170], "d": [700, 900], "e": [101, 102]},
            self.timeouts,
        )
        self.assertEqual(new, {"a": 150, "b": 200, "d": 750, "e": 102})
        self.assertEqual(
            notes,
            [
                "c: no samples and the old weight 10 is not usable; dropped",
                "d: measured 800s, clamped to 750s; raise its globalTimeout to keep "
                "the measured value",
                "gone: not a leaf E2E test; dropped",
            ],
        )

    def test_reports_tests_without_any_data(self) -> None:
        new, notes = weights_tool.regen({}, {"a": [60]}, {"a": 900, "b": 900})
        self.assertEqual(new, {"a": 60})
        self.assertEqual(notes, ["b: no samples and no previous weight"])

    def test_output_format_is_stable(self) -> None:
        self.assertEqual(
            weights_tool.format_weights({"b": 60, "a": 120}),
            '{\n  "a": 120,\n  "b": 60\n}\n',
        )


class DriftTest(unittest.TestCase):
    weights = {f"t{index}": 100 for index in range(6)}

    def test_uniformly_slower_run_flags_only_the_speed_factor(self) -> None:
        samples = {test: [150] for test in self.weights}
        report = weights_tool.drift(self.weights, samples)
        self.assertEqual(report.speed_factor, 1.5)
        self.assertTrue(report.suite_drifted)
        self.assertEqual(report.flagged, [])
        self.assertEqual(
            weights_tool.format_drift_annotations(report),
            [
                "::warning title=E2E shard weight drift::tests in this run took "
                "1.50x their checked-in weights"
            ],
        )

    def test_flags_tests_beyond_the_threshold_after_normalising(self) -> None:
        samples = {test: [120] for test in self.weights}
        samples["t0"] = [240]
        samples["t1"] = [145]
        samples["new"] = [60]
        report = weights_tool.drift(self.weights, samples)
        self.assertEqual(report.speed_factor, 1.2)
        self.assertFalse(report.suite_drifted)
        self.assertEqual([row.test for row in report.flagged], ["t0"])
        self.assertAlmostEqual(report.flagged[0].drift, 1.0)
        self.assertEqual(report.unweighted, ["new"])
        self.assertEqual(
            weights_tool.format_drift_annotations(report),
            [
                "::warning title=E2E shard weight drift::t0: measured 240s against "
                "a weight of 100s (+100%25)",
                "::warning title=E2E shard weight drift::new: no weight",
            ],
        )
        markdown = weights_tool.format_drift_markdown(report, "Drift")
        self.assertIn("| `t0` | 100 | 240 | +100% |", markdown)
        self.assertIn("1.20x", markdown)
        self.assertIn("Tests without a weight: `new`", markdown)

    def test_few_samples_are_compared_without_a_speed_factor(self) -> None:
        report = weights_tool.drift(self.weights, {"t0": [130], "t1": [110]})
        self.assertIsNone(report.speed_factor)
        self.assertEqual([row.test for row in report.flagged], ["t0"])
        self.assertIn(
            "without a speed factor", weights_tool.format_drift_markdown(report, "D")
        )

    def test_empty_run_reports_nothing_recorded(self) -> None:
        report = weights_tool.drift(self.weights, {})
        self.assertEqual(weights_tool.format_drift_annotations(report), [])
        self.assertIn(
            "No boot-verified durations",
            weights_tool.format_drift_markdown(report, "D"),
        )


class LoadMetadataTest(unittest.TestCase):
    def test_reads_timeouts_from_stdin(self) -> None:
        payload = json.dumps(
            {"leafTests": ["a", "b"], "timeouts": {"a": 900, "b": 1500}}
        )
        self.assertEqual(
            weights_tool.load_metadata("-", io.StringIO(payload)), {"a": 900, "b": 1500}
        )

    def test_rejects_metadata_without_timeouts(self) -> None:
        for payload in (
            {"leafTests": ["a"]},
            {"leafTests": ["a"], "timeouts": {}},
            {"leafTests": ["a"], "timeouts": {"a": "900"}},
            {"leafTests": "a", "timeouts": {"a": 900}},
            ["a"],
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(weights_tool.InputError):
                    weights_tool.load_metadata("-", io.StringIO(json.dumps(payload)))


class CommandLineTest(TempDirTestCase):
    def run_tool(
        self, *args: str, stdin: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOL), *args],
            input=stdin,
            capture_output=True,
            text=True,
            check=False,
        )

    def write_json(self, name: str, payload: Any) -> Path:
        path = self.tmp / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def plan(
        self, metadata: dict[str, Any], weights: Path, index: int, count: int
    ) -> subprocess.CompletedProcess[str]:
        return self.run_tool(
            "plan",
            "--shard-index",
            str(index),
            "--shard-count",
            str(count),
            "--weights",
            str(weights),
            "--metadata",
            "-",
            "--",
            *metadata["leafTests"],
            stdin=json.dumps(metadata),
        )

    def test_plan_splits_the_suite_into_disjoint_shards(self) -> None:
        metadata = scan_nix_metadata()
        selected: list[str] = []
        for index in range(1, 5):
            result = self.plan(metadata, WEIGHTS_FILE, index, 4)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("planned shard loads (s):", result.stderr)
            selected += result.stdout.split()
        self.assertEqual(sorted(selected), metadata["leafTests"])

    def test_plan_refuses_a_weight_at_the_timeout(self) -> None:
        metadata = scan_nix_metadata()
        metadata["timeouts"]["performance"] = 600
        result = self.plan(metadata, WEIGHTS_FILE, 1, 4)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("performance: weight 684s is at or above", result.stderr)

    def test_plan_only_warns_about_hygiene(self) -> None:
        metadata = {"leafTests": ["a", "b"], "timeouts": {"a": 900, "b": 900}}
        weights = self.write_json("weights.json", {"a": 10, "gone": 100})
        result = self.plan(metadata, weights, 1, 1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split(), ["a", "b"])
        self.assertIn("warning: a: weight 10s is below 30s", result.stderr)

    def test_plan_deals_round_robin_without_a_weights_file(self) -> None:
        metadata = {
            "leafTests": ["a", "b", "c"],
            "timeouts": {"a": 900, "b": 900, "c": 900},
        }
        result = self.plan(metadata, self.tmp / "absent.json", 1, 2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split(), ["a", "c"])
        self.assertIn("round-robin", result.stderr)

    def test_plan_rejects_bad_input(self) -> None:
        metadata = {"leafTests": ["a"], "timeouts": {"a": 900}}
        result = self.run_tool(
            "plan",
            "--shard-index",
            "1",
            "--shard-count",
            "1",
            "--weights",
            str(WEIGHTS_FILE),
            "--metadata",
            "-",
            "--",
            "nope",
            stdin=json.dumps(metadata),
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("not leaf E2E tests: nope", result.stderr)
        result = self.run_tool(
            "plan",
            "--shard-index",
            "3",
            "--shard-count",
            "2",
            "--weights",
            str(WEIGHTS_FILE),
            "--metadata",
            "-",
            "--",
            "a",
            stdin=json.dumps(metadata),
        )
        self.assertEqual(result.returncode, 2)
        result = self.run_tool(
            "plan",
            "--shard-index",
            "1",
            "--shard-count",
            "1",
            "--weights",
            str(WEIGHTS_FILE),
            "--metadata",
            "-",
            "--",
            "a",
            stdin="{",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("<stdin>: invalid JSON", result.stderr)

    def test_check_is_strict(self) -> None:
        metadata = self.write_json("meta.json", scan_nix_metadata())
        result = self.run_tool(
            "check", "--weights", str(WEIGHTS_FILE), "--metadata", str(metadata)
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        weights = real_weights()
        weights["notify-no-notify-send"] = 11
        stale = self.write_json("weights.json", weights)
        result = self.run_tool(
            "check", "--weights", str(stale), "--metadata", str(metadata)
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "error: notify-no-notify-send: weight 11s is below 30s", result.stderr
        )

    def test_regen_rewrites_the_weights_file(self) -> None:
        metadata = self.write_json(
            "meta.json", {"leafTests": ["a", "b"], "timeouts": {"a": 900, "b": 900}}
        )
        weights = self.write_json("weights.json", {"a": 3609, "b": 200})
        samples = write_jsonl(
            self.tmp, "d.jsonl", [{"test": "a", "result": "pass", "seconds": 140}]
        )
        result = self.run_tool(
            "regen",
            "--weights",
            str(weights),
            "--metadata",
            str(metadata),
            str(samples),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            weights.read_text(encoding="utf-8"), '{\n  "a": 140,\n  "b": 200\n}\n'
        )

    def test_regen_refuses_runs_without_samples(self) -> None:
        metadata = self.write_json(
            "meta.json", {"leafTests": ["a"], "timeouts": {"a": 900}}
        )
        weights = self.write_json("weights.json", {"a": 100})
        samples = write_jsonl(
            self.tmp, "d.jsonl", [{"test": "a", "result": "fail", "seconds": 140}]
        )
        result = self.run_tool(
            "regen",
            "--weights",
            str(weights),
            "--metadata",
            str(metadata),
            str(samples),
        )
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(weights.read_text(encoding="utf-8")), {"a": 100})

    def test_drift_appends_a_summary_and_annotations(self) -> None:
        weights = self.write_json("weights.json", {"a": 100, "b": 100})
        samples = write_jsonl(
            self.tmp,
            "d.jsonl",
            [
                {"test": "a", "result": "pass", "seconds": 300},
                {"test": "b", "result": "pass", "seconds": 100},
            ],
        )
        summary = self.tmp / "summary.md"
        summary.write_text("# Existing\n", encoding="utf-8")
        result = self.run_tool(
            "drift",
            "--weights",
            str(weights),
            "--summary",
            str(summary),
            "--github",
            str(samples),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            "::warning title=E2E shard weight drift::a: measured 300s against a "
            "weight of 100s (+200%25)\n",
        )
        text = summary.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("# Existing\n## E2E shard weight drift\n"))
        self.assertIn("| `a` | 100 | 300 | +200% |", text)


@unittest.skipUnless(shutil.which("bash"), "the runner needs bash")
class RunnerTest(TempDirTestCase):
    """run-e2e-tests.sh against a stand-in `nix` that serves scanned metadata."""

    def setUp(self) -> None:
        super().setUp()
        self.metadata = scan_nix_metadata()
        fake_bin = self.tmp / "bin"
        fake_bin.mkdir()
        fake_nix = fake_bin / "nix"
        fake_nix.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                case "$1" in
                    eval) cat "$FAKE_E2E_METADATA" ;;
                    build)
                        failing="${FAKE_FAIL_TEST:-}"
                        if [[ -n "$failing" && "$2" == *".e2e-$failing" ]]; then
                            exit 1
                        fi
                        ;;
                    *) exit 64 ;;
                esac
                """
            ),
            encoding="utf-8",
        )
        fake_nix.chmod(0o755)
        self.fake_bin = fake_bin

    def run_runner(
        self, *args: str, fail_test: str = ""
    ) -> subprocess.CompletedProcess[str]:
        metadata_path = self.tmp / "meta.json"
        metadata_path.write_text(json.dumps(self.metadata), encoding="utf-8")
        env = {
            key: value
            for key, value in os.environ.items()
            if key not in ("CI", "GITHUB_ACTIONS", "NAILS_E2E_DEFAULT_TARGET")
        }
        env.update(
            PATH=f"{self.fake_bin}{os.pathsep}{env.get('PATH', '')}",
            FAKE_E2E_METADATA=str(metadata_path),
            FAKE_FAIL_TEST=fail_test,
            NAILS_E2E_SYSTEM="x86_64-linux",
        )
        return subprocess.run(
            ["bash", str(RUNNER), *args],
            env=env,
            capture_output=True,
            text=True,
            check=False,
            cwd=self.tmp,
        )

    def test_dry_run_shards_cover_the_suite_once(self) -> None:
        selected: list[str] = []
        for index in range(1, 5):
            result = self.run_runner(
                "--dry-run", "--shard-index", str(index), "--shard-count", "4", "all"
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            selected += result.stdout.split()
        self.assertEqual(sorted(selected), self.metadata["leafTests"])

    def test_planner_failure_stops_the_run(self) -> None:
        self.metadata["timeouts"]["performance"] = 600
        result = self.run_runner(
            "--dry-run", "--shard-index", "1", "--shard-count", "4", "all"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("could not select the tests", result.stderr)
        self.assertNotIn("nothing to run", result.stdout + result.stderr)

    def test_durations_are_recorded_per_test(self) -> None:
        durations = self.tmp / "out" / "durations.jsonl"
        durations.parent.mkdir()
        durations.write_text("stale\n", encoding="utf-8")
        result = self.run_runner(
            "--durations-out",
            "out/durations.jsonl",
            "basic-workflow",
            "verify",
            fail_test="verify",
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        records = [
            json.loads(line)
            for line in durations.read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(
            [(record["test"], record["result"]) for record in records],
            [("basic-workflow", "pass"), ("verify", "fail")],
        )
        for record in records:
            self.assertIsInstance(record["seconds"], int)

    def test_durations_out_requires_a_value(self) -> None:
        result = self.run_runner("--durations-out")
        self.assertEqual(result.returncode, 1)
        self.assertIn("--durations-out requires a value", result.stderr)


class ScanTest(unittest.TestCase):
    def test_scan_sees_the_default_and_the_performance_override(self) -> None:
        timeouts = scan_nix_metadata()["timeouts"]
        self.assertEqual(timeouts["performance"], 1500)
        self.assertEqual(statistics.mode(timeouts.values()), 900)


if __name__ == "__main__":
    unittest.main()
