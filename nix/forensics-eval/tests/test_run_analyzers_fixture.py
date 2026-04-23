import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUN_ANALYZERS = ROOT / "nix" / "forensics-eval" / "analyzers" / "run_analyzers.py"
FIXTURE_RUN = ROOT / "nix" / "forensics-eval" / "fixtures" / "samples" / "sample-run"
REGISTRY = ROOT / "nix" / "forensics-eval" / "analyzers" / "registry.json"


def _run_analyzers(
    output_dir: Path, *extra_args: str
) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        str(RUN_ANALYZERS),
        "--run-dir",
        str(FIXTURE_RUN),
        "--output",
        str(output_dir),
        "--baseline-dir",
        str(FIXTURE_RUN / "baseline"),
        "--stage",
        "active",
        "--stage",
        "post-standard",
        "--stage",
        "post-emergency",
        *extra_args,
    ]
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, check=False)


class RunAnalyzersFixtureTest(unittest.TestCase):
    def test_active_stage_is_enforced_positive_control_and_fls_oracle_uses_exact_mode(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "compare"
            result = _run_analyzers(output_dir)
            self.assertEqual(result.returncode, 0, result.stderr)

            summary = json.loads(
                (output_dir / "summary.json").read_text(encoding="utf-8")
            )
            active = next(
                stage for stage in summary["stages"] if stage["stage"] == "active"
            )
            self.assertEqual(active["expectation"]["kind"], "positive-control")
            self.assertTrue(active["expectation"]["expectedFindings"])
            self.assertGreater(active["findingCount"], 0)
            self.assertTrue(active["positiveControlContract"]["enforced"])
            self.assertTrue(active["positiveControlContract"]["satisfied"])
            self.assertEqual(
                active["positiveControlContract"]["requiredAnalyzers"],
                ["path_delta", "canary_scan", "indicator_scan"],
            )
            self.assertTrue(
                all(
                    result["satisfied"]
                    for result in active["positiveControlContract"][
                        "requiredAnalyzerResults"
                    ]
                )
            )
            self.assertEqual(summary["contractFailures"], [])

            active_fls = json.loads(
                (output_dir / "analyzers" / "active" / "fls_oracle.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(active_fls["status"], "finding")
            self.assertEqual(active_fls["summary"]["oracleMode"], "exact-oracle")
            self.assertGreaterEqual(active_fls["metrics"]["exactExpectedCount"], 1)
            self.assertGreaterEqual(active_fls["metrics"]["preservedFindings"], 1)

            post_standard_fls = json.loads(
                (
                    output_dir / "analyzers" / "post-standard" / "fls_oracle.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(post_standard_fls["summary"]["oracleMode"], "exact-oracle")

            post_emergency_fls = json.loads(
                (
                    output_dir / "analyzers" / "post-emergency" / "fls_oracle.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(post_emergency_fls["status"], "clean")
            self.assertEqual(
                post_emergency_fls["summary"]["oracleMode"], "exact-oracle"
            )

            manifest = json.loads(REGISTRY.read_text(encoding="utf-8"))
            expected_per_stage = sum(
                1 for analyzer in manifest["analyzers"] if analyzer.get("enabled", True)
            )
            self.assertEqual(
                summary["analyzerCoverage"]["expectedPerStage"], expected_per_stage
            )
            self.assertEqual(summary["analyzerCoverage"]["stageCount"], 3)
            report = (output_dir / "report.md").read_text(encoding="utf-8")
            self.assertIn("positive-control", report)
            self.assertIn("ENFORCED PASS", report)

    def test_positive_control_fails_when_all_expected_findings_are_allowlisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "compare"
            allowlist_path = Path(tmp) / "mask-positive-control.json"
            allowlist_path.write_text(
                json.dumps(
                    {
                        "contractVersion": "1",
                        "profiles": {
                            "default": {
                                "global": {
                                    "pathRegex": [],
                                    "contentRegex": [],
                                    "findingIds": [],
                                },
                                "analyzers": {
                                    "path_delta": {
                                        "pathRegex": [".*"],
                                        "contentRegex": [],
                                        "findingIds": [],
                                    },
                                    "canary_scan": {
                                        "pathRegex": [".*"],
                                        "contentRegex": [".*"],
                                        "findingIds": [],
                                    },
                                    "indicator_scan": {
                                        "pathRegex": [".*"],
                                        "contentRegex": [".*"],
                                        "findingIds": [],
                                    },
                                    "fls_oracle": {
                                        "pathRegex": [".*"],
                                        "contentRegex": [".*"],
                                        "findingIds": [],
                                    },
                                },
                            }
                        },
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )

            result = _run_analyzers(output_dir, "--allowlist", str(allowlist_path))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Enforced analyzer contracts failed", result.stderr)

            summary = json.loads(
                (output_dir / "summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(summary["status"], "error")
            active = next(
                stage for stage in summary["stages"] if stage["stage"] == "active"
            )
            self.assertFalse(active["positiveControlContract"]["satisfied"])
            self.assertTrue(
                active["positiveControlContract"]["allowlistMaskedAnalyzers"]
            )
            self.assertIn(
                "required analyzer path_delta produced only allowlisted findings",
                active["positiveControlContract"]["failures"],
            )
            self.assertIn(
                "required analyzer canary_scan produced only allowlisted findings",
                active["positiveControlContract"]["failures"],
            )
            self.assertIn(
                "required analyzer indicator_scan produced only allowlisted findings",
                active["positiveControlContract"]["failures"],
            )

            report = (output_dir / "report.md").read_text(encoding="utf-8")
            self.assertIn("ENFORCED-FAIL", report)
            self.assertIn("produced only allowlisted findings", report)

    def test_positive_control_fails_when_required_analyzer_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "compare"
            canaries_path = FIXTURE_RUN / "canaries.json"
            renamed_path = FIXTURE_RUN / "canaries.json.disabled"
            canaries_path.rename(renamed_path)
            try:
                result = _run_analyzers(output_dir)
            finally:
                renamed_path.rename(canaries_path)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "required analyzer canary_scan ended as skipped", result.stderr
            )

            summary = json.loads(
                (output_dir / "summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(summary["status"], "error")
            active = next(
                stage for stage in summary["stages"] if stage["stage"] == "active"
            )
            self.assertFalse(active["positiveControlContract"]["satisfied"])
            self.assertIn(
                "required analyzer canary_scan ended as skipped: canary inventory unavailable",
                active["positiveControlContract"]["failures"],
            )

    def test_baseline_stage_keeps_baseline_expectation_label_when_analyzed(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "compare"
            cmd = [
                sys.executable,
                str(RUN_ANALYZERS),
                "--run-dir",
                str(FIXTURE_RUN),
                "--output",
                str(output_dir),
                "--baseline-dir",
                str(FIXTURE_RUN / "baseline"),
                "--stage",
                "baseline",
            ]
            result = subprocess.run(
                cmd, check=False, cwd=ROOT, text=True, capture_output=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            summary = json.loads(
                (output_dir / "summary.json").read_text(encoding="utf-8")
            )
            baseline = next(
                stage for stage in summary["stages"] if stage["stage"] == "baseline"
            )
            self.assertEqual(baseline["expectation"]["kind"], "baseline")
            self.assertFalse(baseline["expectation"]["expectedFindings"])


if __name__ == "__main__":
    unittest.main()
