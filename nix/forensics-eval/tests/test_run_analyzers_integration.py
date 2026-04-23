from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
FORENSICS_EVAL_ROOT = REPO_ROOT / "nix" / "forensics-eval"
SAMPLE_RUN_DIR = FORENSICS_EVAL_ROOT / "fixtures" / "samples" / "sample-run"
RUN_ANALYZERS_SCRIPT = FORENSICS_EVAL_ROOT / "analyzers" / "run_analyzers.py"


def _load_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load module {module_name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class RunAnalyzersIntegrationTests(unittest.TestCase):
    def test_run_analyzers_writes_expected_fixture_outputs(self):
        module = _load_module(
            "forensics_eval_test_run_analyzers_integration",
            RUN_ANALYZERS_SCRIPT,
        )

        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "compare"

            exit_code = module.main(
                [
                    "--run-dir",
                    str(SAMPLE_RUN_DIR),
                    "--baseline-dir",
                    str(SAMPLE_RUN_DIR / "baseline"),
                    "--output",
                    str(output_dir),
                    "--stage",
                    "post-standard",
                    "--stage",
                    "post-emergency",
                ]
            )

            self.assertEqual(exit_code, 0)

            summary_path = output_dir / "summary.json"
            report_path = output_dir / "report.md"
            diff_json_path = output_dir / "findings-diff.json"
            diff_md_path = output_dir / "findings-diff.md"

            self.assertTrue(summary_path.is_file())
            self.assertTrue(report_path.is_file())
            self.assertTrue(diff_json_path.is_file())
            self.assertTrue(diff_md_path.is_file())
            self.assertGreater(report_path.stat().st_size, 0)
            self.assertGreater(diff_md_path.stat().st_size, 0)

            summary = _read_json(summary_path)
            diff_summary = _read_json(diff_json_path)

            self.assertEqual(summary["runId"], "sample-run-001")
            self.assertEqual(summary["profileId"], "direct-headless")
            self.assertEqual(summary["scenarioId"], "sample")
            self.assertEqual(summary["status"], "finding")
            self.assertEqual(summary["stageCount"], 2)
            self.assertEqual(
                summary["totals"],
                {
                    "findings": 5,
                    "errors": 0,
                    "skipped": 3,
                    "clean": 2,
                    "analyzers": 10,
                },
            )

            stage_summary = {entry["stage"]: entry for entry in summary["stages"]}
            self.assertEqual(set(stage_summary), {"post-standard", "post-emergency"})
            self.assertEqual(stage_summary["post-standard"]["status"], "finding")
            self.assertEqual(stage_summary["post-standard"]["resultCount"], 5)
            self.assertGreater(stage_summary["post-standard"]["findingCount"], 0)
            self.assertEqual(stage_summary["post-emergency"]["status"], "finding")
            self.assertEqual(stage_summary["post-emergency"]["resultCount"], 5)
            self.assertGreater(stage_summary["post-emergency"]["findingCount"], 0)

            self.assertEqual(
                set(diff_summary["stages"]), {"post-standard", "post-emergency"}
            )
            self.assertGreater(
                diff_summary["stages"]["post-standard"]["findingCount"], 0
            )
            self.assertGreater(
                diff_summary["stages"]["post-emergency"]["findingCount"], 0
            )
            self.assertGreater(
                diff_summary["stages"]["post-standard"]["findingCount"],
                diff_summary["stages"]["post-emergency"]["findingCount"],
            )
            self.assertEqual(len(diff_summary["comparisons"]), 1)
            self.assertEqual(diff_summary["comparisons"][0]["left"], "post-standard")
            self.assertEqual(diff_summary["comparisons"][0]["right"], "post-emergency")

            expected_statuses = {
                ("post-standard", "path_delta"): "finding",
                ("post-standard", "canary_scan"): "finding",
                ("post-standard", "indicator_scan"): "finding",
                ("post-standard", "bulk_extractor_adapter"): "finding",
                ("post-standard", "autopsy_adapter"): "skipped",
                ("post-emergency", "path_delta"): "finding",
                ("post-emergency", "canary_scan"): "clean",
                ("post-emergency", "indicator_scan"): "clean",
                ("post-emergency", "bulk_extractor_adapter"): "skipped",
                ("post-emergency", "autopsy_adapter"): "skipped",
            }

            for (stage_name, analyzer_id), expected_status in expected_statuses.items():
                with self.subTest(stage=stage_name, analyzer=analyzer_id):
                    result_path = (
                        output_dir / "analyzers" / stage_name / f"{analyzer_id}.json"
                    )
                    self.assertTrue(
                        result_path.is_file(),
                        msg=f"missing analyzer output: {result_path}",
                    )
                    payload = _read_json(result_path)
                    self.assertEqual(payload["stage"], stage_name)
                    self.assertEqual(payload["analyzer"], analyzer_id)
                    self.assertEqual(payload["status"], expected_status)


if __name__ == "__main__":
    unittest.main()
