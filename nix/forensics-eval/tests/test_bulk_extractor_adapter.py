import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ANALYZERS_DIR = Path(__file__).resolve().parents[1] / "analyzers"
if str(ANALYZERS_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYZERS_DIR))

from framework import AllowlistProfile, AnalyzerContext
from plugins.bulk_extractor_adapter import BulkExtractorAdapter


def make_context(root: Path, *, baseline_dir: Path | None = None):
    return AnalyzerContext(
        run_dir=root,
        output_dir=root / "out",
        scratch_dir=root / "scratch",
        baseline_dir=baseline_dir,
        stages={},
        profile="default",
        scenario_id="scenario",
        run_id="run",
        iteration=None,
        manifest={},
        scenario=None,
        canaries=None,
        allowlist=AllowlistProfile.empty(),
    )


class BulkExtractorAdapterTests(unittest.TestCase):
    def test_skips_when_tool_and_exports_are_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage_dir = root / "active"
            stage_dir.mkdir()

            with patch(
                "plugins.bulk_extractor_adapter.shutil.which", return_value=None
            ):
                result = BulkExtractorAdapter().analyze(
                    make_context(root),
                    "active",
                    stage_dir,
                )

            self.assertEqual(result.status, "skipped")
            self.assertEqual(
                result.summary["reason"],
                "bulk_extractor unavailable and no bulk output supplied",
            )

    def test_skips_when_tool_exists_but_no_export_is_supplied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage_dir = root / "active"
            stage_dir.mkdir()

            with patch(
                "plugins.bulk_extractor_adapter.shutil.which",
                return_value="/usr/bin/bulk_extractor",
            ):
                result = BulkExtractorAdapter().analyze(
                    make_context(root),
                    "active",
                    stage_dir,
                )

            self.assertEqual(result.status, "skipped")
            self.assertEqual(
                result.summary["reason"],
                "bulk_extractor present but no exported bulk evidence supplied",
            )

    def test_reports_only_non_baseline_bulk_matches_from_synthetic_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline_dir = root / "baseline"
            stage_dir = root / "active"
            baseline_dir.mkdir()
            stage_dir.mkdir()

            baseline_bulk = baseline_dir / "bulk-baseline"
            baseline_bulk.mkdir()
            (baseline_bulk / "report.txt").write_text("LEAK-ONE\n", encoding="utf-8")

            stage_bulk = stage_dir / "bulk-stage"
            stage_bulk.mkdir()
            (stage_bulk / "report.txt").write_text(
                "LEAK-ONE\nLEAK-TWO\n",
                encoding="utf-8",
            )

            analyzer = BulkExtractorAdapter(
                options={"patterns": {"custom": r"LEAK-[A-Z]+"}}
            )
            with patch(
                "plugins.bulk_extractor_adapter.shutil.which", return_value=None
            ):
                result = analyzer.analyze(
                    make_context(root, baseline_dir=baseline_dir),
                    "active",
                    stage_dir,
                )

            self.assertEqual(result.status, "finding")
            self.assertEqual(result.metrics["bulkDirCount"], 1)
            self.assertEqual(result.metrics["observedHits"], 2)
            self.assertEqual(result.metrics["baselineEquivalentHits"], 1)
            self.assertEqual(result.metrics["preservedFindings"], 1)
            self.assertEqual(result.summary["bulkExtractorAvailable"], False)
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(len(result.findings[0].evidence), 1)
            self.assertEqual(
                result.findings[0].evidence[0].path, "bulk-stage/report.txt"
            )
            self.assertEqual(result.findings[0].evidence[0].snippet, "LEAK-TWO")


if __name__ == "__main__":
    unittest.main()
