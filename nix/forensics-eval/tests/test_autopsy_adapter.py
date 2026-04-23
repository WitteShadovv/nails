import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ANALYZERS_DIR = Path(__file__).resolve().parents[1] / "analyzers"
if str(ANALYZERS_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYZERS_DIR))

from framework import AllowlistProfile, AnalyzerContext
from plugins.autopsy_adapter import AutopsyAdapter


def make_context(root: Path):
    return AnalyzerContext(
        run_dir=root,
        output_dir=root / "out",
        scratch_dir=root / "scratch",
        baseline_dir=None,
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


class AutopsyAdapterTests(unittest.TestCase):
    def test_skips_when_export_is_absent_and_autopsy_is_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage_dir = root / "active"
            stage_dir.mkdir()

            with patch("plugins.autopsy_adapter.shutil.which", return_value=None):
                result = AutopsyAdapter().analyze(
                    make_context(root), "active", stage_dir
                )

            self.assertEqual(result.status, "skipped")
            self.assertEqual(
                result.summary["reason"],
                "autopsy unavailable and no export supplied",
            )

    def test_skips_when_export_is_absent_even_if_autopsy_is_installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage_dir = root / "active"
            stage_dir.mkdir()

            with patch(
                "plugins.autopsy_adapter.shutil.which", return_value="/usr/bin/autopsy"
            ):
                result = AutopsyAdapter().analyze(
                    make_context(root), "active", stage_dir
                )

            self.assertEqual(result.status, "skipped")
            self.assertEqual(
                result.summary["reason"],
                "autopsy export not supplied; external ingest intentionally not invoked",
            )

    def test_reports_findings_from_minimal_synthetic_autopsy_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage_dir = root / "active"
            stage_dir.mkdir()

            export_dir = stage_dir / "autopsy-export"
            export_dir.mkdir()
            (export_dir / "report.txt").write_text(
                "TOKEN-1 and TOKEN-2",
                encoding="utf-8",
            )

            analyzer = AutopsyAdapter(options={"patterns": {"custom": r"TOKEN-\d"}})
            with patch("plugins.autopsy_adapter.shutil.which", return_value=None):
                result = analyzer.analyze(make_context(root), "active", stage_dir)

            self.assertEqual(result.status, "finding")
            self.assertEqual(result.summary["baselineAware"], False)
            self.assertEqual(result.metrics["observedHits"], 2)
            self.assertEqual(result.metrics["preservedFindings"], 1)
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(
                [item.snippet for item in result.findings[0].evidence],
                ["TOKEN-1", "TOKEN-2"],
            )
            self.assertEqual(
                result.findings[0].evidence[0].path, "autopsy-export/report.txt"
            )


if __name__ == "__main__":
    unittest.main()
