import sys
import tempfile
import unittest
from pathlib import Path


ANALYZERS_DIR = Path(__file__).resolve().parents[1] / "analyzers"
if str(ANALYZERS_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYZERS_DIR))

from framework import AllowlistProfile, AnalyzerContext
from plugins.indicator_scan import DEFAULT_PATTERNS, IndicatorScanAnalyzer


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


class IndicatorScanAnalyzerTests(unittest.TestCase):
    def test_default_patterns_match_paths_and_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage_dir = root / "active"
            stage_dir.mkdir()

            browser_path = stage_dir / "apps/tor-browser-profile.txt"
            browser_path.parent.mkdir(parents=True)
            browser_path.write_text("benign", encoding="utf-8")

            notes = stage_dir / "notes.txt"
            notes.write_text("use /mnt/hidden then nails activate", encoding="utf-8")

            result = IndicatorScanAnalyzer().analyze(
                make_context(root), "active", stage_dir
            )

            self.assertEqual(result.status, "finding")
            self.assertEqual(result.summary["baselineAware"], True)
            self.assertEqual(result.summary["patternCount"], len(DEFAULT_PATTERNS))
            self.assertEqual(result.metrics["observedHits"], 3)
            self.assertEqual(len(result.findings), 3)

            descriptions = {finding.description for finding in result.findings}
            self.assertIn(
                "Indicator set 'browser-or-pkg' matched stage evidence.", descriptions
            )
            self.assertIn(
                "Indicator set 'hidden-mount' matched stage evidence.", descriptions
            )
            self.assertIn(
                "Indicator set 'nails-command' matched stage evidence.", descriptions
            )

    def test_baseline_equivalent_indicator_hits_are_suppressed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline_dir = root / "baseline"
            stage_dir = root / "active"
            baseline_dir.mkdir()
            stage_dir.mkdir()

            baseline_file = baseline_dir / "docs/plan.txt"
            baseline_file.parent.mkdir(parents=True)
            baseline_file.write_text("Operation Nightingale", encoding="utf-8")

            stage_file = stage_dir / "docs/plan.txt"
            stage_file.parent.mkdir(parents=True)
            stage_file.write_text("Operation Nightingale", encoding="utf-8")

            extra_file = stage_dir / "docs/extra.txt"
            extra_file.write_text("Operation Nightingale", encoding="utf-8")

            result = IndicatorScanAnalyzer().analyze(
                make_context(root, baseline_dir=baseline_dir),
                "active",
                stage_dir,
            )

            self.assertEqual(result.status, "finding")
            self.assertEqual(result.metrics["observedHits"], 2)
            self.assertEqual(result.metrics["baselineEquivalentHits"], 1)
            self.assertEqual(result.metrics["preservedFindings"], 1)
            self.assertEqual(len(result.findings), 1)

            evidence = result.findings[0].evidence
            self.assertEqual(len(evidence), 1)
            self.assertEqual(evidence[0].path, "docs/extra.txt")
            self.assertEqual(evidence[0].snippet, "Operation Nightingale")


if __name__ == "__main__":
    unittest.main()
