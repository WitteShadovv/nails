import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUN_ANALYZERS = ROOT / "nix" / "forensics-eval" / "analyzers" / "run_analyzers.py"
RENDER_CAMPAIGN = (
    ROOT / "nix" / "forensics-eval" / "analyzers" / "render_campaign_summary.py"
)
FIXTURE_RUN = ROOT / "nix" / "forensics-eval" / "fixtures" / "samples" / "sample-run"


class CampaignSummaryTest(unittest.TestCase):
    def test_campaign_summary_aggregates_stage_and_analyzer_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            campaign_dir = Path(tmp)
            for run_id in ("run-a", "run-b"):
                output_dir = campaign_dir / run_id / "compare"
                output_dir.mkdir(parents=True, exist_ok=True)
                subprocess.run(
                    [
                        sys.executable,
                        str(RUN_ANALYZERS),
                        "--run-dir",
                        str(FIXTURE_RUN),
                        "--output",
                        str(output_dir),
                        "--baseline-dir",
                        str(FIXTURE_RUN / "baseline"),
                        "--run-id",
                        run_id,
                        "--iteration",
                        "1",
                        "--stage",
                        "active",
                        "--stage",
                        "post-standard",
                        "--stage",
                        "post-emergency",
                    ],
                    check=True,
                    cwd=ROOT,
                )

            subprocess.run(
                [
                    sys.executable,
                    str(RENDER_CAMPAIGN),
                    "--campaign-dir",
                    str(campaign_dir),
                ],
                check=True,
                cwd=ROOT,
            )
            summary = json.loads(
                (campaign_dir / "campaign-summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(summary["runCount"], 2)
            self.assertTrue(
                any(stage["stage"] == "active" for stage in summary["stageTotals"])
            )
            self.assertTrue(
                any(
                    analyzer["analyzer"] == "fls_oracle"
                    for analyzer in summary["analyzerTotals"]
                )
            )
            report = (campaign_dir / "campaign-summary.md").read_text(encoding="utf-8")
            self.assertIn("## Stage coverage", report)
            self.assertIn("## Analyzer coverage", report)


if __name__ == "__main__":
    unittest.main()
