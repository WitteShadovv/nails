import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "run-forensics-eval.sh"
FIXTURE_RUN = ROOT / "nix" / "forensics-eval" / "fixtures" / "samples" / "sample-run"


class FixtureCampaignDeterminismTest(unittest.TestCase):
    def test_two_iteration_fixture_campaign_has_expected_active_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "campaign"
            subprocess.run(
                [
                    str(SCRIPT),
                    "--fixture-run-dir",
                    str(FIXTURE_RUN),
                    "--iterations",
                    "2",
                    "--out",
                    str(out_dir),
                ],
                check=True,
                cwd=ROOT,
            )
            campaign_summary = json.loads(
                (out_dir / "campaign-summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(campaign_summary["runCount"], 2)
            self.assertTrue(
                any(
                    stage["stage"] == "active"
                    for stage in campaign_summary["stageTotals"]
                )
            )

            compare_summaries = sorted(out_dir.glob("*/compare/summary.json"))
            self.assertEqual(len(compare_summaries), 2)
            finding_counts = []
            for path in compare_summaries:
                summary = json.loads(path.read_text(encoding="utf-8"))
                active = next(
                    stage for stage in summary["stages"] if stage["stage"] == "active"
                )
                self.assertEqual(active["expectation"]["kind"], "positive-control")
                self.assertTrue(active["findingCount"] > 0)
                finding_counts.append(summary["totals"]["findings"])
            self.assertEqual(finding_counts[0], finding_counts[1])


if __name__ == "__main__":
    unittest.main()
