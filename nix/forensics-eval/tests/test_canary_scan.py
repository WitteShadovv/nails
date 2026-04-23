import sys
import tempfile
import unittest
from pathlib import Path


ANALYZERS_DIR = Path(__file__).resolve().parents[1] / "analyzers"
if str(ANALYZERS_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYZERS_DIR))

from framework import AllowlistProfile, AnalyzerContext
from plugins.canary_scan import CanaryScanAnalyzer


def make_context(root: Path, *, baseline_dir: Path | None = None, canaries=None):
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
        canaries=canaries,
        allowlist=AllowlistProfile.empty(),
    )


class CanaryScanAnalyzerTests(unittest.TestCase):
    def test_reports_path_and_content_hits_but_ignores_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage_dir = root / "active"
            stage_dir.mkdir()

            canary_token = "NAILS-CANARY-123"
            canaries = {
                "namespace": "tests",
                "entries": [{"label": "alpha", "token": canary_token}],
            }

            path_hit = stage_dir / f"logs/{canary_token}-trace.txt"
            path_hit.parent.mkdir(parents=True)
            path_hit.write_text("benign", encoding="utf-8")

            content_hit = stage_dir / "notes.txt"
            content_hit.write_text(f"found {canary_token} in content", encoding="utf-8")

            external_target = root / "external.txt"
            external_target.write_text(canary_token, encoding="utf-8")
            (stage_dir / f"{canary_token}-link.txt").symlink_to(external_target)

            result = CanaryScanAnalyzer().analyze(
                make_context(root, canaries=canaries),
                "active",
                stage_dir,
            )

            self.assertEqual(result.status, "finding")
            self.assertEqual(result.summary["canaryNamespace"], "tests")
            self.assertEqual(result.metrics["observedHits"], 2)
            self.assertEqual(result.metrics["baselineEquivalentHits"], 0)
            self.assertEqual(len(result.findings), 1)

            evidence = {
                (item.type, item.path, item.snippet) for item in result.evidence
            }
            self.assertIn(
                ("path", f"logs/{canary_token}-trace.txt", canary_token), evidence
            )
            self.assertIn(("content", "notes.txt", canary_token), evidence)
            self.assertFalse(any("link.txt" in item.path for item in result.evidence))

    def test_suppresses_baseline_equivalent_hits_and_preserves_new_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline_dir = root / "baseline"
            stage_dir = root / "active"
            baseline_dir.mkdir()
            stage_dir.mkdir()

            canary_token = "NAILS-CANARY-456"
            canaries = {
                "entries": [{"label": "alpha", "token": canary_token}],
            }

            baseline_file = baseline_dir / f"same/{canary_token}.txt"
            baseline_file.parent.mkdir(parents=True)
            baseline_file.write_text(canary_token, encoding="utf-8")

            stage_file = stage_dir / f"same/{canary_token}.txt"
            stage_file.parent.mkdir(parents=True)
            stage_file.write_text(canary_token, encoding="utf-8")

            new_file = stage_dir / "new.txt"
            new_file.write_text(canary_token, encoding="utf-8")

            result = CanaryScanAnalyzer().analyze(
                make_context(root, baseline_dir=baseline_dir, canaries=canaries),
                "active",
                stage_dir,
            )

            self.assertEqual(result.status, "finding")
            self.assertEqual(result.metrics["observedHits"], 3)
            self.assertEqual(result.metrics["baselineEquivalentHits"], 2)
            self.assertEqual(result.metrics["preservedFindings"], 1)
            self.assertEqual(len(result.findings), 1)
            self.assertEqual(len(result.findings[0].evidence), 1)

            preserved = result.findings[0].evidence[0]
            self.assertEqual(preserved.type, "content")
            self.assertEqual(preserved.path, "new.txt")
            self.assertEqual(preserved.snippet, canary_token)


if __name__ == "__main__":
    unittest.main()
