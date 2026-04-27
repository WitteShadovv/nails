import re
import sys
import tempfile
import unittest
from pathlib import Path


ANALYZERS_DIR = Path(__file__).resolve().parents[1] / "analyzers"
if str(ANALYZERS_DIR) not in sys.path:
    sys.path.insert(0, str(ANALYZERS_DIR))

from framework import AllowlistProfile, AnalyzerContext
from plugins.path_delta import PathDeltaAnalyzer


def make_context(root: Path, *, baseline_dir: Path, allowlist=None):
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
        allowlist=allowlist or AllowlistProfile.empty(),
    )


class PathDeltaAnalyzerTests(unittest.TestCase):
    def test_detects_added_removed_and_changed_files_dirs_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline_dir = root / "baseline"
            stage_dir = root / "active"
            baseline_dir.mkdir()
            stage_dir.mkdir()

            (baseline_dir / "common.txt").write_text("same", encoding="utf-8")
            (stage_dir / "common.txt").write_text("same", encoding="utf-8")

            (baseline_dir / "removed.txt").write_text("removed", encoding="utf-8")
            (baseline_dir / "old-dir").mkdir()
            (baseline_dir / "changed.txt").write_text("before", encoding="utf-8")
            (baseline_dir / "swap-link").symlink_to("target-a")

            (stage_dir / "added.txt").write_text("added", encoding="utf-8")
            (stage_dir / "new-dir").mkdir()
            (stage_dir / "changed.txt").write_text("after", encoding="utf-8")
            (stage_dir / "swap-link").symlink_to("target-b")
            (stage_dir / "added-link").symlink_to("target-c")

            result = PathDeltaAnalyzer().analyze(
                make_context(root, baseline_dir=baseline_dir),
                "active",
                stage_dir,
            )

            self.assertEqual(result.status, "finding")
            self.assertEqual(result.metrics["added"], 3)
            self.assertEqual(result.metrics["removed"], 2)
            self.assertEqual(result.metrics["changed"], 2)
            self.assertEqual(result.metrics["preservedFindings"], 7)

            observed = {
                (finding.id, finding.evidence[0].path, finding.evidence[0].type)
                for finding in result.findings
            }
            self.assertIn(("added-path", "added.txt", "file"), observed)
            self.assertIn(("added-path", "new-dir", "dir"), observed)
            self.assertIn(("added-path", "added-link", "symlink"), observed)
            self.assertIn(("removed-path", "removed.txt", "file"), observed)
            self.assertIn(("removed-path", "old-dir", "dir"), observed)
            self.assertIn(("changed-path", "changed.txt", "file"), observed)
            self.assertIn(("changed-path", "swap-link", "symlink"), observed)

    def test_respects_analyzer_specific_allowlist_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline_dir = root / "baseline"
            stage_dir = root / "active"
            baseline_dir.mkdir()
            stage_dir.mkdir()

            (stage_dir / "ignored.txt").write_text("ignore me", encoding="utf-8")
            (stage_dir / "kept.txt").write_text("keep me", encoding="utf-8")

            allowlist = AllowlistProfile(
                path_patterns=[],
                content_patterns=[],
                finding_ids=set(),
                analyzer_path_patterns={"path_delta": [re.compile(r"ignored\.txt$")]},
                analyzer_content_patterns={},
                analyzer_finding_ids={},
            )

            result = PathDeltaAnalyzer().analyze(
                make_context(root, baseline_dir=baseline_dir, allowlist=allowlist),
                "active",
                stage_dir,
            )

            self.assertEqual(result.status, "finding")
            self.assertEqual(result.metrics["added"], 2)
            self.assertEqual(result.metrics["allowlisted"], 1)
            self.assertEqual(result.metrics["preservedFindings"], 1)
            self.assertEqual(result.findings[0].evidence[0].path, "kept.txt")


if __name__ == "__main__":
    unittest.main()
