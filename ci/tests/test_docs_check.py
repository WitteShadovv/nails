"""Tests for ci.docs_check."""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from ci import docs_check


class CheckRealRepo(unittest.TestCase):
    def test_docs_document_every_workflow(self) -> None:
        undocumented, stale = docs_check.check()
        self.assertEqual(undocumented, set(), "workflows missing from docs/ci.md")
        self.assertEqual(stale, set(), "docs/ci.md names a workflow that is gone")


class CheckFixtures(unittest.TestCase):
    def _layout(self, workflows: list[str], doc_body: str) -> tuple[Path, Path]:
        root = Path(self.tmp)
        wf_dir = root / "workflows"
        wf_dir.mkdir()
        for name in workflows:
            (wf_dir / name).write_text("name: x\n", encoding="utf-8")
        doc = root / "ci.md"
        doc.write_text(doc_body, encoding="utf-8")
        return wf_dir, doc

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.tmp = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def test_all_documented_is_clean(self) -> None:
        wf_dir, doc = self._layout(
            ["ci.yml", "e2e.yml"],
            "`.github/workflows/ci.yml` and `.github/workflows/e2e.yml`\n",
        )
        self.assertEqual(docs_check.check(wf_dir, doc), (set(), set()))

    def test_detects_an_undocumented_workflow(self) -> None:
        wf_dir, doc = self._layout(
            ["ci.yml", "e2e.yml"],
            "`.github/workflows/ci.yml`\n",
        )
        undocumented, stale = docs_check.check(wf_dir, doc)
        self.assertEqual(undocumented, {"e2e.yml"})
        self.assertEqual(stale, set())

    def test_detects_a_stale_reference(self) -> None:
        wf_dir, doc = self._layout(
            ["ci.yml"],
            "`.github/workflows/ci.yml` and `.github/workflows/old.yml`\n",
        )
        undocumented, stale = docs_check.check(wf_dir, doc)
        self.assertEqual(undocumented, set())
        self.assertEqual(stale, {"old.yml"})


if __name__ == "__main__":
    unittest.main()
