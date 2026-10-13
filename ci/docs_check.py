"""Check that docs/ci.md lists every workflow and no workflow that is gone.

The CI documentation carries a table of every workflow; a workflow added or
removed without updating the table leaves the docs lying. ``just docs-check``
runs this, and the ci/tests suite runs it against the repository too, so the
drift fails CI as well as a local check.

A workflow counts as documented when docs/ci.md mentions its path,
``.github/workflows/<name>.yml``. Composite actions under
``.github/actions/`` are not workflows and are not checked here.

Usage: python3 -m ci.docs_check
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORKFLOW_DIR = REPO / ".github" / "workflows"
DOC = REPO / "docs" / "ci.md"

# Every reference to a workflow file, wherever it appears in the document.
REFERENCE = re.compile(r"\.github/workflows/([A-Za-z0-9._-]+\.yml)")


def workflow_files(workflow_dir: Path = WORKFLOW_DIR) -> set[str]:
    """The names of the workflow files that exist."""
    return {path.name for path in workflow_dir.glob("*.yml")}


def documented_workflows(doc: Path = DOC) -> set[str]:
    """The workflow file names docs/ci.md refers to."""
    return set(REFERENCE.findall(doc.read_text(encoding="utf-8")))


def check(
    workflow_dir: Path = WORKFLOW_DIR, doc: Path = DOC
) -> tuple[set[str], set[str]]:
    """Return (undocumented, stale) workflow names.

    ``undocumented`` are workflow files the doc never mentions; ``stale`` are
    names the doc mentions that have no file.
    """
    files = workflow_files(workflow_dir)
    documented = documented_workflows(doc)
    return files - documented, documented - files


def main(argv: list[str] | None = None) -> int:
    undocumented, stale = check()
    problems = []
    if undocumented:
        problems.append(
            "not documented in docs/ci.md: " + ", ".join(sorted(undocumented))
        )
    if stale:
        problems.append(
            "documented in docs/ci.md but missing: " + ", ".join(sorted(stale))
        )
    if problems:
        for problem in problems:
            print(f"docs/ci.md workflow table: {problem}", file=sys.stderr)
        return 1
    print(f"docs/ci.md documents all {len(workflow_files())} workflows.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
