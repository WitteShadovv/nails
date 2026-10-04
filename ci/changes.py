"""Decide which ci.yml jobs a pull request needs.

The ``changes`` job in ci.yml runs this once, and every other job is gated on
its outputs, so the path rules live here and nowhere else. Each filter is a
pattern over repository paths; it is true when at least one changed path
matches it, and a job runs when one of its filters is true.

Only pull requests are filtered. Without a base revision (a push to main, a
manual run) every filter is true: those runs are unattended, they keep the
shared Rust cache warm, and a skipped job could never close the CI red issue.
An unknown base revision counts as a change to everything, and so does a
change to ci.yml or to this file, since either can alter any job.

Usage: python3 -m ci.changes [--base REV]

Prints one ``name=true|false`` line per filter, the format of
``$GITHUB_OUTPUT``, and explains the decision on stderr.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path

FILTERS: dict[str, re.Pattern[str]] = {
    # Everything cargo reads, plus the files that decide how the Rust jobs run.
    "rust": re.compile(
        r"^(nails-cli/|nails-core/|benches/|\.cargo/|\.config/nextest\.toml$"
        r"|Cargo\.(toml|lock)$|rust-toolchain\.toml$|(clippy|rustfmt)\.toml$"
        r"|justfile$|scripts/check-[^/]+\.sh$)"
    ),
    # The dependency graph and its policy; the advisory check gates on these.
    "deps": re.compile(r"^(Cargo\.lock|deny\.toml|(.+/)?Cargo\.toml)$"),
    # The flake and what it evaluates besides the Rust sources.
    "nix": re.compile(r"^(flake\.(nix|lock)$|nix/|\.github/actions/setup-nix/)|\.nix$"),
    # The CI tooling: workflows, composite actions, the ci package, scripts.
    "workflows": re.compile(r"^(\.github/|ci/|scripts/|pyproject\.toml$)|\.sh$"),
    # The Markdown docs and the checker that lints them.
    "docs": re.compile(r"\.md$|^scripts/docs-check\.sh$"),
}

# A change to one of these can alter any job, so it runs them all.
RUN_EVERYTHING = frozenset({".github/workflows/ci.yml", "ci/changes.py"})


def everything() -> dict[str, bool]:
    return dict.fromkeys(FILTERS, True)


def select(paths: Iterable[str]) -> dict[str, bool]:
    """Evaluate every filter over the changed ``paths``."""
    paths = list(paths)
    if RUN_EVERYTHING.intersection(paths):
        return everything()
    return {
        name: any(pattern.search(path) for path in paths)
        for name, pattern in FILTERS.items()
    }


def changed_paths(base: str, repo: Path | None = None) -> list[str] | None:
    """Paths that differ between ``base`` and HEAD; None when ``base`` is unknown."""
    known = subprocess.run(
        ["git", "rev-parse", "--quiet", "--verify", f"{base}^{{commit}}"],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    if known.returncode != 0:
        return None
    # --no-renames lists a moved file under its old and its new path, so moving
    # a file out of a filtered directory still counts as a change there.
    diff = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", "-z", base, "HEAD"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return [path for path in diff.stdout.split("\0") if path]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m ci.changes",
        description="Print which ci.yml path filters a change matches.",
    )
    parser.add_argument(
        "--base",
        help="revision to compare HEAD with; without it every filter is true",
    )
    args = parser.parse_args(argv)

    if args.base is None:
        print("No base revision: every job runs.", file=sys.stderr)
        outputs = everything()
    else:
        paths = changed_paths(args.base)
        if paths is None:
            print(f"Unknown base {args.base}: every job runs.", file=sys.stderr)
            outputs = everything()
        else:
            print(f"{len(paths)} path(s) changed since {args.base}.", file=sys.stderr)
            outputs = select(paths)

    for name, value in outputs.items():
        print(f"{name}={str(value).lower()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
