"""Tests for the justfile's kani recipe, which judges what Kani reports."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
JUSTFILE = REPO_ROOT / "justfile"

PROOF = "#[kani::proof]\nfn proof() {}\n"
COVERED = "#[kani::proof]\nfn covered() {\n    kani::cover!(true);\n}\n"


def kani_recipe() -> str:
    """The script of the justfile's kani recipe, without its indentation."""
    text = JUSTFILE.read_text(encoding="utf-8")
    found = re.search(r"^kani:\n((?:[ \t]+[^\n]*\n|\n)*)", text, re.M)
    if found is None:
        raise AssertionError("no recipe kani in the justfile")
    return textwrap.dedent(found.group(1))


def harness(name: str, covers: str | None = None) -> str:
    """What `cargo kani --output-format terse` prints for one proof it
    verified, with its line on cover properties when ``covers`` gives it."""
    lines = [
        f"Checking harness proofs::{name}...",
        "",
        "VERIFICATION RESULT:",
        " ** 0 of 93 failed (1 unreachable)",
        "",
    ]
    if covers is not None:
        lines += [f" ** {covers} cover properties satisfied", ""]
    lines += ["", "VERIFICATION:- SUCCESSFUL", "Verification Time: 0.25s", ""]
    return "\n".join(lines) + "\n"


def summary(verified: int, total: int) -> str:
    """The summary Kani prints after the last proof."""
    failures = total - verified
    return (
        "Manual Harness Summary:\n"
        f"Complete - {verified} successfully verified harnesses, "
        f"{failures} failures, {total} total.\n"
    )


class KaniRecipeTest(unittest.TestCase):
    def run_recipe(
        self, sources: list[str], report: str, status: int = 0
    ) -> subprocess.CompletedProcess[str]:
        """The recipe, run as just runs it in a tree whose nails-base/src
        holds ``sources``, with a cargo that prints ``report`` and ends with
        ``status``. bash reads no startup file."""
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp, "nails-base", "src")
            src.mkdir(parents=True)
            for number, text in enumerate(sources):
                Path(src, f"proofs_{number}.rs").write_text(text, encoding="utf-8")
            Path(tmp, "report").write_text(report, encoding="utf-8")
            tools = Path(tmp, "bin")
            tools.mkdir()
            cargo = tools / "cargo"
            cargo.write_text(
                f'#!/bin/sh\ncat "{tmp}/report"\nexit {status}\n', encoding="utf-8"
            )
            cargo.chmod(0o755)
            return subprocess.run(
                ["bash", "--norc", "--noprofile", "-c", kani_recipe()],
                cwd=tmp,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=60,
                env={"PATH": f"{tools}{os.pathsep}{os.environ.get('PATH', '')}"},
            )

    def test_every_proof_verified_and_every_cover_satisfied_passes(self) -> None:
        report = harness("covered", "1 of 1") + harness("proof") + summary(2, 2)
        done = self.run_recipe([COVERED, PROOF], report)
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_a_cover_never_satisfied_fails(self) -> None:
        # Kani still counts the proof as verified.
        report = harness("covered", "0 of 1") + harness("proof") + summary(2, 2)
        done = self.run_recipe([COVERED, PROOF], report)
        self.assertEqual(done.returncode, 1)
        self.assertIn("satisfied 0 of the 1 cover properties", done.stderr)

    def test_a_cover_kani_does_not_report_fails(self) -> None:
        report = harness("covered") + harness("proof") + summary(2, 2)
        done = self.run_recipe([COVERED, PROOF], report)
        self.assertEqual(done.returncode, 1)
        self.assertIn("of the 1 in nails-base/src", done.stderr)

    def test_fewer_proofs_verified_than_the_sources_hold_fails(self) -> None:
        report = harness("covered", "1 of 1") + summary(1, 1)
        done = self.run_recipe([COVERED, PROOF], report)
        self.assertEqual(done.returncode, 1)
        self.assertIn("verified 1 of the 2 proofs", done.stderr)

    def test_a_failed_proof_fails(self) -> None:
        report = harness("covered", "1 of 1") + summary(1, 2)
        done = self.run_recipe([COVERED, PROOF], report, status=1)
        self.assertEqual(done.returncode, 1)

    def test_sources_without_a_cover_pass_when_kani_reports_none(self) -> None:
        done = self.run_recipe([PROOF], harness("proof") + summary(1, 1))
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_sources_without_a_proof_fail_with_the_reason(self) -> None:
        done = self.run_recipe(["fn plain() {}\n"], summary(0, 0))
        self.assertEqual(done.returncode, 1)
        self.assertIn("nails-base/src holds no #[kani::proof]", done.stderr)


if __name__ == "__main__":
    unittest.main()
