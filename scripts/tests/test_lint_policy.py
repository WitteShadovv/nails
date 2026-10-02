"""Keep the compile-time lint policy switched on for every crate.

The policy lives in `[workspace.lints]` of the root Cargo.toml, but it only
applies to a crate whose manifest opts in with `[lints] workspace = true`. A new
member without that line, or a crate-wide `#![allow(unsafe_code)]`, would turn
the unsafe-code denial off without any build failing, so this scan fails instead.
"""

from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CLIPPY_LINTS = ("undocumented_unsafe_blocks", "too_many_lines", "cognitive_complexity")
TEST_ONLY_UNSAFE_ALLOW = "#![cfg_attr(test, allow(unsafe_code))]"


def load(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


class LintPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = load(REPO_ROOT / "Cargo.toml")

    def test_workspace_denies_unsafe_and_enables_the_clippy_lints(self) -> None:
        lints = self.workspace["workspace"]["lints"]
        self.assertEqual(lints["rust"]["unsafe_code"], "deny")
        for lint in CLIPPY_LINTS:
            with self.subTest(lint=lint):
                self.assertIn(lints["clippy"][lint], ("warn", "deny"))

    def test_every_member_inherits_the_workspace_lints(self) -> None:
        members = self.workspace["workspace"]["members"]
        self.assertTrue(members)
        for member in members:
            with self.subTest(member=member):
                manifest = load(REPO_ROOT / member / "Cargo.toml")
                self.assertEqual(manifest.get("lints"), {"workspace": True})

    def test_clippy_thresholds_are_set(self) -> None:
        config = load(REPO_ROOT / "clippy.toml")
        for key in ("too-many-lines-threshold", "cognitive-complexity-threshold"):
            with self.subTest(key=key):
                self.assertIsInstance(config[key], int)

    def test_unsafe_is_allowed_file_wide_only_for_tests(self) -> None:
        # An inner attribute covers a whole crate or module file, so the only
        # one that may mention unsafe_code is the cfg(test) allow.
        for member in self.workspace["workspace"]["members"]:
            for source in sorted((REPO_ROOT / member / "src").rglob("*.rs")):
                for line in source.read_text(encoding="utf-8").splitlines():
                    attribute = line.strip()
                    if (
                        attribute.startswith("#![")
                        and "unsafe_code" in attribute
                        and attribute != TEST_ONLY_UNSAFE_ALLOW
                    ):
                        self.fail(f"{source.relative_to(REPO_ROOT)}: {attribute}")

    def test_library_roots_allow_unsafe_in_tests(self) -> None:
        for member in self.workspace["workspace"]["members"]:
            with self.subTest(member=member):
                root = (REPO_ROOT / member / "src" / "lib.rs").read_text("utf-8")
                self.assertIn(TEST_ONLY_UNSAFE_ALLOW, root)


if __name__ == "__main__":
    unittest.main()
