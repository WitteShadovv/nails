"""Parser tests for the host-side disk forensics module.

These run in the fast lane (`python3 -m unittest`, no VM, no root) against real
tool output captured once under `fixtures/forensics/`. They lock the parsers
that the VM forensic tests rely on: a silent parser regression would otherwise
turn every leak into a false pass.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

import disk_forensics as df

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "forensics"
_INDICATORS = Path(__file__).resolve().parents[2] / "fixtures" / "indicators.json"


def _read(name: str) -> str:
    return (_FIXTURES / name).read_text(encoding="utf-8")


class ParseFlsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.entries = df.parse_fls(_read("fls-sample.txt"))
        self.by_path = {entry.path: entry for entry in self.entries}

    def test_relative_paths_have_no_leading_slash(self) -> None:
        self.assertTrue(self.entries)
        for entry in self.entries:
            self.assertFalse(entry.path.startswith("/"), entry.path)

    def test_tab_separates_meta_from_name(self) -> None:
        entry = self.by_path["etc/nixos/configuration.nix"]
        self.assertEqual(entry.inode, "13")
        self.assertEqual(entry.name_type, "r")
        self.assertFalse(entry.deleted)

    def test_deleted_marker_is_parsed(self) -> None:
        entry = self.by_path["home/testuser/canary-document.txt"]
        self.assertTrue(entry.deleted)
        self.assertEqual(entry.inode, "5120")

    def test_compound_inode_is_kept_verbatim(self) -> None:
        entry = self.by_path["tmp/nails-canary-temp"]
        self.assertTrue(entry.deleted)
        self.assertEqual(entry.inode, "5121-128-2")

    def test_realloc_suffix_is_stripped_but_name_kept(self) -> None:
        entry = self.by_path["home/testuser/secret-project.txt"]
        self.assertTrue(entry.reallocated)
        self.assertTrue(entry.deleted)
        self.assertNotIn("realloc", entry.path)

    def test_directory_and_link_types(self) -> None:
        self.assertEqual(self.by_path["mnt/nails-pivot"].name_type, "d")
        self.assertEqual(self.by_path["run/nails"].name_type, "l")

    def test_fls_paths_includes_deleted_names(self) -> None:
        paths = df.fls_paths(self.entries)
        self.assertIn("home/testuser/canary-document.txt", paths)
        self.assertIn(
            "nix/store/qz9hidden0000000000000000000000-nails-session-nonce", paths
        )

    def test_blank_and_tabless_lines_are_ignored(self) -> None:
        mixed = "\n\nr/r 1:\tetc/hosts\nnot a real line without a tab\n"
        parsed = df.parse_fls(mixed)
        self.assertEqual([e.path for e in parsed], ["etc/hosts"])


class ScanTokensTest(unittest.TestCase):
    def test_strings_hit_finds_planted_canary(self) -> None:
        text = _read("strings-sample.txt")
        hits = df.scan_tokens(text, ["NAILS_CANARY_STRINGS_7f3a2b", "absent-token"])
        self.assertEqual(hits, {"NAILS_CANARY_STRINGS_7f3a2b"})

    def test_journal_hit_finds_planted_canary(self) -> None:
        text = _read("journal-sample.txt")
        hits = df.scan_tokens(text, ["NAILS_CANARY_JOURNAL_9c1d4e"])
        self.assertEqual(hits, {"NAILS_CANARY_JOURNAL_9c1d4e"})

    def test_empty_token_never_matches(self) -> None:
        self.assertEqual(df.scan_tokens("anything", [""]), set())

    def test_absent_tokens_yield_empty_set(self) -> None:
        self.assertEqual(df.scan_tokens("clean", ["leak"]), set())


class StoreDbTest(unittest.TestCase):
    def setUp(self) -> None:
        self.paths = df.read_valid_paths(_FIXTURES / "store.sqlite")

    def test_reads_every_valid_path(self) -> None:
        self.assertEqual(len(self.paths), 3)

    def test_hidden_store_path_is_detected(self) -> None:
        hits = df.store_path_hits(self.paths, ["nails-session-nonce", "coreutils"])
        self.assertIn("nails-session-nonce", hits)
        self.assertIn("coreutils", hits)

    def test_absent_token_not_in_store(self) -> None:
        hits = df.store_path_hits(self.paths, ["never-registered-pkg"])
        self.assertEqual(hits, set())


class DiffTest(unittest.TestCase):
    def test_diff_returns_only_additions(self) -> None:
        before = {"a", "b", "c"}
        after = {"b", "c", "d", "e"}
        self.assertEqual(df.diff(before, after), {"d", "e"})

    def test_baseline_strings_are_not_leaks(self) -> None:
        # A token present in both baseline and post image is decoy-native and
        # must not count: this is what keeps "configuration.nix" quiet.
        before = df.fls_paths(df.parse_fls(_read("fls-sample.txt")))
        after = set(before) | {"home/testuser/brand-new-leak.txt"}
        self.assertEqual(df.diff(before, after), {"home/testuser/brand-new-leak.txt"})


class IndicatorsIntegrationTest(unittest.TestCase):
    """The registry feeds the VM scans; keep it loadable and non-empty here."""

    def test_image_tokens_are_present_and_scannable(self) -> None:
        data = json.loads(_INDICATORS.read_text(encoding="utf-8"))
        tokens = [a["image_token"] for a in data["artifacts"]]
        self.assertTrue(tokens)
        for token in tokens:
            self.assertTrue(token, "empty image_token in registry")
        # The parsers accept the real registry tokens without choking.
        self.assertIsInstance(df.scan_tokens("no tokens here", tokens), set)


if __name__ == "__main__":
    unittest.main()
