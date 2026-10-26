"""Parser tests for the host-side disk forensics module.

These run in the fast lane (`python3 -m unittest`, no VM, no root) against real
tool output captured once under `fixtures/forensics/`. They lock the parsers
that the VM forensic tests rely on: a silent parser regression would otherwise
turn every leak into a false pass.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import random
import re
import subprocess
import tempfile
import unittest
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from unittest import mock

import disk_forensics as df

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "forensics"
_INDICATORS = Path(__file__).resolve().parents[2] / "fixtures" / "indicators.json"
# The allowlist of the NixOS decoys the VM tests boot.
NIXOS = df.image_volatile("nixos")


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


def _strings_model(data: bytes) -> str:
    """A model of ``strings -a`` (7-bit, minimum length 4): one run per line."""
    runs = re.findall(rb"[\t\x20-\x7e]{4,}", data)
    return "\n".join(run.decode("ascii") for run in runs)


class RunStringsScanTest(unittest.TestCase):
    """The native image scan must report exactly what strings + scan_tokens did."""

    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.dir = Path(directory.name)

    def _image(self, chunks: list[tuple[int, bytes]], size: int) -> Path:
        path = self.dir / "disk.raw"
        with path.open("wb") as handle:
            handle.truncate(size)
            for offset, data in chunks:
                handle.seek(offset)
                handle.write(data)
        return path

    def test_finds_a_token_after_a_large_hole(self) -> None:
        image = self._image([(64 << 20, b"\0LEAK_TOKEN_1234\0")], 128 << 20)
        hits = df.run_strings_scan(image, ["LEAK_TOKEN_1234", "absent-token"])
        self.assertEqual(hits, {"LEAK_TOKEN_1234"})

    def test_finds_a_token_straddling_a_read_boundary(self) -> None:
        token = "STRADDLE_TOKEN_abcdef"
        image = self._image([(4096 - 5, token.encode())], 16384)
        with mock.patch.object(df, "_SCAN_CHUNK", 4096):
            self.assertEqual(df.run_strings_scan(image, [token]), {token})

    def test_a_short_token_counts_only_inside_a_printed_run(self) -> None:
        image = self._image([(0, b"abc\x00xyzw\x00tab\there\x00")], 4096)
        # "abc" is a 3-byte run strings never prints; "yz" sits in "xyzw".
        hits = df.run_strings_scan(image, ["abc", "yz", "", "tab\there"])
        self.assertEqual(hits, {"yz", "tab\there"})

    def test_a_token_strings_cannot_print_is_refused(self) -> None:
        image = self._image([(0, b"SPLIT_\nTOKEN\0")], 4096)
        with self.assertRaises(ValueError):
            df.run_strings_scan(image, ["SPLIT_\nTOKEN"])
        with self.assertRaises(ValueError):
            df.run_strings_scan(image, ["caf\u00e9"])
        self.assertEqual(df.run_strings_scan(image, ["SPLIT_TOKEN"]), set())

    def test_matches_the_strings_model_on_random_images(self) -> None:
        rng = random.Random(7)
        alphabet = b"ABCD\t \n\x00\xff"
        tokens = ["ABCD", "ABAB", "A BC", "D\tAB", "CCCCC", "AB", "C"]
        for _ in range(40):
            data = bytes(rng.choice(alphabet) for _ in range(3000))
            offset = rng.randrange(0, 1 << 20)
            image = self._image([(offset, data)], (1 << 20) + 8192)
            expected = df.scan_tokens(_strings_model(data), tokens)
            with mock.patch.object(df, "_SCAN_CHUNK", 257):
                self.assertEqual(df.run_strings_scan(image, tokens), expected)

    def test_data_extents_cover_written_data(self) -> None:
        image = self._image([(1 << 20, b"x" * 10)], 4 << 20)
        with image.open("rb") as handle:
            fd = handle.fileno()
            extents = df._data_extents(fd, os.fstat(fd).st_size)
        self.assertTrue(any(s <= (1 << 20) < e for s, e in extents), extents)


class TokenSnippetTest(unittest.TestCase):
    def test_absent_token_returns_none(self) -> None:
        self.assertIsNone(df.token_snippet("clean content", "leak"))

    def test_empty_token_returns_none(self) -> None:
        self.assertIsNone(df.token_snippet("anything", ""))

    def test_snippet_keeps_context_around_the_hit(self) -> None:
        haystack = "loading config from /mnt/data/config/nails.toml and continuing on"
        snippet = df.token_snippet(haystack, "nails.toml", context=8)
        assert snippet is not None
        self.assertIn("nails.toml", snippet)
        # Context is bounded, so the far ends of the line are trimmed with ellipses.
        self.assertTrue(snippet.startswith("…"))
        self.assertTrue(snippet.endswith("…"))

    def test_snippet_flattens_control_bytes_to_one_line(self) -> None:
        haystack = "a\x00\nstate.json\t\x01b"
        snippet = df.token_snippet(haystack, "state.json")
        assert snippet is not None
        self.assertNotIn("\n", snippet)
        self.assertNotIn("\x00", snippet)
        self.assertIn("state.json", snippet)


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


class BodyfileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.entries = df.parse_bodyfile(_read("bodyfile-sample.txt"))
        self.by_path = {entry.path: entry for entry in self.entries}

    def test_paths_are_relative_and_virtual_entries_skipped(self) -> None:
        self.assertIn("etc/hosts", self.by_path)
        self.assertFalse(any(e.path.startswith("/") for e in self.entries))
        self.assertFalse(any(e.path.startswith("$") for e in self.entries))

    def test_fields_are_parsed(self) -> None:
        hosts = self.by_path["etc/hosts"]
        self.assertEqual(hosts.inode, "14")
        self.assertEqual(hosts.mode, "r/rrw-r--r--")
        self.assertEqual(hosts.size, 3)
        self.assertEqual(hosts.mtime, 1791328642)
        self.assertFalse(hosts.deleted)

    def test_a_name_with_a_pipe_survives(self) -> None:
        self.assertIn("home/testuser/odd|name with space", self.by_path)

    def test_deleted_symlink_loses_marker_and_target(self) -> None:
        link = self.by_path["etc/link"]
        self.assertTrue(link.deleted)
        self.assertNotIn("etc/link", df.bodyfile_index(self.entries))

    def test_malformed_lines_are_skipped(self) -> None:
        self.assertEqual(df.parse_bodyfile("garbage\n0|/x|1|r/r|0|0|nan|1|1|1|1\n"), [])


def _entry(path: str, **changes: object) -> df.BodyEntry:
    base = df.BodyEntry(
        path=path,
        inode="10",
        mode="r/rrw-r--r--",
        uid="0",
        gid="0",
        size=5,
        atime=100,
        mtime=100,
        ctime=100,
        crtime=100,
        deleted=False,
    )
    return replace(base, **changes)  # type: ignore[arg-type]


class MacChangesTest(unittest.TestCase):
    def test_changed_fields_of_existing_paths(self) -> None:
        before = {"a": _entry("a"), "b": _entry("b"), "gone": _entry("gone")}
        after = {
            "a": _entry("a", mtime=200, ctime=200),
            "b": _entry("b", atime=300),
            "new": _entry("new"),
        }
        self.assertEqual(df.mac_changes(before, after), {"a": {"mtime", "ctime"}})
        self.assertEqual(
            df.mac_changes(before, after, df.MAC_FIELDS_OBSERVED), {"b": {"atime"}}
        )

    def test_a_replaced_inode_is_a_change(self) -> None:
        changes = df.mac_changes({"a": _entry("a")}, {"a": _entry("a", inode="99")})
        self.assertEqual(changes, {"a": {"inode"}})

    def test_hash_changes(self) -> None:
        before = {"a": "1", "b": "2", "c": "3"}
        after = {"a": "1", "b": "9", "d": "4"}
        self.assertEqual(df.hash_changes(before, after), {"b": {"content"}})


class UnexplainedTest(unittest.TestCase):
    def test_control_and_allowlist_explain_boot_noise(self) -> None:
        volatile = re.compile(r"^var/")
        test = {
            "etc/static": {"ctime", "inode"},
            "etc/shadow": {"mtime", "ctime"},
            "var/log/wtmp": {"mtime"},
            "home/u/notes": {"content"},
        }
        control = {"etc/static": {"ctime", "inode"}, "etc/shadow": {"ctime"}}
        self.assertEqual(
            df.unexplained(test, control, volatile),
            {"etc/shadow": ["mtime"], "home/u/notes": ["content"]},
        )

    def test_format_changes_shows_old_and_new_values(self) -> None:
        before = {"a": _entry("a")}
        after = {"a": _entry("a", mtime=200)}
        text = df.format_changes({"a": ["mtime"], "b": ["content"]}, before, after)
        self.assertIn("a: mtime 100 -> 200", text)
        self.assertIn("b: content", text)


class MacDiffTest(unittest.TestCase):
    """The control-run diff the forensic image tests assert."""

    def _state(self, body: dict[str, df.BodyEntry], **hashes: str) -> df.ImageState:
        return df.ImageState(body=body, hashes=dict(hashes))

    def test_only_changes_the_control_span_did_not_make_are_left(self) -> None:
        baseline = self._state(
            {"etc/a": _entry("etc/a"), "home/u/x": _entry("home/u/x")},
            **{"etc/a": "1", "home/u/x": "1"},
        )
        # Boot noise: etc/a's ctime moves on every boot.
        control = self._state(
            {"etc/a": _entry("etc/a", ctime=150), "home/u/x": _entry("home/u/x")},
            **{"etc/a": "1", "home/u/x": "1"},
        )
        # The session span repeats the noise and also rewrites home/u/x in place.
        post = self._state(
            {
                "etc/a": _entry("etc/a", ctime=250),
                "home/u/x": _entry("home/u/x", mtime=300, atime=300),
            },
            **{"etc/a": "1", "home/u/x": "2"},
        )
        result = df.mac_diff(baseline, control, post, NIXOS)
        self.assertEqual(result.left, {"home/u/x": ["content", "mtime"]})
        self.assertEqual(result.atime_left, {"home/u/x": ["atime"]})
        self.assertIn("home/u/x: content, mtime 100 -> 300", result.report)

    def test_volatile_paths_are_never_left(self) -> None:
        baseline = self._state({"var/log/x": _entry("var/log/x")})
        post = self._state({"var/log/x": _entry("var/log/x", mtime=999)})
        result = df.mac_diff(baseline, baseline, post, NIXOS)
        self.assertEqual(result.left, {})

    def test_a_clean_session_passes_and_keeps_the_report(self) -> None:
        state = self._state({"etc/a": _entry("etc/a")}, **{"etc/a": "1"})
        with tempfile.TemporaryDirectory() as out:
            machine = mock.Mock(out_dir=out)
            result = df.assert_mac_unchanged(
                machine, state, state, state, NIXOS, artifact="t.txt"
            )
            self.assertEqual(result.left, {})
            text = (Path(out) / "forensics" / "t.txt").read_text(encoding="utf-8")
            self.assertIn("unexplained changes:\n(none)", text)

    def test_an_unexplained_change_fails(self) -> None:
        baseline = self._state({"etc/a": _entry("etc/a")}, **{"etc/a": "1"})
        post = self._state({"etc/a": _entry("etc/a")}, **{"etc/a": "2"})
        with tempfile.TemporaryDirectory() as out:
            machine = mock.Mock(out_dir=out)
            with self.assertRaises(AssertionError) as raised:
                df.assert_mac_unchanged(machine, baseline, baseline, post, NIXOS)
            self.assertIn("etc/a: content", str(raised.exception))


class ImageVolatileTest(unittest.TestCase):
    # Entries only a NixOS decoy churns at every boot (store bookkeeping and the
    # activation-replaced links); on an FHS distro each is a real finding.
    NIXOS_ONLY = (
        "nix/store/.links",
        "nix/var/nix/db/db.sqlite",
        "bin/sh",
        "usr/bin/env",
    )
    # Boot noise every distribution shares.
    GENERIC = ("var/log/x", "run/y", "tmp/z", "etc/machine-id")
    # A var/, run/ or tmp/ below the image root, and the boot-noise names
    # anywhere but where the system keeps them, are decoy files like any other.
    NESTED = (
        "home/alice/tmp/notes.txt",
        "root/projects/var/x",
        "root/.cache/run/x",
        "srv/data/etc/machine-id",
        "home/alice/bin/sh",
        "opt/tool/usr/bin/env",
    )
    FHS_IDS = ("debian", "ubuntu", "fedora", "arch")

    def test_the_nixos_constant_is_the_nixos_allowlist(self) -> None:
        self.assertEqual(
            df.image_volatile("nixos").pattern, df.DEFAULT_IMAGE_VOLATILE.pattern
        )

    def test_no_caller_gets_the_nixos_list_by_default(self) -> None:
        # The NixOS list is the widest, so a caller that forgot the os-id or
        # the allowlist must fail rather than get it.
        for function, parameter in (
            (df.image_volatile, "os_id"),
            (df.mac_diff, "volatile"),
            (df.assert_mac_unchanged, "volatile"),
        ):
            default = inspect.signature(function).parameters[parameter].default
            self.assertIs(default, inspect.Parameter.empty, function.__name__)

    def test_nixos_allowlists_the_activation_entries(self) -> None:
        nixos = df.image_volatile("nixos")
        for path in self.NIXOS_ONLY:
            self.assertTrue(nixos.search(path), path)

    def test_fhs_distros_do_not_allowlist_the_activation_entries(self) -> None:
        for os_id in self.FHS_IDS:
            volatile = df.image_volatile(os_id)
            for path in self.NIXOS_ONLY:
                self.assertIsNone(volatile.search(path), f"{os_id}: {path}")

    def test_generic_boot_noise_is_allowlisted_everywhere(self) -> None:
        for os_id in ("nixos", *self.FHS_IDS):
            volatile = df.image_volatile(os_id)
            for path in self.GENERIC:
                self.assertTrue(volatile.search(path), f"{os_id}: {path}")

    def test_a_nested_runtime_name_is_a_finding_everywhere(self) -> None:
        for os_id in ("nixos", *self.FHS_IDS):
            volatile = df.image_volatile(os_id)
            for path in self.NESTED:
                self.assertIsNone(volatile.search(path), f"{os_id}: {path}")

    def test_the_nix_database_is_noise_only_on_nixos(self) -> None:
        # Through the generic var/ alternative it used to match everywhere: a
        # Nix database that appeared on an FHS decoy is a finding.
        path = "nix/var/nix/db/db.sqlite"
        self.assertTrue(df.image_volatile("nixos").search(path))
        for os_id in self.FHS_IDS:
            self.assertIsNone(df.image_volatile(os_id).search(path), os_id)

    def test_a_general_store_path_is_a_finding_even_on_nixos(self) -> None:
        # Only the store's .links bookkeeping is boot noise; an actual store
        # path that appeared is a finding on every decoy, so gating the NixOS
        # entries never over-allows.
        store_path = "nix/store/abcd1234-hello-1.0/bin/hello"
        self.assertIsNone(df.image_volatile("nixos").search(store_path))
        self.assertIsNone(df.image_volatile("debian").search(store_path))


class HashTreeTest(unittest.TestCase):
    def test_hashes_regular_files_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "d").mkdir()
            (root / "d" / "f").write_bytes(b"abc")
            (root / "l").symlink_to("d/f")
            sums = df.hash_tree(root)
        self.assertEqual(sums, {"d/f": hashlib.sha256(b"abc").hexdigest()})

    def test_write_artifact_uses_the_out_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:

            class _Machine:
                out_dir = tmp

            path = df.write_artifact(_Machine(), "x.body", "0|/a|1\n")
            self.assertEqual(path, Path(tmp) / "forensics" / "x.body")
            self.assertEqual(path.read_text(encoding="utf-8"), "0|/a|1\n")


class OracleImageNameTest(unittest.TestCase):
    """The snapshot-label -> oracle-image-name mapping the real-image slice keys
    on. A single disk lineage ``baseline -> control -> post*`` becomes the
    oracle's ``before`` / ``control`` / ``after`` triple; everything else is not
    an oracle image."""

    def test_baseline_control_and_post_map_to_the_triple(self) -> None:
        self.assertEqual(df.oracle_image_name("baseline"), "before")
        self.assertEqual(df.oracle_image_name("control"), "control")
        self.assertEqual(df.oracle_image_name("post"), "after")

    def test_every_post_variant_is_the_after_image(self) -> None:
        for label in ("post-standard", "post-emergency", "post-deactivation"):
            self.assertEqual(df.oracle_image_name(label), "after")

    def test_other_labels_are_not_oracle_images(self) -> None:
        for label in ("reboot", "positive", "active", "pre_session", ""):
            self.assertIsNone(df.oracle_image_name(label))


class RdumpTest(unittest.TestCase):
    """debugfs has no offset option, so a partition is opened through the
    ``<image>?offset=<bytes>`` device form, and the request quotes its paths
    because debugfs splits it on blanks."""

    def _argv(self, offset: int, dest: Path) -> list[str]:
        with mock.patch.object(df, "_run") as run:
            df._rdump("/img/root.raw", offset, "/var/log/journal", dest)
        run.assert_called_once()
        argv: list[str] = run.call_args.args[0]
        return argv

    def test_a_partition_is_opened_at_its_byte_offset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            argv = self._argv(2048, Path(tmp) / "out")
        self.assertEqual(argv[0], df.DEBUGFS)
        self.assertNotIn("-o", argv)
        self.assertEqual(argv[-1], "/img/root.raw?offset=1048576")

    def test_a_bare_filesystem_is_opened_as_is(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            argv = self._argv(0, Path(tmp) / "out")
        self.assertEqual(argv[-1], "/img/root.raw")

    def test_the_request_quotes_a_path_with_a_blank_or_a_quote(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            argv = self._argv(0, Path(tmp) / 'a b"c')
        self.assertEqual(
            argv[1:3], ["-R", f'rdump "/var/log/journal" "{tmp}/a b""c"']
        )


# mmls output for a GPT disk: an ESP, then two partitions of the Linux type.
_MMLS_GPT = """GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  Meta      0000000001   0000000001   0000000001   GPT Header
003:  Meta      0000000002   0000000033   0000000032   Partition Table
004:  000       0000002048   0000018431   0000016384   EFI System
005:  001       0000018432   0000067583   0000049152   Linux filesystem
006:  002       0000067584   0000131038   0000063455   Linux filesystem
007:  -------   0000131039   0000131071   0000000033   Unallocated
"""
# The byte offsets of the three partitions above.
_ESP, _ROOT, _SECOND = 2048 * 512, 18432 * 512, 67584 * 512


class PartitionOffsetTest(unittest.TestCase):
    """The root is the one partition of a whole-disk image that can hold it,
    and only when that is ext{2,3,4}; a bare image is read whole only when it
    is ext{2,3,4}. Anything else is refused rather than carved at a guess:
    debugfs exits 0 on a filesystem it cannot open or a path it does not find,
    so a carve of the wrong filesystem finds nothing and the scan passes."""

    def _offset(
        self, mmls: str | None, types: Mapping[int, str | int], bare: str | int = ""
    ) -> int:
        """``partition_offset`` with ``mmls`` printing ``mmls`` (failing when
        ``None``), ``blkid`` finding ``types[start]`` in the partition at each
        start and ``bare`` in the whole image. A number there is the status
        ``blkid`` exits with instead."""
        self.blkid_calls: list[list[str]] = []

        def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
            if cmd[0] == df.MMLS:
                if mmls is None:
                    raise subprocess.CalledProcessError(1, cmd)
                return subprocess.CompletedProcess(cmd, 0, mmls, "")
            self.assertEqual(cmd[0], df.BLKID)
            self.blkid_calls.append(cmd)
            found = types.get(int(cmd[cmd.index("-O") + 1])) if "-O" in cmd else bare
            if isinstance(found, int):
                raise subprocess.CalledProcessError(found, cmd, "", "blkid: probe\n")
            if not found:
                raise subprocess.CalledProcessError(2, cmd)
            return subprocess.CompletedProcess(cmd, 0, f"{found}\n", "")

        with mock.patch.object(df, "_run", side_effect=run):
            return df.partition_offset("/img/disk.raw")

    def test_the_one_ext_partition_is_the_root(self) -> None:
        offset = self._offset(_MMLS_GPT, {_ESP: "vfat", _ROOT: "ext4", _SECOND: "swap"})
        self.assertEqual(offset, 18432)
        # Every partition is probed in its own window, in its low-level mode.
        self.assertEqual(len(self.blkid_calls), 3)
        for cmd in self.blkid_calls:
            self.assertIn("-p", cmd)
        self.assertEqual(
            self.blkid_calls[1][-5:],
            ["-O", str(_ROOT), "-S", str(49152 * 512), "/img/disk.raw"],
        )

    def test_a_second_linux_partition_after_the_root_is_refused(self) -> None:
        # A root followed by a /home: the root cannot be told apart, so no
        # guess (the greatest start would be the /home) is carved.
        types = {_ESP: "vfat", _ROOT: "ext4", _SECOND: "ext4"}
        with self.assertRaises(RuntimeError) as raised:
            self._offset(_MMLS_GPT, types)
        message = str(raised.exception)
        self.assertIn(f"ext4 at byte {_ROOT}", message)
        self.assertIn(f"ext4 at byte {_SECOND}", message)

    def test_an_ext4_boot_next_to_a_btrfs_root_is_refused(self) -> None:
        # Fedora's layout: an ESP, an ext4 /boot and a btrfs root. The one ext
        # partition is the /boot, and the scans would find nothing in it.
        types = {_ESP: "vfat", _ROOT: "ext4", _SECOND: "btrfs"}
        with self.assertRaises(RuntimeError) as raised:
            self._offset(_MMLS_GPT, types)
        message = str(raised.exception)
        self.assertIn("more than one partition can hold the root", message)
        self.assertIn(f"btrfs at byte {_SECOND}", message)

    def test_any_filesystem_or_volume_but_an_esp_or_swap_can_be_the_root(self) -> None:
        # An ext4 /boot next to a root of any other kind, an encrypted or LVM
        # volume included, is refused the same way.
        roots = ("xfs", "f2fs", "bcachefs", "zfs_member", "crypto_LUKS", "LVM2_member")
        for root in roots:
            types = {_ESP: "vfat", _ROOT: "ext4", _SECOND: root}
            with self.assertRaises(RuntimeError, msg=root) as raised:
                self._offset(_MMLS_GPT, types)
            self.assertIn(f"{root} at byte {_SECOND}", str(raised.exception))

    def test_a_disk_whose_root_is_not_ext_is_refused(self) -> None:
        # One partition can hold the root, but the scans carve only ext.
        with self.assertRaises(RuntimeError) as raised:
            self._offset(_MMLS_GPT, {_ESP: "vfat", _ROOT: "btrfs"})
        self.assertIn("the root partition holds btrfs", str(raised.exception))
        # No partition can hold the root, or blkid recognises none.
        for types in ({_ESP: "vfat", _SECOND: "swap"}, {}):
            with self.assertRaises(RuntimeError, msg=str(types)) as raised:
                self._offset(_MMLS_GPT, types)
            self.assertIn("no partition can hold the root", str(raised.exception))

    def test_an_ambivalent_probe_is_refused_not_read_as_nothing(self) -> None:
        # blkid exits 8 when it finds more than one signature in a partition,
        # a stale superblock next to the one in use, and cannot tell which one
        # is. That partition may hold the root, so the disk is refused rather
        # than carved from the one ext partition next to it.
        types: dict[int, str | int] = {_ESP: "vfat", _ROOT: "ext4", _SECOND: 8}
        with self.assertRaises(RuntimeError) as raised:
            self._offset(_MMLS_GPT, types)
        message = str(raised.exception)
        self.assertIn("ambivalent", message)
        self.assertIn(f"in the partition at byte {_SECOND}", message)
        # A bare image whose probe is ambivalent is refused the same way, not
        # as one in which blkid recognises no filesystem.
        with self.assertRaises(RuntimeError) as raised:
            self._offset(None, {}, bare=8)
        self.assertIn("ambivalent", str(raised.exception))
        self.assertIn("in the image", str(raised.exception))

    def test_a_probe_that_fails_otherwise_is_refused(self) -> None:
        # Only exit 2 means blkid found nothing; a usage or other error
        # (exit 4) says nothing about what the partition holds.
        types: dict[int, str | int] = {_ESP: "vfat", _ROOT: "ext4", _SECOND: 4}
        with self.assertRaises(RuntimeError) as raised:
            self._offset(_MMLS_GPT, types)
        message = str(raised.exception)
        self.assertIn(f"could not probe in the partition at byte {_SECOND}", message)
        self.assertIn("exit 4", message)

    def test_partition_names_do_not_decide(self) -> None:
        # mmls prints a GPT partition's name, which need not say Linux.
        named = _MMLS_GPT.replace("Linux filesystem", "nixos", 1).replace(
            "Linux filesystem", "data", 1
        )
        offset = self._offset(named, {_ESP: "vfat", _ROOT: "ext4"})
        self.assertEqual(offset, 18432)

    def test_a_bare_ext_filesystem_is_read_whole(self) -> None:
        self.assertEqual(self._offset(None, {}, bare="ext4"), 0)
        # blkid probes the whole image, with no partition window.
        self.assertEqual(
            self.blkid_calls,
            [[df.BLKID, "-p", "-o", "value", "-s", "TYPE", "/img/disk.raw"]],
        )

    def test_a_bare_filesystem_of_another_kind_is_refused(self) -> None:
        with self.assertRaises(RuntimeError) as raised:
            self._offset(None, {}, bare="btrfs")
        self.assertIn("a bare btrfs filesystem", str(raised.exception))
        with self.assertRaises(RuntimeError) as raised:
            self._offset(None, {})
        self.assertIn("no filesystem blkid recognises", str(raised.exception))

    def test_an_mbr_slot_in_larger_sectors_is_converted(self) -> None:
        mbr = (
            "DOS Partition Table\n"
            "Offset Sector: 0\n"
            "Units are in 4096-byte sectors\n\n"
            "      Slot      Start        End          Length       Description\n"
            "000:  Meta      0000000000   0000000000   0000000001   Primary Table\n"
            "001:  -------   0000000000   0000000255   0000000256   Unallocated\n"
            "002:  000:000   0000000256   0000008191   0000007936   Linux (0x83)\n"
        )
        offset = self._offset(mbr, {256 * 4096: "ext4"})
        self.assertEqual(offset, 256 * 4096 // 512)
        self.assertEqual(self.blkid_calls[0][-2], str(7936 * 4096))


class CopySparseTest(unittest.TestCase):
    def test_round_trips_data_and_holes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src.raw"
            dest = Path(tmp) / "dest.raw"
            with open(src, "wb") as handle:
                handle.write(b"head")
                handle.seek(1 << 20)  # a hole
                handle.write(b"tail")
            df._copy_sparse(src, dest)
            self.assertEqual(dest.stat().st_size, src.stat().st_size)
            self.assertEqual(dest.read_bytes(), src.read_bytes())


if __name__ == "__main__":
    unittest.main()
