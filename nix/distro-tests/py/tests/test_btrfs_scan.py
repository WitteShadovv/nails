"""Unit tests for the btrfs logical-scan helpers of the smoke scenario.

They lock the parts of the logical scan that run without btrfs-progs: where
the partition lies in the image, which filter btrfs restore gets, how the
roots btrfs-find-root lists are read and how a restored tree is searched. A
silent drift here would turn the planted btrfs controls, or the scan of the
decoy after a session, into a pass that read nothing.
"""

from __future__ import annotations

import json
import os
import re
import struct
import tempfile
import unittest
from pathlib import Path

import btrfs_scan as bs


class PartitionTest(unittest.TestCase):
    def test_partition_numbers(self) -> None:
        for device, number in (
            ("/dev/sda3", 3),
            ("/dev/vda12", 12),
            ("/dev/nvme0n1p2", 2),
            ("/dev/mmcblk0p1", 1),
        ):
            with self.subTest(device=device):
                self.assertEqual(bs.partition_number(device), number)

    def test_a_whole_disk_names_no_partition(self) -> None:
        for device in ("/dev/sda", "/dev/nvme0n1", "/dev/mapper/root", "sda3"):
            with self.subTest(device=device), self.assertRaises(ValueError):
                bs.partition_number(device)

    def test_the_extent_of_a_partition_in_bytes(self) -> None:
        table = json.dumps(
            {
                "partitiontable": {
                    "label": "gpt",
                    "unit": "sectors",
                    "sectorsize": 512,
                    "partitions": [
                        {"node": "/tmp/disk.raw1", "start": 2048, "size": 2048},
                        {"node": "/tmp/disk.raw2", "start": 4096, "size": 614400},
                        {"node": "/tmp/disk.raw3", "start": 618496, "size": 83267551},
                    ],
                }
            }
        )
        self.assertEqual(bs.partition_extent(table, 3), (618496 * 512, 83267551 * 512))
        with self.assertRaises(ValueError):
            bs.partition_extent(table, 4)


class SuperblockTest(unittest.TestCase):
    def test_the_generation(self) -> None:
        block = bytearray(0x100)
        block[0x40:0x48] = b"_BHRfS_M"
        struct.pack_into("<Q", block, 0x48, 4711)
        self.assertEqual(bs.superblock_generation(bytes(block)), 4711)

    def test_no_magic_no_superblock(self) -> None:
        with self.assertRaises(ValueError):
            bs.superblock_generation(bytes(0x100))

    def test_read_from_an_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp, "fs.img")
            block = bytearray(0x100)
            block[0x40:0x48] = b"_BHRfS_M"
            struct.pack_into("<Q", block, 0x48, 9)
            with open(image, "wb") as handle:
                handle.truncate(1 << 20)
                handle.seek(bs.SUPERBLOCK_OFFSET)
                handle.write(block)
            self.assertEqual(bs.read_generation(image), 9)


class FindRootTest(unittest.TestCase):
    OUTPUT = (
        "Superblock thinks the generation is 12\n"
        "Superblock thinks the level is 0\n"
        "Found tree root at 30605312 gen 12 level 0\n"
        "Well block 30588928(gen: 11 level: 0) seems good, but generation/level"
        " doesn't match, want gen: 12 level: 0\n"
        "Well block 30572544(gen: 10 level: 0) seems good, but generation/level"
        " doesn't match, want gen: 12 level: 0\n"
        "Well block 30588928(gen: 11 level: 0) seems good, but generation/level"
        " doesn't match, want gen: 12 level: 0\n"
    )

    def test_the_roots_newest_first_each_once(self) -> None:
        self.assertEqual(
            bs.parse_find_root(self.OUTPUT),
            [
                bs.TreeRoot(30605312, 12, 0),
                bs.TreeRoot(30588928, 11, 0),
                bs.TreeRoot(30572544, 10, 0),
            ],
        )

    def test_nothing_found(self) -> None:
        self.assertEqual(
            bs.parse_find_root("Superblock thinks the generation is 3\n"), []
        )


class PathFilterTest(unittest.TestCase):
    def matches(self, pattern: str, paths: list[str]) -> list[bool]:
        compiled = re.compile(pattern)
        return [bool(compiled.match(path)) for path in paths]

    def test_each_ancestor_and_the_path_but_nothing_below(self) -> None:
        pattern = bs.path_filter(["/var/tmp/x"])
        self.assertEqual(pattern, "^/(|var(|/tmp(|/x)))$")
        self.assertEqual(
            self.matches(
                pattern,
                [
                    "/",
                    "/var",
                    "/var/tmp",
                    "/var/tmp/x",
                    "/var/tmp/x/y",
                    "/var/tmpx",
                    "/etc",
                ],
            ),
            [True, True, True, True, False, False, False],
        )

    def test_below_takes_the_whole_subtree(self) -> None:
        pattern = bs.path_filter(["/var/tmp/x"], below=True)
        self.assertEqual(
            self.matches(pattern, ["/var/tmp/x", "/var/tmp/x/y/z", "/var/tmp/y"]),
            [True, True, False],
        )

    def test_several_paths_share_their_ancestors(self) -> None:
        pattern = bs.path_filter(
            ["/home/nails-canary-home", "/etc/nails-canary-etc", "/a.b/c"]
        )
        self.assertEqual(
            pattern,
            "^/(|a\\.b(|/c)|etc(|/nails-canary-etc)|home(|/nails-canary-home))$",
        )
        self.assertEqual(
            self.matches(
                pattern, ["/etc/nails-canary-etc", "/home", "/aXb/c", "/etc/passwd"]
            ),
            [True, True, False, False],
        )

    def test_the_top_alone_is_no_filter(self) -> None:
        for paths in ([], ["/"]):
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                bs.path_filter(paths)


class FilesystemPathTest(unittest.TestCase):
    def test_the_top_level_mounted_at_the_root(self) -> None:
        self.assertEqual(bs.filesystem_path("/", "/", "/var/tmp/x"), "/var/tmp/x")

    def test_a_subvolume_is_a_directory_of_its_name(self) -> None:
        self.assertEqual(bs.filesystem_path("/root", "/", "/etc/x"), "/root/etc/x")
        self.assertEqual(bs.filesystem_path("/var", "/var", "/var/tmp/x"), "/var/tmp/x")
        self.assertEqual(
            bs.filesystem_path("/@home", "/home", "/home/u/f"), "/@home/u/f"
        )

    def test_a_path_outside_the_mount(self) -> None:
        with self.assertRaises(ValueError):
            bs.filesystem_path("/var", "/var", "/etc/x")


class ExtractTest(unittest.TestCase):
    def test_a_sparse_partition_copy_holds_the_partition_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp, "disk.raw")
            part = Path(tmp, "part.img")
            with open(image, "wb") as handle:
                handle.truncate(64 << 20)
                handle.seek(1 << 20)
                handle.write(b"before")
                handle.seek(8 << 20)
                handle.write(b"inside-start")
                handle.seek(40 << 20)
                handle.write(b"inside-later")
                handle.seek(48 << 20)
                handle.write(b"after")
            bs.extract_partition(image, 8 << 20, 40 << 20, part)
            data = part.read_bytes()
            self.assertEqual(len(data), 40 << 20)
            self.assertEqual(data[:12], b"inside-start")
            self.assertEqual(data[32 << 20 : (32 << 20) + 12], b"inside-later")
            self.assertNotIn(b"before", data)
            self.assertNotIn(b"after", data)

    def test_data_extents_of_a_range(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            image = Path(tmp, "disk.raw")
            with open(image, "wb") as handle:
                handle.truncate(16 << 20)
                handle.seek(4 << 20)
                handle.write(b"x" * 4096)
            with open(image, "rb") as handle:
                extents = list(bs.data_extents(handle.fileno(), 0, 16 << 20))
            covered = sum(end - start for start, end in extents)
            self.assertGreaterEqual(covered, 4096)
            self.assertTrue(any(start <= (4 << 20) < end for start, end in extents))


class TokensInTreeTest(unittest.TestCase):
    def test_tokens_in_contents_not_in_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(Path(tmp, "a", "b"))
            Path(tmp, "a", "b", "TOKEN-NAME").write_bytes(b"nothing")
            Path(tmp, "a", "file").write_bytes(b"xx TOKEN-ONE yy")
            os.symlink("/proc/self/environ", Path(tmp, "a", "link"))
            self.assertEqual(
                bs.tokens_in_tree(tmp, ["TOKEN-ONE", "TOKEN-NAME", "TOKEN-TWO"]),
                {"TOKEN-ONE"},
            )

    def test_a_token_across_two_reads(self) -> None:
        chunk = bs._CHUNK
        try:
            bs._CHUNK = 8
            with tempfile.TemporaryDirectory() as tmp:
                Path(tmp, "f").write_bytes(b"0123456TOKEN-ACROSS789")
                self.assertEqual(
                    bs.tokens_in_tree(tmp, ["TOKEN-ACROSS"]), {"TOKEN-ACROSS"}
                )
        finally:
            bs._CHUNK = chunk

    def test_no_token_finds_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(bs.tokens_in_tree(tmp, []), set())


if __name__ == "__main__":
    unittest.main()
