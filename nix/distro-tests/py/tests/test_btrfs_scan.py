"""Unit tests for the btrfs logical-scan helpers of the smoke scenario.

They lock the parts of the reads of a btrfs decoy's image that run without
btrfs-progs: where the partition lies in the image, which filter btrfs
restore gets, how the roots btrfs-find-root lists are read, which lines of
btrfs restore's output say it could not read something, which algorithm a
mount compresses with, how a restored tree is searched for tokens and paths,
and how the zstd frames on the partition are found, decompressed and
searched. A silent drift here would turn the planted btrfs controls, or the
scan of the decoy after a session, into a pass that read nothing.
"""

from __future__ import annotations

import json
import os
import random
import re
import struct
import tempfile
import unittest
from compression import zstd
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


class PathsInTreeTest(unittest.TestCase):
    def test_the_paths_a_restore_wrote_whatever_they_hold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(Path(tmp, "home"))
            # Empty, as btrfs restore leaves a file it could not read.
            Path(tmp, "home", "canary").write_bytes(b"")
            os.symlink("/nowhere", Path(tmp, "home", "dangling"))
            wanted = ["/home/canary", "/home/dangling", "/home/absent", "/etc/canary"]
            self.assertEqual(
                bs.paths_in_tree(tmp, wanted), ["/home/canary", "/home/dangling"]
            )

    def test_no_path_finds_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(bs.paths_in_tree(tmp, []), [])


class RestoreErrorsTest(unittest.TestCase):
    # What btrfs restore -s -i printed for an older root of the arch-boxes
    # image, filtered to one file it cannot read: the notes on the root's own
    # block, then the file.
    OUTPUT = (
        "parent transid verify failed on 49037312 wanted 121 found 120\n"
        "parent transid verify failed on 49037312 wanted 121 found 120\n"
        "Ignoring transid failure\n"
        "ERROR: zstd frame incomplete\n"
        "ERROR: copying data for /out//var/lib/pacman/local/a-1/desc failed\n"
        "  ERROR: searching directory /out//var/lib/pacman failed: -5\n"
    )

    def test_the_lines_of_what_it_could_not_read(self) -> None:
        self.assertEqual(
            bs.restore_errors(self.OUTPUT),
            [
                "ERROR: zstd frame incomplete",
                "ERROR: copying data for /out//var/lib/pacman/local/a-1/desc failed",
                "ERROR: searching directory /out//var/lib/pacman failed: -5",
            ],
        )

    def test_notes_on_an_older_root_are_no_error(self) -> None:
        notes = "\n".join(self.OUTPUT.splitlines()[:3])
        self.assertEqual(bs.restore_errors(notes), [])
        self.assertEqual(bs.restore_errors(""), [])


class CompressionTest(unittest.TestCase):
    def test_the_algorithm_of_the_mount(self) -> None:
        for options, algorithm in (
            (
                "rw,relatime,compress=zstd:3,ssd,space_cache=v2,subvolid=5,subvol=/",
                "zstd",
            ),
            ("rw,relatime,seclabel,compress-force=zstd:1,ssd,subvol=/root", "zstd"),
            ("rw,compress=lzo,ssd", "lzo"),
            ("rw,compress=zlib:3", "zlib"),
            ("rw,compress", "zlib"),
            ("rw,compress=zstd,compress=lzo", "lzo"),
            ("rw,compress=zstd:3,compress=no", None),
            ("rw,compress-force=none", None),
            ("rw,relatime,ssd,space_cache=v2,subvol=/", None),
            ("rw,nocompress_test=zstd", None),
        ):
            with self.subTest(options=options):
                self.assertEqual(bs.compression(options), algorithm)


def frame(data: bytes, **options: int) -> bytes:
    """A zstd frame of `data`, as btrfs writes one: with its content size."""
    parameters: dict[int, int] = {
        zstd.CompressionParameter[key]: value for key, value in options.items()
    }
    return zstd.compress(data, options=parameters or None)


class DecompressFrameTest(unittest.TestCase):
    def test_a_frame_and_what_follows_it(self) -> None:
        data = b"NAILS_CANARY_home\n" * 100
        view = frame(data) + random.Random(5).randbytes(4096)
        self.assertEqual(bs.decompress_frame(view), data)

    def test_a_padded_block_reads_whole(self) -> None:
        # An inline extent: the file's 356 bytes, then zeros to the block.
        block = b"%NAME%\niana-etc\n".ljust(356, b"x").ljust(4096, b"\0")
        self.assertEqual(bs.decompress_frame(frame(block)), block)

    def test_no_frame_decodes_to_nothing(self) -> None:
        # A frame header with its reserved bit set, as no encoder writes one.
        self.assertEqual(bs.decompress_frame(bs.ZSTD_MAGIC + b"\xff" * 64), b"")
        self.assertEqual(bs.decompress_frame(b"\x01" * 64), b"")
        self.assertEqual(bs.decompress_frame(b""), b"")

    def test_what_decodes_before_the_damage_counts(self) -> None:
        # Blocks of at most 1 KiB, so that the frame's first pieces decode on
        # their own; then a later write overwrote the frame's second half.
        rng = random.Random(7)
        data = b"".join(
            b"%06d NAILS-POISON-%d " % (i, i % 7)
            + rng.randbytes(16).hex().encode()
            + b"\n"
            for i in range(4000)
        )[: bs.MAX_EXTENT]
        whole = frame(data, window_log=10)
        self.assertGreater(len(whole), 4 * 4096)
        half = len(whole) // 2
        damaged = whole[:half] + b"\xff" * (len(whole) - half)
        got = bs.decompress_frame(damaged)
        self.assertGreater(len(got), 4096)
        self.assertLess(len(got), len(data))
        self.assertEqual(got, data[: len(got)])

    def test_the_output_ends_at_an_extent(self) -> None:
        data = random.Random(3).randbytes(64).hex().encode() * (
            3 * bs.MAX_EXTENT // 128
        )
        self.assertEqual(bs.decompress_frame(frame(data)), data[: bs.MAX_EXTENT])


class ZstdFramesTest(unittest.TestCase):
    def image(self, tmp: str, pieces: dict[int, bytes], size: int) -> Path:
        path = Path(tmp, "part.img")
        with open(path, "wb") as handle:
            handle.truncate(size)
            for offset, data in pieces.items():
                handle.seek(offset)
                handle.write(data)
        return path

    def test_frames_wherever_they_start(self) -> None:
        aligned = frame(b"NAILS_CANARY_etc\n" * 300)
        inline = frame(b"NAILS_CANARY2_root\n".ljust(4096, b"\0"))
        across = frame(b"NAILS-POISON-C-" * 17476)
        later = frame(b"rehearsal-token-0123\n" * 9)
        pieces = {
            # Data from the start on, longer than one read of the scan.
            0: b"\x01" * (bs._CHUNK + (1 << 20)),
            4096: aligned,
            # Inside a metadata block, after an item's header.
            65536: b"\x01" * 53 + inline + b"\x02" * 77,
            # Four bytes that read as the magic, then nothing that decodes.
            1 << 20: bs.ZSTD_MAGIC + b"\xff" * 512,
            # A frame whose magic straddles two reads of the scan.
            bs._CHUNK - 2: across,
            # Past a hole.
            40 << 20: later,
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = self.image(tmp, pieces, 64 << 20)
            frames = dict(bs.zstd_frames(path))
        self.assertEqual(
            sorted(frames), [4096, 65536 + 53, bs._CHUNK - 2, 40 << 20], sorted(frames)
        )
        self.assertEqual(frames[4096], b"NAILS_CANARY_etc\n" * 300)
        self.assertEqual(frames[65536 + 53][:19], b"NAILS_CANARY2_root\n")
        self.assertEqual(len(frames[65536 + 53]), 4096)
        self.assertEqual(
            frames[bs._CHUNK - 2], (b"NAILS-POISON-C-" * 17476)[: bs.MAX_EXTENT]
        )
        self.assertEqual(frames[40 << 20], b"rehearsal-token-0123\n" * 9)

    def test_an_image_without_frames(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self.image(tmp, {8192: b"NAILS_CANARY_home\n" * 64}, 1 << 20)
            self.assertEqual(list(bs.zstd_frames(path)), [])


class FrameTokensTest(unittest.TestCase):
    def test_the_tokens_the_frames_hold(self) -> None:
        pieces = {
            4096: frame(b"x" * 900 + b"NAILS_CANARY_home" + b"y" * 900),
            1 << 20: frame(b"NAILS-POISON-B-" * 17476),
            # In clear only: a raw scan's find, not the carve's.
            2 << 20: b"NAILS_CANARY_var\n",
            # Cut between two frames that lie one after the other.
            3 << 20: frame(b"z" * 2000 + b"TOKEN-CU") + frame(b"T-HERE" + b"z" * 2000),
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "part.img")
            with open(path, "wb") as handle:
                handle.truncate(8 << 20)
                for offset, data in pieces.items():
                    handle.seek(offset)
                    handle.write(data)
            found, frames = bs.frame_tokens(
                path,
                [
                    "NAILS_CANARY_home",
                    "NAILS-POISON-B-NAILS-POISON-B-",
                    "NAILS_CANARY_var",
                    "TOKEN-CUT-HERE",
                    "",
                ],
            )
        self.assertEqual(
            found,
            {"NAILS_CANARY_home": 4096, "NAILS-POISON-B-NAILS-POISON-B-": 1 << 20},
        )
        self.assertEqual(frames, 4)

    def test_tokens_found_across_batches(self) -> None:
        batch = bs._BATCH
        try:
            bs._BATCH = 1
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp, "part.img")
                with open(path, "wb") as handle:
                    handle.truncate(4 << 20)
                    handle.seek(4096)
                    handle.write(frame(b"first TOKEN-A"))
                    handle.seek(1 << 20)
                    handle.write(frame(b"then TOKEN-B and TOKEN-A"))
                found, frames = bs.frame_tokens(path, ["TOKEN-A", "TOKEN-B"])
            self.assertEqual(found, {"TOKEN-A": 4096, "TOKEN-B": 1 << 20})
            self.assertEqual(frames, 2)
        finally:
            bs._BATCH = batch

    def test_each_token_with_the_frame_it_ends(self) -> None:
        # Short tokens that end their frame, in frames that lie one after the
        # other: each is told by the frame it is in, not the one after it.
        frames = [frame(b"%d " % i * 50 + b"Q%02d" % i) for i in range(12)]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "part.img")
            path.write_bytes(b"".join(frames))
            found, count = bs.frame_tokens(path, [f"Q{i:02d}" for i in range(12)])
        starts = [sum(len(f) for f in frames[:i]) for i in range(12)]
        self.assertEqual(found, {f"Q{i:02d}": starts[i] for i in range(12)})
        self.assertEqual(count, 12)

    def test_a_token_with_a_nul_byte(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "part.img")
            path.write_bytes(b"")
            with self.assertRaises(ValueError):
                bs.frame_tokens(path, ["TOKEN\0A"])


if __name__ == "__main__":
    unittest.main()
