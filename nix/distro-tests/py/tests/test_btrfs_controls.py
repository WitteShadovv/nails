"""Tests for the pure parts of btrfs_controls, the btrfs scan controls of the
Fedora gate."""

from __future__ import annotations

import subprocess
import unittest

import btrfs_controls as bc

FILEFRAG = """\
Filesystem type is: 9123683e
File size of /var/tmp/scan-controls/compressed/c is 262144 (64 blocks of 4096 bytes)
 ext:     logical_offset:        physical_offset: length:   expected: flags:
   0:        0..      31:     264195..    264226:     32:             encoded
   1:       32..      63:     264196..    264227:     32:     264227: last,encoded,eof
/var/tmp/scan-controls/compressed/c: 2 extents found
"""


class EncodedExtentsTest(unittest.TestCase):
    def test_reads_the_address_of_each_extent(self) -> None:
        self.assertEqual(bc.encoded_extents(FILEFRAG), [264195 * 4096, 264196 * 4096])

    def test_a_missing_filefrag_lists_none(self) -> None:
        self.assertEqual(bc.encoded_extents("sh: filefrag: command not found"), [])


CHUNKS = """\
chunk tree
\titem 0 key (DEV_ITEMS DEV_ITEM 1) itemoff 16185 itemsize 98
\t\tdevid 1 total_bytes 314572800 bytes_used 92274688
\titem 1 key (FIRST_CHUNK_TREE CHUNK_ITEM 13631488) itemoff 16105 itemsize 80
\t\tlength 8388608 owner 2 stripe_len 65536 type DATA|single
\t\tnum_stripes 1 sub_stripes 1
\t\t\tstripe 0 devid 1 offset 13631488
\titem 3 key (FIRST_CHUNK_TREE CHUNK_ITEM 30408704) itemoff 15881 itemsize 112
\t\tlength 33554432 owner 2 stripe_len 65536 type METADATA|DUP
\t\tnum_stripes 2 sub_stripes 1
\t\t\tstripe 0 devid 1 offset 38797312
\t\t\tstripe 1 devid 1 offset 72351744
"""


class ChunkMapTest(unittest.TestCase):
    def test_reads_each_chunk_and_its_first_stripe(self) -> None:
        self.assertEqual(
            bc.chunk_map(CHUNKS),
            [(13631488, 8388608, 13631488), (30408704, 33554432, 38797312)],
        )

    def test_maps_an_address_into_its_chunk(self) -> None:
        chunks = bc.chunk_map(CHUNKS)
        self.assertEqual(bc.physical_address(chunks, 13631488 + 4096), 13635584)
        self.assertEqual(bc.physical_address(chunks, 30408704 + 8192), 38805504)
        self.assertIsNone(bc.physical_address(chunks, 4096))


class RestoreMessagesTest(unittest.TestCase):
    def test_keeps_what_it_said_without_its_prompts(self) -> None:
        done = subprocess.CompletedProcess(
            ["btrfs", "restore"],
            0,
            "We seem to be looping a lot on x, do you want to keep going on ? "
            "(y/N/a): \n",
            "ERROR: zstd decompress failed Unknown frame descriptor\n\n",
        )
        self.assertEqual(
            bc.restore_messages(done),
            ["ERROR: zstd decompress failed Unknown frame descriptor"],
        )

    def test_keeps_at_most_twenty_lines(self) -> None:
        done = subprocess.CompletedProcess(
            ["btrfs"], 1, "".join(f"line {n}\n" for n in range(30)), ""
        )
        self.assertEqual(len(bc.restore_messages(done)), 20)


class PoisonTest(unittest.TestCase):
    def test_a_token_is_four_units(self) -> None:
        self.assertEqual(bc.poison_token("C"), "NAILS-POISON-C-" * 4)

    def test_a_compressed_control_fills_whole_blocks(self) -> None:
        self.assertEqual(bc.POISON_BYTES % bc.BLOCK, 0)
        # The units written cover it, so the truncation only cuts.
        self.assertGreaterEqual(17477 * len(bc.poison_unit("C")), bc.POISON_BYTES)


class HistoryTest(unittest.TestCase):
    LIVE = bc.poison_token("B")
    DELETED = bc.poison_token("C")
    LIVE_PATH = "/tmp/scan-controls/compressed/b"
    DELETED_PATH = "/tmp/scan-controls/compressed/c"

    def test_the_newest_root_is_no_history(self) -> None:
        # A deletion that never reached the disk leaves the file in the
        # current tree: that is no older root keeping it.
        found = bc.history(
            [({self.LIVE, self.DELETED}, [self.LIVE_PATH, self.DELETED_PATH])],
            self.LIVE,
            self.LIVE_PATH,
        )
        self.assertEqual(found["older"], [])
        self.assertEqual(found["kept"], [])
        self.assertEqual(found["newest"], sorted({self.LIVE, self.DELETED}))
        self.assertEqual(found["newestPaths"], [self.LIVE_PATH, self.DELETED_PATH])

    def test_an_older_root_keeps_the_deleted_control(self) -> None:
        found = bc.history(
            [
                ({self.LIVE}, [self.LIVE_PATH]),
                ({self.LIVE, self.DELETED}, [self.LIVE_PATH, self.DELETED_PATH]),
                (set(), []),
            ],
            self.LIVE,
            self.LIVE_PATH,
        )
        self.assertEqual(found["older"], [self.DELETED])
        self.assertEqual(found["kept"], [self.DELETED_PATH])
        self.assertEqual(found["newest"], [self.LIVE])
        self.assertEqual(found["newestPaths"], [self.LIVE_PATH])

    def test_no_root_holds_nothing(self) -> None:
        self.assertEqual(
            bc.history([], self.LIVE, self.LIVE_PATH),
            {"newest": [], "newestPaths": [], "older": [], "kept": []},
        )


if __name__ == "__main__":
    unittest.main()
