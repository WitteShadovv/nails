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


if __name__ == "__main__":
    unittest.main()
