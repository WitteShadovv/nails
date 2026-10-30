"""Tests for ci/oracle/plant-in-free-space.sh, the mount-free planting of the
oracle's positive controls into the free space of an ext4 or btrfs image."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "ci" / "oracle" / "plant-in-free-space.sh"

BLOCK = 4096
SIZE = 16 * 1024 * 1024
SENTINELS = [f"unallocated-{n}@oracle.example" for n in (1, 2, 3)]


def e2fs(tool: str) -> str | None:
    """An e2fsprogs tool, from PATH or the sbin directories a user's PATH may
    leave out."""
    found = shutil.which(tool)
    if found:
        return found
    for directory in ("/usr/sbin", "/sbin"):
        candidate = Path(directory) / tool
        if candidate.exists():
            return str(candidate)
    return None


MKFS = e2fs("mkfs.ext4")
DEBUGFS = e2fs("debugfs")
E2FSCK = e2fs("e2fsck")
MKFS_BTRFS = e2fs("mkfs.btrfs")
BTRFS = e2fs("btrfs")


def blocks(data: bytes) -> list[bytes]:
    return [data[i : i + BLOCK] for i in range(0, len(data), BLOCK)]


def changed_blocks(before: bytes, after: bytes) -> list[int]:
    pairs = zip(blocks(before), blocks(after), strict=True)
    return [i for i, (old, new) in enumerate(pairs) if old != new]


@unittest.skipUnless(MKFS and DEBUGFS and E2FSCK, "needs e2fsprogs")
class PlantInFreeSpaceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.image = self.dir / "root.img"
        # Only PATH, with e2fsprogs on it even where a user's PATH lacks sbin.
        tools = str(Path(str(DEBUGFS)).parent)
        self.env = {"PATH": os.pathsep.join([tools, os.environ.get("PATH", "")])}

    def make_fs(self, fill: bytes = b"\0") -> None:
        """A small ext4 filesystem holding one file, made from a directory with
        no mount. With `fill`, every block mkfs does not write keeps that byte,
        as free space holding old data does."""
        content = self.dir / "content"
        (content / "var" / "log").mkdir(parents=True, exist_ok=True)
        (content / "var" / "log" / "wtmp").write_bytes(b"\x01" * 10_000)
        self.image.write_bytes(fill * SIZE)
        options = "nodiscard,lazy_itable_init=0"
        subprocess.run(
            [str(MKFS), "-q", "-F", "-b", str(BLOCK), "-E", options]
            + ["-d", str(content), str(self.image)],
            check=True,
            capture_output=True,
        )

    def run_script(self, *args: str) -> subprocess.CompletedProcess[str]:
        # Through bash: the flake check copies the tree without its file modes.
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            capture_output=True,
            text=True,
            check=False,
            env=self.env,
        )

    def plant(self, *strings: str) -> subprocess.CompletedProcess[str]:
        return self.run_script(str(self.image), "0", *strings)

    def free_blocks(self, goal: int, count: int) -> list[int]:
        found = subprocess.run(
            [str(DEBUGFS), "-R", f"ffb {count} {goal}", str(self.image)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        return [int(b) for b in found.split(":", 1)[1].split()]

    def test_each_string_lands_once_in_its_own_block_that_was_zero(self) -> None:
        self.make_fs()
        before = self.image.read_bytes()
        result = self.plant(*SENTINELS)
        self.assertEqual(result.returncode, 0, result.stderr)
        after = self.image.read_bytes()
        self.assertEqual(len(after), len(before))
        for sentinel in SENTINELS:
            self.assertEqual(after.count(f"{sentinel}\n".encode()), 1, sentinel)
        changed = changed_blocks(before, after)
        self.assertEqual(len(changed), len(SENTINELS))
        for i in changed:
            self.assertEqual(blocks(before)[i], bytes(BLOCK), f"block {i}")
        # Nothing the filesystem tracks changed: the blocks are still free.
        fsck = subprocess.run(
            [str(E2FSCK), "-f", "-n", str(self.image)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(fsck.returncode, 0, fsck.stdout + fsck.stderr)

    def test_a_free_block_holding_old_data_is_passed_over(self) -> None:
        # Free space holds old data except one free block past the first
        # candidates: that block, and only it, takes the string.
        self.make_fs(fill=b"\xab")
        target = self.free_blocks(SIZE // BLOCK // 2, 16)[9]
        data = bytearray(self.image.read_bytes())
        data[target * BLOCK : (target + 1) * BLOCK] = bytes(BLOCK)
        self.image.write_bytes(bytes(data))
        before = self.image.read_bytes()

        result = self.plant(SENTINELS[0])
        self.assertEqual(result.returncode, 0, result.stderr)
        after = self.image.read_bytes()
        self.assertEqual(changed_blocks(before, after), [target])
        self.assertTrue(blocks(after)[target].startswith(SENTINELS[0].encode()))

    def test_no_zero_filled_free_block_leaves_the_image_unchanged(self) -> None:
        self.make_fs(fill=b"\xab")
        before = self.image.read_bytes()
        result = self.plant(*SENTINELS)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("no zero-filled free block", result.stderr)
        self.assertEqual(self.image.read_bytes(), before)

    def test_a_filesystem_at_an_offset_in_a_disk_image(self) -> None:
        # A partition starting one MiB in: its blocks count from there.
        self.make_fs()
        fs_bytes = self.image.read_bytes()
        lead = b"\xcd" * (1024 * 1024)
        self.image.write_bytes(lead + fs_bytes)
        result = self.run_script(str(self.image), str(len(lead)), SENTINELS[0])
        self.assertEqual(result.returncode, 0, result.stderr)
        after = self.image.read_bytes()
        self.assertTrue(after.startswith(lead))
        at = after.index(SENTINELS[0].encode()) - len(lead)
        self.assertEqual(at % BLOCK, 0)
        self.assertEqual(fs_bytes[at : at + BLOCK], bytes(BLOCK))

    def test_an_image_without_an_ext_filesystem_is_refused(self) -> None:
        self.image.write_bytes(bytes(SIZE))
        result = self.plant(*SENTINELS)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.image.read_bytes(), bytes(SIZE))

    def test_a_usage_error_is_exit_2(self) -> None:
        self.make_fs()
        before = self.image.read_bytes()
        image = str(self.image)
        self.assertEqual(self.run_script(image, "0").returncode, 2)
        self.assertEqual(self.run_script(image, "x", SENTINELS[0]).returncode, 2)
        self.assertEqual(self.plant("x" * BLOCK).returncode, 2)
        missing = str(self.dir / "none.img")
        self.assertEqual(self.run_script(missing, "0", SENTINELS[0]).returncode, 2)
        self.assertEqual(self.image.read_bytes(), before)


BTRFS_SIZE = 256 * 1024 * 1024
MIB = 1024 * 1024
# The superblock copy that falls inside a 256 MiB btrfs: at 64 MiB.
MIRROR = 64 * MIB
_DEV_EXTENT = re.compile(r"key \((\d+) DEV_EXTENT (\d+)\)")
_LENGTH = re.compile(r"\blength (\d+)")


@unittest.skipUnless(MKFS_BTRFS and BTRFS, "needs btrfs-progs")
class PlantInBtrfsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.image = self.dir / "root.img"
        tools = str(Path(str(BTRFS)).parent)
        self.env = {
            "PATH": os.pathsep.join([tools, os.environ.get("PATH", "")]),
            "TMPDIR": str(self.dir),
        }

    def make_fs(self, fill: bytes = b"\0") -> None:
        """A small single-device btrfs filesystem holding one file, made from a
        directory with no mount. With `fill`, every byte mkfs does not write
        keeps that value, as unallocated space holding old data does."""
        content = self.dir / "content"
        (content / "var" / "log").mkdir(parents=True, exist_ok=True)
        (content / "var" / "log" / "wtmp").write_bytes(b"\x01" * 10_000)
        self.image.write_bytes(fill * BTRFS_SIZE)
        subprocess.run(
            [str(MKFS_BTRFS), "-q", "-f", "-K", "--rootdir", str(content)]
            + [str(self.image)],
            check=True,
            capture_output=True,
        )

    def run_script(self, *args: str) -> subprocess.CompletedProcess[str]:
        # Through bash: the flake check copies the tree without its file modes.
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            capture_output=True,
            text=True,
            check=False,
            env=self.env,
        )

    def dev_extents(self) -> list[tuple[int, int]]:
        """Every device extent of the filesystem as (start, length)."""
        tree = subprocess.run(
            [str(BTRFS), "inspect-internal", "dump-tree", "-t", "dev"]
            + [str(self.image)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        extents = []
        start = None
        for line in tree.splitlines():
            key = _DEV_EXTENT.search(line)
            if key:
                start = int(key.group(2))
                continue
            length = _LENGTH.search(line)
            if start is not None and length:
                extents.append((start, int(length.group(1))))
                start = None
        return extents

    def unallocated(self, at: int, extents: list[tuple[int, int]]) -> bool:
        """Whether the block at filesystem byte `at` lies outside every device
        extent, the first MiB and the superblock copy."""
        if at < MIB or MIRROR - BLOCK < at < MIRROR + BLOCK:
            return False
        return all(not (s <= at < s + n) for s, n in extents)

    def test_each_string_lands_once_in_its_own_unallocated_zero_block(self) -> None:
        self.make_fs()
        extents = self.dev_extents()
        before = self.image.read_bytes()
        result = self.run_script(str(self.image), "0", *SENTINELS)
        self.assertEqual(result.returncode, 0, result.stderr)
        after = self.image.read_bytes()
        self.assertEqual(len(after), len(before))
        for sentinel in SENTINELS:
            self.assertEqual(after.count(f"{sentinel}\n".encode()), 1, sentinel)
        changed = changed_blocks(before, after)
        self.assertEqual(len(changed), len(SENTINELS))
        for i in changed:
            self.assertEqual(blocks(before)[i], bytes(BLOCK), f"block {i}")
            self.assertTrue(self.unallocated(i * BLOCK, extents), f"block {i}")
        # The superblock copy at 64 MiB, the first string's goal, is kept. It
        # holds data, so the zero check alone keeps it here, and the layout
        # btrfs-progs gives may put it in a chunk: MirrorTest tests the mirror
        # check itself.
        mirror = slice(MIRROR, MIRROR + BLOCK)
        self.assertEqual(before[mirror], after[mirror])
        # Nothing btrfs tracks changed: the same device extents, a clean check.
        self.assertEqual(self.dev_extents(), extents)
        check = subprocess.run(
            [str(BTRFS), "check", "--readonly", str(self.image)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(check.returncode, 0, check.stdout + check.stderr)

    def test_old_data_is_passed_over_and_never_overwritten(self) -> None:
        # Unallocated space holding old data throughout: nothing is planted and
        # the image is unchanged. One zeroed unallocated block past the goal
        # then takes the string, and only it.
        self.make_fs(fill=b"\xab")
        extents = self.dev_extents()
        # mkfs.btrfs zeroes the end of the device to wipe old signatures; give
        # every unallocated block old data, as a disk in use holds.
        data = bytearray(self.image.read_bytes())
        for i in range(BTRFS_SIZE // BLOCK):
            if self.unallocated(i * BLOCK, extents):
                data[i * BLOCK : (i + 1) * BLOCK] = b"\xab" * BLOCK
        self.image.write_bytes(bytes(data))
        before = self.image.read_bytes()
        result = self.run_script(str(self.image), "0", SENTINELS[0])
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("no zero-filled unallocated block", result.stderr)
        self.assertEqual(self.image.read_bytes(), before)

        first = BTRFS_SIZE // BLOCK // 2 + 5
        target = next(
            i
            for i in range(first, BTRFS_SIZE // BLOCK)
            if self.unallocated(i * BLOCK, extents)
        )
        data = bytearray(before)
        data[target * BLOCK : (target + 1) * BLOCK] = bytes(BLOCK)
        self.image.write_bytes(bytes(data))
        zeroed = self.image.read_bytes()
        result = self.run_script(str(self.image), "0", SENTINELS[0])
        self.assertEqual(result.returncode, 0, result.stderr)
        after = self.image.read_bytes()
        self.assertEqual(changed_blocks(zeroed, after), [target])
        self.assertTrue(blocks(after)[target].startswith(SENTINELS[0].encode()))

    def test_a_btrfs_filesystem_at_an_offset_in_a_disk_image(self) -> None:
        # A partition one MiB in: the script reads the filesystem from a sparse
        # copy, removes it, and plants into the image itself.
        self.make_fs()
        extents = self.dev_extents()
        fs_bytes = self.image.read_bytes()
        lead = b"\xcd" * MIB
        self.image.write_bytes(lead + fs_bytes)
        result = self.run_script(str(self.image), str(len(lead)), SENTINELS[0])
        self.assertEqual(result.returncode, 0, result.stderr)
        after = self.image.read_bytes()
        self.assertTrue(after.startswith(lead))
        at = after.index(SENTINELS[0].encode()) - len(lead)
        self.assertEqual(at % BLOCK, 0)
        self.assertEqual(fs_bytes[at : at + BLOCK], bytes(BLOCK))
        self.assertTrue(self.unallocated(at, extents))
        names = sorted(p.name for p in self.dir.iterdir())
        self.assertEqual(names, ["content", "root.img"])


_IS_MIRROR = re.compile(r"^is_mirror\(\) \{\n.*?^\}\n", re.MULTILINE | re.DOTALL)


class MirrorTest(unittest.TestCase):
    """is_mirror, the check that keeps a control off a btrfs superblock copy,
    which btrfs writes outside its chunks: run on its own, since whether a
    copy lies in unallocated space at all depends on the layout btrfs-progs
    gives a filesystem."""

    def is_mirror(self, at: int, size: int) -> bool:
        function = _IS_MIRROR.search(SCRIPT.read_text())
        self.assertIsNotNone(function, "is_mirror is not a top-level function")
        assert function is not None
        result = subprocess.run(
            [
                "bash",
                "-c",
                function.group(0) + 'is_mirror "$1" "$2"',
                "_",
                str(at),
                str(size),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertIn(result.returncode, (0, 1), result.stderr)
        return result.returncode == 0

    def test_a_block_overlapping_a_copy_is_one(self) -> None:
        for copy in (64 * MIB, 256 * 1024 * MIB, 1024 * 1024 * 1024 * MIB):
            for at, size in (
                (copy, BLOCK),
                (copy - 2048, BLOCK),
                (copy + 4095, 1),
                (copy - 32768, 65536),
            ):
                self.assertTrue(self.is_mirror(at, size), (copy, at, size))

    def test_a_block_beside_a_copy_is_not(self) -> None:
        for copy in (64 * MIB, 256 * 1024 * MIB, 1024 * 1024 * 1024 * MIB):
            for at, size in (
                (copy - BLOCK, BLOCK),
                (copy + BLOCK, BLOCK),
                (copy - 65536, 65536),
            ):
                self.assertFalse(self.is_mirror(at, size), (copy, at, size))
        for at in (0, MIB, 128 * MIB):
            self.assertFalse(self.is_mirror(at, BLOCK), at)


if __name__ == "__main__":
    unittest.main()
