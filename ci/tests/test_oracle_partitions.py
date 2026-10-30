"""Tests for ci/oracle/partitions.sh: which partition of a whole-disk image the
oracle carves as the root, how its restore channel compares every other part
of the disk, and which images it refuses. The disk images are built from
files, with no root, no loop device and no mount."""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
LIBRARY = REPO_ROOT / "ci" / "oracle" / "partitions.sh"

MIB = 1024 * 1024
SECTOR = 512

# GPT partition types: a BIOS boot partition, an EFI system partition and a
# Linux filesystem.
BIOS_BOOT = "21686148-6449-6E6F-744E-656564454649"
ESP = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
LINUX = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"


def tool(name: str) -> str | None:
    """A tool from PATH or the sbin directories a user's PATH may leave out."""
    found = shutil.which(name)
    if found:
        return found
    for directory in ("/usr/sbin", "/sbin"):
        candidate = Path(directory) / name
        if candidate.exists():
            return str(candidate)
    return None


TOOLS = {
    name: tool(name)
    for name in (
        "sfdisk",
        "mmls",
        "blkid",
        "mkfs.fat",
        "mkfs.btrfs",
        "mkswap",
    )
}


@unittest.skipUnless(
    all(TOOLS.values()),
    "needs util-linux, sleuthkit, dosfstools and btrfs-progs",
)
class PartitionPlanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        directories = sorted({str(Path(str(path)).parent) for path in TOOLS.values()})
        # The tools first, then PATH for bash and the core utilities.
        self.env = {"PATH": os.pathsep.join([*directories, os.environ.get("PATH", "")])}

    # --- images -------------------------------------------------------------

    def filesystem(self, name: str, mib: int, *mkfs: str) -> bytes:
        """The bytes of a filesystem of `mib` MiB made in a file of its own."""
        path = self.dir / name
        path.write_bytes(bytes(mib * MIB))
        subprocess.run(
            [*mkfs, str(path)], check=True, capture_output=True, env=self.env
        )
        return path.read_bytes()

    def vfat(self, mib: int = 8, *options: str) -> bytes:
        return self.filesystem("esp.img", mib, str(TOOLS["mkfs.fat"]), *options)

    def btrfs(self) -> bytes:
        return self.filesystem("root.img", 128, str(TOOLS["mkfs.btrfs"]), "-q", "-f")

    def swap(self) -> bytes:
        return self.filesystem("swap.img", 8, str(TOOLS["mkswap"]))

    def disk(
        self, partitions: list[tuple[str, int, bytes]], label: str = "gpt"
    ) -> Path:
        """A disk image holding each (type, size in bytes, content) partition
        in order, each starting at the next MiB from 1 MiB on, with its content
        written at its start. A dos label takes MBR type codes."""
        image = self.dir / "disk.img"
        script = [f"label: {label}"]
        start = MIB
        for kind, size, _ in partitions:
            script.append(
                f"start={start // SECTOR}, size={size // SECTOR}, type={kind}"
            )
            start += -(-size // MIB) * MIB
        with image.open("wb") as handle:
            handle.truncate(start + MIB)
        self.sfdisk(image, script)
        start = MIB
        with image.open("r+b") as handle:
            for _, size, content in partitions:
                handle.seek(start)
                handle.write(content)
                start += -(-size // MIB) * MIB
        return image

    def sfdisk(self, image: Path, script: list[str]) -> None:
        subprocess.run(
            [
                str(TOOLS["sfdisk"]),
                "--quiet",
                "--no-reread",
                "--no-tell-kernel",
                str(image),
            ],
            input="\n".join(script) + "\n",
            text=True,
            check=True,
            capture_output=True,
            env=self.env,
        )

    def call(self, function: str, *args: str) -> subprocess.CompletedProcess[str]:
        # Through bash: the flake check copies the tree without its file modes.
        # PATH is set again inside, after anything bash reads as it starts.
        script = 'PATH=$1; shift; set -euo pipefail; . "$1"; shift; "$@"'
        return subprocess.run(
            [
                "bash",
                "-c",
                script,
                "_",
                self.env["PATH"],
                str(LIBRARY),
                function,
                *args,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            env=self.env,
        )

    def plan(self, image: Path, root: int) -> list[str]:
        result = self.call("partition_plan", str(image), str(root))
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines()

    def refused(self, function: str, *args: str) -> str:
        result = self.call(function, *args)
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(result.stdout, "")
        return result.stderr

    # --- the root and the plan ----------------------------------------------

    def test_a_fedora_disk_carves_its_root_and_compares_every_other_partition(
        self,
    ) -> None:
        # A BIOS boot partition holding boot code but no filesystem, an EFI
        # system partition and the btrfs root, as the Fedora Cloud image lays
        # them out.
        boot_code = b"\xeb\x63\x90" + b"core image " * 100
        image = self.disk(
            [
                (BIOS_BOOT, MIB, boot_code),
                (ESP, 8 * MIB, self.vfat()),
                (LINUX, 128 * MIB, self.btrfs()),
            ]
        )
        root = self.call("detect_fs", str(image))
        self.assertEqual(root.returncode, 0, root.stderr)
        self.assertEqual(root.stdout.split(), ["btrfs", str(10 * MIB), str(128 * MIB)])
        self.assertEqual(
            self.plan(image, 10 * MIB),
            [f"1 {MIB} {MIB} raw", f"2 {2 * MIB} {8 * MIB} vfat"],
        )

    def test_the_root_need_not_be_the_last_partition(self) -> None:
        # The root is told by its offset, and the partitions after it are
        # compared as well.
        image = self.disk(
            [
                (LINUX, 128 * MIB, self.btrfs()),
                (ESP, 8 * MIB, self.vfat()),
                (BIOS_BOOT, MIB, b"boot code"),
            ]
        )
        root = self.call("detect_fs", str(image))
        self.assertEqual(root.stdout.split()[:2], ["btrfs", str(MIB)], root.stderr)
        self.assertEqual(
            self.plan(image, MIB),
            [f"2 {129 * MIB} {8 * MIB} vfat", f"3 {137 * MIB} {MIB} raw"],
        )

    def test_an_mbr_disk_with_a_logical_partition(self) -> None:
        # A DOS table: the btrfs root and a vfat partition as primaries, and an
        # extended partition holding one logical vfat partition. The extended
        # partition is a container, not a partition: its tables lie outside
        # every partition, and the logical one is compared like a primary.
        image = self.dir / "disk.img"
        with image.open("wb") as handle:
            handle.truncate(160 * MIB)
        self.sfdisk(
            image,
            [
                "label: dos",
                f"start={MIB // SECTOR}, size={128 * MIB // SECTOR}, type=83",
                f"start={129 * MIB // SECTOR}, size={8 * MIB // SECTOR}, type=c",
                f"start={137 * MIB // SECTOR}, size={20 * MIB // SECTOR}, type=5",
                f"start={138 * MIB // SECTOR}, size={8 * MIB // SECTOR}, type=c",
            ],
        )
        with image.open("r+b") as handle:
            for at, content in (
                (MIB, self.btrfs()),
                (129 * MIB, self.vfat()),
                (138 * MIB, self.vfat()),
            ):
                handle.seek(at)
                handle.write(content)
        self.assertEqual(
            self.plan(image, MIB),
            [f"2 {129 * MIB} {8 * MIB} vfat", f"3 {138 * MIB} {8 * MIB} vfat"],
        )
        gaps = self.call("outside_partitions", str(image))
        self.assertEqual(gaps.returncode, 0, gaps.stderr)
        # The extended partition's own table sits at its first sector, outside
        # every partition.
        self.assertIn(f"{137 * MIB} {138 * MIB}", gaps.stdout.splitlines())

    def test_a_raw_partition_is_compared_whole_up_to_64_mib(self) -> None:
        # Compared whole only up to 64 MiB: one sector more would cost its size
        # in disk on every image and stops the run.
        image = self.disk([(LINUX, 64 * MIB, b""), (LINUX, 128 * MIB, self.btrfs())])
        self.assertEqual(self.plan(image, 65 * MIB), [f"1 {MIB} {64 * MIB} raw"])
        image = self.disk(
            [(LINUX, 64 * MIB + SECTOR, b""), (LINUX, 128 * MIB, self.btrfs())]
        )
        error = self.refused("partition_plan", str(image), str(66 * MIB))
        self.assertIn("holds no filesystem blkid recognises", error)

    def test_a_partition_no_carver_reads_stops_the_scan(self) -> None:
        # A swap partition beside the root: its content would go uncompared.
        image = self.disk(
            [(LINUX, 8 * MIB, self.swap()), (LINUX, 128 * MIB, self.btrfs())]
        )
        error = self.refused("partition_plan", str(image), str(9 * MIB))
        self.assertIn("partition 1 of", error)
        self.assertIn("holds a swap filesystem", error)

    def test_a_partition_blkid_cannot_tell_stops_the_scan(self) -> None:
        # blkid exits 8 when its probe is ambivalent (two filesystems on one
        # partition) and 4 on an error: either way the partition is not known
        # to be free of a filesystem, so it is not compared as raw bytes.
        image = self.disk(
            [(ESP, 8 * MIB, self.vfat()), (LINUX, 128 * MIB, self.btrfs())]
        )
        stub = self.dir / "bin" / "blkid"
        stub.parent.mkdir()
        for status in (8, 4):
            stub.write_text(f"#!/bin/sh\nexit {status}\n")
            stub.chmod(0o755)
            self.env["PATH"] = f"{stub.parent}:{self.env['PATH']}"
            error = self.refused("partition_plan", str(image), str(9 * MIB))
            self.assertIn(
                f"blkid cannot tell what partition 1 of {image} holds (exit {status})",
                error,
            )

    def test_a_table_mmls_cannot_read_or_without_the_root_stops_the_plan(
        self,
    ) -> None:
        # No table at all, and a table with no partition at the root's offset:
        # an empty plan would leave every other partition unseen.
        bare = self.dir / "bare.img"
        bare.write_bytes(self.btrfs())
        self.assertIn(
            "mmls cannot read", self.refused("partition_plan", str(bare), str(MIB))
        )
        image = self.disk(
            [(ESP, 8 * MIB, self.vfat()), (LINUX, 128 * MIB, self.btrfs())]
        )
        error = self.refused("partition_plan", str(image), str(11 * MIB))
        self.assertIn(f"at byte {11 * MIB}, the root's, 0 times, not once", error)

    def test_a_bare_filesystem_has_no_other_partition(self) -> None:
        image = self.dir / "bare.img"
        image.write_bytes(self.btrfs())
        root = self.call("detect_fs", str(image))
        self.assertEqual(root.returncode, 0, root.stderr)
        self.assertEqual(root.stdout.split(), ["btrfs", "0", "0"])

    def test_a_filesystem_at_byte_0_beside_a_partition_table_stops_the_scan(
        self,
    ) -> None:
        # btrfs from byte 0 and a GPT whose only partition, a vfat one, lies
        # past it: the image is neither a bare filesystem nor a whole disk the
        # scan can tell apart.
        image = self.dir / "disk.img"
        with image.open("wb") as handle:
            handle.truncate(150 * MIB)
        self.sfdisk(
            image,
            [
                "label: gpt",
                f"start={130 * MIB // SECTOR}, size={8 * MIB // SECTOR}, type={ESP}",
            ],
        )
        btrfs = self.btrfs()
        with image.open("r+b") as handle:
            # The first 64 KiB of btrfs are unused, so the GPT there stays.
            handle.seek(65536)
            handle.write(btrfs[65536:])
            handle.seek(130 * MIB)
            handle.write(self.vfat())
        error = self.refused("detect_fs", str(image))
        self.assertIn("a btrfs filesystem at byte 0 and a partition table too", error)

    # --- what lies outside the partitions -----------------------------------

    def test_outside_partitions_is_every_byte_no_partition_covers(self) -> None:
        # The protective MBR, the GPT and the gap before the first partition,
        # the gap between two partitions, and the backup GPT after the last.
        image = self.dir / "disk.img"
        with image.open("wb") as handle:
            handle.truncate(32 * MIB)
        self.sfdisk(
            image,
            [
                "label: gpt",
                f"start={MIB // SECTOR}, size={8 * MIB // SECTOR}, type={LINUX}",
                f"start={12 * MIB // SECTOR}, size={8 * MIB // SECTOR}, type={LINUX}",
            ],
        )
        gaps = self.call("outside_partitions", str(image))
        self.assertEqual(gaps.returncode, 0, gaps.stderr)
        self.assertEqual(
            gaps.stdout.splitlines(),
            [f"0 {MIB}", f"{9 * MIB} {12 * MIB}", f"{20 * MIB} {32 * MIB}"],
        )
        bare = self.dir / "bare.img"
        bare.write_bytes(bytes(MIB))
        self.assertIn("mmls cannot read", self.refused("outside_partitions", str(bare)))

    def test_the_fat_structures_end_where_the_data_area_starts(self) -> None:
        # FAT16 keeps its root directory among the structures, FAT32 in the
        # data area. The size is what the boot sector's parameters give.
        for fat, mib in (("16", 16), ("32", 64)):
            image = self.dir / f"fat{fat}.img"
            image.write_bytes(self.vfat(mib, "-F", fat))
            boot = image.read_bytes()[:512]
            bps, _, rsvd, nfats, rootents = struct.unpack_from("<HBHBH", boot, 11)
            fatsz = (
                struct.unpack_from("<H", boot, 22)[0]
                or struct.unpack_from("<I", boot, 36)[0]
            )
            want = (rsvd + nfats * fatsz + -(-rootents * 32 // bps)) * bps
            size = self.call("vfat_structures_size", str(image), "0", str(mib * MIB))
            self.assertEqual(
                (size.returncode, size.stdout.strip()), (0, str(want)), size.stderr
            )
            self.assertEqual(fat == "16", rootents > 0)
        garbage = self.dir / "garbage.img"
        garbage.write_bytes(b"\x01" * MIB)
        error = self.refused("vfat_structures_size", str(garbage), "0", str(MIB))
        self.assertIn("cannot read its layout", error)


if __name__ == "__main__":
    unittest.main()
