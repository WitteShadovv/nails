"""Tests for ci/oracle/partitions.sh: which partition of a whole-disk image the
oracle carves as the root, and how its restore channel compares every other
one. The disk images are built from files, with no root, no loop device and
no mount."""

from __future__ import annotations

import os
import shutil
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
    for name in ("sfdisk", "mmls", "blkid", "mkfs.fat", "mkfs.btrfs", "mkswap")
}


@unittest.skipUnless(
    all(TOOLS.values()), "needs util-linux, sleuthkit, dosfstools and btrfs-progs"
)
class PartitionPlanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(self.enterContext(tempfile.TemporaryDirectory()))
        directories = sorted({str(Path(str(path)).parent) for path in TOOLS.values()})
        # The tools first, then PATH for bash and the core utilities.
        self.env = {"PATH": os.pathsep.join([*directories, os.environ.get("PATH", "")])}

    def filesystem(self, name: str, mib: int, *mkfs: str) -> bytes:
        """The bytes of a filesystem of `mib` MiB made in a file of its own."""
        path = self.dir / name
        path.write_bytes(bytes(mib * MIB))
        subprocess.run(
            [*mkfs, str(path)], check=True, capture_output=True, env=self.env
        )
        return path.read_bytes()

    def vfat(self, mib: int = 8) -> bytes:
        return self.filesystem("esp.img", mib, str(TOOLS["mkfs.fat"]))

    def btrfs(self) -> bytes:
        return self.filesystem("root.img", 128, str(TOOLS["mkfs.btrfs"]), "-q", "-f")

    def swap(self) -> bytes:
        return self.filesystem("swap.img", 8, str(TOOLS["mkswap"]))

    def disk(self, partitions: list[tuple[str, int, bytes]]) -> Path:
        """A GPT disk image holding each (type, size in MiB, content) partition
        in order from 1 MiB on, each content written at its partition's start."""
        image = self.dir / "disk.img"
        total = 1 + sum(size for _, size, _ in partitions) + 1
        with image.open("wb") as handle:
            handle.truncate(total * MIB)
        script = ["label: gpt"]
        start = MIB
        for kind, size, _ in partitions:
            script.append(
                f"start={start // SECTOR}, size={size * MIB // SECTOR}, type={kind}"
            )
            start += size * MIB
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
        with image.open("r+b") as handle:
            start = MIB
            for _, size, content in partitions:
                handle.seek(start)
                handle.write(content)
                start += size * MIB
        return image

    def call(self, function: str, *args: str) -> subprocess.CompletedProcess[str]:
        # Through bash: the flake check copies the tree without its file modes.
        return subprocess.run(
            [
                "bash",
                "-c",
                'set -euo pipefail; . "$1"; shift; "$@"',
                "_",
                str(LIBRARY),
                function,
                *args,
            ],
            capture_output=True,
            text=True,
            check=False,
            env=self.env,
        )

    def test_a_fedora_disk_carves_its_root_and_compares_every_other_partition(
        self,
    ) -> None:
        # A BIOS boot partition holding boot code but no filesystem, an EFI
        # system partition and the btrfs root, as the Fedora Cloud image lays
        # them out.
        boot_code = b"\xeb\x63\x90" + b"core image " * 100
        image = self.disk(
            [
                (BIOS_BOOT, 1, boot_code),
                (ESP, 8, self.vfat()),
                (LINUX, 128, self.btrfs()),
            ]
        )
        root = self.call("detect_fs", str(image))
        self.assertEqual(root.returncode, 0, root.stderr)
        self.assertEqual(root.stdout.split(), ["btrfs", str(10 * MIB), str(128 * MIB)])
        plan = self.call("partition_plan", str(image), str(10 * MIB))
        self.assertEqual(plan.returncode, 0, plan.stderr)
        self.assertEqual(
            plan.stdout.splitlines(),
            [f"1 {MIB} {MIB} raw", f"2 {2 * MIB} {8 * MIB} vfat"],
        )

    def test_a_partition_no_carver_reads_stops_the_scan(self) -> None:
        # A swap partition beside the root: its content would go uncompared.
        image = self.disk([(LINUX, 8, self.swap()), (LINUX, 128, self.btrfs())])
        plan = self.call("partition_plan", str(image), str(9 * MIB))
        self.assertEqual(plan.returncode, 1)
        self.assertIn("partition 1 of", plan.stderr)
        self.assertIn("holds a swap filesystem", plan.stderr)
        self.assertEqual(plan.stdout, "")

    def test_a_partition_blkid_cannot_tell_stops_the_scan(self) -> None:
        # blkid exits 8 when its probe is ambivalent (two filesystems on one
        # partition) and 4 on an error: either way the partition is not known
        # to be free of a filesystem, so it is not compared as raw bytes.
        image = self.disk([(ESP, 8, self.vfat()), (LINUX, 128, self.btrfs())])
        stub = self.dir / "bin" / "blkid"
        stub.parent.mkdir()
        for status in (8, 4):
            stub.write_text(f"#!/bin/sh\nexit {status}\n")
            stub.chmod(0o755)
            self.env["PATH"] = f"{stub.parent}:{self.env['PATH']}"
            plan = self.call("partition_plan", str(image), str(9 * MIB))
            self.assertEqual(plan.returncode, 1, plan.stdout)
            self.assertIn(
                f"blkid cannot tell what partition 1 of {image} holds (exit {status})",
                plan.stderr,
            )

    def test_a_large_partition_without_a_filesystem_stops_the_scan(self) -> None:
        # Compared whole only up to 64 MiB: a larger one would cost its size in
        # disk on every image.
        image = self.disk([(LINUX, 65, b""), (LINUX, 128, self.btrfs())])
        plan = self.call("partition_plan", str(image), str(66 * MIB))
        self.assertEqual(plan.returncode, 1)
        self.assertIn("holds no filesystem blkid recognises", plan.stderr)

    def test_a_bare_filesystem_has_no_other_partition(self) -> None:
        image = self.dir / "bare.img"
        image.write_bytes(self.btrfs())
        root = self.call("detect_fs", str(image))
        self.assertEqual(root.returncode, 0, root.stderr)
        self.assertEqual(root.stdout.split(), ["btrfs", "0", "0"])
        plan = self.call("partition_plan", str(image), "0")
        self.assertEqual((plan.returncode, plan.stdout), (0, ""), plan.stderr)


if __name__ == "__main__":
    unittest.main()
