"""Logical scans of a btrfs filesystem in a disk image, beside the raw one.

A raw scan of a disk image (``disk_forensics.run_strings_scan``) reads the
bytes as they lie on the disk. On a btrfs that compresses file contents it
cannot see what a compressed extent holds, and it never tells a deleted file
from free space. The smoke scenario (``nix/distro-tests/tests/smoke.nix``)
therefore also reads a btrfs decoy the way btrfs-progs does, offline and
read-only, from a sparse copy of its partition:

- the live tree: ``btrfs restore`` writes the files out decompressed, and the
  scan searches their contents;
- the history: ``btrfs-find-root`` lists the older roots of the tree of tree
  roots that copy-on-write left on the disk, and ``btrfs restore -t`` restores
  from one of them, so a file written and deleted since is still found while
  its blocks have not been reused.

Three planted controls show what each read sees on the image: a file btrfs
keeps plain, which the raw scan finds; a compressed file, which only the
logical scan finds; and a compressed file written and deleted, which only the
history finds.

The pure parts (reading ``sfdisk --json``, ``btrfs-find-root`` and a
superblock, building a path filter) are unit-tested without a VM by the
``distro-checks`` flake check; the parts that run a tool take its path, as the
scenario passes the store paths in.
"""

from __future__ import annotations

import errno
import json
import os
import re
import struct
import subprocess
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

# Where the primary superblock lies in a btrfs filesystem, and where in it the
# magic and the generation are (struct btrfs_super_block).
SUPERBLOCK_OFFSET = 0x10000
SUPERBLOCK_MAGIC = b"_BHRfS_M"
_MAGIC_AT = 0x40
_GENERATION_AT = 0x48

# How much of a file or an image one read takes.
_CHUNK = 8 * 1024 * 1024

# The prompt btrfs restore shows for a file whose extents it walks many times;
# "a" answers it for every file.
_RESTORE_ANSWERS = "a\n" * 4096


@dataclass(frozen=True)
class TreeRoot:
    """One root of the tree of tree roots that btrfs-find-root found."""

    bytenr: int
    generation: int
    level: int


def partition_number(device: str) -> int:
    """The partition number of a device node: 3 for /dev/sda3, 2 for
    /dev/nvme0n1p2. A disk whose name ends in a digit (nvme0n1, mmcblk0) numbers
    its partitions after a ``p``; any other disk, after its letters."""
    match = re.fullmatch(r"/dev/[a-z]+(\d+)", device) or re.fullmatch(
        r"/dev/[a-z]\S*\dp(\d+)", device
    )
    if not match:
        raise ValueError(f"{device} names no partition")
    return int(match.group(1))


def partition_extent(sfdisk_json: str, number: int) -> tuple[int, int]:
    """The start and the size in bytes of partition `number`, from ``sfdisk --json``.

    sfdisk names each partition by the image's path and its number; the number
    is the one the kernel gives the partition's device (sda3 is the third).
    """
    table = json.loads(sfdisk_json)["partitiontable"]
    if table.get("unit", "sectors") != "sectors":
        raise ValueError(
            f"sfdisk reports the table in {table.get('unit')}, not sectors"
        )
    sector = int(table.get("sectorsize", 512))
    for partition in table.get("partitions", []):
        node = str(partition["node"])
        found = re.search(r"(\d+)$", node)
        if found and int(found.group(1)) == number:
            return int(partition["start"]) * sector, int(partition["size"]) * sector
    raise ValueError(f"the partition table lists no partition {number}")


def superblock_generation(block: bytes) -> int:
    """The generation in a btrfs superblock, given the bytes at its offset."""
    if block[_MAGIC_AT : _MAGIC_AT + len(SUPERBLOCK_MAGIC)] != SUPERBLOCK_MAGIC:
        raise ValueError("no btrfs superblock at the given offset")
    (generation,) = struct.unpack_from("<Q", block, _GENERATION_AT)
    return int(generation)


_FOUND_ROOT = re.compile(r"Found tree root at (\d+) gen (\d+) level (\d+)")
_WELL_BLOCK = re.compile(r"Well block (\d+)\s*\(gen: (\d+) level: (\d+)\)")


def parse_find_root(output: str) -> list[TreeRoot]:
    """The roots ``btrfs-find-root`` reports, the newest generation first.

    It names the current root ("Found tree root at ...") and every older one it
    finds a block of ("Well block ... seems good, but generation/level doesn't
    match"). A root it reports twice is listed once.
    """
    roots: dict[int, TreeRoot] = {}
    for line in output.splitlines():
        for pattern in (_FOUND_ROOT, _WELL_BLOCK):
            match = pattern.search(line)
            if match:
                bytenr, generation, level = (int(group) for group in match.groups())
                roots.setdefault(bytenr, TreeRoot(bytenr, generation, level))
    return sorted(roots.values(), key=lambda root: (-root.generation, root.bytenr))


_ERE_SPECIAL = re.compile(r"([.^$\[\]()*+?{}|\\])")


def _ere_escape(name: str) -> str:
    """`name` as a literal in a POSIX extended regular expression."""
    return _ERE_SPECIAL.sub(r"\\\1", name)


def path_filter(paths: Iterable[str], below: bool = False) -> str:
    """A ``btrfs restore --path-regex`` that takes exactly `paths`.

    btrfs restore tests the filter (a POSIX extended regular expression)
    against every directory on the way to a file as well as against the file,
    so each ancestor matches as an empty alternative: ``^/(|var(|/tmp))$``
    takes /var and /var/tmp. With `below`, everything below each path is taken
    too.
    """
    tree: dict[str, dict] = {}
    for path in paths:
        parts = [part for part in path.split("/") if part]
        if not parts:
            raise ValueError(f"the filter needs a path below the top, not {path!r}")
        node = tree
        for part in parts:
            node = node.setdefault(part, {})
    if not tree:
        raise ValueError("the filter needs at least one path")

    def alternatives(node: dict[str, dict], separator: str) -> str:
        if not node:
            return "(|/.*)" if below else ""
        return (
            "(|"
            + "|".join(
                separator + _ere_escape(name) + alternatives(child, "/")
                for name, child in sorted(node.items())
            )
            + ")"
        )

    return "^/" + alternatives(tree, "") + "$"


def filesystem_path(subvolume: str, mount_point: str, path: str) -> str:
    """Where `path` lies in the btrfs filesystem, as btrfs restore writes it out.

    `path` lies below `mount_point`, which mounts the subvolume `subvolume`
    (the ``subvol=`` option, ``/`` for the top level). btrfs restore writes the
    top level out with each subvolume as a directory of that name, so a file
    of the subvolume ``/root`` mounted at ``/`` lies at ``/root/<path>``.
    """
    relative = os.path.relpath(path, mount_point)
    if relative.startswith(".."):
        raise ValueError(f"{path} is not below {mount_point}")
    base = "/" + subvolume.strip("/")
    joined = os.path.normpath(os.path.join(base, relative))
    return joined


def data_extents(fd: int, start: int, end: int) -> Iterator[tuple[int, int]]:
    """The stretches of [start, end) of a sparse file that hold data."""
    seek_data = getattr(os, "SEEK_DATA", None)
    seek_hole = getattr(os, "SEEK_HOLE", None)
    if seek_data is None or seek_hole is None:
        yield (start, end)
        return
    offset = start
    while offset < end:
        try:
            data = os.lseek(fd, offset, seek_data)
        except OSError as err:
            if err.errno == errno.ENXIO:
                return
            raise
        if data >= end:
            return
        hole = min(os.lseek(fd, data, seek_hole), end)
        yield (data, hole)
        offset = hole


def extract_partition(
    image: str | os.PathLike[str], start: int, size: int, dest: str | os.PathLike[str]
) -> None:
    """Copy [start, start + size) of a sparse disk image into a sparse file."""
    with open(image, "rb") as source, open(dest, "wb") as target:
        target.truncate(size)
        fd = source.fileno()
        for begin, finish in data_extents(fd, start, start + size):
            position = begin
            while position < finish:
                chunk = os.pread(fd, min(_CHUNK, finish - position), position)
                if not chunk:
                    break
                if chunk.count(0) != len(chunk):
                    os.pwrite(target.fileno(), chunk, position - start)
                position += len(chunk)


def read_generation(btrfs_image: str | os.PathLike[str]) -> int:
    """The generation in the superblock of a btrfs image."""
    with open(btrfs_image, "rb") as handle:
        handle.seek(SUPERBLOCK_OFFSET)
        return superblock_generation(handle.read(0x100))


def find_roots(find_root: str, btrfs_image: str | os.PathLike[str]) -> list[TreeRoot]:
    """The roots of the tree of tree roots on the image, newest first."""
    completed = subprocess.run(
        [find_root, str(btrfs_image)],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        check=False,
        timeout=900,
    )
    roots = parse_find_root(completed.stdout + "\n" + completed.stderr)
    if not roots:
        raise RuntimeError(
            f"btrfs-find-root found no root (exit {completed.returncode}):\n"
            f"{completed.stdout}\n{completed.stderr}"
        )
    return roots


def restore(
    btrfs: str,
    btrfs_image: str | os.PathLike[str],
    dest: str | os.PathLike[str],
    *,
    root: int | None = None,
    regex: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """``btrfs restore`` the image into `dest`, from `root` when given.

    Subvolumes and snapshots are restored as directories (-s), errors in one
    file do not stop the rest (-i), and only the paths `regex` takes are
    written when it is given. An older root's tree may be partly overwritten,
    so a restore from it may end with an error: what it wrote still counts.
    """
    os.makedirs(dest, exist_ok=True)
    command = [btrfs, "restore", "-s", "-i"]
    if root is not None:
        command += ["-t", str(root)]
    if regex is not None:
        command += ["--path-regex", regex]
    command += [str(btrfs_image), str(dest)]
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        input=_RESTORE_ANSWERS,
        check=False,
        timeout=1800,
    )


def tokens_in_tree(tree: str | os.PathLike[str], tokens: Sequence[str]) -> set[str]:
    """Which of `tokens` occur in the contents of a file below `tree`."""
    needles = {token: token.encode() for token in tokens if token}
    found: set[str] = set()
    if not needles:
        return found
    overlap = max(len(needle) for needle in needles.values())
    for directory, _, files in os.walk(tree):
        for name in files:
            path = Path(directory, name)
            if path.is_symlink() or not path.is_file():
                continue
            carry = b""
            with open(path, "rb") as handle:
                while len(found) < len(needles):
                    chunk = handle.read(_CHUNK)
                    if not chunk:
                        break
                    window = carry + chunk
                    for token, needle in needles.items():
                        if token not in found and needle in window:
                            found.add(token)
                    carry = window[-overlap:]
            if len(found) == len(needles):
                return found
    return found
