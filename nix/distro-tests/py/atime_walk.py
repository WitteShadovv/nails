"""The guest side of the access-time scenario: age and list the decoy disk.

The scenario (nix/distro-tests/tests/access-times.nix) runs this with the
guest's own python3, through ``noatime-run``, so that its reads change no
access time: every mount of its namespace is noatime. It knows only the
standard library, and its output is one JSON object on standard output.

``mounts``
    The decoy disk's filesystems: every mount of a block device of the disk
    that holds ``/``, of a filesystem that keeps access times to the
    nanosecond (ext2/3/4, xfs, btrfs, f2fs). The ESP (vfat keeps the date of
    an access only) and the hidden volume (a loop or device-mapper device)
    are not on the list.
``age SECONDS MOUNT...``
    Set the access time of every entry of those filesystems, files,
    directories and links alike, to SECONDS before now, and keep its
    modification time. The change time becomes now. Under ``relatime`` the
    next read of each entry then updates its access time, because the access
    time is older than a day and older than the change time: an aged tree
    shows every read once.
``list REF_NS MOUNT...``
    Every entry whose access time is later than REF_NS (nanoseconds since the
    epoch), with its access, change and modification times.

A walk stays on its filesystem: it does not enter a directory that another
mount covers (it does enter a btrfs subvolume that is not mounted, which is
part of the tree), and it lists the root of each walked mount. ``--skip PATH``
before the command, given any number of times, leaves PATH and everything
below it out: the scenario's own tools, which the decoy's shell starts.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from collections.abc import Iterator

#: Filesystems whose access times the scenario reads.
DISK_FSTYPES = frozenset({"ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs"})


def unescape(field: str) -> str:
    """A mountinfo field with the kernel's octal escapes undone."""
    out = []
    i = 0
    while i < len(field):
        if field[i] == "\\" and i + 4 <= len(field) and field[i + 1 : i + 4].isdigit():
            out.append(chr(int(field[i + 1 : i + 4], 8)))
            i += 4
        else:
            out.append(field[i])
            i += 1
    return "".join(out)


def parse_mountinfo(text: str) -> list[tuple[str, str, str]]:
    """(target, fstype, source) of each mount, in the table's order."""
    mounts = []
    for line in text.splitlines():
        head, sep, tail = line.partition(" - ")
        fields = head.split()
        rest = tail.split()
        if not sep or len(fields) < 5 or len(rest) < 2:
            continue
        mounts.append((unescape(fields[4]), rest[0], unescape(rest[1])))
    return mounts


def disk_of(device: str) -> str | None:
    """The whole disk a block device node is on (``vda`` for /dev/vda4)."""
    if not device.startswith("/dev/"):
        return None
    try:
        real = os.path.realpath(device)
    except OSError:
        return None
    name = os.path.basename(real)
    block = f"/sys/class/block/{name}"
    if not os.path.exists(block):
        return None
    if os.path.exists(os.path.join(block, "partition")):
        return os.path.basename(os.path.dirname(os.path.realpath(block)))
    return name


def decoy_mounts(mounts: list[tuple[str, str, str]]) -> list[str]:
    """The targets of the decoy disk's filesystems (see the module docs)."""
    root = [source for target, fstype, source in mounts if target == "/"]
    if not root:
        return []
    disk = disk_of(root[-1])
    if disk is None:
        return []
    targets: list[str] = []
    for target, fstype, source in mounts:
        if fstype in DISK_FSTYPES and disk_of(source) == disk and target not in targets:
            targets.append(target)
    return targets


def walk(top: str, covered: frozenset[str]) -> Iterator[tuple[str, os.stat_result]]:
    """Every entry below the mount ``top``, ``top`` included, by lstat,
    without entering a directory in ``covered`` (another mount's target)."""
    try:
        yield top, os.lstat(top)
    except OSError:
        return
    stack = [top]
    while stack:
        directory = stack.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError:
            continue
        for entry in entries:
            path = entry.path
            if path in covered:
                continue
            try:
                st = os.lstat(path)
            except OSError:
                continue
            yield path, st
            if stat.S_ISDIR(st.st_mode):
                stack.append(path)


def kind(mode: int) -> str:
    """One letter for the entry's type."""
    if stat.S_ISREG(mode):
        return "f"
    if stat.S_ISDIR(mode):
        return "d"
    if stat.S_ISLNK(mode):
        return "l"
    return "o"


def all_targets() -> frozenset[str]:
    with open(
        "/proc/self/mountinfo", encoding="utf-8", errors="surrogateescape"
    ) as handle:
        return frozenset(target for target, _, _ in parse_mountinfo(handle.read()))


def entries_of(
    tops: list[str], skip: frozenset[str] = frozenset()
) -> Iterator[tuple[str, os.stat_result]]:
    targets = all_targets()
    for top in tops:
        yield from walk(top, (targets - {top}) | skip)


def age(
    seconds: int, tops: list[str], skip: frozenset[str] = frozenset()
) -> dict[str, object]:
    """Age every entry (see the module docs). The whole walk comes first, so
    that a listing of a directory after its aging cannot update its access
    time again where the namespace keeps access times."""
    when = time.time_ns() - seconds * 1_000_000_000
    count = failed = 0
    for path, st in list(entries_of(tops, skip)):
        try:
            os.utime(path, ns=(when, st.st_mtime_ns), follow_symlinks=False)
            count += 1
        except OSError:
            failed += 1
    return {"aged": count, "failed": failed, "to": when}


def listing(
    ref_ns: int, tops: list[str], skip: frozenset[str] = frozenset()
) -> dict[str, object]:
    """The entries read since ``ref_ns`` (see the module docs)."""
    walked = 0
    found = []
    for path, st in entries_of(tops, skip):
        walked += 1
        if st.st_atime_ns > ref_ns:
            found.append(
                [path, st.st_atime_ns, st.st_ctime_ns, st.st_mtime_ns, kind(st.st_mode)]
            )
    found.sort()
    return {"walked": walked, "ref": ref_ns, "entries": found}


def main(argv: list[str]) -> int:
    skipped = []
    while len(argv) >= 2 and argv[0] == "--skip":
        skipped.append(argv[1])
        argv = argv[2:]
    skip = frozenset(skipped)
    if len(argv) >= 1 and argv[0] == "mounts":
        with open(
            "/proc/self/mountinfo", encoding="utf-8", errors="surrogateescape"
        ) as handle:
            result: dict[str, object] = {
                "mounts": decoy_mounts(parse_mountinfo(handle.read()))
            }
    elif len(argv) >= 3 and argv[0] == "age":
        result = age(int(argv[1]), argv[2:], skip)
    elif len(argv) >= 3 and argv[0] == "list":
        result = listing(int(argv[1]), argv[2:], skip)
    else:
        print(
            "usage: atime_walk.py [--skip PATH]... mounts | age SECONDS MOUNT... "
            "| list REF_NS MOUNT...",
            file=sys.stderr,
        )
        return 2
    json.dump(result, sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
