"""Host-side forensic inspection of a decoy VM's raw disk image.

This module runs inside the NixOS test *driver* (the Python the driver execs),
not inside the guest. The driver shuts a machine down, converts its root qcow2
to a flat raw image, and these helpers read that image from the outside with The
Sleuth Kit, ``strings``, ``debugfs`` and SQLite to answer one question: does any
trace of the hidden session survive on the *decoy* disk once the overlays are
gone?

The point of imaging the decoy root is that the old checks ran ``fls`` against
``/dev/vdb`` -- the LUKS *ciphertext* of the hidden volume -- so they could never
see a leak onto the decoy and could never fail. Here the whole decoy root is
imaged while the machine is off, exactly as a disk acquired post-seizure would
be, and the hidden volume is never consulted.

Tool paths default to bare command names, so the pure parsers below import and
unit-test without Nix. The ``forensic-vm-config.nix`` test wrapper points the
``NAILS_*`` environment variables at the Nix store before importing the module
(see ``disk-forensics.nix``); nothing here assumes a Nix store path.
"""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

# Tool paths. The driver sets these from the Nix store before import; the
# defaults keep the module importable (and the parsers testable) on their own.
QEMU_IMG = os.environ.get("NAILS_QEMU_IMG", "qemu-img")
FLS = os.environ.get("NAILS_FLS", "fls")
MMLS = os.environ.get("NAILS_MMLS", "mmls")
ICAT = os.environ.get("NAILS_ICAT", "icat")
STRINGS = os.environ.get("NAILS_STRINGS", "strings")
DEBUGFS = os.environ.get("NAILS_DEBUGFS", "debugfs")
JOURNALCTL = os.environ.get("NAILS_JOURNALCTL", "journalctl")


@dataclass(frozen=True)
class FlsEntry:
    """One line of ``fls -r -p`` output.

    ``path`` is relative to the filesystem root with no leading slash, exactly as
    ``fls`` prints it. ``deleted`` is the ``*`` marker; ``reallocated`` is the
    ``(realloc)`` suffix, meaning the name slot was reused and the content may be
    gone -- the name itself is still evidence.
    """

    path: str
    inode: str
    name_type: str
    deleted: bool
    reallocated: bool


_REALLOC_SUFFIX = "(realloc)"


def parse_fls(output: str) -> list[FlsEntry]:
    """Parse ``fls -r -p`` output into entries.

    The format is ``<meta>\\t<name>`` where ``<meta>`` is ``<t>/<t> [*] <inode>:``
    -- the two type characters, an optional ``*`` deleted marker, and the inode
    with a trailing colon. The name is whatever follows the single tab, so names
    with spaces survive. ``fls`` can print a plain integer inode (ext4) or a
    compound ``<inode>-<type>-<id>`` (NTFS); both are kept verbatim.
    """
    entries: list[FlsEntry] = []
    for raw_line in output.splitlines():
        line = raw_line.rstrip("\n")
        if not line.strip() or "\t" not in line:
            continue
        meta, name = line.split("\t", 1)
        tokens = meta.split()
        if len(tokens) < 2:
            continue
        name_types = tokens[0]
        deleted = "*" in tokens
        inode = tokens[-1].rstrip(":")
        name = name.strip()
        reallocated = name.endswith(_REALLOC_SUFFIX)
        if reallocated:
            name = name[: -len(_REALLOC_SUFFIX)].strip()
        if not name:
            continue
        name_type = name_types.split("/")[-1]
        entries.append(
            FlsEntry(
                path=name,
                inode=inode,
                name_type=name_type,
                deleted=deleted,
                reallocated=reallocated,
            )
        )
    return entries


def fls_paths(entries: Iterable[FlsEntry]) -> set[str]:
    """Collapse entries to the set of names seen, deleted names included."""
    return {entry.path for entry in entries}


def scan_tokens(haystack: str, tokens: Iterable[str]) -> set[str]:
    """Return the tokens that occur literally in ``haystack``.

    Used for both the raw ``strings`` dump and the recovered journal: a leak is a
    token that shows up at all, so this is a plain substring test rather than a
    regex. An empty token never matches (it would match everything).
    """
    found: set[str] = set()
    for token in tokens:
        if token and token in haystack:
            found.add(token)
    return found


_VALID_PATHS_QUERY = "SELECT path FROM ValidPaths"


def read_valid_paths(db_path: str | os.PathLike[str]) -> set[str]:
    """Read every registered store path from a Nix ``db.sqlite``.

    The store database records each realised path in ``ValidPaths``. Reading it
    straight (read-only, so a half-synced copy from the image cannot be written)
    shows which store paths the disk still vouches for -- a hidden package the
    decoy store registered is as telling as its files.
    """
    uri = f"file:{Path(db_path)}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        rows = conn.execute(_VALID_PATHS_QUERY).fetchall()
    return {str(row[0]) for row in rows}


def store_path_hits(valid_paths: Iterable[str], tokens: Iterable[str]) -> set[str]:
    """Return tokens that appear in any registered store path."""
    joined = "\n".join(valid_paths)
    return scan_tokens(joined, tokens)


def diff(before: Iterable[str], after: Iterable[str]) -> set[str]:
    """What the workflow added: names present after but not before.

    Keying the comparison on the baseline is what lets a stock image keep its own
    ``configuration.nix`` or ``nixos`` strings without tripping the scan: only
    what the activate/deactivate cycle introduced is a candidate leak.
    """
    return set(after) - set(before)


# --- Subprocess-backed helpers (driver side; exercised by the VM tests) -------


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=True, text=True, capture_output=True)


def root_image(machine: object) -> Path:
    """Locate a stopped machine's root qcow2 under its state directory.

    With ``useNixStoreImage`` the machine has a read-only Nix-store image as a
    second drive; the writable root overlay is the qcow2 named after the machine,
    and that is the disk the hidden session could have leaked onto. Raise rather
    than guess if the name is ambiguous.
    """
    state_dir = Path(machine.state_dir)  # type: ignore[attr-defined]
    name = getattr(machine, "name", "machine")
    preferred = state_dir / f"{name}.qcow2"
    if preferred.is_file():
        return preferred
    candidates = sorted(state_dir.glob("*.qcow2"))
    if len(candidates) == 1:
        return candidates[0]
    raise RuntimeError(
        f"cannot identify root qcow2 for {name!r} in {state_dir}: {candidates}"
    )


def snapshot(machine: object, label: str, *, restart: bool = True) -> Path:
    """Shut the machine down and convert its root disk to a flat raw image.

    Shutting down first flushes the guest page cache so the image is consistent.
    ``restart`` brings the same machine back up afterwards, which is what keeps a
    single disk lineage across ``baseline -> active -> post-standard`` instead of
    a fresh disk per stage (every fresh disk used to read as a finding).
    """
    machine.shutdown()  # type: ignore[attr-defined]
    image = root_image(machine)
    out_dir = Path(tempfile.mkdtemp(prefix="nails-forensic-"))
    raw = out_dir / f"{label}.raw"
    _run([QEMU_IMG, "convert", "-O", "raw", str(image), str(raw)])
    if restart:
        machine.start()  # type: ignore[attr-defined]
        machine.wait_for_unit("multi-user.target")  # type: ignore[attr-defined]
    return raw


_MMLS_LINUX = re.compile(
    r"^\s*\d+:\s+\S+\s+(?P<start>\d+)\s+\d+\s+\d+\s+(?P<desc>.+?)\s*$"
)


def partition_offset(image: str | os.PathLike[str]) -> int:
    """Sector offset of the largest Linux filesystem partition, or 0.

    The root image is a whole GPT disk (ESP plus root), so ``fls`` needs the
    partition start in sectors. ``mmls`` lists them; the Linux data partition is
    the one to carve. A single-filesystem image with no partition table yields 0.
    """
    try:
        proc = _run([MMLS, str(image)])
    except (subprocess.CalledProcessError, FileNotFoundError):
        return 0
    best_offset = 0
    best_start = -1
    for line in proc.stdout.splitlines():
        match = _MMLS_LINUX.match(line)
        if not match:
            continue
        desc = match.group("desc").lower()
        if "linux" not in desc and "ext" not in desc:
            continue
        start = int(match.group("start"))
        if start > best_start:
            best_start = start
            best_offset = start
    return best_offset


def run_fls(image: str | os.PathLike[str], offset: int | None = None) -> list[FlsEntry]:
    """Run ``fls -r -p`` over the image's Linux partition and parse it."""
    if offset is None:
        offset = partition_offset(image)
    cmd = [FLS, "-r", "-p"]
    if offset:
        cmd += ["-o", str(offset), "-b", "512"]
    cmd.append(str(image))
    proc = _run(cmd)
    return parse_fls(proc.stdout)


def run_strings_scan(
    image: str | os.PathLike[str], tokens: Iterable[str]
) -> set[str]:
    """Which of ``tokens`` appear anywhere in the raw image bytes."""
    proc = _run([STRINGS, "-a", str(image)])
    return scan_tokens(proc.stdout, tokens)


def _rdump(image: str, offset: int, src: str, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    args = [DEBUGFS]
    if offset:
        # debugfs wants a byte offset into the whole-disk image.
        args += ["-o", str(offset * 512)]
    args += ["-R", f"rdump {src} {dest}", str(image)]
    _run(args)


def run_journal_scan(
    image: str | os.PathLike[str],
    tokens: Iterable[str],
    *,
    offset: int | None = None,
) -> set[str]:
    """Carve the persistent journal out of the image and scan its text.

    ``debugfs rdump`` lifts ``/var/log/journal`` out of the ext4 partition;
    ``journalctl --directory`` then renders it to plain text that the token scan
    reads. A journal that is empty or absent simply yields no hits.
    """
    offset = partition_offset(image) if offset is None else offset
    work = Path(tempfile.mkdtemp(prefix="nails-journal-"))
    try:
        _rdump(str(image), offset, "/var/log/journal", work)
        journal_root = work / "journal"
        if not journal_root.is_dir():
            return set()
        text_parts: list[str] = []
        for machine_dir in sorted(journal_root.iterdir()):
            if not machine_dir.is_dir():
                continue
            proc = _run(
                [JOURNALCTL, "--directory", str(machine_dir), "--no-pager", "-o", "cat"]
            )
            text_parts.append(proc.stdout)
        return scan_tokens("\n".join(text_parts), tokens)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run_store_scan(
    image: str | os.PathLike[str],
    tokens: Iterable[str],
    *,
    offset: int | None = None,
) -> set[str]:
    """Carve the Nix store DB out of the image and scan its registered paths."""
    offset = partition_offset(image) if offset is None else offset
    work = Path(tempfile.mkdtemp(prefix="nails-store-"))
    try:
        _rdump(str(image), offset, "/nix/var/nix/db/db.sqlite", work)
        db = work / "db.sqlite"
        if not db.is_file():
            return set()
        return store_path_hits(read_valid_paths(db), tokens)
    finally:
        shutil.rmtree(work, ignore_errors=True)
