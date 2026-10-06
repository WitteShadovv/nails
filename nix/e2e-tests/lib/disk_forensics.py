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

import hashlib
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
    # Several of these tools (notably ``fls`` and ``strings``) echo raw on-disk
    # filenames and byte sequences that are not valid UTF-8. Decode with
    # replacement rather than letting an undecodable byte abort the whole scan:
    # the tokens we search for are ASCII, so a replacement char never hides or
    # invents a match.
    return subprocess.run(
        cmd, check=True, text=True, capture_output=True, errors="replace"
    )


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


def run_strings_scan(image: str | os.PathLike[str], tokens: Iterable[str]) -> set[str]:
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


# Bytes of context kept on each side of a token hit for the diagnostic snippet.
_SNIPPET_CONTEXT = 80
# How many matching paths to record per token before a token stops being scanned.
_MAX_PATHS_PER_TOKEN = 10


def token_snippet(
    haystack: str, token: str, context: int = _SNIPPET_CONTEXT
) -> str | None:
    """A one-line context snippet around the first occurrence of ``token``.

    Returns ``None`` when the token is absent. The window is ``context`` bytes on
    each side of the hit, collapsed to a single line so a binary file's control
    bytes cannot wreck the assertion message. Pure, so it is unit-testable without
    an image.
    """
    if not token:
        return None
    index = haystack.find(token)
    if index < 0:
        return None
    start = max(0, index - context)
    end = min(len(haystack), index + len(token) + context)
    window = haystack[start:end]
    # Flatten newlines/tabs and drop other control bytes so the snippet prints on
    # one readable line; the latin-1 decode upstream never fails, so this only
    # tidies, never hides, the match.
    cleaned = "".join(ch if (ch.isprintable() or ch == " ") else " " for ch in window)
    cleaned = " ".join(cleaned.split())
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(haystack) else ""
    return f"{prefix}{cleaned}{suffix}"


def scan_decoy_files_for_paths(
    image: str | os.PathLike[str],
    tokens: Iterable[str],
    *,
    offset: int | None = None,
    exclude: Iterable[str] = ("var/log/journal",),
    max_paths: int = _MAX_PATHS_PER_TOKEN,
) -> dict[str, list[str]]:
    """Map each present token to the decoy files that carry it, with context.

    Same carve as :func:`run_decoy_file_scan`, but instead of a bare set it returns
    ``{token: ["<relpath> :: <snippet>", …]}`` (sorted, at most ``max_paths`` per
    token) so a failing assertion can name the offending files and show a short
    latin-1 snippet around each hit. A token with no match is omitted.
    """
    offset = partition_offset(image) if offset is None else offset
    work = Path(tempfile.mkdtemp(prefix="nails-files-"))
    try:
        _rdump(str(image), offset, "/", work)
        for rel in exclude:
            shutil.rmtree(work / rel, ignore_errors=True)
        candidates = {token for token in tokens if token}
        hits: dict[str, list[str]] = {}
        for path in work.rglob("*"):
            # A token stops being scanned once it has enough example paths; when
            # every candidate is satisfied the walk can end early.
            pending = {t for t in candidates if len(hits.get(t, [])) < max_paths}
            if not pending:
                break
            if path.is_symlink():
                # A symlink's target name is still evidence; scan the link text.
                text = os.readlink(path)
            elif path.is_file():
                try:
                    text = _nails_latin1(path.read_bytes())
                except OSError:
                    continue
            else:
                continue
            # The path itself (a planted file's name) is evidence too.
            relpath = str(path.relative_to(work))
            haystack = text + "\n" + relpath
            for token in pending:
                snippet = token_snippet(haystack, token)
                if snippet is not None:
                    hits.setdefault(token, []).append(f"{relpath} :: {snippet}")
        return {token: sorted(paths) for token, paths in hits.items()}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run_decoy_file_scan(
    image: str | os.PathLike[str],
    tokens: Iterable[str],
    *,
    offset: int | None = None,
    exclude: Iterable[str] = ("var/log/journal",),
) -> set[str]:
    """Which ``tokens`` occur in the decoy's on-disk *files*, journal excluded.

    This answers "did the activate/deactivate cycle plant a nails artifact onto
    the decoy filesystem?" — a file whose name or content carries a registry
    token. It deliberately does not read the persistent journal: in this VM every
    command runs through a journaled service, so nails' own diagnostic stderr
    (which names its files, e.g. ``state.json`` or ``config/nails.toml``) is
    recorded in the journal even though nothing was written onto the decoy. That
    capture of the operator's console is a property of the harness, not a decoy
    trace — on a real host the operator's terminal output never reaches the decoy
    disk. Session-*content* leaking into the journal is still caught by the
    dedicated ``run_journal_scan``. With ``useNixStoreImage`` the Nix store is a
    separate drive, so carving the root partition does not pull in the store.

    Tokens are matched against raw file bytes decoded 1:1 (latin-1), so an ASCII
    token is found wherever it occurs regardless of surrounding binary content.
    Use :func:`scan_decoy_files_for_paths` for the offending paths and snippets.
    """
    # One example path per token is enough to know it occurs, and it lets the walk
    # stop as soon as every token is accounted for — the set API's old behaviour.
    return set(
        scan_decoy_files_for_paths(
            image, tokens, offset=offset, exclude=exclude, max_paths=1
        )
    )


def _nails_latin1(data: bytes) -> str:
    # latin-1 maps every byte to a code point 1:1, so ASCII tokens survive intact
    # and no byte can abort decoding.
    return data.decode("latin-1")


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


# --- Bodyfiles: MAC times of existing inodes ----------------------------------


@dataclass(frozen=True)
class BodyEntry:
    """One line of a sleuthkit bodyfile (``fls -r -m /``).

    ``path`` is relative to the filesystem root with no leading slash, with the
    `` -> target`` of a symlink and the ``(deleted)`` marker stripped; ``deleted``
    records the marker. Times are Unix seconds as ``fls`` prints them.
    """

    path: str
    inode: str
    mode: str
    uid: str
    gid: str
    size: int
    atime: int
    mtime: int
    ctime: int
    crtime: int
    deleted: bool


_DELETED_SUFFIXES = (" (deleted-realloc)", " (deleted)")

# The fields a hidden session must not change on an existing decoy inode. atime
# is kept out: it is reported, not asserted (see ``MAC_FIELDS_OBSERVED``).
MAC_FIELDS = ("inode", "mode", "uid", "gid", "size", "mtime", "ctime", "crtime")
MAC_FIELDS_OBSERVED = ("atime",)


def parse_bodyfile(text: str) -> list[BodyEntry]:
    """Parse bodyfile 3.x lines: ``MD5|name|inode|mode|UID|GID|size|atime|mtime|
    ctime|crtime``.

    The name is everything between the first ``|`` and the last nine, so a name
    holding ``|`` survives. Virtual sleuthkit entries (``$OrphanFiles``) and
    malformed lines are skipped.
    """
    entries: list[BodyEntry] = []
    for line in text.splitlines():
        head = line.split("|", 1)
        if len(head) != 2:
            continue
        fields = head[1].rsplit("|", 9)
        if len(fields) != 10:
            continue
        name, inode, mode, uid, gid, size, atime, mtime, ctime, crtime = fields
        deleted = False
        for suffix in _DELETED_SUFFIXES:
            if name.endswith(suffix):
                name = name[: -len(suffix)]
                deleted = True
                break
        if mode.startswith("l/") and " -> " in name:
            name = name.split(" -> ", 1)[0]
        path = name.lstrip("/")
        if not path or path.startswith("$Orphan"):
            continue
        try:
            entry = BodyEntry(
                path=path,
                inode=inode,
                mode=mode,
                uid=uid,
                gid=gid,
                size=int(size),
                atime=int(atime),
                mtime=int(mtime),
                ctime=int(ctime),
                crtime=int(crtime),
                deleted=deleted,
            )
        except ValueError:
            continue
        entries.append(entry)
    return entries


def bodyfile_index(entries: Iterable[BodyEntry]) -> dict[str, BodyEntry]:
    """Allocated entries by path; deleted names are ignored (``diff`` on the fls
    names already covers them)."""
    return {entry.path: entry for entry in entries if not entry.deleted}


def mac_changes(
    before: dict[str, BodyEntry],
    after: dict[str, BodyEntry],
    fields: Iterable[str] = MAC_FIELDS,
) -> dict[str, set[str]]:
    """For every path allocated in both, the ``fields`` whose values differ.

    A changed ``inode`` means the path was replaced; the other fields are then
    compared too, because a replacement is itself the finding.
    """
    wanted = tuple(fields)
    changes: dict[str, set[str]] = {}
    for path in before.keys() & after.keys():
        old, new = before[path], after[path]
        changed = {f for f in wanted if getattr(old, f) != getattr(new, f)}
        if changed:
            changes[path] = changed
    return changes


def hash_changes(before: dict[str, str], after: dict[str, str]) -> dict[str, set[str]]:
    """Paths present in both whose content hash differs, as ``{path: {"content"}}``
    so they combine with :func:`mac_changes` in :func:`unexplained`."""
    return {
        path: {"content"}
        for path in before.keys() & after.keys()
        if before[path] != after[path]
    }


def unexplained(
    test: dict[str, set[str]],
    control: dict[str, set[str]],
    volatile: re.Pattern[str],
) -> dict[str, list[str]]:
    """The test run's changes that neither the control run nor the allowlist
    explains.

    A ``(path, field)`` that also changed across the plain-reboot control run is
    boot noise; a path matching ``volatile`` is allowlisted outright. What is
    left changed only because of the hidden session.
    """
    left: dict[str, list[str]] = {}
    for path, fields in test.items():
        if volatile.search(path):
            continue
        extra = fields - control.get(path, set())
        if extra:
            left[path] = sorted(extra)
    return dict(sorted(left.items()))


def format_changes(
    changes: dict[str, list[str]],
    before: dict[str, BodyEntry],
    after: dict[str, BodyEntry],
    limit: int = 40,
) -> str:
    """One line per changed path with the old and new value of each field."""
    lines: list[str] = []
    for path, fields in list(changes.items())[:limit]:
        parts = []
        for field in fields:
            if field == "content":
                parts.append("content")
            elif path in before and path in after:
                parts.append(
                    f"{field} {getattr(before[path], field)} -> "
                    f"{getattr(after[path], field)}"
                )
            else:
                parts.append(field)
        lines.append(f"{path}: {', '.join(parts)}")
    if len(changes) > limit:
        lines.append(f"... and {len(changes) - limit} more")
    return "\n".join(lines)


def run_bodyfile(
    image: str | os.PathLike[str], offset: int | None = None
) -> tuple[str, list[BodyEntry]]:
    """Run ``fls -r -m /`` over the image's Linux partition; return the raw
    bodyfile (to keep as a test artifact, ``mactime -b`` ready) and its parse."""
    if offset is None:
        offset = partition_offset(image)
    cmd = [FLS, "-r", "-m", "/"]
    if offset:
        cmd += ["-o", str(offset), "-b", "512"]
    cmd.append(str(image))
    text = _run(cmd).stdout
    return text, parse_bodyfile(text)


def hash_tree(root: Path) -> dict[str, str]:
    """SHA-256 of every regular file under ``root``, keyed by relative path."""
    sums: dict[str, str] = {}
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        sums[str(path.relative_to(root))] = digest.hexdigest()
    return sums


def run_content_hashes(
    image: str | os.PathLike[str],
    *,
    offset: int | None = None,
    exclude: Iterable[str] = ("var/log/journal", "nix"),
) -> dict[str, str]:
    """Carve the decoy root out of the image and hash every regular file."""
    offset = partition_offset(image) if offset is None else offset
    work = Path(tempfile.mkdtemp(prefix="nails-hashes-"))
    try:
        _rdump(str(image), offset, "/", work)
        for rel in exclude:
            shutil.rmtree(work / rel, ignore_errors=True)
        return hash_tree(work)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def write_artifact(machine: object, name: str, text: str) -> Path:
    """Write ``text`` into the test's output directory (the derivation output,
    so a failing run keeps it), falling back to a temporary directory."""
    base = getattr(machine, "out_dir", None)
    out = Path(base) if base else Path(tempfile.mkdtemp(prefix="nails-artifacts-"))
    target = out / "forensics" / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target
