"""Distribution-agnostic helpers for the portable distribution scenarios.

The smoke scenario (``nix/distro-tests/tests/smoke.nix``) runs the same
whole-root lifecycle on every distribution in the image table. A few of its
assertions have to know the decoy's own shape -- where a hidden write lands
depends on whether the tree it writes to is a filesystem of its own, and which
boot filesystems a distribution mounts differs between families. It also
compares the units failed each time it lists them with the failures the image
table lists as known for the image. The refusal scenario
(``nix/distro-tests/refusal.nix``) compares listings of the hidden root and of
the decoy's disk filesystems taken before and after NAILS refuses a family it
has not admitted. Keeping that logic here, as pure functions with a unit-test
suite, means the scenarios themselves stay thin driver scripts and the rules
cannot drift unnoticed: the ``distro-checks`` flake check locks them on every
``nix flake check``, without a VM.

Nothing here imports Nix or the test driver, so it runs under a plain
``python3 -m unittest``. The scenarios load it on the driver the same way they
load ``nails_e2e`` (a ``sys.path`` entry plus ``import distro_checks``).
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

# The hidden-volume layout the whole-root session writes, mirrored from
# ``nails_session::session::layout``. A hidden write to a path on the decoy
# root lands under ``<hidden>/root/upper``; a hidden write to a path on a decoy
# filesystem that is overlaid on its own lands under
# ``<hidden>/root/mounts/<unit>/upper``, where ``<unit>`` is the mount point as
# systemd escapes it. These two constants and :func:`escape_path` are the only
# coupling to that Rust layout; the Rust side carries the upgrade note if it
# moves.
ROOT_LAYER = "root/upper"
MOUNT_LAYERS = "root/mounts"

# The boot filesystems a hidden root must never be able to write to. A
# distribution may mount any subset of these; the scenario checks exactly the
# ones that are mounted. ``/boot/efi`` must come before ``/boot`` nowhere here --
# the order is only the order the scenario reports them in.
BOOT_FILESYSTEMS = ("/boot", "/boot/efi", "/efi")

# Overlay feature options whose "on" form would let the overlay diverge from a
# plain copy-up (an index that survives into the upper, a metadata-only copy
# that leaves data in the lower, a redirect created on a rename or followed back
# into the lower). NAILS pins all three off on every overlay it mounts
# (``nails_teardown::whole_root::nextroot::OVERLAY_FEATURE_OPTIONS``:
# ``index=off,metacopy=off,redirect_dir=nofollow``). None of the dangerous
# states may ever appear in the mount table.
FORBIDDEN_OVERLAY_OPTIONS = (
    "index=on",
    "metacopy=on",
    "redirect_dir=on",
    "redirect_dir=follow",
)

# The kernel echoes a feature option only when it differs from its own
# compiled default, so the absence of the "on" states proves nothing on a
# kernel whose defaults are those states: an overlay mounted without the pins
# echoes nothing there. ``redirect_dir`` defaults to ``nofollow`` only on a
# kernel built without ``CONFIG_OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW``, which the
# upstream default and the kernels of the image table keep: Debian's and
# Ubuntu's default to ``follow``, Arch's to ``on``. So every overlay NAILS
# mounts must echo the pin, and one that does not was mounted without the pins.
# ``index`` and ``metacopy`` default to their pinned "off" on Debian and
# Ubuntu, where nothing is echoed either way. This mirrors the kernel-tier twin
# in ``nails-core/tests/kernel_semantics.rs``, which asserts the same pin.
REQUIRED_OVERLAY_OPTIONS = ("redirect_dir=nofollow",)


def escape_path(path: str) -> str:
    """Escape a mount point as systemd does for a unit name, minus the suffix.

    A faithful port of ``nails_base::fstab::escape_path`` (which itself follows
    ``systemd-escape --path``): the leading slash and ``.`` components are
    dropped, ``..`` leading an absolute path is dropped, ``/`` becomes ``-`` and
    any byte outside ``[A-Za-z0-9:_.]`` becomes ``\\xNN``, with a leading ``.``
    escaped so a unit name never starts with a dot. The empty path is ``-``.

    The scenario needs this to name a decoy filesystem's layer directory on the
    hidden volume (``root/mounts/<escape_path(target)>/upper``), exactly as the
    session does, so a canary written to a separately mounted ``/home`` is read
    back from the right place.
    """
    absolute = path.startswith("/")
    kept: list[str] = []
    for component in path.split("/"):
        if not component or component == ".":
            continue
        if absolute and not kept and component == "..":
            continue
        kept.append(component)
    if not kept:
        return "-"
    joined = "/".join(kept)
    out: list[str] = []
    for index, byte in enumerate(joined.encode("utf-8")):
        char = chr(byte)
        if char == "/":
            out.append("-")
        elif char == "." and index == 0:
            out.append("\\x2e")
        elif char.isascii() and (char.isalnum() or char in ":_."):
            out.append(char)
        else:
            out.append(f"\\x{byte:02x}")
    return "".join(out)


def canary_name(tree: str) -> str:
    """The canary file the smoke scenario plants at the root of ``/<tree>``."""
    return f"nails-canary-{tree}"


def parse_mount_targets(findmnt_output: str) -> list[str]:
    """The mount points in ``findmnt -rn -o TARGET`` output, in order.

    One target per line; blank lines are dropped. The cloud images the suite
    boots have no mount point with a space in it, so the raw targets are taken
    verbatim.
    """
    return [line.strip() for line in findmnt_output.splitlines() if line.strip()]


def parse_findmnt_pairs(findmnt_output: str) -> list[tuple[str, str]]:
    """Parse ``findmnt -rn -o TARGET,OPTIONS`` output into ``(target, options)``.

    Each line is a target, a single space, then the comma-separated options; the
    options never contain a space, so splitting on the first run of whitespace is
    exact. A line with no options yields an empty option string.
    """
    pairs: list[tuple[str, str]] = []
    for line in findmnt_output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(None, 1)
        target = parts[0]
        options = parts[1] if len(parts) > 1 else ""
        pairs.append((target, options))
    return pairs


def _is_under(path: str, mount: str) -> bool:
    """Whether ``path`` lies on the filesystem mounted at ``mount``."""
    if mount == "/":
        return True
    mount = mount.rstrip("/")
    return path == mount or path.startswith(mount + "/")


def containing_mount(path: str, mounts: Iterable[str]) -> str:
    """The deepest mount point from ``mounts`` that ``path`` lies on.

    ``/`` is always an implicit candidate, so a path on no other mount resolves
    to ``/``. When two mount points both contain the path (a mount below a
    mount), the longer one wins -- the filesystem the path is actually on.
    """
    best = "/"
    for mount in mounts:
        if _is_under(path, mount) and len(mount.rstrip("/")) > len(best.rstrip("/")):
            best = mount
    return best


def canary_upper(hidden_root: str, tree: str, mounts: Iterable[str]) -> str:
    """Where a canary written into ``/<tree>`` lands on the hidden volume.

    The canary file sits at ``/<tree>/<canary_name(tree)>``. If ``/<tree>`` is
    part of the decoy root, the write lands in the root overlay's upper under
    ``<hidden>/root/upper/<tree>/...``. If ``/<tree>`` (or an ancestor of it) is
    a decoy filesystem of its own, the write lands in that filesystem's overlay
    upper under ``<hidden>/root/mounts/<unit>/upper/...``, with the path taken
    relative to the mount point. This assumes a writable tree gets an overlay,
    which is how the session treats the decoy's own home, ``/var`` and the like;
    a read-only bind would refuse the write instead, which the scenario never
    plants a canary into.
    """
    hidden_root = hidden_root.rstrip("/")
    full = f"/{tree.strip('/')}/{canary_name(tree)}"
    mount = containing_mount(f"/{tree.strip('/')}", mounts)
    if mount == "/":
        relative = full.lstrip("/")
        return f"{hidden_root}/{ROOT_LAYER}/{relative}"
    unit = escape_path(mount)
    relative = full[len(mount.rstrip("/")) :].lstrip("/")
    return f"{hidden_root}/{MOUNT_LAYERS}/{unit}/upper/{relative}"


def boot_mounts(mounts: Iterable[str]) -> list[str]:
    """The boot filesystems that are mounted, in :data:`BOOT_FILESYSTEMS` order.

    The scenario checks each of these is read-only in the hidden root; a
    distribution that mounts none of them (a BIOS host with ``/boot`` on the
    root filesystem) yields an empty list and the scenario skips the check.
    """
    present = set(mounts)
    return [target for target in BOOT_FILESYSTEMS if target in present]


# The units a mount pulls in that act on its device or filesystem, by the
# prefix of their name: the instances of systemd's templates, which the
# session skips with a skipped mount (``nails_session::session::fstab::checkers``).
DEVICE_UNIT_TEMPLATES = (
    "systemd-fsck@",
    "systemd-makefs@",
    "systemd-mkswap@",
    "systemd-growfs@",
    "systemd-pcrfs@",
    "systemd-validatefs@",
    "systemd-quotacheck@",
    "quotaon@",
)


def device_units(dependencies: str) -> list[str]:
    """The units in ``dependencies`` that act on a mount's device.

    ``dependencies`` is what ``systemctl show -P Requires`` and ``-P Wants``
    print for the mount: unit names separated by spaces, one property per
    line, and a name that holds a backslash (an escaped device path) in
    double quotes with the backslash doubled, so the names are split as a
    shell splits them. A skipped mount still starts these before its
    condition is tested, so the session skips them with it; the scenario
    checks that none of them ran.
    """
    units: list[str] = []
    for unit in shlex.split(dependencies):
        if unit.endswith(".service") and unit.startswith(DEVICE_UNIT_TEMPLATES):
            if unit not in units:
                units.append(unit)
    return units


def overlay_option_violations(options: str) -> list[str]:
    """How an overlay's options break the feature-option pins.

    ``options`` is a comma-separated mount-option list as ``findmnt`` prints it.
    The result lists the members of :data:`FORBIDDEN_OVERLAY_OPTIONS` present,
    in declaration order, then ``missing <pin>`` for each member of
    :data:`REQUIRED_OVERLAY_OPTIONS` absent; an empty result means the overlay
    pins the feature options as NAILS requires.
    """
    tokens = {token.strip() for token in options.split(",") if token.strip()}
    found = [option for option in FORBIDDEN_OVERLAY_OPTIONS if option in tokens]
    for option in REQUIRED_OVERLAY_OPTIONS:
        if option not in tokens:
            found.append(f"missing {option}")
    return found


def upperdir(options: str) -> str | None:
    """The ``upperdir=`` of an overlay's options, or None for a read-only one."""
    for token in options.split(","):
        key, _, value = token.strip().partition("=")
        if key == "upperdir":
            return value
    return None


def nails_overlays(
    pairs: Sequence[tuple[str, str]], hidden_root: str
) -> list[tuple[str, str]]:
    """The overlays NAILS mounted, from parsed ``findmnt`` ``(target, options)``.

    They are the ones whose upper is a layer directory on the hidden volume
    (``hidden_root``): its :data:`ROOT_LAYER` for the root overlay, a directory
    below its :data:`MOUNT_LAYERS` for a decoy filesystem overlaid on its own.
    Any other overlay (one the image itself mounts) is not NAILS's to pin and
    is left out.
    """
    hidden_root = hidden_root.rstrip("/")
    root_upper = f"{hidden_root}/{ROOT_LAYER}"
    mount_layers = f"{hidden_root}/{MOUNT_LAYERS}/"
    picked: list[tuple[str, str]] = []
    for target, options in pairs:
        upper = upperdir(options) or ""
        if upper == root_upper or upper.startswith(mount_layers):
            picked.append((target, options))
    return picked


def overlay_targets_with_violations(
    pairs: Sequence[tuple[str, str]],
) -> dict[str, list[str]]:
    """Map each overlay mount that violates the option pins to its violations.

    ``pairs`` is parsed ``findmnt -rn -t overlay -o TARGET,OPTIONS`` output,
    narrowed to NAILS's overlays (:func:`nails_overlays`). An overlay with no
    violation is omitted, so an empty mapping means every one of them pins the
    feature options correctly.
    """
    violations: dict[str, list[str]] = {}
    for target, options in pairs:
        found = overlay_option_violations(options)
        if found:
            violations[target] = found
    return violations


# --- What a refused run may leave behind ----------------------------------------
#
# The refusal scenario proves that a run NAILS refuses leaves nothing behind:
# it lists the hidden root and the decoy's disk filesystems before and after
# the refused commands, compares the listings and reads the journal entries
# written in between. A listing is plain ``find`` output, so the guest needs
# nothing the stock images do not ship. The listings of the decoy disk run to
# megabytes and are compared in the guest (``comm``), so only what differs
# crosses the driver's console.

#: The fields of a listed entry, in the order :func:`listing_command` prints them
#: between the device number and the path: the file type, the permission bits,
#: the owner, the group, the size, the inode, and the modification and
#: status-change times (seconds since the epoch, with the fraction). Access times
#: are left out: reading a file moves them, and a refused run reads the decoy's
#: configuration by design.
LISTING_FIELDS = ("type", "mode", "uid", "gid", "size", "inode", "mtime", "ctime")

#: Every field a listing with hashes records: what an entry is and holds, and
#: when it last changed.
ALL_FIELDS = (*LISTING_FIELDS, "sha256")

#: What an entry is and holds, without when it last changed or which inode holds
#: it.
CONTENT_FIELDS = ("type", "mode", "uid", "gid", "size", "sha256")

#: What shows that an entry changed, for a listing without hashes: every write
#: and every metadata change moves the status-change time, which no program can
#: set back. The inode number adds nothing to that, and on vfat it is not even
#: stable: the driver numbers an inode afresh each time it reads it back in.
CHANGE_FIELDS = ("type", "mode", "uid", "gid", "size", "mtime", "ctime")

#: The filesystem types a decoy keeps on its disk. A mount of any other type
#: (proc, tmpfs, an automount point, the harness's 9p shares and store overlay)
#: holds nothing of the decoy disk.
DISK_FILESYSTEMS = frozenset({"btrfs", "ext2", "ext3", "ext4", "f2fs", "vfat", "xfs"})

# The printf directives of one listed entry: the device, LISTING_FIELDS, the path.
_LISTING_FORMAT = "\\t".join(
    ("%D", "%y", "%m", "%U", "%G", "%s", "%i", "%T@", "%C@", "%p")
)


def listing_command(root: str, *, live: bool = False, hashes: bool = False) -> str:
    """The guest command that lists every entry of the filesystem at ``root``.

    One line per entry, tab-separated: the device number, the
    :data:`LISTING_FIELDS` and the path. ``find -xdev`` does not descend into
    another filesystem, but it still prints each mount point on ``root``, with
    the filesystem mounted there; the ``awk`` keeps the entries on the device of
    ``root`` itself, the first one ``find`` prints. On a ``live`` filesystem,
    one the system writes to on its own, an entry that goes away between the
    directory read and its ``stat`` does not fail the listing (``find`` still
    names it on stderr). With ``hashes``, a ``---`` line follows and then the
    ``sha256sum`` of every regular file.
    """
    quoted = shlex.quote(root)
    walk = f"find {quoted} -xdev -printf '{_LISTING_FORMAT}\\n'"
    if live:
        walk = f"{{ {walk} || true; }}"
    command = f"{walk} | awk -F '\\t' 'NR == 1 {{ dev = $1 }} $1 == dev'"
    if hashes:
        command += f"; echo ---; find {quoted} -xdev -type f -exec sha256sum -- {{}} +"
    return command


def parse_listing(text: str) -> dict[str, dict[str, str]]:
    """Parse :func:`listing_command` output into ``{path: {field: value}}``.

    The values stay the text the guest printed, so two listings compare field by
    field without reading the values. A regular file of a listing with hashes
    also carries ``sha256``. A line that does not split into the expected
    fields (a path with a tab in it) raises ``ValueError``, since a listing that
    dropped it could hide a change.
    """
    lines = text.splitlines()
    hashed: list[str] = []
    if "---" in lines:
        cut = lines.index("---")
        lines, hashed = lines[:cut], lines[cut + 1 :]
    entries: dict[str, dict[str, str]] = {}
    for line in lines:
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) != len(LISTING_FIELDS) + 2:
            raise ValueError(f"not a listing line: {line!r}")
        entries[parts[-1]] = dict(zip(LISTING_FIELDS, parts[1:-1], strict=True))
    for line in hashed:
        digest, separator, path = line.partition("  ")
        if not separator or path not in entries:
            raise ValueError(f"not a hash of a listed file: {line!r}")
        entries[path]["sha256"] = digest
    return entries


def listing_changes(
    before: dict[str, dict[str, str]],
    after: dict[str, dict[str, str]],
    fields: Sequence[str] = ALL_FIELDS,
) -> dict[str, str]:
    """How ``after`` differs from ``before``, by path, in path order.

    A path is ``added``, ``removed`` or ``changed: <field>, ...``, naming the
    ``fields`` whose values differ; a path whose ``fields`` all match is left
    out, so an empty result means the two listings agree on every one of them.
    """
    changes: dict[str, str] = {}
    for path in sorted(before.keys() | after.keys()):
        if path not in before:
            changes[path] = "added"
        elif path not in after:
            changes[path] = "removed"
        else:
            differ = [
                field
                for field in fields
                if before[path].get(field) != after[path].get(field)
            ]
            if differ:
                changes[path] = "changed: " + ", ".join(differ)
    return changes


def format_changes(changes: dict[str, str]) -> str:
    """One ``<path>: <change>`` line per changed path, for an assertion message."""
    return "\n".join(f"{path}: {change}" for path, change in changes.items())


def split_comm(text: str) -> tuple[str, str]:
    """Split ``comm -3 <before> <after>`` output of two sorted listings.

    ``comm`` prints a line only ``before`` holds as it is and a line only
    ``after`` holds behind one tab. A listing line starts with the device number,
    never with a tab, so the two never mix. The result is the ``before`` lines
    and the ``after`` lines, each a listing :func:`parse_listing` reads: a path
    listed in only one of them was removed or added, one listed in both changed.
    """
    before: list[str] = []
    after: list[str] = []
    for line in text.splitlines():
        if line.startswith("\t"):
            after.append(line[1:])
        elif line:
            before.append(line)
    return "\n".join(before), "\n".join(after)


def scan_offset(
    before: dict[str, dict[str, str]],
    after: dict[str, dict[str, str]],
    path: str,
) -> int:
    """Where to start reading the changed file ``path`` for what was written.

    A regular file that kept its inode and only grew, as a log does, gained what
    lies past its old size, which is where to look; anything older was there
    before. A new, replaced, truncated or rewritten file is read from the start.
    """
    old, new = before.get(path), after.get(path)
    if (
        old is None
        or new is None
        or old.get("type") != "f"
        or new.get("type") != "f"
        or old.get("inode") != new.get("inode")
    ):
        return 0
    old_size, new_size = int(old.get("size", "0")), int(new.get("size", "0"))
    return old_size if new_size > old_size else 0


def decoy_disk_mounts(pairs: Sequence[tuple[str, str]], hidden_root: str) -> list[str]:
    """The decoy's disk filesystems, from parsed ``findmnt -rn -o TARGET,FSTYPE``.

    These are the mounts of a :data:`DISK_FILESYSTEMS` type, in mount-table
    order, without the hidden root and anything below it. A mount under an
    automount point (the ESP that systemd's GPT generator mounts on demand) is
    left out as well: listing it would mount it, and its idle timeout unmounts
    it again at any moment, so two listings of it would differ for neither
    reason the scenario looks for.
    """
    automounts = {target for target, fstype in pairs if fstype == "autofs"}
    hidden = hidden_root.rstrip("/")
    found: list[str] = []
    for target, fstype in pairs:
        if fstype not in DISK_FILESYSTEMS or target in automounts:
            continue
        if _is_under(target, hidden) or target in found:
            continue
        found.append(target)
    return found


def outside_boot_noise(paths: Iterable[str], volatile: re.Pattern[str]) -> list[str]:
    """The ``paths`` that the boot-noise allowlist ``volatile`` does not cover.

    ``volatile`` is a pattern over paths relative to the decoy root, without a
    leading slash, as the forensic suite's ``disk_forensics.image_volatile``
    builds it (``var/``, ``run/``, ``tmp/`` and a few files in ``etc/``). An
    allowlisted tree's own directory (``/var`` itself) counts as covered too, so
    an entry added at its top level does not make its parent a finding.
    """
    left: list[str] = []
    for path in paths:
        relative = path.lstrip("/")
        if volatile.search(relative) or volatile.search(relative + "/"):
            continue
        left.append(path)
    return sorted(left)


def named_like_nails(paths: Iterable[str], names: Iterable[str]) -> list[str]:
    """The ``paths`` whose last component is a NAILS name.

    That is a name from ``names`` (the artifact registry's file names and the
    state lock's ``.lock``), or any name with ``nails`` in it, in any case.
    """
    known = set(names)
    found: list[str] = []
    for path in paths:
        name = path.rstrip("/").rsplit("/", 1)[-1]
        if name in known or "nails" in name.lower():
            found.append(path)
    return sorted(found)


def _journal_text(value: object) -> str:
    """A journal field's value as text: a field the journal stores as bytes is a
    JSON array of numbers, read byte for byte; a field set more than once is a
    list of its values."""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        if all(isinstance(item, int) for item in value):
            return bytes(value).decode("latin-1")
        return "\n".join(_journal_text(item) for item in value)
    return "" if value is None else str(value)


def _journal_entries(journal_json: str) -> list[dict[str, object]]:
    """The entries of ``journalctl -o json`` output, one JSON object per line."""
    return [json.loads(line) for line in journal_json.splitlines() if line.strip()]


def _describe(entry: dict[str, object]) -> str:
    """An entry as the unit or identifier that logged it and its message."""
    who = entry.get("UNIT") or entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM")
    return f"{_journal_text(who) or '?'}: {_journal_text(entry.get('MESSAGE'))}"


def journal_messages(journal_json: str) -> list[str]:
    """Every entry of ``journalctl -o json`` output, as :func:`journal_traces`
    reports one."""
    return [_describe(entry) for entry in _journal_entries(journal_json)]


def journal_traces(journal_json: str, tokens: Iterable[str]) -> list[str]:
    """The journal entries that name any of ``tokens``, from ``journalctl -o json``.

    Every field of an entry is searched, ignoring case: an entry a NAILS process
    wrote names it in ``_COMM`` and ``_EXE`` even when its message does not, and
    a mount unit systemd reports on names its mount point in the unit's escaped
    form only. Each match is reported as the unit or identifier that logged it
    and its message.
    """
    wanted = [token.lower() for token in tokens if token]
    found: list[str] = []
    for entry in _journal_entries(journal_json):
        text = "\n".join(_journal_text(value) for value in entry.values()).lower()
        if any(token in text for token in wanted):
            found.append(_describe(entry))
    return found


# --- The failures an image is known to show ----------------------------------
#
# An image-table entry can list the units its image is known to fail
# (``knownFailedUnits`` in nix/distro-tests/images.json): the ones failed in
# both hidden sessions and on the decoy after both ways back, each with a line
# its failed start logs, and the ones the release's warning names that the
# image does not install. The smoke scenario lists the failed units on the
# decoy before the first switch and right after each switch, and compares each
# listing with that list: a listing sees only what is failed at that moment,
# not a unit that failed while a switch stopped the old system and that the new
# system started again. It checks that each listed failure is the known one,
# and that the ``platform`` row of ``check`` warns about every unit listed. A
# known failure that is gone asks for the list, and then the warning, to be
# narrowed; the scenario never requires the warning to go away.

#: The image table, where a known failure is listed.
TABLE_FILE = "nix/distro-tests/images.json"

#: Where a release's warning is worded, for the messages that ask to narrow it.
WARNING_FILES = (
    "the caveat in nails-platform/src/platform/family.rs and docs/decoy-requirements.md"
)

#: The phases a ``knownFailedUnits`` table lists failed units for.
PHASES = ("hiddenSession", "afterReturn")

#: The unit types systemd knows, as the suffix of a unit name.
UNIT_SUFFIXES = (
    ".automount",
    ".device",
    ".mount",
    ".path",
    ".scope",
    ".service",
    ".slice",
    ".socket",
    ".swap",
    ".target",
    ".timer",
)

# The status circle systemctl puts before a failed unit on a terminal, in a
# UTF-8 locale and in any other; ``--plain`` leaves it out.
_STATUS_MARKS = ("\u25cf", "*")


def parse_failed_units(output: str) -> set[str]:
    """The units in ``systemctl list-units --state=failed --all --plain
    --no-legend --no-pager`` output: the first field of each line.

    A status circle in front of the name, which ``--plain`` leaves out, is not
    taken for a unit.
    """
    units: set[str] = set()
    for line in output.splitlines():
        fields = line.split()
        if fields and fields[0] in _STATUS_MARKS:
            fields = fields[1:]
        if fields:
            units.add(fields[0])
    return units


def failed_unit_mismatch(
    observed: Iterable[str], expected: Iterable[str]
) -> tuple[list[str], list[str]]:
    """How the failed units ``observed`` differ from the ``expected`` ones.

    The result is the unexpected units (failed, not expected) and the missing
    ones (expected, not failed), each sorted.
    """
    seen, wanted = set(observed), set(expected)
    return sorted(seen - wanted), sorted(wanted - seen)


def unit_stem(unit: str) -> str:
    """A unit name without its type suffix: ``chrony`` for ``chrony.service``."""
    for suffix in UNIT_SUFFIXES:
        if unit.endswith(suffix):
            return unit[: -len(suffix)]
    return unit


def units_not_named(message: str, units: Iterable[str]) -> list[str]:
    """The ``units`` whose stem ``message`` does not contain, ignoring case.

    A warning that names chrony and CUPS covers ``chrony.service`` and
    ``cups.service``. The result keeps the order of ``units``.
    """
    text = message.lower()
    return [unit for unit in units if unit_stem(unit).lower() not in text]


def listed_units(known: Mapping[str, Any]) -> list[str]:
    """Every unit a ``knownFailedUnits`` table lists, in a phase or as not in
    the image, sorted."""
    units = set(known["notInImage"])
    for phase in PHASES:
        units.update(known[phase])
    return sorted(units)


def messages_since(journal_json: str, since_usec: int) -> list[str]:
    """The messages of the ``journalctl -o json`` entries received at or after
    ``since_usec``.

    ``since_usec`` is a time on this boot's monotonic clock in microseconds, as
    ``systemctl show`` gives a unit's ``InactiveExitTimestampMonotonic``, the
    start of its latest run. Read from ``journalctl -u <unit>``, the result is
    everything the unit logged since that start, which needs only the unit's
    name on each entry. A soft-reboot keeps the boot and its clock, so what the
    unit logged in an earlier phase stays before that start.
    """
    found: list[str] = []
    for entry in _journal_entries(journal_json):
        stamp = _journal_text(entry.get("__MONOTONIC_TIMESTAMP"))
        if stamp.isdigit() and int(stamp) >= since_usec:
            found.append(_journal_text(entry.get("MESSAGE")))
    return found


def unexpected_failures(where: str, name: str, units: Sequence[str]) -> str:
    """Why the scenario stops on failed units its table does not list."""
    return (
        f"units failed {where} that knownFailedUnits does not expect on {name}:"
        f" {', '.join(units)}. A change to NAILS or to the image made them fail;"
        " their status is printed above."
    )


def known_failure_gone(
    unit: str, where: str, name: str, phase: str, not_in_image: Sequence[str]
) -> str:
    """What to do when a listed unit no longer fails in a phase."""
    message = (
        f"{unit} no longer fails {where} on {name}. The known upstream failure is"
        " gone there, probably fixed in a newer image. Remove it from"
        f" knownFailedUnits.{phase} in {TABLE_FILE}."
    )
    if not not_in_image:
        return f"{message} Then narrow the release's warning ({WARNING_FILES})."
    return (
        f"{message} The release's warning ({WARNING_FILES}) also covers what this"
        f" image does not install: {', '.join(not_in_image)}. Check those on an"
        " image that has them, or by hand, then narrow the warning to what still"
        " fails. Remove the warning only when all of it is shown fixed."
    )


def failure_not_known(
    unit: str, where: str, name: str, line: str, messages: Sequence[str]
) -> str | None:
    """None when the ``messages`` of a unit's failed start hold its known
    ``line``; otherwise why its failure is not the known one."""
    if any(line in message for message in messages):
        return None
    logged = "\n".join(messages) or "nothing"
    return (
        f"{unit} failed {where} on {name}, but its failed start did not log the"
        f" known line {line!r}, so it fails in another way. Find out why before"
        f" knownFailedUnits is changed. It logged:\n{logged}"
    )


def now_in_image(unit: str, name: str) -> str:
    """What to do when a unit listed as not in the image is in it."""
    return (
        f"{unit} is now in the {name} image, so this test can observe it. Move it"
        " from notInImage to hiddenSession and afterReturn with the line its"
        " failed start logs, or, if it starts in every phase, narrow the"
        f" release's warning ({WARNING_FILES}) to what still fails."
    )


def platform_row_problem(
    row: Mapping[str, Any] | None, known: Mapping[str, Any], name: str
) -> str | None:
    """None when the ``platform`` row of ``check --json`` covers every unit the
    ``knownFailedUnits`` table ``known`` lists; otherwise why it does not.

    The rule goes one way: while the table lists a unit, the row must warn and
    name it. A table that lists none asks nothing of the row, and the row never
    has to pass, so a warning broader than the table, or one given for another
    reason, is fine.
    """
    units = listed_units(known)
    if not units:
        return None
    status = row.get("status") if row is not None else "missing"
    message = str(row.get("message", "")) if row is not None else ""
    unnamed = units_not_named(message, units)
    if status == "warn" and not unnamed:
        return None
    wanted = unnamed if status == "warn" else units
    return (
        f"the platform row on {name} must warn and name {', '.join(wanted)} while"
        f" knownFailedUnits lists them, but it is {status}: {message!r}. Keep that"
        " part of the caveat until the unit is shown fixed and removed from the"
        " table."
    )
