"""libmount's utab against the mount table, for the NixOS test driver.

libmount keeps the options the kernel does not store (``x-initrd.mount``,
``x-*``) in ``/run/mount/utab`` and joins each line to a mount whenever a
program reads the mount table through it: a line that names a mount ID to the
mount with that ID, wherever it is and whatever its source; a line without one
to the newest mount at the line's target with its source and root. A line
joins only when it has a source, a target, a root and options or attributes.
systemd reads the joined options, and a mount it takes for an initrd mount
leaves the shutdown order, which is how a stale line hangs a switch.

NAILS keeps a line across a switch only while it names a mount the switch
carries, and the way back gives the decoy's lines back under the new IDs of
the mounts it restores. :func:`wrong_lines` finds the lines that name no mount
or another one than they were written for; :func:`not_given_back` compares the
decoy's utab after a way back with the copy recorded before the entry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: The keys whose first value libmount reads, besides ``ID`` and ``UNIQID``.
STRING_KEYS = ("SRC", "TARGET", "ROOT", "BINDSRC", "OPTS", "ATTRS")
#: Where an initrd mounts the root it switches to.
SYSROOT = "/sysroot"


@dataclass(frozen=True)
class Mount:
    """One line of ``/proc/self/mountinfo``."""

    id: int
    dev: str
    root: str
    point: str
    source: str

    @property
    def identity(self) -> tuple[str, str, str]:
        """What a switch keeps of a mount it carries: its place, its
        filesystem and the directory of that filesystem it shows."""
        return (self.point, self.dev, self.root)


@dataclass(frozen=True)
class Line:
    """One utab line as libmount 2.42 reads it."""

    text: str
    #: The mount ID, 0 for none.
    id: int
    fields: dict[str, str]

    @property
    def joins(self) -> bool:
        """Whether libmount joins the line to a mount at all."""
        return all(key in self.fields for key in ("SRC", "TARGET", "ROOT")) and (
            "OPTS" in self.fields or "ATTRS" in self.fields
        )


def unescape(value: str) -> str:
    """A path as the kernel and libmount write it, octal escapes undone."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), value)


def parse_mountinfo(text: str) -> list[Mount]:
    """The mounts of a ``/proc/self/mountinfo`` text, in its order."""
    mounts = []
    for row in text.splitlines():
        fields = row.split(" ")
        if "-" not in fields or len(fields) < 5:
            continue
        sep = fields.index("-")
        mounts.append(
            Mount(
                id=int(fields[0]),
                dev=fields[2],
                root=unescape(fields[3]),
                point=unescape(fields[4]),
                source=unescape(fields[sep + 2]) if len(fields) > sep + 2 else "",
            )
        )
    return mounts


#: A number as ``strtol`` reads one, up to where libmount wants it to end.
NUMBER = re.compile(r"[ \t\n\v\f\r]*([+-]?[0-9]+)")


def parse_line(text: str) -> Line | None:
    """One utab line, or ``None`` for one libmount skips: a blank line, a
    comment, a line with a number it cannot read."""
    body = text.removesuffix("\r").lstrip(" \t")
    if body == "" or body.startswith("#"):
        return None
    numbers = {"ID": 0, "UNIQID": 0}
    fields: dict[str, str] = {}
    tokens = body.split(" ")
    for i, token in enumerate(tokens):
        key, eq, value = token.partition("=")
        if not eq:
            continue
        # A value ends at a tab; what follows it up to a space is skipped.
        value = value.partition("\t")[0]
        if key in numbers and numbers[key] == 0:
            # An empty number at the very end of the line is none at all.
            if value == "" and i == len(tokens) - 1:
                continue
            number = NUMBER.fullmatch(value)
            if number is None:
                return None
            numbers[key] = int(number.group(1))
        elif key in STRING_KEYS and key not in fields:
            fields[key] = unescape(value)
    return Line(text=text, id=numbers["ID"], fields=fields)


def parse_utab(text: str) -> list[Line]:
    """The lines of a utab text that libmount reads."""
    lines = (parse_line(row) for row in text.splitlines())
    return [line for line in lines if line is not None]


def joined(line: Line, mounts: list[Mount]) -> Mount | None:
    """The mount libmount joins ``line`` to among ``mounts``."""
    if not line.joins:
        return None
    if line.id > 0:
        return next((m for m in mounts if m.id == line.id), None)
    at = line.fields["TARGET"], line.fields["SRC"], line.fields["ROOT"]
    return next(
        (m for m in reversed(mounts) if (m.point, m.source, m.root) == at), None
    )


def _written_for(line: Line, mount: Mount) -> bool:
    """Whether ``mount`` is the one ``line`` was written for: its source and
    root, at its target or, for a line an initrd wrote, at that target seen
    from the root it switched to."""
    target = line.fields["TARGET"]
    places = {target}
    if target == SYSROOT or target.startswith(SYSROOT + "/"):
        places.add(target.removeprefix(SYSROOT) or "/")
    return (
        mount.source == line.fields["SRC"]
        and mount.root == line.fields["ROOT"]
        and mount.point in places
    )


def wrong_lines(utab: str, mountinfo: str) -> list[str]:
    """The lines of ``utab`` that libmount joins to no mount, or to another
    mount than the one they were written for. Lines libmount never joins to a
    mount are left alone."""
    mounts = parse_mountinfo(mountinfo)
    wrong = []
    for line in parse_utab(utab):
        if not line.joins:
            continue
        mount = joined(line, mounts)
        if mount is None or not _written_for(line, mount):
            wrong.append(line.text)
    return wrong


def _with_id(text: str, ident: str) -> str:
    """``text`` with the value of its ``ID`` field replaced by ``ident``."""
    tokens = text.split(" ")
    for i, token in enumerate(tokens):
        if token.startswith("ID="):
            tokens[i] = "ID=" + ident
            break
    return " ".join(tokens)


def without_id(text: str) -> str:
    """A utab line with the value of its mount ID left out: what stays of a
    line that a way back gives back under a new ID."""
    return _with_id(text, "")


def not_given_back(
    recorded_utab: str, recorded_mountinfo: str, utab: str, mountinfo: str
) -> tuple[list[str], list[str]]:
    """Compare the decoy's ``utab`` after a way back with its copy recorded,
    with the mount table, before the entry.

    Returns the lines that do not belong there, and the recorded lines that
    did not come back. A line belongs when it is a recorded line with at most
    its mount ID changed, or when it is the decoy's own line for a filesystem
    it mounted after the switch, at the line's own target. A recorded line
    must come back, under the ID of the mount now in its mount's place, when
    the way back restored that mount: the same filesystem at the same place.
    A filesystem is told by its device number, which a new filesystem can
    reuse only once the old one is gone: the filesystems the recorded lines
    name must stay mounted somewhere until the comparison, as the ones a
    session carries do.
    """
    then = parse_mountinfo(recorded_mountinfo)
    now = parse_mountinfo(mountinfo)
    recorded = parse_utab(recorded_utab)
    current = parse_utab(utab)
    expected = []
    for line in recorded:
        mount = joined(line, then)
        if mount is None:
            continue
        back = next((m for m in reversed(now) if m.identity == mount.identity), None)
        if back is None:
            continue
        expected.append(_with_id(line.text, str(back.id)) if line.id > 0 else line.text)
    texts = [line.text for line in current]
    lost = [text for text in expected if text not in texts]
    shapes = {without_id(line.text) for line in recorded}
    named = (joined(line, then) for line in recorded)
    known = {mount.identity for mount in named if mount is not None}
    foreign = []
    for line in current:
        if without_id(line.text) in shapes:
            continue
        mount = joined(line, now)
        if (
            mount is not None
            and mount.point == line.fields["TARGET"]
            and _written_for(line, mount)
            and mount.identity not in known
        ):
            continue
        foreign.append(line.text)
    return foreign, lost
