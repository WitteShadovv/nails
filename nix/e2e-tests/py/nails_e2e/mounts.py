"""The decoy's mount table across a session, for the NixOS test driver.

A soft-reboot into a new root carries the API filesystems (PID 1 moves
``/dev``, ``/proc`` and ``/sys`` into it) and ``/run`` without what is mounted
below it; the way back mounts the decoy root again and makes the decoy's other
mounts again. After a session every mount has a new ID and, once the decoy's
PID 1 has marked the tree shared again, a new peer group, so a mount table is
compared without them: :func:`shape` gives each mount by its place (the mount
points from the root of the table down to it) with its filesystem (the device
number, which a new filesystem would not have), the directory of it that it
shows, its source and type, its per-mount and superblock options and its
propagation type. :func:`differences` compares two shapes mount by mount, so
two alike mounts count twice, and the order of the mounts the way back makes.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

from .utab import unescape

#: A mount's place: the mount points of the mounts from the root of the table
#: down to it, its own last. A mount stacked on another repeats that one's
#: mount point, and a mount hidden under another at its mount point keeps a
#: place of its own.
Place = tuple[str, ...]

#: The mounts at and below these mount points are not made by the way back:
#: PID 1 moves the API filesystems into the next root, and carries ``/run``.
NOT_MADE_AGAIN = ("/dev", "/proc", "/sys", "/run")


@dataclass(frozen=True)
class Mount:
    """One line of ``/proc/self/mountinfo``, with its propagation type."""

    id: int
    parent: int
    dev: str
    root: str
    point: str
    options: str
    propagation: str
    fstype: str
    source: str
    super_options: str


@dataclass(frozen=True)
class Shape:
    """What a mount is, without its ID and peer group."""

    place: Place
    dev: str
    root: str
    source: str
    fstype: str
    options: str
    super_options: str
    propagation: str

    @property
    def made_again(self) -> bool:
        """Whether the way back makes this mount."""
        point = self.place[-1]
        return not any(
            point == top or point.startswith(top + "/") for top in NOT_MADE_AGAIN
        )


def propagation(optional: list[str]) -> str:
    """The propagation type that a mount's optional fields give it."""
    kinds = []
    if any(field.startswith("shared:") for field in optional):
        kinds.append("shared")
    if any(field.startswith("master:") for field in optional):
        kinds.append("slave")
    if "unbindable" in optional:
        kinds.append("unbindable")
    return ",".join(kinds) or "private"


def parse(text: str) -> list[Mount]:
    """The mounts of a ``/proc/self/mountinfo`` text, in its order."""
    mounts = []
    for row in text.splitlines():
        fields = row.split(" ")
        if "-" not in fields:
            continue
        sep = fields.index("-")
        if sep < 6 or len(fields) < sep + 3:
            continue
        mounts.append(
            Mount(
                id=int(fields[0]),
                parent=int(fields[1]),
                dev=fields[2],
                root=unescape(fields[3]),
                point=unescape(fields[4]),
                options=fields[5],
                propagation=propagation(fields[6:sep]),
                fstype=fields[sep + 1],
                source=unescape(fields[sep + 2]),
                super_options=fields[sep + 3] if len(fields) > sep + 3 else "",
            )
        )
    return mounts


def shape(text: str, leave_out: Callable[[str], bool]) -> list[Shape]:
    """The mounts of a ``mountinfo`` text in its order, each by its place,
    but those whose mount point ``leave_out`` names."""
    mounts = parse(text)
    by_id = {mount.id: mount for mount in mounts}
    places: dict[int, Place] = {}

    def place(mount: Mount) -> Place:
        # Iteratively up to the root of the table, never round a cycle.
        chain = [mount]
        while chain[-1].id not in places:
            parent = by_id.get(chain[-1].parent)
            if parent is None or parent in chain:
                places[chain[-1].id] = (chain[-1].point,)
                break
            chain.append(parent)
        for below in reversed(chain[:-1]):
            places[below.id] = places[by_id[below.parent].id] + (below.point,)
        return places[mount.id]

    return [
        Shape(
            place=place(mount),
            dev=mount.dev,
            root=mount.root,
            source=mount.source,
            fstype=mount.fstype,
            options=mount.options,
            super_options=mount.super_options,
            propagation=mount.propagation,
        )
        for mount in mounts
        if not leave_out(mount.point)
    ]


def differences(before: list[Shape], after: list[Shape]) -> list[str]:
    """What ``after`` has otherwise than ``before``: each mount missing or
    extra (two alike mounts are two), a different number of mounts and,
    where both have the same mounts, the mounts the way back makes in
    another order."""
    missing = Counter(before) - Counter(after)
    extra = Counter(after) - Counter(before)
    found = [f"missing: {mount}" for mount in missing.elements()]
    found += [f"extra: {mount}" for mount in extra.elements()]
    if len(before) != len(after):
        found.append(f"{len(before)} mounts before, {len(after)} after")
    if not found:
        then = [mount.place for mount in before if mount.made_again]
        now = [mount.place for mount in after if mount.made_again]
        if then != now:
            found.append(f"made in another order: {then} -> {now}")
    return found
