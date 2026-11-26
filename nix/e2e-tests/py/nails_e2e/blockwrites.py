"""Count the guest's writes to the decoy disk from the host, through QEMU.

The block-write oracle: from the trigger of a switch into the hidden root until
the session ends, QEMU dirty bitmaps (granularity 512 bytes) on every decoy
drive record each write and write-zeroes the guest makes, and each discard a
drive with ``discard=unmap`` passes on. They live in QEMU, on the host, where
nothing in the guest can reach them. The oracle reports what it found, with the
sector ranges and, on ext4, what each range holds, and judges it with two
verdicts (:data:`SWITCH_VERDICT`, :data:`SESSION_VERDICT`). Both report for
now and fail no test; what they cannot tell is listed in
``nix/e2e-tests/README.md``.

A window opens just before the trigger of a switch (:func:`before_switch`,
after a guest ``sync``): it covers the activation, the decoy's own shutdown and
the switch. A switch that does not land in the hidden root discards it. It ends
on the way back to the decoy at the hold line of the decoy's early mark unit
(``blkstat-mark``, see ``lib/vm-config.nix``), which waits while the host cuts
the bitmaps, so nothing the decoy's own start writes after the cut counts; at a
power-off, which QEMU turns into a pause while a window is open
(``set-action``) so the host can read the bitmaps before it lets QEMU exit; or
live, at a crash and at the end of the test script. The same hold line at the
hidden root's own start splits the window into the phases ``switch`` and
``session``.

The mark unit holds a start only while the host armed it (:data:`ARM`, a
file in ``/run``, which a soft-reboot carries and a cold boot does not have):
from just before the trigger of a watched switch until the window ends.

Decoy drives are every writable drive but those that hold the hidden volume
and nothing else, told by their serial from the session plan's hidden root
once a session has started (:func:`hidden_volume`); before that, every
writable drive but the suite's extra disks (``empty<N>.qcow2``). A drive that
holds the hidden volume beside other data stays a decoy drive, with an oracle
error, and so does every extra disk when the hidden volume's drives cannot be
told. Writes to the hidden volume's own drives are reported and never judged.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Any

#: The bitmaps' granularity: one guest sector.
GRANULARITY = 512

#: The file in ``/run`` that arms the mark unit: it holds a start only where
#: this file is there. A soft-reboot keeps ``/run``, the session's switch
#: binds it into the hidden root, and the way back's scrub of ``/run`` keeps
#: what the decoy had there before the entry; a cold boot starts without it.
ARM = "/run/blkstat-arm"
#: What the mark unit prints on the serial console at each userspace start
#: the host armed it for, then waits.
HOLD = "blkstat-mark hold"
#: What it prints when it stops waiting (its start: a kernel line can cut
#: the rest off).
RELEASE = "blkstat-mark rel"
#: What the host types on the serial console to end the wait, once it cut.
GO = "blkstat-go\n"
#: What the host types first at a plain soft-reboot's hold line: the unit
#: flushes the page cache, so what the decoy's stop jobs wrote counts in the
#: control, and says :data:`SYNCED`.
SYNC = "blkstat-sync\n"
#: What the mark unit says once it flushed.
SYNCED = "blkstat-mark synced"
#: How long the host waits for :data:`SYNCED`.
SYNC_WAIT = 60.0

#: The phase a window starts with: the activation, the decoy's shutdown, the
#: switch.
SWITCH = "switch"
#: The phase from the hidden root's start on.
SESSION = "session"

#: A verdict that prints every finding and fails no test.
REPORT = "report"
#: A verdict that fails the test.
STRICT = "strict"

#: The switch phase's verdict: what the decoy disk took between the trigger
#: and the hidden root's start must be, file by file and metadata class by
#: class, a part of what a plain soft-reboot of the decoy (the control) takes
#: in the same test: the decoy's own stop jobs.
SWITCH_VERDICT = REPORT
#: The session phase's verdict: no write at all outside the allowed extents.
#: Strict once the decoy disk is read-only for the session (item 2's fence).
SESSION_VERDICT = REPORT

#: The tool names :func:`install` takes; ``mark_setup``, a shell command that
#: installs the mark unit where the VM's image has none, is optional.
TOOLS = ("qemu_img", "debugfs", "sfdisk")

#: The most blocks of one range the report names a writer for.
ATTRIBUTE_LIMIT = 64


@dataclass(frozen=True)
class Drive:
    """A drive as ``query-block`` lists it."""

    device: str
    node: str
    file: str
    #: The serial of the device the drive backs, "" where it has none.
    serial: str = ""


def drives(
    blocks: list[dict[str, Any]],
    serials: dict[str, str] | None = None,
    hidden: set[str] | None = None,
) -> tuple[list[Drive], list[Drive]]:
    """The writable drives of a ``query-block`` reply, each with its serial
    from ``serials`` (by device): the decoy drives, then the others. With
    ``hidden``, the serials of the drives the hidden volume lies on, the
    others are those drives; without it, the extra disks
    (``empty<N>.qcow2``)."""
    decoy: list[Drive] = []
    other: list[Drive] = []
    for block in blocks:
        inserted = block.get("inserted")
        if not inserted or inserted.get("ro"):
            continue
        device = str(block.get("device") or block.get("qdev") or "")
        drive = Drive(
            device=device,
            node=str(inserted.get("node-name", "")),
            file=str(inserted.get("file", "")),
            serial=(serials or {}).get(device, ""),
        )
        name = os.path.basename(_backing_file(inserted))
        if hidden is not None:
            is_other = bool(drive.serial) and drive.serial in hidden
        else:
            is_other = re.fullmatch(r"empty\d+\.qcow2", name) is not None
        if is_other:
            other.append(drive)
        else:
            decoy.append(drive)
    return decoy, other


def _backing_file(inserted: dict[str, Any]) -> str:
    """The image a drive was started with: below ``-snapshot``'s temporary
    overlay, its backing file."""
    image = inserted.get("image") or {}
    while image.get("backing-image"):
        image = image["backing-image"]
    return str(image.get("filename") or inserted.get("file", ""))


def bitmap_count(blocks: list[dict[str, Any]], drive: Drive, name: str) -> int | None:
    """The dirty byte count of bitmap ``name`` on ``drive``, from a
    ``query-block`` reply; ``None`` when it is not listed."""
    for block in blocks:
        inserted = block.get("inserted") or {}
        if inserted.get("node-name") != drive.node and block.get("device") != (
            drive.device
        ):
            continue
        listed = list(inserted.get("dirty-bitmaps") or []) + list(
            block.get("dirty-bitmaps") or []
        )
        for bitmap in listed:
            if bitmap.get("name") == name:
                return int(bitmap.get("count", 0))
    return None


Range = tuple[int, int]


def dirty_ranges(entries: list[dict[str, Any]], count: int) -> list[Range]:
    """The dirty byte ranges ``(offset, length)`` in a ``qemu-img map`` over an
    NBD export with ``x-dirty-bitmap``, given the bitmap's dirty ``count``.

    The NBD client reports the bitmap through the allocation flags, where a
    dirty area reads as a hole (``"data": false``). Which reading holds is
    settled against the count QEMU reports for the bitmap: the one whose total
    matches it. Raises when neither does.
    """
    holes = merge(
        [(e["start"], e["length"]) for e in entries if not e.get("data", False)]
    )
    data = merge([(e["start"], e["length"]) for e in entries if e.get("data", False)])
    for candidate in (holes, data):
        if total(candidate) == count:
            return candidate
    raise ValueError(
        f"the map shows {total(holes)} or {total(data)} dirty bytes, the bitmap {count}"
    )


def merge(ranges: list[Range]) -> list[Range]:
    """``ranges`` sorted, with touching and overlapping ones joined."""
    out: list[Range] = []
    for start, length in sorted(r for r in ranges if r[1] > 0):
        if out and start <= out[-1][0] + out[-1][1]:
            end = max(out[-1][0] + out[-1][1], start + length)
            out[-1] = (out[-1][0], end - out[-1][0])
        else:
            out.append((start, length))
    return out


def total(ranges: list[Range]) -> int:
    """The bytes ``ranges`` cover."""
    return sum(length for _, length in ranges)


def outside(ranges: list[Range], allowed: list[Range]) -> list[Range]:
    """The parts of ``ranges`` outside every range of ``allowed``."""
    out: list[Range] = []
    allowed = merge(allowed)
    for start, length in merge(ranges):
        cursor, end = start, start + length
        for a_start, a_length in allowed:
            a_end = a_start + a_length
            if a_end <= cursor or a_start >= end:
                continue
            if a_start > cursor:
                out.append((cursor, a_start - cursor))
            cursor = max(cursor, a_end)
        if cursor < end:
            out.append((cursor, end - cursor))
    return out


def sector_text(ranges: list[Range], limit: int = 40) -> str:
    """``ranges`` as inclusive 512-byte sector ranges, at most ``limit``."""
    parts = []
    for start, length in ranges[:limit]:
        first = start // 512
        last = (start + length - 1) // 512
        parts.append(f"{first}" if first == last else f"{first}-{last}")
    more = len(ranges) - limit
    return ", ".join(parts) + (f" and {more} more" if more > 0 else "")


#: The shell that tells when the mark unit last started and ended, and when
#: journald started, in microseconds of uptime (0 where it did not).
BOOT_TIMES = (
    "systemctl show -p InactiveExitTimestampMonotonic "
    "-p InactiveEnterTimestampMonotonic blkstat-mark.service; "
    "systemctl show -p ExecMainStartTimestampMonotonic systemd-journald.service"
)


def boot_times(text: str) -> str:
    """The report line of :data:`BOOT_TIMES`' output."""
    values: dict[str, float] = {}
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if value.strip().isdigit():
            values[key.strip()] = int(value) / 1e6
    start = values.get("InactiveExitTimestampMonotonic", 0.0)
    end = values.get("InactiveEnterTimestampMonotonic", 0.0)
    journald = values.get("ExecMainStartTimestampMonotonic", 0.0)
    mark = (
        f"the mark unit ran {end - start:.2f} s from {start:.2f} s"
        if start and end >= start
        else "the mark unit did not run"
    )
    return f"{mark}; journald started at {journald:.2f} s"


def hold_and_release(lines: list[str]) -> tuple[int | None, int | None]:
    """The index of the first hold line in ``lines`` and of the first release
    line after it."""
    hold = next((i for i, line in enumerate(lines) if HOLD in line), None)
    if hold is None:
        return None, None
    release = next(
        (i for i, line in enumerate(lines) if i > hold and RELEASE in line), None
    )
    return hold, release


# --- What a range holds, on ext4 --------------------------------------------


@dataclass
class Ext4Layout:
    """What ``debugfs stats`` says of an ext4 filesystem's layout."""

    block_size: int
    inodes_per_group: int
    inode_size: int
    #: (first block, last block, what it is) of every metadata area.
    areas: list[tuple[int, int, str]] = field(default_factory=list)
    #: (first block of the inode table, its group).
    tables: list[tuple[int, int, int]] = field(default_factory=list)


def _backup_groups(groups: int) -> list[int]:
    """The groups that hold a superblock copy under ``sparse_super``: 0, 1
    and the powers of 3, 5 and 7."""
    found = {0, 1}
    for base in (3, 5, 7):
        power = base
        while power < groups:
            found.add(power)
            power *= base
    return sorted(g for g in found if g < groups)


def parse_stats(text: str) -> Ext4Layout | None:
    """The layout in ``debugfs -R stats`` output, ``None`` when it shows
    none. The superblock copies and group descriptors are placed as
    ``sparse_super`` places them."""

    def header(name: str) -> int | None:
        m = re.search(rf"^{re.escape(name)}:\s+(\d+)", text, re.MULTILINE)
        return int(m.group(1)) if m else None

    block_size = header("Block size")
    per_group = header("Inodes per group")
    inode_size = header("Inode size")
    if not block_size or not per_group or not inode_size:
        return None
    layout = Ext4Layout(block_size, per_group, inode_size)
    first = header("First block") or 0
    blocks_per_group = header("Blocks per group") or 0
    table_blocks = header("Inode blocks per group") or 1
    reserved = header("Reserved GDT blocks") or 0
    desc_size = header("Group descriptor size") or 32
    groups = 0
    for m in re.finditer(
        r"Group\s+(\d+): block bitmap at (\d+), inode bitmap at (\d+), "
        r"inode table at (\d+)",
        text,
    ):
        group = int(m.group(1))
        groups = max(groups, group + 1)
        for at, what in ((int(m.group(2)), "block"), (int(m.group(3)), "inode")):
            layout.areas.append((at, at, f"{what} bitmap of group {group}"))
        table = int(m.group(4))
        layout.tables.append((table, table + table_blocks - 1, group))
    if blocks_per_group:
        gdt = -(-groups * desc_size // block_size)
        for group in _backup_groups(groups):
            start = group * blocks_per_group + first
            layout.areas.append((start, start, f"superblock of group {group}"))
            if gdt + reserved:
                last = start + gdt + reserved
                what = f"group descriptors of group {group}"
                layout.areas.append((start + 1, last, what))
    return layout


@dataclass
class BlockKind:
    """What one filesystem block is: a named metadata area, an inode-table
    block (with the inodes it holds), or neither (a data or journal block,
    for ``icheck``)."""

    area: str | None = None
    inodes: tuple[int, int] | None = None


def classify(layout: Ext4Layout, block: int) -> BlockKind:
    """What ``block`` holds by ``layout``."""
    if block == 0:
        return BlockKind(area="superblock of group 0")
    for first, last, what in layout.areas:
        if first <= block <= last:
            return BlockKind(area=what)
    for first, last, group in layout.tables:
        if first <= block <= last:
            per_block = layout.block_size // layout.inode_size
            first_inode = group * layout.inodes_per_group + (block - first) * (
                per_block
            )
            return BlockKind(inodes=(first_inode + 1, first_inode + per_block))
    return BlockKind()


def parse_icheck(text: str) -> dict[int, int | None]:
    """Block to inode from ``debugfs icheck`` output (``None``: no inode)."""
    found: dict[int, int | None] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].isdigit():
            found[int(parts[0])] = int(parts[1]) if parts[1].isdigit() else None
    return found


def parse_ncheck(text: str) -> dict[int, str]:
    """Inode to path from ``debugfs ncheck`` output."""
    found: dict[int, str] = {}
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            found.setdefault(int(parts[0]), re.sub(r"^/+", "/", parts[1].strip()))
    return found


#: Inodes ext4 reserves, by number.
RESERVED_INODES = {
    1: "bad blocks inode",
    2: "/",
    5: "boot loader inode",
    7: "reserved GDT inode",
    8: "the journal",
    11: "lost+found",
}


_DATA = re.compile(r"data of inode \d+ \(([^)]*)\)")
_AREA = re.compile(
    r"(superblock|group descriptors|reserved GDT blocks|block bitmap|inode bitmap)"
    r" of group \d+"
)
_EXT4 = re.compile(
    r"^sectors [^:]+: (?P<part>[^,]+), ext4 blocks [0-9-]+(?: \(first blocks\))?: "
    r"(?P<desc>.*)$"
)
_NOT_EXT4 = re.compile(r"^sectors [^:]+: (?P<part>[^,]+), not ext4")


def items_of(writers: list[str]) -> set[str]:
    """What the writer lines of :func:`describe` name, comparable from one
    window to another: each written file by its path and each ext4 metadata
    area by its class (``superblock``, ``journal``, ``inode table``, ``free
    blocks``...), each with its partition; a range not told is
    ``unattributed``."""
    items: set[str] = set()
    for line in writers:
        line = line.strip()
        if "outside every partition" in line:
            items.add("outside every partition")
            continue
        m = _NOT_EXT4.match(line)
        if m:
            items.add(f"{m['part']}: not ext4")
            continue
        m = _EXT4.match(line)
        if not m:
            items.add("unattributed")
            continue
        part, desc = m["part"], m["desc"]
        for path in _DATA.findall(desc):
            name = {"the journal": "journal", "no name": "an unlinked inode"}.get(
                path, path
            )
            items.add(f"{part}: {re.sub(r'^/+', '/', name)}")
        for area in _AREA.findall(desc):
            items.add(f"{part}: {area}")
        if "inode table slots" in desc:
            items.add(f"{part}: inode table")
        if "free blocks" in desc:
            items.add(f"{part}: free blocks")
        if desc == "nothing told":
            items.add("unattributed")
    return items


# --- The windows --------------------------------------------------------------


@dataclass
class Phase:
    """One phase of a window: its bitmap name on every tracked drive."""

    name: str
    bitmap: str


@dataclass
class Finding:
    """What one drive took in one phase."""

    label: str
    phase: str
    drive: str
    decoy: bool
    ranges: list[Range]
    writers: list[str] = field(default_factory=list)

    def text(self) -> str:
        role = "decoy drive" if self.decoy else "extra disk"
        lines = [
            f"{self.label}: {self.phase}: {role} {self.drive}: {total(self.ranges)} "
            f"bytes in {len(self.ranges)} ranges, sectors {sector_text(self.ranges)}"
        ]
        lines += [f"    {w}" for w in self.writers]
        return "\n".join(lines)


@dataclass
class Window:
    """An open window: its label, its phases, the QEMU it runs in."""

    label: str
    process: int
    phases: list[Phase]
    decoy: list[Drive]
    other: list[Drive]
    #: A plain soft-reboot of the decoy: what it takes is the switch phase's
    #: measure.
    control: bool = False


class Oracle:
    """The block-write oracle of one machine."""

    def __init__(self, machine: Any, tools: dict[str, str]) -> None:
        self.machine = machine
        self.tools = tools
        self.window: Window | None = None
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.allowed: dict[str, list[Range]] = {}
        #: What the plain soft-reboots of the test (the controls) took, by
        #: drive (:func:`items_of`).
        self.controls: dict[str, set[str]] = {}
        #: Whether a control's window had no cut, so it takes in the decoy's
        #: own start too.
        self.uncut_control = False
        #: The serials of the drives the hidden volume lies on, once a session
        #: told them (:func:`hidden_volume`).
        self.hidden: set[str] | None = None
        #: Why the test's end runs no control (:func:`skip_control`).
        self.no_control: str | None = None
        #: Whether the report names how long the mark unit held the boot the
        #: first window opened in (:meth:`_note_boot`).
        self.boot_noted = False
        #: The decoy's filesystem types by device number, read as each window
        #: opens: a mount the hidden root does not show (the distribution
        #: tests' tmpfs at /run/blk) still holds a loop device's file.
        self.mount_types: dict[str, str] = {}
        self.serial = 0
        #: Held by every step that reads or changes the window, from the test
        #: script's thread and from the watch thread (:func:`install`).
        self.lock = threading.RLock()

    # The QMP side.

    def _qmp(self, command: str, args: dict[str, Any] | None = None) -> Any:
        client = self.machine.qmp_client
        if client is None:
            raise RuntimeError("the machine has no QMP client")
        _serialize(client)
        reply = client.send(command, args or {})
        return reply.get("return")

    def _process(self) -> int:
        process = getattr(self.machine, "process", None)
        return id(process) if process is not None else 0

    def _bitmap(self) -> str:
        self.serial += 1
        return f"bw{self.serial}"

    def _add(self, drives_: list[Drive], name: str) -> list[dict[str, Any]]:
        return [
            {
                "type": "block-dirty-bitmap-add",
                "data": {"node": d.node, "name": name, "granularity": GRANULARITY},
            }
            for d in drives_
        ]

    def _disable(self, drives_: list[Drive], name: str) -> list[dict[str, Any]]:
        return [
            {
                "type": "block-dirty-bitmap-disable",
                "data": {"node": d.node, "name": name},
            }
            for d in drives_
        ]

    def open(self, label: str, control: bool = False) -> None:
        """Open a window labelled ``label``, for a ``control`` (a plain
        soft-reboot of the decoy) or a session; nothing when one is open."""
        if self.window is not None:
            return
        self.machine.succeed("sync")
        if not self.boot_noted:
            self.boot_noted = True
            self._note_boot()
        try:
            self.mount_types.update(mount_types(self.machine))
        except Exception:  # noqa: BLE001 - the hidden session's table stays
            pass
        blocks = self._qmp("query-block")
        decoy, other = drives(blocks, self._serials(blocks), self.hidden)
        if not decoy:
            self.errors.append(f"{label}: no decoy drive to watch")
            return
        name = self._bitmap()
        self._qmp("transaction", {"actions": self._add(decoy + other, name)})
        self._qmp("set-action", {"shutdown": "pause"})
        self.window = Window(
            label, self._process(), [Phase(SWITCH, name)], decoy, other, control
        )
        self.machine.log(
            f"block-write oracle: {label}: watching "
            + ", ".join(d.device or d.node for d in decoy)
        )

    def _note_boot(self) -> None:
        """Report when the mark unit last ran and when journald started, in
        seconds of uptime: at the first window of a test, the boot the test
        started with, which the unit must not hold (:data:`ARM`)."""
        try:
            text = self.machine.succeed(BOOT_TIMES)
        except Exception as e:  # noqa: BLE001 - a report line, nothing more
            self.machine.log(f"block-write oracle: boot times unread: {e}")
            return
        self.machine.log(f"block-write oracle: boot: {boot_times(text)}")

    def _serials(self, blocks: list[dict[str, Any]]) -> dict[str, str]:
        """The serial of each drive's device, by drive ("" where it has none
        or QEMU cannot say)."""
        found: dict[str, str] = {}
        for block in blocks:
            qdev = block.get("qdev")
            if not qdev or not block.get("inserted"):
                continue
            try:
                serial = self._qmp("qom-get", {"path": qdev, "property": "serial"})
            except Exception:  # noqa: BLE001 - a device without a serial
                serial = ""
            found[str(block.get("device") or qdev)] = str(serial or "")
        return found

    def learn_hidden(self, serials: set[str]) -> None:
        """Take ``serials`` as the hidden volume's drives, and sort the open
        window's drives by them."""
        self.hidden = serials
        window = self.window
        if window is None:
            return
        tracked = window.decoy + window.other
        window.decoy = [d for d in tracked if not (d.serial and d.serial in serials)]
        window.other = [d for d in tracked if d.serial and d.serial in serials]

    def cut(self, phase: str) -> None:
        """End the window's current phase and start ``phase``, atomically."""
        window = self.window
        if window is None:
            return
        tracked = window.decoy + window.other
        name = self._bitmap()
        actions = self._disable(tracked, window.phases[-1].bitmap) + self._add(
            tracked, name
        )
        self._qmp("transaction", {"actions": actions})
        window.phases.append(Phase(phase, name))

    def close(self, why: str, keep_last: bool = True) -> list[Finding]:
        """Close the window and record what it found. ``keep_last`` false
        drops its last phase unread: the decoy's own start after a cut."""
        window = self.window
        if window is None:
            return []
        self.window = None
        found: list[Finding] = []
        try:
            if window.process != self._process():
                raise RuntimeError("QEMU was restarted while the window was open")
            tracked = window.decoy + window.other
            self._qmp(
                "transaction",
                {"actions": self._disable(tracked, window.phases[-1].bitmap)},
            )
            phases = window.phases if keep_last else window.phases[:-1]
            blocks = self._qmp("query-block")
            for phase in phases:
                for drive in tracked:
                    found.extend(self._read(window, phase, drive, blocks))
            for phase in window.phases:
                for drive in tracked:
                    self._try(
                        "block-dirty-bitmap-remove",
                        {"node": drive.node, "name": phase.bitmap},
                    )
            self._try("set-action", {"shutdown": "poweroff"})
        except Exception as e:  # noqa: BLE001 - every failure is an oracle error
            self.errors.append(f"{window.label}: the window could not be read: {e}")
        if window.control:
            for finding in found:
                if finding.decoy:
                    taken = self.controls.setdefault(finding.drive, set())
                    taken.update(items_of(finding.writers))
        else:
            self.findings.extend(found)
        clean = not [f for f in found if f.decoy]
        what = "control" if window.control else "session"
        self.machine.log(
            f"block-write oracle: {window.label}: {what} closed at {why}: "
            + ("no write to a decoy drive" if clean else "writes to a decoy drive")
        )
        for finding in found:
            self.machine.log("block-write oracle: " + finding.text())
        return found

    def discard(self) -> None:
        """Drop the open window unread."""
        window = self.window
        if window is None:
            return
        self.window = None
        for phase in window.phases:
            for drive in window.decoy + window.other:
                self._try(
                    "block-dirty-bitmap-remove",
                    {"node": drive.node, "name": phase.bitmap},
                )
        self._try("set-action", {"shutdown": "poweroff"})
        self.machine.log(f"block-write oracle: {window.label}: no session; dropped")

    def _try(self, command: str, args: dict[str, Any]) -> None:
        try:
            self._qmp(command, args)
        except Exception:  # noqa: BLE001 - cleanup only
            pass

    def _read(
        self, window: Window, phase: Phase, drive: Drive, blocks: list[dict[str, Any]]
    ) -> list[Finding]:
        count = bitmap_count(blocks, drive, phase.bitmap)
        if count is None:
            raise RuntimeError(f"bitmap {phase.bitmap} of {drive.device} is gone")
        if count == 0:
            return []
        decoy = drive in window.decoy
        with tempfile.TemporaryDirectory(prefix="bw") as tmp:
            sock = os.path.join(tmp, "s")
            self._qmp(
                "nbd-server-start",
                {"addr": {"type": "unix", "data": {"path": sock}}},
            )
            try:
                self._qmp(
                    "block-export-add",
                    {
                        "type": "nbd",
                        "id": "bwexport",
                        "node-name": drive.node,
                        "name": "bw",
                        "writable": False,
                        "bitmaps": [phase.bitmap],
                    },
                )
                opts = f"driver=nbd,server.type=unix,server.path={sock},export=bw"
                entries = json.loads(
                    _run(
                        [
                            self.tools["qemu_img"],
                            "map",
                            "--output=json",
                            "--image-opts",
                            f"{opts},x-dirty-bitmap=qemu:dirty-bitmap:{phase.bitmap}",
                        ]
                    )
                )
                ranges = dirty_ranges(entries, count)
                if decoy:
                    ranges = outside(ranges, self.allowed.get(drive.device, []))
                writers: list[str] = []
                if ranges and decoy:
                    writers = self._writers(opts, tmp, ranges)
            finally:
                self._try("block-export-del", {"id": "bwexport", "mode": "hard"})
                time.sleep(0.2)  # sync-lint: allow sleep -- the export ends async
                self._try("nbd-server-stop", {})
        if not ranges:
            return []
        return [
            Finding(
                window.label,
                phase.name,
                drive.device or drive.node,
                decoy,
                ranges,
                writers,
            )
        ]

    def _writers(self, opts: str, tmp: str, ranges: list[Range]) -> list[str]:
        """What each range holds, from a raw copy of the drive. Best effort:
        a step that fails says so in the list."""
        raw = os.path.join(tmp, "disk.raw")
        try:
            _run(
                [
                    self.tools["qemu_img"],
                    "convert",
                    "-O",
                    "raw",
                    "--image-opts",
                    opts,
                    raw,
                ]
            )
            return describe(raw, ranges, self.tools)
        except Exception as e:  # noqa: BLE001 - attribution is best effort
            return [f"could not tell the writers: {e}"]
        finally:
            if os.path.exists(raw):
                os.unlink(raw)

    def verdict(self) -> tuple[list[str], list[str]]:
        """The switch phase's and the session phase's verdicts, one line per
        finding that breaks them (see :data:`SWITCH_VERDICT` and
        :data:`SESSION_VERDICT`)."""
        switch: list[str] = []
        session: list[str] = []
        for finding in self.findings:
            if not finding.decoy:
                continue
            if finding.phase != SWITCH:
                session.append(finding.text())
                continue
            control = self.controls.get(finding.drive)
            if control is None:
                why = f" ({self.no_control})" if self.no_control else ""
                switch.append(
                    f"{finding.label}: {finding.drive}: no plain soft-reboot to judge "
                    f"the switch phase by{why}"
                )
                continue
            extra = sorted(items_of(finding.writers) - control)
            if extra:
                switch.append(
                    f"{finding.label}: {finding.drive}: the switch wrote what a plain "
                    f"soft-reboot does not: {'; '.join(extra)}"
                )
        return switch, session

    def raise_on_findings(self) -> None:
        """Print the verdicts, and raise for the strict ones that do not hold
        and for an oracle error where a verdict is strict."""
        switch, session = self.verdict()
        lines: list[str] = []
        if switch:
            lines.append(f"switch phase ({SWITCH_VERDICT}): not a part of the control:")
            lines += switch
        if session:
            lines.append(
                f"session phase ({SESSION_VERDICT}): writes to the decoy disk:"
            )
            lines += session
        if self.uncut_control:
            lines.append(
                "note: a control had no cut and takes in the decoy's own start"
            )
        lines += [f"oracle error: {e}" for e in self.errors]
        for line in lines or ["no finding"]:
            self.machine.log(f"block-write oracle verdict: {line}")
        failing = (switch and SWITCH_VERDICT == STRICT) or (
            session and SESSION_VERDICT == STRICT
        )
        strict = STRICT in (SWITCH_VERDICT, SESSION_VERDICT)
        if failing or (self.errors and strict):
            raise AssertionError(
                "the block-write oracle's verdict fails:\n" + "\n".join(lines)
            )


def _run(argv: list[str]) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True).stdout


def partitions(raw: str, tools: dict[str, str]) -> list[tuple[int, int, str]]:
    """``(byte offset, byte length, name)`` of each partition of the raw disk
    image, or the whole image when it has no partition table."""
    size = os.path.getsize(raw)
    try:
        table = json.loads(_run([tools["sfdisk"], "--json", raw]))["partitiontable"]
    except Exception:  # noqa: BLE001 - no partition table
        return [(0, size, "the whole disk")]
    sector = int(table.get("sectorsize", 512))
    out = []
    for part in table.get("partitions", []):
        out.append(
            (
                int(part["start"]) * sector,
                int(part["size"]) * sector,
                os.path.basename(str(part.get("node", "partition"))),
            )
        )
    return out or [(0, size, "the whole disk")]


def describe(raw: str, ranges: list[Range], tools: dict[str, str]) -> list[str]:
    """One line per range: the partition it falls in and, on ext4, what each
    written block holds."""
    lines: list[str] = []
    layouts: dict[str, tuple[Ext4Layout | None, str]] = {}
    parts = partitions(raw, tools)
    for start, length in ranges:
        sectors = sector_text([(start, length)])
        part = next((p for p in parts if p[0] <= start < p[0] + p[1]), None)
        if part is None:
            lines.append(f"sectors {sectors}: outside every partition")
            continue
        offset, _, name = part
        device = f"{raw}?offset={offset}" if offset else raw
        if device not in layouts:
            layouts[device] = _layout(device, tools)
        layout, why = layouts[device]
        if layout is None:
            lines.append(
                f"sectors {sectors}: {name}, not ext4 ({why}): writer not told"
            )
            continue
        first = (start - offset) // layout.block_size
        last = (start - offset + length - 1) // layout.block_size
        blocks = list(range(first, last + 1))[:ATTRIBUTE_LIMIT]
        held = _ext4_writers(device, layout, blocks, tools)
        cut = " (first blocks)" if last - first + 1 > ATTRIBUTE_LIMIT else ""
        lines.append(
            f"sectors {sectors}: {name}, ext4 blocks {first}-{last}{cut}: {held}"
        )
    return lines


def _layout(device: str, tools: dict[str, str]) -> tuple[Ext4Layout | None, str]:
    """The ext4 layout of ``device``, or ``None`` and why not."""
    try:
        layout = parse_stats(_run([tools["debugfs"], "-R", "stats", device]))
    except subprocess.CalledProcessError as e:
        said = (e.stderr or "").strip().splitlines()
        return None, said[-1] if said else str(e)
    except Exception as e:  # noqa: BLE001 - not ext4
        return None, str(e)
    return layout, "" if layout else "debugfs shows no ext4 layout"


def _ext4_writers(
    device: str, layout: Ext4Layout, blocks: list[int], tools: dict[str, str]
) -> str:
    named: list[str] = []
    inodes: set[int] = set()
    plain: list[int] = []
    for block in blocks:
        kind = classify(layout, block)
        if kind.area:
            named.append(kind.area)
        elif kind.inodes:
            inodes.update(range(kind.inodes[0], kind.inodes[1] + 1))
        else:
            plain.append(block)
    data: set[int] = set()
    if plain:
        owners = parse_icheck(
            _run(
                [tools["debugfs"], "-R", "icheck " + " ".join(map(str, plain)), device]
            )
        )
        unowned = [b for b, i in owners.items() if i is None]
        data.update(i for i in owners.values() if i is not None)
        if unowned:
            named.append(f"free blocks {unowned[:8]}")
    wanted = sorted((inodes | data) - set(RESERVED_INODES))
    paths = (
        parse_ncheck(
            _run(
                [
                    tools["debugfs"],
                    "-R",
                    "ncheck -c " + " ".join(map(str, wanted)),
                    device,
                ]
            )
        )
        if wanted
        else {}
    )
    for inode in sorted(data):
        name = RESERVED_INODES.get(inode) or paths.get(inode, "no name")
        named.append(f"data of inode {inode} ({name})")
    if inodes:
        held = [
            f"{i} {RESERVED_INODES.get(i) or paths[i]}"
            for i in sorted(inodes)
            if i in paths or i in RESERVED_INODES
        ]
        span = f"{min(inodes)}-{max(inodes)}"
        named.append(
            f"inode table slots {span}"
            + (f", in use: {'; '.join(held[:12])}" if held else ", none in use")
        )
    return "; ".join(dict.fromkeys(named)) or "nothing told"


# --- The machine hooks ----------------------------------------------------------

#: The attribute an installed oracle is kept in on its machine.
_ATTRIBUTE = "_nails_block_write_oracle"

#: Serializes every QMP command sent through a machine's client: the watch
#: thread's and those of the test script's thread, the oracle's own and any
#: other (a test's set-action, say).
_QMP_LOCK = threading.RLock()


def _serialize(client: Any) -> None:
    """Make ``client.send`` take :data:`_QMP_LOCK`, once per client."""
    if getattr(client, "_nails_serialized", False):
        return
    send = client.send

    def serialized(*args: Any, **kwargs: Any) -> Any:
        with _QMP_LOCK:
            return send(*args, **kwargs)

    client.send = serialized
    client._nails_serialized = True


def install(machine: Any, tools: dict[str, str], watch: bool = True) -> Oracle:
    """Watch ``machine`` with the oracle. Wraps its ``wait_for_shutdown`` and
    ``crash`` so a power-off or crash closes an open window first, and, with
    ``watch``, starts a thread that finishes a power-off QEMU paused for while
    a window is open, so a test that waits for the power-off in a loop of its
    own (on ``machine.process``) sees QEMU exit."""
    oracle = Oracle(machine, tools)
    setattr(machine, _ATTRIBUTE, oracle)
    original_wait = machine.wait_for_shutdown
    original_crash = machine.crash

    def wait_for_shutdown(*args: Any, **kwargs: Any) -> Any:
        if oracle.window is not None:
            timeout = kwargs.get("timeout", args[0] if args else None)
            seconds = getattr(timeout, "total_seconds", lambda: timeout)()
            # The caller's timeout bounds the whole wait: run out here, and
            # the driver's own wait would take as long again.
            if not wait_for_exit(machine, seconds):
                raise TimeoutError(f"the machine did not power off in {seconds} s")
        return original_wait(*args, **kwargs)

    def crash(*args: Any, **kwargs: Any) -> Any:
        with oracle.lock:
            if oracle.window is not None and _running(machine):
                oracle.close("a crash")
        return original_crash(*args, **kwargs)

    machine.wait_for_shutdown = wait_for_shutdown
    machine.crash = crash
    if watch:
        threading.Thread(
            target=_watch, args=(machine, oracle), name="block-writes", daemon=True
        ).start()
    return oracle


def _watch(machine: Any, oracle: Oracle) -> None:
    """The watch thread: every half second, finish a power-off QEMU paused for
    while a window is open."""
    while True:
        time.sleep(0.5)  # sync-lint: allow sleep -- the watch thread's pace
        try:
            if oracle.window is None or not _running(machine):
                continue
            with oracle.lock:
                if paused_at_shutdown(machine):
                    finish_power_off(machine)
        except Exception as e:  # noqa: BLE001 - the thread must go on
            oracle.errors.append(f"the watch thread failed: {e}")


def oracle_of(machine: Any) -> Oracle | None:
    """The oracle watching ``machine``, if any."""
    oracle = getattr(machine, _ATTRIBUTE, None)
    return oracle if isinstance(oracle, Oracle) else None


def watching(machine: Any) -> bool:
    """Whether an oracle watches ``machine`` with a window open."""
    oracle = oracle_of(machine)
    return oracle is not None and oracle.window is not None


def _running(machine: Any) -> bool:
    process = getattr(machine, "process", None)
    return process is not None and process.poll() is None


def paused_at_shutdown(machine: Any) -> bool:
    """Whether QEMU paused at a guest power-off, as it does while a window is
    open."""
    oracle = oracle_of(machine)
    if oracle is None or oracle.window is None or not _running(machine):
        return False
    try:
        status = oracle._qmp("query-status") or {}
    except Exception:  # noqa: BLE001 - a QEMU on its way out
        return False
    return status.get("status") == "shutdown"


def finish_power_off(machine: Any) -> None:
    """At a power-off QEMU paused for: read the window, then let QEMU exit."""
    oracle = oracle_of(machine)
    if oracle is None:
        return
    with oracle.lock:
        if oracle.window is None:
            return
        oracle.close("a power-off")
        # The monitor's quit, as the driver's own crash() sends it: a QMP
        # quit can end QEMU before its reply, which the driver's QMP reader
        # would wait for without end.
        try:
            machine.send_monitor_command("quit")
        except Exception:  # noqa: BLE001 - QEMU exits as it answers
            process = getattr(machine, "process", None)
            if process is not None and process.poll() is None:
                process.terminate()


def wait_for_exit(machine: Any, timeout: float | None) -> bool:
    """Wait for QEMU to exit, closing an open window at a power-off it paused
    for. Returns false when ``timeout`` ran out first."""
    process = getattr(machine, "process", None)
    if process is None:
        return True
    deadline = None if timeout is None else time.monotonic() + timeout
    while process.poll() is None:
        if paused_at_shutdown(machine):
            finish_power_off(machine)
        if deadline is not None and time.monotonic() > deadline:
            return False
        time.sleep(0.2)  # sync-lint: allow sleep -- polls QEMU under the deadline
    return True


def before_switch(machine: Any, label: str, control: bool = False) -> bool:
    """Before the trigger of a switch: open a window when none is open, and
    arm the mark unit (:data:`ARM`) while one is. Returns whether this switch
    opened it."""
    oracle = oracle_of(machine)
    if oracle is None:
        return False
    opened = False
    if oracle.window is None:
        try:
            with oracle.lock:
                oracle.open(label, control)
        except Exception as e:  # noqa: BLE001 - recorded, raised at the end
            oracle.errors.append(f"{label}: the window could not be opened: {e}")
            return False
        opened = oracle.window is not None
    if oracle.window is not None:
        try:
            # Created once, never rewritten: the way back's scrub of /run
            # keeps an entry the decoy had before the entry, by its inode.
            machine.succeed(f"[ -e {ARM} ] || : > {ARM}")
        except Exception as e:  # noqa: BLE001 - judged with the rest
            oracle.errors.append(f"{label}: the mark unit could not be armed: {e}")
    return opened


def at_hold(machine: Any, opened_here: bool, since: int | None = None) -> int:
    """At the mark unit's hold line: cut the window, then end the unit's wait
    by typing :data:`GO` on the serial console, unless it already stopped
    waiting. Returns the console index of the cut, to check the release line
    came after it. The driver's console reader can fall seconds behind the
    guest in the burst of lines a switch prints, so a wait of fixed length
    would end before the host saw the hold line."""
    oracle = oracle_of(machine)
    send = getattr(machine, "send_console", None)
    if oracle is not None:
        with oracle.lock:
            if oracle.window is not None:
                if oracle.window.control and send is not None:
                    _flush(machine, oracle, send)
                try:
                    oracle.cut(SESSION if opened_here else "after the way back")
                except Exception as e:  # noqa: BLE001 - judged with the rest
                    oracle.errors.append(f"the cut failed: {e}")
    cut_at = len(machine.full_console_log)
    # Only this switch's lines say whether the unit stopped waiting: an older
    # hold and release pair would keep the answer back.
    lines = machine.full_console_log[since if since is not None else -200 :]
    _, release = hold_and_release(lines)
    if send is not None and release is None:
        send(GO)
    return cut_at


def _flush(machine: Any, oracle: Oracle, send: Any) -> None:
    """Have the mark unit flush the guest's page cache before a control's
    cut, and wait, bounded, until it says it has."""
    since = len(machine.full_console_log)
    send(SYNC)
    deadline = time.monotonic() + SYNC_WAIT
    while not any(SYNCED in line for line in machine.full_console_log[since:]):
        if time.monotonic() > deadline:
            oracle.errors.append("a control's flush did not end in time")
            return
        time.sleep(
            0.1
        )  # sync-lint: allow sleep -- polls the console under the deadline


#: The session plan the hidden session runs by; it names the hidden root.
PLAN = "/run/overlay-runtime/plan.json"
#: The filesystems in RAM, on no drive.
_IN_RAM = ("tmpfs", "ramfs")
#: The block devices in RAM: a hidden volume there lies on no drive.
_RAM_DEVICE = re.compile(r"/dev/(zram|ram)\d+")


@dataclass
class HiddenVolume:
    """The drives a hidden volume lies on, by serial."""

    #: Those that hold the hidden volume and nothing else.
    alone: set[str] = field(default_factory=set)
    #: Those that hold other data beside it, each with what that is.
    shared: dict[str, str] = field(default_factory=dict)
    #: Filesystem types by device number that the hidden root may not show.
    known: dict[str, str] = field(default_factory=dict, repr=False)


def _row(line: str, width: int) -> list[str]:
    """The fields of a raw ``lsblk``/``findmnt`` line, ``width`` of them: an
    empty field is an empty string, a space in one is ``\\x20``."""
    return (line.split(" ") + [""] * width)[:width]


#: The shell that lists every mount's device number and filesystem type.
MOUNT_TYPES = "findmnt -nro MAJ:MIN,FSTYPE"


def mount_types(machine: Any) -> dict[str, str]:
    """The filesystem type of each mount, by device number."""
    return dict(_row(line, 2) for line in machine.succeed(MOUNT_TYPES).splitlines())


def hidden_volume(machine: Any, known: dict[str, str] | None = None) -> HiddenVolume:
    """The drives the session plan's hidden root lies on, read in the hidden
    session: below its filesystem, through device mapper and LVM, and through
    a loop device to the drive of its backing file. ``known`` names the
    filesystem types of mounts the hidden root may not show, by device
    number. Raises ``ValueError`` naming what it cannot tell."""
    plan = json.loads(machine.succeed(f"cat {PLAN}"))
    root = str(plan.get("hidden_root") or "")
    if not root:
        raise ValueError("the session plan names no hidden root")
    volume = HiddenVolume(known=dict(known or {}))
    _place(machine, root, volume, None, 0)
    for serial in volume.shared:
        volume.alone.discard(serial)
    return volume


def _place(
    machine: Any, path: str, volume: HiddenVolume, beside: str | None, depth: int
) -> None:
    """Add the drives ``path`` lies on to ``volume``; ``beside``, when known,
    is the other data they hold."""
    line = machine.succeed(
        f"findmnt -nro SOURCE,FSTYPE,TARGET --target {shlex.quote(path)} | head -n 1"
    ).strip()
    source, fstype, target = _row(line, 3)
    device, _, sub = source.partition("[")
    if fstype in _IN_RAM:
        return
    if not device.startswith("/dev/"):
        raise ValueError(f"{path} lies on {source or 'nothing'} ({fstype})")
    if beside is None and sub.strip("]/"):
        # A btrfs subvolume, or a directory bind-mounted alone.
        beside = f"{path} is only {sub.rstrip(']')} of its {fstype} filesystem"
    if beside is None and os.path.normpath(target) != os.path.normpath(path):
        beside = f"{path} is a folder of the filesystem at {target}"
    _below(machine, device, path, volume, beside, depth)


def _below(
    machine: Any,
    device: str,
    what: str,
    volume: HiddenVolume,
    beside: str | None,
    depth: int,
) -> None:
    """Add the drives below the block ``device`` (that ``what`` lies on) to
    ``volume``."""
    if depth > 3:
        raise ValueError(f"{what} lies below too many loop devices")
    chain: set[str] = set()
    disks: list[tuple[str, str]] = []
    for row in machine.succeed(
        f"lsblk -nrspo PATH,TYPE,SERIAL {shlex.quote(device)}"
    ).splitlines():
        name, kind, serial = _row(row, 3)
        chain.add(name)
        if kind == "loop":
            _backing(machine, name, what, volume, depth)
        elif kind == "disk" and not _RAM_DEVICE.fullmatch(name):
            if not serial:
                raise ValueError(f"{name}, below {what}, has no serial")
            disks.append((name, serial))
    for disk, serial in disks:
        shared = beside
        if shared is None:
            others = [
                f"{name} ({fs})"
                for name, fs in (
                    _row(row, 2)
                    for row in machine.succeed(
                        f"lsblk -nrpo PATH,FSTYPE {shlex.quote(disk)}"
                    ).splitlines()
                )
                if fs and name not in chain
            ]
            shared = ("it also holds " + ", ".join(others)) if others else None
        if shared is None:
            volume.alone.add(serial)
        else:
            volume.shared[serial] = shared


def _backing(
    machine: Any, loop: str, what: str, volume: HiddenVolume, depth: int
) -> None:
    """Add the drives that hold the backing file of ``loop`` to ``volume``.
    The file is found by its filesystem's device number: the path the loop
    device keeps is the one its file had where it was set up, which the
    hidden root may not show (the distribution tests' file on a tmpfs at
    ``/run/blk`` is ``/data.img`` there)."""
    row = machine.succeed(f"losetup -nO BACK-MAJ:MIN,BACK-FILE --raw {loop}")
    number, back = _row(row.strip(), 2)
    if ":" not in number:
        raise ValueError(f"{loop}, below {what}, has no backing file")
    beside = f"the file {back} holds it"
    if not number.startswith("0:"):
        name = machine.succeed(
            f'basename "$(readlink /sys/dev/block/{number})"'
        ).strip()
        if not name:
            raise ValueError(f"no block device has the number {number} of {back}")
        _below(machine, f"/dev/{name}", back, volume, beside, depth + 1)
        return
    # No block device of its own: a tmpfs, or a filesystem such as btrfs that
    # gives each subvolume an anonymous number.
    fstype = mount_types(machine).get(number) or volume.known.get(number)
    if fstype in _IN_RAM:
        return
    if fstype is None:
        raise ValueError(f"the filesystem of {back} ({number}) is not mounted here")
    _place(machine, back, volume, beside, depth + 1)


def skip_control(machine: Any, why: str) -> None:
    """Run no control at the end of the test, for ``why``; the switch phase
    is then judged by the test's own plain soft-reboots alone."""
    oracle = oracle_of(machine)
    if oracle is not None:
        oracle.no_control = why


def is_control(trigger: str) -> bool:
    """Whether a switch's ``trigger`` is a plain soft-reboot of the decoy:
    one that soft-reboots and runs no nails command (a reboot is none)."""
    return "soft-reboot" in trigger and "nails" not in trigger


def after_switch(
    machine: Any,
    label: str,
    opened_here: bool,
    cut_at: int | None,
    release_at: int | None,
    hidden: bool,
) -> None:
    """Once the new userspace is up: keep the window in the hidden root, drop
    it when this switch opened it and did not land there, and close it on the
    way back, at the cut."""
    oracle = oracle_of(machine)
    if oracle is None:
        return
    with oracle.lock:
        _after_switch(oracle, label, opened_here, cut_at, release_at, hidden)
    disarm(machine)


def _after_switch(
    oracle: Oracle,
    label: str,
    opened_here: bool,
    cut_at: int | None,
    release_at: int | None,
    hidden: bool,
) -> None:
    if oracle.window is None:
        return
    if cut_at is not None and release_at is not None and release_at < cut_at:
        oracle.errors.append(
            f"{label}: the mark unit stopped waiting before the host cut the window"
        )
    if hidden:
        if oracle.window.control:
            oracle.errors.append(
                f"{label}: a plain soft-reboot landed in the hidden root"
            )
            oracle.discard()
            return
        learn(oracle, label)
        if opened_here and cut_at is None:
            oracle.errors.append(
                f"{label}: the hidden root's start came without the mark unit's "
                "hold line; its switch and session phases are one"
            )
        return
    if opened_here and not oracle.window.control:
        oracle.discard()
        return
    if oracle.window.control and cut_at is None:
        oracle.uncut_control = True
        oracle.close("the plain soft-reboot, without a cut")
        return
    if cut_at is None:
        oracle.errors.append(
            f"{label}: the way back came without the mark unit's hold line; "
            "the window includes the decoy's own start"
        )
        oracle.close("the way back, without a cut")
        return
    oracle.close("the way back", keep_last=False)


def learn(oracle: Oracle, label: str) -> None:
    """In the hidden session: tell the hidden volume's drives, and sort the
    open window's drives by them."""
    try:
        volume = hidden_volume(oracle.machine, oracle.mount_types)
    except Exception as e:  # noqa: BLE001 - fails closed, as an oracle error
        oracle.errors.append(
            f"{label}: the hidden volume's drives cannot be told ({e}); "
            "the extra disks stay unjudged"
        )
        return
    for serial, what in sorted(volume.shared.items()):
        oracle.errors.append(
            f"{label}: the drive with serial {serial} holds the hidden volume "
            f"beside other data ({what}); it stays a decoy drive, so the "
            "hidden volume's own writes there are findings"
        )
    oracle.learn_hidden(volume.alone)
    held = sorted(volume.alone | set(volume.shared))
    oracle.machine.log(
        f"block-write oracle: {label}: the hidden volume lies on "
        + (", ".join(f"the drive with serial {s}" for s in held) or "no drive")
    )


def disarm(machine: Any) -> None:
    """Remove :data:`ARM` once no window is open, so the next start the host
    does not watch is not held."""
    oracle = oracle_of(machine)
    if oracle is None or oracle.window is not None or not _running(machine):
        return
    try:
        machine.succeed(f"rm -f {ARM}")
    except Exception as e:  # noqa: BLE001 - a later start waits 15 s, no more
        oracle.errors.append(f"the mark unit could not be disarmed: {e}")


def finish(machines: list[Any]) -> None:
    """At the end of the test script: close the windows still open, live,
    measure a control where a session's switch phase needs one and the test
    ran none (:func:`needs_control`), and give the verdicts
    (:meth:`Oracle.raise_on_findings`)."""
    for machine in machines:
        oracle = oracle_of(machine)
        if oracle is None:
            continue
        with oracle.lock:
            _finish_one(machine, oracle)
        if needs_control(oracle):
            _control(machine, oracle)
    for machine in machines:
        oracle = oracle_of(machine)
        if oracle is not None:
            oracle.raise_on_findings()


def needs_control(oracle: Oracle) -> bool:
    """Whether a session's switch phase wrote to a decoy drive that no plain
    soft-reboot of the test was measured on, and the test did not ask for no
    control (:func:`skip_control`)."""
    if oracle.no_control is not None:
        return False
    return any(
        f.decoy and f.phase == SWITCH and f.drive not in oracle.controls
        for f in oracle.findings
    )


#: The plain soft-reboot the oracle runs as its control where the test ran
#: none.
CONTROL_TRIGGER = "systemctl soft-reboot"


def _control(machine: Any, oracle: Oracle) -> None:
    """Measure a plain soft-reboot of the decoy at the end of the test, the
    switch phase's control (:data:`SWITCH_VERDICT`): started first where
    the test left the machine off. A test that ended in the hidden root has
    none."""
    from . import session  # session imports this module

    try:
        if not _running(machine):
            machine.start()
            machine.wait_for_unit("multi-user.target")
        if session.root_fstype(machine) == "overlay":
            oracle.errors.append("no control: the test ended in the hidden root")
            return
        # A distribution VM boots its pristine image again after a power-off,
        # without the mark unit the test installed.
        if oracle.tools.get("mark_setup"):
            machine.succeed(oracle.tools["mark_setup"])
        session.follow_soft_reboot(machine, CONTROL_TRIGGER, "oracle-control")
    except Exception as e:  # noqa: BLE001 - recorded, judged with the rest
        oracle.errors.append(f"the control soft-reboot failed: {e}")


def _finish_one(machine: Any, oracle: Oracle) -> None:
    """Close ``oracle``'s open window live, or note that QEMU ended with it."""
    if oracle.window is None:
        return
    if _running(machine):
        oracle.close("the end of the test")
    else:
        oracle.errors.append(f"{oracle.window.label}: QEMU ended without the oracle")
        oracle.window = None


def tools_on_path() -> dict[str, str]:
    """The tools from ``PATH``, for a driver that has them there."""
    return {name: shutil.which(name.replace("_", "-")) or name for name in TOOLS}
