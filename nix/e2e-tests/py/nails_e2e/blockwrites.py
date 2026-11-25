"""Count every guest write to the decoy disk from the host, through QEMU.

The block-write oracle: from the trigger of a switch into the hidden root until
the session ends, QEMU dirty bitmaps (granularity 512 bytes) on every decoy
drive record each write, write-zeroes and discard the guest makes. They live in
QEMU, on the host, where nothing in the guest can reach them, so the proof does
not depend on knowing which program might write. At the end of the session the
test fails for every byte written to a decoy drive outside the allowed extents
(none in the suite's fixtures: the hidden volume lies on another disk or in
RAM), with the sector ranges and, on ext4, what each range holds.

A window opens just before the trigger of a switch (:func:`before_switch`,
after a guest ``sync``): it covers the activation, the decoy's own shutdown and
the switch. A switch that does not land in the hidden root discards it. It ends
on the way back to the decoy at the hold line of the decoy's early mark unit
(``blkstat-mark``, see ``lib/vm-config.nix``), which waits while the host cuts
the bitmaps, so nothing the decoy's own start writes counts; at a power-off,
which QEMU turns into a pause while a window is open (``set-action``) so the
host can read the bitmaps before it lets QEMU exit; or live, at a crash and at
the end of the test script. The same hold line at the hidden root's own start
splits the window into the phases ``switch`` and ``session``, for the report.

Decoy drives are every writable drive but the suite's extra disks
(``empty<N>.qcow2``: the hidden ``data`` disk, external disks), whose writes
are reported and never asserted.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any

#: The bitmaps' granularity: one guest sector.
GRANULARITY = 512

#: What the mark unit prints on the serial console at each userspace start
#: after the first boot, then waits.
HOLD = "blkstat-mark hold"
#: What it prints when it stops waiting.
RELEASE = "blkstat-mark release"
#: What the host types on the serial console to end the wait, once it cut.
GO = "blkstat-go\n"

#: The phase a window starts with: the activation, the decoy's shutdown, the
#: switch.
SWITCH = "switch"
#: The phase from the hidden root's start on.
SESSION = "session"

#: The tool names :func:`install` takes.
TOOLS = ("qemu_img", "debugfs", "sfdisk")

#: The most blocks of one range the report names a writer for.
ATTRIBUTE_LIMIT = 64


@dataclass(frozen=True)
class Drive:
    """A drive as ``query-block`` lists it."""

    device: str
    node: str
    file: str


def drives(blocks: list[dict[str, Any]]) -> tuple[list[Drive], list[Drive]]:
    """The writable drives of a ``query-block`` reply: the decoy drives, then
    the extra disks (``empty<N>.qcow2``)."""
    decoy: list[Drive] = []
    other: list[Drive] = []
    for block in blocks:
        inserted = block.get("inserted")
        if not inserted or inserted.get("ro"):
            continue
        drive = Drive(
            device=str(block.get("device") or block.get("qdev") or ""),
            node=str(inserted.get("node-name", "")),
            file=str(inserted.get("file", "")),
        )
        name = os.path.basename(_backing_file(inserted))
        if re.fullmatch(r"empty\d+\.qcow2", name):
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


class Oracle:
    """The block-write oracle of one machine."""

    def __init__(self, machine: Any, tools: dict[str, str]) -> None:
        self.machine = machine
        self.tools = tools
        self.window: Window | None = None
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.allowed: dict[str, list[Range]] = {}
        self.serial = 0

    # The QMP side.

    def _qmp(self, command: str, args: dict[str, Any] | None = None) -> Any:
        client = self.machine.qmp_client
        if client is None:
            raise RuntimeError("the machine has no QMP client")
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

    def open(self, label: str) -> None:
        """Open a window labelled ``label``; nothing when one is open."""
        if self.window is not None:
            return
        self.machine.succeed("sync")
        decoy, other = drives(self._qmp("query-block"))
        if not decoy:
            self.errors.append(f"{label}: no decoy drive to watch")
            return
        name = self._bitmap()
        self._qmp("transaction", {"actions": self._add(decoy + other, name)})
        self._qmp("set-action", {"shutdown": "pause"})
        self.window = Window(
            label, self._process(), [Phase(SWITCH, name)], decoy, other
        )
        self.machine.log(
            f"block-write oracle: {label}: watching "
            + ", ".join(d.device or d.node for d in decoy)
        )

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
        self.findings.extend(found)
        clean = not [f for f in found if f.decoy]
        self.machine.log(
            f"block-write oracle: {window.label}: closed at {why}: "
            + ("no write to a decoy drive" if clean else "WRITES TO A DECOY DRIVE")
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

    def raise_on_findings(self) -> None:
        """Raise when a window found a write to a decoy drive, or failed."""
        decoy = [f for f in self.findings if f.decoy]
        if not decoy and not self.errors:
            return
        lines = ["the block-write oracle found writes to the decoy disk:"]
        lines += [f.text() for f in decoy]
        lines += [f"oracle error: {e}" for e in self.errors]
        raise AssertionError("\n".join(lines))


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


def install(machine: Any, tools: dict[str, str]) -> Oracle:
    """Watch ``machine`` with the oracle. Wraps its ``wait_for_shutdown`` and
    ``crash`` so a power-off or crash closes an open window first."""
    oracle = Oracle(machine, tools)
    setattr(machine, _ATTRIBUTE, oracle)
    original_wait = machine.wait_for_shutdown
    original_crash = machine.crash

    def wait_for_shutdown(*args: Any, **kwargs: Any) -> Any:
        if oracle.window is not None:
            wait_for_exit(machine, None)
        return original_wait(*args, **kwargs)

    def crash(*args: Any, **kwargs: Any) -> Any:
        if oracle.window is not None and _running(machine):
            oracle.close("a crash")
        return original_crash(*args, **kwargs)

    machine.wait_for_shutdown = wait_for_shutdown
    machine.crash = crash
    return oracle


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
    oracle.close("a power-off")
    # The monitor's quit, as the driver's own crash() sends it: a QMP quit
    # can end QEMU before its reply, which the driver's QMP reader would
    # wait for without end.
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


def before_switch(machine: Any, label: str) -> bool:
    """Before the trigger of a switch: open a window when none is open.
    Returns whether this switch opened it."""
    oracle = oracle_of(machine)
    if oracle is None or oracle.window is not None:
        return False
    try:
        oracle.open(label)
    except Exception as e:  # noqa: BLE001 - recorded, raised at the end
        oracle.errors.append(f"{label}: the window could not be opened: {e}")
        return False
    return oracle.window is not None


def at_hold(machine: Any, opened_here: bool) -> int:
    """At the mark unit's hold line: cut the window, then end the unit's wait
    by typing :data:`GO` on the serial console, unless it already stopped
    waiting. Returns the console index of the cut, to check the release line
    came after it. The driver's console reader can fall seconds behind the
    guest in the burst of lines a switch prints, so a wait of fixed length
    would end before the host saw the hold line."""
    oracle = oracle_of(machine)
    if oracle is not None and oracle.window is not None:
        oracle.cut(SESSION if opened_here else "after the way back")
    cut_at = len(machine.full_console_log)
    _, release = hold_and_release(machine.full_console_log[-200:])
    send = getattr(machine, "send_console", None)
    if send is not None and release is None:
        send(GO)
    return cut_at


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
    if oracle is None or oracle.window is None:
        return
    if cut_at is not None and release_at is not None and release_at < cut_at:
        oracle.errors.append(
            f"{label}: the mark unit stopped waiting before the host cut the window"
        )
    if hidden:
        return
    if opened_here:
        oracle.discard()
        return
    if cut_at is None:
        oracle.errors.append(
            f"{label}: the way back came without the mark unit's hold line; "
            "the window includes the decoy's own start"
        )
        oracle.close("the way back, without a cut")
        return
    oracle.close("the way back", keep_last=False)


def finish(machines: list[Any]) -> None:
    """At the end of the test script: close the windows still open, live, and
    raise for every write to a decoy drive."""
    for machine in machines:
        oracle = oracle_of(machine)
        if oracle is None:
            continue
        if oracle.window is not None:
            if _running(machine):
                oracle.close("the end of the test")
            else:
                oracle.errors.append(
                    f"{oracle.window.label}: QEMU ended without the oracle"
                )
                oracle.window = None
    for machine in machines:
        oracle = oracle_of(machine)
        if oracle is not None:
            oracle.raise_on_findings()


def tools_on_path() -> dict[str, str]:
    """The tools from ``PATH``, for a driver that has them there."""
    return {name: shutil.which(name.replace("_", "-")) or name for name in TOOLS}
