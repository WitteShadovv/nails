"""What the hidden session hands the decoy's journal at the way back.

The way back writes journald's kmsg cursor, so the decoy's journald imports no
kernel record logged before the cursor. Two channels reach past it unless the
way back closes them, and a test plants something in each before the way
back (:func:`plant`) and judges the decoy's journal after it
(:func:`judge`):

- the kernel log after the cursor: PID 1's final ``Sending SIGKILL to PID N
  (<name>)`` lines, naming each process of the session still alive (the
  planted *lingering* process is one), and the kernel's unmount line of the
  hidden filesystem, which names its UUID;
- journald's sockets, which a soft-reboot keeps open: a unit that stops after
  the hidden journald (the *late writer*) logs a line through ``/dev/log``,
  its standard output and the native socket, and the hidden root's last
  audit records wait in the audit socket.

The judgment reads the kernel ring buffer (RAM, where the hidden session's
records stay until power-off) to place what the decoy's journal holds: the
in-session marker the test wrote right before the way back, the start of the
way back's last step (``Starting systemd-soft-reboot.service``) and the first
line of the decoy's service manager (``systemd <version> running in system
mode``). No kernel record from the marker to the step's start may be in the
decoy's journal (the cursor). Between the step's start and that first line,
the hidden root's service manager logs only the soft-reboot's own end
(:data:`HIDDEN_PID1_LINES`), and the decoy's, before its first line, only its
policy load (:data:`DECOY_PID1_LINES`): any other line of PID 1 there that
the decoy's journal holds is the hidden session's. No record anywhere may
name a planted process or mark, or the hidden filesystem, and no audit record
the hidden root sent may be in the decoy's journal by any transport. The
kernel's lines of a device-mapper teardown (:data:`DM_TEARDOWN`) are judged
apart: they are the residue a hidden volume on device-mapper leaves.

:func:`nextroot_left` reads what the switch left at ``/run/nextroot``.
"""

from __future__ import annotations

import json
import re
import shlex
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol


class Machine(Protocol):
    """The slice of the driver's machine object these helpers use."""

    def succeed(self, *commands: str) -> str: ...


#: The hidden service manager's own last lines after the step: the end of the
#: soft-reboot service and the switch. A plain soft-reboot logs them as well.
HIDDEN_PID1_LINES = (
    re.compile(r"systemd-soft-reboot\.service: Deactivated successfully\."),
    re.compile(r"Finished systemd-soft-reboot\.service( - .*)?\.?"),
    re.compile(r"Soft-rebooting\."),
)

#: The decoy's service manager before its first line: it loads its SELinux
#: policy, or says it keeps the one loaded. A plain soft-reboot logs the same.
DECOY_PID1_LINES = (
    re.compile(r"Failed to load new SELinux policy\. Continuing with old policy\."),
    re.compile(r"Successfully loaded SELinux policy in .*"),
    re.compile(r"Relabeled? .*"),
)

#: The first line of a service manager's start.
BANNER = re.compile(r"systemd \S+ running in system mode")

#: The start of the way back's last step, which the cursor must lie past.
STEP_START = re.compile(r"Starting systemd-soft-reboot\.service")

#: The kernel's own records the tail may hold: the audit records of the
#: hidden service manager's last two (the soft-reboot service's start and
#: stop), the BPF programs it unloads as it hands over, and the decoy's
#: service manager loading its SELinux policy (the policy's records, and
#: PID 1's own checks on reading it).
KERNEL_LINES = (
    re.compile(
        r"audit: type=113[01] audit\([^)]*\): pid=1 .*msg='unit=systemd-soft-reboot .*"
    ),
    re.compile(r"audit: type=1334 audit\([^)]*\): prog-id=\d+ op=(UN)?LOAD"),
    re.compile(
        r"audit: type=1400 audit\([^)]*\): avc: +(denied|granted) "
        r"+\{ [a-z_ ]+ \} for +pid=1 "
        r'comm="systemd" path="/etc/selinux/.*'
    ),
    re.compile(r"audit: type=140[34] audit\([^)]*\): .*"),
    re.compile(r"SELinux: .*"),
)

#: The kernel's lines of the hidden device-mapper volume's teardown, which it
#: logs as the decoy starts: the dm-crypt target's audit record, and the
#: deferred removal's count of other device-mapper devices.
DM_TEARDOWN = (
    re.compile(r"audit: type=1338 .*\bmodule=crypt op=dtr\b"),
    re.compile(r"device-mapper: ioctl: remove_all left \d+ open device\(s\)"),
)

#: An audit record's time stamp and serial, ``audit(1794677720.975:717)``.
AUDIT_STAMP = re.compile(r"audit\((\d+)\.(\d+):(\d+)\)")


@dataclass(frozen=True)
class Record:
    """One record of the kernel ring buffer."""

    seq: int
    usec: int
    text: str


def parse_kmsg(dump: str) -> list[Record]:
    """The records of a ``/dev/kmsg`` dump (``prio,seq,usec,flags;text`` lines;
    continuation lines start with a space)."""
    records = []
    for line in dump.splitlines():
        if not line or line.startswith(" ") or ";" not in line:
            continue
        header, _, text = line.partition(";")
        parts = header.split(",")
        if len(parts) < 3:
            continue
        try:
            records.append(Record(int(parts[1]), int(parts[2]), text))
        except ValueError:
            continue
    return records


def first_after(
    records: Sequence[Record], seq: int, pattern: re.Pattern[str]
) -> Record | None:
    """The first record numbered above ``seq`` whose text matches."""
    return next((r for r in records if r.seq > seq and pattern.search(r.text)), None)


def message(entry: Mapping[str, Any]) -> str:
    """An entry's MESSAGE as text (journalctl gives bytes as a number list)."""
    value = entry.get("MESSAGE", "")
    if isinstance(value, list):
        return bytes(int(b) & 0xFF for b in value).decode("utf-8", "replace")
    return str(value)


def parse_journal(text: str) -> list[dict[str, Any]]:
    """The entries of ``journalctl -o json`` output."""
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            entries.append(value)
    return entries


def kernel_text(entry: Mapping[str, Any]) -> str:
    """How the ring buffer shows a kernel-transport entry: a userspace line
    written to ``/dev/kmsg`` with its identifier and process number."""
    text = message(entry)
    ident = entry.get("SYSLOG_IDENTIFIER")
    pid = entry.get("SYSLOG_PID") or entry.get("_PID")
    if ident and ident != "kernel" and pid:
        return f"{ident}[{pid}]: {text}"
    return text


def audit_serial(text: str) -> int | None:
    """The serial of the audit record ``text`` names, or None."""
    match = AUDIT_STAMP.search(text)
    return int(match.group(3)) if match else None


@dataclass
class Verdict:
    """What the decoy's journal holds of the hidden session after one way
    back. ``findings`` must be empty; ``dm_teardown`` lists the lines of the
    hidden volume's device-mapper teardown it holds, ``tail`` every ring
    record between the step's start and the decoy's first line, marked
    ``*`` where the decoy's journal holds it."""

    findings: list[str] = field(default_factory=list)
    dm_teardown: list[str] = field(default_factory=list)
    tail: list[str] = field(default_factory=list)
    judged: bool = False


def judge_records(
    ring: Sequence[Record],
    entries: Sequence[Mapping[str, Any]],
    marker: str,
    names: Iterable[str],
) -> Verdict:
    """Judge the decoy's journal ``entries`` against the ring buffer ``ring``,
    from the in-session kernel ``marker`` on. ``names`` are strings no record
    may hold: the planted processes' names and marks, the hidden
    filesystem's UUID."""
    verdict = Verdict()
    names = [n for n in names if n]
    at = next((r for r in ring if marker in r.text), None)
    if at is None:
        verdict.findings.append(
            f"the in-session marker {marker} is not in the ring buffer"
        )
        return verdict
    step = first_after(ring, at.seq, STEP_START)
    if step is None:
        verdict.findings.append("the way back's last step is not in the ring buffer")
        return verdict
    banner = first_after(ring, step.seq, BANNER)
    if banner is None:
        verdict.findings.append("the decoy's service manager never started")
        return verdict
    verdict.judged = True

    kernel = [e for e in entries if e.get("_TRANSPORT") == "kernel"]
    by_usec: dict[int, list[str]] = {}
    for entry in kernel:
        try:
            usec = int(entry.get("_SOURCE_MONOTONIC_TIMESTAMP", ""))
        except ValueError:
            continue
        by_usec.setdefault(usec, []).append(kernel_text(entry))

    def imported(record: Record) -> bool:
        return any(
            record.text == text
            or record.text.endswith(text)
            or text.endswith(record.text)
            for text in by_usec.get(record.usec, [])
        )

    for record in ring:
        if at.seq <= record.seq <= step.seq and imported(record):
            verdict.findings.append(f"before the cursor: {record.seq} {record.text}")
    last_hidden_audit: int | None = None
    for record in ring:
        if record.seq < step.seq and record.text.startswith("audit:"):
            last_hidden_audit = audit_serial(record.text) or last_hidden_audit
        if not step.seq < record.seq < banner.seq:
            continue
        held = imported(record)
        verdict.tail.append(f"{'*' if held else ' '} {record.seq} {record.text}")
        if not held:
            continue
        if any(p.search(record.text) for p in DM_TEARDOWN):
            verdict.dm_teardown.append(record.text)
            continue
        pid1 = re.fullmatch(r"systemd\[1\]: (.*)", record.text)
        if pid1:
            allowed = HIDDEN_PID1_LINES + DECOY_PID1_LINES
            ok = any(p.fullmatch(pid1.group(1)) for p in allowed)
        else:
            ok = any(p.fullmatch(record.text) for p in KERNEL_LINES)
        if not ok:
            verdict.findings.append(f"after the cursor: {record.seq} {record.text}")
    for entry in entries:
        text = message(entry)
        transport = str(entry.get("_TRANSPORT", ""))
        hit = [n for n in names if n in text]
        if hit:
            verdict.findings.append(f"{transport} names {hit}: {text[:200]}")
            continue
        if transport == "audit" and last_hidden_audit is not None:
            serial = audit_serial(text)
            if serial is None:
                try:
                    serial = int(str(entry.get("_AUDIT_ID", "")))
                except ValueError:
                    serial = None
            if serial is not None and serial <= last_hidden_audit:
                verdict.findings.append(
                    f"audit record of the hidden root: {text[:200]}"
                )
    return verdict


#: The unit of the late writer.
LATE_UNIT = "late-writer"


def late_stop_command(logger: str, mark: str) -> str:
    """The late writer's stop: one line through ``/dev/log``, its standard
    output and the native socket, each with its own suffix of ``mark``. The
    service manager turns the doubled backslashes into the single ones
    printf reads as a newline."""
    return (
        f'/bin/sh -c "{logger} -t late {mark}-syslog; echo {mark}-stdout; '
        f"printf 'MESSAGE={mark}-native\\\\nSYSLOG_IDENTIFIER=late\\\\n' "
        f'| {logger} --journald"'
    )


def plant(machine: Machine, mark: str, linger: str) -> None:
    """In the hidden session, right before its way back: the late writer, a
    unit that stops after the hidden journald (ordered before it, without
    the default dependencies) and logs ``mark`` through each of journald's
    sockets as it does; and a process in the unit ``linger``, which the
    shutdown does not stop, so that PID 1 would name it in its final kill.
    It runs from the root itself, so it keeps no other mount busy."""
    logger = machine.succeed("command -v logger").strip()
    sleep = machine.succeed("command -v sleep").strip()
    stop = late_stop_command(logger, mark)
    machine.succeed(
        f"systemd-run --unit={LATE_UNIT} --remain-after-exit "
        "-p DefaultDependencies=no -p Conflicts=shutdown.target "
        "-p Before=shutdown.target -p Before=systemd-journald.service "
        f"-p ExecStop={shlex.quote(stop)} /bin/sh -c true",
        f"systemctl is-active {LATE_UNIT}.service",
    )
    machine.succeed(
        f"systemd-run --unit={shlex.quote(linger)} -p DefaultDependencies=no "
        f"{shlex.quote(sleep)} infinity",
        f"systemctl is-active {shlex.quote(linger)}.service",
    )


def write_marker(machine: Machine, marker: str) -> None:
    """Write ``marker`` to the kernel log: a record of the session, which the
    decoy's journal must not hold."""
    machine.succeed(f"echo {shlex.quote(marker)} > /dev/kmsg")


#: The ring buffer, read to its end without waiting for more.
RING = "dd if=/dev/kmsg bs=16384 iflag=nonblock 2>/dev/null; true"

#: The decoy's journal, every transport, with the fields the judgment reads.
JOURNAL = (
    "journalctl -o json --no-pager "
    "--output-fields=_TRANSPORT,MESSAGE,SYSLOG_IDENTIFIER,SYSLOG_PID,_PID,"
    "_SOURCE_MONOTONIC_TIMESTAMP,_AUDIT_ID"
)


def judge(
    machine: Machine, marker: str, mark: str, linger: str, uuid: str | None
) -> Verdict:
    """After the way back, on the decoy: judge its journal (see the module
    docs). ``uuid`` is the hidden filesystem's, or None."""
    machine.succeed("journalctl --sync")
    ring = parse_kmsg(machine.succeed(RING))
    entries = parse_journal(machine.succeed(JOURNAL))
    names = [mark, linger, f"{LATE_UNIT}.service"]
    if uuid:
        names.append(uuid)
    return judge_records(ring, entries, marker, names)


def nextroot_left(machine: Machine) -> str:
    """What the switch left at ``/run/nextroot``: ``absent``, or its type and
    entries."""
    return machine.succeed(
        "if test -e /run/nextroot -o -L /run/nextroot; then "
        "stat -c '%F' /run/nextroot; mountpoint -q /run/nextroot && echo mounted; "
        "find /run/nextroot -xdev -mindepth 1 -maxdepth 1 | head -n 5; "
        "else echo absent; fi"
    ).strip()
