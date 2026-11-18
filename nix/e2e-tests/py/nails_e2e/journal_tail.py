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

Each plant proves it ran, in the ring buffer: the late writer writes a
record after its lines, which must follow the hidden journald's stop, and
one for each of ``/dev/log`` and the native socket that took its line,
which each must have done unless the hidden service manager had closed that
socket before (before systemd 258 it fails a journald socket that receives
anything once journald has stopped for the soft-reboot, and the socket
holds nothing then), and
the lingering unit's stop command writes one as the way back's last step
ends it, which must fall inside that step. That stop command also writes a
file to ``/run``, which the way back's scrub must have removed: the way back
ends the session's processes before it scrubs ``/run``. An emergency kills
every unit of the session itself before the soft-reboot, the lingering one
among them, so after an emergency the lingering unit is only known to have
run until the plant.

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
apart: they are the residue a hidden volume on device-mapper leaves. After
the decoy's first line its service manager must not open journald's socket,
its ``/dev/log`` socket or its audit socket anew (:data:`REOPENED`), nor
udevd's kernel or control socket (:data:`UDEV_REOPENED`): a plain
soft-reboot carries them listening, and their ``Listening on`` lines would
tell a way back from it, unless the decoy's own shutdown had closed one
already at the entry, which the hidden start then opened anew as well (PID 1
before systemd 258 fails a journald socket that receives anything once
journald has stopped for a soft-reboot). A network link the session leaves
up (:func:`plant_link`), which the way back deletes, must leave no record in
udevd's database.

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
#: soft-reboot service (with its unit name, or its description alone, as
#: NixOS logs it) and the switch, the final kill of the helpers it forks to
#: close a descriptor, which it starts after the step, and the final kill of
#: udevd and its workers, which the way back leaves running for the events
#: its network restore causes, where the soft-reboot leaves udevd running
#: (as on Debian 13 and Ubuntu 24.04). None carries a name of the session,
#: and a plain soft-reboot logs them as well.
HIDDEN_PID1_LINES = (
    re.compile(r"systemd-soft-reboot\.service: Deactivated successfully\."),
    re.compile(r"Finished (systemd-soft-reboot\.service - )?Reboot System Userspace\."),
    re.compile(r"Soft-rebooting\."),
    re.compile(r"Sending SIGKILL to PID \d+ \(\(sd-close\)\)\."),
    re.compile(r"Sending SIGKILL to PID \d+ \((systemd-udevd|\(udev-worker\))\)\."),
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

#: The start of the way back's last step, which the cursor must lie past
#: (NixOS logs the unit's description alone).
STEP_START = re.compile(
    r"systemd\[1\]: Starting (systemd-soft-reboot\.service - )?Reboot System Userspace"
)

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

#: The hidden journald's stop, which the late writer's lines must follow
#: (NixOS logs the unit's description alone).
JOURNALD_STOPPED = re.compile(
    r"systemd\[1\]: (Stopped (systemd-journald\.service - )?Journal Service\."
    r"|systemd-journald\.service: Deactivated successfully\.)"
)

#: The hidden service manager failing journald's socket and its ``/dev/log``
#: socket, which closes each with what it holds.
SOCKET_FAILED = {
    "syslog": re.compile(
        r"systemd\[1\]: systemd-journald-dev-log\.socket: Failed with result"
    ),
    "native": re.compile(r"systemd\[1\]: systemd-journald\.socket: Failed with result"),
}

#: A service manager opening journald's socket, its ``/dev/log`` socket or
#: its audit socket, by unit name and description, or by its description
#: alone as NixOS logs it.
REOPENED = re.compile(
    r"systemd\[1\]: Listening on "
    r"(systemd-journald(-dev-log|-audit)?\.socket - )?"
    r"Journal (Sockets?(\.| \(/dev/log\))|Audit Socket\.)"
)


def reopened_socket(text: str) -> str:
    """Which of journald's sockets a :data:`REOPENED` line opens."""
    if "dev-log" in text or "/dev/log" in text:
        return "dev-log"
    return "audit" if "Audit" in text else "journald"


#: A service manager opening udevd's kernel or control socket, by unit name
#: and description, or by its description alone. On Debian 13 PID 1 failed
#: udevd's kernel socket when an event came in while udevd was stopped inside
#: a soft-reboot, and the decoy's start then opened it anew, which a plain
#: soft-reboot does not.
UDEV_REOPENED = re.compile(
    r"systemd\[1\]: Listening on "
    r"(systemd-udevd-(kernel|control)\.socket - )?udev (Kernel|Control) Socket\."
)


def reopened_udev_socket(text: str) -> str:
    """Which of udevd's sockets a :data:`UDEV_REOPENED` line opens."""
    return "udev-control" if "ontrol" in text else "udev-kernel"


def reopened(text: str) -> str | None:
    """Which socket of journald's or udevd's a ``Listening on`` line opens,
    or None for any other line."""
    if REOPENED.search(text):
        return reopened_socket(text)
    if UDEV_REOPENED.search(text):
        return reopened_udev_socket(text)
    return None


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
    hidden volume's device-mapper teardown it holds, ``closed`` the late
    writer's channels the hidden service manager had closed before it wrote,
    ``tail`` every ring record between the step's start and the decoy's
    first line, marked ``*`` where the decoy's journal holds it."""

    findings: list[str] = field(default_factory=list)
    dm_teardown: list[str] = field(default_factory=list)
    closed: list[str] = field(default_factory=list)
    tail: list[str] = field(default_factory=list)
    judged: bool = False


def judge_records(
    ring: Sequence[Record],
    entries: Sequence[Mapping[str, Any]],
    marker: str,
    names: Iterable[str],
    late_mark: str | None = None,
    linger: str | None = None,
) -> Verdict:
    """Judge the decoy's journal ``entries`` against the ring buffer ``ring``,
    from the in-session kernel ``marker`` on. ``names`` are strings no record
    may hold: the planted processes' names and marks, the hidden
    filesystem's UUID. With ``late_mark`` and ``linger``, the plants of
    :func:`plant` must have run (see the module docs)."""
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
    if late_mark is not None:
        stopped = first_after(ring, at.seq, JOURNALD_STOPPED)
        late = (
            first_after(ring, stopped.seq, re.compile(re.escape(f"{late_mark}-kmsg")))
            if stopped is not None
            else None
        )
        if stopped is None or late is None or late.seq >= step.seq:
            verdict.findings.append(
                "not judged: the late writer did not log after the hidden "
                "journald stopped and before the way back's last step"
            )
        else:
            for channel, failed in SOCKET_FAILED.items():
                sent = re.compile(re.escape(f"{late_mark}-sent-{channel}"))
                if any(
                    stopped.seq < r.seq < late.seq and sent.search(r.text) for r in ring
                ):
                    continue
                if any(
                    stopped.seq < r.seq < late.seq and failed.search(r.text)
                    for r in ring
                ):
                    verdict.closed.append(channel)
                    continue
                verdict.findings.append(
                    f"not judged: the late writer's {channel} line did not go "
                    "out, and its socket was open"
                )
    if linger is not None:
        ended = first_after(ring, step.seq, re.compile(re.escape(f"{linger}-stopped")))
        if ended is None or ended.seq >= banner.seq:
            verdict.findings.append(
                "not judged: the lingering unit did not run until the way "
                "back's last step ended it"
            )
    # The hidden service manager's start after the entry shows what a plain
    # soft-reboot of the decoy does: a socket the decoy's own shutdown closed
    # is opened anew there, and may be after the way back too.
    entered = next(
        (r for r in reversed(ring) if r.seq < at.seq and BANNER.search(r.text)), None
    )
    plain = {
        reopened(r.text)
        for r in ring
        if entered is not None and entered.seq < r.seq < at.seq
    }
    for record in ring:
        socket = reopened(record.text) if record.seq > banner.seq else None
        if socket is not None and socket not in plain:
            owner = "udevd" if socket.startswith("udev") else "journald"
            verdict.findings.append(
                f"the decoy's start opened {owner}'s socket anew: {record.seq} "
                f"{record.text}"
            )

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
        # Only what the journal took in from the marker on: the decoy's own
        # records from before the session, a persistent journal's among them,
        # may name the hidden filesystem (its setup mounted it on the decoy).
        try:
            received = int(entry.get("__MONOTONIC_TIMESTAMP", ""))
        except ValueError:
            received = None
        if received is not None and received < at.usec:
            continue
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
    output and the native socket, each with its own suffix of ``mark``, then
    to the kernel log ``<mark>-sent-syslog`` and ``<mark>-sent-native`` for
    each socket that took its line, and ``<mark>-kmsg`` last, the proof it
    ran. The service manager turns the doubled backslashes into the single
    ones printf reads as a newline."""
    return (
        f'/bin/sh -c "{logger} -t late {mark}-syslog '
        f"&& echo {mark}-sent-syslog > /dev/kmsg; echo {mark}-stdout; "
        f"printf 'MESSAGE={mark}-native\\\\nSYSLOG_IDENTIFIER=late\\\\n' "
        f"| {logger} --journald && echo {mark}-sent-native > /dev/kmsg; "
        f'echo {mark}-kmsg > /dev/kmsg"'
    )


def linger_file(linger: str) -> str:
    """The file in ``/run`` the lingering unit's stop command writes."""
    return f"/run/{linger}-stop"


def linger_stop_command(linger: str) -> str:
    """The lingering unit's stop: :func:`linger_file`, then ``<linger>-stopped``
    to the kernel log, the proof it ran."""
    return (
        f'/bin/sh -c "echo {linger} > {linger_file(linger)} && '
        f'echo {linger}-stopped > /dev/kmsg"'
    )


def plant(machine: Machine, mark: str, linger: str) -> None:
    """In the hidden session, right before its way back: the late writer, a
    unit that stops after the hidden journald (ordered before it, without
    the default dependencies) and logs ``mark`` through each of journald's
    sockets as it does; and a process in the unit ``linger``, which the
    shutdown does not stop, so that PID 1 would name it in its final kill,
    with a stop command that writes to ``/run`` (:func:`linger_stop_command`).
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
        f"-p ExecStop={shlex.quote(linger_stop_command(linger))} "
        f"{shlex.quote(sleep)} infinity",
        f"systemctl is-active {shlex.quote(linger)}.service",
    )


def plant_link(machine: Machine, link: str) -> None:
    """In the hidden session, right before its way back: a network link the
    session made and leaves up (a dummy link named ``link``), which the way
    back's network restore deletes, and udevd's record of it, which udevd
    removes when it handles the deletion. The record must be there now, or
    its absence after the way back would prove nothing."""
    machine.succeed(
        f"ip link add {shlex.quote(link)} type dummy",
        f"ip link set {shlex.quote(link)} up",
        "udevadm settle -t 30",
    )
    if not udev_records_of(machine, link):
        raise AssertionError(f"udevd keeps no record of the planted link {link}")


def udev_records_of(machine: Machine, link: str) -> list[str]:
    """The files of udevd's database that name the network link ``link``."""
    return machine.succeed(
        "grep -lsxE -e "
        + shlex.quote(f"E:(INTERFACE|ID_NET_NAME)={re.escape(link)}")
        + " /run/udev/data/n* || true"
    ).split()


def write_marker(machine: Machine, marker: str) -> None:
    """Write ``marker`` to the kernel log: a record of the session, which the
    decoy's journal must not hold."""
    machine.succeed(f"echo {shlex.quote(marker)} > /dev/kmsg")


#: The ring buffer, read to its end without waiting for more: dd stops with
#: EAGAIN there, an error the driver's shell would fail the command on.
RING = "dd if=/dev/kmsg bs=16384 iflag=nonblock 2>/dev/null || true"

#: The decoy's journal of this boot (a soft-reboot keeps the boot), every
#: transport, with the fields the judgment reads; the receive time
#: (``__MONOTONIC_TIMESTAMP``) comes with every entry.
JOURNAL = (
    "journalctl -b 0 -o json --no-pager "
    "--output-fields=_TRANSPORT,MESSAGE,SYSLOG_IDENTIFIER,SYSLOG_PID,_PID,"
    "_SOURCE_MONOTONIC_TIMESTAMP,_AUDIT_ID"
)


def judge(
    machine: Machine,
    marker: str,
    mark: str,
    linger: str,
    uuid: str | None,
    ended_by_step: bool = True,
    link: str | None = None,
) -> Verdict:
    """After the way back, on the decoy: judge its journal and what the
    lingering unit's stop wrote to ``/run`` (see the module docs). ``uuid``
    is the hidden filesystem's, or None. ``ended_by_step`` is false after an
    emergency, which ends the lingering unit before the way back's last
    step. ``link`` is the network link :func:`plant_link` planted, or None:
    no record of udevd's may name it after the way back."""
    machine.succeed("journalctl --sync")
    ring = parse_kmsg(machine.succeed(RING))
    entries = parse_journal(machine.succeed(JOURNAL))
    names = [mark, linger, f"{LATE_UNIT}.service"]
    if uuid:
        names.append(uuid)
    verdict = judge_records(
        ring, entries, marker, names, mark, linger if ended_by_step else None
    )
    left = machine.succeed(
        f"test -e {linger_file(linger)} && echo left || echo gone"
    ).strip()
    if left != "gone":
        verdict.findings.append(
            f"{linger_file(linger)}, which the lingering unit's stop wrote, "
            "is still in /run"
        )
    if link is not None:
        records = udev_records_of(machine, link)
        if records:
            verdict.findings.append(
                f"udevd's records of the session's link {link} are still in "
                f"/run/udev: {records}"
            )
    return verdict


def nextroot_left(machine: Machine) -> str:
    """What the switch left at ``/run/nextroot``: ``absent``, or its type and
    entries."""
    return machine.succeed(
        "if test -e /run/nextroot -o -L /run/nextroot; then "
        "stat -c '%F' /run/nextroot; mountpoint -q /run/nextroot && echo mounted; "
        "find /run/nextroot -xdev -mindepth 1 -maxdepth 1 | head -n 5; "
        "else echo absent; fi"
    ).strip()
