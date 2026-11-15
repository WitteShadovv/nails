"""Reading the kernel log of an enforcing Fedora decoy for the admission gate.

The gate scenarios (``nix/distro-tests/fedora-gate.nix``, run by
``py/fedora_gate.py``) run NAILS on a Fedora image booted with SELinux
enforcing and count the AVC denials of every step, from the boot before NAILS
ran, in both roots. They mark each step in the kernel log (``/dev/kmsg``) and
read the whole log after it, so that a denial falls between two markers. This
module holds the pure parts:

- the reader the guest runs and the parsing of its records (:func:`kmsg_command`,
  :func:`parse_kmsg`), with the sequence gaps that would mean a lost record;
- the markers (:func:`marker`, :func:`marker_seq`);
- the denials and SELinux errors (:func:`parse_avc`, :func:`parse_selinux_err`),
  who they belong to (:func:`source`) and what makes two of them the same
  (:func:`signature`);
- the records auditd wrote while it ran (:func:`audit_log`), which the kernel
  hands to a running auditd instead of its log, and the audit serial numbers
  of a boot (:func:`audit_serials`, :func:`serial_gaps`), so that a record
  that reached neither log shows as a gap;
- a phase between two markers (:func:`phase`): which of its denials are new,
  that is NAILS's own, or not among those of the decoy before NAILS ran and
  of the first plain soft-reboot, nor a race of the image's own
  (:data:`IMAGE_RACES`), and the lines that say the kernel lost records;
- whether the decoy's journal took kernel records of a hidden session after
  the way back (:func:`cursor`), the leak the transition's kmsg cursor
  prevents.

Nothing here imports Nix or the test driver.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

# Prints every record of /dev/kmsg whose sequence number is at least the first
# argument, one record per read, as the kernel formats it. A record the ring
# buffer dropped while reading shows as one "#EPIPE" line.
KMSG_READER = r"""
import errno, os, sys
first = int(sys.argv[1])
fd = os.open("/dev/kmsg", os.O_RDONLY | os.O_NONBLOCK)
out = sys.stdout.buffer
while True:
    try:
        record = os.read(fd, 65536)
    except BlockingIOError:
        break
    except OSError as error:
        if error.errno == errno.EPIPE:
            out.write(b"#EPIPE\n")
            continue
        raise
    if not record:
        break
    head = record.split(b",", 2)
    if len(head) > 2 and head[1].isdigit() and int(head[1]) < first:
        continue
    out.write(record)
out.flush()
"""

# The prefix of every marker line the scenario writes to /dev/kmsg.
MARK = "GATEMARK"

# Every message reaches the kernel log and no rate limit drops one. The kernel
# prints only its warnings and worse to the console: what it prints there
# bypasses the terminal and can split a program's line in two, such as the
# backdoor's announcement the test driver waits for after a soft-reboot
# (nails_e2e.session.BACKDOOR_MARKER), and the serial console's pace held
# back the kernel's queue of audit records. Every record stays in the kernel
# log the gate reads.
KMSG_SETTINGS = (
    ("kernel.printk_ratelimit", "0"),
    ("kernel.printk_devkmsg", "on"),
    ("kernel.printk", "5 4 1 7"),
)
KMSG_LIMITS = "sysctl -w " + " ".join(f"'{k}={v}'" for k, v in KMSG_SETTINGS)

# The image's own races: a denial with this signature is the image's whatever
# phase it falls in. agetty reads the console-login helper's issue file while
# that helper's NetworkManager dispatcher replaces it, at some boots of either
# root, a plain boot of the stock image's included.
IMAGE_RACES = frozenset(
    {
        "kernel {read} agetty getty_t NetworkManager_dispatcher_console_var_run_t file",
    }
)

_RECORD = re.compile(r"^(\d+),(\d+),(\d+),([^;]*);(.*)$")
_FIELD = re.compile(r"(\w+)=(\"[^\"]*\"|'[^']*'|\S+)")
_PERMS = re.compile(r"\{ ([^}]*) \}")
_BANNER = re.compile(r"systemd\[1\]: systemd \d+")
# The records PID 1 logs once the switch's last userspace step has ended.
_STEP_END = (
    "systemd-soft-reboot.service: Deactivated successfully",
    "systemd-soft-reboot.service: Main process exited",
    "Soft-rebooting.",
)
# What the kernel prints when it lost audit records or kernel log lines: a rate
# limit that suppressed printk callbacks, and the audit subsystem's own notices
# of a record it dropped (audit_log_lost) or held back past its queue.
SUPPRESSED = (
    "callbacks suppressed",
    "suppressed due to ratelimiting",
    "audit_lost=",
    "backlog limit exceeded",
    "rate limit exceeded",
    "hold queue overflow",
    "retry queue overflow",
    "printk limit exceeded",
)
# The numbers the kernel log prints for the record types auditd's log names.
AUDIT_NUMBERS = {"AVC": "1400", "USER_AVC": "1107", "SELINUX_ERR": "1401"}
# The record types that report an SELinux error rather than a denial: the
# kernel's, by its number in the kernel log or its name in auditd's log, and
# a userspace object manager's, by its name.
ERROR_TYPES = ("type=1401 ", "type=SELINUX_ERR ", "type=USER_SELINUX_ERR ")
_AUDIT_LINE = re.compile(r"^type=(\w+) msg=audit\((\d+)\.(\d+):(\d+)\): ?(.*)$")
_SERIAL = re.compile(r"audit\(\d+\.\d+:(\d+)\)")
_SYSCALL = "type=1300 "


def kmsg_command(first: int) -> str:
    """The guest command that prints the records from ``first`` on."""
    return f"python3 - {int(first)} <<'GATEEOF'\n{KMSG_READER}\nGATEEOF\n"


def parse_kmsg(text: str) -> tuple[list[dict[str, Any]], int]:
    """The records in ``text`` (output of :data:`KMSG_READER`), and how many
    times the reader saw the ring buffer drop records."""
    records: list[dict[str, Any]] = []
    dropped = 0
    for line in text.splitlines():
        if line == "#EPIPE":
            dropped += 1
            continue
        if line.startswith(" ") and records:
            records[-1]["dict"].append(line.strip())
            continue
        match = _RECORD.match(line)
        if match is None:
            continue
        records.append(
            {
                "pri": int(match.group(1)),
                "seq": int(match.group(2)),
                "us": int(match.group(3)),
                "msg": match.group(5),
                "dict": [],
            }
        )
    return records, dropped


def merge(
    known: dict[int, dict[str, Any]], records: Iterable[Mapping[str, Any]]
) -> None:
    """Add ``records`` to ``known`` by sequence number."""
    for record in records:
        known.setdefault(int(record["seq"]), dict(record))


def gaps(seqs: Sequence[int]) -> list[tuple[int, int]]:
    """The missing ranges in the sorted sequence numbers ``seqs``."""
    missing = []
    for before, after in zip(seqs, seqs[1:], strict=False):
        if after > before + 1:
            missing.append((before + 1, after - 1))
    return missing


def marker(label: str, nonce: str) -> str:
    """The text of the marker ``label`` of a run with ``nonce``."""
    return f"{MARK} {nonce} {label}"


def marker_seq(records: Iterable[Mapping[str, Any]], text: str) -> int | None:
    """The sequence number of the first record that is the marker ``text``."""
    for record in sorted(records, key=lambda r: int(r["seq"])):
        if str(record["msg"]).strip().endswith(text):
            return int(record["seq"])
    return None


def fields(text: str) -> dict[str, str]:
    """The ``key=value`` fields of an audit record, quotes removed."""
    found: dict[str, str] = {}
    for key, value in _FIELD.findall(text):
        if len(value) > 1 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        found.setdefault(key, value)
    return found


def context_type(context: str) -> str:
    """The type of an SELinux context (``system_u:system_r:init_t:s0``)."""
    parts = context.split(":")
    return parts[2] if len(parts) > 2 else context


def parse_avc(message: str) -> dict[str, Any] | None:
    """The denial in a kernel (1400) or userspace (1107) AVC record, or None."""
    at = message.find("avc:  denied")
    if at < 0:
        return None
    body = message[at:]
    perms = _PERMS.search(body)
    values = fields(body.split("}", 1)[1] if "}" in body else body)
    kind = "user" if "type=1107" in message else "kernel"
    if kind == "user":
        # The sender's own fields come before msg='...'.
        outer = fields(message[: message.find("msg=")])
        values.setdefault("pid", outer.get("pid", ""))
        values.setdefault("subj", outer.get("subj", ""))
    return {
        "kind": kind,
        "perms": perms.group(1).strip() if perms else "",
        "pid": values.get("pid", ""),
        "comm": values.get("comm", values.get("exe", "")),
        "name": values.get("name", ""),
        "path": values.get("path", ""),
        "dev": values.get("dev", ""),
        "scontext": values.get("scontext", ""),
        "tcontext": values.get("tcontext", ""),
        "tclass": values.get("tclass", ""),
        "permissive": values.get("permissive", ""),
    }


def parse_selinux_err(message: str) -> dict[str, Any] | None:
    """The SELinux error in a kernel (1401) or userspace record, or None: an
    invalid context, a transition the policy's bounds refuse. Its operation
    (``op``) stands where a denial has its permissions. The contexts are the
    source and target (``scontext``, ``tcontext``) or the old and the new
    (``oldcontext``, ``newcontext``) of a refused transition."""
    at = next((message.find(kind) for kind in ERROR_TYPES if kind in message), -1)
    if at < 0:
        return None
    values = fields(message[at:])
    return {
        "kind": "error",
        "perms": values.get("op", ""),
        "pid": values.get("pid", ""),
        "comm": values.get("comm", values.get("exe", "")),
        "name": values.get("name", ""),
        "path": values.get("path", ""),
        "dev": values.get("dev", ""),
        "scontext": values.get("scontext", values.get("oldcontext", "")),
        "tcontext": values.get(
            "tcontext", values.get("newcontext", values.get("invalid_context", ""))
        ),
        "tclass": values.get("tclass", ""),
        "permissive": "",
    }


def serial_of(message: str) -> int | None:
    """The audit serial number of a record (``audit(<time>:<serial>)``)."""
    match = _SERIAL.search(message)
    return int(match.group(1)) if match else None


def audit_log(text: str, since: float) -> list[dict[str, Any]]:
    """The records of auditd's log ``text`` written at ``since`` (seconds
    since the epoch) or later: each one's time, serial number and type, and its
    message as the kernel log prints a record (``audit: type=1400
    audit(...): ...``), so that :func:`parse_avc` reads it alike. The
    interpreted fields of the log's ENRICHED format, after a 0x1d byte, are
    left out."""
    found = []
    for line in text.splitlines():
        line = line.split("\x1d", 1)[0].strip()
        match = _AUDIT_LINE.match(line)
        if match is None:
            continue
        kind, seconds, fraction, serial, body = match.groups()
        time = float(f"{seconds}.{fraction}")
        if time < since:
            continue
        number = AUDIT_NUMBERS.get(kind, kind)
        found.append(
            {
                "time": time,
                "serial": int(serial),
                "type": kind,
                "msg": f"audit: type={number} audit({seconds}.{fraction}:{serial}): "
                f"{body}",
            }
        )
    return found


def boot_audit_log(
    text: str, btime: float, slack: float = 120.0
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """The records auditd's log ``text`` holds of the boot that started at
    ``btime`` (seconds since the epoch), as :func:`audit_log` reads them, and
    what bounded them.

    They are the records after auditd's last start in the log, its
    DAEMON_START record, when that start is of this boot: dated no more than
    ``slack`` seconds before ``btime``, since a step of the clock moves the
    times of a boot against each other. Without such a start the boot's
    records are not told apart from an earlier boot's, and none is taken.
    auditd's own records (DAEMON_START, DAEMON_END and the like) carry its own
    serial numbers, not the kernel's, and are left out."""
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.startswith("type=DAEMON_START "):
            start = index
    info: dict[str, Any] = {"btime": btime, "start": None}
    if start is None:
        return [], info
    first = audit_log(lines[start], 0)
    began = first[0]["time"] if first else None
    info["start"] = began
    if began is None or began < btime - slack:
        return [], info
    records = [
        record
        for record in audit_log("\n".join(lines[start + 1 :]), 0)
        if not str(record["type"]).startswith("DAEMON_")
    ]
    if records:
        info["serials"] = [
            min(r["serial"] for r in records),
            max(r["serial"] for r in records),
        ]
        info["times"] = [records[0]["time"], records[-1]["time"]]
    return records, info


def audit_serials(messages: Iterable[str]) -> set[int]:
    """The audit serial numbers the records ``messages`` carry."""
    return {
        serial for serial in (serial_of(str(m)) for m in messages) if serial is not None
    }


def serial_gaps(serials: Iterable[int], first: int = 1) -> list[tuple[int, int]]:
    """The audit serial numbers of a boot from ``first`` on that no record
    carries, as ranges: the kernel numbers the events of a boot from 1 on,
    each record of an event carries its event's number, and a record reaches
    the kernel log or the daemon that reads the audit socket, so a number
    neither shows was lost. Before the gate lifts printk's rate limit, and
    while no daemon reads the socket, the kernel drops what the limit keeps
    from its log, so the gate judges the numbers from its first marker on."""
    known = sorted({serial for serial in serials if serial >= first})
    if not known:
        return []
    missing = gaps(known)
    if known[0] > first:
        missing.insert(0, (first, known[0] - 1))
    return missing


def source(avc: Mapping[str, Any]) -> str:
    """Who a denial belongs to: NAILS (the RAM copy, which runs as
    ``control``, and the CLI, or a path below a NAILS runtime directory), PID
    1, or another process."""
    where = f"{avc.get('name', '')} {avc.get('path', '')}"
    comm = str(avc.get("comm", ""))
    if (
        comm in ("control", "(control)", "nails", "alert")
        or "overlay-runtime" in where
        or "overlay-runtime" in comm
    ):
        return "nails"
    if str(avc.get("pid", "")) == "1":
        return "pid1"
    return "other"


def signature(avc: Mapping[str, Any]) -> str:
    """What makes two denials the same, whatever process numbers they had."""
    return " ".join(
        (
            str(avc.get("kind", "")),
            "{" + str(avc.get("perms", "")) + "}",
            str(avc.get("comm", "")),
            context_type(str(avc.get("scontext", ""))),
            context_type(str(avc.get("tcontext", ""))),
            str(avc.get("tclass", "")),
        )
    )


def syscalls(records: Iterable[Mapping[str, Any]]) -> dict[int, dict[str, str]]:
    """The ``comm``, ``exe`` and ``pid`` of each event's SYSCALL record, by
    the event's serial number: an SELinux error names no process itself."""
    found = {}
    for record in records:
        message = str(record["msg"])
        if _SYSCALL not in message and "type=SYSCALL " not in message:
            continue
        serial = serial_of(message)
        if serial is not None:
            values = fields(message)
            found[serial] = {key: values.get(key, "") for key in ("comm", "exe", "pid")}
    return found


def _judged(
    records: Sequence[Mapping[str, Any]],
) -> list[tuple[Mapping[str, Any], dict[str, Any]]]:
    """Each denial and SELinux error in ``records``, with the record it is in,
    its source and its signature; an error takes the process of its event's
    SYSCALL record."""
    calls = syscalls(records)
    found = []
    for record in records:
        message = str(record["msg"])
        avc = parse_avc(message) or parse_selinux_err(message)
        if avc is None:
            continue
        serial = serial_of(message)
        call = calls.get(serial, {}) if serial is not None else {}
        if not avc["comm"]:
            avc["comm"] = call.get("comm", "") or call.get("exe", "")
        if not avc["pid"]:
            avc["pid"] = call.get("pid", "")
        avc["serial"] = serial
        avc["source"] = source(avc)
        avc["signature"] = signature(avc)
        found.append((record, avc))
    return found


def denials(
    records: Iterable[Mapping[str, Any]], first: int | None, last: int | None
) -> list[dict[str, Any]]:
    """The denials and SELinux errors between the records ``first`` and
    ``last`` (exclusive), each with its sequence number, source and
    signature."""
    inside = [
        record
        for record in sorted(records, key=lambda r: int(r["seq"]))
        if not (first is not None and int(record["seq"]) <= first)
        and not (last is not None and int(record["seq"]) >= last)
    ]
    found = []
    for record, avc in _judged(inside):
        avc["seq"] = int(record["seq"])
        avc["log"] = "kernel"
        found.append(avc)
    return found


def audit_denials(audit: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The denials and SELinux errors among records of auditd's log
    (:func:`audit_log`), each with its time and serial number."""
    records = sorted(audit, key=lambda r: (float(r["time"]), int(r["serial"])))
    found = []
    for record, avc in _judged(records):
        avc["seq"] = None
        avc["time"] = float(record["time"])
        avc["log"] = "audit"
        found.append(avc)
    return found


def phase(
    records: Iterable[Mapping[str, Any]],
    first: int | None,
    last: int | None,
    baseline: Iterable[str] = (),
    audit: Iterable[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """The denials of the phase between the records ``first`` and ``last``,
    with those of ``audit``, the records auditd's log holds of the phase
    (:func:`audit_log`).

    A denial is new when it is NAILS's own, or when its signature is neither
    in ``baseline`` (the denials of the decoy before NAILS ran and of the
    first plain soft-reboot) nor one of the image's own races. The result
    also names the lines that say the kernel lost records, and the policy
    loads."""
    records = list(records)
    known = set(baseline)
    found = denials(records, first, last) + audit_denials(audit)
    for avc in found:
        if avc["source"] == "nails":
            avc["new"] = True
            avc["why"] = "a NAILS process or path"
        elif avc["signature"] in known:
            avc["new"] = False
            avc["why"] = "also without NAILS in this run"
        elif avc["signature"] in IMAGE_RACES:
            avc["new"] = False
            avc["why"] = "the image's own race"
        else:
            avc["new"] = True
            avc["why"] = "not seen without NAILS"
    inside = [
        r
        for r in records
        if (first is None or int(r["seq"]) > first)
        and (last is None or int(r["seq"]) < last)
    ]
    return {
        "first": first,
        "last": last,
        "records": len(inside),
        "denials": found,
        "new": [avc for avc in found if avc["new"]],
        "suppressed": [
            str(r["msg"]) for r in inside if any(s in str(r["msg"]) for s in SUPPRESSED)
        ],
        "policy": [
            str(r["msg"])
            for r in inside
            if "SELinux policy" in str(r["msg"]) or "Relabel" in str(r["msg"])
        ],
    }


def journal_records(text: str) -> list[dict[str, Any]]:
    """The records of ``journalctl -o json`` output: the kernel timestamp
    (``_SOURCE_MONOTONIC_TIMESTAMP``, microseconds) and the message."""
    found = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        stamp = entry.get("_SOURCE_MONOTONIC_TIMESTAMP")
        message = entry.get("MESSAGE")
        if isinstance(message, list):
            message = bytes(b & 0xFF for b in message).decode("utf-8", "replace")
        if stamp is None or not str(stamp).isdigit():
            continue
        found.append({"us": int(stamp), "msg": str(message or "")})
    return found


def first_after(
    records: Iterable[Mapping[str, Any]],
    after: int,
    before: int | None,
    match: Any,
) -> int | None:
    """The first record between ``after`` and ``before`` whose message
    ``match`` accepts."""
    for record in sorted(records, key=lambda r: int(r["seq"])):
        seq = int(record["seq"])
        if seq <= after or (before is not None and seq >= before):
            continue
        if match(str(record["msg"])):
            return seq
    return None


def imported(
    records: Iterable[Mapping[str, Any]], journal: Iterable[Mapping[str, Any]]
) -> list[int]:
    """The sequence numbers of the kernel records the journal holds, matched by
    their kernel timestamp (and message where two records share one)."""
    by_us: dict[int, list[Mapping[str, Any]]] = {}
    for record in records:
        by_us.setdefault(int(record["us"]), []).append(record)
    seqs = set()
    for entry in journal:
        candidates = by_us.get(int(entry["us"]), [])
        if len(candidates) > 1:
            text = str(entry["msg"])[:40]
            candidates = [c for c in candidates if text in str(c["msg"])] or candidates
        for record in candidates[:1]:
            seqs.add(int(record["seq"]))
    return sorted(seqs)


def cursor(
    records: Sequence[Mapping[str, Any]],
    journal_text: str,
    enter: int | None,
    leave: int | None,
    back: int | None,
) -> dict[str, Any]:
    """Whether the decoy's runtime journal after a way back holds kernel
    records of the session.

    The transition step writes the cursor as it ends, so every record the
    journal imported from the session's entry (``enter``) up to the end of
    that step (found after ``leave``, before ``back``) is a leak. The records
    PID 1 logs after the step, up to the new userspace, cannot be skipped by a
    cursor written before them: they are counted apart. ``known`` is False
    when a marker or the step's end was not found, so nothing was judged."""
    journal = journal_records(journal_text)
    seqs = imported(records, journal)
    step_end = banner = None
    if leave is not None:
        step_end = first_after(
            records, leave, back, lambda m: any(t in m for t in _STEP_END)
        )
        banner = first_after(
            records,
            leave,
            back,
            lambda m: bool(_BANNER.search(m)) or "SELinux policy" in m,
        )
    known = enter is not None and step_end is not None
    session = (
        [s for s in seqs if enter <= s < step_end]
        if enter is not None and step_end is not None
        else []
    )
    after_step = [
        s
        for s in seqs
        if step_end is not None and banner is not None and step_end <= s < banner
    ]
    by_seq = {int(r["seq"]): str(r["msg"]) for r in records}
    return {
        "known": known,
        "journalKernelRecords": len(journal),
        "matched": len(seqs),
        "stepEnd": step_end,
        "newUserspace": banner,
        "leakedFromSession": len(session),
        "afterStep": len(after_step),
        "examples": [f"{s} {by_seq.get(s, '')[:160]}" for s in session[:12]],
    }


def seqnum_from_od(text: str) -> int | None:
    """The kernel seqnum journald's cursor file holds, from ``od -An -t u8``
    of ``/run/systemd/journal/kernel-seqnum`` (one unsigned 64-bit number)."""
    words = text.split()
    if len(words) != 1 or not words[0].isdigit():
        return None
    return int(words[0])


def unconfined(label: str) -> bool:
    """Whether a process label (``/proc/<pid>/attr/current``, ``ps -o
    label``) is one of the unconfined domains NAILS must run in."""
    return context_type(label.strip().rstrip("\x00")) in (
        "unconfined_t",
        "unconfined_service_t",
    )
