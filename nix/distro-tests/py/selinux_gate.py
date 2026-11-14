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
- the denials (:func:`parse_avc`), who they belong to (:func:`source`) and
  what makes two of them the same (:func:`signature`);
- a phase between two markers (:func:`phase`): which of its denials are new,
  that is NAILS's own, or not among those of the run's plain boots and plain
  soft-reboots, nor a race of the image's own (:data:`IMAGE_RACES`);
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

# Every message reaches the kernel log and no rate limit drops one.
KMSG_LIMITS = "sysctl -w kernel.printk_ratelimit=0 kernel.printk_devkmsg=on"

# The image's own races: a denial with this signature is the image's whatever
# phase it falls in. agetty reads the console-login helper's issue file while
# that helper's NetworkManager dispatcher replaces it, at some boots of either
# root with or without NAILS (the D-SEL-EXP cells saw it in every mechanism's
# cells, and at plain boots).
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
SUPPRESSED = ("callbacks suppressed", "suppressed due to ratelimiting", "backlog")


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


def denials(
    records: Iterable[Mapping[str, Any]], first: int | None, last: int | None
) -> list[dict[str, Any]]:
    """The denials between the records ``first`` and ``last`` (exclusive),
    each with its sequence number, source and signature."""
    found = []
    for record in sorted(records, key=lambda r: int(r["seq"])):
        seq = int(record["seq"])
        if (first is not None and seq <= first) or (last is not None and seq >= last):
            continue
        avc = parse_avc(str(record["msg"]))
        if avc is None:
            continue
        avc["seq"] = seq
        avc["source"] = source(avc)
        avc["signature"] = signature(avc)
        found.append(avc)
    return found


def phase(
    records: Iterable[Mapping[str, Any]],
    first: int | None,
    last: int | None,
    baseline: Iterable[str] = (),
) -> dict[str, Any]:
    """The denials of the phase between the records ``first`` and ``last``.

    A denial is new when it is NAILS's own, or when its signature is neither
    in ``baseline`` (the denials of the run's boots and plain soft-reboots
    before NAILS ran, and of its plain soft-reboots after) nor one of the
    image's own races. The result also names the lines that say the log
    dropped something, and the policy loads."""
    records = list(records)
    known = set(baseline)
    found = denials(records, first, last)
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
