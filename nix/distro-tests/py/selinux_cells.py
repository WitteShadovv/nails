"""Reading the kernel log of an SELinux cell run (research branch only).

A cell (``nix/distro-tests/cells.nix``) runs NAILS on an enforcing Fedora
image with one way of starting the RAM copy of the binary, and reads the
kernel log (``/dev/kmsg``) at every step. This module holds the pure parts:
the reader the guest runs, the parsing of its records, the markers the cell
writes, the AVC denials and their attribution, and the trace lines the
research build of NAILS appends. Nothing here imports Nix or the test driver.
"""

from __future__ import annotations

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

# The prefix of every marker line a cell writes to /dev/kmsg.
MARK = "DSXMARK"

_RECORD = re.compile(r"^(\d+),(\d+),(\d+),([^;]*);(.*)$")
_FIELD = re.compile(r"(\w+)=(\"[^\"]*\"|'[^']*'|\S+)")
_PERMS = re.compile(r"\{ ([^}]*) \}")


def kmsg_command(first: int) -> str:
    """The guest command that prints the records from ``first`` on."""
    return f"python3 - {int(first)} <<'DSXEOF'\n{KMSG_READER}\nDSXEOF\n"


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


def trace_lines(text: str) -> list[dict[str, str]]:
    """The lines the research build appends at every start of the binary."""
    lines = []
    for line in text.splitlines():
        if not line.startswith("uptime="):
            continue
        head, _, args = line.partition(" args=")
        entry = dict(part.split("=", 1) for part in head.split() if "=" in part)
        entry["args"] = args
        lines.append(entry)
    return lines


def nails_pids(trace: Iterable[Mapping[str, str]]) -> dict[str, str]:
    """Each traced process number with the first argument it ran."""
    pids = {}
    for entry in trace:
        argument = entry.get("args", "").split(" ")
        verb = next((word for word in argument if not word.startswith("-")), "")
        pids[entry.get("pid", "")] = verb
    return pids


def source(avc: Mapping[str, Any], pids: Mapping[str, str]) -> str:
    """Who an AVC belongs to: the cell's own instrumentation, NAILS (by the
    traced process, the RAM copy's name or a NAILS path), PID 1, or other."""
    where = f"{avc.get('name', '')} {avc.get('path', '')}"
    if "dsx" in where:
        return "instrumentation"
    comm = str(avc.get("comm", ""))
    if (
        str(avc.get("pid", "")) in pids
        or comm in ("control", "nails")
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


SUPPRESSED = ("callbacks suppressed", "suppressed due to ratelimiting", "backlog")


def phase(
    records: Iterable[Mapping[str, Any]],
    first: int | None,
    last: int | None,
    control: Iterable[str] = (),
    pids: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """The denials between the records ``first`` and ``last`` (exclusive):
    each with its source, how many there are, how many share no signature with
    ``control`` (the denials of a plain soft-reboot), and the lines that say
    the log dropped something."""
    pids = pids or {}
    known = set(control)
    inside = [
        r
        for r in sorted(records, key=lambda r: int(r["seq"]))
        if (first is None or int(r["seq"]) > first)
        and (last is None or int(r["seq"]) < last)
    ]
    avcs = []
    for record in inside:
        avc = parse_avc(str(record["msg"]))
        if avc is None:
            continue
        avc["seq"] = int(record["seq"])
        avc["source"] = source(avc, pids)
        avc["verb"] = pids.get(str(avc["pid"]), "")
        avc["signature"] = signature(avc)
        avc["new"] = (
            avc["signature"] not in known and avc["source"] != "instrumentation"
        )
        avcs.append(avc)
    counts: dict[str, int] = {}
    for avc in avcs:
        counts[avc["source"]] = counts.get(avc["source"], 0) + 1
    return {
        "first": first,
        "last": last,
        "records": len(inside),
        "avcs": avcs,
        "total": len(avcs),
        "counted": sum(1 for a in avcs if a["source"] != "instrumentation"),
        "new": sum(1 for a in avcs if a["new"]),
        "bySource": counts,
        "signatures": sorted({a["signature"] for a in avcs}),
        "suppressed": [
            str(r["msg"]) for r in inside if any(s in str(r["msg"]) for s in SUPPRESSED)
        ],
        "policy": [
            str(r["msg"])
            for r in inside
            if "SELinux policy" in str(r["msg"]) or "Relabel" in str(r["msg"])
        ],
    }
