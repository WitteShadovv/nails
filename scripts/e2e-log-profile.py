#!/usr/bin/env python3
"""Break down where E2E VM-test wall time goes, from `nix build -L` logs.

The NixOS test driver prints no wall-clock timestamps, but every nested driver
action ends with a `(finished: <action>, in <N> seconds)` line. This script
rebuilds the nesting of those actions per test and attributes each top-level
action (one whose parent is a subtest or the script itself) to a category:

  boot      a start/wait that contains "waiting for the VM to finish booting"
            (VM boot up to the backdoor shell, plus the wait for the unit)
  poweroff  waiting for the VM to power off / shutdown / crash
  poll      wait_until_succeeds/fails, wait_for_unit (non-boot), wait_for_file,
            wait_for_console_text, wait_for_x/window/text, tty waits
  nails     a must-succeed/must-fail command that runs the nails binary
  sleep     an in-guest `sleep N` command
  guest     every other logged guest command
  forensic  host-side disk imaging and scanning, from the timing lines that
            disk_forensics.py prints (logs from before those lines existed
            count this work as unlogged)
  unlogged  script time no driver action accounts for: host-side Python
            (disk imaging and scanning, screenshots), `time.sleep`, and
            `machine.execute` calls, which the driver does not log

Usage:
  e2e-log-profile.py LOG [LOG...]            # table of the top tests
  e2e-log-profile.py --json LOG [LOG...]     # one JSON object per test
  e2e-log-profile.py --top 25 --markdown LOG...

When a test appears in several logs, the last log given wins, so list older
runs first.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

PREFIX = re.compile(r"^vm-test-run-(?P<test>[A-Za-z0-9._+-]+)> ?(?P<body>.*)$")
FINISHED = re.compile(
    r"^(?:(?P<who>[\w-]+): )?\(finished: (?P<msg>.*?)"
    r"(?:, in (?P<sec>[\d.]+) seconds\))?$"
)
# Printed by nix/e2e-tests/lib/disk_forensics.py around host-side imaging and
# scanning, which the driver itself does not time.
FORENSIC = re.compile(r"^disk_forensics: (?P<what>.+) took (?P<sec>[\d.]+) seconds$")
TAIL = re.compile(r", in (?P<sec>[\d.]+) seconds\)$")
START = re.compile(r"^(?:(?P<who>[\w-]+): )?(?P<msg>.+)$")

CATEGORIES = (
    "boot",
    "poweroff",
    "poll",
    "nails",
    "sleep",
    "guest",
    "forensic",
    "unlogged",
)

POLL_PREFIXES = (
    "waiting for success",
    "waiting for failure",
    "waiting for unit",
    "waiting for file",
    "waiting for TCP port",
    "waiting for the X11 server",
    "waiting for a window",
    "waiting up to",
)
POWEROFF_MARKERS = ("power off", "shutting down", "crash", "container to power off")
SLEEP = re.compile(r"^must (?:succeed|fail): sleep [\d.]+\s*$")
NAILS = re.compile(r"(^|[\s/'\"])nails(\s|$)")


def split_tests(paths: list[Path]) -> dict[str, list[str]]:
    """Return the log lines of each test, last log wins."""
    tests: dict[str, list[str]] = {}
    for path in paths:
        per_file: dict[str, list[str]] = defaultdict(list)
        with path.open(errors="replace") as handle:
            for line in handle:
                match = PREFIX.match(line.rstrip("\n"))
                if match:
                    per_file[match["test"]].append(match["body"])
        for name, lines in per_file.items():
            if any("run the VM test script" in ln for ln in lines):
                tests[name] = lines
    return tests


def parse_blocks(lines: list[str]) -> list[dict]:
    """Reconstruct finished blocks, each with a unique id and its parent id."""
    # Pass 1: count the first line of every finished block, so that plain log
    # lines (which never finish) are not mistaken for block starts.
    finished_keys: Counter[str] = Counter()
    for line in lines:
        match = FINISHED.match(line)
        if match:
            finished_keys[(match["who"] or "") + "|" + match["msg"]] += 1

    blocks: list[dict] = []
    stack: list[tuple[str, int]] = []
    next_id = 0
    pending: dict | None = None  # a finished line whose seconds come later
    for line in lines:
        if pending is not None:
            tail = TAIL.search(line)
            if tail:
                pending["seconds"] = float(tail["sec"])
                blocks.append(pending)
                pending = None
            continue
        fin = FINISHED.match(line)
        if fin:
            key = (fin["who"] or "") + "|" + fin["msg"]
            block_id = -1
            if any(k == key for k, _ in stack):
                while stack and stack[-1][0] != key:
                    stack.pop()
                block_id = stack.pop()[1]
            parent = stack[-1][1] if stack else None
            block = {"id": block_id, "parent": parent, "msg": fin["msg"]}
            if fin["sec"] is not None:
                block["seconds"] = float(fin["sec"])
                blocks.append(block)
            else:
                pending = block
            continue
        start = START.match(line)
        if start:
            key = (start["who"] or "") + "|" + start["msg"]
            if finished_keys.get(key, 0) > 0:
                finished_keys[key] -= 1
                stack.append((key, next_id))
                next_id += 1
    return blocks


def categorise(msg: str, contains_boot: bool) -> str:
    if contains_boot or msg.startswith("waiting for the VM to finish booting"):
        return "boot"
    lowered = msg.lower()
    if any(marker in lowered for marker in POWEROFF_MARKERS):
        return "poweroff"
    if msg.startswith(POLL_PREFIXES) or " to appear on " in msg:
        return "poll"
    if SLEEP.match(msg):
        return "sleep"
    if msg.startswith(("must succeed", "must fail")) and NAILS.search(msg):
        return "nails"
    return "guest"


def profile(name: str, lines: list[str]) -> dict:
    blocks = parse_blocks(lines)
    total = next(
        (b["seconds"] for b in blocks if b["msg"] == "run the VM test script"), 0.0
    )
    # Depth of the "run the VM test script" block is 0; subtests are depth 1.
    # A top-level action is the first non-subtest block on its path.
    out = dict.fromkeys(CATEGORIES, 0.0)
    boots = sum(1 for ln in lines if re.match(r"^[\w-]+: starting vm$", ln))
    sleeps = 0

    def is_frame(msg: str) -> bool:
        return msg in ("run the VM test script", "cleanup") or msg.startswith(
            ("start all VLans", "subtest: ")
        )

    by_id = {b["id"]: b for b in blocks if b["id"] >= 0}
    booting = {
        b["parent"]
        for b in blocks
        if b["msg"].startswith("waiting for the VM to finish booting")
    }
    for block in blocks:
        msg = block["msg"]
        if is_frame(msg):
            continue
        parent = by_id.get(block["parent"]) if block["parent"] is not None else None
        if parent is not None and not is_frame(parent["msg"]):
            continue  # nested inside another action; counted with it
        cat = categorise(msg, block["id"] in booting)
        out[cat] += block["seconds"]
        if cat == "sleep":
            sleeps += 1
    out["forensic"] = sum(
        float(m["sec"]) for m in map(FORENSIC.match, lines) if m is not None
    )
    logged = sum(out[c] for c in CATEGORIES if c != "unlogged")
    out["unlogged"] = max(0.0, total - logged)
    return {
        "test": name,
        "total": round(total, 2),
        "boots": boots,
        "reboots": max(0, boots - 1),
        "guest_sleeps": sleeps,
        **{k: round(v, 2) for k, v in out.items()},
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("logs", nargs="+", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--markdown", action="store_true")
    parser.add_argument("--top", type=int, default=25)
    args = parser.parse_args(argv)

    rows = [profile(n, ls) for n, ls in split_tests(args.logs).items()]
    rows.sort(key=lambda r: r["total"], reverse=True)
    if args.json:
        for row in rows:
            print(json.dumps(row))
        return 0

    cols = ["total", "boots", *CATEGORIES]
    sep = " | " if args.markdown else "  "
    header = ["test", *cols]
    if args.markdown:
        print("| " + " | ".join(header) + " |")
        print("|" + "---|" * len(header))
    else:
        print(sep.join(f"{h:>9}" if h != "test" else f"{h:<40}" for h in header))
    for row in rows[: args.top]:
        cells = [row["test"]] + [
            f"{row[c]:.0f}" if isinstance(row[c], float) else str(row[c]) for c in cols
        ]
        if args.markdown:
            print("| " + " | ".join(cells) + " |")
        else:
            print(sep.join(f"{c:>9}" if i else f"{c:<40}" for i, c in enumerate(cells)))
    totals = {c: sum(r[c] for r in rows) for c in cols}
    cells = [f"ALL ({len(rows)} tests)"] + [f"{totals[c]:.0f}" for c in cols]
    if args.markdown:
        print("| " + " | ".join(cells) + " |")
    else:
        print(sep.join(f"{c:>9}" if i else f"{c:<40}" for i, c in enumerate(cells)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
