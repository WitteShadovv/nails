"""The host side of the access-time scenario: which reads of the decoy disk
NAILS made.

The scenario (nix/distro-tests/tests/access-times.nix) ages the decoy disk
before each phase (``atime_walk.py age``): every entry's access time is set two
days back, which also sets its change time to then. On a root mounted
``relatime`` the next read of an entry therefore updates its access time, and
later reads of it do not. After the phase it lists the entries whose access
time is later than a reference taken after the aging (``atime_walk.py list``).

A *read* is an entry whose access time is later than the reference while its
change time is not (:func:`reads_since`): something opened, executed, listed or
followed it and changed nothing about it. An entry written, created or
renamed in the phase changes its change time too and is left out: the
scenario judges reads.

Three kinds of phase are judged:

- ``nails check`` on an idle decoy. Every read in it is a finding.
- A **control**: a plain ``systemctl soft-reboot`` of the decoy into itself,
  started with no read of the decoy's own (the scenario's ``noatime-run``).
  Its reads before the new userspace's start are what the decoy's own stop
  reads, the ones after it what the decoy's own start reads
  (:func:`control_of`).
- A **flow**: an activation, a session and the way back. A read before the
  way back started (the *way in*: the activation, the decoy's stop and the
  entry step) is a finding unless a control's stop read the same path; a read
  after it (the *way back*: the step that runs in the hidden root, the decoy's
  start and NAILS' pieces there) is a finding unless a control's stop or start
  read it. The hidden session reads the decoy through a read-only lower, which
  updates no access time, so no read falls between the two.

A path the decoy's own soft-reboot reads at the same point is no finding:
NAILS reading it too leaves nothing a plain switch does not. Everything else
is: a program NAILS starts, a file, a directory or a link it reads, a module
the kernel loads for it, a unit file the service manager loads because NAILS
asked about it.

A finding that is a symbolic link is of a kind of its own (:func:`split_links`):
NAILS reads its own files with ``O_NOATIME`` and starts its programs with every
mount ``noatime``, but a lookup of its own still updates the access time of
each link it follows or reads on the decoy, which the operator guide names.
So is a listing of udevd's rule and link directories (:func:`split_udevd`):
udevd lists them whenever it handles a uevent, every three seconds at most, to
see whether one changed, so their access times follow the machine's own
uevents. The scenario lists both kinds and fails on every other finding.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

#: Where a finding was read.
CHECK = "check"
WAY_IN = "way in"
WAY_BACK = "way back"


@dataclass(frozen=True)
class Stamp:
    """One entry of a listing: its path, its times in nanoseconds since the
    epoch and its kind (``f`` file, ``d`` directory, ``l`` link, ``o`` other)."""

    path: str
    atime: int
    ctime: int
    mtime: int
    kind: str


@dataclass(frozen=True)
class Listing:
    """What ``atime_walk.py list`` printed: how many entries it walked and the
    ones whose access time is later than ``ref``."""

    walked: int
    ref: int
    stamps: tuple[Stamp, ...]


def parse_listing(text: str) -> Listing:
    """Read the JSON ``atime_walk.py list`` printed."""
    data = json.loads(text)
    stamps = tuple(
        Stamp(
            path=str(path),
            atime=int(atime),
            ctime=int(ctime),
            mtime=int(mtime),
            kind=str(kind),
        )
        for path, atime, ctime, mtime, kind in data["entries"]
    )
    return Listing(walked=int(data["walked"]), ref=int(data["ref"]), stamps=stamps)


def parse_epoch_ns(text: str) -> int:
    """Nanoseconds since the epoch from bash's ``$EPOCHREALTIME`` (seconds and
    microseconds, the separator being the locale's decimal point)."""
    seconds, _, micros = text.strip().replace(",", ".").partition(".")
    return int(seconds) * 1_000_000_000 + int((micros + "000000")[:6]) * 1_000


def parse_busctl_times(text: str) -> list[int]:
    """Nanoseconds since the epoch from ``busctl get-property`` of microsecond
    timestamps (``t 1731700000123456`` per line)."""
    values = []
    for line in text.splitlines():
        kind, _, value = line.strip().partition(" ")
        if kind == "t" and value.strip().isdigit():
            values.append(int(value.strip()) * 1_000)
    return values


def reads_since(listing: Listing) -> list[Stamp]:
    """The entries read and not changed since the listing's reference."""
    return [
        s for s in listing.stamps if s.atime > listing.ref and s.ctime <= listing.ref
    ]


@dataclass(frozen=True)
class Control:
    """The paths a plain soft-reboot read before its new userspace started
    (its stop) and after (its start)."""

    stop: frozenset[str]
    start: frozenset[str]


def control_of(reads: Iterable[Stamp], userspace: int) -> Control:
    """Split a control's reads at its new userspace's start."""
    reads = list(reads)
    return Control(
        stop=frozenset(s.path for s in reads if s.atime < userspace),
        start=frozenset(s.path for s in reads if s.atime >= userspace),
    )


def merge(controls: Sequence[Control]) -> Control:
    """The paths any of the controls read at each point."""
    return Control(
        stop=frozenset().union(*(c.stop for c in controls)),
        start=frozenset().union(*(c.start for c in controls)),
    )


@dataclass(frozen=True)
class Finding:
    """A read of the decoy disk that no plain soft-reboot explains."""

    window: str
    path: str
    atime: int
    kind: str


def judge_check(reads: Iterable[Stamp]) -> list[Finding]:
    """Every read in the window of ``nails check`` is a finding."""
    return [Finding(CHECK, s.path, s.atime, s.kind) for s in reads]


def judge_flow(
    reads: Iterable[Stamp], way_back: int, control: Control
) -> list[Finding]:
    """The reads of a flow that the controls do not explain (see the module
    docs). ``way_back`` is when the way back was asked for."""
    findings = []
    for s in reads:
        if s.atime < way_back:
            if s.path not in control.stop:
                findings.append(Finding(WAY_IN, s.path, s.atime, s.kind))
        elif s.path not in control.stop and s.path not in control.start:
            findings.append(Finding(WAY_BACK, s.path, s.atime, s.kind))
    return sorted(findings, key=lambda f: (f.atime, f.path))


def split_links(findings: Iterable[Finding]) -> tuple[list[Finding], list[Finding]]:
    """The findings that are not symbolic links, and the ones that are."""
    others: list[Finding] = []
    links: list[Finding] = []
    for f in findings:
        (links if f.kind == "l" else others).append(f)
    return others, links


# The directories udevd lists to see whether its rules (``RULES_DIRS``) or its
# link files (``NETWORK_DIRS``, which networkd reads too) changed, as they are
# on a disk: on a merged /usr, and below /lib where it is not merged.
UDEVD_DIRS = frozenset(
    f"{prefix}/{below}"
    for prefix in ("/etc", "/usr/local/lib", "/usr/lib", "/lib")
    for below in ("udev/rules.d", "systemd/network")
)


def split_udevd(findings: Iterable[Finding]) -> tuple[list[Finding], list[Finding]]:
    """The findings that are not udevd's listing of its rule and link
    directories, and the ones that are: the directories themselves, read as
    directories. A file below one read is a finding as any other."""
    others: list[Finding] = []
    udevd: list[Finding] = []
    for f in findings:
        (udevd if f.kind == "d" and f.path in UDEVD_DIRS else others).append(f)
    return others, udevd


def describe(findings: Sequence[Finding], marks: Sequence[tuple[str, int]] = ()) -> str:
    """The findings one per line, each with the last of ``marks`` (label and
    time) at or before it, so a reader sees which step made it."""
    lines = []
    ordered = sorted(marks, key=lambda mark: mark[1])
    for f in findings:
        before = [label for label, at in ordered if at <= f.atime]
        after = before[-1] if before else "-"
        lines.append(f"{f.window}: {f.path} ({f.kind}) at {f.atime} after {after}")
    return "\n".join(lines)


def as_json(findings: Sequence[Finding]) -> list[dict[str, object]]:
    """The findings as plain data for the scenario's report."""
    return [
        {"window": f.window, "path": f.path, "atime": f.atime, "kind": f.kind}
        for f in findings
    ]
