"""Host-side readers for login, boot and seed records on a decoy disk image.

These parsers answer one question for the cross-distro login- and boot-record
test: *what rows and bytes does a NAILS session add to or change on the decoy
disk, measured against a power-cycle control?* They read the records as data --
SQLite rows and the fields of the binary account files -- not as opaque blobs,
so an assertion can name the row that gives a session away (for example wtmpdb's
``soft-reboot`` boot row, or a boot record stamped before the shutdown that
precedes it) instead of merely reporting that a file's bytes or mtime changed.

Like :mod:`disk_forensics`, this module is plain Python with no Nix and no VM:
its parsers are locked by ``tests/test_records.py`` against fixtures the test
builds itself, so a silent parser regression cannot turn a real trace into a
false pass. A forensic VM test extracts the record files from a decoy disk image
(``disk_forensics`` already carves files out of an ext4 partition with
``debugfs rdump``) and hands their bytes to the readers here.

Record formats read:

* **wtmpdb** (Debian 13 ``/var/log/wtmp.db``) -- SQLite. The boot writer names
  the boot row ``soft-reboot`` when systemd reports a soft-reboot, or when it
  cannot ask and the kernel has been up for more than five minutes (wtmpdb
  ``src/wtmpdb.c`` ``main_boot``), which ordinary use never writes.
* **lastlog2** (``/var/lib/lastlog/lastlog2.db``) -- SQLite, one row per user's
  last login.
* **classic wtmp / btmp** (``/var/log/wtmp``, ``/var/log/btmp``) -- an array of
  glibc ``struct utmpx`` (384 bytes each on x86_64): boot, shutdown and login
  records.
* **classic lastlog** (``/var/log/lastlog``) -- a sparse file of fixed 292-byte
  ``struct lastlog`` slots indexed by UID.
* **systemd random seed** (``/var/lib/systemd/random-seed``) -- opaque bytes,
  summarised by length and digest so a change is visible without printing the
  secret.

Every reader returns plain dicts/lists so a test can print them verbatim into an
evidence log and diff two captures field by field.
"""

from __future__ import annotations

import hashlib
import sqlite3
import struct
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

# --- classic utmpx / lastlog on-disk layout (x86_64 glibc) ------------------

# glibc `struct utmpx` is 384 bytes on every Linux architecture NAILS targets
# (the layout is fixed by the glibc ABI, not the word size): a short type, a
# pid, the line/id/user/host strings, an exit struct, a session int, a 32-bit
# timeval, a 4-word v6 address and padding. wtmp and btmp are arrays of it.
UTMP_RECORD_SIZE = 384
# ``<h2x...``: ut_type is a short, then two pad bytes align ut_pid (a 32-bit
# int) -- glibc keeps that padding on x86_64. ut_session, ut_tv and ut_addr_v6
# are all 32-bit fields regardless of word size, so the record is 384 bytes.
_UTMP_STRUCT = struct.Struct("<h2xi32s4s32s256shhiii4i20s")
assert _UTMP_STRUCT.size == UTMP_RECORD_SIZE, _UTMP_STRUCT.size

# `ut_type` values from <utmpx.h>; the names forensic readers care about.
UTMP_TYPES = {
    0: "EMPTY",
    1: "RUN_LVL",
    2: "BOOT_TIME",
    3: "NEW_TIME",
    4: "OLD_TIME",
    5: "INIT_PROCESS",
    6: "LOGIN_PROCESS",
    7: "USER_PROCESS",
    8: "DEAD_PROCESS",
    9: "ACCOUNTING",
}

# glibc `struct lastlog`: a 32-bit time, a 32-char line and a 256-char host.
LASTLOG_RECORD_SIZE = 292
_LASTLOG_STRUCT = struct.Struct("<i32s256s")
assert _LASTLOG_STRUCT.size == LASTLOG_RECORD_SIZE, _LASTLOG_STRUCT.size


def _cstr(raw: bytes) -> str:
    """Decode a fixed-width NUL-padded C string field, 1:1, stopping at NUL."""
    return raw.split(b"\x00", 1)[0].decode("latin-1")


# --- binary readers ---------------------------------------------------------


def parse_utmp(data: bytes) -> list[dict[str, object]]:
    """Parse wtmp/btmp bytes into a list of records, in file order.

    A trailing partial record (a torn write) is ignored rather than raised on,
    so a live-imaged file never aborts the scan. ``EMPTY`` records are kept:
    their presence and position are themselves evidence.
    """
    records: list[dict[str, object]] = []
    count = len(data) // UTMP_RECORD_SIZE
    for index in range(count):
        chunk = data[index * UTMP_RECORD_SIZE : (index + 1) * UTMP_RECORD_SIZE]
        (
            ut_type,
            ut_pid,
            ut_line,
            ut_id,
            ut_user,
            ut_host,
            _e_term,
            _e_exit,
            ut_session,
            tv_sec,
            tv_usec,
            _a0,
            _a1,
            _a2,
            _a3,
            _unused,
        ) = _UTMP_STRUCT.unpack(chunk)
        records.append(
            {
                "type": UTMP_TYPES.get(ut_type, f"UNKNOWN({ut_type})"),
                "pid": ut_pid,
                "line": _cstr(ut_line),
                "id": _cstr(ut_id),
                "user": _cstr(ut_user),
                "host": _cstr(ut_host),
                "session": ut_session,
                "tv_sec": tv_sec,
                "tv_usec": tv_usec,
            }
        )
    return records


def read_utmp(path: str | Path) -> list[dict[str, object]]:
    """Read and parse a classic wtmp/btmp file; an absent file is no records."""
    file = Path(path)
    if not file.is_file():
        return []
    return parse_utmp(file.read_bytes())


def parse_lastlog(data: bytes) -> dict[int, dict[str, object]]:
    """Parse a classic lastlog file into ``{uid: record}``, empty slots dropped.

    lastlog is sparse and indexed by UID; a slot with a zero time and empty
    line/host is "never logged in" and is left out, so the result names only the
    UIDs that actually carry a login time.
    """
    out: dict[int, dict[str, object]] = {}
    count = len(data) // LASTLOG_RECORD_SIZE
    for uid in range(count):
        chunk = data[uid * LASTLOG_RECORD_SIZE : (uid + 1) * LASTLOG_RECORD_SIZE]
        ll_time, ll_line, ll_host = _LASTLOG_STRUCT.unpack(chunk)
        line, host = _cstr(ll_line), _cstr(ll_host)
        if ll_time == 0 and not line and not host:
            continue
        out[uid] = {"uid": uid, "time": ll_time, "line": line, "host": host}
    return out


def read_lastlog(path: str | Path) -> dict[int, dict[str, object]]:
    """Read and parse a classic lastlog file; an absent file is no records."""
    file = Path(path)
    if not file.is_file():
        return {}
    return parse_lastlog(file.read_bytes())


# --- SQLite readers (wtmpdb, lastlog2) --------------------------------------


def _read_sqlite_tables(path: str | Path) -> dict[str, list[dict[str, object]]]:
    """Dump every user table of a SQLite file as ``{table: [row-dicts]}``.

    Reading generically -- every column of every table -- keeps the parser from
    silently missing a row because an upstream schema gained or renamed a
    column; the test and the evidence log see exactly what the database holds.
    The file is opened read-only through a temp copy so a WAL or a lock on a
    freshly imaged database cannot block or mutate it.
    """
    src = Path(path)
    if not src.is_file() or src.stat().st_size == 0:
        return {}
    with tempfile.TemporaryDirectory(prefix="nails-records-") as tmp:
        copy = Path(tmp) / "db.sqlite"
        copy.write_bytes(src.read_bytes())
        con = sqlite3.connect(copy)
        try:
            con.row_factory = sqlite3.Row
            tables = [
                row[0]
                for row in con.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
                )
            ]
            out: dict[str, list[dict[str, object]]] = {}
            for table in tables:
                # The table name comes from sqlite_master, never from untrusted
                # input, so quoting it is enough; parameters cannot name a table.
                rows = con.execute(f'SELECT * FROM "{table}"').fetchall()
                out[table] = [dict(row) for row in rows]
            return out
        finally:
            con.close()


def read_wtmpdb(path: str | Path) -> list[dict[str, object]]:
    """Read wtmpdb's login/boot rows (the ``wtmp`` table) as a list of dicts.

    Falls back to concatenating every table if upstream ever renames ``wtmp``,
    so a schema change degrades to "all rows" rather than to silence.
    """
    tables = _read_sqlite_tables(path)
    if "wtmp" in tables:
        return tables["wtmp"]
    return [row for rows in tables.values() for row in rows]


def read_lastlog2(path: str | Path) -> list[dict[str, object]]:
    """Read lastlog2's rows (the ``Lastlog2`` table) as a list of dicts."""
    tables = _read_sqlite_tables(path)
    for name in ("Lastlog2", "lastlog2", "Lastlog"):
        if name in tables:
            return tables[name]
    return [row for rows in tables.values() for row in rows]


# --- random seed ------------------------------------------------------------


def seed_digest(path: str | Path) -> dict[str, object] | None:
    """Summarise ``/var/lib/systemd/random-seed`` without exposing its bytes.

    Returns the length and a SHA-256 so two captures can be compared (did the
    session change the seed, and does it differ from a plain reboot's change?)
    while the secret itself never reaches a log. ``None`` for an absent file.
    """
    file = Path(path)
    if not file.is_file():
        return None
    data = file.read_bytes()
    return {"length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


# --- diffing two captures ----------------------------------------------------

# How two rows are compared: ignore the fields that always move (row id, exact
# timestamps) so the diff shows the rows a session adds or whose identity
# changes, not the clock. Timestamps are still carried in the row for the log.
_UTMP_IDENTITY = ("type", "line", "id", "user", "host")
_VOLATILE_SQL = {"ID", "id", "rowid"}


def _utmp_identity(row: Mapping[str, object]) -> tuple[object, ...]:
    return tuple(row.get(key) for key in _UTMP_IDENTITY)


def utmp_added(
    control: Sequence[Mapping[str, object]],
    session: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Records present in ``session`` beyond those in ``control``, by identity.

    Multiplicity matters -- two boot records are not one -- so this subtracts
    per-identity counts rather than treating the records as a set.
    """
    seen: dict[tuple[object, ...], int] = {}
    for row in control:
        seen[_utmp_identity(row)] = seen.get(_utmp_identity(row), 0) + 1
    extra: list[dict[str, object]] = []
    for row in session:
        key = _utmp_identity(row)
        if seen.get(key, 0) > 0:
            seen[key] -= 1
        else:
            extra.append(dict(row))
    return extra


def sql_rows_added(
    control: Sequence[Mapping[str, object]],
    session: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """SQLite rows in ``session`` not in ``control``, ignoring volatile columns.

    Two rows are "the same" when every column except the autoincrement id and
    exact login/logout timestamps matches, so the diff reports a genuinely new
    login or boot row and not the same row with a later clock.
    """

    def identity(row: Mapping[str, object]) -> tuple[tuple[str, object], ...]:
        return tuple(
            sorted(
                (key, value)
                for key, value in row.items()
                if key not in _VOLATILE_SQL and key not in ("Login", "Logout", "Time")
            )
        )

    seen: dict[tuple[tuple[str, object], ...], int] = {}
    for row in control:
        seen[identity(row)] = seen.get(identity(row), 0) + 1
    extra: list[dict[str, object]] = []
    for row in session:
        key = identity(row)
        if seen.get(key, 0) > 0:
            seen[key] -= 1
        else:
            extra.append(dict(row))
    return extra


def row_mentions(row: Mapping[str, object], needle: str) -> bool:
    """True if any field of a row contains ``needle`` (case-insensitive)."""
    low = needle.lower()
    return any(low in str(value).lower() for value in row.values())


def has_soft_reboot_boot_row(rows: Iterable[Mapping[str, object]]) -> bool:
    """Whether any wtmpdb row names a ``soft-reboot`` -- the predicted trace."""
    return any(row_mentions(row, "soft-reboot") for row in rows)


def boot_record_times(records: Sequence[Mapping[str, object]]) -> list[int]:
    """The ``tv_sec`` of each classic-wtmp boot record, in file order."""

    def tv_sec(row: Mapping[str, object]) -> int:
        value = row.get("tv_sec", 0)
        return value if isinstance(value, int) else 0

    return [tv_sec(r) for r in records if r.get("type") == "BOOT_TIME"]


def last_boot_is_backdated(records: Sequence[Mapping[str, object]]) -> bool:
    """Whether a classic-wtmp file's last boot record is stamped before an
    event that precedes it.

    An ordinary power cycle writes its boot record as the newest event, so no
    earlier record carries a later time. A soft-reboot into a decoy on a service
    manager that keeps the userspace start time across the switch leaves a boot
    record stamped with the decoy's first boot time, which falls before the
    shutdown that precedes it: that is the trace this reports. ``False`` when
    there is no boot record or nothing precedes the last one.
    """

    def tv_sec(row: Mapping[str, object]) -> int:
        value = row.get("tv_sec", 0)
        return value if isinstance(value, int) else 0

    boots = [i for i, r in enumerate(records) if r.get("type") == "BOOT_TIME"]
    if not boots:
        return False
    last = boots[-1]
    earlier = [tv_sec(r) for r in records[:last]]
    return bool(earlier) and tv_sec(records[last]) < max(earlier)


def last_boot_record(
    records: Sequence[Mapping[str, object]],
) -> dict[str, object] | None:
    """The last classic-wtmp boot record (``BOOT_TIME``) in file order, or ``None``.

    The way back's boot record is the newest boot the decoy carries, so a test
    reads this one to check its stamped time (seconds and microseconds) and its
    identity against a power-cycle reference's own boot record.
    """
    boots = [r for r in records if r.get("type") == "BOOT_TIME"]
    return dict(boots[-1]) if boots else None


# --- one capture of every record on one platform ----------------------------


@dataclass
class RecordCapture:
    """Every login/boot/seed record read from one decoy disk image (or guest).

    A platform populates only the record files it ships (NixOS has no wtmpdb;
    Debian's cloud image has no classic wtmp until the packages are installed),
    so absent files are simply empty collections, and the capture still prints
    and diffs cleanly.
    """

    label: str
    wtmpdb: list[dict[str, object]] = field(default_factory=list)
    lastlog2: list[dict[str, object]] = field(default_factory=list)
    wtmp: list[dict[str, object]] = field(default_factory=list)
    btmp: list[dict[str, object]] = field(default_factory=list)
    lastlog: dict[int, dict[str, object]] = field(default_factory=dict)
    seed: dict[str, object] | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "wtmpdb": self.wtmpdb,
            "lastlog2": self.lastlog2,
            "wtmp": self.wtmp,
            "btmp": self.btmp,
            "lastlog": {str(uid): rec for uid, rec in sorted(self.lastlog.items())},
            "seed": self.seed,
        }


# Default on-disk locations, relative to a carved filesystem root (no leading
# slash, matching how `debugfs rdump /` lays a tree out). A platform overrides
# the paths it keeps elsewhere.
DEFAULT_PATHS = {
    "wtmpdb": "var/log/wtmp.db",
    "lastlog2": "var/lib/lastlog/lastlog2.db",
    "wtmp": "var/log/wtmp",
    "btmp": "var/log/btmp",
    "lastlog": "var/log/lastlog",
    "seed": "var/lib/systemd/random-seed",
}


def capture_from_tree(
    label: str,
    root: str | Path,
    paths: Mapping[str, str] = DEFAULT_PATHS,
) -> RecordCapture:
    """Read every record file that exists under a carved filesystem ``root``.

    ``root`` is a directory tree extracted from the decoy image (for example by
    ``disk_forensics`` carving ``/`` with ``debugfs rdump``); each entry of
    ``paths`` is tried and contributes to the capture only if the file is there.
    """
    base = Path(root)
    return RecordCapture(
        label=label,
        wtmpdb=read_wtmpdb(base / paths["wtmpdb"]),
        lastlog2=read_lastlog2(base / paths["lastlog2"]),
        wtmp=read_utmp(base / paths["wtmp"]),
        btmp=read_utmp(base / paths["btmp"]),
        lastlog=read_lastlog(base / paths["lastlog"]),
        seed=seed_digest(base / paths["seed"]),
    )


def diff_captures(control: RecordCapture, session: RecordCapture) -> dict[str, object]:
    """What ``session`` adds to or changes against ``control``, per record type.

    The result is plain data meant to be printed into the evidence log and
    asserted on: the extra wtmpdb/lastlog2 rows, the extra wtmp/btmp records, the
    UIDs whose lastlog time moved, whether the seed digest differs, and a flag
    for a ``soft-reboot`` wtmpdb row among the rows ``session`` added.
    """
    seed_changed = (control.seed or {}).get("sha256") != (session.seed or {}).get(
        "sha256"
    )
    lastlog_moved = {
        uid: {"control": control.lastlog.get(uid), "session": rec}
        for uid, rec in session.lastlog.items()
        if control.lastlog.get(uid, {}).get("time") != rec.get("time")
    }
    wtmpdb_added = sql_rows_added(control.wtmpdb, session.wtmpdb)
    return {
        "wtmpdb_added": wtmpdb_added,
        "lastlog2_added": sql_rows_added(control.lastlog2, session.lastlog2),
        "wtmp_added": utmp_added(control.wtmp, session.wtmp),
        "btmp_added": utmp_added(control.btmp, session.btmp),
        "lastlog_time_moved": lastlog_moved,
        "seed_changed": seed_changed,
        "seed_control": control.seed,
        "seed_session": session.seed,
        # Judged on the rows the session added, so a control that itself
        # soft-reboots (and so already holds such a row) cannot hide one.
        "session_adds_soft_reboot_row": has_soft_reboot_boot_row(wtmpdb_added),
    }


# --- does a way back read as a power cycle? ---------------------------------

# wtmpdb's row type for a boot (``BOOT_TIME`` in its header, as in utmpx).
WTMPDB_BOOT_TIME = 2

# How far (seconds) a stamped time may lie outside the window the test measured
# around the way back: the guest's clock reads are whole commands apart.
WINDOW_SLACK = 2.0


def _as_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _row_times(row: Mapping[str, object]) -> list[int]:
    """The login and logout times (microseconds) a wtmpdb row carries."""
    return [
        t
        for t in (_as_int(row.get("Login")), _as_int(row.get("Logout")))
        if t is not None
    ]


def wtmpdb_boot_logins(rows: Sequence[Mapping[str, object]]) -> list[int]:
    """The login time (microseconds) of each wtmpdb boot row, in ``ID`` order."""
    boots = sorted(
        (row for row in rows if _as_int(row.get("Type")) == WTMPDB_BOOT_TIME),
        key=lambda row: _as_int(row.get("ID")) or 0,
    )
    return [t for row in boots if (t := _as_int(row.get("Login"))) is not None]


def wtmpdb_way_back_problems(
    reference: Sequence[Mapping[str, object]],
    after: Sequence[Mapping[str, object]],
    window: tuple[float, float],
) -> list[str]:
    """Why the rows a way back added to wtmpdb do not read as a power cycle's.

    ``reference`` is the database as a power cycle left it before the session,
    ``after`` the same database after the way back, and ``window`` the earliest
    and latest wall-clock time (seconds) the way back can have happened at. A
    power cycle adds one row: a boot named ``reboot``, stamped when the machine
    came back, so no earlier than any time the database held before it -- the
    shutdown of the boot before it included, which a crash would leave unset.
    Rows are told apart by ``ID``, which wtmpdb never reuses. An empty list
    means the way back reads as a power cycle.
    """
    known = {_as_int(row.get("ID")) for row in reference}
    added = [row for row in after if _as_int(row.get("ID")) not in known]
    if len(added) != 1:
        return [
            f"the way back added {len(added)} rows, a power cycle adds one: {added}"
        ]
    row = added[0]
    problems: list[str] = []
    if _as_int(row.get("Type")) != WTMPDB_BOOT_TIME:
        problems.append(f"the row the way back added is no boot row: {row}")
    if str(row.get("User", "")) != "reboot":
        problems.append(
            f"the boot row is named {row.get('User')!r}, not 'reboot': {row}"
        )
    login = _as_int(row.get("Login"))
    row_id = _as_int(row.get("ID"))
    if login is None or row_id is None:
        return problems + [f"the boot row has no login time or ID: {row}"]
    earlier = [r for r in after if (_as_int(r.get("ID")) or 0) < row_id]
    latest = max((t for r in earlier for t in _row_times(r)), default=None)
    if latest is not None and login < latest:
        problems.append(
            f"the boot row is stamped {login} us, before {latest} us that an "
            f"earlier row carries (the shutdown before it): backdated"
        )
    boots = [r for r in earlier if _as_int(r.get("Type")) == WTMPDB_BOOT_TIME]
    if boots and _as_int(boots[-1].get("Logout")) is None:
        problems.append(
            "the boot before it has no shutdown time, so it reads as a crash: "
            f"{boots[-1]}"
        )
    low, high = window
    if not low - WINDOW_SLACK <= login / 1e6 <= high + WINDOW_SLACK:
        problems.append(
            f"the boot row is stamped {login / 1e6:.6f}, outside the way back "
            f"({low:.6f} to {high:.6f})"
        )
    return problems


def _utmp_time(record: Mapping[str, object]) -> float:
    sec = _as_int(record.get("tv_sec")) or 0
    usec = _as_int(record.get("tv_usec")) or 0
    return sec + usec / 1e6


def _boot_segment(
    records: Sequence[Mapping[str, object]],
) -> tuple[int, list[Mapping[str, object]]] | None:
    """The index of the last boot record and the records written after it."""
    boots = [i for i, r in enumerate(records) if r.get("type") == "BOOT_TIME"]
    if not boots:
        return None
    return boots[-1], list(records[boots[-1] + 1 :])


def classic_way_back_problems(
    reference: Sequence[Mapping[str, object]],
    after: Sequence[Mapping[str, object]],
    window: tuple[float, float],
) -> list[str]:
    """Why the boot a way back added to a classic wtmp does not read as a power
    cycle's.

    ``reference`` and ``after`` are parsed wtmp files (:func:`parse_utmp`), the
    first as a power cycle left it before the session, and ``window`` the
    earliest and latest wall-clock time (seconds) of the way back. A power cycle
    appends one boot record, stamped when the machine came back with a live
    microsecond reading, no earlier than any record before it; every record its
    start writes, the run level among them, follows it in time as well as in
    the file, as the reference's own last boot shows. An empty list means the
    way back reads as a power cycle.
    """
    added = len(boot_record_times(after)) - len(boot_record_times(reference))
    if added != 1:
        return [f"the way back added {added} boot records, a power cycle adds one"]
    segment = _boot_segment(after)
    assert segment is not None
    index, written_after = segment
    boot = after[index]
    problems: list[str] = []
    if last_boot_is_backdated(after):
        problems.append(f"the boot record is stamped before an earlier record: {boot}")
    if _as_int(boot.get("tv_usec")) == 0:
        problems.append(
            f"the boot record carries a cleared microsecond field, which no "
            f"genuine boot does: {boot}"
        )
    stamped = _utmp_time(boot)
    low, high = window
    if not low - WINDOW_SLACK <= stamped <= high + WINDOW_SLACK:
        problems.append(
            f"the boot record is stamped {stamped:.6f}, outside the way back "
            f"({low:.6f} to {high:.6f})"
        )
    early = [r for r in written_after if _utmp_time(r) < stamped]
    if early:
        problems.append(
            f"records of the way back's start are dated before its boot: {early}"
        )
    reference_segment = _boot_segment(reference)
    reference_run_level = reference_segment is not None and any(
        r.get("type") == "RUN_LVL" for r in reference_segment[1]
    )
    if reference_run_level and not any(
        r.get("type") == "RUN_LVL" for r in written_after
    ):
        problems.append(
            "the way back's start wrote no run-level record after its boot, where "
            "the power cycle's start did"
        )
    return problems
