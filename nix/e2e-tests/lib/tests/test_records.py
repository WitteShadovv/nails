"""Parser tests for the host-side login/boot/seed record readers.

Like ``test_disk_forensics``, these run in the fast lane (``python3 -m
unittest``, no VM, no root). They build each record format by hand -- a wtmpdb
and a lastlog2 SQLite database, a classic wtmp/btmp blob, a sparse lastlog, a
random seed -- so the parsers and the session-vs-control diff are locked without
depending on a booted distribution. A silent regression here would let a real
decoy trace (wtmpdb's ``soft-reboot`` boot row) pass unseen in the VM tests.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

import records as rec


def _utmp_record(
    ut_type: int,
    user: str = "",
    line: str = "",
    host: str = "",
    pid: int = 0,
    tv_sec: int = 0,
) -> bytes:
    """Pack one 384-byte glibc ``struct utmpx`` the way wtmp/btmp store it."""
    return rec._UTMP_STRUCT.pack(
        ut_type,
        pid,
        line.encode("latin-1"),
        b"",
        user.encode("latin-1"),
        host.encode("latin-1"),
        0,
        0,
        0,
        tv_sec,
        0,
        0,
        0,
        0,
        0,
        b"",
    )


def _lastlog_slot(time: int = 0, line: str = "", host: str = "") -> bytes:
    return rec._LASTLOG_STRUCT.pack(
        time, line.encode("latin-1"), host.encode("latin-1")
    )


def _make_wtmpdb(path: Path, rows: list[dict[str, object]]) -> None:
    """A wtmpdb-shaped SQLite file: the ``wtmp`` table upstream defines."""
    con = sqlite3.connect(path)
    try:
        con.execute(
            "CREATE TABLE wtmp(ID INTEGER PRIMARY KEY, Type INTEGER, User TEXT, "
            "Login INTEGER, Logout INTEGER, TTY TEXT, RemoteHost TEXT, Service TEXT)"
        )
        for i, row in enumerate(rows, start=1):
            con.execute(
                "INSERT INTO wtmp(ID, Type, User, Login, Logout, TTY, "
                "RemoteHost, Service) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    i,
                    row.get("Type", 0),
                    row.get("User", ""),
                    row.get("Login", 0),
                    row.get("Logout"),
                    row.get("TTY"),
                    row.get("RemoteHost"),
                    row.get("Service"),
                ),
            )
        con.commit()
    finally:
        con.close()


def _make_lastlog2(path: Path, rows: list[dict[str, object]]) -> None:
    con = sqlite3.connect(path)
    try:
        con.execute(
            "CREATE TABLE Lastlog2(Name TEXT PRIMARY KEY, Time INTEGER, TTY TEXT, "
            "RemoteHost TEXT, Service TEXT)"
        )
        for row in rows:
            con.execute(
                "INSERT INTO Lastlog2(Name, Time, TTY, RemoteHost, Service) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    row["Name"],
                    row.get("Time", 0),
                    row.get("TTY"),
                    row.get("RemoteHost"),
                    row.get("Service"),
                ),
            )
        con.commit()
    finally:
        con.close()


class UtmpParserTest(unittest.TestCase):
    def test_parses_boot_and_login_records(self) -> None:
        blob = _utmp_record(2, user="reboot", line="~", tv_sec=1000) + _utmp_record(
            7, user="root", line="pts/0", host="localhost", pid=42, tv_sec=1001
        )
        parsed = rec.parse_utmp(blob)
        self.assertEqual([r["type"] for r in parsed], ["BOOT_TIME", "USER_PROCESS"])
        self.assertEqual(parsed[0]["user"], "reboot")
        self.assertEqual(parsed[1]["user"], "root")
        self.assertEqual(parsed[1]["line"], "pts/0")
        self.assertEqual(parsed[1]["host"], "localhost")
        self.assertEqual(parsed[1]["pid"], 42)

    def test_trailing_partial_record_is_ignored(self) -> None:
        blob = _utmp_record(2, user="reboot") + b"\x00\x01\x02"
        self.assertEqual(len(rec.parse_utmp(blob)), 1)

    def test_absent_file_is_no_records(self) -> None:
        self.assertEqual(rec.read_utmp("/nonexistent/wtmp"), [])


class LastlogParserTest(unittest.TestCase):
    def test_drops_empty_slots_keeps_logins(self) -> None:
        # UID 0 empty, UID 1 empty, UID 1000 a real login.
        blob = _lastlog_slot() * 1000 + _lastlog_slot(
            time=1700000000, line="pts/1", host="10.0.2.2"
        )
        parsed = rec.parse_lastlog(blob)
        self.assertEqual(list(parsed), [1000])
        self.assertEqual(parsed[1000]["time"], 1700000000)
        self.assertEqual(parsed[1000]["host"], "10.0.2.2")


class WtmpdbReaderTest(unittest.TestCase):
    def test_reads_rows_and_detects_soft_reboot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "wtmp.db"
            _make_wtmpdb(
                db,
                [
                    {"Type": 2, "User": "reboot", "Login": 1000, "Service": "0"},
                    {"Type": 1, "User": "shutdown", "Login": 2000},
                    {
                        "Type": 2,
                        "User": "reboot",
                        "Login": 3000,
                        "Service": "soft-reboot",
                    },
                ],
            )
            rows = rec.read_wtmpdb(db)
            self.assertEqual(len(rows), 3)
            self.assertTrue(rec.has_soft_reboot_boot_row(rows))

    def test_no_soft_reboot_in_normal_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "wtmp.db"
            _make_wtmpdb(db, [{"Type": 2, "User": "reboot", "Login": 1000}])
            self.assertFalse(rec.has_soft_reboot_boot_row(rec.read_wtmpdb(db)))

    def test_absent_db_is_no_rows(self) -> None:
        self.assertEqual(rec.read_wtmpdb("/nonexistent/wtmp.db"), [])


class Lastlog2ReaderTest(unittest.TestCase):
    def test_reads_named_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "lastlog2.db"
            _make_lastlog2(
                db,
                [
                    {"Name": "root", "Time": 1700000000, "TTY": "pts/0"},
                    {"Name": "user", "Time": 1700000100, "TTY": "pts/1"},
                ],
            )
            rows = rec.read_lastlog2(db)
            self.assertEqual({r["Name"] for r in rows}, {"root", "user"})


class SeedDigestTest(unittest.TestCase):
    def test_length_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            seed = Path(tmp) / "random-seed"
            seed.write_bytes(b"\x00" * 256)
            digest = rec.seed_digest(seed)
            assert digest is not None
            self.assertEqual(digest["length"], 256)
            self.assertEqual(len(str(digest["sha256"])), 64)

    def test_absent_seed_is_none(self) -> None:
        self.assertIsNone(rec.seed_digest("/nonexistent/random-seed"))


class DiffTest(unittest.TestCase):
    def test_utmp_added_counts_multiplicity(self) -> None:
        control = rec.parse_utmp(_utmp_record(2, user="reboot", line="~"))
        session = rec.parse_utmp(
            _utmp_record(2, user="reboot", line="~")
            + _utmp_record(2, user="reboot", line="~")
        )
        added = rec.utmp_added(control, session)
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0]["type"], "BOOT_TIME")

    def test_sql_rows_added_ignores_id_and_timestamp(self) -> None:
        control = [
            {"ID": 1, "Type": 2, "User": "reboot", "Login": 1000, "Service": "0"}
        ]
        session = [
            {"ID": 7, "Type": 2, "User": "reboot", "Login": 9999, "Service": "0"},
            {
                "ID": 8,
                "Type": 2,
                "User": "reboot",
                "Login": 9998,
                "Service": "soft-reboot",
            },
        ]
        added = rec.sql_rows_added(control, session)
        # The first row matches the control but for id/timestamp; only the
        # soft-reboot row is genuinely new.
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0]["Service"], "soft-reboot")

    def test_diff_captures_flags_soft_reboot_and_seed(self) -> None:
        control = rec.RecordCapture(
            label="control",
            wtmpdb=[{"ID": 1, "Type": 2, "User": "reboot", "Login": 1, "Service": "0"}],
            seed={"length": 256, "sha256": "a"},
        )
        session = rec.RecordCapture(
            label="session",
            wtmpdb=[
                {"ID": 1, "Type": 2, "User": "reboot", "Login": 1, "Service": "0"},
                {
                    "ID": 2,
                    "Type": 2,
                    "User": "reboot",
                    "Login": 2,
                    "Service": "soft-reboot",
                },
            ],
            seed={"length": 256, "sha256": "b"},
        )
        diff = rec.diff_captures(control, session)
        self.assertTrue(diff["session_adds_soft_reboot_row"])
        added = diff["wtmpdb_added"]
        assert isinstance(added, list)
        self.assertEqual(len(added), 1)
        self.assertTrue(diff["seed_changed"])

    def test_capture_from_tree_reads_present_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "var/log").mkdir(parents=True)
            (root / "var/lib/systemd").mkdir(parents=True)
            (root / "var/log/wtmp").write_bytes(
                _utmp_record(2, user="reboot", line="~")
            )
            (root / "var/lib/systemd/random-seed").write_bytes(b"\x01" * 512)
            cap = rec.capture_from_tree("after", root)
            self.assertEqual(len(cap.wtmp), 1)
            assert cap.seed is not None
            self.assertEqual(cap.seed["length"], 512)
            # Absent files stay empty, and the capture still serialises.
            self.assertEqual(cap.wtmpdb, [])
            self.assertIn("lastlog", cap.as_dict())


class BackdatedBootTest(unittest.TestCase):
    def test_a_boot_stamped_before_an_earlier_record_is_backdated(self) -> None:
        # Cold boot, a shutdown at a later time, then a boot stamped back at the
        # cold-boot time: the trace a soft-reboot into a decoy leaves.
        blob = (
            _utmp_record(2, user="reboot", line="~", tv_sec=1000)
            + _utmp_record(1, user="shutdown", tv_sec=2000)
            + _utmp_record(2, user="reboot", line="~", tv_sec=1000)
        )
        self.assertTrue(rec.last_boot_is_backdated(rec.parse_utmp(blob)))

    def test_a_boot_that_is_the_newest_event_is_not_backdated(self) -> None:
        blob = (
            _utmp_record(2, user="reboot", line="~", tv_sec=1000)
            + _utmp_record(1, user="shutdown", tv_sec=2000)
            + _utmp_record(2, user="reboot", line="~", tv_sec=3000)
        )
        self.assertFalse(rec.last_boot_is_backdated(rec.parse_utmp(blob)))

    def test_no_boot_record_is_not_backdated(self) -> None:
        self.assertFalse(rec.last_boot_is_backdated([]))
        self.assertFalse(
            rec.last_boot_is_backdated(rec.parse_utmp(_utmp_record(7, user="root")))
        )

    def test_boot_record_times_lists_each_boot_in_order(self) -> None:
        blob = (
            _utmp_record(2, user="reboot", tv_sec=1000)
            + _utmp_record(7, user="root", tv_sec=1001)
            + _utmp_record(2, user="reboot", tv_sec=1000)
        )
        self.assertEqual(rec.boot_record_times(rec.parse_utmp(blob)), [1000, 1000])
        self.assertEqual(rec.boot_record_times([]), [])

    def test_last_boot_record_returns_the_newest_boot(self) -> None:
        blob = (
            _utmp_record(2, user="reboot", line="~", host="6.x", tv_sec=1000)
            + _utmp_record(1, user="shutdown", tv_sec=2000)
            + _utmp_record(2, user="reboot", line="~", host="6.x", tv_sec=3000)
        )
        last = rec.last_boot_record(rec.parse_utmp(blob))
        assert last is not None
        self.assertEqual(last["tv_sec"], 3000)
        self.assertEqual(last["user"], "reboot")
        self.assertEqual(last["host"], "6.x")
        self.assertIsNone(rec.last_boot_record([]))
        self.assertIsNone(
            rec.last_boot_record(rec.parse_utmp(_utmp_record(7, user="root")))
        )


if __name__ == "__main__":
    unittest.main()
