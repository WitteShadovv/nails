"""Tests for the judgments of fedora_gate, the gate scenario of an enforcing
Fedora decoy, that run without a VM."""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from typing import Any

import fedora_gate as fg
import selinux_gate as sg


class FakeSession:
    """The e2e package's session helpers, as far as the judgments use them."""

    def __init__(self) -> None:
        self.calls: list[tuple[set[str], str]] = []

    def carried_run_residue(self, vm: Any, before: set[str], since: str) -> list[str]:
        self.calls.append((set(before), since))
        return ["/run/left"]


def gate(session: Any = None, **settings: Any) -> fg.Gate:
    return fg.Gate(
        None,
        session or FakeSession(),
        None,
        None,
        {"image": "fedora-44", **settings},
        tempfile.mkdtemp(prefix="gate-test-"),
    )


def quiet(call: Any, *args: Any) -> Any:
    """``call`` with what it prints kept off the test's output."""
    with contextlib.redirect_stdout(io.StringIO()):
        return call(*args)


class RowTest(unittest.TestCase):
    def test_a_row_is_judged_only_with_a_verdict(self) -> None:
        rows = {"decoy-persistence": {"status": "warn"}, "x": {"status": "fail"}}
        self.assertTrue(fg.judged_row(rows, "decoy-persistence"))
        self.assertFalse(fg.judged_row(rows, "x"))
        # check printed no report: no row, nothing it could no longer name.
        self.assertFalse(fg.judged_row({}, "decoy-persistence"))


class FailedUnitsTest(unittest.TestCase):
    def test_sorts_the_failed_units(self) -> None:
        found = fg.failed_units_problems(
            [
                "overlay-runtime-boot.service",
                "systemd-remount-fs.service",
                "systemd-zram-setup@zram0.service",
                "chronyd.service",
            ],
            fg.SOFT_REBOOT_FAILURES,
        )
        self.assertEqual(
            found,
            {
                "nails": ["overlay-runtime-boot.service"],
                "masked": ["systemd-remount-fs.service"],
                "known": ["systemd-zram-setup@zram0.service"],
                "other": ["chronyd.service"],
            },
        )


class DecoyDiskTest(unittest.TestCase):
    def test_the_record_files_are_left_to_the_records_checks(self) -> None:
        listing = "\n".join(
            (
                "/var/log/wtmp",
                "/var/lib/lastlog",
                "/var/lib/lastlog/lastlog2.db",
                "/var/lib/lastlogger",
                "/var/lib/systemd/random-seed",
                "find: '/proc/1': no such file",
                "",
            )
        )
        self.assertEqual(
            fg.changed_paths(listing),
            {"/var/lib/lastlogger", "/var/lib/systemd/random-seed"},
        )

    def test_a_way_back_may_change_what_a_control_changes(self) -> None:
        way_back = {"/var/lib/NetworkManager", "/etc/x", "/var/lib/chrony/drift"}
        controls = [{"/var/lib/NetworkManager"}, {"/var/lib/chrony/drift"}]
        self.assertEqual(fg.decoy_disk_residue(way_back, controls), ["/etc/x"])
        self.assertEqual(fg.decoy_disk_residue(way_back, []), sorted(way_back))

    def test_no_control_judges_no_way_back(self) -> None:
        run = gate()
        run.disk = {"way-back-1": {"/etc/x"}}
        quiet(run.judge_disk)
        self.assertEqual([c["passed"] for c in run.checks], [False])
        self.assertIn("no control", run.checks[0]["detail"])

    def test_judges_each_way_back_against_every_control(self) -> None:
        run = gate()
        run.disk = {
            "control-1": {"/var/a"},
            "way-back-1": {"/var/a", "/var/b"},
            "control-2": {"/var/b"},
            "way-back-2": {"/var/a", "/etc/label"},
        }
        quiet(run.judge_disk)
        self.assertEqual(
            [(c["name"].split(":")[0], c["passed"]) for c in run.checks],
            [("way back 1", True), ("way back 2", False)],
        )
        self.assertIn("/etc/label", run.checks[1]["detail"])


ROOT = "/dev/vda4"
BLIND = (
    "the decoy filesystem compresses file contents, so a leaked canary may be "
    "stored compressed, which this raw plaintext scan cannot match"
)


class RehearseScanTest(unittest.TestCase):
    def scan(self, **root: Any) -> dict[str, Any]:
        device = {"device": ROOT, "hits": [], "bytes_scanned": 10, "blind_spot": BLIND}
        device.update(root)
        boot = {"device": "/dev/vda3", "hits": [], "bytes_scanned": 5}
        return {"devices": [device, boot]}

    def test_a_clean_scan_names_the_compressing_root(self) -> None:
        self.assertEqual(fg.rehearse_scan_problems(9, self.scan(), ROOT), [])

    def test_a_root_without_its_blind_spot_reads_as_clean(self) -> None:
        problems = fg.rehearse_scan_problems(0, self.scan(blind_spot=None), ROOT)
        self.assertEqual(len(problems), 2, problems)

    def test_a_hit_an_error_or_another_device_s_blind_spot_fails(self) -> None:
        self.assertTrue(fg.rehearse_scan_problems(9, self.scan(hits=["x"]), ROOT))
        self.assertTrue(fg.rehearse_scan_problems(9, self.scan(error="EIO"), ROOT))
        scan = self.scan()
        scan["devices"][1]["blind_spot"] = "x"
        self.assertTrue(fg.rehearse_scan_problems(9, scan, ROOT))

    def test_a_scan_that_read_nothing_fails(self) -> None:
        self.assertEqual(
            fg.rehearse_scan_problems(9, {"devices": []}, ROOT),
            ["the scan read no device"],
        )
        scan = self.scan(bytes_scanned=0)
        scan["devices"][1]["bytes_scanned"] = 0
        self.assertIn("the scan read no byte", fg.rehearse_scan_problems(9, scan, ROOT))
        self.assertTrue(fg.rehearse_scan_problems(9, self.scan(), "/dev/vdb1"))


class RunResidueTest(unittest.TestCase):
    def test_counts_from_the_wall_clock_of_the_way_back(self) -> None:
        # What the session made in /run changed after the entry, so a wall
        # clock from before the entry would let every one of them pass.
        session = FakeSession()
        run = gate(session)
        run.facts["leave-wall-1"] = "1794687000"
        state = {"run": {"/run/a"}, "since": "1794686900.5"}
        self.assertEqual(run.run_residue(1, state), ["/run/left"])
        self.assertEqual(session.calls, [({"/run/a"}, "1794687000")])


def kmsg(seq: int, msg: str) -> dict[str, Any]:
    return {"seq": seq, "us": seq * 1000, "msg": msg, "pri": 6, "dict": []}


def marker(label: str, seq: int, wall: float) -> dict[str, Any]:
    return {"label": label, "seq": seq, "wall": f"{wall:.9f}"}


DENIAL = (
    "audit: type=1400 audit({t}:{s}): avc:  denied  {{ read }} for  pid=9 "
    'comm="{comm}" name="x" dev="vda4" ino=1 '
    "scontext=system_u:system_r:{stype}:s0 "
    "tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=0"
)


def denial(t: float, serial: int, comm: str, stype: str = "init_t") -> str:
    return DENIAL.format(t=f"{t:.3f}", s=serial, comm=comm, stype=stype)


class DenialsTest(unittest.TestCase):
    # Each marker's sequence number in the kernel log and its wall clock.
    MARKERS = (
        ("boot-ready", 10, 100.0),
        ("prep-decoy", 20, 110.0),
        ("check-check-journal", 30, 120.0),
        ("prep-after-check-journal", 40, 130.0),
        ("control-1-start", 50, 140.0),
        ("enter-1", 60, 150.0),
        ("prep-drift", 70, 160.0),
    )

    def boot(self, placed: dict[int, str], audit_text: str = "") -> dict[str, Any]:
        """A reference boot whose kernel log runs from 1 to 80 without a gap:
        the first audit record (serial 1), the markers, ``placed`` by their
        sequence numbers, and filler."""
        records = {}
        for seq in range(1, 81):
            records[seq] = kmsg(seq, "filler")
        records[1] = kmsg(1, "audit: type=2000 audit(0.100:1): state=initialized")
        for label, seq, _ in self.MARKERS:
            records[seq] = kmsg(seq, sg.marker(label, "n"))
        # Each switch keeps the decoy's policy, as at a plain soft-reboot.
        for seq in (55, 62):
            records[seq] = kmsg(seq, f"systemd[1]: {fg.POLICY_KEPT}")
        for seq, message in placed.items():
            records[seq] = kmsg(seq, message)
        return {
            "why": "reference",
            "records": records,
            "dropped": 0,
            "markers": [marker(*m) for m in self.MARKERS],
            "console": [],
            "audit": sg.audit_log(audit_text, 0),
            "btime": 0,
        }

    def failed(self, boot: dict[str, Any]) -> list[str]:
        run = gate()
        run.boots = [boot]
        quiet(run.judge_denials)
        self.run_checks = run.checks
        return [c["name"] for c in run.checks if not c["passed"]]

    def test_a_clean_boot_passes(self) -> None:
        self.assertEqual(self.failed(self.boot({})), [])

    def test_a_check_phase_judges_what_auditd_logged_of_it(self) -> None:
        # nails check ran while auditd took every record: its denial is only
        # in auditd's log, dated inside the check's phase.
        audit = (
            "type=AVC msg=audit(125.000:2): avc:  denied  { read } for  pid=9 "
            'comm="nails" name="x" dev="vda4" ino=1 '
            "scontext=unconfined_u:unconfined_r:unconfined_t:s0 "
            "tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=0"
        )
        failed = self.failed(self.boot({}, audit))
        self.assertEqual(failed, ["no new denial from marker check-check-journal on"])
        detail = next(c for c in self.run_checks if c["name"] == failed[0])
        self.assertIn("audit log", detail["detail"])

    def test_an_audit_record_in_neither_log_fails_the_boot(self) -> None:
        # Serial 1 is in the kernel log, 3 in auditd's: 2 reached neither.
        audit = "type=DAEMON_START msg=audit(105.000:3): op=start res=1"
        self.assertEqual(
            self.failed(self.boot({}, audit)),
            ["every audit record of the boot is in the kernel log or auditd's log"],
        )
        audit += "\ntype=CONFIG_CHANGE msg=audit(104.000:2): op=set res=1"
        self.assertEqual(self.failed(self.boot({}, audit)), [])

    def test_a_phase_that_lost_records_fails(self) -> None:
        lost = {65: "kauditd_printk_skb: 3 callbacks suppressed"}
        self.assertEqual(
            self.failed(self.boot(lost)), ["the kernel lost no record from enter-1 on"]
        )

    def test_the_baseline_is_the_decoy_before_the_first_entry(self) -> None:
        self.assertEqual(
            fg.Gate.baseline_labels(self.boot({})),
            {"boot-ready", "prep-decoy", "prep-after-check-journal", "control-1-start"},
        )
        # A denial a phase after the first session logs is new unless the
        # decoy logged it before the first entry; one a check logged is no
        # baseline.
        late = denial(161.0, 2, "rpm", "rpm_t")
        self.assertEqual(
            self.failed(self.boot({75: late})),
            ["no new denial from marker prep-drift on"],
        )
        early = denial(111.0, 3, "rpm", "rpm_t")
        self.assertEqual(self.failed(self.boot({25: early, 75: late})), [])
        in_check = denial(121.0, 3, "rpm", "rpm_t")
        self.assertEqual(
            self.failed(self.boot({35: in_check, 75: late})),
            [
                "no new denial from marker check-check-journal on",
                "no new denial from marker prep-drift on",
            ],
        )

    def test_a_nails_denial_before_the_first_entry_still_counts(self) -> None:
        self.assertEqual(
            self.failed(self.boot({25: denial(111.0, 2, "control")})),
            ["no new denial from marker prep-decoy on"],
        )


if __name__ == "__main__":
    unittest.main()
