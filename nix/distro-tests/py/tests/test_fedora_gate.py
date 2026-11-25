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


def gate(**settings: Any) -> fg.Gate:
    return fg.Gate(
        None,
        None,
        None,
        {"image": "fedora-44", **settings},
        tempfile.mkdtemp(prefix="gate-test-"),
    )


def quiet(call: Any, *args: Any) -> Any:
    """``call`` with what it prints kept off the test's output."""
    with contextlib.redirect_stdout(io.StringIO()):
        return call(*args)


class PrepareTest(unittest.TestCase):
    def test_every_start_takes_the_gate_s_kernel_log_settings(self) -> None:
        for key, value in sg.KMSG_SETTINGS:
            self.assertIn(f"'{key} = {value}'", fg.PREPARE_DECOY)
        self.assertIn("/etc/sysctl.d/", fg.PREPARE_DECOY)


class RowTest(unittest.TestCase):
    def test_a_row_is_judged_only_with_a_verdict(self) -> None:
        rows = {
            "decoy-persistence": {"status": "warn"},
            # Refused for another reason: still a row check printed.
            "x": {"status": "fail"},
            "y": {"message": "no verdict"},
        }
        self.assertTrue(fg.judged_row(rows, "decoy-persistence"))
        self.assertTrue(fg.judged_row(rows, "x"))
        self.assertFalse(fg.judged_row(rows, "y"))
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
            {"systemd-zram-setup@zram0.service": "known"},
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


class DecoyZramFailuresTest(unittest.TestCase):
    """A zram setup unit failed in a hidden session counts as the decoy's own
    run only with the invocation ID it had in the decoy before the entry."""

    UNIT = "systemd-zram-setup@zram0.service"
    BEFORE = f"Id={UNIT}\nInvocationID=0f3a9c\n"

    def test_the_decoy_s_run_failed_at_its_stop_is_allowed(self) -> None:
        # Fedora 45: the decoy's stop at the switch failed to reset zram0, and
        # the hidden session shows the decoy's run failed.
        found = fg.decoy_zram_failures([self.UNIT], self.BEFORE, self.BEFORE)
        self.assertEqual(list(found), [self.UNIT])
        problems = fg.failed_units_problems([self.UNIT], found)
        self.assertEqual(problems["other"], [])

    def test_a_run_of_the_hidden_session_is_not(self) -> None:
        hidden = f"Id={self.UNIT}\nInvocationID=77e01b\n"
        self.assertEqual(fg.decoy_zram_failures([self.UNIT], self.BEFORE, hidden), {})
        problems = fg.failed_units_problems([self.UNIT], {})
        self.assertEqual(problems["other"], [self.UNIT])

    def test_without_an_invocation_on_either_side_nothing_is_allowed(self) -> None:
        none = f"Id={self.UNIT}\nInvocationID=\n"
        for before, hidden in (("", self.BEFORE), (self.BEFORE, ""), (none, none)):
            self.assertEqual(fg.decoy_zram_failures([self.UNIT], before, hidden), {})

    def test_only_zram_setup_units_and_only_failed_ones(self) -> None:
        other = "chronyd.service"
        both = self.BEFORE + f"\nId={other}\nInvocationID=0f3a9c\n"
        self.assertEqual(
            list(fg.decoy_zram_failures([other, self.UNIT], both, both)), [self.UNIT]
        )
        self.assertEqual(fg.decoy_zram_failures([], both, both), {})


class ZramTest(unittest.TestCase):
    COLD = "\n".join(
        (
            "zram0 initstate=1 disksize=3103784960 backing=none "
            "mm_stat=4096 74 12288 0 12288 0 0 0 0",
            "/dev/zram0 partition 3103780864 0 100",
            "Id=systemd-zram-setup@zram0.service",
            "LoadState=loaded",
            "ActiveState=active",
            "Result=success",
            "",
            "Id=dev-zram0.swap",
            "LoadState=loaded",
            "ActiveState=active",
            "Result=success",
        )
    )

    def test_use_does_not_change_the_shape(self) -> None:
        used = self.COLD.replace("mm_stat=4096 74", "mm_stat=9999 99").replace(
            "3103780864 0 100", "3103780864 2621440 100"
        )
        self.assertEqual(fg.zram_shape(used), fg.zram_shape(self.COLD))

    def test_a_device_left_set_up_without_its_swap_differs(self) -> None:
        # The setup failed: the device keeps its size, no swap is on, and the
        # units are failed and inactive.
        failed = "\n".join(
            (
                "zram0 initstate=1 disksize=3103784960 backing=none mm_stat=0 0 0",
                "Id=systemd-zram-setup@zram0.service",
                "LoadState=loaded",
                "ActiveState=failed",
                "Result=exit-code",
                "Id=dev-zram0.swap",
                "LoadState=loaded",
                "ActiveState=inactive",
                "Result=success",
            )
        )
        self.assertNotEqual(fg.zram_shape(failed), fg.zram_shape(self.COLD))
        # A device of another size, or none, differs as well.
        other = self.COLD.replace("disksize=3103784960", "disksize=1")
        self.assertNotEqual(fg.zram_shape(other), fg.zram_shape(self.COLD))
        self.assertNotEqual(fg.zram_shape(""), fg.zram_shape(self.COLD))

    def test_the_marker_counts(self) -> None:
        probe = "\n".join(
            (
                "VmSwap:\t   20480 kB",
                "held:",
                "/dev/zram0=4021",
                "stopped:",
                "/dev/zram0=0",
                "/dev/zram1=grep: /dev/zram1: Permission denied",
            )
        )
        self.assertEqual(
            fg.zram_marker_counts(probe),
            {
                "held /dev/zram0": 4021,
                "stopped /dev/zram0": 0,
                "stopped /dev/zram1": None,
            },
        )
        self.assertEqual(fg.zram_marker_counts("/dev/zram0=0"), {"/dev/zram0": 0})
        self.assertEqual(fg.zram_marker_counts(""), {})


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

    def test_a_unit_s_private_folder_is_named_by_its_unit(self) -> None:
        boot = "ab" * 16  # a boot id: 32 hex digits
        listing = "\n".join(
            (
                f"/var/tmp/systemd-private-{boot}-chronyd.service-WSgY0s",
                f"/var/tmp/systemd-private-{boot}-chronyd.service-WSgY0s/tmp",
                f"/var/tmp/systemd-private-{boot}-dbus-broker.service-nf0Nj1/tmp/x",
            )
        )
        self.assertEqual(
            fg.changed_paths(listing),
            {
                "/var/tmp/systemd-private-*-chronyd.service-*",
                "/var/tmp/systemd-private-*-chronyd.service-*/tmp",
                "/var/tmp/systemd-private-*-dbus-broker.service-*/tmp/x",
            },
        )

    def test_a_control_of_another_boot_explains_a_unit_s_private_folder(
        self,
    ) -> None:
        # The control before the cold power cycle ran under another boot ID
        # than the session's cold boot after it (seen on Fedora 45:
        # hostnamed's folder).
        control = fg.changed_paths(
            f"/var/tmp/systemd-private-{'b5' * 16}-systemd-hostnamed.service-Ab12Cd"
        )
        session = fg.changed_paths(
            f"/var/tmp/systemd-private-{'21' * 16}-systemd-hostnamed.service-Zz98Yy\n"
            "/etc/x"
        )
        self.assertEqual(fg.decoy_disk_residue(session, [control]), ["/etc/x"])

    def test_another_filesystem_s_mount_point_is_left_out(self) -> None:
        listing = "/\n/nix/.ro-store\n/nix/store\n/etc/x\n/run"
        self.assertEqual(
            fg.changed_paths(listing, ["/nix/.ro-store", "/nix/store", "/run"]),
            {"/", "/etc/x"},
        )

    def test_a_session_may_change_what_a_control_changes(self) -> None:
        session = {"/var/lib/NetworkManager", "/etc/x", "/var/lib/chrony/drift"}
        controls = [{"/var/lib/NetworkManager"}, {"/var/lib/chrony/drift"}]
        self.assertEqual(fg.decoy_disk_residue(session, controls), ["/etc/x"])
        self.assertEqual(fg.decoy_disk_residue(session, []), sorted(session))

    def test_no_control_judges_no_session(self) -> None:
        run = gate()
        run.disk = {"session-1": {"/etc/x"}}
        quiet(run.judge_disk)
        self.assertEqual([c["passed"] for c in run.checks], [False])
        self.assertIn("no control", run.checks[0]["detail"])

    def test_judges_each_session_against_every_control(self) -> None:
        run = gate()
        run.disk = {
            "control-1": {"/var/a"},
            "control-cold": {"/var/c"},
            "session-1": {"/var/a", "/var/b", "/var/c"},
            "control-2": {"/var/b"},
            "session-2": {"/var/a", "/etc/label"},
        }
        quiet(run.judge_disk)
        self.assertEqual(
            [(c["name"].split(":")[0], c["passed"]) for c in run.checks],
            [("session 1", True), ("session 2", False)],
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


SYSCALL = (
    "audit: type=1300 audit(1794705307.950:{serial}): arch=c000003e syscall=59 "
    "success={success} exit=0 items=2 ppid=1 pid=4146 auid=4294967295 uid=0 "
    'comm="{comm}" exe="{exe}" subj=system_u:system_r:{domain}:s0 key="{key}"'
)
EXECVE = "audit: type=1309 audit(1794705307.950:{serial}): argc={argc} {args}"
PATH = (
    "audit: type=1302 audit(1794705307.950:{serial}): item=0 "
    'name="{name}" inode=4311 obj=system_u:object_r:init_var_run_t:s0'
)


def run(
    serial: int,
    exe: str,
    domain: str,
    *args: str,
    key: str = fg.EXEC_RUN_KEY,
    ran: bool = True,
) -> list[str]:
    """The kernel's records of one run: its system call and its arguments."""
    argv = [exe, *args]
    return [
        SYSCALL.format(
            serial=serial,
            success="yes" if ran else "no",
            comm=exe.rsplit("/", 1)[-1],
            exe=exe if ran else "/usr/lib/systemd/systemd-executor",
            domain=domain,
            key=key,
        ),
        EXECVE.format(
            serial=serial,
            argc=len(argv),
            args=" ".join(f'a{i}="{a}"' for i, a in enumerate(argv)),
        ),
        PATH.format(serial=serial, name=exe),
    ]


COPY = "/run/overlay-runtime/control"


def every_step(domain: str = "unconfined_service_t") -> list[str]:
    """A run of each step of NAILS from its copy in /run."""
    lines: list[str] = []
    for serial, step in enumerate(fg.NAILS_STEPS, 100):
        lines += run(serial, COPY, domain, "--config", "/run/x.toml", step)
    return lines


class ExecTest(unittest.TestCase):
    def boot(self, *messages: str) -> dict[str, Any]:
        return {
            "why": "cold",
            "records": {seq: kmsg(seq, m) for seq, m in enumerate(messages, 1)},
        }

    def test_reads_what_the_rules_recorded(self) -> None:
        records = self.boot(
            *run(800, COPY, "init_t", "transition", key=fg.EXEC_KEY),
            *run(801, "/usr/bin/true", "init_t", key="other"),
            *run(802, COPY, "init_t", "transition", ran=False),
            "audit: type=1400 audit(1.0:803): avc:  denied  { map }",
        )["records"].values()
        found = fg.exec_records(records)
        self.assertEqual(
            [(r["key"], r["program"], r["step"], r["ran"]) for r in found],
            [
                (fg.EXEC_KEY, COPY, "transition", True),
                (fg.EXEC_RUN_KEY, COPY, "transition", False),
            ],
        )
        self.assertEqual(found[0]["subj"], "system_u:system_r:init_t:s0")

    def judged(self, *messages: str, probes: tuple[str, ...]) -> list[bool]:
        run_ = gate()
        run_.exec_audit = True
        run_.exec_probes = list(probes)
        run_.boots = [self.boot(*messages)]
        quiet(run_.judge_execs)
        self.judged_facts = run_.facts
        return [c["passed"] for c in run_.checks]

    PROBE = f"{fg.EXEC_PROBE}-hidden-1"

    def probe(self) -> list[str]:
        return run(5, self.PROBE, "unconfined_service_t", key=fg.EXEC_KEY)

    def test_every_step_outside_init_t_passes(self) -> None:
        self.assertEqual(
            self.judged(*self.probe(), *every_step(), probes=(self.PROBE,)),
            [True, True, True, True],
        )
        self.assertEqual(
            self.judged_facts["nails-step-domains"]["guard-device"],
            ["unconfined_service_t"],
        )

    def test_a_copy_labelled_as_runtime_data_fails(self) -> None:
        data = run(6, COPY, "init_t", "watch", key=fg.EXEC_KEY)
        self.assertEqual(
            self.judged(*self.probe(), *every_step(), *data, probes=(self.PROBE,)),
            [True, False, False, True],
        )

    def test_a_step_in_init_t_fails(self) -> None:
        self.assertEqual(
            self.judged(*self.probe(), *every_step("init_t"), probes=(self.PROBE,)),
            [True, True, False, True],
        )

    def test_a_step_the_kernel_never_recorded_fails(self) -> None:
        # The policy refused the disk guard: it never ran, so its domain is
        # unknown, and the copy it tried was labelled as runtime data.
        steps = [line for line in every_step() if "guard-device" not in line]
        steps += run(104, COPY, "init_t", "guard-device", key=fg.EXEC_KEY, ran=False)
        self.assertEqual(
            self.judged(*self.probe(), *steps, probes=(self.PROBE,)),
            [True, False, True, False],
        )

    def test_without_the_probe_s_record_nothing_shows_the_rules_work(self) -> None:
        missing = self.judged(*every_step(), probes=(f"{fg.EXEC_PROBE}-after-1",))
        self.assertEqual(missing[0], False)
        self.assertEqual(self.judged(*every_step(), probes=())[0], False)

    def test_the_variant_without_the_rules_judges_nothing(self) -> None:
        run_ = gate(dontaudit=False)
        quiet(run_.judge_execs)
        self.assertEqual(run_.checks, [])

    def test_the_listed_rules_hold_only_with_each_one_there(self) -> None:
        rule = "-a always,exit -F arch=b64 -S execve,execveat"
        listed = [
            f"{rule} -F obj_type={kind} -F key={fg.EXEC_KEY}" for kind in fg.EXEC_TYPES
        ]
        listed.append(f"{rule} -F dir=/run -F key={fg.EXEC_RUN_KEY}")
        self.assertTrue(fg.exec_rules_held("\n".join(listed)))
        self.assertFalse(fg.exec_rules_held("\n".join(listed[1:])))
        self.assertFalse(fg.exec_rules_held("\n".join(listed[:-1])))
        self.assertFalse(fg.exec_rules_held("No rules"))

    def test_the_rules_record_each_runtime_label_and_all_of_run(self) -> None:
        for kind in fg.EXEC_TYPES:
            self.assertIn(f"-F obj_type={kind} -k {fg.EXEC_KEY};", fg.EXEC_RULES)
        self.assertTrue(fg.EXEC_RULES.startswith("auditctl -D;"))
        # The labels' rules come first: the first rule a run matches names it.
        self.assertLess(
            fg.EXEC_RULES.index(fg.EXEC_KEY + ";"),
            fg.EXEC_RULES.index(f"-F dir=/run -k {fg.EXEC_RUN_KEY};"),
        )


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

    def boot(
        self, placed: dict[int, str], audit_text: str = "", started: bool = True
    ) -> dict[str, Any]:
        """A reference boot whose kernel log runs from 1 to 80 without a gap:
        the first audit record (serial 1), the markers, the first audit record
        after the first marker (serial 2) unless not ``started``, ``placed``
        by their sequence numbers, and filler."""
        records = {}
        for seq in range(1, 81):
            records[seq] = kmsg(seq, "filler")
        records[1] = kmsg(1, "audit: type=2000 audit(0.100:1): state=initialized")
        if started:
            records[11] = kmsg(11, "audit: type=1130 audit(100.500:2): pid=1 res=1")
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
            "type=AVC msg=audit(125.000:3): avc:  denied  { read } for  pid=9 "
            'comm="nails" name="x" dev="vda4" ino=1 '
            "scontext=unconfined_u:unconfined_r:unconfined_t:s0 "
            "tcontext=system_u:object_r:etc_t:s0 tclass=file permissive=0"
        )
        failed = self.failed(self.boot({}, audit))
        self.assertEqual(failed, ["no new denial from marker check-check-journal on"])
        detail = next(c for c in self.run_checks if c["name"] == failed[0])
        self.assertIn("audit log", detail["detail"])

    SERIALS = (
        "every audit record of the boot from its first marker on is in the "
        "kernel log or auditd's log"
    )

    def test_an_audit_record_in_neither_log_fails_the_boot(self) -> None:
        # From the first marker on, 3 is in auditd's log and 5 in the kernel
        # log: 4 reached neither.
        audit = "type=CONFIG_CHANGE msg=audit(105.000:3): op=set res=1"
        late = {25: "audit: type=1130 audit(111.000:5): pid=1 msg='unit=x'"}
        self.assertEqual(self.failed(self.boot(late, audit)), [self.SERIALS])
        audit += "\ntype=CONFIG_CHANGE msg=audit(106.000:4): op=set res=1"
        self.assertEqual(self.failed(self.boot(late, audit)), [])

    def test_what_the_boot_s_start_lost_is_recorded_only(self) -> None:
        # Before the gate lifted printk's rate limit the kernel dropped 2 to
        # 38; auditd took 39 on.
        audit = "type=CONFIG_CHANGE msg=audit(105.000:39): op=set res=1"
        run = gate()
        run.boots = [self.boot({}, audit, started=False)]
        quiet(run.judge_denials)
        self.assertEqual([c["name"] for c in run.checks if not c["passed"]], [])
        self.assertEqual(
            run.facts["audit-serials-reference"],
            {"fromFirstMarker": 39, "highest": 39, "lostAtTheBootsStart": [(2, 38)]},
        )

    def test_a_phase_that_lost_records_fails(self) -> None:
        lost = {65: "kauditd_printk_skb: 3 callbacks suppressed"}
        self.assertEqual(
            self.failed(self.boot(lost)), ["the kernel lost no record from enter-1 on"]
        )

    def test_what_the_boot_s_start_dropped_is_recorded_only(self) -> None:
        run = gate()
        run.boots = [self.boot({5: "kauditd_printk_skb: 2 callbacks suppressed"})]
        quiet(run.judge_denials)
        self.assertEqual([c["name"] for c in run.checks if not c["passed"]], [])
        self.assertEqual(
            run.facts["lost-at-the-boots-start-reference"],
            ["kauditd_printk_skb: 2 callbacks suppressed"],
        )

    def test_the_baseline_is_the_decoy_before_the_first_entry(self) -> None:
        self.assertEqual(
            fg.Gate.baseline_labels(self.boot({})),
            {"boot-ready", "prep-decoy", "prep-after-check-journal", "control-1-start"},
        )
        # A denial a phase after the first session logs is new unless the
        # decoy logged it before the first entry; one a check logged is no
        # baseline.
        late = denial(161.0, 3, "rpm", "rpm_t")
        self.assertEqual(
            self.failed(self.boot({75: late})),
            ["no new denial from marker prep-drift on"],
        )
        early = denial(111.0, 4, "rpm", "rpm_t")
        self.assertEqual(self.failed(self.boot({25: early, 75: late})), [])
        in_check = denial(121.0, 4, "rpm", "rpm_t")
        self.assertEqual(
            self.failed(self.boot({35: in_check, 75: late})),
            [
                "no new denial from marker check-check-journal on",
                "no new denial from marker prep-drift on",
            ],
        )

    def test_without_dontaudit_rules_only_nails_s_new_denials_fail(self) -> None:
        # The policy's quiet denials of other programs show then: recorded.
        late = {75: denial(161.0, 3, "systemd-hwdb", "systemd_hwdb_t")}
        run = gate(dontaudit=False)
        run.boots = [self.boot(late)]
        quiet(run.judge_denials)
        self.assertEqual([c["name"] for c in run.checks if not c["passed"]], [])
        self.assertEqual(len(run.facts["noda-other-new"]["marker prep-drift"]), 1)
        nails = {75: denial(161.0, 3, "control")}
        run = gate(dontaudit=False)
        run.boots = [self.boot(nails)]
        quiet(run.judge_denials)
        self.assertEqual(
            [c["name"] for c in run.checks if not c["passed"]],
            ["no new denial from marker prep-drift on"],
        )

    def test_a_nails_denial_before_the_first_entry_still_counts(self) -> None:
        self.assertEqual(
            self.failed(self.boot({25: denial(111.0, 3, "control")})),
            ["no new denial from marker prep-decoy on"],
        )


if __name__ == "__main__":
    unittest.main()
