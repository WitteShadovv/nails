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
                f"/var/tmp/systemd-private-{boot}-chronyd.service-*",
                f"/var/tmp/systemd-private-{boot}-chronyd.service-*/tmp",
                f"/var/tmp/systemd-private-{boot}-dbus-broker.service-*/tmp/x",
            },
        )

    def test_another_filesystem_s_mount_point_is_left_out(self) -> None:
        listing = "/\n/nix/.ro-store\n/nix/store\n/etc/x\n/run"
        self.assertEqual(
            fg.changed_paths(listing, ["/nix/.ro-store", "/nix/store", "/run"]),
            {"/", "/etc/x"},
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
    BEFORE = {
        "d /run/systemd",
        "f /run/systemd/journal/streams/10:100",
        "f /run/nails-gate.toml",
    }

    def test_an_entry_the_session_left_at_any_depth_is_residue(self) -> None:
        link = "l /run/systemd/system/multi-user.target.wants/overlay-runtime-boot"
        after = {*self.BEFORE, link, "f /run/gate-probe-1"}
        self.assertEqual(
            fg.run_residue(self.BEFORE, after, []), ["f /run/gate-probe-1", link]
        )

    def test_a_shape_a_plain_soft_reboot_adds_is_no_residue(self) -> None:
        # Each start of the decoy opens new journal streams, named by their
        # device and inode.
        control = (
            {"f /run/systemd/journal/streams/10:200"},
            {
                "f /run/systemd/journal/streams/10:200",
                "f /run/systemd/journal/streams/10:345",
            },
        )
        after = {*self.BEFORE, "f /run/systemd/journal/streams/10:29536"}
        self.assertEqual(fg.run_residue(self.BEFORE, after, [control]), [])
        # A folder of the same name is another shape.
        odd = {*self.BEFORE, "d /run/systemd/journal/streams/10:29536"}
        self.assertEqual(
            fg.run_residue(self.BEFORE, odd, [control]),
            ["d /run/systemd/journal/streams/10:29536"],
        )

    def test_the_reconcile_pieces_that_stayed_are_left_to_their_check(
        self,
    ) -> None:
        wants = "/run/systemd/system/multi-user.target.wants"
        pieces = ["/run/overlay-runtime-boot", f"{wants}/overlay-runtime-boot.service"]
        after = {
            *self.BEFORE,
            "d /run/overlay-runtime-boot",
            "f /run/overlay-runtime-boot/control",
            f"d {wants}",
            f"l {wants}/overlay-runtime-boot.service",
            "f /run/left",
        }
        self.assertEqual(
            fg.run_residue(self.BEFORE, after, [], pieces), ["f /run/left"]
        )
        self.assertTrue(fg.of_pieces("l /run/overlay-runtime-boot -> x", pieces))
        self.assertFalse(fg.of_pieces("d /run/overlay-runtime-bootx", pieces))

    def test_reads_the_listing(self) -> None:
        listing = "d /run/a\nf /run/a/b c\n\nfind: oops\n"
        self.assertEqual(fg.run_entries(listing), {"d /run/a", "f /run/a/b c"})
        self.assertEqual(
            fg.run_shape("f /run/log/journal/0123456789abcdef0123/system@5.journal"),
            "f /run/log/journal/#/system@#.journal",
        )

    def test_judges_each_way_back_against_the_controls(self) -> None:
        run = gate()
        run.runs = {
            "control-1": ({"d /run/a"}, {"d /run/a", "f /run/s/1"}),
            "way-back-1": ({"d /run/a"}, {"d /run/a", "f /run/s/7", "f /run/left"}),
            "way-back-2": ({"d /run/a"}, {"d /run/a", "d /run/overlay-runtime-boot/x"}),
        }
        run.pieces = {2: ["/run/overlay-runtime-boot"]}
        quiet(run.judge_run)
        name = "nothing of the session stays in /run, at any depth"
        self.assertEqual(
            [(c["name"], c["passed"]) for c in run.checks],
            [(f"way back 1: {name}", False), (f"way back 2: {name}", True)],
        )
        self.assertEqual(run.facts["run-residue-way-back-1"], ["f /run/left"])
        # Without a control nothing is judged, so nothing passes.
        run = gate()
        run.runs = {"way-back-1": ({"d /run/a"}, {"d /run/a"})}
        quiet(run.judge_run)
        self.assertFalse(run.checks[0]["passed"])


def entry(
    transport: str,
    msg: str,
    pid: int | None = 1,
    serial: int | None = None,
    sent: int | None = None,
) -> dict[str, Any]:
    return {
        "transport": transport,
        "pid": pid,
        "who": "x",
        "unit": "",
        "auditId": serial,
        "sent": sent,
        "received": None,
        "msg": msg,
    }


class CarriedTest(unittest.TestCase):
    LATE = "GATELATE-n-1"
    ENTRIES = (
        entry("driver", "Journal started", pid=640),
        # The hidden root's last records, waiting in the sockets.
        entry("audit", "SERVICE_STOP unit=systemd-journald", serial=1272),
        entry("audit", "SERVICE_STOP unit=gate-late-1", serial=1276),
        entry("syslog", f"{LATE}-syslog", pid=12001, sent=733_126_747),
        entry("journal", f"{LATE}-native", pid=12003, sent=733_128_735),
        entry("stdout", f"{LATE}-stdout", pid=12001),
        entry("stdout", "Error: Device or resource busy", pid=12007),
        entry("syslog", "a hidden daemon's last line", pid=11990, sent=733_200_000),
        # The decoy's own start, after the switch.
        entry("audit", "AVC map policy.35", serial=1282),
        entry("journal", "Finished lvm2-monitor.service", sent=734_764_503),
        entry("stdout", "zram0: formatted", pid=650),
    )

    def test_sorts_what_the_hidden_root_sent_after_its_journald_stopped(self) -> None:
        found = fg.carried_records(self.ENTRIES, self.LATE, 1281, 734_000_000, 12000)
        self.assertEqual(len(found["late"]), 3)
        self.assertEqual(
            [line.split(":", 1)[1].strip() for line in found["audit"]],
            ["SERVICE_STOP unit=systemd-journald"],
        )
        self.assertEqual(len(found["datagram"]), 1)
        self.assertIn("a hidden daemon's last line", found["datagram"][0])
        self.assertEqual(len(found["stream"]), 1)
        self.assertIn("resource busy", found["stream"][0])

    def test_a_bound_it_lacks_judges_nothing_of_its_kind(self) -> None:
        found = fg.carried_records(self.ENTRIES, self.LATE, None, None, None)
        self.assertEqual(len(found["late"]), 3)
        self.assertEqual(
            (found["audit"], found["datagram"], found["stream"]), ([], [], [])
        )

    def test_the_late_writer_stops_after_the_hidden_journald(self) -> None:
        stop = "audit: type=1131 audit(1.0:{s}): pid=1 uid=0 msg='unit={u} comm=x'"
        log = [
            kmsg(1, stop.format(s=1, u="systemd-journald")),
            kmsg(2, stop.format(s=2, u="gate-late-1")),
            kmsg(3, "audit: type=1130 audit(1.0:3): msg='unit=gate-late-2 comm=x'"),
        ]
        self.assertIs(fg.stopped_after(log, "systemd-journald", "gate-late-1"), True)
        self.assertIs(fg.stopped_after(log, "gate-late-1", "systemd-journald"), False)
        # A start is no stop.
        self.assertIsNone(fg.stopped_after(log, "systemd-journald", "gate-late-2"))

    def test_the_late_writer_logs_through_each_socket(self) -> None:
        stop = fg.LATE_STOP.format(mark="M")
        self.assertIn("logger -t gatelate M-syslog", stop)
        self.assertIn("echo M-stdout", stop)
        self.assertIn("MESSAGE=M-native", stop)
        self.assertIn("logger --journald", stop)
        # systemd reads the line with its own quoting: one argument for sh.
        self.assertTrue(stop.startswith('/bin/sh -c "') and stop.endswith('"'))


def utmp(kind: str, pid: int = 0, line: str = "") -> dict[str, Any]:
    return {"type": kind, "pid": pid, "line": line}


class GettyTest(unittest.TestCase):
    def test_the_power_of_two_range(self) -> None:
        self.assertEqual(fg.pid_range(700), (512, 1023))
        self.assertEqual(fg.pid_range(1024), (1024, 2047))
        self.assertEqual(fg.pid_range(3175), (2048, 4095))
        self.assertEqual(fg.pid_range(0), (0, 0))

    def test_reads_the_consoles_of_the_last_start(self) -> None:
        wtmp = [
            utmp("BOOT_TIME"),
            utmp("INIT_PROCESS", 921, "tty1"),
            utmp("LOGIN_PROCESS", 921, "tty1"),
            utmp("BOOT_TIME"),
            utmp("RUN_LVL"),
            # kmscon on Fedora 45: the unit's record alone.
            utmp("INIT_PROCESS", 644, "tty1"),
            utmp("LOGIN_PROCESS", 671, "hvc0"),
            utmp("USER_PROCESS", 990, "tty1"),
            utmp("DEAD_PROCESS", 644, "tty1"),
            utmp("INIT_PROCESS", 3000, "tty1"),
        ]
        self.assertEqual(fg.getty_logins(wtmp), {"tty1": 644, "hvc0": 671})
        self.assertEqual(fg.getty_logins([utmp("LOGIN_PROCESS", 5, "tty1")]), {})

    def test_a_getty_numbered_from_the_session_fails(self) -> None:
        cold = {"ttyS0": 670}
        self.assertEqual(fg.getty_problems(cold, {"ttyS0": 702}, 12000), [])
        # No set-back: the number continues from the session's.
        self.assertEqual(len(fg.getty_problems(cold, {"ttyS0": 12040}, 12000)), 2)
        # Set back from a soft-reboot's numbers, not a cold boot's.
        soft = fg.getty_problems(cold, {"ttyS0": 3175}, 12000)
        self.assertIn("in (2048, 4095)", soft[0])
        self.assertTrue(fg.getty_problems(cold, {}, 12000))
        self.assertTrue(fg.getty_problems({}, {"ttyS0": 702}, 12000))
        self.assertTrue(fg.getty_problems(cold, {"ttyS0": 702}, None))


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
BOOT_COPY = "/run/overlay-runtime-boot/control"


def every_step(domain: str = "unconfined_service_t") -> list[str]:
    """A run of each step of NAILS from its copy in /run."""
    lines: list[str] = []
    for serial, step in enumerate(fg.NAILS_STEPS, 100):
        copy = BOOT_COPY if step == "reconcile-records" else COPY
        lines += run(serial, copy, domain, "--config", "/run/x.toml", step)
    return lines


class ExecTest(unittest.TestCase):
    def boot(self, *messages: str) -> dict[str, Any]:
        return {
            "why": "cold",
            "records": {seq: kmsg(seq, m) for seq, m in enumerate(messages, 1)},
        }

    def test_reads_what_the_rules_recorded(self) -> None:
        records = self.boot(
            *run(800, BOOT_COPY, "init_t", "reconcile-records", key=fg.EXEC_KEY),
            *run(801, "/usr/bin/true", "init_t", key="other"),
            *run(802, BOOT_COPY, "init_t", "reconcile-records", ran=False),
            "audit: type=1400 audit(1.0:803): avc:  denied  { map }",
        )["records"].values()
        found = fg.exec_records(records)
        self.assertEqual(
            [(r["key"], r["program"], r["step"], r["ran"]) for r in found],
            [
                (fg.EXEC_KEY, BOOT_COPY, "reconcile-records", True),
                (fg.EXEC_RUN_KEY, BOOT_COPY, "reconcile-records", False),
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
        # The policy refused the reconcile step: it never ran, so its domain
        # is unknown, and the copy it tried was labelled as runtime data.
        steps = [
            line
            for line in every_step()
            if "reconcile-records" not in line and BOOT_COPY not in line
        ]
        steps += run(
            104, BOOT_COPY, "init_t", "reconcile-records", key=fg.EXEC_KEY, ran=False
        )
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
