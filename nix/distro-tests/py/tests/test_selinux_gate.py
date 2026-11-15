"""Tests for selinux_gate, the kernel-log reading of the Fedora gate."""

from __future__ import annotations

import json
import unittest

import selinux_gate as sg

KERNEL = (
    "audit: type=1400 audit(1731571234.567:123): avc:  denied  { read } for  "
    'pid=1234 comm="control" name="kmsg" dev="devtmpfs" ino=10 '
    "scontext=system_u:system_r:init_t:s0 "
    "tcontext=system_u:object_r:kmsg_device_t:s0 tclass=chr_file permissive=0"
)
POLICY_MAP = (
    "audit: type=1400 audit(1731571234.600:124): avc:  denied  { map } for  "
    'pid=1 comm="systemd" path="/etc/selinux/targeted/policy/policy.35" '
    'dev="sda3" ino=2309 scontext=system_u:system_r:init_t:s0 '
    "tcontext=system_u:object_r:semanage_store_t:s0 tclass=file permissive=0"
)
AGETTY = (
    "audit: type=1400 audit(1731571235.000:125): avc:  denied  { read } for  "
    'pid=812 comm="agetty" name="22_clhm_ens4.issue" dev="sda3" ino=77 '
    "scontext=system_u:system_r:getty_t:s0-s0:c0.c1023 "
    "tcontext=system_u:object_r:NetworkManager_dispatcher_console_var_run_t:s0 "
    "tclass=file permissive=0"
)
OTHER = (
    "audit: type=1400 audit(1731571236.000:126): avc:  denied  { write } for  "
    'pid=900 comm="chronyd" name="drift" dev="sda3" ino=78 '
    "scontext=system_u:system_r:chronyd_t:s0 "
    "tcontext=system_u:object_r:var_lib_t:s0 tclass=file permissive=0"
)
USER = (
    "audit: type=1107 audit(1731571234.600:124): pid=1 uid=0 auid=4294967295 "
    "ses=4294967295 subj=system_u:system_r:init_t:s0 msg='avc:  denied  "
    '{ status } for auid=n/a uid=0 gid=0 path="/run/x" cmdline="" '
    "scontext=system_u:system_r:unconfined_service_t:s0 "
    "tcontext=system_u:system_r:init_t:s0 tclass=system permissive=0 "
    'exe="/usr/lib/systemd/systemd" sauid=0 hostname=? addr=? terminal=?\''
)


def kmsg(seq: int, msg: str) -> str:
    return f"6,{seq},{seq * 1000},-;{msg}"


def records(*messages: str) -> list[dict[str, object]]:
    parsed, _ = sg.parse_kmsg(
        "\n".join(kmsg(seq, msg) for seq, msg in enumerate(messages, start=1))
    )
    return parsed


class ParseTest(unittest.TestCase):
    def test_records_markers_and_drops(self) -> None:
        text = "\n".join(
            (
                kmsg(10, sg.marker("start", "n1")),
                " SUBSYSTEM=block",
                "#EPIPE",
                kmsg(12, KERNEL),
                kmsg(13, sg.marker("end", "n1")),
            )
        )
        parsed, dropped = sg.parse_kmsg(text)
        self.assertEqual(dropped, 1)
        self.assertEqual([r["seq"] for r in parsed], [10, 12, 13])
        self.assertEqual(parsed[0]["dict"], ["SUBSYSTEM=block"])
        self.assertEqual(sg.marker_seq(parsed, sg.marker("end", "n1")), 13)
        self.assertIsNone(sg.marker_seq(parsed, sg.marker("end", "n2")))
        self.assertEqual(sg.gaps([10, 12, 13]), [(11, 11)])

    def test_merge_keeps_each_record_once(self) -> None:
        known: dict[int, dict[str, object]] = {}
        sg.merge(known, records("a", "b"))
        sg.merge(known, records("a", "b", "c"))
        self.assertEqual(sorted(known), [1, 2, 3])

    def test_the_reader_takes_the_first_sequence_number(self) -> None:
        command = sg.kmsg_command(42)
        self.assertTrue(command.startswith("python3 - 42 <<'GATEEOF'\n"))
        self.assertIn("/dev/kmsg", command)


class DenialTest(unittest.TestCase):
    def test_kernel_and_user_denials(self) -> None:
        kernel = sg.parse_avc(KERNEL)
        assert kernel is not None
        self.assertEqual(
            (kernel["perms"], kernel["comm"], kernel["pid"]),
            ("read", "control", "1234"),
        )
        self.assertEqual(sg.context_type(kernel["scontext"]), "init_t")
        user = sg.parse_avc(USER)
        assert user is not None
        self.assertEqual((user["kind"], user["pid"]), ("user", "1"))
        self.assertEqual(user["comm"], "/usr/lib/systemd/systemd")
        self.assertIsNone(sg.parse_avc("audit: type=1130 SERVICE_START"))

    def test_sources(self) -> None:
        def of(message: str) -> str:
            avc = sg.parse_avc(message)
            assert avc is not None
            return sg.source(avc)

        self.assertEqual(of(KERNEL), "nails")
        self.assertEqual(of(POLICY_MAP), "pid1")
        self.assertEqual(of(OTHER), "other")
        under_runtime = OTHER.replace('name="drift"', 'name="/run/overlay-runtime/x"')
        self.assertEqual(of(under_runtime), "nails")

    def test_the_signature_leaves_out_process_numbers(self) -> None:
        first = sg.parse_avc(AGETTY)
        second = sg.parse_avc(AGETTY.replace("pid=812", "pid=9000"))
        assert first is not None and second is not None
        self.assertEqual(sg.signature(first), sg.signature(second))
        self.assertIn(sg.signature(first), sg.IMAGE_RACES)


class PhaseTest(unittest.TestCase):
    def test_new_denials_are_nails_own_or_unseen_without_nails(self) -> None:
        found = sg.phase(
            records(sg.marker("a", "n"), KERNEL, POLICY_MAP, AGETTY, OTHER, "x"),
            1,
            6,
            baseline=[sg.signature(sg.parse_avc(POLICY_MAP) or {})],
        )
        whys = {avc["comm"]: avc["why"] for avc in found["denials"]}
        self.assertEqual(
            whys,
            {
                "control": "a NAILS process or path",
                "systemd": "also without NAILS in this run",
                "agetty": "the image's own race",
                "chronyd": "not seen without NAILS",
            },
        )
        self.assertEqual([avc["comm"] for avc in found["new"]], ["control", "chronyd"])

    def test_a_nails_denial_is_new_even_when_the_baseline_has_it(self) -> None:
        signature = sg.signature(sg.parse_avc(KERNEL) or {})
        found = sg.phase(records(KERNEL), None, None, baseline=[signature])
        self.assertEqual(len(found["new"]), 1)

    def test_the_bounds_are_exclusive(self) -> None:
        found = sg.phase(records(OTHER, OTHER, OTHER), 1, 3)
        self.assertEqual([avc["seq"] for avc in found["denials"]], [2])

    def test_names_what_the_log_dropped_and_the_policy_loads(self) -> None:
        found = sg.phase(
            records(
                "audit: audit_lost=3 audit_backlog=65 backlog limit exceeded",
                "systemd[1]: Failed to load new SELinux policy. Continuing.",
            ),
            None,
            None,
        )
        self.assertEqual(len(found["suppressed"]), 1)
        self.assertEqual(len(found["policy"]), 1)


class CursorTest(unittest.TestCase):
    def session(self) -> list[dict[str, object]]:
        return records(
            "booted",
            sg.marker("enter-1", "n"),
            "hidden kernel line",
            sg.marker("leave-1", "n"),
            "systemd[1]: Soft-rebooting.",
            "systemd[1]: systemd 259.5-1.fc44 running in system mode",
            sg.marker("back-1", "n"),
        )

    @staticmethod
    def journal(*seqs: int) -> str:
        return "\n".join(
            json.dumps({"_SOURCE_MONOTONIC_TIMESTAMP": str(seq * 1000), "MESSAGE": "x"})
            for seq in seqs
        )

    def test_a_record_of_the_session_in_the_decoy_journal_is_a_leak(self) -> None:
        found = sg.cursor(self.session(), self.journal(3, 5, 6, 7), 2, 4, 7)
        self.assertTrue(found["known"])
        self.assertEqual((found["stepEnd"], found["newUserspace"]), (5, 6))
        self.assertEqual(found["leakedFromSession"], 1)
        self.assertEqual(found["afterStep"], 1)

    def test_the_records_after_the_step_are_no_leak(self) -> None:
        found = sg.cursor(self.session(), self.journal(5, 6, 7), 2, 4, 7)
        self.assertEqual(found["leakedFromSession"], 0)

    def test_nothing_is_judged_without_the_step_end(self) -> None:
        found = sg.cursor(self.session()[:4], self.journal(3), 2, 4, None)
        self.assertFalse(found["known"])
        self.assertEqual(found["leakedFromSession"], 0)

    def test_a_list_message_is_decoded(self) -> None:
        entry = {"_SOURCE_MONOTONIC_TIMESTAMP": "5000", "MESSAGE": [104, 105]}
        self.assertEqual(
            sg.journal_records(json.dumps(entry)), [{"us": 5000, "msg": "hi"}]
        )


AUDIT_LOG = "\n".join(
    (
        # A record of the boot before: left out by its time.
        "type=DAEMON_START msg=audit(1794686000.000:1): op=start ver=4.1.2 res=1",
        "type=AVC msg=audit(1794686740.123:57): avc:  denied  { read } for  "
        'pid=1234 comm="control" name="kmsg" dev="devtmpfs" ino=10 '
        "scontext=system_u:system_r:init_t:s0 "
        "tcontext=system_u:object_r:kmsg_device_t:s0 tclass=chr_file "
        "permissive=0",
        "type=SYSCALL msg=audit(1794686740.123:57): arch=c000003e syscall=257 "
        'success=no exit=-13 pid=1234 comm="control" '
        'exe="/run/overlay-runtime/control"\x1dARCH=x86_64 SYSCALL=openat '
        'AUID="unset"',
        "type=USER_AVC msg=audit(1794686741.500:58): pid=1 uid=0 "
        "auid=4294967295 ses=4294967295 subj=system_u:system_r:init_t:s0 "
        "msg='avc:  denied  { status } for auid=n/a uid=0 gid=0 "
        'path="/run/x" cmdline="" '
        "scontext=system_u:system_r:unconfined_service_t:s0 "
        "tcontext=system_u:system_r:init_t:s0 tclass=system permissive=0 "
        "exe=\"/usr/lib/systemd/systemd\" sauid=0 hostname=? addr=? "
        "terminal=?'\x1dUID=\"root\" AUID=\"unset\" SAUID=\"root\"",
        "type=SELINUX_ERR msg=audit(1794686742.000:59): "
        "op=security_compute_sid "
        'invalid_context="system_u:system_r:foo_t:s0" '
        "scontext=system_u:system_r:init_t:s0 "
        "tcontext=system_u:object_r:bin_t:s0 tclass=process",
        "type=SYSCALL msg=audit(1794686742.000:59): arch=c000003e syscall=59 "
        'success=no exit=-13 pid=999 comm="control" '
        'exe="/run/overlay-runtime/control"',
        "not a record",
    )
)


class AuditLogTest(unittest.TestCase):
    def test_reads_the_records_of_the_boot_as_the_kernel_log_prints_them(
        self,
    ) -> None:
        found = sg.audit_log(AUDIT_LOG, 1794686700)
        self.assertEqual([r["serial"] for r in found], [57, 57, 58, 59, 59])
        self.assertTrue(found[0]["msg"].startswith("audit: type=1400 audit("))
        self.assertEqual(found[0]["time"], 1794686740.123)
        self.assertNotIn("ARCH=", found[1]["msg"])
        self.assertTrue(found[2]["msg"].startswith("audit: type=1107 "))

    def test_its_denials_and_errors_are_judged_as_the_kernel_logs(self) -> None:
        found = sg.audit_denials(sg.audit_log(AUDIT_LOG, 1794686700))
        self.assertEqual(
            [(a["kind"], a["comm"], a["source"]) for a in found],
            [
                ("kernel", "control", "nails"),
                ("user", "/usr/lib/systemd/systemd", "pid1"),
                ("error", "control", "nails"),
            ],
        )
        self.assertEqual(found[2]["perms"], "security_compute_sid")
        self.assertEqual(
            found[2]["signature"].split()[:2], ["error", "{security_compute_sid}"]
        )
        self.assertEqual({a["log"] for a in found}, {"audit"})
        self.assertEqual(found[0]["time"], 1794686740.123)

    def test_a_phase_judges_the_audit_records_with_the_kernel_ones(self) -> None:
        audit = sg.audit_log(AUDIT_LOG, 1794686700)
        found = sg.phase(records(OTHER), None, None, audit=audit)
        self.assertEqual(
            [avc["log"] for avc in found["denials"]],
            ["kernel", "audit", "audit", "audit"],
        )
        self.assertEqual(len(found["new"]), 4)


BOOTS = "\n".join(
    (
        # The boot before: its own start and records, in the same log.
        "type=DAEMON_START msg=audit(1794686000.000:3001): op=start res=1",
        "type=SERVICE_START msg=audit(1794686001.000:40): pid=1 res=success",
        "type=DAEMON_END msg=audit(1794686300.000:3002): op=terminate res=1",
        # This boot: auditd starts and writes the records it holds from 1 on.
        "type=DAEMON_START msg=audit(1794686399.500:3636): op=start res=1",
        "type=SYSTEM_BOOT msg=audit(1794686399.000:1): pid=1 res=success",
        "type=SERVICE_START msg=audit(1794686400.000:2): pid=1 res=success",
        "type=DAEMON_END msg=audit(1794686500.000:3637): op=terminate res=1",
    )
)


class BootAuditLogTest(unittest.TestCase):
    def test_takes_the_records_after_the_boot_s_own_start(self) -> None:
        records, info = sg.boot_audit_log(BOOTS, 1794686400)
        self.assertEqual([r["serial"] for r in records], [1, 2])
        self.assertEqual(info["start"], 1794686399.5)
        self.assertEqual(info["serials"], [1, 2])

    def test_takes_nothing_without_a_start_of_this_boot(self) -> None:
        # auditd did not start in this boot: its last start is the boot
        # before's, whose serial numbers are another boot's.
        records, info = sg.boot_audit_log(BOOTS, 1794690000)
        self.assertEqual(records, [])
        self.assertEqual(info["start"], 1794686399.5)
        self.assertEqual(sg.boot_audit_log("", 1794690000)[0], [])

    def test_a_clock_step_within_the_slack_keeps_the_start(self) -> None:
        records, _ = sg.boot_audit_log(BOOTS, 1794686399.5 + 100)
        self.assertEqual([r["serial"] for r in records], [1, 2])


class SerialTest(unittest.TestCase):
    def test_the_serials_of_kernel_and_audit_records(self) -> None:
        self.assertEqual(
            sg.audit_serials([KERNEL, POLICY_MAP, "no record"]), {123, 124}
        )
        early = "audit: type=2000 audit(0.123:1): state=initialized res=1"
        self.assertEqual(sg.serial_of(early), 1)

    def test_a_boot_numbers_its_records_from_one(self) -> None:
        self.assertEqual(sg.serial_gaps([1, 2, 3]), [])
        self.assertEqual(sg.serial_gaps([3, 1, 2, 2]), [])
        self.assertEqual(sg.serial_gaps([1, 2, 5, 6]), [(3, 4)])
        self.assertEqual(sg.serial_gaps([4, 5]), [(1, 3)])
        self.assertEqual(sg.serial_gaps([]), [])

    def test_judges_the_serials_from_a_first_one_on(self) -> None:
        self.assertEqual(sg.serial_gaps([1, 39, 40, 42], 39), [(41, 41)])
        self.assertEqual(sg.serial_gaps([1, 40], 39), [(39, 39)])
        self.assertEqual(sg.serial_gaps([1, 2], 39), [])


class SelinuxErrorTest(unittest.TestCase):
    def test_a_kernel_error_takes_its_event_s_process(self) -> None:
        error = (
            "audit: type=1401 audit(1731571236.000:200): "
            "op=security_bounded_transition "
            "seresult=denied oldcontext=system_u:system_r:init_t:s0 "
            "newcontext=system_u:system_r:unconfined_service_t:s0"
        )
        call = (
            "audit: type=1300 audit(1731571236.000:200): arch=c000003e syscall=59 "
            'pid=77 comm="control" exe="/run/overlay-runtime/control"'
        )
        found = sg.denials(records(error, call), None, None)
        self.assertEqual(len(found), 1)
        self.assertEqual(
            (found[0]["kind"], found[0]["comm"], found[0]["source"], found[0]["seq"]),
            ("error", "control", "nails", 1),
        )
        self.assertEqual(sg.context_type(found[0]["scontext"]), "init_t")

    def test_a_denial_is_no_error_and_a_notice_is_neither(self) -> None:
        self.assertIsNone(sg.parse_selinux_err(KERNEL))
        notice = (
            "audit: type=1107 audit(1.0:3): pid=1 msg='avc:  received policyload "
            "notice (seqno=2) exe=\"/usr/lib/systemd/systemd\"'"
        )
        self.assertIsNone(sg.parse_avc(notice))
        self.assertIsNone(sg.parse_selinux_err(notice))


class SuppressedTest(unittest.TestCase):
    def test_names_the_kernel_s_notices_of_lost_records(self) -> None:
        lost = (
            "kauditd_printk_skb: 12 callbacks suppressed",
            "audit: audit_lost=1 audit_rate_limit=0 audit_backlog_limit=64",
            "audit: backlog limit exceeded",
            "audit: kauditd hold queue overflow",
        )
        found = sg.phase(records(*lost), None, None)
        self.assertEqual(len(found["suppressed"]), len(lost))

    def test_a_backlog_setting_is_no_loss(self) -> None:
        setting = (
            "audit: type=1305 audit(1.0:4): op=set audit_backlog_limit=8192 "
            "old=64 auid=4294967295 ses=4294967295 res=1"
        )
        self.assertEqual(sg.phase(records(setting), None, None)["suppressed"], [])


class LimitsTest(unittest.TestCase):
    def test_the_kernel_prints_only_warnings_and_worse_to_the_console(self) -> None:
        # Its notices, the audit records among them, would split the
        # backdoor's announcement on the serial console.
        self.assertIn("'kernel.printk=5 4 1 7'", sg.KMSG_LIMITS)
        self.assertIn("'kernel.printk_ratelimit=0'", sg.KMSG_LIMITS)


class SmallTest(unittest.TestCase):
    def test_the_seqnum_of_the_cursor_file(self) -> None:
        self.assertEqual(sg.seqnum_from_od(" 1234\n"), 1234)
        self.assertIsNone(sg.seqnum_from_od(""))
        self.assertIsNone(sg.seqnum_from_od("1 2"))

    def test_unconfined_domains(self) -> None:
        self.assertTrue(sg.unconfined("system_u:system_r:unconfined_service_t:s0"))
        self.assertTrue(
            sg.unconfined("unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023\x00")
        )
        self.assertFalse(sg.unconfined("system_u:system_r:init_t:s0"))
        self.assertFalse(sg.unconfined("system_u:system_r:udev_t:s0"))


if __name__ == "__main__":
    unittest.main()
