"""Host-side tests for the judgment of what the way back hands the decoy's
journal: a ring buffer and a decoy journal, as a Fedora 44 way back left them
before the way back emptied journald's sockets and quieted the tail."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from typing import Any

from nails_e2e import journal_tail
from nails_e2e.journal_tail import Record, judge_records, parse_journal, parse_kmsg

RING = "\n".join(
    (
        "6,1500,63000000,-;NAILSIN1",
        (
            "6,1501,63100000,-;audit: type=1131 audit(1794677720.878:716): pid=1"
            " uid=0 msg='unit=lvm2-monitor comm=\"systemd\" res=success'"
        ),
        (
            "30,1572,63865372,-;systemd[1]: Starting systemd-soft-reboot.service -"
            " Reboot System Userspace..."
        ),
        (
            "30,1573,63950921,-;systemd[1]: systemd-soft-reboot.service:"
            " Deactivated successfully."
        ),
        (
            "30,1574,63951148,-;systemd[1]: Finished systemd-soft-reboot.service -"
            " Reboot System Userspace."
        ),
        (
            "5,1575,63953147,-;audit: type=1130 audit(1794677720.975:717): pid=1"
            " uid=0 auid=4294967295 ses=4294967295"
            " subj=system_u:system_r:init_t:s0 msg='unit=systemd-soft-reboot"
            ' comm="systemd" exe="/usr/lib/systemd/systemd" hostname=? addr=?'
            " terminal=? res=success'"
        ),
        "29,1576,63955241,-;systemd[1]: Soft-rebooting.",
        (
            "5,1578,64000040,-;audit: type=1334 audit(1794677721.022:719):"
            " prog-id=186 op=UNLOAD"
        ),
        (
            "29,1579,64008283,-;systemd[1]: Sending SIGKILL to PID 2236"
            " (systemd-userdbd)."
        ),
        (
            "6,1593,64038253,-;EXT4-fs (dm-1): unmounting filesystem"
            " 4c60945a-a1f1-475c-a530-322790a578b9."
        ),
        (
            "5,1594,64040153,-;audit: type=1338 audit(1794677721.062:720):"
            ' module=crypt op=dtr ppid=2 pid=67 comm="kworker/u8:3" dev=252:1'
            " error_msg='success' res=1"
        ),
        (
            "5,1595,64045317,-;audit: type=1400 audit(1794677721.067:721): avc: "
            ' denied  { map } for  pid=1 comm="systemd"'
            ' path="/etc/selinux/targeted/policy/policy.35" dev="sda3" ino=2309'
            " scontext=system_u:system_r:init_t:s0"
            " tcontext=system_u:object_r:semanage_store_t:s0 tclass=file"
            " permissive=0"
        ),
        (
            "27,1596,64045346,-;systemd[1]: Failed to load new SELinux policy."
            " Continuing with old policy."
        ),
        ("4,1597,64052157,-;device-mapper: ioctl: remove_all left 1 open device(s)"),
        (
            "30,1598,64726387,-;systemd[1]: systemd 259.5-1.fc44 running in system"
            " mode (+PAM +AUDIT)"
        ),
        " SUBSYSTEM=foo",
        "6,1599,64726400,-;systemd[1]: Detected virtualization kvm.",
    )
)

UUID = "4c60945a-a1f1-475c-a530-322790a578b9"


def kernel(record: Record) -> dict[str, Any]:
    """The decoy journal's entry for a kmsg record."""
    entry: dict[str, Any] = {
        "_TRANSPORT": "kernel",
        "_SOURCE_MONOTONIC_TIMESTAMP": str(record.usec),
    }
    if record.text.startswith("systemd[1]: "):
        entry |= {
            "SYSLOG_IDENTIFIER": "systemd",
            "SYSLOG_PID": "1",
            "MESSAGE": record.text.removeprefix("systemd[1]: "),
        }
    else:
        entry |= {"SYSLOG_IDENTIFIER": "kernel", "MESSAGE": record.text}
    return entry


def journal(ring: list[Record], seqs: range | list[int]) -> list[dict[str, Any]]:
    return [kernel(r) for r in ring if r.seq in seqs]


class ParseTest(unittest.TestCase):
    def test_the_ring_skips_continuation_lines(self) -> None:
        ring = parse_kmsg(RING)
        self.assertEqual(ring[0], Record(1500, 63000000, "NAILSIN1"))
        self.assertNotIn("SUBSYSTEM=foo", [r.text for r in ring])
        self.assertEqual(ring[-1].seq, 1599)

    def test_a_message_in_bytes_reads_as_text(self) -> None:
        line = json.dumps({"MESSAGE": [104, 105], "_TRANSPORT": "stdout"})
        entries = parse_journal(line + "\nnot json\n\n")
        self.assertEqual(journal_tail.message(entries[0]), "hi")
        self.assertEqual(len(entries), 1)


class JudgeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.ring = parse_kmsg(RING)

    def judge(self, entries: list[dict[str, Any]]) -> journal_tail.Verdict:
        return judge_records(
            self.ring, entries, "NAILSIN1", ["NAILSLATE1", "lngr1", UUID]
        )

    def test_the_tail_as_the_cursor_alone_left_it_is_found(self) -> None:
        verdict = self.judge(journal(self.ring, range(1573, 1600)))
        self.assertTrue(verdict.judged)
        found = "\n".join(verdict.findings)
        self.assertIn("Sending SIGKILL to PID 2236", found)
        self.assertIn("unmounting filesystem", found)
        self.assertNotIn("Soft-rebooting", found)
        self.assertNotIn("Failed to load new SELinux policy", found)
        self.assertNotIn("type=1334", found)
        self.assertEqual(len(verdict.dm_teardown), 2)
        # Every ring record between the step's start and the decoy's first
        # line is listed, each marked as held.
        self.assertTrue(all(line.startswith("*") for line in verdict.tail))
        self.assertEqual(len(verdict.tail), 11)

    def test_the_quiet_tail_holds_only_the_generic_lines(self) -> None:
        held = [1573, 1574, 1575, 1576, 1578, 1594, 1595, 1596, 1597, 1598, 1599]
        verdict = self.judge(journal(self.ring, held))
        self.assertEqual(verdict.findings, [])
        self.assertEqual(len(verdict.dm_teardown), 2)

    def test_a_record_before_the_step_is_a_cursor_finding(self) -> None:
        verdict = self.judge(journal(self.ring, [1500, 1501, 1598]))
        self.assertEqual(
            [f.split(":")[0] for f in verdict.findings],
            ["before the cursor", "before the cursor"],
        )

    def test_a_planted_name_in_any_transport_is_found(self) -> None:
        entries = [
            {"_TRANSPORT": "stdout", "MESSAGE": "NAILSLATE1-stdout"},
            {"_TRANSPORT": "syslog", "MESSAGE": "NAILSLATE1-syslog"},
            {"_TRANSPORT": "journal", "MESSAGE": "NAILSLATE1-native"},
            {"_TRANSPORT": "journal", "MESSAGE": "decoy line"},
        ]
        verdict = self.judge(entries)
        self.assertEqual(len(verdict.findings), 3)

    def test_a_decoy_record_from_before_the_marker_names_nothing(self) -> None:
        entries = [
            {
                "_TRANSPORT": "kernel",
                "MESSAGE": f"EXT4-fs (loop0): mounted filesystem {UUID} r/w",
                "__MONOTONIC_TIMESTAMP": "62000000",
            },
            {
                "_TRANSPORT": "kernel",
                "MESSAGE": f"EXT4-fs (loop0): mounted filesystem {UUID} r/w",
                "__MONOTONIC_TIMESTAMP": "64800000",
            },
        ]
        verdict = self.judge(entries)
        self.assertEqual(len(verdict.findings), 1)

    def test_an_audit_record_of_the_hidden_root_is_found_by_its_serial(self) -> None:
        entries = [
            {
                "_TRANSPORT": "audit",
                "MESSAGE": "SERVICE_STOP unit=lvm2-monitor",
                "_AUDIT_ID": "716",
            },
            {
                "_TRANSPORT": "audit",
                "MESSAGE": "SERVICE_START unit=decoy",
                "_AUDIT_ID": "730",
            },
        ]
        verdict = self.judge(entries)
        self.assertEqual(len(verdict.findings), 1)
        self.assertIn("lvm2-monitor", verdict.findings[0])

    def test_the_step_s_start_is_found_by_its_description_too(self) -> None:
        ring = [
            r
            if "Starting systemd-soft-reboot" not in r.text
            else Record(
                r.seq, r.usec, "systemd[1]: Starting Reboot System Userspace..."
            )
            for r in self.ring
        ]
        self.assertTrue(judge_records(ring, [], "NAILSIN1", []).judged)

    def test_without_the_marker_or_the_step_nothing_is_judged(self) -> None:
        self.assertFalse(judge_records(self.ring, [], "NOPE", []).judged)
        ring = [r for r in self.ring if "Starting systemd-soft-reboot" not in r.text]
        self.assertFalse(judge_records(ring, [], "NAILSIN1", []).judged)
        ring = [r for r in self.ring if "running in system mode" not in r.text]
        self.assertFalse(judge_records(ring, [], "NAILSIN1", []).judged)


def with_controls(ring: list[Record]) -> list[Record]:
    """``ring`` with what the plants write when they ran: the hidden
    journald's stop and the late writer's record after it, before the step,
    and the lingering unit's record inside the step."""
    step = next(r for r in ring if "Starting systemd-soft-reboot" in r.text)
    added = [
        Record(1502, 63200000, "systemd[1]: Stopped Journal Service."),
        Record(1503, 63210000, "NAILSLATE1-sent-syslog"),
        Record(1504, 63220000, "NAILSLATE1-sent-native"),
        Record(1505, 63300000, "NAILSLATE1-kmsg"),
        Record(step.seq + 1, step.usec + 1, "lngr1-stopped"),
    ]
    moved = [Record(r.seq + 1, r.usec, r.text) if r.seq > step.seq else r for r in ring]
    return sorted(moved + added, key=lambda r: r.seq)


class ControlTest(unittest.TestCase):
    def judge(self, ring: list[Record]) -> journal_tail.Verdict:
        return judge_records(
            ring, [], "NAILSIN1", ["NAILSLATE1", "lngr1"], "NAILSLATE1", "lngr1"
        )

    def test_plants_that_ran_leave_nothing_to_find(self) -> None:
        verdict = self.judge(with_controls(parse_kmsg(RING)))
        self.assertTrue(verdict.judged)
        self.assertEqual(verdict.findings, [])

    def test_plants_that_never_ran_fail_the_judgment(self) -> None:
        found = "\n".join(self.judge(parse_kmsg(RING)).findings)
        self.assertIn("the late writer did not log", found)
        self.assertIn("the lingering unit did not run", found)

    def test_a_late_line_before_journald_stopped_proves_nothing(self) -> None:
        ring = [
            Record(r.seq, r.usec, "x") if "Stopped Journal Service" in r.text else r
            for r in with_controls(parse_kmsg(RING))
        ]
        ring.append(Record(1499, 62900000, "systemd[1]: Stopped Journal Service."))
        ring.sort(key=lambda r: r.seq)
        found = self.judge(ring).findings
        self.assertEqual(len(found), 1)
        self.assertIn("the late writer did not log", found[0])

    def test_a_channel_closed_before_the_late_writer_is_not_judged(self) -> None:
        ring = [
            r
            if r.text != "NAILSLATE1-sent-native"
            else Record(
                r.seq,
                r.usec,
                "systemd[1]: systemd-journald.socket: Failed with result 'resources'.",
            )
            for r in with_controls(parse_kmsg(RING))
        ]
        verdict = self.judge(ring)
        self.assertEqual(verdict.findings, [])
        self.assertEqual(verdict.closed, ["native"])
        # An open socket that took no line fails the judgment.
        ring = [r for r in ring if "Failed with result" not in r.text]
        found = self.judge(ring).findings
        self.assertEqual(len(found), 1)
        self.assertIn("native line did not go out", found[0])

    def test_journald_s_sockets_opened_anew_by_the_decoy_are_found(self) -> None:
        ring = with_controls(parse_kmsg(RING))
        last = ring[-1]
        for n, text in enumerate(
            (
                "systemd[1]: Listening on systemd-journald.socket - Journal Sockets.",
                "systemd[1]: Listening on Journal Socket (/dev/log).",
                "systemd[1]: Listening on Journal Audit Socket.",
                "systemd[1]: Listening on systemd-udevd-control.socket - udev "
                "Control Socket.",
            ),
            start=1,
        ):
            ring.append(Record(last.seq + n, last.usec + n, text))
        found = self.judge(ring).findings
        self.assertEqual(len(found), 4, found)
        self.assertEqual(
            [f.split(":")[0] for f in found],
            ["the decoy's start opened journald's socket anew"] * 3
            + ["the decoy's start opened udevd's socket anew"],
        )
        # One the hidden start opened anew after the entry, as the decoy's own
        # shutdown had closed it, may be opened anew after the way back too.
        entry = [
            Record(1400, 50000000, "systemd[1]: systemd 259 running in system mode"),
            Record(
                1401,
                50000100,
                "systemd[1]: Listening on systemd-journald.socket - Journal Sockets.",
            ),
            Record(1402, 50000200, "systemd[1]: Listening on udev Control Socket."),
        ]
        found = self.judge(entry + ring).findings
        self.assertEqual(len(found), 2, found)
        self.assertIn("(/dev/log)", found[0])
        self.assertIn("Journal Audit Socket", found[1])

    def test_udevd_s_kernel_socket_opened_anew_by_the_decoy_is_found(self) -> None:
        # Stopped before the restores' events, udevd leaves PID 1 to fail its
        # kernel socket inside the soft-reboot, and the decoy opens it anew.
        ring = with_controls(parse_kmsg(RING))
        last = ring[-1]
        for n, text in enumerate(
            (
                "systemd[1]: Listening on systemd-udevd-kernel.socket - udev "
                "Kernel Socket.",
                "systemd[1]: Listening on udev Kernel Socket.",
            ),
            start=1,
        ):
            ring.append(Record(last.seq + n, last.usec + n, text))
        found = self.judge(ring).findings
        self.assertEqual(len(found), 2, found)
        self.assertTrue(all("opened udevd's socket anew" in f for f in found))
        self.assertEqual(
            [journal_tail.reopened(r.text) for r in ring[-2:]],
            ["udev-kernel", "udev-kernel"],
        )
        self.assertIsNone(journal_tail.reopened("systemd[1]: Listening on D-Bus."))


class AllowedTest(unittest.TestCase):
    def test_the_generic_lines_of_each_family_are_allowed(self) -> None:
        for line in (
            "Finished Reboot System Userspace.",
            "Finished systemd-soft-reboot.service - Reboot System Userspace.",
            "Sending SIGKILL to PID 387 ((sd-close)).",
            "Sending SIGKILL to PID 3393 (systemd-udevd).",
            "Sending SIGKILL to PID 3394 ((udev-worker)).",
        ):
            self.assertTrue(
                any(p.fullmatch(line) for p in journal_tail.HIDDEN_PID1_LINES), line
            )
        for line in (
            "Sending SIGKILL to PID 2236 (systemd-userdbd).",
            "Sending SIGKILL to PID 3395 (udev-worker).",
            "Sending SIGKILL to PID 3396 (lngr-udevd).",
            "late-writer.service: Failed with result 'exit-code'.",
        ):
            self.assertFalse(
                any(p.fullmatch(line) for p in journal_tail.HIDDEN_PID1_LINES), line
            )


class CommandTest(unittest.TestCase):
    def test_the_late_stop_logs_through_each_socket(self) -> None:
        stop = journal_tail.late_stop_command("/usr/bin/logger", "M")
        self.assertIn("-t late M-syslog", stop)
        self.assertIn("echo M-stdout", stop)
        self.assertIn("MESSAGE=M-native\\\\nSYSLOG_IDENTIFIER=late", stop)
        self.assertIn("| /usr/bin/logger --journald", stop)
        self.assertIn("M-syslog && echo M-sent-syslog > /dev/kmsg;", stop)
        self.assertIn("--journald && echo M-sent-native > /dev/kmsg;", stop)
        self.assertTrue(stop.endswith('; echo M-kmsg > /dev/kmsg"'), stop)
        self.assertNotIn("$", stop)

    def test_the_linger_stop_writes_to_run_and_then_says_so(self) -> None:
        self.assertEqual(
            journal_tail.linger_stop_command("L"),
            '/bin/sh -c "echo L > /run/L-stop && echo L-stopped > /dev/kmsg"',
        )


class UdevDatabase:
    """A machine whose ``/run/udev/data`` is a folder of the host, where each
    command runs in a shell."""

    def __init__(self, data: str) -> None:
        self.data = data
        self.commands: list[str] = []

    def succeed(self, *commands: str) -> str:
        out = ""
        for command in commands:
            self.commands.append(command)
            if command.startswith(("ip ", "udevadm ")):
                continue
            out += subprocess.run(
                ["sh", "-c", command.replace("/run/udev/data", self.data)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        return out


class LinkTest(unittest.TestCase):
    def test_only_a_record_that_names_the_link_counts(self) -> None:
        with tempfile.TemporaryDirectory() as data:
            machine = UdevDatabase(data)
            self.assertEqual(journal_tail.udev_records_of(machine, "nl1"), [])
            for name, text in (
                ("n3", "I:1\nE:ID_NET_NAME=nl1\nE:ID_NET_DRIVER=dummy\n"),
                ("n4", "E:INTERFACE=nl1\n"),
                ("n5", "E:ID_NET_NAME=nl10\nE:ID_NET_NAME_MAC=nl1\n"),
                ("b8:0", "E:ID_NET_NAME=nl1\n"),
            ):
                with open(os.path.join(data, name), "w", encoding="utf-8") as handle:
                    handle.write(text)
            found = journal_tail.udev_records_of(machine, "nl1")
            self.assertEqual(sorted(os.path.basename(f) for f in found), ["n3", "n4"])

    def test_the_plant_proves_udevd_recorded_its_link(self) -> None:
        with tempfile.TemporaryDirectory() as data:
            machine = UdevDatabase(data)
            with self.assertRaises(AssertionError):
                journal_tail.plant_link(machine, "nl1")
            self.assertEqual(
                machine.commands[:3],
                [
                    "ip link add nl1 type dummy",
                    "ip link set nl1 up",
                    "udevadm settle -t 30",
                ],
            )
            with open(os.path.join(data, "n3"), "w", encoding="utf-8") as handle:
                handle.write("E:ID_NET_NAME=nl1\n")
            journal_tail.plant_link(machine, "nl1")


if __name__ == "__main__":
    unittest.main()
