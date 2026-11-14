"""Unit tests for the kernel-log reading of the SELinux cells."""

from __future__ import annotations

import unittest

import selinux_cells as sc

KERNEL = (
    "audit: type=1400 audit(1731571234.567:123): avc:  denied  { read } for  "
    'pid=1234 comm="control" name="kmsg" dev="devtmpfs" ino=10 '
    "scontext=system_u:system_r:init_t:s0 "
    "tcontext=system_u:object_r:kmsg_device_t:s0 tclass=chr_file permissive=0"
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


class ParseTests(unittest.TestCase):
    def test_records_markers_and_drops(self) -> None:
        text = "\n".join(
            (
                kmsg(10, sc.marker("start", "n1")),
                " SUBSYSTEM=block",
                "#EPIPE",
                kmsg(12, KERNEL),
                kmsg(13, sc.marker("end", "n1")),
            )
        )
        records, dropped = sc.parse_kmsg(text)
        self.assertEqual(dropped, 1)
        self.assertEqual([r["seq"] for r in records], [10, 12, 13])
        self.assertEqual(records[0]["dict"], ["SUBSYSTEM=block"])
        self.assertEqual(sc.marker_seq(records, sc.marker("end", "n1")), 13)
        self.assertIsNone(sc.marker_seq(records, sc.marker("end", "n2")))
        self.assertEqual(sc.gaps([10, 12, 13]), [(11, 11)])

    def test_kernel_and_user_denials(self) -> None:
        kernel = sc.parse_avc(KERNEL)
        assert kernel is not None
        self.assertEqual(kernel["perms"], "read")
        self.assertEqual(kernel["comm"], "control")
        self.assertEqual(kernel["pid"], "1234")
        self.assertEqual(sc.context_type(kernel["scontext"]), "init_t")
        user = sc.parse_avc(USER)
        assert user is not None
        self.assertEqual(user["kind"], "user")
        self.assertEqual(user["pid"], "1")
        self.assertEqual(user["comm"], "/usr/lib/systemd/systemd")
        self.assertEqual(user["tclass"], "system")
        self.assertIsNone(sc.parse_avc("audit: type=1130 SERVICE_START"))

    def test_a_phase_counts_new_denials_by_source(self) -> None:
        records, _ = sc.parse_kmsg(
            "\n".join(
                (
                    kmsg(1, sc.marker("a", "n")),
                    kmsg(2, KERNEL),
                    kmsg(3, USER),
                    kmsg(
                        4,
                        KERNEL.replace('name="kmsg"', 'name="dsxtrace"').replace(
                            "pid=1234", "pid=99"
                        ),
                    ),
                    kmsg(5, sc.marker("b", "n")),
                )
            )
        )
        trace = sc.trace_lines(
            "uptime=1.0 pid=1234 ppid=1 current=x prev=y args=transition\n"
        )
        pids = sc.nails_pids(trace)
        summary = sc.phase(
            records, 1, 5, control=[sc.signature(sc.parse_avc(USER) or {})], pids=pids
        )
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["counted"], 2)
        self.assertEqual(summary["new"], 1)
        self.assertEqual(
            summary["bySource"], {"nails": 1, "pid1": 1, "instrumentation": 1}
        )
        self.assertEqual(summary["avcs"][0]["verb"], "transition")


if __name__ == "__main__":
    unittest.main()
