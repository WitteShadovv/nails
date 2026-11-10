"""Host-side tests for the report of a guest that stopped answering.

A fake QMP client stands in for QEMU: pressing Alt+ArrowUp prints a report of
PID 1's jobs to the fake console, and the SysRq keys print a dump line.
"""

from __future__ import annotations

import unittest
from typing import Any
from unittest import mock

from nails_e2e import stall

#: A report of the re-entry hang: local-fs.target's start job was held back
#: for a mount that lost its order, and waits for nothing now.
STUCK_REPORT = [
    stall.REPORT_BEGIN,
    "JOB UNIT                   TYPE  STATE",
    "64  sysinit.target         start waiting",
    "└─    \twaiting for job 61 (local-fs.target/start)",
    "61  local-fs.target        start waiting",
    "└─    \tblocking job 64 (sysinit.target/start)",
    "",
    "2 jobs listed.",
    "--- utab",
    "ID=26 SRC=tmpfs TARGET=/nix/.rw-store ROOT=/ OPTS=x-initrd.mount",
    stall.REPORT_END,
]


class FakeQmp:
    """Answers ``send-key`` the way the guest's console would."""

    def __init__(self, machine: FakeMachine, report: list[str] | None) -> None:
        self.machine = machine
        self.report = report
        self.sent: list[tuple[str, ...]] = []

    def send(self, cmd: str, args: dict[str, Any]) -> dict[str, Any]:
        keys = tuple(key["data"] for key in args["keys"])
        self.sent.append(keys)
        if keys == stall.REPORT_KEYS and self.report is not None:
            self.machine.full_console_log.extend(self.report)
        elif keys[:2] == ("alt", "sysrq"):
            self.machine.full_console_log.append(f"sysrq: dump {keys[2]}")
        return {"return": {}}


class FakeMachine:
    def __init__(self, report: list[str] | None = None) -> None:
        self.full_console_log: list[str] = ["boot"]
        self.logged: list[str] = []
        self.qmp_client: Any = FakeQmp(self, report)

    def log(self, msg: str) -> None:
        self.logged.append(msg)


def quick() -> Any:
    """The report's waits, shortened for a test."""
    return mock.patch.multiple(
        stall, REPORT_TIMEOUT_S=0.5, QUIET_S=0.05, DUMP_TIMEOUT_S=0.5
    )


class ReportTest(unittest.TestCase):
    def test_a_job_that_waits_for_nothing_is_named(self) -> None:
        machine = FakeMachine(STUCK_REPORT)
        with quick():
            why = stall.report(machine, "perf-activate-1")
        self.assertEqual(
            why, "PID 1 holds jobs that wait for no job: local-fs.target/start"
        )
        # The dumps come before the key press, which wakes PID 1.
        self.assertEqual(
            machine.qmp_client.sent,
            [("alt", "sysrq", "w"), ("alt", "sysrq", "t"), ("alt", "up")],
        )
        logged = machine.logged[-1]
        self.assertIn("local-fs.target", logged)
        self.assertIn("sysrq: dump w", logged)
        self.assertIn("sysrq: dump t", logged)

    def test_without_the_report_the_dumps_still_come(self) -> None:
        machine = FakeMachine(None)
        with quick():
            why = stall.report(machine, "power-off")
        self.assertEqual(why, "no report of PID 1's jobs")
        self.assertIn("sysrq: dump t", machine.logged[-1])

    def test_a_missing_qmp_socket_is_reported_not_raised(self) -> None:
        machine = FakeMachine(STUCK_REPORT)
        machine.qmp_client = None
        with quick():
            why = stall.report(machine, "power-off")
        self.assertTrue(why.startswith("no report of PID 1's jobs; "), why)
        self.assertIn("QMP is not connected", why)

    def test_jobs_with_something_to_wait_for_are_not_named(self) -> None:
        lines = [
            stall.REPORT_BEGIN,
            "70  poweroff.target    start waiting",
            "└─    \twaiting for job 71 (final.target/start)",
            "71  final.target       start running",
            stall.REPORT_END,
        ]
        self.assertEqual(stall.waiting_for_nothing(lines), [])
        self.assertEqual(stall.waiting_for_nothing(["no report"]), [])


if __name__ == "__main__":
    unittest.main()
