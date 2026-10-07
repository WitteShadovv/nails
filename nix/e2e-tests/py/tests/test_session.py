"""Host-side tests for the whole-root session helpers.

A fake machine stands in for the driver's node: its console log is a list the
test appends to, so following a soft-reboot is exercised without a VM.
"""

from __future__ import annotations

import unittest
from typing import Any

from nails_e2e import session


class FakeMachine:
    """A node whose console prints ``lines`` once the trigger has run."""

    def __init__(self, lines: list[str], outputs: dict[str, str] | None = None) -> None:
        self.connected = True
        self.full_console_log: list[str] = ["boot"]
        self.pending = lines
        self.outputs = outputs or {}
        self.connects = 0
        self.logged: list[str] = []
        self.process: Any = None

    def succeed(self, *commands: str, timeout: int | None = None) -> str:
        for prefix, out in self.outputs.items():
            if commands[0].startswith(prefix):
                return out
        if "uptime" in commands[0]:
            return "10.0"
        return ""

    def execute(
        self,
        command: str,
        check_return: bool = True,
        check_output: bool = True,
        timeout: int | None = 900,
    ) -> tuple[int, str]:
        if command.endswith("&"):
            self.full_console_log.extend(self.pending)
        return (0, "")

    def connect(self) -> None:
        self.connects += 1
        self.connected = True

    def log(self, msg: str) -> None:
        self.logged.append(msg)

    def wait_for_unit(
        self, unit: str, user: str | None = None, timeout: int = 900
    ) -> Any:
        return None

    def wait_for_shutdown(self) -> None:
        self.connected = False

    def get_console_log(self) -> str:
        return "\n".join(self.full_console_log)


class FollowSoftRebootTest(unittest.TestCase):
    def test_reconnects_once_the_new_backdoor_announces_itself(self) -> None:
        machine = FakeMachine(
            ["Soft-rebooting.", "backdoor: connecting to host..."],
            {
                "systemctl show": "ShutdownStartTimestampMonotonic=1000000\n"
                "UserspaceTimestampMonotonic=2000000\nFinishTimestampMonotonic=9000000\n"
            },
        )
        timings = session.follow_soft_reboot(
            machine, "nails activate -y", "enter", deadline_s=5
        )
        self.assertEqual(machine.connects, 1)
        self.assertEqual(timings["shutdown_phase"], 1.0)
        self.assertEqual(timings["startup_phase"], 7.0)
        self.assertEqual(timings["grey_out"], 8.0)

    def test_a_userspace_in_emergency_mode_fails_at_once(self) -> None:
        machine = FakeMachine(
            ["Timed out waiting for device", "Reached target Emergency Mode"]
        )
        with self.assertRaises(AssertionError) as raised:
            session.follow_soft_reboot(machine, "true", "leave", deadline_s=5)
        self.assertIn("stuck", str(raised.exception))
        self.assertEqual(machine.connects, 0)


class TriggerFailureTest(unittest.TestCase):
    def test_a_failed_trigger_stops_the_wait_at_once(self) -> None:
        machine = FakeMachine(["activation failed", "nails-trigger-exit=1"])
        with self.assertRaises(AssertionError) as raised:
            session.follow_soft_reboot(
                machine, "nails activate -y", "enter", deadline_s=5
            )
        self.assertIn("exit status 1", str(raised.exception))

    def test_a_zero_exit_is_not_a_failure(self) -> None:
        self.assertIsNone(session.trigger_failure(["nails-trigger-exit=0"]))


class PureHelpersTest(unittest.TestCase):
    def test_pid1_timestamps_are_read_in_seconds(self) -> None:
        values = session.parse_pid1_timestamps("A=1500000\nB=\nC=x\n")
        self.assertEqual(values, {"A": 1.5})

    def test_stuck_lines_name_the_markers_only(self) -> None:
        self.assertEqual(
            session.stuck_lines(["ok", "Freezing execution.", "fine"]),
            ["Freezing execution."],
        )

    def test_carried_residue_is_what_was_not_there_before(self) -> None:
        machine = FakeMachine([], {"find /run": "/run/a\n/run/b\n/run/nextroot\n"})
        residue = session.carried_run_residue(machine, {"/run/a"}, "100")
        self.assertEqual(residue, ["/run/b"])


if __name__ == "__main__":
    unittest.main()
