"""Host-side tests for the operator-session helpers of the alert tests.

A fake machine stands in for the driver's node: it records the commands the
helpers run and answers ``cat`` with the records the notification server would
have written.
"""

from __future__ import annotations

import json
import subprocess
import unittest

from nails_e2e import desktop

REMINDER = {
    "app_name": "System",
    "summary": "Reminder",
    "body": "rehearse-0f1e",
    "hints": {"urgency": 0},
    "uid": 1000,
    "comm": "busctl",
}
DISK = {
    "app_name": "System",
    "summary": "Disk mounted with write access",
    "body": "/mnt/extra (/dev/vdc) is mounted read-write.",
    "hints": {"urgency": 2, "sender-pid": 4242},
    "uid": 1000,
    "comm": "notify-send",
}


class FakeMachine:
    """A node whose notification server has written ``records``."""

    def __init__(self, records: list[dict[str, object]] | None) -> None:
        self.records = records
        self.commands: list[str] = []

    def succeed(self, *commands: str, timeout: int | None = None) -> str:
        self.commands.extend(commands)
        return "1000\n" if commands[0].startswith("id -u") else ""

    def execute(
        self,
        command: str,
        check_return: bool = True,
        check_output: bool = True,
        timeout: int | None = 900,
    ) -> tuple[int, str]:
        self.commands.append(command)
        if self.records is None:
            return (1, "cat: no such file\n")
        return (0, "".join(json.dumps(record) + "\n" for record in self.records))

    def wait_for_unit(
        self, unit: str, user: str | None = None, timeout: int = 900
    ) -> None:
        self.commands.append(f"wait_for_unit {unit}")

    def wait_until_succeeds(self, command: str, timeout: int = 900) -> str:
        self.commands.append(command)
        return ""

    def wait_until_tty_matches(
        self, tty: str, regexp: str, timeout: int = 900
    ) -> None:
        self.commands.append(f"tty{tty} {regexp}")

    def send_chars(self, chars: str, delay: float | None = 0.01) -> None:
        self.commands.append(f"type {chars!r}")


class DesktopTest(unittest.TestCase):
    def test_received_reads_the_records_of_the_operators_server(self) -> None:
        machine = FakeMachine([REMINDER, DISK])
        self.assertEqual(desktop.received(machine, 1000), [REMINDER, DISK])
        self.assertEqual(
            machine.commands, ["cat /run/user/1000/notifications.jsonl"]
        )

    def test_no_records_file_means_nothing_received(self) -> None:
        self.assertEqual(desktop.received(FakeMachine(None), 1000), [])

    def test_wait_for_keeps_only_the_notifications_with_that_summary(self) -> None:
        machine = FakeMachine([REMINDER, DISK, DISK])
        found = desktop.wait_for(machine, 1000, "Disk mounted with write access")
        self.assertEqual(found, [DISK, DISK])

    def test_the_wait_greps_for_the_summary_as_the_server_writes_it(self) -> None:
        machine = FakeMachine([DISK])
        desktop.wait_for(machine, 1000, "Disk mounted with write access")
        grep = machine.commands[0]
        # The pattern the wait runs must match the line the server wrote.
        line = json.dumps(DISK) + "\n"
        result = subprocess.run(
            ["sh", "-c", grep.replace("/run/user/1000/notifications.jsonl", "-")],
            input=line,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, grep)

    def test_the_login_waits_for_the_active_seat_and_the_server(self) -> None:
        machine = FakeMachine([])
        self.assertEqual(desktop.login_on_console(machine), 1000)
        self.assertIn("type 'testuser\\n'", machine.commands)
        self.assertIn("type 'test\\n'", machine.commands)
        self.assertTrue(
            any("show-seat seat0" in command for command in machine.commands)
        )
        self.assertIn(
            "systemctl --user --machine=testuser@ is-active "
            "notification-recorder.service",
            machine.commands,
        )


if __name__ == "__main__":
    unittest.main()
