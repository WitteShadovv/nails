"""Tests for power_off, the power-off and cold boot of a distribution VM that
keeps its disk."""

from __future__ import annotations

import unittest
from typing import Any
from unittest import mock

import power_off as po


class FakeQmp:
    """Answers query-status with the next of ``statuses`` (the last repeats)
    and records every command."""

    def __init__(self, statuses: list[str]) -> None:
        self.statuses = statuses
        self.sent: list[tuple[str, dict[str, Any]]] = []

    def send(self, command: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self.sent.append((command, arguments))
        if command == "query-status":
            status = self.statuses[0]
            if len(self.statuses) > 1:
                self.statuses.pop(0)
            return {"return": {"status": status}}
        return {"return": {}}


class Running:
    def poll(self) -> None:
        return None


class Exited:
    def poll(self) -> int:
        return 0


class FakeVm:
    """A node whose console prints ``lines`` once the trigger has run."""

    def __init__(self, lines: list[str], statuses: list[str]) -> None:
        self.connected = True
        self.full_console_log: list[str] = ["boot"]
        self.pending = lines
        self.process: Any = Running()
        self.qmp_client: Any = FakeQmp(statuses)
        self.connects = 0
        self.units: list[str] = []
        self.logged: list[str] = []
        self.commands: list[str] = []

    def execute(
        self,
        command: str,
        check_return: bool = True,
        check_output: bool = True,
        timeout: int | None = 900,
    ) -> tuple[int, str]:
        self.commands.append(command)
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
        self.units.append(unit)


class NoSleep:
    """The ``time`` module with a real clock and sleeps that return at once."""

    monotonic = staticmethod(__import__("time").monotonic)
    monotonic_ns = staticmethod(__import__("time").monotonic_ns)

    @staticmethod
    def sleep(seconds: float) -> None:
        return None


POWER_OFF = [
    "[  41.2] systemd-shutdown[1]: Powering off.",
    "[  41.3] reboot: Power down",
]


@mock.patch.object(po, "SETTLE_S", 0.0)
class FollowPowerOffTest(unittest.TestCase):
    def follow(self, vm: FakeVm, deadline_s: float = 600.0) -> None:
        with mock.patch.object(po, "time", NoSleep):
            po.follow_power_off(vm, "nails deactivate -y", "deactivate", deadline_s)

    def test_a_power_off_that_pauses_qemu_is_followed_to_its_end(self) -> None:
        vm = FakeVm(POWER_OFF, ["running", "shutdown"])
        self.follow(vm)
        self.assertFalse(vm.connected)
        sent = vm.qmp_client.sent
        self.assertEqual(sent[0], ("set-action", {"shutdown": "pause"}))
        self.assertIn("nails deactivate -y", vm.commands[0])
        self.assertIn(po.TRIGGER_EXIT_MARKER, vm.commands[0])

    def test_a_new_userspace_fails_at_once(self) -> None:
        vm = FakeVm(["backdoor: connecting to host..."], ["running"])
        with self.assertRaises(AssertionError) as raised:
            self.follow(vm)
        self.assertIn("a new userspace came up instead", str(raised.exception))

    def test_a_reboot_instead_is_no_power_off(self) -> None:
        vm = FakeVm(["[  12.0] reboot: Restarting system"], ["shutdown"])
        with self.assertRaises(AssertionError) as raised:
            self.follow(vm)
        self.assertIn("the machine rebooted", str(raised.exception))

    def test_a_panic_on_the_way_down_is_no_power_off(self) -> None:
        vm = FakeVm(["Kernel panic - not syncing", *POWER_OFF], ["shutdown"])
        with self.assertRaises(AssertionError) as raised:
            self.follow(vm)
        self.assertIn("the kernel panicked", str(raised.exception))

    def test_qemu_that_exits_lost_the_disk(self) -> None:
        vm = FakeVm(POWER_OFF, ["running"])
        vm.process = Exited()
        with self.assertRaises(AssertionError) as raised:
            self.follow(vm)
        self.assertIn("QEMU exited instead of pausing", str(raised.exception))

    def test_a_failed_trigger_fails_at_once(self) -> None:
        vm = FakeVm([f"{po.TRIGGER_EXIT_MARKER}4 running"], ["running"])
        with self.assertRaises(AssertionError) as raised:
            self.follow(vm)
        self.assertIn("the trigger failed (exit status 4", str(raised.exception))

    def test_a_machine_that_stays_on_runs_out_its_deadline(self) -> None:
        vm = FakeVm([], ["running"])
        with self.assertRaises(AssertionError) as raised:
            self.follow(vm, deadline_s=0)
        self.assertIn("did not power off 0 s after the trigger", str(raised.exception))

    def test_an_ending_something_else_starts_runs_nothing(self) -> None:
        vm = FakeVm([], ["shutdown"])
        index = len(vm.full_console_log)
        vm.full_console_log.extend(POWER_OFF)
        with mock.patch.object(po, "time", NoSleep):
            po.follow_power_off(vm, None, "watcher", console_index=index)
        self.assertEqual(vm.commands, [])


class BootAgainTest(unittest.TestCase):
    def test_the_reset_boots_the_kept_disk_and_reconnects(self) -> None:
        vm = FakeVm([], ["shutdown", "prelaunch"])
        vm.connected = False

        def announce(command: str, arguments: dict[str, Any]) -> dict[str, Any]:
            if command == "cont":
                vm.full_console_log.append("backdoor: connecting to host...")
            return FakeQmp.send(vm.qmp_client, command, arguments)

        vm.qmp_client.send = announce
        with mock.patch.object(po, "time", NoSleep):
            po.boot_again(vm, "cold boot")
        sent = vm.qmp_client.sent
        commands = [command for command, _ in sent]
        # -no-reboot would turn the reset into a shutdown: the reset is let
        # through for this once, and the reboot action is put back before
        # cont. A power-off keeps pausing QEMU: no action ends it.
        self.assertEqual(
            sent[0], ("set-action", {"reboot": "reset", "shutdown": "pause"})
        )
        self.assertEqual(commands[1], "system_reset")
        restored = ("set-action", {"reboot": "shutdown", "shutdown": "pause"})
        self.assertIn(restored, sent)
        self.assertLess(sent.index(restored), commands.index("cont"))
        self.assertNotIn(
            "poweroff", [args.get("shutdown") for command, args in sent]
        )
        self.assertEqual(vm.connects, 1)
        self.assertEqual(vm.units, ["multi-user.target"])

    def test_a_boot_qemu_stops_again_at_once_is_reset_again(self) -> None:
        # A shutdown request QEMU still held stops the first boot at once.
        vm = FakeVm([], ["shutdown", "prelaunch", "shutdown", "prelaunch"])
        conts = []

        def held(command: str, arguments: dict[str, Any]) -> dict[str, Any]:
            if command == "cont":
                conts.append(command)
                if len(conts) == 2:
                    vm.full_console_log.append("backdoor: connecting to host...")
            return FakeQmp.send(vm.qmp_client, command, arguments)

        vm.qmp_client.send = held
        with mock.patch.object(po, "time", NoSleep):
            po.boot_again(vm, "cold boot")
        commands = [command for command, _ in vm.qmp_client.sent]
        self.assertEqual(commands.count("system_reset"), 2)
        self.assertEqual(vm.connects, 1)

    def test_a_stuck_boot_fails_at_once(self) -> None:
        vm = FakeVm([], ["prelaunch"])

        def stuck(command: str, arguments: dict[str, Any]) -> dict[str, Any]:
            if command == "cont":
                vm.full_console_log.append("Reached target Emergency Mode")
            return FakeQmp.send(vm.qmp_client, command, arguments)

        vm.qmp_client.send = stuck
        with (
            mock.patch.object(po, "time", NoSleep),
            self.assertRaises(AssertionError) as raised,
        ):
            po.boot_again(vm, "cold boot")
        self.assertIn("the cold boot is stuck", str(raised.exception))
        self.assertEqual(vm.connects, 0)


class PureTest(unittest.TestCase):
    def test_a_zero_exit_is_not_a_failure(self) -> None:
        self.assertIsNone(po.trigger_failure([f"{po.TRIGGER_EXIT_MARKER}0 "]))

    def test_a_non_zero_exit_while_stopping_is_not_a_failure(self) -> None:
        self.assertIsNone(po.trigger_failure([f"{po.TRIGGER_EXIT_MARKER}7 stopping"]))

    def test_a_cut_report_decides_nothing(self) -> None:
        self.assertIsNone(po.trigger_failure([f"{po.TRIGGER_EXIT_MARKER}4 run[  3.1]"]))

    def test_only_the_power_down_line_proves_a_power_off(self) -> None:
        self.assertIsNone(po.stopped_problem(POWER_OFF))
        self.assertEqual(
            po.stopped_problem(["Powering off."]),
            "the kernel never said it powered off",
        )

    def test_image_needs_a_powered_off_machine(self) -> None:
        vm = FakeVm([], ["running"])
        with self.assertRaises(AssertionError) as raised:
            po.image_paused_disk(vm, "/nonexistent/disk.raw")
        self.assertIn("not powered off", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
