"""Host-side tests for the whole-root session helpers.

A fake machine stands in for the driver's node: its console log is a list the
test appends to, so following a soft-reboot is exercised without a VM.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

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
        self.qmp_client: Any = None

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


class ShellMachine(FakeMachine):
    """A node that runs the trigger on this host the way the driver runs a
    command in the guest: through ``bash -c 'set -euo pipefail; ...'``,
    returning once its stdout is closed. A scratch file stands in for the
    serial console and a stand-in ``systemctl`` reports ``state``. The
    console then shows ``then`` (the switch, when one comes)."""

    def __init__(
        self, scratch: Path, state: str, then: list[str] | None = None
    ) -> None:
        super().__init__(then or [])
        self.console = scratch / "console"
        self.console.touch()
        self.asked = scratch / "systemctl-asked"
        bin_dir = scratch / "bin"
        bin_dir.mkdir()
        bash = shutil.which("bash")
        assert bash is not None, "the tests run bash"
        systemctl = bin_dir / "systemctl"
        # An absolute interpreter: the Nix build sandbox has no /usr/bin/env.
        systemctl.write_text(
            f'#!{bash}\necho "$*" >> {self.asked}\necho {state}\nexit 1\n',
            encoding="utf-8",
        )
        systemctl.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}")

    def execute(
        self,
        command: str,
        check_return: bool = True,
        check_output: bool = True,
        timeout: int | None = 900,
    ) -> tuple[int, str]:
        if not command.endswith("&"):
            return (0, "")
        subprocess.run(
            ["bash", "-c", f"set -euo pipefail; {command}"],
            env=self.env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=60,
            check=False,
        )
        report = self.console.read_text(encoding="utf-8").splitlines()
        if not any(session.TRIGGER_EXIT_MARKER in line for line in report):
            raise AssertionError(
                f"the trigger left no report on the console: {command}"
            )
        self.full_console_log.extend(report)
        self.full_console_log.extend(self.pending)
        return (0, "")


class Polled(Exception):
    """The follower waited for another poll instead of deciding."""


class NoPolling:
    """The ``time`` module as the follower sees it: the clock is real, and a
    poll, which only a wait that goes on would make, ends the test."""

    monotonic = staticmethod(time.monotonic)

    @staticmethod
    def sleep(seconds: float) -> None:
        raise Polled(f"the follower polled again after {seconds} s")


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

    def test_a_switch_that_never_ends_says_what_pid1_waits_on(self) -> None:
        machine = FakeMachine(["Soft-rebooting."])
        with self.assertRaises(AssertionError) as raised:
            session.follow_soft_reboot(machine, "true", "leave", deadline_s=0)
        # Without QMP the report says so, and the failure stays the stall.
        failure = str(raised.exception)
        self.assertIn("leave: no backdoor 0 s after the soft-reboot (", failure)
        self.assertIn("QMP is not connected", failure)
        self.assertIn("what PID 1 waits on", machine.logged[-1])

    def test_a_userspace_in_emergency_mode_fails_at_once(self) -> None:
        machine = FakeMachine(
            ["Timed out waiting for device", "Reached target Emergency Mode"]
        )
        with self.assertRaises(AssertionError) as raised:
            session.follow_soft_reboot(machine, "true", "leave", deadline_s=5)
        self.assertIn("stuck", str(raised.exception))
        self.assertEqual(machine.connects, 0)


class PowerOffTest(unittest.TestCase):
    def test_a_power_off_that_never_ends_says_what_pid1_waits_on(self) -> None:
        class Running:
            def wait(self, timeout: float) -> int:
                raise subprocess.TimeoutExpired("qemu", timeout)

        machine = FakeMachine([])
        machine.process = Running()
        with self.assertRaises(AssertionError) as raised:
            session.wait_for_power_off(machine, timeout=0)
        self.assertIn("did not power off within 0 s (", str(raised.exception))
        self.assertIn("what PID 1 waits on", machine.logged[-1])


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

    def test_a_failure_while_the_system_runs_names_its_state(self) -> None:
        self.assertEqual(
            session.trigger_failure(["nails-trigger-exit=4 degraded"]),
            "exit status 4 while the system was degraded",
        )
        self.assertEqual(
            session.trigger_failure(["nails-trigger-exit=1"]),
            "exit status 1 while the system was in an unknown state",
        )

    def test_a_non_zero_exit_with_the_switch_enqueued_is_not_a_failure(self) -> None:
        # An activation with warnings exits 9, an emergency that left mounts
        # behind 7, both with the switch already under way.
        self.assertIsNone(session.trigger_failure(["nails-trigger-exit=9 stopping"]))
        self.assertIsNone(session.trigger_failure(["nails-trigger-exit=7 stopping"]))


class TriggerReportTest(unittest.TestCase):
    """The report the real shell leaves when the trigger returns, under the
    driver's ``set -euo pipefail``, and what the follower makes of it."""

    def setUp(self) -> None:
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.scratch = Path(scratch.name)
        console = mock.patch.object(
            session, "SERIAL_CONSOLE", str(self.scratch / "console")
        )
        console.start()
        self.addCleanup(console.stop)

    def test_a_failed_activation_ends_a_1200_s_wait_at_once(self) -> None:
        # The deadline of the tests that copy a whole NixOS closure.
        machine = ShellMachine(self.scratch, "running")
        started = time.monotonic()
        with (
            mock.patch.object(session, "time", NoPolling),
            self.assertRaises(AssertionError) as raised,
        ):
            session.follow_soft_reboot(machine, "exit 4", "activate", deadline_s=1200.0)
        elapsed = time.monotonic() - started
        self.assertEqual(
            str(raised.exception),
            "activate: the trigger failed (exit status 4 while the system was "
            "running) and never soft-rebooted",
        )
        self.assertIn("nails-trigger-exit=4 running", machine.full_console_log)
        self.assertLess(elapsed, 10.0)
        asked = machine.asked.read_text(encoding="utf-8")
        self.assertEqual(asked, "is-system-running\n")
        self.assertEqual(machine.connects, 0)

    def test_an_activation_with_warnings_is_followed_into_its_switch(self) -> None:
        machine = ShellMachine(
            self.scratch, "stopping", then=["backdoor: connecting to host..."]
        )
        session.follow_soft_reboot(machine, "exit 9", "activate", deadline_s=5)
        self.assertIn("nails-trigger-exit=9 stopping", machine.full_console_log)
        self.assertEqual(machine.connects, 1)

    def test_a_trigger_that_exits_0_does_not_ask_the_service_manager(self) -> None:
        machine = ShellMachine(
            self.scratch, "running", then=["backdoor: connecting to host..."]
        )
        session.follow_soft_reboot(machine, "true", "deactivate", deadline_s=5)
        reports = [
            line.strip()
            for line in machine.full_console_log
            if session.TRIGGER_EXIT_MARKER in line
        ]
        self.assertEqual(reports, ["nails-trigger-exit=0"])
        self.assertFalse(machine.asked.exists())
        self.assertEqual(machine.connects, 1)

    def test_the_trigger_stops_at_its_first_failing_command(self) -> None:
        # As every command the driver runs: the trigger keeps errexit.
        machine = ShellMachine(self.scratch, "running")
        with (
            mock.patch.object(session, "time", NoPolling),
            self.assertRaises(AssertionError) as raised,
        ):
            session.follow_soft_reboot(machine, "false; true", "activate")
        self.assertIn(
            "(exit status 1 while the system was running)", str(raised.exception)
        )


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

    def test_the_store_mounted_from_the_initrd_is_no_leftover(self) -> None:
        store = (
            "ro,nosuid,nodev,relatime,lowerdir=/sysroot/nix/.ro-store,"
            "upperdir=/sysroot/nix/.rw-store/upper,"
            "workdir=/sysroot/nix/.rw-store/work,uuid=on"
        )
        self.assertEqual(session.leftover_overlays(f"/nix/store {store}\n"), [])

    def test_the_stacked_vm_store_is_no_leftover_but_a_hidden_overlay_is(self) -> None:
        store = (
            "rw,lowerdir=/nix/.ro-store,upperdir=/nix/.rw-store/upper,"
            "workdir=/nix/.rw-store/work"
        )
        hidden = (
            "/srv/data rw,lowerdir=/run/overlay-runtime/lower-1,"
            "upperdir=/mnt/data/root/mounts/srv-data/upper"
        )
        lines = f"/nix/store {store}\n/nix/store {store}\n{hidden}\n"
        self.assertEqual(
            session.leftover_overlays(lines),
            [hidden],
        )
        self.assertEqual(session.leftover_overlays(""), [])


if __name__ == "__main__":
    unittest.main()
