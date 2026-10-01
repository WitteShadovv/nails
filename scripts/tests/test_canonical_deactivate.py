"""Behaviour of canonical_deactivate from nix/e2e-tests/lib/test-helpers.nix.

The helper is Python inside a Nix string that the NixOS test driver runs with
a global `machine`. These tests extract it and run it against a fake machine
whose QEMU process is a real subprocess, so the power-off deadline and the
diagnostics fallback are exercised without booting a VM.
"""

from __future__ import annotations

import contextlib
import subprocess
import sys
import textwrap
import threading
import time
import unittest
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
TEST_HELPERS = REPO_ROOT / "nix" / "e2e-tests" / "lib" / "test-helpers.nix"

DIAGNOSTIC_SECTIONS = (
    "--- systemctl status nails-deactivate ---",
    "--- journal of nails-deactivate ---",
    "--- journal tail ---",
    "--- pending systemd jobs ---",
    "--- process list ---",
)


def extract_snippet(nix_text: str, attribute: str) -> str:
    """Return the Python held in `attribute = '' ... '';`, dedented like Nix."""
    opener = f"  {attribute} = ''\n"
    start = nix_text.index(opener) + len(opener)
    end = nix_text.index("\n  '';\n", start)
    body = nix_text[start:end]
    for marker in ("${", "''"):
        if marker in body:
            raise ValueError(
                f"{attribute} contains {marker!r}, which Nix would not pass "
                "through verbatim"
            )
    return textwrap.dedent(body) + "\n"


class FakeMachine:
    """The subset of the driver's QemuMachine that the helper uses."""

    def __init__(
        self,
        process: subprocess.Popen[bytes] | None,
        *,
        shell_alive: bool = True,
        console_log: str = "",
    ) -> None:
        self.process = process
        self.shell_alive = shell_alive
        self.console_log = console_log
        self.release_shell = threading.Event()
        self.calls: list[tuple[str, ...]] = []

    def succeed(self, command: str) -> str:
        self.calls.append(("succeed", command))
        return ""

    def execute(
        self,
        command: str,
        check_return: bool = True,
        check_output: bool = True,
        timeout: int | None = 900,
    ) -> tuple[int, str]:
        self.calls.append(("execute", command))
        if not self.shell_alive:
            # A dead backdoor shell never answers.
            self.release_shell.wait()
            return (-1, "")
        return (-1, f"output of {command}\n")

    @contextlib.contextmanager
    def nested(self, message: str) -> Iterator[None]:
        self.calls.append(("nested", message))
        yield

    def get_console_log(self) -> str:
        return self.console_log

    def wait_for_shutdown(self) -> None:
        self.calls.append(("wait_for_shutdown",))

    def start(self) -> None:
        self.calls.append(("start",))

    def wait_for_unit(self, unit: str) -> None:
        self.calls.append(("wait_for_unit", unit))


def load_helper(machine: FakeMachine) -> Callable[..., Any]:
    source = extract_snippet(
        TEST_HELPERS.read_text(encoding="utf-8"), "canonicalDeactivateFn"
    )
    namespace: dict[str, Any] = {"machine": machine}
    exec(compile(source, str(TEST_HELPERS), "exec"), namespace)
    return namespace["canonical_deactivate"]


class CanonicalDeactivateTest(unittest.TestCase):
    def spawn_hung_qemu(self) -> subprocess.Popen[bytes]:
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(120)"]
        )

        def stop() -> None:
            process.kill()
            process.wait()

        self.addCleanup(stop)
        return process

    def spawn_exited_qemu(self) -> subprocess.Popen[bytes]:
        process = subprocess.Popen([sys.executable, "-c", "pass"])
        process.wait()
        return process

    def test_extracted_snippet_has_no_nix_interpolation(self) -> None:
        source = extract_snippet(
            TEST_HELPERS.read_text(encoding="utf-8"), "canonicalDeactivateFn"
        )
        self.assertTrue(source.startswith("def canonical_deactivate("))
        compile(source, str(TEST_HELPERS), "exec")

    def test_powered_off_vm_is_started_again(self) -> None:
        machine = FakeMachine(self.spawn_exited_qemu())

        load_helper(machine)("/etc/nails/nails.yaml")

        self.assertEqual(machine.calls[0][0], "succeed")
        self.assertIn("systemd-run --unit nails-deactivate", machine.calls[0][1])
        self.assertIn(
            "nails --config /etc/nails/nails.yaml deactivate", machine.calls[0][1]
        )
        self.assertEqual(
            machine.calls[-3:],
            [
                ("wait_for_shutdown",),
                ("start",),
                ("wait_for_unit", "multi-user.target"),
            ],
        )
        self.assertFalse(any(call[0] == "execute" for call in machine.calls))

    def test_hung_power_off_fails_within_deadline_with_diagnostics(self) -> None:
        machine = FakeMachine(self.spawn_hung_qemu())
        helper = load_helper(machine)

        started = time.monotonic()
        with self.assertRaises(AssertionError) as raised:
            helper("/etc/nails/nails.yaml", shutdown_timeout=1)
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 5)
        message = str(raised.exception)
        self.assertIn("did not power off within 1s", message)
        for section in DIAGNOSTIC_SECTIONS:
            self.assertIn(section, message)
        self.assertIn("output of timeout 10s journalctl -b -n 200", message)
        self.assertNotIn(("start",), machine.calls)
        executed = [call[1] for call in machine.calls if call[0] == "execute"]
        self.assertEqual(len(executed), len(DIAGNOSTIC_SECTIONS))
        for command in executed:
            self.assertTrue(command.startswith("timeout 10s "), command)

    def test_dead_guest_shell_falls_back_to_the_serial_console(self) -> None:
        console = "\n".join(f"console line {index}" for index in range(150))
        machine = FakeMachine(
            self.spawn_hung_qemu(), shell_alive=False, console_log=console
        )
        self.addCleanup(machine.release_shell.set)
        helper = load_helper(machine)

        started = time.monotonic()
        with self.assertRaises(AssertionError) as raised:
            helper(
                "/etc/nails/nails.yaml",
                shutdown_timeout=1,
                diagnostics_timeout=1,
            )
        elapsed = time.monotonic() - started

        self.assertLess(elapsed, 5)
        message = str(raised.exception)
        self.assertIn("guest shell unresponsive; serial console tail", message)
        lines = message.splitlines()
        self.assertIn("console line 149", lines)
        self.assertIn("console line 50", lines)
        self.assertNotIn("console line 49", lines)

    def test_custom_unit_name_is_used_for_diagnostics(self) -> None:
        machine = FakeMachine(self.spawn_hung_qemu())
        helper = load_helper(machine)

        with self.assertRaises(AssertionError) as raised:
            helper(
                "/etc/nails/nails.yaml",
                unit_name="nails-deactivate-second",
                shutdown_timeout=1,
            )

        message = str(raised.exception)
        self.assertIn("after starting nails-deactivate-second", message)
        self.assertIn("--- journal of nails-deactivate-second ---", message)
        self.assertIn("systemd-run --unit nails-deactivate-second", machine.calls[0][1])


if __name__ == "__main__":
    unittest.main()
