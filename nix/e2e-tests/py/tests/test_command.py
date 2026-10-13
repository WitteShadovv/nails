"""Host-side tests for ``run_command_capture``.

These run without Nix or a VM: a fake machine records the commands the helper
would run and feeds back canned output, so the generated shell and the returned
shape are locked without booting anything.
"""

from __future__ import annotations

import unittest

from nails_e2e import run_command_capture


class FakeMachine:
    """Records every command and answers ``cat`` reads from a lookup table."""

    def __init__(self, reads: dict[str, str]) -> None:
        self.commands: list[str] = []
        self._reads = reads

    def succeed(self, *commands: str) -> str:
        outputs = []
        for command in commands:
            self.commands.append(command)
            outputs.append(self._reads.get(command, ""))
        return "".join(outputs)


class RunCommandCaptureTest(unittest.TestCase):
    def test_returns_the_superset_shape(self) -> None:
        reads = {
            "cat /run/demo.stdout || true": "out\n",
            "cat /run/demo.stderr || true": "err\n",
            "cat /run/demo.rc": "7",
        }
        machine = FakeMachine(reads)

        result = run_command_capture(machine, "demo", "nails status")

        self.assertEqual(
            result,
            {
                "rc": 7,
                "stdout": "out\n",
                "stderr": "err\n",
                "combined": "out\nerr\n",
                "stdout_path": "/run/demo.stdout",
                "stderr_path": "/run/demo.stderr",
            },
        )

    def test_runs_the_command_without_asserting_success(self) -> None:
        machine = FakeMachine({"cat /run/demo.rc": "0"})

        run_command_capture(machine, "demo", "nails status")

        runner = machine.commands[0]
        self.assertTrue(runner.startswith("bash -lc "))
        # The command runs under `set +e` so a non-zero exit is captured, not
        # raised, and the exit status is persisted for read-back.
        self.assertIn("set +e;", runner)
        self.assertIn("nails status", runner)
        self.assertIn('printf "%s" "$?"', runner)

    def test_label_scopes_every_capture_path(self) -> None:
        machine = FakeMachine({"cat /run/other.rc": "0"})

        result = run_command_capture(machine, "other", "true")

        self.assertEqual(result["stdout_path"], "/run/other.stdout")
        self.assertEqual(result["stderr_path"], "/run/other.stderr")


if __name__ == "__main__":
    unittest.main()
