"""Tests for ci/e2e_sync_lint.py, the E2E synchronisation lint."""

from __future__ import annotations

import unittest
from pathlib import Path

from ci import e2e_sync_lint as lint


def rules(text: str) -> list[str]:
    return [finding.rule for finding in lint.lint_text(Path("t.nix"), text)]


class SleepTest(unittest.TestCase):
    def test_a_bare_sleep_is_flagged(self) -> None:
        self.assertEqual(rules("    time.sleep(5)\n"), ["sleep"])
        self.assertEqual(rules("    machine.sleep(10)\n"), ["sleep"])

    def test_a_sleep_in_a_deadline_loop_is_fine(self) -> None:
        text = (
            "    deadline = time.monotonic() + 30\n"
            "    while time.monotonic() < deadline:\n"
            "        time.sleep(0.2)\n"
        )
        self.assertEqual(rules(text), [])

    def test_a_sleep_in_a_bounded_for_loop_is_fine(self) -> None:
        text = "    for _ in range(60):\n        time.sleep(2)\n"
        self.assertEqual(rules(text), [])

    def test_a_marked_sleep_is_allowed(self) -> None:
        text = "    # sync-lint: allow sleep -- absence window\n    time.sleep(30)\n"
        self.assertEqual(rules(text), [])

    def test_a_marker_needs_a_reason_and_a_known_rule(self) -> None:
        self.assertEqual(
            rules("    # sync-lint: allow sleep\n    time.sleep(30)\n"),
            ["marker"],
        )
        self.assertEqual(
            rules("    x = 1  # sync-lint: allow nap -- why\n"), ["marker"]
        )

    def test_a_sleep_in_a_comment_is_ignored(self) -> None:
        self.assertEqual(rules("    # never time.sleep(5) here\n"), [])


class ConsoleWaitTest(unittest.TestCase):
    def test_console_waits_are_flagged_but_the_definition_is_not(self) -> None:
        self.assertEqual(
            rules('    machine.wait_for_console_text("done")\n'), ["console-wait"]
        )
        self.assertEqual(
            rules('    wait_for_console_log(r"done", timeout=30)\n'), ["console-wait"]
        )
        self.assertEqual(
            rules("    def wait_for_console_log(regex, timeout, start_index=0):\n"), []
        )


class TmpCaptureTest(unittest.TestCase):
    def test_redirected_output_into_tmp_is_flagged(self) -> None:
        self.assertEqual(
            rules('    "nails status > /tmp/s.stdout 2>/tmp/s.stderr"\n'),
            ["tmp-capture"],
        )
        self.assertEqual(rules("    \"printf '%s' $? > /tmp/x.rc\"\n"), ["tmp-capture"])

    def test_config_files_and_run_captures_are_fine(self) -> None:
        self.assertEqual(rules("    cat > /tmp/nails-headless.toml <<'EOF'\n"), [])
        self.assertEqual(rules('    "nails status > /run/s.stdout"\n'), [])


class ShutdownTest(unittest.TestCase):
    def test_a_bare_wait_for_shutdown_is_flagged(self) -> None:
        self.assertEqual(
            rules("    machine.wait_for_shutdown()\n"), ["unbounded-shutdown"]
        )

    def test_a_wait_after_a_bounded_process_wait_is_fine(self) -> None:
        text = (
            "    process = machine.process\n"
            "    process.wait(timeout=300)\n"
            "    machine.wait_for_shutdown()\n"
        )
        self.assertEqual(rules(text), [])


class SuiteTest(unittest.TestCase):
    def test_the_checked_in_suite_is_clean(self) -> None:
        findings = lint.lint_paths(lint.DEFAULT_PATHS)
        self.assertEqual([finding.format(lint.REPO_ROOT) for finding in findings], [])


if __name__ == "__main__":
    unittest.main()
