"""Tests for ci/mutants_guard.py, which runs the in-diff lane's test binaries."""

from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path

from ci import mutants_guard

REPO_ROOT = Path(__file__).resolve().parents[2]
GUARD = REPO_ROOT / "ci" / "mutants_guard.py"
JUSTFILE = REPO_ROOT / "justfile"


def guard(*arguments: str) -> list[str]:
    """The command line that runs a Python snippet through the guard."""
    return [sys.executable, "-I", str(GUARD), *arguments]


def python(code: str, *arguments: str) -> list[str]:
    return [sys.executable, "-I", "-c", code, *arguments]


class GuardTest(unittest.TestCase):
    def run_guard(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            guard(*arguments), capture_output=True, text=True, timeout=60
        )

    def test_passes_the_arguments_on_and_the_exit_code_back(self) -> None:
        code = "import sys; print(sys.argv[1:]); sys.exit(int(sys.argv[1]))"
        done = self.run_guard(*python(code, "7", "--exact", "a test"))
        self.assertEqual(done.returncode, 7, done.stderr)
        self.assertEqual(done.stdout, "['7', '--exact', 'a test']\n")

    def test_reports_a_binary_a_signal_ended_as_a_shell_does(self) -> None:
        code = "import os, signal; os.kill(os.getpid(), signal.SIGUSR1)"
        done = self.run_guard(*python(code))
        self.assertEqual(done.returncode, 128 + signal.SIGUSR1, done.stderr)

    def test_caps_what_the_binary_may_allocate(self) -> None:
        # A binary that allocates past the cap fails; under it, it does not.
        code = "import sys; bytearray(int(sys.argv[1])); print('allocated')"
        cap = 256 * 1024**2
        capped = self.run_guard("--memory", str(cap), *python(code, str(2 * cap)))
        self.assertNotEqual(capped.returncode, 0)
        self.assertIn("MemoryError", capped.stderr)
        self.assertNotIn("allocated", capped.stdout)
        fits = self.run_guard("--memory", str(cap), *python(code, str(cap // 4)))
        self.assertEqual(fits.returncode, 0, fits.stderr)
        self.assertEqual(fits.stdout, "allocated\n")

    def test_the_default_cap_is_the_one_the_docs_give(self) -> None:
        # docs/ci.md gives the cap and the grace.
        self.assertEqual(mutants_guard.MEMORY_BYTES, 4 * 1024**3)
        self.assertEqual(mutants_guard.GRACE_SECONDS, 2)

    def start(self, code: str, grace: str) -> subprocess.Popen[str]:
        """Start ``code`` under the guard, in a group of their own; wait for it."""
        started = subprocess.Popen(
            guard("--grace", grace, *python(code)),
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        self.addCleanup(self.stop, started)
        assert started.stdout is not None
        self.assertEqual(started.stdout.readline(), "ready\n")
        return started

    @staticmethod
    def stop(started: subprocess.Popen[str]) -> None:
        if started.poll() is None:
            os.killpg(started.pid, signal.SIGKILL)
            started.wait()
        if started.stdout is not None:
            started.stdout.close()

    def test_kills_a_binary_that_ignores_the_signal_ending_its_run(self) -> None:
        # As a test binary does once a test installed the SIGTERM handler of
        # the cancel module. cargo-mutants signals the whole process group of
        # a test run that passed its timeout.
        code = (
            "import signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "print('ready', flush=True)\n"
            "time.sleep(60)\n"
        )
        started = self.start(code, "0.5")
        sent = time.monotonic()
        os.killpg(started.pid, signal.SIGTERM)
        self.assertEqual(started.wait(timeout=30), 128 + signal.SIGKILL)
        self.assertLess(time.monotonic() - sent, 20)

    def test_passes_a_signal_on_to_the_binary(self) -> None:
        # A signal that reaches the guard alone still reaches the binary, which
        # ends by its default action, as a test binary does.
        code = (
            "import signal, time\n"
            "signal.signal(signal.SIGINT, signal.SIG_DFL)\n"
            "print('ready', flush=True)\n"
            "time.sleep(60)\n"
        )
        for signum in mutants_guard.PASSED_ON:
            with self.subTest(signal=signal.Signals(signum).name):
                started = self.start(code, "30")
                sent = time.monotonic()
                started.send_signal(signum)
                self.assertEqual(started.wait(timeout=30), 128 + signum)
                self.assertLess(time.monotonic() - sent, 20)

    def test_the_binary_stays_in_the_process_group_of_its_test_run(self) -> None:
        # So the SIGTERM with which cargo-mutants ends a test run reaches the
        # binary as well as the guard.
        code = "import os; print(os.getpgrp())"
        started = subprocess.Popen(
            guard(*python(code)),
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        printed, _ = started.communicate(timeout=60)
        self.assertEqual(started.returncode, 0)
        # The guard leads the group it was started in.
        self.assertEqual(printed, f"{started.pid}\n")

    def test_a_binary_that_cannot_start_fails(self) -> None:
        done = self.run_guard(str(REPO_ROOT / "no-such-binary"))
        self.assertEqual(done.returncode, 127)
        self.assertIn("no-such-binary", done.stderr)

    def test_without_a_binary_it_fails(self) -> None:
        done = self.run_guard()
        self.assertEqual(done.returncode, 2)


class LaneTest(unittest.TestCase):
    def test_the_lane_runs_every_test_binary_through_the_guard(self) -> None:
        text = JUSTFILE.read_text(encoding="utf-8")
        recipe = re.search(
            r"^mutants-in-diff [^\n]*:\n((?:[ \t]+[^\n]*\n|\n)*)", text, re.M
        )
        if recipe is None:
            raise AssertionError("no recipe mutants-in-diff in the justfile")
        body = recipe.group(1)
        # cargo's runner for the host, the target of the test binaries.
        self.assertIn("host=$(rustc --print host-tuple)", body)
        self.assertIn(
            'export "CARGO_TARGET_${host//-/_}_RUNNER=python3 -I '
            '{{ justfile_directory() }}/ci/mutants_guard.py"',
            body,
        )
        # Before cargo-mutants starts.
        self.assertLess(body.index("_RUNNER="), body.index("cargo mutants"))


if __name__ == "__main__":
    unittest.main()
