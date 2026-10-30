"""Tests for ci/mutants_guard.py, which runs the in-diff lane's test binaries."""

from __future__ import annotations

import contextlib
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


def stat_fields(pid: int) -> list[str] | None:
    """The fields of /proc/<pid>/stat after the command, or None when gone."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except (FileNotFoundError, ProcessLookupError):
        return None
    return stat.rsplit(")", 1)[1].split()


def alive(pid: int) -> bool:
    """Whether process ``pid`` runs: it is there and not a zombie."""
    fields = stat_fields(pid)
    return fields is not None and fields[0] != "Z"


def kill_if_alive(pid: int) -> None:
    with contextlib.suppress(ProcessLookupError):
        if alive(pid):
            os.kill(pid, signal.SIGKILL)


def kill_session(session: int) -> None:
    """Kill every process of ``session``: a guard and all it started."""
    for entry in os.listdir("/proc"):
        fields = stat_fields(int(entry)) if entry.isdigit() else None
        if fields is not None and fields[3] == str(session):
            kill_if_alive(int(entry))


def gone_soon(pid: int, seconds: float = 20) -> bool:
    """Whether process ``pid`` has ended within ``seconds``."""
    deadline = time.monotonic() + seconds
    while alive(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    return not alive(pid)


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
        """Start ``code`` under the guard, in a session of its own; wait for it."""
        started, line = self.start_reading(code, grace)
        self.assertEqual(line, "ready\n")
        return started

    def start_reading(self, code: str, grace: str) -> tuple[subprocess.Popen[str], str]:
        """Start ``code`` under the guard; return it and the first line it prints."""
        started = subprocess.Popen(
            guard("--grace", grace, *python(code)),
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        self.addCleanup(self.stop, started)
        assert started.stdout is not None
        return started, started.stdout.readline()

    @staticmethod
    def stop(started: subprocess.Popen[str]) -> None:
        # The guard leads a session of its own, which holds the binary's
        # process group too.
        kill_session(started.pid)
        started.wait()
        if started.stdout is not None:
            started.stdout.close()

    def test_kills_a_binary_that_ignores_the_signal_ending_its_run(self) -> None:
        # As a test binary does once a test installed the SIGTERM handler of
        # the cancel module. cargo-mutants signals the whole process group of
        # a test run that passed its timeout, which the guard is in and the
        # binary is not.
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

    def test_the_binary_leads_a_process_group_of_its_own(self) -> None:
        # So the guard can signal the binary and what it starts as one.
        code = "import os; print(os.getpgrp() == os.getpid() != os.getsid(0))"
        done = self.run_guard(*python(code))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, "True\n")

    def test_a_stopped_run_ends_what_the_binary_started_too(self) -> None:
        # As the nails binary that a nails-cli test runs: a process the test
        # binary started, here one that ignores SIGTERM, goes with the binary.
        grandchild = (
            "import signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "print('ready', flush=True)\n"
            "time.sleep(60)\n"
        )
        code = (
            "import subprocess, sys, time\n"
            "started = subprocess.Popen([sys.executable, '-I', '-c', sys.argv[1]],"
            " stdout=subprocess.PIPE, text=True)\n"
            "started.stdout.readline()\n"
            "print(started.pid, flush=True)\n"
            "time.sleep(60)\n"
        )
        started = subprocess.Popen(
            guard("--grace", "30", *python(code, grandchild)),
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        self.addCleanup(self.stop, started)
        assert started.stdout is not None
        pid = int(started.stdout.readline())
        self.addCleanup(kill_if_alive, pid)
        self.assertTrue(alive(pid))
        # The binary ends on the SIGTERM, long before the grace runs out, and
        # what it started is killed with the rest of its group.
        started.send_signal(signal.SIGTERM)
        self.assertEqual(started.wait(timeout=30), 128 + signal.SIGTERM)
        self.assertTrue(gone_soon(pid))

    def run_reading(self, code: str, *arguments: str) -> tuple[int, int]:
        """Run ``code`` under the guard; its exit status and the pid it prints."""
        started = subprocess.Popen(
            guard(*python(code, *arguments)),
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        self.addCleanup(self.stop, started)
        assert started.stdout is not None
        pid = int(started.stdout.readline())
        self.addCleanup(kill_if_alive, pid)
        return started.wait(timeout=30), pid

    def test_what_a_binary_that_ends_on_its_own_started_goes_too(self) -> None:
        # A failing test, a panic or the abort at the cap ends the binary with
        # no signal to the guard: what it started is killed all the same.
        code = (
            "import subprocess, sys\n"
            "started = subprocess.Popen([sys.executable, '-I', '-c',"
            " 'import time; time.sleep(60)'])\n"
            "print(started.pid, flush=True)\n"
            "sys.exit(101)\n"
        )
        status, pid = self.run_reading(code)
        self.assertEqual(status, 101)
        self.assertTrue(gone_soon(pid))

    def test_a_process_that_left_the_binary_s_group_goes_too(self) -> None:
        # As the workspace's process runner and some tests start their
        # children: in a group or a session of their own, out of reach of the
        # group's signals. The guard, their subreaper, kills them at the end,
        # also when the process that started them has ended before.
        sleeper = "import time; time.sleep(60)"
        starter = (
            "import subprocess, sys\n"
            "away = {'session': {'start_new_session': True},"
            " 'group': {'process_group': 0}}[sys.argv[1]]\n"
            "started = subprocess.Popen([sys.executable, '-I', '-c', sys.argv[2]],"
            " **away)\n"
            "print(started.pid, flush=True)\n"
        )
        binary = (
            "import subprocess, sys\n"
            "starter = subprocess.Popen([sys.executable, '-I', '-c', *sys.argv[1:]],"
            " stdout=subprocess.PIPE, text=True)\n"
            "print(starter.stdout.readline().strip(), flush=True)\n"
            "starter.wait()\n"
        )
        for way in ("session", "group"):
            with self.subTest(way=way):
                status, pid = self.run_reading(binary, starter, way, sleeper)
                self.assertEqual(status, 0)
                self.assertTrue(gone_soon(pid))

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
