"""Tests for ci/e2e/run.py: the internal-json duration parser and one build."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Iterator
from pathlib import Path
from unittest import mock

from ci.e2e import evaluate, plan, run
from ci.e2e.metadata import Metadata

DRV_TO_TEST = {"/nix/store/a.drv": "a", "/nix/store/b.drv": "b"}


def _running(pid: int, wait: float = 5.0) -> bool:
    """Whether a process is still alive (not gone, and not a zombie) after
    up to ``wait`` seconds."""
    deadline = time.monotonic() + wait
    while True:
        try:
            stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        except OSError:
            return False
        # The state follows the command name, which is in parentheses.
        if stat.rpartition(")")[2].split()[0] == "Z":
            return False
        if time.monotonic() > deadline:
            return True
        time.sleep(0.1)
REPO_ROOT = Path(__file__).resolve().parents[2]
E2E_ROOT = REPO_ROOT / "nix" / "e2e-tests"
# A Nix identifier, such as a node name.
NIX_NAME = r"[A-Za-z_][A-Za-z0-9_'-]*"


def e2e_sources() -> list[Path]:
    """The Nix files the E2E suite's VMs are made of.

    The tests, the batched scenarios, the helper library and default.nix, which
    gives a test without nodes of its own the node ``machine``.
    """
    files = [E2E_ROOT / "default.nix"]
    for part in ("tests", "scenarios", "lib"):
        files += sorted((E2E_ROOT / part).rglob("*.nix"))
    return files


def node_names_in(text: str, shown: object) -> Iterator[str]:
    """The VM node names one E2E source defines, in order.

    A node is named as ``nodes.<name>`` or as a key of a ``nodes = {`` block,
    one per line two spaces deeper than the block (nixfmt layout). The block
    runs to its closing brace, dedented to the block's own indent, which must
    end the statement (``};``).

    Every node must be named in the literal: a block merged with another
    attrset (``} // builtins.listToAttrs ...``) builds nodes at eval time,
    whose names no text scan can read, so it raises, as does any other
    ``nodes =`` and any unrecognised entry at a key's depth, rather than let a
    node past the socket budget unseen; ``shown`` names the file in the error.
    """
    for match in re.finditer(rf"\bnodes\.({NIX_NAME})", text):
        yield match[1]
    for block in re.finditer(r"^( *)nodes =(.*)$", text, re.M):
        indent = block[1]
        if block[2] != " {":
            raise AssertionError(f"{shown}: unrecognised {block[0].strip()!r}")
        for line in text[block.end() :].splitlines():
            if line.startswith(f"{indent}}}"):
                if line.strip() != "};":
                    raise AssertionError(
                        f"{shown}: the nodes block ends in {line.strip()!r}, "
                        "not '};': name every node in the literal"
                    )
                break
            if len(line) - len(line.lstrip()) != len(indent) + 2:
                continue
            entry = line.strip()
            key = re.match(rf"({NIX_NAME}) =", entry)
            if key is not None:
                yield key[1]
            elif not entry.startswith(("#", "}", "]", ")", "''")):
                raise AssertionError(f"{shown}: unrecognised node {entry!r}")


def scan_node_names() -> dict[str, Path]:
    """Every VM node name in the E2E suite, with the first file that names it."""
    names: dict[str, Path] = {}
    for path in e2e_sources():
        shown = path.relative_to(REPO_ROOT)
        for name in node_names_in(path.read_text(encoding="utf-8"), shown):
            names.setdefault(name, path)
    return names


class DurationParserTest(unittest.TestCase):
    def test_pairs_builds_and_times_them_against_the_clock(self) -> None:
        lines = [
            '@nix {"action":"start","type":105,"id":1,"fields":["/nix/store/a.drv"]}',
            '@nix {"action":"start","type":105,"id":2,'
            '"text":"building \'/nix/store/b.drv\'"}',
            "a plain log line that is not JSON",
            '@nix {"action":"stop","id":1}',
            '@nix {"action":"stop","id":2}',
        ]
        clock = iter([0.0, 10.0, 100.4, 130.0]).__next__
        outcomes = run.durations_from_internal_json(lines, DRV_TO_TEST, clock)
        self.assertEqual(outcomes["a"], run.TestOutcome("pass", 100))
        self.assertEqual(outcomes["b"], run.TestOutcome("pass", 120))

    def test_a_build_that_never_stops_is_a_failure(self) -> None:
        lines = [
            '@nix {"action":"start","type":105,"id":1,"fields":["/nix/store/a.drv"]}',
        ]
        # Timed up to the end of the stream.
        outcomes = run.durations_from_internal_json(
            lines, DRV_TO_TEST, iter([0.0, 42.0]).__next__
        )
        self.assertEqual(outcomes, {"a": run.TestOutcome("fail", 42)})

    def test_unknown_derivations_and_other_activities_are_ignored(self) -> None:
        lines = [
            '@nix {"action":"start","type":105,"id":1,"fields":["/nix/store/x.drv"]}',
            '@nix {"action":"start","type":100,"id":2,"fields":["/nix/store/a.drv"]}',
            '@nix {"action":"stop","id":1}',
            '@nix {"action":"stop","id":2}',
        ]
        self.assertEqual(
            run.durations_from_internal_json(lines, DRV_TO_TEST, iter([0.0]).__next__),
            {},
        )


class LiveTimingTest(unittest.TestCase):
    """A build is timed while nix runs, as its start and stop lines arrive."""

    def test_each_build_takes_the_time_between_its_lines(self) -> None:
        lines = [
            '@nix {"action":"start","type":105,"id":1,"fields":["/nix/store/a.drv"]}\n',
            '@nix {"action":"start","type":105,"id":2,"fields":["/nix/store/b.drv"]}\n',
            '@nix {"action":"stop","id":1}\n',
            '@nix {"action":"msg","level":0,"msg":"error: a warning of b"}\n',
            '@nix {"action":"stop","id":2}\n',
        ]
        arrived = 0

        def stream() -> Iterator[str]:
            nonlocal arrived
            for line in lines:
                arrived += 1
                yield line

        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.stderr = stream()
        process.wait.return_value = 0
        with (
            mock.patch.object(run.subprocess, "Popen", return_value=process),
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            # Ten seconds pass between two lines. Lines read to the end before
            # any was parsed would all carry the time of the last one.
            attempt = run._build_once(
                ["a", "b"], DRV_TO_TEST, None, lambda: arrived * 10.0
            )
        self.assertEqual(attempt.status, 0)
        self.assertEqual(
            attempt.outcomes,
            {"a": run.TestOutcome("pass", 20), "b": run.TestOutcome("pass", 30)},
        )
        self.assertFalse(attempt.stopped)
        # Each test's start and finish, and nix's own errors and warnings.
        self.assertEqual(
            stderr.getvalue().splitlines(),
            [
                "a: started",
                "b: started",
                "a: finished after 20s",
                "error: a warning of b",
                "b: finished after 30s",
            ],
        )


class WriteDurationsTest(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)

    def test_writes_one_line_per_test_in_run_order(self) -> None:
        path = self.tmp / "nested" / "e2e-durations.json"
        outcomes = {
            "a": run.TestOutcome("pass", 120),
            "b": run.TestOutcome("fail", 0),
        }
        run.write_durations(path, ["a", "b", "cached"], outcomes)
        records = [json.loads(line) for line in path.read_text().splitlines()]
        self.assertEqual(
            records,
            [
                {"test": "a", "result": "pass", "seconds": 120},
                {"test": "b", "result": "fail", "seconds": 0},
                {"test": "cached", "result": "pass", "seconds": 0},
            ],
        )

    def test_a_test_out_of_time_or_never_run_says_so(self) -> None:
        path = self.tmp / "e2e-durations.json"
        outcomes = {
            "h": run.TestOutcome("fail", 750, timed_out=True),
            "q": run.TestOutcome("fail", 0, not_run=True),
        }
        run.write_durations(path, ["h", "q"], outcomes)
        self.assertEqual(
            [json.loads(line) for line in path.read_text().splitlines()],
            [
                {"test": "h", "result": "fail", "seconds": 750, "timed_out": True},
                {"test": "q", "result": "fail", "seconds": 0, "not_run": True},
            ],
        )


class RunBuildTest(unittest.TestCase):
    """run_build against a stand-in `nix` that serves drvPaths and build logs."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        self.log = self.tmp / "nix.log"
        fake = bin_dir / "nix"
        fake.write_text(
            # The interpreter running these tests, by its path: the hermetic Nix
            # build sandbox the ci-python check runs in has no /usr/bin/env.
            f"#!{sys.executable}\n"
            "import json, os, sys, time\n"
            "def emit(payload):\n"
            "    print('@nix ' + json.dumps(payload), file=sys.stderr, flush=True)\n"
            "args = sys.argv[1:]\n"
            "if args[0] == 'eval':\n"
            "    expression = args[args.index('--apply') + 1]\n"
            "    names = json.loads(expression.split(\"''\")[1])\n"
            "    print(json.dumps({n: f'/nix/store/{n}.drv' for n in names}))\n"
            "elif args[0] == 'build':\n"
            "    with open(os.environ['FAKE_NIX_LOG'], 'a') as log:\n"
            "        log.write('build ' + ' '.join(args) + '\\n')\n"
            # A test whose name FAKE_NIX_SERVED lists is already in the store: no build.
            "    served = os.environ.get('FAKE_NIX_SERVED', '').split()\n"
            "    ident = 0\n"
            "    for arg in args:\n"
            "        if arg.startswith('/nix/store/') and arg.endswith('.drv^*'):\n"
            "            drv = arg.removesuffix('^*')\n"
            "            name = drv.removeprefix('/nix/store/').removesuffix('.drv')\n"
            "            if name in served:\n"
            "                continue\n"
            "            ident += 1\n"
            "            emit({'action': 'start', 'type': 105, 'id': ident,\n"
            "                  'fields': [drv]})\n"
            "            emit({'action': 'result', 'type': 101, 'id': ident,\n"
            "                  'fields': [name + ' logged this']})\n"
            # The test FAKE_NIX_HANG names never finishes: the build waits
            # until it is stopped, and the tests after it never start.
            "            if name == os.environ.get('FAKE_NIX_HANG'):\n"
            "                time.sleep(60)\n"
            "            emit({'action': 'stop', 'id': ident})\n"
            # FAKE_NIX_FAIL fails the build, as a failed test does.
            "    if os.environ.get('FAKE_NIX_FAIL'):\n"
            "        sys.exit(1)\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        self.bin_dir = bin_dir

    def test_one_build_records_one_duration_per_test(self) -> None:
        durations = self.tmp / "e2e-durations.json"
        env = {
            **os.environ,
            "PATH": f"{self.bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "FAKE_NIX_LOG": str(self.log),
        }
        with mock.patch.dict(os.environ, env, clear=True):
            status = run.run_build(
                ["basic-workflow", "verify"],
                durations_out=durations,
                clock=iter([0.0, 5.0, 60.0, 75.0]).__next__,
            )
        self.assertEqual(status, 0)
        build_calls = self.log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(build_calls), 1, build_calls)
        records = [json.loads(line) for line in durations.read_text().splitlines()]
        self.assertEqual([r["test"] for r in records], ["basic-workflow", "verify"])
        self.assertTrue(all(r["result"] == "pass" for r in records))

    def test_builds_by_derivation_path_with_bounded_jobs(self) -> None:
        env = {
            **os.environ,
            "PATH": f"{self.bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "FAKE_NIX_LOG": str(self.log),
        }
        with (
            mock.patch.dict(os.environ, env, clear=True),
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            status = run.run_build(
                ["basic-workflow", "verify"],
                jobs=3,
                clock=iter([0.0, 5.0, 60.0, 75.0]).__next__,
            )
        self.assertEqual(status, 0)
        (call,) = self.log.read_text(encoding="utf-8").splitlines()
        args = call.split()
        self.assertIn("--keep-going", args)
        self.assertEqual(args[args.index("--max-jobs") + 1], "3")
        self.assertIn("/nix/store/basic-workflow.drv^*", args)
        self.assertFalse([a for a in args if ".e2e." in a], args)
        self.assertIn("2 test(s), 0 failed", stderr.getvalue())

    def test_a_test_the_store_served_fails_only_a_run_that_must_boot(self) -> None:
        env = {
            **os.environ,
            "PATH": f"{self.bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "FAKE_NIX_LOG": str(self.log),
            "FAKE_NIX_SERVED": "verify",
        }
        for require_boot, expected in ((False, 0), (True, 1)):
            durations = self.tmp / f"durations-{require_boot}.jsonl"
            with (
                mock.patch.dict(os.environ, env, clear=True),
                contextlib.redirect_stderr(io.StringIO()) as stderr,
            ):
                status = run.run_build(
                    ["basic-workflow", "verify"],
                    durations_out=durations,
                    clock=iter([0.0, 30.0]).__next__,
                    require_boot=require_boot,
                )
            self.assertEqual(status, expected, stderr.getvalue())
            records = [json.loads(line) for line in durations.read_text().splitlines()]
            self.assertEqual(records[0]["result"], "pass")
            self.assertEqual(records[1]["result"], "fail" if require_boot else "pass")
            self.assertEqual(records[1].get("not_booted", False), require_boot)


    def environ(self, **extra: str) -> dict[str, str]:
        return {
            **os.environ,
            "PATH": f"{self.bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "FAKE_NIX_LOG": str(self.log),
            **extra,
        }

    def test_the_log_of_a_failed_test_is_kept_as_it_was_built(self) -> None:
        logs = self.tmp / "logs"
        with (
            mock.patch.dict(os.environ, self.environ(FAKE_NIX_FAIL="1"), clear=True),
            mock.patch.object(run, "missing_outputs", return_value=["verify"]),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            status = run.run_build(["basic-workflow", "verify"], log_dir=logs)
        self.assertEqual(status, 1)
        self.assertEqual(
            (logs / "verify.log").read_text(encoding="utf-8"), "verify logged this\n"
        )
        # Passing logs are removed; only failures are worth uploading.
        self.assertFalse((logs / "basic-workflow.log").exists())

    def test_the_time_limit_stops_a_hung_test_and_keeps_its_log(self) -> None:
        logs = self.tmp / "logs"
        durations = self.tmp / "durations.jsonl"
        limit = run.TimeLimit(time.monotonic() + 1.0, 600)
        with (
            mock.patch.dict(
                os.environ, self.environ(FAKE_NIX_HANG="verify"), clear=True
            ),
            mock.patch.object(run, "STOP_GRACE_SECONDS", 5),
            mock.patch.object(
                run, "missing_outputs", return_value=["verify", "lifecycle"]
            ),
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            status = run.run_build(
                ["basic-workflow", "verify", "lifecycle"],
                durations_out=durations,
                log_dir=logs,
                retries=1,
                limit=limit,
            )
        self.assertEqual(status, 1)
        records = {
            record["test"]: record
            for record in map(json.loads, durations.read_text().splitlines())
        }
        self.assertEqual(records["basic-workflow"]["result"], "pass")
        self.assertEqual(records["verify"]["result"], "fail")
        self.assertTrue(records["verify"]["timed_out"])
        self.assertTrue(records["lifecycle"]["not_run"])
        # The hung test's log up to the stop, and nothing for the others.
        self.assertEqual(
            (logs / "verify.log").read_text(encoding="utf-8"), "verify logged this\n"
        )
        self.assertFalse((logs / "basic-workflow.log").exists())
        self.assertFalse((logs / "lifecycle.log").exists())
        # nix was told the test's share, and nothing was retried: the run was
        # out of time.
        (call,) = self.log.read_text(encoding="utf-8").splitlines()
        self.assertIn("--timeout", call.split())
        text = stderr.getvalue()
        self.assertIn("verify: started", text)
        self.assertIn("the run reached its time limit: stopping the build", text)
        self.assertIn("verify ran out of time after", text)
        self.assertIn("verify logged this", text)
        self.assertIn("no time left to retry 2 failed test(s)", text)


class FailureTest(unittest.TestCase):
    """How run_build tells a test that failed from one that ran out of time."""

    def test_a_build_still_running_at_the_stop_timed_out(self) -> None:
        attempt = run._Attempt(
            1, {"a": run.TestOutcome("fail", 30)}, unfinished={"a"}, stopped=True
        )
        self.assertEqual(
            run._failure("a", attempt, None),
            run.TestOutcome("fail", 30, timed_out=True),
        )

    def test_a_test_the_stop_kept_from_starting_was_not_run(self) -> None:
        attempt = run._Attempt(1, {}, stopped=True)
        self.assertEqual(
            run._failure("a", attempt, None), run.TestOutcome("fail", 0, not_run=True)
        )

    def test_a_test_that_never_started_otherwise_failed(self) -> None:
        # A dependency failed, so its build never started.
        self.assertEqual(
            run._failure("a", run._Attempt(1, {}), None), run.TestOutcome("fail", 0)
        )

    def test_a_build_nix_stopped_at_its_timeout_timed_out(self) -> None:
        attempt = run._Attempt(101, {"a": run.TestOutcome("pass", 750)}, timeout=750)
        self.assertTrue(run._failure("a", attempt, {"a": 900}).timed_out)

    def test_a_driver_stopped_by_its_own_timeout_timed_out(self) -> None:
        attempt = run._Attempt(1, {"a": run.TestOutcome("pass", 902)}, timeout=1500)
        self.assertTrue(run._failure("a", attempt, {"a": 900}).timed_out)

    def test_a_failure_well_inside_its_time_is_a_plain_failure(self) -> None:
        attempt = run._Attempt(1, {"a": run.TestOutcome("pass", 120)}, timeout=750)
        self.assertEqual(
            run._failure("a", attempt, {"a": 900}), run.TestOutcome("fail", 120)
        )


class TimeLimitTest(unittest.TestCase):
    def test_a_job_keeps_its_reserve_and_shares_the_rest_per_attempt(self) -> None:
        with mock.patch.object(run.time, "monotonic", return_value=1000.0):
            limit = run.job_time_limit(30, retries=1)
            self.assertEqual(limit.deadline, 1000.0 + 25 * 60)
            self.assertEqual(limit.test_seconds, 750)
            self.assertEqual(limit.for_test(), 750)
        self.assertEqual(run.job_time_limit(30, retries=0).test_seconds, 1500)

    def test_a_test_is_stopped_well_before_its_shard_job(self) -> None:
        # The shortest shard job the planner gives, and longer ones: one
        # attempt of a test, even with its retry after it, ends with time to
        # spare for the reporting and the uploads.
        for minutes in (plan.MIN_SHARD_TIMEOUT_MINUTES, 45, 120):
            with self.subTest(minutes=minutes):
                limit = run.job_time_limit(minutes, retries=1)
                self.assertLessEqual(limit.test_seconds, minutes * 60 / 2)
                self.assertLessEqual(
                    2 * limit.test_seconds, (minutes - run.JOB_RESERVE_MINUTES) * 60
                )

    def test_a_test_never_runs_past_the_deadline(self) -> None:
        limit = run.TimeLimit(deadline=1100.0, test_seconds=750)
        with mock.patch.object(run.time, "monotonic", return_value=1000.0):
            self.assertEqual(limit.left(), 100.0)
            self.assertEqual(limit.for_test(), 100)
        with mock.patch.object(run.time, "monotonic", return_value=1200.0):
            self.assertEqual(limit.left(), 0.0)
            self.assertEqual(limit.for_test(), 1)

    def test_a_job_too_short_for_its_reserve_is_refused(self) -> None:
        with self.assertRaisesRegex(run.RunError, "leaves no time to run a test"):
            run.job_time_limit(run.JOB_RESERVE_MINUTES, retries=1)


class EvalDrvsTest(unittest.TestCase):
    @staticmethod
    def names(command: list[str]) -> list[str]:
        return json.loads(command[command.index("--apply") + 1].split("''")[1])

    def fake_run(self, calls: list[list[str]]):
        def fake(command, **_kwargs):
            calls.append(command)
            payload = {name: f"/nix/store/{name}.drv" for name in self.names(command)}
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

        return fake

    def test_batches_bound_each_nix_eval_process(self) -> None:
        calls: list[list[str]] = []
        with mock.patch.object(
            evaluate.subprocess, "run", side_effect=self.fake_run(calls)
        ):
            drvs = run.eval_drvs(["a", "b", "c", "d", "e"], ".#x.e2e", 2, workers=3)
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(c[:3] == ["nix", "eval", "--json"] for c in calls))
        self.assertTrue(all(len(self.names(c)) <= 2 for c in calls))
        self.assertEqual(drvs["e"], "/nix/store/e.drv")
        self.assertEqual(list(drvs), ["a", "b", "c", "d", "e"])

    def test_without_a_batch_size_the_tests_spread_over_the_processes(self) -> None:
        calls: list[list[str]] = []
        with mock.patch.object(
            evaluate.subprocess, "run", side_effect=self.fake_run(calls)
        ):
            drvs = run.eval_drvs(["a", "b", "c", "d", "e"], ".#x.e2e", None, workers=2)
        self.assertEqual(sorted(len(self.names(c)) for c in calls), [2, 3])
        self.assertEqual(list(drvs), ["a", "b", "c", "d", "e"])


class BuildDriversTest(unittest.TestCase):
    @staticmethod
    def fake_eval(_attr, tests, value, **_kwargs) -> dict[str, str]:
        assert value == "t: t.driver.drvPath", value
        return {test: f"/nix/store/{test}-driver.drv" for test in tests}

    def test_evaluates_the_drivers_and_builds_them_in_one_call(self) -> None:
        builds: list[list[str]] = []

        def fake_build(command, **_kwargs):
            builds.append(command)
            built = [
                {
                    "drvPath": f"/nix/store/{test}-driver.drv",
                    "outputs": {"out": f"/nix/store/{test}-driver"},
                }
                for test in ("b", "a")
            ]
            return subprocess.CompletedProcess(command, 0, json.dumps(built), "")

        with (
            mock.patch.object(run.evaluate, "evaluate", side_effect=self.fake_eval),
            mock.patch.object(run.subprocess, "run", side_effect=fake_build),
        ):
            drivers = run.build_drivers(["a", "b"], ".#x.e2e", workers=2)
        self.assertEqual(
            drivers,
            {"a": Path("/nix/store/a-driver"), "b": Path("/nix/store/b-driver")},
        )
        (command,) = builds
        self.assertEqual(command[:4], ["nix", "build", "--no-link", "--json"])
        self.assertEqual(
            command[4:], ["/nix/store/a-driver.drv^*", "/nix/store/b-driver.drv^*"]
        )

    def test_a_driver_that_does_not_build_is_a_run_error(self) -> None:
        failed = subprocess.CompletedProcess(
            [], 1, "", "building\nerror: builder for 'a-driver.drv' failed\n"
        )
        with (
            mock.patch.object(run.evaluate, "evaluate", side_effect=self.fake_eval),
            mock.patch.object(run.subprocess, "run", return_value=failed),
        ):
            with self.assertRaisesRegex(
                run.RunError, "did not build:\nbuilding\nerror: builder for"
            ):
                run.build_drivers(["a"], ".#x.e2e", workers=1)


class AutoJobsTest(unittest.TestCase):
    def meminfo(self, kib: int) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "meminfo"
        path.write_text(f"MemTotal:       {kib} kB\nMemFree: 1 kB\n")
        return path

    def test_a_15_gib_host_runs_three_vms(self) -> None:
        self.assertEqual(run.auto_jobs(self.meminfo(15 * 1024 * 1024), cpus=12), 3)

    def test_cores_cap_the_count(self) -> None:
        self.assertEqual(run.auto_jobs(self.meminfo(64 * 1024 * 1024), cpus=4), 2)

    def test_a_small_or_unreadable_host_still_runs_one(self) -> None:
        self.assertEqual(run.auto_jobs(self.meminfo(2 * 1024 * 1024), cpus=8), 1)
        self.assertEqual(run.auto_jobs(Path("/nonexistent/meminfo"), cpus=8), 1)


class ConsoleSummaryTest(unittest.TestCase):
    def test_lists_every_test_with_failure_logs(self) -> None:
        text = run.format_console_summary(
            ["a", "b", "c"],
            {"a": run.TestOutcome("pass", 50), "b": run.TestOutcome("fail", 7)},
            {"b": "/logs/b.log"},
        )
        lines = text.splitlines()
        self.assertTrue(lines[0].startswith("pass") and lines[0].endswith("a"))
        self.assertIn("FAIL", lines[1])
        self.assertTrue(lines[1].endswith("log: /logs/b.log"))
        self.assertTrue(lines[2].startswith("cached"))
        self.assertEqual(lines[3], "3 test(s), 1 failed")


class RetryTest(unittest.TestCase):
    """run_build's failure detection, retry and flaky marking, nix mocked out."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        patches = [
            mock.patch.object(run, "eval_drvs", side_effect=self._drvs),
            mock.patch.object(run, "_write_nix_log", side_effect=self._log),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.logged: list[str] = []

    @staticmethod
    def _drvs(tests, *_args) -> dict[str, str]:
        return {test: f"/nix/store/{test}.drv" for test in tests}

    def _log(self, drv: str, path: Path) -> None:
        self.logged.append(path.name)

    def run_with(
        self,
        builds: list[tuple[int, dict[str, run.TestOutcome]]],
        missing: list[list[str]],
        retries: int,
        require_boot: bool = False,
    ) -> tuple[int, list[dict[str, object]], list[list[str]]]:
        built: list[list[str]] = []

        def fake_build(tests, *_args):
            built.append(list(tests))
            status, outcomes = builds.pop(0)
            return run._Attempt(status, outcomes)

        durations = self.tmp / "d.jsonl"
        with (
            mock.patch.object(run, "_build_once", side_effect=fake_build),
            mock.patch.object(run, "missing_outputs", side_effect=missing),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            status = run.run_build(
                ["a", "b", "c"],
                durations_out=durations,
                retries=retries,
                log_dir=self.tmp / "logs",
                require_boot=require_boot,
            )
        records = [json.loads(line) for line in durations.read_text().splitlines()]
        return status, records, built

    def test_a_pass_on_retry_is_flaky_and_the_run_passes(self) -> None:
        status, records, built = self.run_with(
            builds=[
                (
                    1,
                    {
                        "a": run.TestOutcome("pass", 50),
                        "b": run.TestOutcome("pass", 70),
                    },
                ),
                (0, {"b": run.TestOutcome("pass", 65)}),
            ],
            missing=[["b"], []],
            retries=1,
        )
        self.assertEqual(status, 0)
        self.assertEqual(built, [["a", "b", "c"], ["b"]])
        self.assertEqual(
            records,
            [
                {"test": "a", "result": "pass", "seconds": 50},
                {"test": "b", "result": "pass", "seconds": 65, "flaky": True},
                {"test": "c", "result": "pass", "seconds": 0},
            ],
        )
        self.assertEqual(self.logged, [])

    def test_a_test_failing_every_attempt_fails_the_run_and_keeps_its_log(
        self,
    ) -> None:
        status, records, built = self.run_with(
            builds=[(1, {"b": run.TestOutcome("pass", 70)}), (1, {})],
            missing=[["b"], ["b"]],
            retries=1,
        )
        self.assertEqual(status, 1)
        self.assertEqual(len(built), 2)
        self.assertEqual(records[1], {"test": "b", "result": "fail", "seconds": 70})
        self.assertEqual(self.logged, ["b.log"])

    def test_without_retries_a_failure_is_not_rebuilt(self) -> None:
        status, _records, built = self.run_with(
            builds=[(1, {})], missing=[["c"]], retries=0
        )
        self.assertEqual(status, 1)
        self.assertEqual(built, [["a", "b", "c"]])

    def test_a_failed_build_without_a_failed_test_keeps_its_status(self) -> None:
        status, records, built = self.run_with(
            builds=[(100, {})], missing=[[]], retries=1
        )
        self.assertEqual(status, 100)
        self.assertEqual(len(built), 1)
        self.assertTrue(all(r["result"] == "pass" for r in records))

    def test_a_green_build_never_queries_the_store(self) -> None:
        status, _records, built = self.run_with(builds=[(0, {})], missing=[], retries=1)
        self.assertEqual(status, 0)
        self.assertEqual(len(built), 1)

    def test_a_run_that_must_boot_fails_a_test_the_store_served(self) -> None:
        status, records, built = self.run_with(
            builds=[
                (
                    0,
                    {
                        "a": run.TestOutcome("pass", 50),
                        "b": run.TestOutcome("pass", 70),
                    },
                )
            ],
            missing=[],
            retries=1,
            require_boot=True,
        )
        self.assertEqual(status, 1)
        # Building again cannot boot a test whose output the store holds.
        self.assertEqual(len(built), 1)
        self.assertEqual(
            records,
            [
                {"test": "a", "result": "pass", "seconds": 50},
                {"test": "b", "result": "pass", "seconds": 70},
                {"test": "c", "result": "fail", "seconds": 0, "not_booted": True},
            ],
        )
        self.assertEqual(self.logged, [])

    def test_a_run_that_must_boot_passes_when_every_test_was_built(self) -> None:
        status, records, _built = self.run_with(
            builds=[(0, {test: run.TestOutcome("pass", 40) for test in "abc"})],
            missing=[],
            retries=1,
            require_boot=True,
        )
        self.assertEqual(status, 0)
        self.assertTrue(all(r["result"] == "pass" for r in records))

    def test_a_run_that_must_boot_fails_a_retry_the_store_served(self) -> None:
        # b fails its build; the retry finds its output without building it.
        status, records, _built = self.run_with(
            builds=[
                (
                    1,
                    {test: run.TestOutcome("pass", 40) for test in "abc"},
                ),
                (0, {}),
            ],
            missing=[["b"], []],
            retries=1,
            require_boot=True,
        )
        self.assertEqual(status, 1)
        self.assertEqual(
            records[1],
            {"test": "b", "result": "fail", "seconds": 0, "not_booted": True},
        )


class MissingOutputsTest(unittest.TestCase):
    def test_a_test_with_an_invalid_output_is_missing(self) -> None:
        def fake_run(command, **_kwargs):
            if command[:3] == ["nix-store", "--query", "--outputs"]:
                name = command[3].removeprefix("/nix/store/").removesuffix(".drv")
                stdout = f"/nix/store/out-{name}\n"
            else:
                self.assertEqual(
                    command[:3], ["nix-store", "--check-validity", "--print-invalid"]
                )
                stdout = "/nix/store/out-b\n"
            return subprocess.CompletedProcess(command, 0, stdout=stdout)

        with mock.patch.object(run.subprocess, "run", side_effect=fake_run):
            missing = run.missing_outputs(
                {"/nix/store/a.drv": "a", "/nix/store/b.drv": "b"}
            )
        self.assertEqual(missing, ["b"])


class ReportTest(unittest.TestCase):
    OUTCOMES = {
        "a": run.TestOutcome("pass", 40),
        "b": run.TestOutcome("pass", 90, flaky=True),
        "c": run.TestOutcome("fail", 12),
    }

    def test_summary_lists_failures_and_flaky_passes_first(self) -> None:
        summary = run.format_summary("E2E shard 1/2", ["a", "b", "c"], self.OUTCOMES)
        self.assertIn("## E2E shard 1/2", summary)
        self.assertIn("3 test(s): 2 passed (1 FLAKY), 1 failed.", summary)
        rows = [line for line in summary.splitlines() if line.startswith("| `")]
        self.assertEqual(
            rows,
            [
                "| `c` | FAIL | 12 |",
                "| `b` | FLAKY (passed on retry) | 90 |",
                "| `a` | pass | 40 |",
            ],
        )

    def test_annotations_flag_failed_and_flaky_tests(self) -> None:
        self.assertEqual(
            run.format_annotations(["a", "b", "c"], self.OUTCOMES),
            [
                "::warning title=FLAKY E2E test::b failed, then passed on retry",
                "::error title=E2E test failed::c failed",
            ],
        )

    def test_a_test_that_did_not_boot_is_named_as_such(self) -> None:
        outcomes = {"d": run.TestOutcome("fail", 0, not_booted=True)}
        summary = run.format_summary("E2E shard 1/1", ["d"], outcomes)
        self.assertIn("| `d` | FAIL (not booted) | 0 |", summary)
        self.assertIn("1 test(s): 0 passed (0 FLAKY), 1 failed.", summary)
        (annotation,) = run.format_annotations(["d"], outcomes)
        self.assertTrue(
            annotation.startswith("::error title=E2E test not booted::d did not boot"),
            annotation,
        )

    def test_a_test_out_of_time_and_one_never_run_are_named_as_such(self) -> None:
        outcomes = {
            "h": run.TestOutcome("fail", 750, timed_out=True),
            "q": run.TestOutcome("fail", 0, not_run=True),
        }
        summary = run.format_summary("E2E shard 1/1", ["h", "q"], outcomes)
        self.assertIn("| `h` | FAIL (timed out) | 750 |", summary)
        self.assertIn("| `q` | FAIL (not run) | 0 |", summary)
        self.assertIn("2 test(s): 0 passed (0 FLAKY), 2 failed.", summary)
        timed_out, not_run = run.format_annotations(["h", "q"], outcomes)
        self.assertTrue(
            timed_out.startswith(
                "::error title=E2E test timed out::h ran out of time after 750s"
            ),
            timed_out,
        )
        self.assertTrue(
            not_run.startswith("::error title=E2E test not run::q did not start"),
            not_run,
        )
        console = run.format_console_summary(["h", "q"], outcomes, {"h": "/l/h.log"})
        self.assertIn("FAIL (timed out)", console)
        self.assertTrue(console.splitlines()[0].endswith("h  log: /l/h.log"))


class ExecuteEnvironmentTest(unittest.TestCase):
    """Where the drivers' scratch directories go and what the host must allow."""

    def test_runner_temp_holds_the_scratch_directories(self) -> None:
        environ = {"RUNNER_TEMP": "/home/runner/work/_temp", "TMPDIR": "/tmp"}
        self.assertEqual(run.scratch_base(environ), Path("/home/runner/work/_temp"))

    def test_without_runner_temp_the_temporary_directory_holds_them(self) -> None:
        self.assertEqual(run.scratch_base({}), Path(tempfile.gettempdir()))

    def test_a_hosted_runner_leaves_room_for_the_longest_socket(self) -> None:
        base = "/home/runner/work/_temp"
        # virtiofsd's store socket for the longest node name in the suite.
        socket = f"{base}/e2e-abcdefgh/vm-state-notify_send/tmp.abcdefghij/nix-store"
        self.assertLessEqual(len(socket) - len(base), run.SOCKET_TAIL_BYTES)
        self.assertLessEqual(len(base) + run.SOCKET_TAIL_BYTES, run.SOCKET_PATH_MAX)

    def test_a_base_one_byte_longer_than_the_room_left_is_refused(self) -> None:
        room = run.SOCKET_PATH_MAX - run.SOCKET_TAIL_BYTES
        # The length comes first: a base of `room` bytes passes it, and this
        # one is refused only because it does not exist.
        with self.assertRaisesRegex(run.RunError, "is not a directory"):
            run.check_scratch_base(Path("/" + "x" * (room - 1)))
        with self.assertRaisesRegex(run.RunError, f"has at most {room} bytes"):
            run.check_scratch_base(Path("/" + "x" * room))

    def test_the_base_must_be_a_directory(self) -> None:
        run.check_scratch_base(Path("/"))
        with self.assertRaisesRegex(run.RunError, "^/nonexistent is not a directory"):
            run.check_scratch_base(Path("/nonexistent"))

    def test_the_hard_limit_of_a_job_is_too_low_for_virtiofsd(self) -> None:
        warning = run.open_file_warning(65_536)
        assert warning is not None
        self.assertIn("hard open-file limit is 65536", warning)
        self.assertIn("prlimit", warning)

    def test_the_hard_limit_of_systemd_and_above_are_enough(self) -> None:
        for hard_limit in (524_288, 1_048_576, resource.RLIM_INFINITY):
            with self.subTest(hard_limit=hard_limit):
                self.assertIsNone(run.open_file_warning(hard_limit))


class SuiteSocketsTest(unittest.TestCase):
    """The suite's VMs make no socket longer than the scratch base check allows."""

    def test_no_node_name_is_longer_than_the_reserve(self) -> None:
        names = scan_node_names()
        # A scan that found nothing would let any name through.
        self.assertIn("machine", names)
        for name, path in sorted(names.items()):
            with self.subTest(node=name, file=str(path.relative_to(REPO_ROOT))):
                self.assertLessEqual(
                    len(name.encode()),
                    run.NODE_NAME_RESERVE,
                    "raise NODE_NAME_RESERVE in ci/e2e/run.py, which leaves "
                    "fewer bytes for RUNNER_TEMP, or shorten the node name",
                )

    def test_no_test_adds_a_socket_the_budget_leaves_out(self) -> None:
        # swtpm's socket lies at vm-state-<node>/<node>-swtpm/socket.ctrl, longer
        # than virtiofsd's for a node name over 6 bytes, and a share of a
        # test's own names a virtiofsd socket that may be longer than
        # nix-store's.
        found = [
            f"{path.relative_to(REPO_ROOT)}:{number}: {line.strip()}"
            for path in e2e_sources()
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            )
            if re.search(r"\b(?:tpm|sharedDirectories)\b", line)
        ]
        self.assertEqual(found, [], "count their sockets in SOCKET_TAIL_BYTES first")


class NodeNameScanTest(unittest.TestCase):
    """node_names_in over crafted node blocks: the scanner's parsing rules."""

    def test_a_static_block_yields_every_key_in_order(self) -> None:
        text = "  nodes = {\n    alpha = _: { };\n    beta = _: { };\n  };\n"
        self.assertEqual(list(node_names_in(text, "t.nix")), ["alpha", "beta"])

    def test_a_node_whose_value_spans_lines_is_still_one_key(self) -> None:
        # nixfmt sets a node's own braces two spaces deeper than the block, so
        # they are read neither as the block's close nor as another node.
        text = (
            "  nodes = {\n"
            "    server =\n"
            "      { ... }:\n"
            "      {\n"
            "        services.nfs.server.enable = true;\n"
            "      };\n"
            "    client = _: { };\n"
            "  };\n"
        )
        self.assertEqual(list(node_names_in(text, "t.nix")), ["server", "client"])

    def test_a_dynamic_merge_fails(self) -> None:
        # A static attrset merged with a listToAttrs/map builds its nodes at
        # eval time: their names never reach the scan, so a name too long for
        # the socket budget would pass unseen. The soak lane once did this
        # with a 12-byte name.
        text = (
            "  nodes = {\n"
            "    soaker = _: decoyNode;\n"
            "  }\n"
            "  // builtins.listToAttrs (\n"
            "    map (name: {\n"
            "      inherit name;\n"
            "      value = _: neighbourNode;\n"
            "    }) neighbours\n"
            "  );\n"
        )
        with self.assertRaisesRegex(
            AssertionError, r"soak\.nix: the nodes block ends in '}', not '};'"
        ):
            list(node_names_in(text, "soak.nix"))

    def test_a_merge_on_the_closing_line_fails(self) -> None:
        text = "  nodes = {\n    machine = _: { };\n  } // extraNodes;\n"
        with self.assertRaisesRegex(AssertionError, r"ends in '} // extraNodes;'"):
            list(node_names_in(text, "bad.nix"))

    def test_a_dynamic_entry_inside_the_literal_still_fails(self) -> None:
        # Inside the braces, at a key's depth, a construct with no node name is
        # one the scan could not read: it must fail rather than slip through.
        text = "  nodes = {\n    machine = _: { };\n    map (n: { }) extra\n  };\n"
        with self.assertRaisesRegex(
            AssertionError, r"bad\.nix: unrecognised node 'map "
        ):
            list(node_names_in(text, "bad.nix"))

    def test_a_nodes_value_that_is_not_a_block_still_fails(self) -> None:
        with self.assertRaisesRegex(AssertionError, r"bad\.nix: unrecognised 'nodes ="):
            list(node_names_in("  nodes = makeNodes cfg;\n", "bad.nix"))

    def test_nodes_dot_references_are_found(self) -> None:
        self.assertEqual(
            list(node_names_in("config.nodes.machine.system\n", "t.nix")), ["machine"]
        )


@unittest.skipUnless(shutil.which("bash"), "the fake drivers need bash")
class RunDriversTest(unittest.TestCase):
    """run_drivers against stand-in drivers that pass, flake, fail or probe."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        # Stands in for the runner's RUNNER_TEMP, which holds the scratch dirs.
        self.runner_temp = self.tmp / "runner-temp"
        self.runner_temp.mkdir()
        self.stderr = ""
        self.drivers: dict[str, Path] = {}
        # Leaves VM state behind where a real driver keeps it.
        vm_state = (
            'mkdir "$XDG_RUNTIME_DIR/vm-state-machine"\n'
            'echo image > "$XDG_RUNTIME_DIR/vm-state-machine/store.img"\n'
        )
        for name, script in {
            "steady": "echo booted; exit 0\n",
            # Fails on the first run and passes on the second.
            "wobbly": (
                f'if [ -e "{self.tmp}/wobbly.seen" ]; then exit 0; fi\n'
                f'touch "{self.tmp}/wobbly.seen"; echo broken; exit 1\n'
            ),
            "broken": f'echo "scratch=$TMPDIR"\n{vm_state}exit 3\n',
            # Hangs until it is killed.
            "hung": f"{vm_state}echo started\nexec sleep 5\n",
            # Starts a stand-in for its VM, then hangs.
            "vm": (
                f'sleep 300 &\necho $! > "{self.tmp}/vm.pid"\n'
                "echo started\nexec sleep 300\n"
            ),
            # Records its directories.
            "probe": (
                'printf "%s\\n" "$TMPDIR" "$XDG_RUNTIME_DIR" '
                f'> "{self.tmp}/probe.seen"\n{vm_state}'
            ),
        }.items():
            driver = self.tmp / name / "bin" / "nixos-test-driver"
            driver.parent.mkdir(parents=True)
            # Resolve bash from PATH rather than /usr/bin/env, which does not
            # exist in the hermetic Nix build sandbox the ci-python check runs in.
            driver.write_text(f"#!{shutil.which('bash')}\n" + script, encoding="utf-8")
            driver.chmod(0o755)
            self.drivers[name] = self.tmp / name

    def execute(
        self,
        tests: list[str],
        retries: int,
        environ: dict[str, str] | None = None,
        timeout: int = 900,
        limit: run.TimeLimit | None = None,
    ) -> tuple[int, dict[str, run.TestOutcome], Path]:
        reported: dict[str, run.TestOutcome] = {}
        logs = self.tmp / "logs"

        def report(_tests, outcomes):
            reported.update(outcomes)

        with (
            mock.patch.object(
                run,
                "build_drivers",
                side_effect=lambda tests, *_args: {t: self.drivers[t] for t in tests},
            ),
            mock.patch.dict(
                os.environ, {"RUNNER_TEMP": str(self.runner_temp), **(environ or {})}
            ),
            # The stand-in drivers open no sockets, so the length of the
            # temporary directory these tests run in does not matter.
            mock.patch.object(run, "check_scratch_base"),
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            status = run.run_drivers(
                tests,
                {name: timeout for name in tests},
                retries=retries,
                log_dir=logs,
                report=report,
                limit=limit,
            )
        self.stderr = stderr.getvalue()
        return status, reported, logs

    def test_a_driver_passing_on_retry_is_flaky(self) -> None:
        status, outcomes, logs = self.execute(["steady", "wobbly"], retries=1)
        self.assertEqual(status, 0)
        self.assertFalse(outcomes["steady"].flaky)
        self.assertEqual(outcomes["wobbly"].result, "pass")
        self.assertTrue(outcomes["wobbly"].flaky)
        # Passing logs are removed; only failures are worth uploading.
        self.assertEqual(list(logs.glob("*.log")), [])

    def test_a_failing_driver_fails_the_run_and_keeps_its_log(self) -> None:
        status, outcomes, logs = self.execute(["steady", "broken"], retries=1)
        self.assertEqual(status, 1)
        self.assertEqual(outcomes["broken"].result, "fail")
        log = (logs / "broken.log").read_text(encoding="utf-8")
        # Every driver runs with a scratch TMPDIR of its own.
        self.assertIn("scratch=", log)
        self.assertNotIn(f"scratch={tempfile.gettempdir()}\n", log)
        # A failed test's VM state goes with its scratch directory, so it
        # cannot fill the disk under the next test.
        self.assertEqual(list(self.runner_temp.iterdir()), [])

    def test_a_driver_that_times_out_fails_and_leaves_no_vm_state(self) -> None:
        with mock.patch.object(run, "DRIVER_GRACE_SECONDS", 0):
            status, outcomes, logs = self.execute(["hung"], retries=0, timeout=1)
        self.assertEqual(status, 1)
        self.assertEqual(outcomes["hung"].result, "fail")
        self.assertTrue(outcomes["hung"].timed_out)
        self.assertIn("hung: timed out in", self.stderr)
        # It was killed after it had written its VM state, and that is gone.
        self.assertIn("started", (logs / "hung.log").read_text(encoding="utf-8"))
        self.assertEqual(list(self.runner_temp.iterdir()), [])

    def test_a_driver_keeps_its_vm_state_in_a_short_scratch_dir_on_disk(
        self,
    ) -> None:
        # The runtime directory of the job: a tmpfs in RAM on a hosted runner.
        inherited = self.tmp / "run-user"
        inherited.mkdir()
        status, _outcomes, _logs = self.execute(
            ["probe"], retries=0, environ={"XDG_RUNTIME_DIR": str(inherited)}
        )
        self.assertEqual(status, 0, self.stderr)
        seen = (self.tmp / "probe.seen").read_text(encoding="utf-8")
        tmpdir, runtime_dir = seen.splitlines()
        # The driver prefers XDG_RUNTIME_DIR for its VM state; both name the
        # test's own scratch directory under RUNNER_TEMP.
        self.assertEqual(runtime_dir, tmpdir)
        scratch = Path(tmpdir)
        self.assertEqual(scratch.parent, self.runner_temp)
        self.assertRegex(scratch.name, r"^e2e-\w{8}$")
        # The scratch directory is gone, and the VM state in it with it.
        self.assertEqual(list(self.runner_temp.iterdir()), [])
        self.assertEqual(list(inherited.iterdir()), [])

    def test_a_low_open_file_limit_warns_and_the_drivers_still_run(self) -> None:
        with mock.patch.object(run.resource, "getrlimit", return_value=(1024, 65_536)):
            status, outcomes, _logs = self.execute(["steady"], retries=0)
        self.assertEqual(status, 0)
        self.assertEqual(outcomes["steady"].result, "pass")
        self.assertIn("warning: the hard open-file limit is 65536", self.stderr)

    def test_a_sufficient_open_file_limit_warns_of_nothing(self) -> None:
        with mock.patch.object(run.resource, "getrlimit", return_value=(1024, 524_288)):
            status, _outcomes, _logs = self.execute(["steady"], retries=0)
        self.assertEqual(status, 0)
        self.assertNotIn("warning:", self.stderr)

    def test_a_driver_out_of_time_is_stopped_with_its_vms(self) -> None:
        with mock.patch.object(run, "DRIVER_GRACE_SECONDS", 0):
            status, outcomes, logs = self.execute(["vm"], retries=0, timeout=1)
        self.assertEqual(status, 1)
        self.assertTrue(outcomes["vm"].timed_out)
        self.assertIn("started", (logs / "vm.log").read_text(encoding="utf-8"))
        # The stand-in VM went with the driver: none outlives its test.
        pid = int((self.tmp / "vm.pid").read_text(encoding="utf-8"))
        self.assertFalse(_running(pid), f"process {pid} outlived its driver")

    def test_a_test_gets_no_more_than_its_share_of_the_run(self) -> None:
        # Its own timeout is long; its share of the run's time is a second.
        limit = run.TimeLimit(time.monotonic() + 600, 1)
        status, outcomes, _logs = self.execute(
            ["hung"], retries=0, timeout=900, limit=limit
        )
        self.assertEqual(status, 1)
        self.assertTrue(outcomes["hung"].timed_out)
        self.assertLess(outcomes["hung"].seconds, 30)

    def test_no_test_starts_too_close_to_the_deadline(self) -> None:
        limit = run.TimeLimit(time.monotonic() + run.MIN_TEST_SECONDS / 2, 600)
        status, outcomes, _logs = self.execute(
            ["steady", "wobbly"], retries=1, limit=limit
        )
        self.assertEqual(status, 1)
        for test in ("steady", "wobbly"):
            self.assertEqual(outcomes[test], run.TestOutcome("fail", 0, not_run=True))
        self.assertIn("steady: not run, out of time", self.stderr)
        self.assertFalse((self.tmp / "wobbly.seen").exists())

    def test_an_unusable_base_stops_the_run_before_any_build(self) -> None:
        too_long = "/" + "x" * (run.SOCKET_PATH_MAX - run.SOCKET_TAIL_BYTES)
        for base, problem in (
            (too_long, r"is too long .*\(config\.sh --work\)"),
            ("/nonexistent", "is not a directory"),
        ):
            with (
                self.subTest(base=base),
                mock.patch.object(run, "build_drivers") as build,
                mock.patch.dict(os.environ, {"RUNNER_TEMP": base}),
            ):
                with self.assertRaisesRegex(run.RunError, problem):
                    run.run_drivers(["steady"], {"steady": 900})
                build.assert_not_called()


class RunCommandTest(unittest.TestCase):
    """The `run` subcommand selects a shard and delegates to one build."""

    def test_shard_selects_tests_and_builds_once(self) -> None:
        from ci.e2e import __main__ as cli

        metadata = Metadata(
            available_targets=["all"],
            leaf_tests=["a", "b", "c", "d"],
            groups={"all": ["a", "b", "c", "d"], "ci": ["a"]},
            timeouts={name: 900 for name in "abcd"},
        )
        captured: dict[str, object] = {}

        def fake_build(tests, **kwargs):
            captured["tests"] = list(tests)
            return 0

        with mock.patch.object(cli, "load_metadata", return_value=metadata):
            build = mock.patch.object(cli.run, "run_build", side_effect=fake_build)
            with build as build_mock, contextlib.redirect_stdout(io.StringIO()):
                code = cli.main(
                    ["run", "all", "--shard", "1/2", "--weights", "/nonexistent"]
                )
        self.assertEqual(code, 0)
        build_mock.assert_called_once()
        # Round-robin without weights puts the even indices on shard 1.
        self.assertEqual(captured["tests"], ["a", "c"])
        self.assertFalse(build_mock.call_args.kwargs["require_boot"])

    def test_require_boot_reaches_the_build(self) -> None:
        from ci.e2e import __main__ as cli

        metadata = Metadata(
            available_targets=["a"],
            leaf_tests=["a"],
            groups={"ci": ["a"]},
            timeouts={"a": 900},
        )
        with (
            mock.patch.object(cli, "load_metadata", return_value=metadata),
            mock.patch.object(cli.run, "run_build", return_value=0) as build,
        ):
            code = cli.main(["run", "a", "--require-boot"])
        self.assertEqual(code, 0)
        self.assertTrue(build.call_args.kwargs["require_boot"])

    def test_execute_reports_a_base_too_long_for_the_sockets(self) -> None:
        from ci.e2e import __main__ as cli

        metadata = Metadata(
            available_targets=["a"],
            leaf_tests=["a"],
            groups={"ci": ["a"]},
            timeouts={"a": 900},
        )
        too_long = "/" + "x" * 100
        with (
            mock.patch.object(cli, "load_metadata", return_value=metadata),
            mock.patch.object(cli.run, "build_drivers") as build,
            mock.patch.dict(os.environ, {"RUNNER_TEMP": too_long}),
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            code = cli.main(["run", "a", "--execute"])
        self.assertEqual(code, cli.EXIT_BAD_INPUT)
        self.assertIn(f"error: {too_long} is too long", stderr.getvalue())
        build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
