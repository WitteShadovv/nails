"""Tests for ci/e2e/run.py: the internal-json duration parser and one build."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ci.e2e import run
from ci.e2e.metadata import Metadata

DRV_TO_TEST = {"/nix/store/a.drv": "a", "/nix/store/b.drv": "b"}
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


def scan_node_names() -> dict[str, Path]:
    """Every VM node name in the E2E suite, with the first file that names it.

    A node is named as ``nodes.<name>`` or as a key of a ``nodes = {`` block,
    one per line two spaces deeper than the block (nixfmt layout). Any other
    ``nodes =``, or any other entry at that depth, fails the scan rather than
    hide a node from it.
    """
    names: dict[str, Path] = {}
    for path in e2e_sources():
        text = path.read_text(encoding="utf-8")
        shown = path.relative_to(REPO_ROOT)
        for match in re.finditer(rf"\bnodes\.({NIX_NAME})", text):
            names.setdefault(match[1], path)
        for block in re.finditer(r"^( *)nodes =(.*)$", text, re.M):
            indent = block[1]
            if block[2] != " {":
                raise AssertionError(f"{shown}: unrecognised {block[0].strip()!r}")
            body = text[block.end() :].split(f"\n{indent}}};", 1)[0]
            for line in body.splitlines():
                if len(line) - len(line.lstrip()) != len(indent) + 2:
                    continue
                entry = line.strip()
                key = re.match(rf"({NIX_NAME}) =", entry)
                if key is not None:
                    names.setdefault(key[1], path)
                elif not entry.startswith(("#", "}", "]", ")", "''")):
                    raise AssertionError(f"{shown}: unrecognised node {entry!r}")
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
        outcomes = run.durations_from_internal_json(
            lines, DRV_TO_TEST, iter([0.0]).__next__
        )
        self.assertEqual(outcomes, {"a": run.TestOutcome("fail", 0)})

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


@unittest.skipUnless(shutil.which("bash"), "the fake nix needs bash")
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
            # Resolve bash from PATH rather than /usr/bin/env, which does not
            # exist in the hermetic Nix build sandbox the ci-python check runs in.
            f"#!{shutil.which('bash')}\n"
            'case "$1" in\n'
            "  eval)\n"
            '    attr="$3"; name="${attr##*.e2e.}"; name="${name%.drvPath}"\n'
            '    printf "/nix/store/%s.drv" "$name"\n'
            "    ;;\n"
            "  build)\n"
            '    echo "build $*" >>"$FAKE_NIX_LOG"\n'
            '    for arg in "$@"; do\n'
            '      case "$arg" in\n'
            "        /nix/store/*.drv^*)\n"
            '          name="${arg#/nix/store/}"; name="${name%.drv^*}"\n'
            "          id=$((id + 1))\n"
            '          printf \'@nix {"action":"start","type":105,"id":%d,'
            '"fields":["/nix/store/%s.drv"]}\\n\' "$id" "$name" >&2\n'
            '          printf \'@nix {"action":"stop","id":%d}\\n\' "$id" >&2\n'
            "          ;;\n"
            "      esac\n"
            "    done\n"
            "    ;;\n"
            "esac\n",
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


class EvalDrvsTest(unittest.TestCase):
    def test_batches_bound_each_nix_eval_process(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command, **_kwargs):
            calls.append(command)
            names = json.loads(
                "["
                + command[-1]
                .split("[", 1)[1]
                .rsplit("]", 1)[0]
                .strip()
                .replace('" "', '", "')
                + "]"
            )
            payload = {name: f"/nix/store/{name}.drv" for name in names}
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

        with mock.patch.object(run.subprocess, "run", side_effect=fake_run):
            drvs = run.eval_drvs(["a", "b", "c", "d", "e"], ".#x.e2e", 2)
        self.assertEqual(len(calls), 3)
        self.assertTrue(all(c[:3] == ["nix", "eval", "--json"] for c in calls))
        self.assertEqual(drvs["e"], "/nix/store/e.drv")
        self.assertEqual(list(drvs), ["a", "b", "c", "d", "e"])

    def test_without_a_batch_size_each_test_gets_its_own_process(self) -> None:
        with mock.patch.object(
            run, "_eval_drv", side_effect=lambda attr: attr + ".drv"
        ) as single:
            drvs = run.eval_drvs(["a", "b"], ".#x.e2e", None)
        self.assertEqual(single.call_count, 2)
        self.assertEqual(drvs, {"a": ".#x.e2e.a.drv", "b": ".#x.e2e.b.drv"})


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
            mock.patch.object(run, "_eval_drv", side_effect=self._drv),
            mock.patch.object(run, "_write_nix_log", side_effect=self._log),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.logged: list[str] = []

    @staticmethod
    def _drv(attr: str) -> str:
        return f"/nix/store/{attr.rsplit('.', 1)[-1]}.drv"

    def _log(self, drv: str, path: Path) -> None:
        self.logged.append(path.name)

    def run_with(
        self,
        builds: list[tuple[int, dict[str, run.TestOutcome]]],
        missing: list[list[str]],
        retries: int,
    ) -> tuple[int, list[dict[str, object]], list[list[str]]]:
        built: list[list[str]] = []

        def fake_build(tests, *_args):
            built.append(list(tests))
            return builds.pop(0)

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
    ) -> tuple[int, dict[str, run.TestOutcome], Path]:
        reported: dict[str, run.TestOutcome] = {}
        logs = self.tmp / "logs"

        def report(_tests, outcomes):
            reported.update(outcomes)

        with (
            mock.patch.object(
                run,
                "_build_driver",
                side_effect=lambda attr: self.drivers[attr.rsplit(".", 1)[-1]],
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

    def test_an_unusable_base_stops_the_run_before_any_build(self) -> None:
        too_long = "/" + "x" * (run.SOCKET_PATH_MAX - run.SOCKET_TAIL_BYTES)
        for base, problem in (
            (too_long, r"is too long .*\(config\.sh --work\)"),
            ("/nonexistent", "is not a directory"),
        ):
            with (
                self.subTest(base=base),
                mock.patch.object(run, "_build_driver") as build,
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
            mock.patch.object(cli.run, "_build_driver") as build,
            mock.patch.dict(os.environ, {"RUNNER_TEMP": too_long}),
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            code = cli.main(["run", "a", "--execute"])
        self.assertEqual(code, cli.EXIT_BAD_INPUT)
        self.assertIn(f"error: {too_long} is too long", stderr.getvalue())
        build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
