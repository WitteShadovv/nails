"""Tests for ci/e2e/run.py: the internal-json duration parser and one build."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ci.e2e import run
from ci.e2e.metadata import Metadata

DRV_TO_TEST = {"/nix/store/a.drv": "a", "/nix/store/b.drv": "b"}


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
            "#!/usr/bin/env bash\n"
            'case "$1" in\n'
            "  eval)\n"
            '    attr="$3"; name="${attr##*.e2e.}"; name="${name%.drvPath}"\n'
            '    printf "/nix/store/%s.drv" "$name"\n'
            "    ;;\n"
            "  build)\n"
            '    echo "build $*" >>"$FAKE_NIX_LOG"\n'
            '    for arg in "$@"; do\n'
            '      case "$arg" in\n'
            "        *.e2e.*)\n"
            '          name="${arg##*.e2e.}"\n'
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

        def fake_build(tests, **kwargs):  # type: ignore[no-untyped-def]
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


if __name__ == "__main__":
    unittest.main()
