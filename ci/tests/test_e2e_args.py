"""Tests for ci/e2e argument routing, including the paths that need no nix."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ci.e2e import __main__ as cli
from ci.e2e.metadata import Metadata

METADATA = Metadata(
    available_targets=["a", "b", "c", "all"],
    leaf_tests=["a", "b", "c"],
    groups={"all": ["a", "b", "c"], "ci": ["a"]},
    timeouts={"a": 900, "b": 900, "c": 900},
)


def _fail_metadata(*_args: object, **_kwargs: object) -> Metadata:
    raise AssertionError("metadata (nix) must not be loaded on this path")


class NoNixPathsTest(unittest.TestCase):
    """--help and interactive parse and dispatch without touching nix."""

    def test_top_level_help_needs_no_nix(self) -> None:
        with mock.patch.object(cli, "load_metadata", _fail_metadata):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                with self.assertRaises(SystemExit) as caught:
                    cli.main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("usage:", out.getvalue())

    def test_interactive_help_needs_no_nix(self) -> None:
        with mock.patch.object(cli, "load_metadata", _fail_metadata):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    cli.main(["interactive", "foo", "--help"])
        self.assertEqual(caught.exception.code, 0)

    def test_interactive_shortcut_launches_the_driver_without_nix(self) -> None:
        with mock.patch.object(cli, "load_metadata", _fail_metadata):
            with mock.patch.object(cli.interactive, "exec_interactive") as launch:
                self.assertEqual(cli.main(["-i", "basic-workflow"]), 0)
        launch.assert_called_once_with("basic-workflow")

    def test_interactive_subcommand_launches_the_driver(self) -> None:
        with mock.patch.object(cli, "load_metadata", _fail_metadata):
            with mock.patch.object(cli.interactive, "exec_interactive") as launch:
                self.assertEqual(cli.main(["interactive", "basic-workflow"]), 0)
        launch.assert_called_once_with("basic-workflow")


class RoutingTest(unittest.TestCase):
    def test_a_bare_target_is_an_implicit_run(self) -> None:
        captured: dict[str, object] = {}

        def fake_build(tests, **kwargs):  # type: ignore[no-untyped-def]
            captured["tests"] = list(tests)
            return 0

        with mock.patch.object(cli, "load_metadata", return_value=METADATA):
            with mock.patch.object(cli.run, "run_build", side_effect=fake_build):
                self.assertEqual(cli.main(["b"]), 0)
        self.assertEqual(captured["tests"], ["b"])

    def test_no_arguments_runs_the_default_target(self) -> None:
        captured: dict[str, object] = {}

        def fake_build(tests, **kwargs):  # type: ignore[no-untyped-def]
            captured["tests"] = list(tests)
            return 0

        with mock.patch.object(cli, "load_metadata", return_value=METADATA):
            with mock.patch.object(cli.run, "run_build", side_effect=fake_build):
                self.assertEqual(cli.main([]), 0)
        # The default target is the ci group.
        self.assertEqual(captured["tests"], ["a"])


class PlanMatrixTest(unittest.TestCase):
    def test_github_matrix_lists_every_shard(self) -> None:
        out = io.StringIO()
        with mock.patch.object(cli, "load_metadata", return_value=METADATA):
            with contextlib.redirect_stdout(out):
                code = cli.main(
                    [
                        "plan",
                        "all",
                        "--shards",
                        "2",
                        "--format",
                        "github-matrix",
                        "--weights",
                        "/nonexistent",
                    ]
                )
        self.assertEqual(code, 0)
        matrix = json.loads(out.getvalue())
        self.assertEqual(
            matrix,
            {
                "include": [
                    {"index": 1, "count": 2, "tests": ["a", "c"], "timeout": 30},
                    {"index": 2, "count": 2, "tests": ["b"], "timeout": 30},
                ]
            },
        )


class PlanShardCountTest(unittest.TestCase):
    def plan_matrix(self, *args: str, weights: dict[str, int] | None = None) -> dict:
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "weights.json"
            if weights is not None:
                path.write_text(json.dumps(weights), encoding="utf-8")
            out = io.StringIO()
            with mock.patch.object(cli, "load_metadata", return_value=METADATA):
                with contextlib.redirect_stdout(out):
                    code = cli.main(
                        [
                            "plan",
                            *args,
                            "--format",
                            "github-matrix",
                            "--weights",
                            str(path),
                        ]
                    )
        self.assertEqual(code, 0)
        return json.loads(out.getvalue())

    def test_max_shards_never_plans_an_empty_shard(self) -> None:
        matrix = self.plan_matrix("b", "--max-shards", "10")
        self.assertEqual(
            matrix,
            {"include": [{"index": 1, "count": 1, "tests": ["b"], "timeout": 30}]},
        )

    def test_max_shards_follows_the_shard_budget(self) -> None:
        matrix = self.plan_matrix(
            "all",
            "--max-shards",
            "10",
            "--shard-seconds",
            "400",
            weights={"a": 300, "b": 300, "c": 200},
        )
        self.assertEqual([entry["count"] for entry in matrix["include"]], [2, 2])
        tests = sorted(t for entry in matrix["include"] for t in entry["tests"])
        self.assertEqual(tests, ["a", "b", "c"])

    def test_a_fixed_count_drops_the_empty_shards_from_the_matrix(self) -> None:
        matrix = self.plan_matrix("a", "--shards", "3")
        self.assertEqual(
            matrix,
            {"include": [{"index": 1, "count": 1, "tests": ["a"], "timeout": 30}]},
        )

    def test_shards_and_max_shards_exclude_each_other(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                cli.main(["plan", "all", "--shards", "2", "--max-shards", "4"])
        self.assertEqual(caught.exception.code, 2)


class RunOptionsTest(unittest.TestCase):
    def test_execute_runs_the_drivers_with_retries_and_a_summary(self) -> None:
        captured: dict[str, object] = {}

        def fake_drivers(tests, timeouts, **kwargs):  # type: ignore[no-untyped-def]
            captured.update(tests=list(tests), timeouts=dict(timeouts), **kwargs)
            kwargs["report"](tests, {"a": cli.run.TestOutcome("pass", 31, flaky=True)})
            return 0

        with tempfile.TemporaryDirectory() as name:
            summary = Path(name) / "summary.md"
            out = io.StringIO()
            with mock.patch.object(cli, "load_metadata", return_value=METADATA):
                with mock.patch.object(
                    cli.run, "run_drivers", side_effect=fake_drivers
                ):
                    with contextlib.redirect_stdout(out):
                        code = cli.main(
                            [
                                "run",
                                "a",
                                "--execute",
                                "--retries",
                                "1",
                                "--summary",
                                str(summary),
                                "--github",
                            ]
                        )
            text = summary.read_text(encoding="utf-8")
        self.assertEqual(code, 0)
        self.assertEqual(captured["tests"], ["a"])
        self.assertEqual(captured["timeouts"], {"a": 900, "b": 900, "c": 900})
        self.assertEqual(captured["retries"], 1)
        self.assertIn("FLAKY", text)
        self.assertIn("::warning title=FLAKY E2E test::a", out.getvalue())

    def test_negative_retries_are_rejected(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                cli.main(["run", "a", "--retries", "-1"])
        self.assertEqual(caught.exception.code, 2)


class RegenCommandTest(unittest.TestCase):
    def test_regen_weights_writes_the_median_of_recent_runs(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            tmp = Path(name)
            weights = tmp / "weights.json"
            weights.write_text(json.dumps({"a": 3609, "b": 200}), encoding="utf-8")
            samples = tmp / "d.jsonl"
            samples.write_text(
                json.dumps({"test": "a", "result": "pass", "seconds": 140}) + "\n",
                encoding="utf-8",
            )
            metadata = Metadata(
                available_targets=["a", "b"],
                leaf_tests=["a", "b"],
                groups={},
                timeouts={"a": 900, "b": 900},
            )
            with mock.patch.object(cli, "load_metadata", return_value=metadata):
                with contextlib.redirect_stdout(io.StringIO()):
                    code = cli.main(
                        ["regen-weights", "--weights", str(weights), str(samples)]
                    )
            self.assertEqual(code, 0)
            self.assertEqual(
                weights.read_text(encoding="utf-8"), '{\n  "a": 140,\n  "b": 200\n}\n'
            )


if __name__ == "__main__":
    unittest.main()
