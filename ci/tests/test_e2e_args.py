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
                    {"index": 1, "count": 2, "tests": ["a", "c"]},
                    {"index": 2, "count": 2, "tests": ["b"]},
                ]
            },
        )


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
