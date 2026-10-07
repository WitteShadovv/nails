"""Tests for ci/e2e/resolve.py: group expansion and `--affected` selection."""

from __future__ import annotations

import contextlib
import io
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from ci.e2e import resolve
from ci.e2e.metadata import Metadata, parse_metadata

METADATA = Metadata(
    available_targets=["a", "b", "c", "smoke", "ci", "all"],
    leaf_tests=["a", "b", "c"],
    groups={"smoke": ["a", "b"], "ci": ["a"], "all": ["a", "b", "c"]},
    timeouts={"a": 900, "b": 900, "c": 1500},
)


class ResolveTargetsTest(unittest.TestCase):
    def test_expands_groups_in_request_order_without_duplicates(self) -> None:
        self.assertEqual(
            resolve.resolve_targets(METADATA, ["smoke", "c", "a"]),
            ["a", "b", "c"],
        )

    def test_a_leaf_name_resolves_before_a_group(self) -> None:
        metadata = parse_metadata(
            {
                "availableTargets": ["a", "shared"],
                "leafTests": ["a", "shared"],
                "groups": {"shared": ["a"]},
                "timeouts": {"a": 900, "shared": 900},
            }
        )
        self.assertEqual(resolve.resolve_targets(metadata, ["shared"]), ["shared"])

    def test_an_alias_resolves_to_its_merged_test(self) -> None:
        metadata = parse_metadata(
            {
                "availableTargets": ["batch", "old-a", "old-b", "all"],
                "leafTests": ["batch"],
                "groups": {"all": ["batch"]},
                "timeouts": {"batch": 900},
                "aliases": {"old-a": "batch", "old-b": "batch"},
            }
        )
        self.assertEqual(metadata.aliases, {"old-a": "batch", "old-b": "batch"})
        # Two old names of one merged test select it once.
        self.assertEqual(
            resolve.resolve_targets(metadata, ["old-a", "old-b"]), ["batch"]
        )
        self.assertEqual(resolve.resolve_targets(metadata, ["old-b", "all"]), ["batch"])

    def test_an_alias_to_an_unknown_test_is_an_error(self) -> None:
        broken = Metadata(
            available_targets=["old"],
            leaf_tests=["a"],
            groups={},
            timeouts={"a": 900},
            aliases={"old": "ghost"},
        )
        with self.assertRaisesRegex(resolve.ResolveError, "unknown leaf test ghost"):
            resolve.resolve_targets(broken, ["old"])

    def test_metadata_without_aliases_still_parses(self) -> None:
        self.assertEqual(METADATA.aliases, {})

    def test_malformed_aliases_are_rejected(self) -> None:
        from ci.e2e.metadata import MetadataError

        with self.assertRaisesRegex(MetadataError, "aliases"):
            parse_metadata(
                {
                    "availableTargets": [],
                    "leafTests": [],
                    "groups": {},
                    "timeouts": {},
                    "aliases": ["old"],
                }
            )

    def test_unknown_target_is_an_error(self) -> None:
        with self.assertRaisesRegex(resolve.ResolveError, "unknown E2E target: nope"):
            resolve.resolve_targets(METADATA, ["nope"])

    def test_group_pointing_at_an_unknown_leaf_is_an_error(self) -> None:
        broken = Metadata(
            available_targets=["group"],
            leaf_tests=["a"],
            groups={"group": ["a", "ghost"]},
            timeouts={"a": 900},
        )
        with self.assertRaisesRegex(resolve.ResolveError, "unknown leaf test ghost"):
            resolve.resolve_targets(broken, ["group"])


class ResolveAffectedTest(unittest.TestCase):
    def test_selects_the_ci_group_plus_changed_tests(self) -> None:
        with mock.patch.object(
            resolve, "changed_leaf_tests", return_value=["c", "a"]
        ) as changed:
            selected = resolve.resolve_affected(METADATA, "HEAD~1")
        changed.assert_called_once_with(METADATA, "HEAD~1")
        # "a" is already in the ci group, so it is not added twice; "c" is new.
        self.assertEqual(selected, ["a", "c"])

    def test_no_changes_leaves_only_the_ci_group(self) -> None:
        with mock.patch.object(resolve, "changed_leaf_tests", return_value=[]):
            self.assertEqual(resolve.resolve_affected(METADATA, "HEAD~1"), ["a"])


class ChangedLeafTestsTest(unittest.TestCase):
    def test_compares_one_evaluation_per_side(self) -> None:
        sides = {
            ".": {
                "a": "/nix/store/a1.drv",
                "b": "/nix/store/b1.drv",
                "c": "/nix/store/c.drv",
            },
            "git+file:///repo?rev=abc": {
                "a": "/nix/store/a1.drv",
                "b": "/nix/store/b0.drv",
            },
        }
        with (
            mock.patch.object(
                resolve, "base_flake_ref", return_value="git+file:///repo?rev=abc"
            ),
            mock.patch.object(
                resolve, "drv_paths", side_effect=lambda ref, tests: sides[ref]
            ) as evaluate,
        ):
            changed = resolve.changed_leaf_tests(METADATA, "main")
        # b changed and c is new at this revision.
        self.assertEqual(changed, ["b", "c"])
        self.assertEqual(evaluate.call_count, 2)

    def test_a_base_that_does_not_evaluate_changes_everything(self) -> None:
        def evaluate(ref, tests):
            if ref == ".":
                return {test: f"/nix/store/{test}.drv" for test in tests}
            raise subprocess.CalledProcessError(1, ["nix"], stderr="error: boom\n")

        with (
            mock.patch.object(resolve, "base_flake_ref", return_value="old"),
            mock.patch.object(resolve, "drv_paths", side_effect=evaluate),
            contextlib.redirect_stderr(io.StringIO()) as err,
        ):
            changed = resolve.changed_leaf_tests(METADATA, "main")
        self.assertEqual(changed, ["a", "b", "c"])
        self.assertIn("error: boom", err.getvalue())


class FlakeRefTest(unittest.TestCase):
    def test_a_git_revision_is_pinned_to_its_commit(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout="0123abcd\n")
        with mock.patch.object(
            resolve.subprocess, "run", return_value=completed
        ) as git:
            ref = resolve.base_flake_ref("origin/main", Path("/repo"))
        self.assertEqual(ref, "git+file:///repo?rev=0123abcd")
        self.assertEqual(
            git.call_args.args[0],
            ["git", "-C", "/repo", "rev-parse", "--verify", "origin/main^{commit}"],
        )

    def test_a_flake_reference_is_used_as_given(self) -> None:
        self.assertEqual(resolve.base_flake_ref("github:o/r/abc"), "github:o/r/abc")

    def test_an_unknown_revision_is_an_error(self) -> None:
        completed = subprocess.CompletedProcess([], 128, stdout="", stderr="bad")
        with mock.patch.object(resolve.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(resolve.ResolveError, "not a commit"):
                resolve.base_flake_ref("nope", Path("/repo"))

    def test_drv_paths_evaluates_every_test_in_one_call(self) -> None:
        completed = subprocess.CompletedProcess(
            [], 0, stdout='{"a": "/nix/store/a.drv"}'
        )
        with mock.patch.object(
            resolve.subprocess, "run", return_value=completed
        ) as nix:
            paths = resolve.drv_paths(".", ["a", "gone"])
        self.assertEqual(paths, {"a": "/nix/store/a.drv"})
        command = nix.call_args.args[0]
        self.assertEqual(
            command[:4], ["nix", "eval", "--json", f".#{resolve.E2E_ATTR}"]
        )
        self.assertIn("''[\"a\", \"gone\"]''", command[5])

    def test_drv_paths_refuses_names_that_are_not_plain(self) -> None:
        with self.assertRaisesRegex(resolve.ResolveError, "odd test name"):
            resolve.drv_paths(".", ["a''; x"])


class ResolveCommandTest(unittest.TestCase):
    """The `resolve` subcommand with metadata injected in place of `nix eval`."""

    def resolve_cli(self, *args: str) -> str:
        from ci.e2e import __main__ as cli

        out = io.StringIO()
        with mock.patch.object(cli, "load_metadata", return_value=METADATA):
            with contextlib.redirect_stdout(out):
                code = cli.main(["resolve", *args])
        self.assertEqual(code, 0)
        return out.getvalue()

    def test_resolves_a_group_to_its_leaf_tests(self) -> None:
        self.assertEqual(self.resolve_cli("smoke").split(), ["a", "b"])

    def test_exclude_leaves_out_a_group(self) -> None:
        self.assertEqual(self.resolve_cli("all", "--exclude", "smoke").split(), ["c"])

    def test_an_unknown_exclude_is_an_error(self) -> None:
        from ci.e2e import __main__ as cli

        with mock.patch.object(cli, "load_metadata", return_value=METADATA):
            with contextlib.redirect_stderr(io.StringIO()) as err:
                code = cli.main(["resolve", "all", "--exclude", "nope"])
        self.assertEqual(code, cli.EXIT_BAD_INPUT)
        self.assertIn("unknown E2E target: nope", err.getvalue())

    def test_affected_is_the_ci_group_plus_changed(self) -> None:
        with mock.patch.object(resolve, "changed_leaf_tests", return_value=["c"]):
            resolved = self.resolve_cli("--affected", "HEAD~1").split()
        self.assertEqual(resolved, ["a", "c"])


if __name__ == "__main__":
    unittest.main()
