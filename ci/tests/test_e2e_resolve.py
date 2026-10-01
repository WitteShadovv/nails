"""Tests for ci/e2e/resolve.py: group expansion and `--affected` selection."""

from __future__ import annotations

import contextlib
import io
import unittest
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

    def test_affected_is_the_ci_group_plus_changed(self) -> None:
        with mock.patch.object(resolve, "changed_leaf_tests", return_value=["c"]):
            resolved = self.resolve_cli("--affected", "HEAD~1").split()
        self.assertEqual(resolved, ["a", "c"])


if __name__ == "__main__":
    unittest.main()
