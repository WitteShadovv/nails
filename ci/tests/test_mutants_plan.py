"""Tests for ci/mutants_plan.py, which sizes the in-diff mutation lane."""

from __future__ import annotations

import contextlib
import io
import json
import math
import os
import re
import shlex
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ci import mutants_plan
from ci.mutants_plan import Plan

REPO_ROOT = Path(__file__).resolve().parents[2]

# One entry of `cargo mutants --list --json`, as cargo-mutants 27 prints it.
MUTANT = {
    "name": "nails-base/src/state/mod.rs:88:13: replace == with != in "
    "SystemState::can",
    "package": "nails-base",
    "file": "nails-base/src/state/mod.rs",
    "function": {
        "function_name": "SystemState::can",
        "return_type": "-> bool",
        "span": {
            "start": {"line": 86, "column": 5},
            "end": {"line": 90, "column": 6},
        },
    },
    "span": {
        "start": {"line": 88, "column": 13},
        "end": {"line": 88, "column": 15},
    },
    "replacement": "!=",
    "genre": "BinaryOperator",
    "diff": "--- nails-base/src/state/mod.rs\n+++ replace == with !=\n",
}


def listing(count: int) -> str:
    """What `cargo mutants --list --json` prints for ``count`` mutants."""
    return json.dumps([MUTANT] * count, indent=2)


def slices(mutants: int, shards: int) -> list[int]:
    """How many mutants each shard tests, as cargo-mutants splits them.

    Its default sharding (`--sharding=slice`) gives shard k of n the k-th run of
    ceil(mutants / n) consecutive mutants; the last may be shorter, or empty.
    """
    size = math.ceil(mutants / shards)
    return [max(0, min(mutants, (k + 1) * size) - k * size) for k in range(shards)]


def cargo_mutants_arguments(recipe: str) -> list[str]:
    """The arguments that a justfile recipe passes to `cargo mutants`."""
    text = (REPO_ROOT / "justfile").read_text(encoding="utf-8")
    found = re.search(
        rf"^{re.escape(recipe)}(?: [^\n]*)?:\n((?:[ \t]+[^\n]*\n|\n)*)", text, re.M
    )
    if found is None:
        raise AssertionError(f"no recipe {recipe} in the justfile")
    script = found.group(1).replace("\\\n", " ")
    commands = [line for line in script.splitlines() if "cargo mutants" in line]
    if len(commands) != 1:
        raise AssertionError(f"{recipe} runs cargo mutants {len(commands)} times")
    words = shlex.split(commands[0])
    arguments = []
    for word in words[words.index("mutants") + 1 :]:
        if word in ("||", "|", "&&", ">", ">>"):
            break
        arguments.append(word)
    return arguments


def without(arguments: list[str], flags: set[str], options: set[str]) -> list[str]:
    """``arguments`` less the ``flags`` and the ``options`` with their values."""
    kept = []
    words = iter(arguments)
    for word in words:
        if word in options:
            next(words, None)
        elif word not in flags:
            kept.append(word)
    return kept


class PlanTest(unittest.TestCase):
    def test_the_measured_cost_puts_30_mutants_in_an_ordinary_shard(self) -> None:
        # The figures the comments of ci/mutants_plan.py and docs/ci.md quote.
        self.assertEqual(mutants_plan.capacity(mutants_plan.SHARD_MINUTES), 30)
        self.assertEqual(mutants_plan.capacity(mutants_plan.MAX_SHARD_MINUTES), 66)
        self.assertEqual(mutants_plan.most_mutants(), 792)

    def test_capacity_is_the_most_a_time_box_holds(self) -> None:
        for minutes in range(
            mutants_plan.SHARD_MINUTES, mutants_plan.MAX_SHARD_MINUTES + 1
        ):
            with self.subTest(minutes=minutes):
                most = mutants_plan.capacity(minutes)
                self.assertLessEqual(mutants_plan.shard_minutes(most), minutes)
                self.assertGreater(mutants_plan.shard_minutes(most + 1), minutes)

    def test_a_small_shard_keeps_the_ordinary_time_box(self) -> None:
        self.assertEqual(mutants_plan.shard_minutes(0), mutants_plan.SHARD_MINUTES)
        self.assertEqual(mutants_plan.shard_minutes(1), mutants_plan.SHARD_MINUTES)

    def test_a_diff_without_mutants_runs_no_shard(self) -> None:
        planned = mutants_plan.plan(0)
        self.assertEqual(planned, Plan(0))
        self.assertFalse(planned.too_large)
        self.assertEqual(mutants_plan.matrix(planned), {"include": []})

    def test_the_shards_grow_with_the_diff(self) -> None:
        self.assertEqual(mutants_plan.plan(1), Plan(1, 1, 1, 15))
        self.assertEqual(mutants_plan.plan(30), Plan(30, 1, 30, 15))
        self.assertEqual(mutants_plan.plan(31), Plan(31, 2, 16, 15))
        self.assertEqual(mutants_plan.plan(275), Plan(275, 10, 28, 15))
        self.assertEqual(mutants_plan.plan(360), Plan(360, 12, 30, 15))

    def test_a_diff_beyond_twelve_ordinary_shards_gets_longer_boxes(self) -> None:
        self.assertEqual(mutants_plan.plan(361), Plan(361, 12, 31, 16))
        # The diff whose four fixed shards were all cancelled at 15 minutes.
        self.assertEqual(mutants_plan.plan(409), Plan(409, 12, 35, 18))
        self.assertEqual(mutants_plan.plan(792), Plan(792, 12, 66, 30))

    def test_a_diff_beyond_the_longest_boxes_runs_no_shard(self) -> None:
        planned = mutants_plan.plan(793)
        self.assertEqual(planned, Plan(793))
        self.assertTrue(planned.too_large)
        self.assertEqual(mutants_plan.matrix(planned), {"include": []})

    def test_every_plan_fits_its_bounds(self) -> None:
        ordinary = mutants_plan.capacity(mutants_plan.SHARD_MINUTES)
        for mutants in range(1, 2000):
            planned = mutants_plan.plan(mutants)
            with self.subTest(mutants=mutants):
                if mutants > mutants_plan.most_mutants():
                    self.assertTrue(planned.too_large)
                    continue
                self.assertFalse(planned.too_large)
                self.assertGreaterEqual(planned.shards, 1)
                self.assertLessEqual(planned.shards, mutants_plan.MAX_SHARDS)
                self.assertLessEqual(planned.minutes, mutants_plan.MAX_SHARD_MINUTES)
                self.assertLessEqual(
                    planned.per_shard, mutants_plan.capacity(planned.minutes)
                )
                # Every shard cargo-mutants slices off tests something, and
                # none tests more than the plan sized its time box for.
                tested = slices(mutants, planned.shards)
                self.assertEqual(sum(tested), mutants)
                self.assertGreater(min(tested), 0)
                self.assertEqual(max(tested), planned.per_shard)
                # The fewest shards that fit the ordinary box, or every shard
                # there is.
                if planned.shards < mutants_plan.MAX_SHARDS:
                    self.assertEqual(planned.minutes, mutants_plan.SHARD_MINUTES)
                    self.assertTrue(
                        planned.shards == 1
                        or math.ceil(mutants / (planned.shards - 1)) > ordinary
                    )

    def test_the_matrix_names_each_shard_of_the_plan(self) -> None:
        self.assertEqual(
            mutants_plan.matrix(Plan(61, 3, 21, 15)),
            {
                "include": [
                    {"shard": 0, "shards": 3, "timeout": 15},
                    {"shard": 1, "shards": 3, "timeout": 15},
                    {"shard": 2, "shards": 3, "timeout": 15},
                ]
            },
        )


class CountTest(unittest.TestCase):
    def test_counts_the_listed_mutants(self) -> None:
        self.assertEqual(mutants_plan.count_mutants(listing(3)), 3)
        self.assertEqual(mutants_plan.count_mutants("[]"), 0)

    def test_no_output_is_no_mutant(self) -> None:
        # cargo-mutants prints nothing for a diff that touches no mutant.
        self.assertEqual(mutants_plan.count_mutants(""), 0)
        self.assertEqual(mutants_plan.count_mutants("\n"), 0)

    def test_anything_but_a_list_of_mutants_is_refused(self) -> None:
        for text in ("Found 3 mutants", "{}", '"x"', "[1, 2]", "[{}, []]"):
            with self.subTest(text=text), self.assertRaises(mutants_plan.ListError):
                mutants_plan.count_mutants(text)


class MainTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.summary = self.dir / "summary.md"

    def run_main(self, text: str | None) -> tuple[int, dict[str, str], str]:
        """Run the planner on a listing; return its outputs and stderr."""
        path = self.dir / "mutants.json"
        path.unlink(missing_ok=True)
        if text is not None:
            path.write_text(text, encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with (
            mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(self.summary)}),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            code = mutants_plan.main([str(path)])
        outputs = {}
        for line in out.getvalue().splitlines():
            name, _, value = line.partition("=")
            outputs[name] = value
        return code, outputs, err.getvalue()

    def test_prints_the_plan_as_step_outputs(self) -> None:
        code, outputs, err = self.run_main(listing(409))
        self.assertEqual(code, 0, err)
        self.assertEqual(set(outputs), {"mutants", "shards", "matrix"})
        self.assertEqual(outputs["mutants"], "409")
        self.assertEqual(outputs["shards"], "12")
        include = json.loads(outputs["matrix"])["include"]
        self.assertEqual([entry["shard"] for entry in include], list(range(12)))
        self.assertEqual({entry["shards"] for entry in include}, {12})
        self.assertEqual({entry["timeout"] for entry in include}, {18})
        message = (
            "409 mutants in the diff: 12 shards of at most 35, each time-boxed "
            "at 18 minutes."
        )
        self.assertIn(message, err)
        self.assertNotIn("::warning", err)
        self.assertIn(message, self.summary.read_text(encoding="utf-8"))

    def test_one_shard(self) -> None:
        code, outputs, err = self.run_main(listing(1))
        self.assertEqual(code, 0, err)
        self.assertEqual(outputs["shards"], "1")
        self.assertIn("1 mutant in the diff: one shard, time-boxed at 15", err)

    def test_a_diff_without_mutants_plans_no_shard(self) -> None:
        code, outputs, err = self.run_main("")
        self.assertEqual(code, 0, err)
        self.assertEqual(outputs["mutants"], "0")
        self.assertEqual(outputs["shards"], "0")
        self.assertEqual(json.loads(outputs["matrix"]), {"include": []})
        self.assertIn("no mutable code", self.summary.read_text(encoding="utf-8"))

    def test_a_diff_too_large_is_reported_and_passes(self) -> None:
        code, outputs, err = self.run_main(listing(1000))
        self.assertEqual(code, 0, err)
        self.assertEqual(outputs["mutants"], "1000")
        self.assertEqual(outputs["shards"], "0")
        self.assertEqual(json.loads(outputs["matrix"]), {"include": []})
        self.assertIn("::warning title=Diff too large for mutation testing::", err)
        summary = self.summary.read_text(encoding="utf-8")
        self.assertIn("The diff holds 1000 mutants, more than the lane can", summary)
        self.assertIn("hold 792. No shard runs and the lane passes", summary)

    def test_a_listing_it_cannot_read_fails_without_outputs(self) -> None:
        for text in (None, "not json", '{"mutants": []}'):
            with self.subTest(text=text):
                code, outputs, err = self.run_main(text)
                self.assertEqual(code, 1)
                self.assertEqual(outputs, {})
                self.assertIn("mutants.json", err)

    def test_reads_the_listing_on_stdin(self) -> None:
        out = io.StringIO()
        with (
            mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}),
            mock.patch("sys.stdin", io.StringIO(listing(31))),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(mutants_plan.main(["-"]), 0)
        self.assertIn("shards=2\n", out.getvalue())


class LaneTest(unittest.TestCase):
    def test_the_plan_lists_with_the_options_the_shards_test_with(self) -> None:
        # Another option could change which mutants a shard tests, so the plan
        # would count a different set from the one the shards slice.
        shards = cargo_mutants_arguments("mutants-in-diff")
        planned = cargo_mutants_arguments("mutants-in-diff-plan")
        self.assertIn("--in-diff", shards)
        self.assertEqual(
            without(shards, set(), {"--shard", "--output"}),
            without(planned, {"--list", "--json"}, set()),
        )

    def test_the_plan_and_the_shards_run_the_same_cargo_mutants(self) -> None:
        # Another release may find other mutants or slice the shards otherwise.
        workflow = REPO_ROOT / ".github" / "workflows" / "mutants-in-diff.yml"
        text = workflow.read_text(encoding="utf-8")
        versions = re.findall(r"cargo-mutants@([^,\s]+)", text)
        self.assertEqual(len(versions), 2, versions)
        self.assertEqual(len(set(versions)), 1, versions)


if __name__ == "__main__":
    unittest.main()
