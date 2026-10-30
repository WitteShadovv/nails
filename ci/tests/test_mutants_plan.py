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
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "mutants-in-diff.yml"
JUSTFILE = REPO_ROOT / "justfile"

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


def listing(count: int, package: str = "nails-base") -> str:
    """What `cargo mutants --list --json` prints for ``count`` mutants."""
    return listing_of([package] * count)


def listing_of(packages: list[str]) -> str:
    """What `cargo mutants --list --json` prints for mutants of ``packages``."""
    return json.dumps([dict(MUTANT, package=package) for package in packages])


def step_outputs(printed: str) -> dict[str, str]:
    """The ``name=value`` lines the planner printed for $GITHUB_OUTPUT."""
    outputs = {}
    for line in printed.splitlines():
        name, _, value = line.partition("=")
        outputs[name] = value
    return outputs


def planned_outputs(text: str) -> dict[str, str]:
    """The step outputs the planner prints for the listing ``text`` on stdin."""
    out = io.StringIO()
    with (
        mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": ""}),
        mock.patch("sys.stdin", io.StringIO(text)),
        contextlib.redirect_stdout(out),
        contextlib.redirect_stderr(io.StringIO()),
    ):
        code = mutants_plan.main(["-"])
    if code != 0:
        raise AssertionError(f"the planner exited {code}")
    return step_outputs(out.getvalue())


def slices(mutants: int, shards: int) -> list[range]:
    """The mutants each shard tests, as cargo-mutants splits them.

    Its default sharding (`--sharding=slice`) gives shard k of n the k-th run of
    ceil(mutants / n) consecutive mutants; the last may be shorter, or empty.
    Written out here rather than taken from the planner, which must agree.
    """
    size = math.ceil(mutants / shards)
    return [
        range(min(mutants, k * size), min(mutants, (k + 1) * size))
        for k in range(shards)
    ]


BASE = "nails-base"
SESSION = "nails-session"
API = "nails-api"
CORE = "nails-core"


def minutes_with(packages: list[str], shards: int) -> int:
    """The box the dearest of ``shards`` slices of ``packages`` needs."""
    return max(
        mutants_plan.shard_minutes(packages[part.start : part.stop])
        for part in slices(len(packages), shards)
    )


def best_count(needs: dict[int, int]) -> int:
    """The fewest shards of those that need the shortest box."""
    shortest = min(needs.values())
    return min(count for count, minutes in needs.items() if minutes == shortest)


def cargo_mutants_arguments(recipe: str) -> list[str]:
    """The arguments that a justfile recipe passes to `cargo mutants`."""
    text = JUSTFILE.read_text(encoding="utf-8")
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
    def test_the_measured_cost_of_each_package(self) -> None:
        # The figures the comments of ci/mutants_plan.py and docs/ci.md quote.
        self.assertEqual(mutants_plan.capacity(15, BASE), 32)
        self.assertEqual(mutants_plan.capacity(15, SESSION), 51)
        self.assertEqual(mutants_plan.capacity(30, BASE), 98)
        self.assertEqual(mutants_plan.capacity(30, SESSION), 154)
        self.assertEqual(mutants_plan.SHARD_MINUTES, 15)
        self.assertEqual(mutants_plan.MAX_SHARD_MINUTES, 30)
        self.assertEqual(mutants_plan.JOB_MINUTES_PAST_BOX, 5)
        self.assertEqual(mutants_plan.TIMEOUTS_PER_SHARD, 2)

    def test_a_package_not_measured_costs_as_much_as_the_dearest(self) -> None:
        dearest = max(mutants_plan.SECONDS_PER_MUTANT.values())
        self.assertEqual(mutants_plan.mutant_seconds(CORE), dearest)
        for package in ("nails-oracle", "nails-platform", "nails-forensics"):
            with self.subTest(package=package):
                self.assertNotIn(package, mutants_plan.SECONDS_PER_MUTANT)
                self.assertEqual(mutants_plan.mutant_seconds(package), dearest)

    def test_capacity_is_the_most_a_time_box_holds(self) -> None:
        for package in [*mutants_plan.SECONDS_PER_MUTANT, "nails-oracle"]:
            for minutes in range(
                mutants_plan.SHARD_MINUTES, mutants_plan.MAX_SHARD_MINUTES + 1
            ):
                with self.subTest(package=package, minutes=minutes):
                    most = mutants_plan.capacity(minutes, package)
                    self.assertLessEqual(
                        mutants_plan.shard_minutes([package] * most), minutes
                    )
                    self.assertGreater(
                        mutants_plan.shard_minutes([package] * (most + 1)), minutes
                    )

    def test_a_small_shard_keeps_the_ordinary_time_box(self) -> None:
        self.assertEqual(mutants_plan.shard_minutes([]), mutants_plan.SHARD_MINUTES)
        self.assertEqual(mutants_plan.shard_minutes([CORE]), mutants_plan.SHARD_MINUTES)

    def test_each_shard_has_room_for_two_mutants_that_time_out(self) -> None:
        # The setup, two timeouts and the mutants, with the margin on top.
        seconds = 120 + 2 * 120 + 32 * 11
        self.assertEqual(seconds * 5 / 4, 890)
        self.assertEqual(mutants_plan.shard_minutes([BASE] * 32), 15)
        self.assertEqual(mutants_plan.shard_minutes([BASE] * 33), 16)

    def test_a_diff_without_mutants_runs_no_shard(self) -> None:
        planned = mutants_plan.plan([])
        self.assertEqual(planned, Plan(0))
        self.assertFalse(planned.too_large)
        self.assertEqual(mutants_plan.matrix(planned), {"include": []})

    def test_the_shards_grow_with_the_diff(self) -> None:
        self.assertEqual(mutants_plan.plan([BASE]), Plan(1, 1, 1, 15))
        self.assertEqual(mutants_plan.plan([BASE] * 32), Plan(32, 1, 32, 15))
        self.assertEqual(mutants_plan.plan([BASE] * 33), Plan(33, 2, 17, 15))
        self.assertEqual(mutants_plan.plan([BASE] * 65), Plan(65, 3, 22, 15))
        self.assertEqual(mutants_plan.plan([BASE] * 384), Plan(384, 12, 32, 15))

    def test_a_diff_no_count_fits_in_the_ordinary_box_gets_longer_boxes(self) -> None:
        # Eleven shards of 35 and twelve of 33 both need 16 minutes: the fewer.
        self.assertEqual(mutants_plan.plan([BASE] * 385), Plan(385, 11, 35, 16))
        self.assertEqual(mutants_plan.plan([BASE] * 409), Plan(409, 12, 35, 16))
        self.assertEqual(mutants_plan.plan([BASE] * 1176), Plan(1176, 12, 98, 30))

    def test_a_diff_beyond_the_longest_boxes_runs_no_shard(self) -> None:
        # The plan keeps the box its twelve shards would need, for the message.
        planned = mutants_plan.plan([BASE] * 1177)
        self.assertEqual(planned, Plan(1177, 0, 99, 31))
        self.assertTrue(planned.too_large)
        self.assertEqual(mutants_plan.matrix(planned), {"include": []})

    def test_a_mutant_costs_what_its_package_costs(self) -> None:
        # Forty mutants of nails-api fit one shard, forty of nails-core three.
        self.assertEqual(mutants_plan.plan([API] * 40), Plan(40, 1, 40, 15))
        self.assertEqual(mutants_plan.plan([CORE] * 40), Plan(40, 3, 14, 15))
        # A session-heavy diff of 388 mutants needs eight.
        self.assertEqual(mutants_plan.plan([SESSION] * 388), Plan(388, 8, 49, 15))

    def test_the_plan_reckons_with_the_mutants_each_shard_gets(self) -> None:
        # The same eighty mutants: spread out, two shards hold them; with the
        # dear ones together, the shard that gets them would run over the box
        # until five shards split them.
        spread = [CORE, API, API, API] * 20
        together = [API] * 60 + [CORE] * 20
        self.assertEqual(mutants_plan.plan(spread), Plan(80, 2, 40, 15))
        self.assertEqual(mutants_plan.plan(together), Plan(80, 5, 16, 15))
        self.assertEqual(
            mutants_plan.shard_minutes(together[slices(80, 2)[1].start :]), 18
        )

    def test_the_box_a_mix_needs_does_not_shrink_with_every_shard(self) -> None:
        # A run of dear mutants among cheap ones: as the slices move over it,
        # twelve shards need a longer box than ten, longer than the lane gives.
        mix = [API] * 150 + [CORE] * 70 + [API] * 400
        needs = {count: minutes_with(mix, count) for count in range(7, 13)}
        self.assertEqual(needs, {7: 28, 8: 37, 9: 33, 10: 25, 11: 30, 12: 31})
        self.assertEqual(mutants_plan.plan(mix), Plan(620, 10, 62, 25))
        # Within the lane's boxes, the fewest of the counts that need the
        # shortest box: ten and eleven need 20 minutes, twelve 21.
        mix = [API] * 10 + [CORE] * 50 + [API] * 300
        needs = {count: minutes_with(mix, count) for count in range(9, 13)}
        self.assertEqual(needs, {9: 22, 10: 20, 11: 20, 12: 21})
        self.assertEqual(mutants_plan.plan(mix), Plan(360, 10, 36, 20))

    def test_every_plan_fits_its_bounds(self) -> None:
        layouts = {
            "nails-base": lambda n: [BASE] * n,
            "dear ones last": lambda n: [API] * (n - n // 4) + [CORE] * (n // 4),
            "dear ones inside": lambda n: (
                [API] * (n // 4) + [CORE] * (n // 8) + [API] * (n - n // 4 - n // 8)
            ),
            "mixed": lambda n: [
                (BASE, SESSION, API, CORE, "nails-oracle")[i % 5] for i in range(n)
            ],
        }
        # Every small diff, where shards fall empty, then a sample up to past
        # the largest the lane tests, with the sizes where the plan changes.
        sizes = {*range(1, 200), *range(200, 1400, 7), 384, 385, 620, 1176, 1177}
        for layout, packages_of in layouts.items():
            for mutants in sorted(sizes):
                packages = packages_of(mutants)
                planned = mutants_plan.plan(packages)
                with self.subTest(layout=layout, mutants=mutants):
                    self.check_bounds(packages, planned)

    def check_bounds(self, packages: list[str], planned: Plan) -> None:
        mutants = len(packages)
        self.assertEqual(planned.mutants, mutants)
        # Every count of shards up to the bound that leaves none empty, and
        # the box each needs.
        needs = {
            count: minutes_with(packages, count)
            for count in range(1, mutants_plan.MAX_SHARDS + 1)
            if all(slices(mutants, count))
        }
        shortest = min(needs.values())
        if planned.too_large:
            # No count fits even the longest box, and the plan names the
            # shortest box any count needs.
            self.assertGreater(shortest, mutants_plan.MAX_SHARD_MINUTES)
            self.assertEqual(planned.minutes, shortest)
            self.assertEqual(
                planned.per_shard,
                max(len(part) for part in slices(mutants, best_count(needs))),
            )
            return
        self.assertGreaterEqual(planned.shards, 1)
        self.assertLessEqual(planned.shards, mutants_plan.MAX_SHARDS)
        self.assertLessEqual(planned.minutes, mutants_plan.MAX_SHARD_MINUTES)
        # The job outlasts the box by the steps around it.
        self.assertEqual(
            planned.job_minutes, planned.minutes + mutants_plan.JOB_MINUTES_PAST_BOX
        )
        # Every shard cargo-mutants slices off tests something, none tests more
        # than the plan says, and none needs more than the box.
        parts = slices(mutants, planned.shards)
        self.assertTrue(all(parts))
        self.assertEqual(max(len(part) for part in parts), planned.per_shard)
        self.assertEqual(needs[planned.shards], planned.minutes)
        # The shortest box any count needs, the ordinary one when a count fits
        # it, and the fewest shards that need that box.
        self.assertEqual(planned.minutes, shortest)
        self.assertEqual(planned.shards, best_count(needs))

    def test_the_matrix_names_each_shard_of_the_plan(self) -> None:
        # Each shard's time box, and the limit of its job five minutes later.
        self.assertEqual(
            mutants_plan.matrix(Plan(61, 3, 21, 15)),
            {
                "include": [
                    {"shard": 0, "shards": 3, "minutes": 15, "timeout": 20},
                    {"shard": 1, "shards": 3, "minutes": 15, "timeout": 20},
                    {"shard": 2, "shards": 3, "minutes": 15, "timeout": 20},
                ]
            },
        )
        self.assertEqual(
            mutants_plan.matrix(Plan(1176, 12, 98, 30))["include"][11],
            {"shard": 11, "shards": 12, "minutes": 30, "timeout": 35},
        )


class ListingTest(unittest.TestCase):
    def test_reads_the_package_of_each_listed_mutant_in_order(self) -> None:
        packages = [BASE, SESSION, BASE, "nails-cli"]
        self.assertEqual(mutants_plan.listed_packages(listing_of(packages)), packages)
        self.assertEqual(mutants_plan.listed_packages("[]"), [])

    def test_no_output_is_no_mutant(self) -> None:
        # cargo-mutants prints nothing for a diff that touches no mutant.
        self.assertEqual(mutants_plan.listed_packages(""), [])
        self.assertEqual(mutants_plan.listed_packages("\n"), [])

    def test_anything_but_a_list_of_mutants_is_refused(self) -> None:
        for text in (
            "Found 3 mutants",
            "{}",
            '"x"',
            "[1, 2]",
            "[{}, []]",
            '[{"name": "a mutant without its package"}]',
            '[{"package": 1}]',
        ):
            with self.subTest(text=text), self.assertRaises(mutants_plan.ListError):
                mutants_plan.listed_packages(text)


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
        return code, step_outputs(out.getvalue()), err.getvalue()

    def test_prints_the_plan_as_step_outputs(self) -> None:
        code, outputs, err = self.run_main(listing(409))
        self.assertEqual(code, 0, err)
        self.assertEqual(set(outputs), {"shards", "matrix"})
        self.assertEqual(outputs["shards"], "12")
        include = json.loads(outputs["matrix"])["include"]
        self.assertEqual([entry["shard"] for entry in include], list(range(12)))
        self.assertEqual({entry["shards"] for entry in include}, {12})
        self.assertEqual({entry["minutes"] for entry in include}, {16})
        self.assertEqual({entry["timeout"] for entry in include}, {21})
        message = (
            "409 mutants (nails-base 409) in the diff: 12 shards of at most 35, "
            "each time-boxed at 16 minutes."
        )
        self.assertIn(message, err)
        self.assertNotIn("::", err)
        self.assertIn(message, self.summary.read_text(encoding="utf-8"))

    def test_one_shard(self) -> None:
        code, outputs, err = self.run_main(listing(1))
        self.assertEqual(code, 0, err)
        self.assertEqual(outputs["shards"], "1")
        self.assertIn(
            "1 mutant (nails-base 1) in the diff: one shard, time-boxed at 15", err
        )

    def test_names_how_many_mutants_of_each_package_the_diff_holds(self) -> None:
        code, outputs, err = self.run_main(
            listing_of([SESSION, BASE, SESSION, "nails-cli", SESSION])
        )
        self.assertEqual(code, 0, err)
        self.assertIn(
            "5 mutants (nails-session 3, nails-base 1, nails-cli 1) in the diff", err
        )

    def test_a_diff_without_mutants_plans_no_shard(self) -> None:
        code, outputs, err = self.run_main("")
        self.assertEqual(code, 0, err)
        self.assertEqual(outputs["shards"], "0")
        self.assertEqual(json.loads(outputs["matrix"]), {"include": []})
        self.assertIn("no mutable code", self.summary.read_text(encoding="utf-8"))

    def test_a_diff_too_large_fails_and_says_nothing_was_tested(self) -> None:
        # The plan still prints its outputs, those of a plan without shards,
        # before it fails.
        code, outputs, err = self.run_main(listing(1200))
        self.assertEqual(code, 1)
        self.assertEqual(outputs["shards"], "0")
        self.assertEqual(json.loads(outputs["matrix"]), {"include": []})
        message = (
            "The diff holds 1200 mutants (nails-base 1200), more than the lane can "
            "test: split the best way, in 12 shards of at most 100, they would "
            "need 31-minute time boxes, and the lane gives a shard 30 minutes at "
            "most. No shard runs, so none of the diff's mutants is tested, and the "
            "lane fails."
        )
        self.assertIn(
            "::error title=Diff too large for mutation testing::" + message, err
        )
        summary = self.summary.read_text(encoding="utf-8")
        self.assertIn(message, summary)
        self.assertNotIn("passes", summary)

    def test_a_listing_it_cannot_read_fails_without_outputs(self) -> None:
        for text in (None, "not json", '{"mutants": []}', '[{"name": "x"}]'):
            with self.subTest(text=text):
                code, outputs, err = self.run_main(text)
                self.assertEqual(code, 1)
                self.assertEqual(outputs, {})
                self.assertIn("mutants.json", err)

    def test_reads_the_listing_on_stdin(self) -> None:
        self.assertEqual(planned_outputs(listing(33))["shards"], "2")


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

    def test_the_plan_reckons_with_the_timeout_the_shards_test_with(self) -> None:
        # Each shard has room for mutants that run into the timeout, so a
        # longer --timeout must lengthen the boxes too.
        options = re.search(
            r'^mutants_in_diff_options := "([^"]*)"$',
            JUSTFILE.read_text(encoding="utf-8"),
            re.M,
        )
        if options is None:
            raise AssertionError("no mutants_in_diff_options in the justfile")
        words = shlex.split(options.group(1))
        self.assertEqual(words.count("--timeout"), 1, words)
        timeout = words[words.index("--timeout") + 1]
        self.assertEqual(int(timeout), mutants_plan.TIMEOUT_SECONDS)

    def test_the_plan_and_the_shards_run_the_same_cargo_mutants(self) -> None:
        # Another release may find other mutants or slice the shards otherwise.
        text = WORKFLOW.read_text(encoding="utf-8")
        versions = re.findall(r"cargo-mutants@([^,\s]+)", text)
        self.assertEqual(len(versions), 2, versions)
        self.assertEqual(len(set(versions)), 1, versions)

    def test_the_workflow_reads_what_the_plan_prints(self) -> None:
        # The plan reaches the shards through the plan job's outputs and the
        # shard matrix. A name renamed on one side alone would show only as a
        # red run on GitHub.
        text = WORKFLOW.read_text(encoding="utf-8")
        outputs = planned_outputs(listing(31))
        include = json.loads(outputs["matrix"])["include"]
        keys = {key for entry in include for key in entry}
        self.assertRegex(text, r"\bid: plan\n\s+run: just mutants-in-diff-plan ")
        # The plan job passes on each output of that step under its own name,
        # and the shard job reads every one of them and every key of the matrix.
        passed_on = re.findall(
            r"^\s+(\w+): \$\{\{ steps\.plan\.outputs\.(\w+) \}\}$", text, re.M
        )
        self.assertCountEqual(passed_on, [(name, name) for name in outputs])
        self.assertEqual(
            set(re.findall(r"\bneeds\.plan\.outputs\.(\w+)", text)), set(outputs)
        )
        self.assertEqual(set(re.findall(r"\bmatrix\.(\w+)", text)), keys)
        # A plan without shards prints 0, which keeps the shard job from
        # starting on an empty matrix.
        self.assertEqual(planned_outputs("")["shards"], "0")
        self.assertIn("if: needs.plan.outputs.shards != '0'", text)

    def test_each_shard_keeps_to_its_time_box(self) -> None:
        # The shard job's limit is the one the plan prints for it, and the
        # mutation step hands the shard's time box to the recipe, which stops
        # cargo-mutants when it runs out. The step then fails, and the upload
        # still runs.
        text = WORKFLOW.read_text(encoding="utf-8")
        recipe = re.search(
            r"^mutants-in-diff ([^:]*):$", JUSTFILE.read_text(encoding="utf-8"), re.M
        )
        if recipe is None:
            raise AssertionError("no recipe mutants-in-diff in the justfile")
        self.assertEqual(
            recipe.group(1).split(),
            ["diff", 'shard="0"', 'shards="1"', 'minutes=""'],
        )
        self.assertRegex(text, r"\n    timeout-minutes: \$\{\{ matrix\.timeout \}\}\n")
        self.assertRegex(text, r"\n          MINUTES: \$\{\{ matrix\.minutes \}\}\n")
        self.assertIn(
            'run: just mutants-in-diff "$RUNNER_TEMP/pr.diff" "$SHARD" "$SHARDS" '
            '"$MINUTES"\n',
            text,
        )
        self.assertRegex(
            text,
            r"- name: Upload the mutants report\n\s+if: \$\{\{ !cancelled\(\) \}\}\n",
        )


if __name__ == "__main__":
    unittest.main()
