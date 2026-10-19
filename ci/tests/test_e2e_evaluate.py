"""Tests for ci/e2e/evaluate.py: batches of tests evaluated side by side."""

from __future__ import annotations

import json
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from ci.e2e import evaluate

ATTR = ".#legacyPackages.x86_64-linux.e2e"


def names_in(command: list[str]) -> list[str]:
    """The test names a `nix eval --apply` command of evaluate asks for."""
    expression = command[command.index("--apply") + 1]
    return json.loads(expression.split("''")[1])


def answer(command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
    payload = {name: f"/nix/store/{name}.drv" for name in names_in(command)}
    return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")


class SplitTest(unittest.TestCase):
    def test_spreads_tests_evenly_over_the_workers_in_order(self) -> None:
        tests = [f"t{index}" for index in range(7)]
        self.assertEqual(
            evaluate.split(tests, 4),
            [["t0", "t1"], ["t2", "t3"], ["t4", "t5"], ["t6"]],
        )

    def test_a_batch_never_exceeds_the_maximum(self) -> None:
        tests = [f"t{index}" for index in range(65)]
        batches = evaluate.split(tests, 2)
        self.assertEqual(sum(batches, []), tests)
        self.assertTrue(all(len(batch) <= evaluate.MAX_BATCH for batch in batches))
        self.assertEqual(len(batches), -(-65 // evaluate.MAX_BATCH))

    def test_fewer_tests_than_workers_get_one_batch_each(self) -> None:
        self.assertEqual(evaluate.split(["a", "b"], 4), [["a"], ["b"]])
        self.assertEqual(evaluate.split([], 4), [])

    def test_a_batch_size_fixes_the_size_of_every_batch_but_the_last(self) -> None:
        self.assertEqual(
            evaluate.split(["a", "b", "c", "d", "e"], 4, batch_size=2),
            [["a", "b"], ["c", "d"], ["e"]],
        )

    def test_rejects_zero_workers_or_batch_size(self) -> None:
        with self.assertRaises(ValueError):
            evaluate.split(["a"], 0)
        with self.assertRaises(ValueError):
            evaluate.split(["a"], 1, batch_size=0)


class AutoWorkersTest(unittest.TestCase):
    def meminfo(self, kib: int) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "meminfo"
        path.write_text(f"MemTotal:       {kib} kB\nMemFree: 1 kB\n")
        return path

    def test_a_hosted_runner_runs_one_process_per_core(self) -> None:
        # 4 vCPUs and 16 GB, of which the kernel reports about 15.6 GiB.
        self.assertEqual(evaluate.auto_workers(self.meminfo(16_365_000), cpus=4), 4)

    def test_memory_caps_the_count(self) -> None:
        gib = evaluate.RESERVED_GIB + 2.5 * evaluate.GIB_PER_PROCESS
        kib = int(gib * 1024 * 1024)
        self.assertEqual(evaluate.auto_workers(self.meminfo(kib), cpus=16), 2)

    def test_without_cpu_affinity_the_cpu_count_counts(self) -> None:
        big = self.meminfo(64 * 1024 * 1024)
        with (
            mock.patch.object(evaluate.os, "sched_getaffinity", None, create=True),
            mock.patch.object(evaluate.os, "cpu_count", return_value=2),
        ):
            self.assertEqual(evaluate.auto_workers(big), 2)

    def test_a_small_or_unreadable_host_still_runs_one(self) -> None:
        small = self.meminfo(2 * 1024 * 1024)
        self.assertEqual(evaluate.auto_workers(small, cpus=8), 1)
        unreadable = Path("/nonexistent/meminfo")
        self.assertEqual(evaluate.auto_workers(unreadable, cpus=8), 1)


class EvaluateTest(unittest.TestCase):
    def test_returns_each_test_in_request_order(self) -> None:
        calls: list[list[str]] = []
        lock = threading.Lock()

        def fake_run(command, **kwargs):
            with lock:
                calls.append(command)
            return answer(command, **kwargs)

        tests = ["e", "d", "c", "b", "a"]
        with mock.patch.object(evaluate.subprocess, "run", side_effect=fake_run):
            result = evaluate.evaluate(ATTR, tests, "t: t.drvPath", workers=2)
        self.assertEqual(list(result), tests)
        self.assertEqual(result["c"], "/nix/store/c.drv")
        self.assertEqual(len(calls), 2)
        self.assertEqual(sorted(sum((names_in(c) for c in calls), [])), sorted(tests))
        for command in calls:
            self.assertEqual(command[:4], ["nix", "eval", "--json", ATTR])
            self.assertIn("(t: t.drvPath) e.${n}", command[5])
            self.assertNotIn("hasAttr", command[5])

    def test_the_batches_run_at_the_same_time(self) -> None:
        # Each batch waits until the other has started too, so batches run
        # one after another would break the barrier instead of passing it.
        barrier = threading.Barrier(2, timeout=10)

        def fake_run(command, **kwargs):
            barrier.wait()
            return answer(command, **kwargs)

        with mock.patch.object(evaluate.subprocess, "run", side_effect=fake_run):
            result = evaluate.evaluate(ATTR, ["a", "b"], "t: t.drvPath", workers=2)
        self.assertEqual(set(result), {"a", "b"})

    def test_skip_missing_leaves_out_tests_the_set_lacks(self) -> None:
        def fake_run(command, **_kwargs):
            self.assertIn("builtins.hasAttr n e", command[5])
            payload = {"a": "/nix/store/a.drv"}
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

        with mock.patch.object(evaluate.subprocess, "run", side_effect=fake_run):
            result = evaluate.evaluate(
                ATTR, ["a", "gone"], "t: t.drvPath", workers=1, skip_missing=True
            )
        self.assertEqual(result, {"a": "/nix/store/a.drv"})

    def test_an_odd_name_is_refused_before_any_evaluation(self) -> None:
        with mock.patch.object(evaluate.subprocess, "run") as nix:
            with self.assertRaisesRegex(evaluate.EvalError, "odd test name"):
                evaluate.evaluate(ATTR, ["a", "b''; x"], "t: t.drvPath", workers=2)
        nix.assert_not_called()

    def test_a_failing_batch_fails_the_evaluation(self) -> None:
        def fake_run(command, **kwargs):
            if names_in(command) == ["c"]:
                raise subprocess.CalledProcessError(1, command, stderr="error: c\n")
            return answer(command, **kwargs)

        with mock.patch.object(evaluate.subprocess, "run", side_effect=fake_run):
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                evaluate.evaluate(
                    ATTR, ["a", "b", "c", "d"], "t: t", workers=2, batch_size=1
                )
        self.assertEqual(caught.exception.stderr, "error: c\n")

    def test_a_reply_that_is_not_an_attribute_set_is_an_error(self) -> None:
        reply = subprocess.CompletedProcess([], 0, "[]", "")
        with mock.patch.object(evaluate.subprocess, "run", return_value=reply):
            with self.assertRaisesRegex(evaluate.EvalError, "no attribute set"):
                evaluate.evaluate(ATTR, ["a"], "t: t.drvPath", workers=1)


if __name__ == "__main__":
    unittest.main()
