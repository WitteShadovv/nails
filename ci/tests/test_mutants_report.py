"""Tests for ci/mutants_report.py, the cargo-mutants report of the justfile."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ci import mutants_report

CAUGHT = "nails-base/src/state/mod.rs:88:13: replace == with != in SystemState::can"
MISSED = "nails-session/src/session/probe.rs:40:9: replace probe -> bool with true"
TIMED_OUT = "nails-teardown/src/whole_root/plan.rs:51:5: replace plan with vec![]"
UNVIABLE = (
    "nails-base/src/state/file.rs:120:9: replace StateFile::load "
    "-> Result<StateFile> with Ok(Default::default())"
)

# The build output of a mutation that does not compile.
COMPILE_ERROR = """*** mutation diff:
--- nails-base/src/state/file.rs
+++ replace StateFile::load -> Result<StateFile> with Ok(Default::default())
*** cargo build --tests --package=nails-base --all-features --locked
   Compiling nails-base v0.3.0 (/tmp/cargo-mutants-nails-AbCd.tmp/nails-base)
error[E0277]: the trait bound `StateFile: Default` is not satisfied
error: could not compile `nails-base` (lib) due to 1 previous error
"""

# What a build prints when the runner, not the mutation, failed it.
ENVIRONMENT_FAILURES = {
    "Disk quota exceeded": "error: failed to write /tmp/cargo-mutants-nails-AbCd.tmp/"
    "target/debug/deps/libnails_core.rlib: Disk quota exceeded (os error 122)",
    "No space left on device": "LLVM ERROR: IO failure on output stream: "
    "No space left on device",
    "signal: 9, SIGKILL": "Caused by:\n  process didn't exit successfully: "
    "`rustc --crate-name nails_core` (signal: 9, SIGKILL: kill)",
    "Cannot allocate memory": "error: could not exec the linker `cc`: "
    "Cannot allocate memory (os error 12)",
    "memory allocation of 2097152 bytes failed": "memory allocation of 2097152 "
    "bytes failed",
    "Input/output error": "error: failed to read `nails-core/src/lib.rs`: "
    "Input/output error (os error 5)",
    "Read-only file system": "error: failed to create directory `target/debug`: "
    "Read-only file system (os error 30)",
    "Too many open files": "error: Too many open files (os error 24)",
    "LLVM ERROR: out of memory": "LLVM ERROR: out of memory\nAllocation failed",
    "signal 9 [Killed]": "  = note: collect2: fatal error: ld terminated with "
    "signal 9 [Killed]",
}


def mutant_outcome(name: str, summary: str, log: str) -> dict[str, object]:
    """One entry of outcomes.json, as cargo-mutants 27 writes it."""
    return {
        "scenario": {"Mutant": {"name": name, "package": "nails-base"}},
        "summary": summary,
        "log_path": log,
        "diff_path": log.replace("log/", "diff/").replace(".log", ".diff"),
        "phase_results": [],
    }


class ReportTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name) / "mutants.out"
        (self.out / "log").mkdir(parents=True)

    def write_run(
        self,
        lists: dict[str, list[str]],
        outcomes: list[dict[str, object]] | None = None,
        logs: dict[str, str] | None = None,
    ) -> None:
        for name in ("caught", "missed", "timeout", "unviable"):
            entries = lists.get(name, [])
            (self.out / f"{name}.txt").write_text(
                "".join(f"{entry}\n" for entry in entries), encoding="utf-8"
            )
        baseline = {"scenario": "Baseline", "summary": "Success", "log_path": "x"}
        if outcomes is not None:
            document = {"outcomes": [baseline, *outcomes], "total_mutants": 0}
            (self.out / "outcomes.json").write_text(
                json.dumps(document), encoding="utf-8"
            )
        for path, text in (logs or {}).items():
            (self.out / path).write_text(text, encoding="utf-8")

    def run_main(self, *args: str, summary: Path | None = None) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        env = {"GITHUB_STEP_SUMMARY": str(summary)} if summary else {}
        with (
            mock.patch.dict(os.environ, env, clear=False),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            if summary is None:
                os.environ.pop("GITHUB_STEP_SUMMARY", None)
            code = mutants_report.main([*args, str(self.out)])
        return code, out.getvalue(), err.getvalue()

    def unviable_run(self, log_text: str) -> None:
        log = "log/nails-base__src__state__file.rs_line_120_col_9.log"
        self.write_run(
            {"caught": [CAUGHT], "unviable": [UNVIABLE]},
            [
                mutant_outcome(CAUGHT, "CaughtMutant", "log/caught.log"),
                mutant_outcome(UNVIABLE, "Unviable", log),
            ],
            {log: log_text},
        )

    def test_counts_every_outcome_and_passes(self) -> None:
        self.unviable_run(COMPILE_ERROR)
        with open(self.out / "missed.txt", "a", encoding="utf-8") as missed:
            missed.write(f"{MISSED}\n")
        with open(self.out / "timeout.txt", "a", encoding="utf-8") as timeout:
            timeout.write(f"{TIMED_OUT}\n")
        code, out, err = self.run_main("--require-caught")
        self.assertEqual(code, 0, err)
        self.assertIn(
            "Mutation testing: 1 caught, 1 missed, 1 timed out, 1 unviable", out
        )

    def test_build_that_failed_for_want_of_resources_fails_the_run(self) -> None:
        for error, line in ENVIRONMENT_FAILURES.items():
            with self.subTest(error=error):
                self.unviable_run(COMPILE_ERROR.replace("error[E0277]", line))
                code, _out, err = self.run_main()
                self.assertEqual(code, 1)
                self.assertIn("1 mutant(s) were not tested", err)
                self.assertIn(f"{UNVIABLE}: {error}", err)

    def test_error_text_in_the_tests_of_a_built_mutant_is_no_failure(self) -> None:
        # A caught mutant's log holds the output of its failing tests, which
        # may quote the very errors a test provokes on purpose.
        self.write_run(
            {"caught": [CAUGHT]},
            [mutant_outcome(CAUGHT, "CaughtMutant", "log/caught.log")],
            {"log/caught.log": "thread panicked: No space left on device\n"},
        )
        code, _out, err = self.run_main("--require-caught")
        self.assertEqual(code, 0, err)

    def test_unreadable_build_log_fails_closed(self) -> None:
        self.write_run(
            {"caught": [CAUGHT], "unviable": [UNVIABLE]},
            [mutant_outcome(UNVIABLE, "Unviable", "log/missing.log")],
        )
        code, _out, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("its build log cannot be read", err)

    def test_outcomes_that_miss_an_unviable_mutant_fail_closed(self) -> None:
        self.write_run(
            {"caught": [CAUGHT], "unviable": [UNVIABLE, UNVIABLE + " (second)"]},
            [mutant_outcome(UNVIABLE, "Unviable", "log/one.log")],
            {"log/one.log": COMPILE_ERROR},
        )
        code, _out, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("outcomes.json holds 1 unviable mutants, unviable.txt 2", err)

    def test_missing_outcomes_fail_a_run_with_unviable_mutants(self) -> None:
        self.write_run({"caught": [CAUGHT], "unviable": [UNVIABLE]})
        code, _out, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("outcomes.json cannot be read", err)

    def test_run_that_caught_nothing_fails_only_when_required(self) -> None:
        self.unviable_run(COMPILE_ERROR)
        (self.out / "caught.txt").write_text("", encoding="utf-8")
        (self.out / "missed.txt").write_text(f"{MISSED}\n", encoding="utf-8")
        code, _out, err = self.run_main("--require-caught")
        self.assertEqual(code, 1)
        self.assertIn("No mutant was caught, so this run proves nothing", err)
        code, _out, err = self.run_main()
        self.assertEqual(code, 0, err)

    def test_run_without_mutants(self) -> None:
        code, out, _err = self.run_main("--title", "Mutation testing on the diff")
        self.assertEqual(code, 0)
        self.assertIn("Mutation testing on the diff: no mutable code in this run", out)
        code, out, err = self.run_main("--require-caught")
        self.assertEqual(code, 1)
        self.assertIn("0 caught, 0 missed, 0 timed out, 0 unviable", out)
        self.assertIn("No mutant was caught", err)

    def test_summary_lists_missed_timed_out_and_untested_mutants(self) -> None:
        self.unviable_run(ENVIRONMENT_FAILURES["Disk quota exceeded"])
        (self.out / "missed.txt").write_text(f"{MISSED}\n", encoding="utf-8")
        (self.out / "timeout.txt").write_text(f"{TIMED_OUT}\n", encoding="utf-8")
        summary = self.out.parent / "summary.md"
        summary.write_text("Line coverage: 90.00%\n", encoding="utf-8")
        code, _out, _err = self.run_main(
            "--title", "Mutation testing on the diff", summary=summary
        )
        self.assertEqual(code, 1)
        text = summary.read_text(encoding="utf-8")
        self.assertTrue(
            text.startswith("Line coverage: 90.00%\n## Mutation testing on the diff")
        )
        self.assertIn("1 caught, 1 missed, 1 timed out, 1 unviable.", text)
        lines = text.splitlines()
        missed = lines.index("### Missed")
        timed_out = lines.index("### Timed out")
        untested = lines.index("### Not tested: the build failed for want of resources")
        self.assertLess(missed, timed_out)
        self.assertLess(timed_out, untested)
        self.assertEqual(lines[missed + 3], MISSED)
        self.assertIn(f"{UNVIABLE}: Disk quota exceeded (log/", text)

    def test_without_a_summary_file_nothing_is_written(self) -> None:
        self.unviable_run(COMPILE_ERROR)
        code, out, _err = self.run_main()
        self.assertEqual(code, 0)
        self.assertNotIn("##", out)


if __name__ == "__main__":
    unittest.main()
