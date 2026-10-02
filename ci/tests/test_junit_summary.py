"""Tests for ci/junit_summary.py, the failed and FLAKY test report of ci.yml."""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ci import junit_summary

# The shape nextest writes: a test that failed both attempts carries failure
# and rerunFailure, a test that passed on its retry carries flakyFailure.
REPORT = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="4" failures="1" errors="0">
    <testsuite name="nails-core" tests="3" disabled="0" errors="0" failures="1">
        <testcase name="state::tests::passes" classname="nails-core" time="0.01">
        </testcase>
        <testcase name="state::tests::broken" classname="nails-core" time="0.02">
            <failure message="panicked" type="test failure">broken</failure>
            <rerunFailure message="panicked" type="test failure">broken</rerunFailure>
        </testcase>
        <testcase name="state::tests::wobbly" classname="nails-core" time="0.01">
            <flakyFailure message="panicked" type="test failure">once</flakyFailure>
        </testcase>
    </testsuite>
    <testsuite name="nails-cli::cli_integration" tests="1" errors="0" failures="0">
        <testcase name="hangs" classname="nails-cli::cli_integration" time="180">
            <error message="timed out" type="test timeout"/>
        </testcase>
    </testsuite>
</testsuites>
"""

CLEAN = """<testsuites><testsuite name="nails-core">
<testcase name="a" classname="nails-core"/><testcase name="b" classname="nails-core"/>
</testsuite></testsuites>"""


class ParseTest(unittest.TestCase):
    def test_sorts_failed_and_flaky_cases(self) -> None:
        report = junit_summary.parse(REPORT)
        self.assertEqual(report.total, 4)
        self.assertEqual(
            report.failed,
            ["nails-core state::tests::broken", "nails-cli::cli_integration hangs"],
        )
        self.assertEqual(report.flaky, ["nails-core state::tests::wobbly"])

    def test_clean_run_has_nothing_to_report(self) -> None:
        report = junit_summary.parse(CLEAN)
        self.assertEqual((report.total, report.failed, report.flaky), (2, [], []))


class FormatTest(unittest.TestCase):
    def test_summary_lists_failed_then_flaky(self) -> None:
        text = junit_summary.format_summary(junit_summary.parse(REPORT))
        self.assertIn("4 test(s): 2 failed, 1 FLAKY (passed on retry).", text)
        lines = text.splitlines()
        broken = lines.index("| FAILED | `nails-core state::tests::broken` |")
        wobbly = lines.index(
            "| FLAKY (passed on retry) | `nails-core state::tests::wobbly` |"
        )
        self.assertLess(broken, wobbly)

    def test_clean_summary_has_no_table(self) -> None:
        text = junit_summary.format_summary(junit_summary.parse(CLEAN))
        self.assertIn("2 test(s): 0 failed, 0 FLAKY (passed on retry).", text)
        self.assertNotIn("|", text)

    def test_annotations_flag_each_test(self) -> None:
        annotations = junit_summary.format_annotations(junit_summary.parse(REPORT))
        self.assertEqual(
            annotations,
            [
                "::error title=Test failed::nails-core state::tests::broken failed",
                "::error title=Test failed::nails-cli::cli_integration hangs failed",
                "::warning title=FLAKY test::nails-core state::tests::wobbly "
                "failed, then passed on retry",
            ],
        )

    def test_annotation_data_is_escaped(self) -> None:
        report = junit_summary.Report(total=1, failed=["odd 100%\nname"])
        self.assertEqual(
            junit_summary.format_annotations(report),
            ["::error title=Test failed::odd 100%25%0Aname failed"],
        )


class MainTest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)

    def run_main(self, junit: Path, summary: Path | None) -> tuple[int, str]:
        env = {"GITHUB_STEP_SUMMARY": str(summary)} if summary else {}
        out = io.StringIO()
        with (
            mock.patch.dict(os.environ, env, clear=False),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            if summary is None:
                os.environ.pop("GITHUB_STEP_SUMMARY", None)
            code = junit_summary.main([str(junit)])
        return code, out.getvalue()

    def test_appends_summary_and_prints_annotations(self) -> None:
        junit = self.dir / "junit.xml"
        junit.write_text(REPORT, encoding="utf-8")
        summary = self.dir / "summary.md"
        summary.write_text("Line coverage: 90.00%\n", encoding="utf-8")
        code, out = self.run_main(junit, summary)
        self.assertEqual(code, 0)
        text = summary.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("Line coverage: 90.00%\n### Tests"))
        self.assertIn(
            "FLAKY (passed on retry) | `nails-core state::tests::wobbly`", text
        )
        self.assertIn("::warning title=FLAKY test::", out)

    def test_without_summary_file_prints_to_stdout(self) -> None:
        junit = self.dir / "junit.xml"
        junit.write_text(CLEAN, encoding="utf-8")
        code, out = self.run_main(junit, None)
        self.assertEqual(code, 0)
        self.assertIn("2 test(s): 0 failed", out)

    def test_missing_report_is_not_an_error(self) -> None:
        code, out = self.run_main(self.dir / "absent.xml", None)
        self.assertEqual(code, 0)
        self.assertIn("the tests did not run", out)

    def test_malformed_report_fails(self) -> None:
        junit = self.dir / "junit.xml"
        junit.write_text("<testsuites>", encoding="utf-8")
        code, _out = self.run_main(junit, None)
        self.assertEqual(code, junit_summary.EXIT_BAD_REPORT)


if __name__ == "__main__":
    unittest.main()
