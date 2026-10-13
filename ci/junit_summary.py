"""Name the failed and FLAKY tests of a nextest run in the GitHub job summary.

The ci profile in .config/nextest.toml retries a failed test once. A test that
passes on that retry no longer fails the run, so without this report it would
only show up deep in the log. Here it is listed as FLAKY in the job summary
and flagged with a warning annotation; failed tests are listed and flagged as
errors, so neither needs a trip through the log.

nextest's JUnit report marks a failed test with a ``failure`` (or ``error``)
element and a flaky one with ``flakyFailure`` (or ``flakyError``) elements, one
per failed attempt.

Usage: python3 -m ci.junit_summary JUNIT_XML

The Markdown goes to $GITHUB_STEP_SUMMARY (stdout when that is unset) and the
annotations to stdout. A missing report means the tests never ran, a build
failure that the job already shows, so it is noted rather than an error.
"""

from __future__ import annotations

import argparse
import os
import sys
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

EXIT_BAD_REPORT = 2


@dataclass
class Report:
    total: int = 0
    failed: list[str] = field(default_factory=list)
    flaky: list[str] = field(default_factory=list)


def parse(xml_text: str) -> Report:
    """Collect the failed and flaky test cases of a nextest JUnit report."""
    report = Report()
    for case in ET.fromstring(xml_text).iter("testcase"):
        report.total += 1
        # nextest puts the test binary in classname and the test path in name.
        name = f"{case.get('classname', '')} {case.get('name', '')}".strip()
        if case.find("failure") is not None or case.find("error") is not None:
            report.failed.append(name)
        elif (
            case.find("flakyFailure") is not None or case.find("flakyError") is not None
        ):
            report.flaky.append(name)
    return report


def format_summary(report: Report) -> str:
    lines = [
        "### Tests",
        "",
        f"{report.total} test(s): {len(report.failed)} failed, "
        f"{len(report.flaky)} FLAKY (passed on retry).",
    ]
    if report.failed or report.flaky:
        lines += ["", "| Result | Test |", "| --- | --- |"]
        lines += [f"| FAILED | `{name}` |" for name in report.failed]
        lines += [f"| FLAKY (passed on retry) | `{name}` |" for name in report.flaky]
    return "\n".join(lines) + "\n"


def _escape(message: str) -> str:
    """Escape the data of a GitHub workflow command."""
    return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def format_annotations(report: Report) -> list[str]:
    annotations = [
        f"::error title=Test failed::{_escape(name)} failed" for name in report.failed
    ]
    annotations += [
        f"::warning title=FLAKY test::{_escape(name)} failed, then passed on retry"
        for name in report.flaky
    ]
    return annotations


def _write_summary(text: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as summary:
            summary.write(text)
    else:
        sys.stdout.write(text)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m ci.junit_summary",
        description="List the failed and FLAKY tests of a nextest JUnit report.",
    )
    parser.add_argument("junit", type=Path, help="nextest JUnit report")
    args = parser.parse_args(argv)

    try:
        xml_text = args.junit.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"No JUnit report at {args.junit}: the tests did not run.")
        return 0
    try:
        report = parse(xml_text)
    except ET.ParseError as error:
        print(f"{args.junit} is not valid JUnit XML: {error}", file=sys.stderr)
        return EXIT_BAD_REPORT

    _write_summary(format_summary(report))
    for annotation in format_annotations(report):
        print(annotation)
    return 0


if __name__ == "__main__":
    sys.exit(main())
