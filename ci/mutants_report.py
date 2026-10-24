"""Report a cargo-mutants run, and fail one that tested less than it claims.

`just mutants` (the weekly sweep) and `just mutants-in-diff` (the pull request
lane) run this on the mutants.out directory that cargo-mutants leaves: one list
per outcome (caught.txt, missed.txt, timeout.txt, unviable.txt) and
outcomes.json, which names the log of every mutant. A mutant that the tests
missed or that timed out is a finding to triage, not a failed run. Two results
fail the run:

untested mutants
    cargo-mutants files every mutant whose build fails as unviable, whatever
    the cause. A build that ran out of disk space, quota or memory, or hit an
    I/O error, never tested its mutant, and a run that counted it as unviable
    would pass on code it did not test. The build log of every unviable mutant
    is searched for those errors; the log of a mutation that does not compile
    holds rustc's errors instead. A log that cannot be read, or an
    outcomes.json that does not account for every unviable mutant, fails the
    run too: then nothing tells why those builds failed.
nothing caught
    With --require-caught, a run that caught no mutant fails: its filters
    matched no code, no mutant built, or the tests fail on none, so it proves
    nothing. The weekly sweep sets it for each of its shards, a quarter of
    several hundred mutants each. The pull request lane does not: a shard of a
    small diff may hold one mutant, or none, and one that does not compile is
    not a failure.

Usage: python3 -m ci.mutants_report [--title TITLE] [--require-caught] MUTANTS_OUT

The counts go to stdout and, in CI, to the job summary ($GITHUB_STEP_SUMMARY)
together with every missed, timed-out and untested mutant and every unviable one
whose build log cannot be read: cargo-mutants flags the missed ones as warning
annotations, of which GitHub shows only a limited number per step.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# What a build prints when its environment fails rather than the mutated code:
# the errno texts of a full disk or quota, exhausted memory, a failing or
# read-only device and a full file table; the aborts of Rust and LLVM when an
# allocation fails; and how a compiler or linker that the kernel's
# out-of-memory killer stopped is reported: by cargo for rustc ("signal: 9,
# SIGKILL: kill"), by rustc for the linker driver it runs ("linking with `cc`
# failed: signal: 9 (SIGKILL)", the form of Rust's own exit status) and by the
# C compiler driver for the linker ("ld terminated with signal 9 [Killed]").
# No production code quotes any of them, so the source lines a build log
# quotes do not match by accident.
INFRASTRUCTURE_ERROR = re.compile(
    r"No space left on device"
    r"|Disk quota exceeded"
    r"|Cannot allocate memory"
    r"|Input/output error"
    r"|Read-only file system"
    r"|Too many open files"
    r"|memory allocation of \d+ bytes failed"
    r"|LLVM ERROR: out of memory"
    r"|signal: 9, SIGKILL"
    r"|signal: 9 \(SIGKILL\)"
    r"|signal 9 \[Killed\]"
)


class ReportError(Exception):
    """mutants.out cannot tell why its unviable mutants did not build."""


@dataclass(frozen=True)
class Untested:
    """An unviable mutant that may never have been tested, and why."""

    mutant: str
    log: str
    error: str

    def __str__(self) -> str:
        where = f" ({self.log})" if self.log else ""
        return f"{self.mutant}: {self.error}{where}"


@dataclass
class Report:
    caught: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)
    timed_out: list[str] = field(default_factory=list)
    unviable: list[str] = field(default_factory=list)
    # Unviable mutants whose build log shows that the runner failed the build.
    untested: list[Untested] = field(default_factory=list)
    # Unviable mutants with no build log to read: nothing shows why.
    unexplained: list[Untested] = field(default_factory=list)

    @property
    def total(self) -> int:
        return (
            len(self.caught)
            + len(self.missed)
            + len(self.timed_out)
            + len(self.unviable)
        )


def _read_list(out: Path, name: str) -> list[str]:
    """The mutants of one outcome; a missing list means none."""
    try:
        text = (out / f"{name}.txt").read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    return [line for line in text.splitlines() if line.strip()]


def _unviable_outcomes(out: Path) -> list[dict[str, Any]]:
    try:
        data = json.loads((out / "outcomes.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise ReportError(f"outcomes.json cannot be read: {error}") from None
    outcomes = data.get("outcomes") if isinstance(data, dict) else None
    if not isinstance(outcomes, list):
        raise ReportError("outcomes.json has no list of outcomes")
    return [
        outcome
        for outcome in outcomes
        if isinstance(outcome, dict) and outcome.get("summary") == "Unviable"
    ]


def find_untested(
    out: Path, outcomes: list[dict[str, Any]]
) -> tuple[list[Untested], list[Untested]]:
    """Name the unviable mutants that may never have been tested.

    The first list holds those whose build log shows a failing environment,
    the second those that have no build log to read.
    """
    untested = []
    unexplained = []
    for outcome in outcomes:
        scenario = outcome.get("scenario")
        mutant = scenario.get("Mutant") if isinstance(scenario, dict) else None
        name = mutant.get("name") if isinstance(mutant, dict) else None
        log_path = outcome.get("log_path")
        if not isinstance(log_path, str) or not log_path:
            label = name if isinstance(name, str) else "an unviable mutant"
            unexplained.append(Untested(label, "", "its outcome names no build log"))
            continue
        label = name if isinstance(name, str) else log_path
        try:
            log = (out / log_path).read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            unexplained.append(
                Untested(label, log_path, f"its build log cannot be read: {error}")
            )
            continue
        match = INFRASTRUCTURE_ERROR.search(log)
        if match:
            untested.append(Untested(label, log_path, match.group(0)))
    return untested, unexplained


def load(out: Path) -> Report:
    """Read the outcome lists of a run and check every unviable mutant's log."""
    report = Report(
        caught=_read_list(out, "caught"),
        missed=_read_list(out, "missed"),
        timed_out=_read_list(out, "timeout"),
        unviable=_read_list(out, "unviable"),
    )
    if report.unviable:
        outcomes = _unviable_outcomes(out)
        if len(outcomes) != len(report.unviable):
            raise ReportError(
                f"outcomes.json holds {len(outcomes)} unviable mutants, "
                f"unviable.txt {len(report.unviable)}"
            )
        report.untested, report.unexplained = find_untested(out, outcomes)
    return report


def counts(report: Report) -> str:
    return (
        f"{len(report.caught)} caught, {len(report.missed)} missed, "
        f"{len(report.timed_out)} timed out, {len(report.unviable)} unviable"
    )


def format_summary(title: str, report: Report) -> str:
    lines = [f"## {title}", "", f"{counts(report)}."]
    sections = (
        ("Missed", report.missed),
        ("Timed out", report.timed_out),
        (
            "Not tested: the build failed for want of resources",
            [str(item) for item in report.untested],
        ),
        (
            "Not shown to be unviable: no build log to read",
            [str(item) for item in report.unexplained],
        ),
    )
    for heading, entries in sections:
        if entries:
            lines += ["", f"### {heading}", "", "```text", *entries, "```"]
    return "\n".join(lines) + "\n"


def _write_summary(text: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as summary:
            summary.write(text)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m ci.mutants_report",
        description="Report a cargo-mutants run and fail one that proved nothing.",
    )
    parser.add_argument("out", type=Path, help="the run's mutants.out directory")
    parser.add_argument(
        "--title",
        default="Mutation testing",
        help="what the run tested, for the output and the job summary",
    )
    parser.add_argument(
        "--require-caught",
        action="store_true",
        help="fail when the run caught no mutant",
    )
    args = parser.parse_args(argv)

    try:
        report = load(args.out)
    except ReportError as error:
        print(f"{args.title}: {args.out}: {error}", file=sys.stderr)
        return 1
    if report.total == 0 and not args.require_caught:
        print(f"{args.title}: no mutable code in this run.")
        return 0

    print(f"{args.title}: {counts(report)} (report in {args.out})")
    _write_summary(format_summary(args.title, report))
    failed = False
    if report.untested:
        print(
            f"{len(report.untested)} mutant(s) were not tested: the build failed "
            "for want of disk, memory or I/O, not because the mutation does not "
            "compile. Run it again on a runner with room to spare.",
            file=sys.stderr,
        )
        for item in report.untested:
            print(f"  {item}", file=sys.stderr)
        failed = True
    if report.unexplained:
        print(
            f"{len(report.unexplained)} unviable mutant(s) have no build log to "
            "read, so nothing shows that the mutation, and not the runner, "
            f"failed their build; see {args.out}",
            file=sys.stderr,
        )
        for item in report.unexplained:
            print(f"  {item}", file=sys.stderr)
        failed = True
    if args.require_caught and not report.caught:
        print(
            f"No mutant was caught, so this run proves nothing; see {args.out}",
            file=sys.stderr,
        )
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
