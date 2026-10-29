"""Size the in-diff mutation lane to the diff it tests.

The plan job of mutants-in-diff.yml lists the mutants of a pull request's diff
(`just mutants-in-diff-plan`: cargo-mutants --list with the options that
`just mutants-in-diff` tests with, which builds nothing) and passes the list
here. The plan costs each mutant by the package whose tests run on it, and
gives the lane as many shards as keep each one inside its time box with a
margin, at most MAX_SHARDS: it reckons with the very mutants each shard gets,
since cargo-mutants hands shard k of n the k-th run of consecutive mutants of
the same list. A diff too large for that many shards of the ordinary box gets
a longer box for each shard, up to MAX_SHARD_MINUTES. A diff that holds no
mutant runs no shard.

A diff too large even for the longest boxes runs no shard either, so none of
its mutants is tested, and the rest of CI does not make up for it: the weekly
sweep mutates only its own three directories, and a release pull request into
main gets no in-diff run. The plan therefore fails, with the count, rather than
pass a diff it did not test. That turns the lane red but blocks nothing: the
lane is informational, and a pull request can merge into next with it red,
cancelled or skipped.

Usage: python3 -m ci.mutants_plan LIST

LIST is what `cargo mutants --list --json` printed, or - for stdin. Prints
``name=value`` lines in the format of $GITHUB_OUTPUT (``shards`` and the shard
``matrix``, which the workflow reads) and explains the plan, with the count of
mutants, on stderr and, in CI, in the job summary ($GITHUB_STEP_SUMMARY). Exits
1 when LIST cannot be read, printing no outputs, and when the diff is too large
for the lane, after printing them.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from fractions import Fraction
from itertools import accumulate
from pathlib import Path

# What a shard costs on a hosted ubuntu-26.04 runner.
#
# The setup, from the start of the job to the end of the unmutated baseline
# (checkout, toolchain, tools, the copy of the tree, the baseline's build and
# tests): 27 to 133 s over 186 shards of the lane's 83 runs of 22 to 24 October
# 2026, 67 s in half of them and over 120 s in five, from GitHub's job times and
# the timestamps of cargo-mutants' log lines; 25 to 121 s over the 25 shards of
# 29 October 2026 below.
SETUP_SECONDS = 120
# One mutant, by the package whose tests cargo-mutants runs on it: the mean
# build and test of a mutant that built and was tested (caught or missed),
# rounded up to the second. Measured on 29 October 2026 from the outcomes.json
# of the 25 shards that the runs of three pull requests finished or stopped at
# their time box, 1,004 mutants, leaving out the two shards in which test
# binaries that had run into the timeout went on running (see TIMEOUT_SECONDS):
#
#   nails-api        63 mutants    1.1 s, 1.2 s in nine of ten
#   nails-base      297           10.4 s, 12.4 s
#   nails-cli        54           14.8 s, 18.0 s
#   nails-core       15           20.5 s, 21.3 s
#   nails-session   299            6.6 s,  7.7 s
#   nails-teardown   43            5.8 s,  6.2 s
#
# A mutant that does not compile costs about a second, and outside those two
# shards none took longer than 35 s. The flat 20 s that the plan took for every
# mutant before overstated all but nails-core. A package not measured here, or
# on too few mutants (nails-forensics, four), costs as much as the dearest one
# measured.
SECONDS_PER_MUTANT = {
    "nails-api": 2,
    "nails-base": 11,
    "nails-cli": 15,
    "nails-core": 21,
    "nails-session": 7,
    "nails-teardown": 6,
}
UNMEASURED_SECONDS_PER_MUTANT = max(SECONDS_PER_MUTANT.values())
# A mutant whose tests run into the --timeout of `just mutants-in-diff` costs
# that much more, and each shard has room for TIMEOUTS_PER_SHARD of them. Of the
# 1,004 mutants, 6 ran into it, five of them in one shard of 59. There each test
# binary that ran into it had installed the SIGTERM handler of nails-base's
# cancel module, outlived the SIGTERM with which cargo-mutants ends a test run
# and kept a core busy: the shard's mutants built in 9 s before its first
# timeout and in 27 to 61 s after its third, and it ran out of its 28-minute box
# after 34 of its mutants. `just mutants-in-diff` now kills such a test binary
# (ci/mutants_guard.py).
TIMEOUT_SECONDS = 120
TIMEOUTS_PER_SHARD = 2
# A shard's expected time plus this share must fit its time box: room for a
# slower runner, a slower setup, or mutants dearer than the mean of their
# package.
MARGIN = Fraction(5, 4)
# A shard's time box, in minutes: the lane's ordinary box, and the longest a
# diff too large for MAX_SHARDS ordinary shards may get, twice the ordinary
# one. The ordinary box holds 32 mutants of nails-base or 51 of nails-session,
# the longest 98 or 154. The box bounds the shard's mutation step, which stops
# cargo-mutants when it runs out.
SHARD_MINUTES = 15
MAX_SHARD_MINUTES = 30
# How much longer than its box a shard's job may run: the checkout and the
# installs before the mutation step (a part of the setup above, at most 133 s
# with the copy and the baseline), and after it the stop of cargo-mutants (a
# minute at most), the report and the upload. Only a step that hangs reaches
# the job's limit.
JOB_MINUTES_PAST_BOX = 5
# The most shards one diff gets. GitHub runs only so many hosted jobs at once
# for an account, and every workflow of every open pull request draws on them:
# a push to a pull request into next starts up to thirty other jobs (ci.yml's,
# the E2E plan and up to ten shards, CodeQL, fuzzing). On 24 October 2026 up to
# 46 jobs of this repository's pull-request runs ran at once, 43 at most when
# this lane's own are left out and 49 when the push, scheduled and dispatched
# runs count too (from the jobs API, over every run created that day: each job
# that ran on a runner, from its start to its end). Twelve keeps this lane,
# which gates nothing, to about a quarter of that peak. Of the pull requests
# into next from 22 to 24 October, diffed as the lane diffs them now, only one
# held more than 360 mutants (409), and the next largest held 275. Three open
# on 29 October held 185, 388 and 700.
MAX_SHARDS = 12

TITLE = "Mutation testing on the diff: the plan"


class ListError(Exception):
    """The listing is not what cargo-mutants --list --json prints."""


@dataclass(frozen=True)
class Plan:
    """How the lane tests the mutants of one diff."""

    mutants: int
    # The shards to run: none for a diff without mutants or with too many.
    shards: int = 0
    # The mutants of the largest shard. cargo-mutants gives shard k of n the
    # k-th run of ceil(mutants / n) consecutive mutants, so no shard holds more.
    per_shard: int = 0
    # The time box of each shard, in minutes: the one the dearest shard needs.
    # For a diff too large for the lane, the box its MAX_SHARDS shards would
    # need.
    minutes: int = 0

    @property
    def too_large(self) -> bool:
        return self.mutants > 0 and self.shards == 0

    @property
    def job_minutes(self) -> int:
        """The limit of a shard's job: its time box and the steps around it."""
        return self.minutes + JOB_MINUTES_PAST_BOX


def mutant_seconds(package: str) -> int:
    """What one mutant whose tests run in ``package`` costs a shard."""
    return SECONDS_PER_MUTANT.get(package, UNMEASURED_SECONDS_PER_MUTANT)


# What every shard costs besides its mutants: the setup and the room for
# mutants that run into the timeout.
_FIXED_SECONDS = SETUP_SECONDS + TIMEOUTS_PER_SHARD * TIMEOUT_SECONDS


def _box(seconds: int) -> int:
    """The time box of a shard whose mutants cost ``seconds``."""
    return max(SHARD_MINUTES, math.ceil((_FIXED_SECONDS + seconds) * MARGIN / 60))


def shard_minutes(packages: Sequence[str]) -> int:
    """The time box of a shard whose mutants run the tests of ``packages``.

    One entry per mutant. Never under SHARD_MINUTES.
    """
    return _box(sum(mutant_seconds(package) for package in packages))


def capacity(minutes: int, package: str) -> int:
    """How many mutants of ``package`` one shard tests in ``minutes``."""
    seconds = minutes * 60 / MARGIN - _FIXED_SECONDS
    return max(0, math.floor(seconds / mutant_seconds(package)))


def slices(mutants: int, shards: int) -> list[range]:
    """The mutants of each shard, as cargo-mutants slices them.

    Its default sharding (`--sharding=slice`) gives shard k of n the k-th run
    of ceil(mutants / n) consecutive mutants of the list; the last may be
    shorter, or empty.
    """
    size = math.ceil(mutants / shards)
    return [
        range(min(k * size, mutants), min((k + 1) * size, mutants))
        for k in range(shards)
    ]


def plan(packages: Sequence[str]) -> Plan:
    """Split the mutants over the fewest shards that fit their time boxes.

    ``packages`` holds the package of each mutant, in the order of the list
    that cargo-mutants slices.
    """
    mutants = len(packages)
    if mutants == 0:
        return Plan(0)
    # The cost of the first i mutants, so that a slice costs a subtraction.
    before = list(accumulate(map(mutant_seconds, packages), initial=0))
    shards = per_shard = minutes = 0
    for count in range(1, min(MAX_SHARDS, mutants) + 1):
        parts = slices(mutants, count)
        # A count that leaves a shard empty splits no finer than the fewer
        # shards that the same slices fill.
        if not parts[-1]:
            continue
        shards, per_shard = count, len(parts[0])
        minutes = max(_box(before[part.stop] - before[part.start]) for part in parts)
        if minutes == SHARD_MINUTES:
            break
    if minutes > MAX_SHARD_MINUTES:
        return Plan(mutants, per_shard=per_shard, minutes=minutes)
    return Plan(mutants, shards, per_shard, minutes)


def listed_packages(text: str) -> list[str]:
    """The package of each mutant in what `cargo mutants --list --json` printed.

    cargo-mutants prints nothing at all, not an empty list, and exits 0 when
    the diff is empty, changes no Rust source file or touches no mutant.
    """
    if not text.strip():
        return []
    try:
        listed = json.loads(text)
    except ValueError as error:
        raise ListError(f"not JSON: {error}") from None
    if not isinstance(listed, list) or not all(
        isinstance(mutant, dict) and isinstance(mutant.get("package"), str)
        for mutant in listed
    ):
        raise ListError("not a JSON list of mutants, each with its package")
    return [mutant["package"] for mutant in listed]


def matrix(planned: Plan) -> dict[str, list[dict[str, int]]]:
    """The shard job's matrix, for each shard k of n.

    ``minutes`` is the shard's time box, which the mutation step keeps to, and
    ``timeout`` the limit of its job: GitHub's expressions cannot add the one to
    the other.
    """
    return {
        "include": [
            {
                "shard": shard,
                "shards": planned.shards,
                "minutes": planned.minutes,
                "timeout": planned.job_minutes,
            }
            for shard in range(planned.shards)
        ]
    }


def _mutants(count: int) -> str:
    return f"{count} mutant" if count == 1 else f"{count} mutants"


def _by_package(packages: Sequence[str]) -> str:
    counts = Counter(packages).most_common()
    return ", ".join(f"{package} {count}" for package, count in counts)


def describe(planned: Plan, packages: Sequence[str] = ()) -> str:
    if planned.mutants == 0:
        return "The diff changes no mutable code, so no shard runs."
    held = _mutants(planned.mutants)
    if packages:
        held += f" ({_by_package(packages)})"
    if planned.too_large:
        return (
            f"The diff holds {held}, more than the lane can test: in "
            f"{MAX_SHARDS} shards of at most {planned.per_shard} they would need "
            f"{planned.minutes}-minute time boxes, and the lane gives a shard "
            f"{MAX_SHARD_MINUTES} minutes at most. No shard runs, so none of the "
            "diff's mutants is tested, and the lane fails. `just mutants-in-diff` "
            "tests the diff where time allows."
        )
    if planned.shards == 1:
        return (
            f"{held} in the diff: one shard, time-boxed at {planned.minutes} minutes."
        )
    return (
        f"{held} in the diff: {planned.shards} shards of at most "
        f"{planned.per_shard}, each time-boxed at {planned.minutes} minutes."
    )


def _escape(message: str) -> str:
    """Escape the data of a GitHub workflow command."""
    return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _write_summary(text: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as summary:
            summary.write(text)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m ci.mutants_plan",
        description="Size the in-diff mutation lane to the mutants of a diff.",
    )
    parser.add_argument(
        "listing",
        help="what `cargo mutants --list --json` printed, or - for stdin",
    )
    args = parser.parse_args(argv)

    try:
        if args.listing == "-":
            text = sys.stdin.read()
        else:
            text = Path(args.listing).read_text(encoding="utf-8")
        packages = listed_packages(text)
    except (OSError, ListError) as error:
        print(f"{args.listing}: {error}", file=sys.stderr)
        return 1

    planned = plan(packages)
    print(f"shards={planned.shards}")
    print("matrix=" + json.dumps(matrix(planned), separators=(",", ":")))
    message = describe(planned, packages)
    print(message, file=sys.stderr)
    _write_summary(f"## {TITLE}\n\n{message}\n")
    if planned.too_large:
        # The runner reads workflow commands on stderr as well; stdout is the
        # step's $GITHUB_OUTPUT.
        print(
            "::error title=Diff too large for mutation testing::" + _escape(message),
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
