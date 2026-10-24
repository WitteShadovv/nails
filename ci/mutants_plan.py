"""Size the in-diff mutation lane to the diff it tests.

The plan job of mutants-in-diff.yml lists the mutants of a pull request's diff
(`just mutants-in-diff-plan`: cargo-mutants --list with the options that
`just mutants-in-diff` tests with, which builds nothing) and passes the list
here. The plan gives the lane as many shards as keep each one inside its time
box with a margin, at most MAX_SHARDS. A diff too large for that many shards of
the ordinary box gets a longer box for each shard, up to MAX_SHARD_MINUTES. A
diff too large even for that runs no shard: the plan reports its count and the
lane passes, since it gates nothing and the weekly sweep still mutates the code
it covers. A diff that holds no mutant runs no shard either.

Usage: python3 -m ci.mutants_plan LIST

LIST is what `cargo mutants --list --json` printed, or - for stdin. Prints
``name=value`` lines in the format of $GITHUB_OUTPUT (``mutants``, ``shards``
and the shard ``matrix``) and explains the plan on stderr and, in CI, in the job
summary ($GITHUB_STEP_SUMMARY).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

# What a shard costs on a hosted ubuntu-26.04 runner, measured on the lane's
# 83 runs of 22 to 24 October 2026 from GitHub's job times and the timestamps
# of cargo-mutants' log lines:
# - From the start of the job to the end of the unmutated baseline (checkout,
#   toolchain, tools, the copy of the tree, the baseline's build and tests):
#   27 to 133 s over 186 shards, 67 s in half of them and over 120 s in five.
# - One mutant: a build of up to 20 s (3 s or less for half of them) and a test
#   run of up to 29 s, or the 120 s --timeout of `just mutants-in-diff`. The
#   logs time only the mutants that survived or timed out: 480, of which 17
#   timed out. A finished shard of 20 mutants or more averaged 2 to 18 s a
#   mutant, the low end where many mutants did not compile, and the four
#   shards of 100 or more that a diff of 409 mutants got, all cancelled at 15
#   minutes, 10 to 19 s up to their last logged mutant.
# At these figures the longest of the 156 finished shards with mutants would
# have used 68% of the time box the plan gives it.
SETUP_SECONDS = 120
SECONDS_PER_MUTANT = 20
# A shard's expected time plus this share must fit its time box: room for a
# slower runner, a slower setup, or a mutant or two that run into the timeout.
MARGIN = Fraction(5, 4)
# A shard's time box, in minutes: the lane's ordinary box, which holds 30
# mutants at the cost above, and the longest a diff too large for MAX_SHARDS
# ordinary shards may get (66 mutants), twice the ordinary one.
SHARD_MINUTES = 15
MAX_SHARD_MINUTES = 30
# The most shards one diff gets. GitHub runs a limited number of hosted jobs at
# once for the whole account (20 on GitHub Free, 40 on Pro), and every workflow
# of every open pull request draws on them: a pull request into next starts up
# to thirty other jobs (ci.yml's, the E2E plan and up to ten shards, CodeQL,
# fuzzing), and this repository's pull requests ran up to 39 jobs at once on
# 24 October 2026. Twelve keeps this lane, which gates nothing, to under a
# third of that. Twelve ordinary shards hold 360 mutants: of the pull requests
# into next from 22 to 24 October, diffed as the lane diffs them now, only one
# needed more (409, which fit twelve 18-minute boxes), and the next largest
# held 275.
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
    # k-th slice of ceil(mutants / n) mutants, so no shard holds more.
    per_shard: int = 0
    # The time box of each shard, in minutes.
    minutes: int = 0

    @property
    def too_large(self) -> bool:
        return self.mutants > 0 and self.shards == 0


def shard_minutes(mutants: int) -> int:
    """The time box of a shard of ``mutants``: never under SHARD_MINUTES."""
    expected = SETUP_SECONDS + mutants * SECONDS_PER_MUTANT
    return max(SHARD_MINUTES, math.ceil(expected * MARGIN / 60))


def capacity(minutes: int) -> int:
    """How many mutants one shard tests inside a time box of ``minutes``."""
    seconds = minutes * 60 / MARGIN - SETUP_SECONDS
    return max(0, math.floor(seconds / SECONDS_PER_MUTANT))


def most_mutants() -> int:
    """The largest diff the lane tests: MAX_SHARDS of the longest box."""
    return MAX_SHARDS * capacity(MAX_SHARD_MINUTES)


def plan(mutants: int) -> Plan:
    """Split ``mutants`` over the fewest shards that fit their time boxes."""
    if mutants <= 0:
        return Plan(0)
    shards = min(MAX_SHARDS, math.ceil(mutants / capacity(SHARD_MINUTES)))
    per_shard = math.ceil(mutants / shards)
    minutes = shard_minutes(per_shard)
    if minutes > MAX_SHARD_MINUTES:
        return Plan(mutants)
    return Plan(mutants, shards, per_shard, minutes)


def count_mutants(text: str) -> int:
    """Count the mutants in what `cargo mutants --list --json` printed.

    cargo-mutants prints nothing at all, not an empty list, and exits 0 when
    the diff is empty, changes no Rust source file or touches no mutant.
    """
    if not text.strip():
        return 0
    try:
        listed = json.loads(text)
    except ValueError as error:
        raise ListError(f"not JSON: {error}") from None
    if not isinstance(listed, list) or not all(
        isinstance(mutant, dict) for mutant in listed
    ):
        raise ListError("not a JSON list of mutants")
    return len(listed)


def matrix(planned: Plan) -> dict[str, list[dict[str, int]]]:
    """The shard job's matrix: shard k of n and its time box, for each k."""
    return {
        "include": [
            {"shard": shard, "shards": planned.shards, "timeout": planned.minutes}
            for shard in range(planned.shards)
        ]
    }


def _mutants(count: int) -> str:
    return f"{count} mutant" if count == 1 else f"{count} mutants"


def describe(planned: Plan) -> str:
    if planned.mutants == 0:
        return "The diff changes no mutable code, so no shard runs."
    if planned.too_large:
        return (
            f"The diff holds {_mutants(planned.mutants)}, more than the lane can "
            f"test: {MAX_SHARDS} shards of {capacity(MAX_SHARD_MINUTES)}, in "
            f"{MAX_SHARD_MINUTES}-minute time boxes, hold {most_mutants()}. No "
            "shard runs and the lane passes; the weekly sweep still mutates the "
            "code it covers, and `just mutants-in-diff` tests the diff where "
            "time allows."
        )
    if planned.shards == 1:
        return (
            f"{_mutants(planned.mutants)} in the diff: one shard, time-boxed at "
            f"{planned.minutes} minutes."
        )
    return (
        f"{_mutants(planned.mutants)} in the diff: {planned.shards} shards of at "
        f"most {planned.per_shard}, each time-boxed at {planned.minutes} minutes."
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
        mutants = count_mutants(text)
    except (OSError, ListError) as error:
        print(f"{args.listing}: {error}", file=sys.stderr)
        return 1

    planned = plan(mutants)
    print(f"mutants={planned.mutants}")
    print(f"shards={planned.shards}")
    print("matrix=" + json.dumps(matrix(planned), separators=(",", ":")))
    message = describe(planned)
    print(message, file=sys.stderr)
    if planned.too_large:
        # The runner reads workflow commands on stderr as well; stdout is the
        # step's $GITHUB_OUTPUT.
        print(
            "::warning title=Diff too large for mutation testing::"
            + _escape(message),
            file=sys.stderr,
        )
    _write_summary(f"## {TITLE}\n\n{message}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
