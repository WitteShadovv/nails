"""Command-line entry point: ``python3 -m ci.e2e``.

Subcommands plan, run and inspect the NixOS E2E suite from one place. Metadata
is loaded lazily, so ``--help`` and ``interactive`` parse their arguments with
no ``nix`` on PATH.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from . import distro, evaluate, interactive, plan, resolve, run
from .metadata import Metadata, MetadataError, load_metadata

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WEIGHTS = REPO_ROOT / "nix" / "e2e-tests" / "shard-durations.json"
DEFAULT_DURATIONS = REPO_ROOT / "e2e-durations.json"
# The group a bare run (no target) builds.
DEFAULT_TARGET = "ci"

EXIT_INVALID = 1
EXIT_BAD_INPUT = 2

SUBCOMMANDS = frozenset(
    {
        "list",
        "resolve",
        "plan",
        "distro-plan",
        "run",
        "regen-weights",
        "interactive",
        "check",
        "drift",
    }
)


def _default_targets() -> list[str]:
    override = os.environ.get("NAILS_E2E_DEFAULT_TARGET")
    return [override] if override else [DEFAULT_TARGET]


def _metadata() -> Metadata:
    return load_metadata()


def _resolve(
    metadata: Metadata,
    targets: Sequence[str],
    affected: str | None,
    exclude: Sequence[str] = (),
) -> list[str]:
    if affected is not None:
        tests = resolve.resolve_affected(metadata, affected)
    else:
        requested = list(targets) or _default_targets()
        tests = resolve.resolve_targets(metadata, requested)
    excluded = set(resolve.resolve_targets(metadata, exclude))
    return [test for test in tests if test not in excluded]


def _shard(
    tests: Sequence[str], weights: dict[str, int], index: int, count: int
) -> list[str]:
    split = plan.allocate(tests, weights or None, count)
    return split.shards[index - 1]


def _parse_shard(text: str) -> tuple[int, int]:
    try:
        index_text, count_text = text.split("/", 1)
        index, count = int(index_text), int(count_text)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a shard in the form i/N"
        ) from None
    if not 1 <= index <= count:
        raise argparse.ArgumentTypeError("a shard must satisfy 1 <= i <= N")
    return index, count


def _weights_for(metadata: Metadata, weights_path: Path) -> dict[str, int]:
    raw = plan.load_weights(weights_path)
    if not raw:
        return {}
    return plan.usable_weights(raw, metadata.timeouts)


def _command_list(args: argparse.Namespace) -> int:
    metadata = _metadata()
    leaf_set = metadata.leaf_set
    for name in metadata.available_targets:
        if name in leaf_set:
            kind = "test"
        elif name in metadata.aliases:
            kind = f"alias of {metadata.aliases[name]}"
        else:
            kind = "group"
        print(f"{name}\t{kind}")
    return 0


def _command_resolve(args: argparse.Namespace) -> int:
    metadata = _metadata()
    for test in _resolve(metadata, args.targets, args.affected, args.exclude):
        print(test)
    return 0


def _command_plan(args: argparse.Namespace) -> int:
    metadata = _metadata()
    tests = _resolve(metadata, args.targets, args.affected, args.exclude)
    weights = _weights_for(metadata, args.weights)
    if args.shards is not None:
        count = args.shards
    else:
        count = plan.shard_count(tests, weights, args.max_shards, args.shard_seconds)
    split = plan.allocate(tests, weights or None, count)
    if args.format == "github-matrix":
        # An empty shard would boot a runner for nothing, but a matrix needs
        # at least one entry, so an empty selection keeps one empty shard.
        shards = [
            (shard, load)
            for shard, load in zip(split.shards, split.loads, strict=True)
            if shard
        ] or [([], 0)]
        include = [
            {
                "index": index,
                "count": len(shards),
                "tests": shard,
                "timeout": plan.shard_timeout_minutes(load),
            }
            for index, (shard, load) in enumerate(shards, start=1)
        ]
        print(json.dumps({"include": include}))
    else:
        for index, shard in enumerate(split.shards, start=1):
            load = split.loads[index - 1]
            print(f"shard {index}/{count} ({load}s): " + " ".join(shard))
    return 0


def _command_distro_plan(args: argparse.Namespace) -> int:
    metadata = distro.load_distro_metadata()
    if args.suite == "probe":
        matrix = distro.plan_probe_matrix(metadata, args.distros)
    else:
        matrix = distro.plan_distro_matrix(
            metadata, args.distros, max_jobs=args.max_jobs
        )
    print(json.dumps(matrix))
    return 0


def _reporter(
    args: argparse.Namespace,
) -> Callable[[Sequence[str], Mapping[str, run.TestOutcome]], None]:
    def report(tests: Sequence[str], outcomes: Mapping[str, run.TestOutcome]) -> None:
        if args.summary is not None:
            with args.summary.open("a", encoding="utf-8") as summary:
                summary.write(run.format_summary(args.heading, tests, outcomes))
        if args.github:
            for annotation in run.format_annotations(tests, outcomes):
                print(annotation)

    return report


def _command_run(args: argparse.Namespace) -> int:
    # The clock starts before anything else, the metadata's evaluation too.
    limit = None
    if args.job_timeout is not None:
        limit = run.job_time_limit(args.job_timeout, args.retries)
        print(
            f"time limit: {args.job_timeout - run.JOB_RESERVE_MINUTES} minutes for "
            f"the run, {limit.test_seconds}s for one attempt of a test",
            file=sys.stderr,
        )
    metadata = _metadata()
    tests = _resolve(metadata, args.targets, args.affected, args.exclude)
    if args.shard is not None:
        index, count = args.shard
        weights = _weights_for(metadata, args.weights)
        tests = _shard(tests, weights, index, count)
    if not tests:
        print("no tests selected for this shard; nothing to run", file=sys.stderr)
        return 0
    if args.execute:
        return run.run_drivers(
            tests,
            metadata.timeouts,
            durations_out=args.durations_out,
            retries=args.retries,
            log_dir=args.log_dir,
            report=_reporter(args),
            eval_batch=args.eval_batch,
            eval_workers=args.eval_jobs,
            limit=limit,
        )
    return run.run_build(
        tests,
        jobs=args.jobs,
        eval_batch=args.eval_batch,
        eval_workers=args.eval_jobs,
        durations_out=args.durations_out,
        retries=args.retries,
        log_dir=args.log_dir,
        report=_reporter(args),
        require_boot=args.require_boot,
        timeouts=metadata.timeouts,
        limit=limit,
    )


def _command_regen(args: argparse.Namespace) -> int:
    metadata = _metadata()
    raw = plan.load_weights(args.weights) or {}
    samples = plan.load_samples(args.samples)
    if not samples:
        raise plan.InputError("the duration files hold no boot-verified samples")
    weights, notes = plan.regen(raw, samples, metadata.timeouts)
    for note in notes:
        print(f"note: {note}", file=sys.stderr)
    args.weights.write_text(plan.format_weights(weights), encoding="utf-8")
    print(
        f"{args.weights}: wrote {len(weights)} weights from samples of "
        f"{len(samples)} tests"
    )
    return 0


def _command_interactive(args: argparse.Namespace) -> int:
    interactive.exec_interactive(args.name)
    return 0  # unreachable: execvp replaces the process


def _command_check(args: argparse.Namespace) -> int:
    timeouts = plan.load_timeouts(args.metadata)
    raw = plan.load_weights(args.weights)
    if raw is None:
        raise plan.InputError(f"{args.weights}: no such file")
    findings = plan.validate(raw, timeouts)
    plan.print_findings(findings, strict=True)
    if findings.errors or findings.issues:
        return EXIT_INVALID
    print(f"{args.weights}: {len(raw)} weights match {len(timeouts)} tests")
    return 0


def _command_drift(args: argparse.Namespace) -> int:
    raw = plan.load_weights(args.weights) or {}
    weights = {
        test: value
        for test, raw_value in raw.items()
        if (value := plan._seconds(raw_value)) is not None
    }
    report = plan.drift(weights, plan.load_samples(args.samples), args.threshold)
    markdown = plan.format_drift_markdown(report, args.heading)
    if args.summary is not None:
        with args.summary.open("a", encoding="utf-8") as summary:
            summary.write(markdown)
    else:
        sys.stdout.write(markdown)
    if args.github:
        for annotation in plan.format_drift_annotations(report):
            print(annotation)
    return 0


def _positive_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not an integer") from None
    if value < 1:
        raise argparse.ArgumentTypeError(f"{text!r} must be at least 1")
    return value


def _jobs(text: str) -> int:
    if text == "auto":
        return run.auto_jobs()
    return _positive_int(text)


def _eval_jobs(text: str) -> int:
    if text == "auto":
        return evaluate.auto_workers()
    return _positive_int(text)


def _non_negative_int(text: str) -> int:
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not an integer") from None
    if value < 0:
        raise argparse.ArgumentTypeError(f"{text!r} must not be negative")
    return value


def _fraction(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number") from None
    if not value > 0:
        raise argparse.ArgumentTypeError(f"{text!r} must be positive")
    return value


def _add_target_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("targets", nargs="*", help="leaf tests or group names")
    parser.add_argument(
        "--affected",
        metavar="BASE_REV",
        help="run the ci group plus every test changed since this revision",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="TARGET",
        help="leave out the tests of this leaf test or group (repeatable)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m ci.e2e",
        description="Plan and run the NixOS E2E suite.",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        metavar="NAME",
        help="launch the interactive driver of one leaf test and exit",
    )
    commands = parser.add_subparsers(dest="command")

    commands.add_parser("list", help="list targets and groups").set_defaults(
        handler=_command_list
    )

    resolve_cmd = commands.add_parser("resolve", help="expand targets to leaf tests")
    _add_target_args(resolve_cmd)
    resolve_cmd.set_defaults(handler=_command_resolve)

    plan_cmd = commands.add_parser("plan", help="split tests into weighted shards")
    _add_target_args(plan_cmd)
    count = plan_cmd.add_mutually_exclusive_group(required=True)
    count.add_argument("--shards", type=_positive_int, help="exactly this many")
    count.add_argument(
        "--max-shards",
        type=_positive_int,
        help="as many shards as --shard-seconds asks for, up to this many",
    )
    plan_cmd.add_argument(
        "--shard-seconds",
        type=_positive_int,
        default=plan.SHARD_SECONDS,
        help="weighted seconds of tests one shard should hold (--max-shards)",
    )
    plan_cmd.add_argument("--weights", type=Path, default=DEFAULT_WEIGHTS)
    plan_cmd.add_argument(
        "--format", choices=("lines", "github-matrix"), default="lines"
    )
    plan_cmd.set_defaults(handler=_command_plan)

    distro_cmd = commands.add_parser(
        "distro-plan", help="emit the distro VM smoke matrix as a GitHub matrix"
    )
    distro_cmd.add_argument(
        "distros",
        nargs="*",
        help=(
            "distributions to run (probes with --suite probe), or all of them "
            "when none are named"
        ),
    )
    distro_cmd.add_argument(
        "--suite",
        choices=("smoke", "probe"),
        default="smoke",
        help=(
            "plan the smoke scenarios, or the fact probes of the images not "
            "admitted yet, one job each"
        ),
    )
    distro_cmd.add_argument(
        "--max-jobs",
        type=_positive_int,
        default=distro.MAX_DISTRO_JOBS,
        help="upper bound on parallel distro jobs (distros x shards; smoke only)",
    )
    distro_cmd.set_defaults(handler=_command_distro_plan)

    run_cmd = commands.add_parser("run", help="build resolved tests in one nix build")
    _add_target_args(run_cmd)
    run_cmd.add_argument("--shard", type=_parse_shard, metavar="i/N")
    run_cmd.add_argument(
        "--jobs",
        type=_jobs,
        help="VM tests built at once (nix --max-jobs); 'auto' sizes it from RAM",
    )
    run_cmd.add_argument(
        "--eval-batch",
        type=_positive_int,
        help="tests evaluated per nix eval process, bounding evaluation memory "
        "(default: the tests spread evenly over --eval-jobs processes, at most "
        f"{evaluate.MAX_BATCH} each)",
    )
    run_cmd.add_argument(
        "--eval-jobs",
        type=_eval_jobs,
        default="auto",
        help="nix eval processes run at once; 'auto' (the default) sizes it "
        "from the host's cores and RAM",
    )
    run_cmd.add_argument("--weights", type=Path, default=DEFAULT_WEIGHTS)
    run_cmd.add_argument("--durations-out", type=Path, default=DEFAULT_DURATIONS)
    run_cmd.add_argument(
        "--retries",
        type=_non_negative_int,
        default=0,
        help="run failed tests again up to this many times; a pass is FLAKY",
    )
    run_cmd.add_argument(
        "--execute",
        action="store_true",
        help="run each test's driver directly, so cached results do not count",
    )
    run_cmd.add_argument(
        "--require-boot",
        action="store_true",
        help="fail a test that the store or a binary cache served instead of a "
        "build in this run (--execute boots every test anyway)",
    )
    run_cmd.add_argument(
        "--job-timeout",
        type=_positive_int,
        metavar="MINUTES",
        help="the timeout of the CI job this run is in: the run ends "
        f"{run.JOB_RESERVE_MINUTES} minutes before it, stopping what still runs, "
        "and one attempt of a test may take an equal share of the rest per "
        "attempt (half of it with --retries 1); a test stopped for its time "
        "fails as timed out, one never started as not run",
    )
    run_cmd.add_argument(
        "--log-dir", type=Path, help="write the log of every failed test here"
    )
    run_cmd.add_argument("--summary", type=Path, help="append Markdown to this file")
    run_cmd.add_argument("--github", action="store_true", help="print annotations")
    run_cmd.add_argument("--heading", default="E2E results")
    run_cmd.set_defaults(handler=_command_run)

    regen_cmd = commands.add_parser(
        "regen-weights", help="rewrite shard-durations.json from recorded runs"
    )
    regen_cmd.add_argument("--weights", type=Path, default=DEFAULT_WEIGHTS)
    regen_cmd.add_argument("samples", nargs="+", type=Path)
    regen_cmd.set_defaults(handler=_command_regen)

    interactive_cmd = commands.add_parser(
        "interactive", help="launch the interactive driver of one leaf test"
    )
    interactive_cmd.add_argument("name", help="the leaf test to open")
    interactive_cmd.set_defaults(handler=_command_interactive)

    check_cmd = commands.add_parser("check", help="strictly validate the weights file")
    check_cmd.add_argument("--weights", type=Path, default=DEFAULT_WEIGHTS)
    check_cmd.add_argument(
        "--metadata", required=True, help="E2E metadata JSON file, or - for stdin"
    )
    check_cmd.set_defaults(handler=_command_check)

    drift_cmd = commands.add_parser(
        "drift", help="report durations that drifted from their weights"
    )
    drift_cmd.add_argument("--weights", type=Path, default=DEFAULT_WEIGHTS)
    drift_cmd.add_argument("--threshold", type=_fraction, default=plan.DRIFT_THRESHOLD)
    drift_cmd.add_argument("--summary", type=Path, help="append Markdown to this file")
    drift_cmd.add_argument("--github", action="store_true", help="print annotations")
    drift_cmd.add_argument("--heading", default="E2E shard weight drift")
    drift_cmd.add_argument("samples", nargs="+", type=Path)
    drift_cmd.set_defaults(handler=_command_drift)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    tokens = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    # A bare target (not an option, not a subcommand) is an implicit `run`, so
    # `run-e2e-tests.sh basic-workflow` keeps working through the wrapper.
    if tokens and not tokens[0].startswith("-") and tokens[0] not in SUBCOMMANDS:
        tokens = ["run", *tokens]
    args = parser.parse_args(tokens)
    if args.interactive is not None:
        interactive.exec_interactive(args.interactive)
        return 0  # unreachable: execvp replaces the process
    if args.command is None:
        # A bare invocation builds the default target.
        args = parser.parse_args(["run"])
    try:
        return int(args.handler(args))
    except (
        plan.InputError,
        resolve.ResolveError,
        evaluate.EvalError,
        MetadataError,
        distro.DistroError,
        run.RunError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_BAD_INPUT


if __name__ == "__main__":
    sys.exit(main())
