#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable, NamedTuple


class ValidationError(ValueError):
    pass


class ValidationResult(NamedTuple):
    requested_target: str
    iterations: int
    resolved_leaves: tuple[str, ...]
    builtin_live_supported_leaves: tuple[str, ...]
    modes: tuple[str, ...]


def _validate_leaf_list(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValidationError(f"{field_name} must be a non-empty list of leaf ids.")

    if any(not isinstance(item, str) or not item for item in value):
        raise ValidationError(f"{field_name} must contain only non-empty strings.")

    normalized = tuple(value)
    if len(set(normalized)) != len(normalized):
        raise ValidationError(f"{field_name} must not contain duplicate leaf ids.")

    return normalized


def _validate_modes(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValidationError("modes must be a non-empty list.")

    if any(not isinstance(item, str) or not item for item in value):
        raise ValidationError("modes must contain only non-empty strings.")

    return tuple(value)


def _parse_iterations(value: Any, *, min_iterations: int, max_iterations: int) -> int:
    if isinstance(value, int):
        iterations = value
    elif isinstance(value, str) and value.isdigit() and not value.startswith("0"):
        iterations = int(value)
    else:
        raise ValidationError(
            f"iterations must be a positive integer string within {min_iterations}-{max_iterations}. "
            f"Received {value!r}."
        )

    if iterations < min_iterations or iterations > max_iterations:
        raise ValidationError(
            f"iterations must be within {min_iterations}-{max_iterations}. Received {iterations}."
        )

    return iterations


def validate_live_scope_plan(
    payload: dict[str, Any],
    *,
    expected_requested_target: str,
    allowed_leaves: Iterable[str],
    min_iterations: int,
    max_iterations: int,
) -> ValidationResult:
    allowed = tuple(sorted(allowed_leaves))
    if not allowed:
        raise ValidationError("allowed_leaves must not be empty.")

    requested_targets = payload.get("requestedTargets")
    if requested_targets != [expected_requested_target]:
        raise ValidationError(
            f"Expected requestedTargets={[expected_requested_target]!r}, got {requested_targets!r}."
        )

    resolved = _validate_leaf_list(payload.get("resolvedLeaves"), "resolvedLeaves")
    builtin_live = _validate_leaf_list(
        payload.get("builtinLiveSupportedLeaves"), "builtinLiveSupportedLeaves"
    )
    modes = _validate_modes(payload.get("modes"))
    iterations = _parse_iterations(
        payload.get("iterations"),
        min_iterations=min_iterations,
        max_iterations=max_iterations,
    )

    if tuple(sorted(resolved)) != allowed:
        raise ValidationError(
            "The privileged live workflow is fail-closed to the repo's supported built-in live leaf set. "
            f"Expected resolvedLeaves={list(allowed)!r}, got {list(resolved)!r}."
        )

    if tuple(sorted(builtin_live)) != allowed:
        raise ValidationError(
            "Forensics metadata drifted outside the current built-in live scope for this repo. "
            f"Expected builtinLiveSupportedLeaves={list(allowed)!r}, got {list(builtin_live)!r}."
        )

    return ValidationResult(
        requested_target=expected_requested_target,
        iterations=iterations,
        resolved_leaves=resolved,
        builtin_live_supported_leaves=builtin_live,
        modes=modes,
    )


def load_plan(
    *,
    plan_json: str | None,
    target: str,
    iterations: str,
    plan_script: Path,
) -> dict[str, Any]:
    if plan_json is None:
        completed = subprocess.run(
            [
                str(plan_script),
                "--plan-json",
                target,
                "--",
                "--iterations",
                iterations,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        plan_json = completed.stdout

    try:
        payload = json.loads(plan_json)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"Failed to parse plan JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValidationError("Plan JSON must decode to an object.")

    return payload


def append_github_output(path: Path, result: ValidationResult) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(f"iterations={result.iterations}\n")
        fh.write(f"modes={','.join(result.modes)}\n")
        fh.write("resolved_leaves<<EOF\n")
        fh.write("\n".join(result.resolved_leaves) + "\n")
        fh.write("EOF\n")
        fh.write("builtin_live_leaves<<EOF\n")
        fh.write("\n".join(result.builtin_live_supported_leaves) + "\n")
        fh.write("EOF\n")


def append_github_summary(
    path: Path,
    *,
    title: str,
    intro: str,
    allowed_leaves: tuple[str, ...],
    result: ValidationResult,
) -> None:
    with path.open("a", encoding="utf-8") as summary:
        summary.write(f"## {title}\n\n")
        summary.write(intro.strip() + "\n\n")
        summary.write("| Property | Value |\n")
        summary.write("|---|---|\n")
        summary.write(f"| Requested target | `{result.requested_target}` |\n")
        summary.write(f"| Requested iterations | `{result.iterations}` |\n")
        summary.write(f"| Resolved leaves | `{', '.join(result.resolved_leaves)}` |\n")
        summary.write(
            "| Built-in live-supported leaves | "
            f"`{', '.join(result.builtin_live_supported_leaves)}` |\n"
        )
        summary.write(f"| Modes | `{','.join(result.modes)}` |\n")
        summary.write(f"| Guardrail | `exactly {', '.join(allowed_leaves)}` |\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate the fail-closed live forensics scope guard."
    )
    parser.add_argument(
        "--target", default="live", help="Requested target to validate."
    )
    parser.add_argument(
        "--iterations",
        default="1",
        help="Requested iteration count to validate and pass to the planner.",
    )
    parser.add_argument(
        "--expected-requested-target",
        default="live",
        help="Required requestedTargets value in the resolved plan.",
    )
    parser.add_argument(
        "--allowed-leaf",
        action="append",
        dest="allowed_leaves",
        default=None,
        help="Allowed live leaf. Repeat for multiple leaves.",
    )
    parser.add_argument(
        "--min-iterations",
        type=int,
        default=1,
        help="Minimum allowed iteration count.",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=5,
        help="Maximum allowed iteration count.",
    )
    parser.add_argument(
        "--plan-script",
        default="./scripts/run-forensics-eval-tests.sh",
        help="Planner script used when --plan-json is not provided.",
    )
    parser.add_argument(
        "--plan-json",
        help="Use an explicit plan JSON payload instead of invoking the planner script.",
    )
    parser.add_argument("--github-output", help="Optional GITHUB_OUTPUT file path.")
    parser.add_argument(
        "--github-step-summary", help="Optional GITHUB_STEP_SUMMARY file path."
    )
    parser.add_argument(
        "--summary-title",
        default="Forensics live-target guard",
        help="Markdown heading used when writing a GitHub step summary.",
    )
    parser.add_argument(
        "--summary-intro",
        default=(
            "This guard fails closed if metadata expands beyond the repo's current built-in live "
            "scope. Unsupported leaves such as graphical or vfat-boot are not treated as built-in "
            "live-supported."
        ),
        help="Introductory text used when writing a GitHub step summary.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    allowed_leaves = tuple(args.allowed_leaves or ["direct-baseline/direct-headless"])

    try:
        payload = load_plan(
            plan_json=args.plan_json,
            target=args.target,
            iterations=args.iterations,
            plan_script=Path(args.plan_script),
        )
        result = validate_live_scope_plan(
            payload,
            expected_requested_target=args.expected_requested_target,
            allowed_leaves=allowed_leaves,
            min_iterations=args.min_iterations,
            max_iterations=args.max_iterations,
        )
    except (ValidationError, subprocess.CalledProcessError) as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1

    if args.github_output:
        append_github_output(Path(args.github_output), result)

    if args.github_step_summary:
        append_github_summary(
            Path(args.github_step_summary),
            title=args.summary_title,
            intro=args.summary_intro,
            allowed_leaves=tuple(sorted(allowed_leaves)),
            result=result,
        )

    print(
        json.dumps(
            {
                "requestedTarget": result.requested_target,
                "iterations": result.iterations,
                "resolvedLeaves": list(result.resolved_leaves),
                "builtinLiveSupportedLeaves": list(
                    result.builtin_live_supported_leaves
                ),
                "modes": list(result.modes),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
