#!/usr/bin/env python3
"""Run pluggable forensic analyzers and render normalized reports."""

from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from framework import (  # noqa: E402
    Analyzer,
    AnalyzerContext,
    AnalyzerError,
    CONTRACT_VERSION,
    finding_fingerprint,
    load_allowlist,
    load_manifest,
    load_optional_json,
    write_json,
    write_text,
)
from schema_validation import validate_with_schema_path  # noqa: E402
from renderers.campaign import (  # noqa: E402
    build_campaign_summary,
    collect_run_summaries,
    render_campaign_markdown,
)
from renderers.markdown import render_report  # noqa: E402
from renderers.summary import build_summary  # noqa: E402


class CliError(RuntimeError):
    """Raised for expected CLI contract failures."""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run NAILS forensic analyzers against exported stage evidence.",
    )
    parser.add_argument("--run-dir", default=None, help="Run bundle directory.")
    parser.add_argument(
        "--stage",
        action="append",
        default=[],
        help="Stage name to analyze. May be repeated.",
    )
    parser.add_argument(
        "--stage-dir",
        action="append",
        default=[],
        help="Explicit stage mapping in NAME=PATH form. May be repeated.",
    )
    parser.add_argument(
        "--baseline-dir",
        default=None,
        help="Explicit baseline stage directory. Defaults to baseline stage mapping.",
    )
    parser.add_argument(
        "--manifest",
        default=str(SCRIPT_DIR / "registry.json"),
        help="Analyzer registry/manifest JSON path.",
    )
    parser.add_argument(
        "--allowlist",
        action="append",
        default=[],
        help="Allowlist JSON path. May be repeated.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output directory. Defaults to <run-dir>/compare or ./compare.",
    )
    parser.add_argument(
        "--scratch-dir",
        default=None,
        help="Scratch directory kept separate from evidence and outputs.",
    )
    parser.add_argument("--profile", default=None, help="Profile identifier.")
    parser.add_argument("--scenario-id", default=None, help="Scenario identifier.")
    parser.add_argument("--run-id", default=None, help="Run identifier.")
    parser.add_argument("--iteration", type=int, default=None, help="Iteration number.")
    parser.add_argument(
        "--summary-output",
        default=None,
        help="summary.json output path. Defaults to <output>/summary.json.",
    )
    parser.add_argument(
        "--report-output",
        default=None,
        help="report.md output path. Defaults to <output>/report.md.",
    )
    parser.add_argument(
        "--diff-json-output",
        default=None,
        help="findings-diff.json output path. Defaults to <output>/findings-diff.json.",
    )
    parser.add_argument(
        "--diff-md-output",
        default=None,
        help="findings-diff.md output path. Defaults to <output>/findings-diff.md.",
    )
    parser.add_argument(
        "--campaign-dir",
        default=None,
        help="Optional campaign directory to aggregate analyzer summaries across runs.",
    )
    parser.add_argument(
        "--campaign-summary-output",
        default=None,
        help="Optional campaign summary JSON path.",
    )
    parser.add_argument(
        "--campaign-report-output",
        default=None,
        help="Optional campaign summary markdown path.",
    )
    return parser.parse_args(argv)


def _default_run_dir() -> Path | None:
    value = sys.modules[__name__].__dict__.get("_RUN_DIR_OVERRIDE")
    if value:
        return Path(value)
    env_value = None
    for key in ("NAILS_FORENSICS_RUN_DIR",):
        env_value = env_value or __import__("os").environ.get(key)
    return Path(env_value).resolve() if env_value else None


def _env_stage_mappings() -> dict[str, Path]:
    import os

    mapping = {}
    env_map = {
        "baseline": "NAILS_FORENSICS_BASELINE_DIR",
        "active": "NAILS_FORENSICS_ACTIVE_DIR",
        "post-standard": "NAILS_FORENSICS_POST_STANDARD_DIR",
        "post-emergency": "NAILS_FORENSICS_POST_EMERGENCY_DIR",
    }
    for name, key in env_map.items():
        value = os.environ.get(key)
        if value:
            mapping[name] = Path(value).resolve()
    return mapping


def _parse_stage_dir(raw: str) -> tuple[str, Path]:
    if "=" not in raw:
        raise CliError(f"Invalid --stage-dir value '{raw}', expected NAME=PATH")
    name, value = raw.split("=", 1)
    name = name.strip()
    if not name:
        raise CliError(f"Invalid --stage-dir value '{raw}', empty stage name")
    return name, Path(value).expanduser().resolve()


def resolve_inputs(args: argparse.Namespace) -> dict[str, Any]:
    import os

    run_dir = (
        Path(args.run_dir).expanduser().resolve()
        if args.run_dir
        else _default_run_dir()
    )
    if run_dir is None:
        raise CliError("--run-dir is required when NAILS_FORENSICS_RUN_DIR is not set")

    stage_dirs = _env_stage_mappings()
    for name, path in [_parse_stage_dir(value) for value in args.stage_dir]:
        stage_dirs[name] = path
    if not stage_dirs:
        for name in ("baseline", "active", "post-standard", "post-emergency"):
            candidate = run_dir / name
            if candidate.exists():
                stage_dirs[name] = candidate

    selected_stages = args.stage or [
        stage
        for stage in stage_dirs
        if stage != "baseline" and stage_dirs[stage].exists()
    ]
    baseline_dir = (
        Path(args.baseline_dir).expanduser().resolve()
        if args.baseline_dir
        else stage_dirs.get("baseline")
    )

    output_dir = (
        Path(args.output).expanduser().resolve()
        if args.output
        else ((run_dir / "compare") if run_dir else Path("compare").resolve())
    )
    scratch_dir = (
        Path(args.scratch_dir).expanduser().resolve()
        if args.scratch_dir
        else (output_dir / "scratch")
    )

    manifest_path = Path(args.manifest).expanduser().resolve()
    default_allowlist = SCRIPT_DIR.parent / "fixtures" / "allowlists" / "default.json"
    allowlist_paths = [
        Path(value).expanduser().resolve() for value in args.allowlist
    ] or [default_allowlist]
    scenario = load_optional_json(run_dir / "scenario.json")
    run_manifest = load_optional_json(run_dir / "run-manifest.json")
    canaries = load_optional_json(run_dir / "canaries.json")

    profile = (
        args.profile
        or (scenario or {}).get("profileId")
        or os.environ.get("NAILS_FORENSICS_PROFILE")
        or "default"
    )
    scenario_id = (
        args.scenario_id
        or (scenario or {}).get("scenarioId")
        or os.environ.get("NAILS_FORENSICS_SCENARIO_ID")
        or "default"
    )
    run_id = (
        args.run_id
        or (scenario or {}).get("runId")
        or os.environ.get("NAILS_FORENSICS_RUN_ID")
        or run_dir.name
    )
    iteration = (
        args.iteration
        if args.iteration is not None
        else (scenario or {}).get("iteration")
    )

    return {
        "run_dir": run_dir,
        "stage_dirs": stage_dirs,
        "selected_stages": selected_stages,
        "baseline_dir": baseline_dir,
        "output_dir": output_dir,
        "scratch_dir": scratch_dir,
        "manifest_path": manifest_path,
        "allowlist_paths": allowlist_paths,
        "scenario": scenario,
        "run_manifest": run_manifest,
        "canaries": canaries,
        "profile": profile,
        "scenario_id": scenario_id,
        "run_id": run_id,
        "iteration": iteration,
        "summary_output": Path(args.summary_output).expanduser().resolve()
        if args.summary_output
        else output_dir / "summary.json",
        "report_output": Path(args.report_output).expanduser().resolve()
        if args.report_output
        else output_dir / "report.md",
        "diff_json_output": Path(args.diff_json_output).expanduser().resolve()
        if args.diff_json_output
        else output_dir / "findings-diff.json",
        "diff_md_output": Path(args.diff_md_output).expanduser().resolve()
        if args.diff_md_output
        else output_dir / "findings-diff.md",
        "campaign_dir": Path(args.campaign_dir).expanduser().resolve()
        if args.campaign_dir
        else None,
        "campaign_summary_output": Path(args.campaign_summary_output)
        .expanduser()
        .resolve()
        if args.campaign_summary_output
        else None,
        "campaign_report_output": Path(args.campaign_report_output)
        .expanduser()
        .resolve()
        if args.campaign_report_output
        else None,
    }


def instantiate_analyzers(manifest: dict[str, Any]) -> list[Analyzer]:
    analyzers: list[Analyzer] = []
    for entry in manifest["analyzers"]:
        if not entry.get("enabled", True):
            continue
        module = importlib.import_module(entry["module"])
        analyzer_cls = getattr(module, entry["class"])
        analyzers.append(analyzer_cls(entry.get("options", {})))
    return analyzers


def build_findings_diff(
    results: list[dict[str, Any]], stages: list[str]
) -> dict[str, Any]:
    stage_findings: dict[str, list[dict[str, Any]]] = {stage: [] for stage in stages}
    stage_fingerprints: dict[str, set[str]] = {stage: set() for stage in stages}
    for result in results:
        for finding in result["findings"]:
            proxy = type(
                "_FindingProxy",
                (),
                {
                    "id": finding["id"],
                    "title": finding["title"],
                    "classification": finding["classification"],
                    "evidence": finding["evidence"],
                },
            )
            fingerprint = finding_fingerprint(
                result["stage"], result["analyzer"], proxy
            )
            stage_fingerprints[result["stage"]].add(fingerprint)
            stage_findings[result["stage"]].append(
                {
                    "fingerprint": fingerprint,
                    "analyzer": result["analyzer"],
                    "id": finding["id"],
                    "title": finding["title"],
                    "severity": finding["severity"],
                }
            )

    comparisons = []
    ordered = [stage for stage in stages if stage in stage_fingerprints]
    for index, left in enumerate(ordered):
        for right in ordered[index + 1 :]:
            left_set = stage_fingerprints[left]
            right_set = stage_fingerprints[right]
            comparisons.append(
                {
                    "left": left,
                    "right": right,
                    "counts": {
                        "common": len(left_set & right_set),
                        "onlyLeft": len(left_set - right_set),
                        "onlyRight": len(right_set - left_set),
                    },
                    "onlyLeft": sorted(left_set - right_set),
                    "onlyRight": sorted(right_set - left_set),
                }
            )

    return {
        "contractVersion": CONTRACT_VERSION,
        "stages": {
            stage: {
                "findingCount": len(stage_findings[stage]),
                "findings": stage_findings[stage],
            }
            for stage in ordered
        },
        "comparisons": comparisons,
    }


def render_findings_diff_markdown(diff_summary: dict[str, Any]) -> str:
    lines = [
        "# Analyzer Findings Diff",
        "",
        "| Stage | Findings |",
        "|---|---:|",
    ]
    for stage, payload in diff_summary["stages"].items():
        lines.append(f"| `{stage}` | {payload['findingCount']} |")
    lines.extend(
        [
            "",
            "## Comparisons",
            "",
            "| Comparison | Common | Left only | Right only |",
            "|---|---:|---:|---:|",
        ]
    )
    for comparison in diff_summary["comparisons"]:
        counts = comparison["counts"]
        lines.append(
            f"| `{comparison['left']}` vs `{comparison['right']}` | {counts['common']} | {counts['onlyLeft']} | {counts['onlyRight']} |"
        )
    return "\n".join(lines) + "\n"


def _schema_path(name: str) -> Path:
    return SCRIPT_DIR.parent / "fixtures" / "schemas" / name


def validate_outputs(
    manifest: dict[str, Any],
    results: list[dict[str, Any]],
    diff_summary: dict[str, Any],
    summary: dict[str, Any],
    campaign_summary: dict[str, Any] | None = None,
) -> None:
    validate_with_schema_path(_schema_path("manifest.json"), manifest)
    for result in results:
        validate_with_schema_path(_schema_path("analyzer-result.json"), result)
    validate_with_schema_path(_schema_path("findings-diff.json"), diff_summary)
    validate_with_schema_path(_schema_path("summary.json"), summary)
    if campaign_summary is not None:
        validate_with_schema_path(
            _schema_path("campaign-summary.json"), campaign_summary
        )


def main(argv: list[str]) -> int:
    try:
        args = parse_args(argv)
        resolved = resolve_inputs(args)
        resolved["output_dir"].mkdir(parents=True, exist_ok=True)
        resolved["scratch_dir"].mkdir(parents=True, exist_ok=True)

        manifest = load_manifest(resolved["manifest_path"])
        allowlist = load_allowlist(resolved["allowlist_paths"], resolved["profile"])
        ctx = AnalyzerContext(
            run_dir=resolved["run_dir"],
            output_dir=resolved["output_dir"],
            scratch_dir=resolved["scratch_dir"],
            baseline_dir=resolved["baseline_dir"],
            stages=resolved["stage_dirs"],
            profile=resolved["profile"],
            scenario_id=resolved["scenario_id"],
            run_id=resolved["run_id"],
            iteration=resolved["iteration"],
            manifest=manifest,
            scenario=resolved["scenario"],
            canaries=resolved["canaries"],
            allowlist=allowlist,
        )
        analyzers = instantiate_analyzers(manifest)
        results: list[dict[str, Any]] = []

        for stage_name in resolved["selected_stages"]:
            stage_dir = resolved["stage_dirs"].get(stage_name)
            if stage_dir is None or not stage_dir.exists():
                raise CliError(f"Selected stage directory missing: {stage_name}")
            for analyzer in analyzers:
                try:
                    result = analyzer.analyze(ctx, stage_name, stage_dir)
                except Exception as exc:  # pragma: no cover - defensive path
                    result = analyzer.error_result(stage_name, str(exc))
                payload = result.to_dict()
                results.append(payload)
                write_json(
                    resolved["output_dir"]
                    / "analyzers"
                    / stage_name
                    / f"{analyzer.analyzer_id}.json",
                    payload,
                )

        diff_summary = build_findings_diff(results, resolved["selected_stages"])
        write_json(resolved["diff_json_output"], diff_summary)
        write_text(
            resolved["diff_md_output"], render_findings_diff_markdown(diff_summary)
        )

        summary = build_summary(
            run_id=resolved["run_id"],
            profile=resolved["profile"],
            scenario_id=resolved["scenario_id"],
            iteration=resolved["iteration"],
            run_dir=str(resolved["run_dir"]),
            output_dir=str(resolved["output_dir"]),
            stages=resolved["selected_stages"],
            manifest_path=str(resolved["manifest_path"]),
            allowlist_paths=[str(path) for path in resolved["allowlist_paths"]],
            results=results,
        )
        validate_outputs(manifest, results, diff_summary, summary)
        write_json(resolved["summary_output"], summary)
        report_template = (
            SCRIPT_DIR.parent / "fixtures" / "templates" / "report.md.tmpl"
        )
        report = render_report(report_template, summary, results, diff_summary)
        write_text(resolved["report_output"], report)

        if resolved["campaign_dir"]:
            campaign_runs = collect_run_summaries(resolved["campaign_dir"])
            campaign_summary = build_campaign_summary(
                resolved["campaign_dir"], campaign_runs
            )
            validate_outputs(
                manifest,
                results,
                diff_summary,
                summary,
                campaign_summary,
            )
            campaign_summary_path = (
                resolved["campaign_summary_output"]
                or resolved["campaign_dir"] / "campaign-summary.json"
            )
            campaign_report_path = (
                resolved["campaign_report_output"]
                or resolved["campaign_dir"] / "campaign-summary.md"
            )
            write_json(campaign_summary_path, campaign_summary)
            write_text(campaign_report_path, render_campaign_markdown(campaign_summary))

        return 0
    except (CliError, AnalyzerError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
