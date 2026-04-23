#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
from typing import Any

from framework import CONTRACT_VERSION, load_json


def collect_run_summaries(root: Path) -> list[dict[str, Any]]:
    summaries = []
    for path in sorted(root.rglob("summary.json")):
        if path.parent.name not in {"compare", "analysis", "analyzers"}:
            continue
        summaries.append(load_json(path))
    return summaries


def build_campaign_summary(
    campaign_dir: Path, run_summaries: list[dict[str, Any]]
) -> dict[str, Any]:
    stage_totals: dict[str, dict[str, Any]] = {}
    analyzer_totals: dict[str, dict[str, Any]] = {}
    for summary in run_summaries:
        for stage in summary.get("stages", []):
            target = stage_totals.setdefault(
                stage["stage"],
                {
                    "stage": stage["stage"],
                    "runs": 0,
                    "findingRuns": 0,
                    "cleanRuns": 0,
                    "skippedRuns": 0,
                    "errorRuns": 0,
                    "findingCount": 0,
                },
            )
            target["runs"] += 1
            target["findingCount"] += stage.get("findingCount", 0)
            status_key = f"{stage.get('status', 'skipped')}Runs"
            if status_key in target:
                target[status_key] += 1
        for analyzer in summary.get("analyzerCoverage", {}).get("analyzers", []):
            target = analyzer_totals.setdefault(
                analyzer["analyzer"],
                {
                    "analyzer": analyzer["analyzer"],
                    "optional": bool(analyzer.get("optional", False)),
                    "finding": 0,
                    "clean": 0,
                    "skipped": 0,
                    "error": 0,
                    "ran": 0,
                },
            )
            for key in ("finding", "clean", "skipped", "error", "ran"):
                target[key] += int(analyzer.get(key, 0))
    return {
        "contractVersion": CONTRACT_VERSION,
        "campaignDir": str(campaign_dir),
        "runCount": len(run_summaries),
        "status": (
            "error"
            if any(summary["status"] == "error" for summary in run_summaries)
            else "finding"
            if any(summary["status"] == "finding" for summary in run_summaries)
            else "clean"
        ),
        "totals": {
            "findings": sum(summary["totals"]["findings"] for summary in run_summaries),
            "errors": sum(summary["totals"]["errors"] for summary in run_summaries),
            "skipped": sum(summary["totals"]["skipped"] for summary in run_summaries),
        },
        "stageTotals": [stage_totals[name] for name in sorted(stage_totals)],
        "analyzerTotals": [analyzer_totals[name] for name in sorted(analyzer_totals)],
        "runs": [
            {
                "runId": summary["runId"],
                "profileId": summary["profileId"],
                "scenarioId": summary["scenarioId"],
                "iteration": summary["iteration"],
                "status": summary["status"],
                "findingResults": summary["totals"]["findings"],
            }
            for summary in run_summaries
        ],
    }


def render_campaign_markdown(summary: dict[str, Any]) -> str:
    lines = [
        f"# Forensics Analyzer Campaign Summary",
        "",
        f"- Campaign dir: `{summary['campaignDir']}`",
        f"- Runs: `{summary['runCount']}`",
        f"- Status: `{summary['status']}`",
        "",
        "| Run | Profile | Scenario | Iteration | Status | Finding results |",
        "|---|---|---|---:|---|---:|",
    ]
    for run in summary["runs"]:
        lines.append(
            f"| `{run['runId']}` | `{run['profileId']}` | `{run['scenarioId']}` | {run['iteration']} | `{run['status']}` | {run['findingResults']} |"
        )
    if summary.get("stageTotals"):
        lines.extend(
            [
                "",
                "## Stage coverage",
                "",
                "| Stage | Runs | Finding runs | Clean runs | Skipped runs | Error runs | Findings |",
                "|---|---:|---:|---:|---:|---:|---:|",
            ]
        )
        for stage in summary["stageTotals"]:
            lines.append(
                f"| `{stage['stage']}` | {stage['runs']} | {stage['findingRuns']} | {stage['cleanRuns']} | {stage['skippedRuns']} | {stage['errorRuns']} | {stage['findingCount']} |"
            )
    if summary.get("analyzerTotals"):
        lines.extend(
            [
                "",
                "## Analyzer coverage",
                "",
                "| Analyzer | Optional | Ran | Findings | Clean | Skipped | Errors |",
                "|---|---|---:|---:|---:|---:|---:|",
            ]
        )
        for analyzer in summary["analyzerTotals"]:
            lines.append(
                f"| `{analyzer['analyzer']}` | `{analyzer['optional']}` | {analyzer['ran']} | {analyzer['finding']} | {analyzer['clean']} | {analyzer['skipped']} | {analyzer['error']} |"
            )
    return "\n".join(lines) + "\n"
