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
    return "\n".join(lines) + "\n"
