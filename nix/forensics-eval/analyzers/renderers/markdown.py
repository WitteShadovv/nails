#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
from typing import Any


def _format_stage_table(summary: dict[str, Any]) -> str:
    lines = [
        "| Stage | Status | Findings | Results |",
        "|---|---|---:|---:|",
    ]
    for stage in summary["stages"]:
        lines.append(
            f"| `{stage['stage']}` | `{stage['status']}` | {stage['findingCount']} | {stage['resultCount']} |"
        )
    return "\n".join(lines)


def _format_findings(results: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for result in results:
        if not result["findings"]:
            continue
        lines.append(f"### {result['stage']} / {result['analyzer']}")
        for finding in result["findings"]:
            lines.append(
                f"- `{finding['severity']}` `{finding['id']}`: {finding['title']}"
            )
            for evidence in finding["evidence"][:5]:
                detail = evidence["detail"]
                path = evidence["path"]
                snippet = evidence.get("snippet")
                if snippet:
                    lines.append(f"  evidence: `{path}` - {detail} - `{snippet}`")
                else:
                    lines.append(f"  evidence: `{path}` - {detail}")
        lines.append("")
    return "\n".join(lines).strip() or "No preserved findings."


def render_report(
    template_path: Path,
    summary: dict[str, Any],
    results: list[dict[str, Any]],
    diff_summary: dict[str, Any],
) -> str:
    template = template_path.read_text(encoding="utf-8")
    metadata = "\n".join(
        [
            f"- Run: `{summary['runId']}`",
            f"- Profile: `{summary['profileId']}`",
            f"- Scenario: `{summary['scenarioId']}`",
            f"- Iteration: `{summary['iteration']}`",
            f"- Status: `{summary['status']}`",
            f"- Manifest: `{summary['manifest']}`",
        ]
    )
    overview = _format_stage_table(summary)
    findings = _format_findings(results)
    diffs = [
        "| Comparison | Common | Left only | Right only |",
        "|---|---:|---:|---:|",
    ]
    for comparison in diff_summary["comparisons"]:
        counts = comparison["counts"]
        diffs.append(
            f"| `{comparison['left']}` vs `{comparison['right']}` | {counts['common']} | {counts['onlyLeft']} | {counts['onlyRight']} |"
        )
    diff_section = "\n".join(diffs)
    analyzer_lines = []
    for stage in summary["stages"]:
        for analyzer in stage["analyzers"]:
            analyzer_lines.append(
                f"- `{stage['stage']}` / `{analyzer['analyzer']}`: `{analyzer['status']}` with {analyzer['findingCount']} findings"
            )
    analyzers = "\n".join(analyzer_lines) or "- No analyzer results."
    assumptions = "\n".join(
        [
            "- Stage evidence is treated as read-only input.",
            "- Findings are preserved only when backed by concrete file/path evidence.",
            "- Baseline-equivalent and allowlisted matches are suppressed from preserved findings.",
        ]
    )
    return (
        template.replace("{{TITLE}}", f"Forensics Analyzer Report: {summary['runId']}")
        .replace("{{METADATA}}", metadata)
        .replace("{{OVERVIEW_TABLE}}", overview)
        .replace("{{FINDINGS}}", findings)
        .replace("{{DIFFS}}", diff_section)
        .replace("{{ANALYZERS}}", analyzers)
        .replace("{{ASSUMPTIONS}}", assumptions)
    )
