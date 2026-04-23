#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
from typing import Any


def _format_stage_table(summary: dict[str, Any]) -> str:
    lines = [
        "| Stage | Expectation | Status | Findings | Contract | Ran | Skipped |",
        "|---|---|---|---:|---|---:|---:|",
    ]
    for stage in summary["stages"]:
        expectation = stage.get("expectation", {})
        expectation_label = expectation.get("kind", "n/a")
        if expectation.get("expectedFindings"):
            expectation_label += " (expected findings)"
        contract = stage.get("positiveControlContract")
        contract_label = (
            "enforced-pass"
            if contract and contract.get("satisfied")
            else "ENFORCED-FAIL"
            if contract
            else "n/a"
        )
        lines.append(
            f"| `{stage['stage']}` | {expectation_label} | `{stage['status']}` | {stage['findingCount']} | {contract_label} | {stage.get('coverage', {}).get('ran', 0)} | {stage.get('coverage', {}).get('skipped', 0)} |"
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
    contract_lines = []
    contract_failures = summary.get("contractFailures", [])
    if contract_failures:
        contract_lines.append("## Contract Failures")
        contract_lines.append("")
        contract_lines.append(
            "These failures are ENFORCED and make the analyzer run fail."
        )
        contract_lines.append("")
        for failure in contract_failures:
            contract_lines.append(
                f"- `{failure['stage']}` `{failure['kind']}`: "
                + "; ".join(failure.get("failures", []))
            )
        contract_lines.append("")
    contract_section = "\n".join(contract_lines).strip()
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
        expectation = stage.get("expectation", {})
        analyzer_lines.append(
            f"### {stage['stage']} ({expectation.get('kind', 'n/a')})"
        )
        notes = expectation.get("notes")
        if notes:
            analyzer_lines.append(f"- Expectation: {notes}")
        positive_control = stage.get("positiveControlContract")
        if positive_control:
            analyzer_lines.append(
                "- Positive-control contract: "
                + (
                    "ENFORCED PASS"
                    if positive_control.get("satisfied")
                    else "ENFORCED FAIL"
                )
            )
            if positive_control.get("requiredAnalyzers"):
                analyzer_lines.append(
                    "  - Required analyzers: "
                    + ", ".join(
                        f"`{name}`" for name in positive_control["requiredAnalyzers"]
                    )
                )
            for analyzer_result in positive_control.get("requiredAnalyzerResults", []):
                line = (
                    f"  - Required `{analyzer_result['analyzer']}`: "
                    f"`{analyzer_result['status']}` with "
                    f"{analyzer_result['findingCount']} preserved findings"
                )
                if analyzer_result.get("allowlisted"):
                    line += (
                        f" and {analyzer_result['allowlisted']} allowlisted findings"
                    )
                if analyzer_result.get("satisfied"):
                    line += " (satisfied)"
                elif analyzer_result.get("reason"):
                    line += f" ({analyzer_result['reason']})"
                analyzer_lines.append(line)
            for message in positive_control.get("failures", []):
                analyzer_lines.append(f"  - Failure: {message}")
        for analyzer in stage["analyzers"]:
            line = (
                f"- `{analyzer['analyzer']}`: `{analyzer['status']}` with "
                f"{analyzer['findingCount']} findings"
            )
            if analyzer.get("allowlisted"):
                line += f" ({analyzer['allowlisted']} allowlisted)"
            analyzer_lines.append(line)
            headline = analyzer.get("summaryHeadline")
            if headline:
                analyzer_lines.append(f"  - {headline}")
        analyzer_lines.append("")
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
        .replace("{{CONTRACTS}}", contract_section or "No enforced contract failures.")
        .replace("{{FINDINGS}}", findings)
        .replace("{{DIFFS}}", diff_section)
        .replace("{{ANALYZERS}}", analyzers)
        .replace("{{ASSUMPTIONS}}", assumptions)
    )
