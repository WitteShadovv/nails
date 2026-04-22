#!/usr/bin/env python3

from __future__ import annotations

from typing import Any

from framework import CONTRACT_VERSION, finding_fingerprint


def build_summary(
    *,
    run_id: str,
    profile: str,
    scenario_id: str,
    iteration: int | None,
    run_dir: str,
    output_dir: str,
    stages: list[str],
    manifest_path: str,
    allowlist_paths: list[str],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    stage_index: dict[str, list[dict[str, Any]]] = {stage: [] for stage in stages}
    for result in results:
        stage_index.setdefault(result["stage"], []).append(result)

    stage_summaries = []
    totals = {
        "findings": 0,
        "errors": 0,
        "skipped": 0,
        "clean": 0,
        "analyzers": len(results),
    }
    for stage in stages:
        stage_results = stage_index.get(stage, [])
        preserved_findings = sum(len(result["findings"]) for result in stage_results)
        statuses = [result["status"] for result in stage_results]
        for status in statuses:
            if status == "finding":
                totals["findings"] += 1
            elif status == "error":
                totals["errors"] += 1
            elif status == "skipped":
                totals["skipped"] += 1
            elif status == "clean":
                totals["clean"] += 1
        stage_summaries.append(
            {
                "stage": stage,
                "resultCount": len(stage_results),
                "status": (
                    "error"
                    if "error" in statuses
                    else "finding"
                    if "finding" in statuses
                    else "clean"
                    if stage_results and all(status == "clean" for status in statuses)
                    else "skipped"
                ),
                "findingCount": preserved_findings,
                "analyzers": [
                    {
                        "analyzer": result["analyzer"],
                        "status": result["status"],
                        "findingCount": len(result["findings"]),
                    }
                    for result in stage_results
                ],
            }
        )

    finding_index = []
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
            finding_index.append(
                {
                    "stage": result["stage"],
                    "analyzer": result["analyzer"],
                    "id": finding["id"],
                    "title": finding["title"],
                    "severity": finding["severity"],
                    "fingerprint": finding_fingerprint(
                        result["stage"], result["analyzer"], proxy
                    ),
                }
            )

    overall_status = "clean"
    if totals["errors"]:
        overall_status = "error"
    elif any(summary["findingCount"] for summary in stage_summaries):
        overall_status = "finding"
    elif stage_summaries and all(
        summary["status"] == "skipped" for summary in stage_summaries
    ):
        overall_status = "skipped"

    return {
        "contractVersion": CONTRACT_VERSION,
        "runId": run_id,
        "profileId": profile,
        "scenarioId": scenario_id,
        "iteration": iteration,
        "runDir": run_dir,
        "outputDir": output_dir,
        "manifest": manifest_path,
        "allowlists": allowlist_paths,
        "status": overall_status,
        "stageCount": len(stages),
        "totals": totals,
        "stages": stage_summaries,
        "findings": finding_index,
    }
