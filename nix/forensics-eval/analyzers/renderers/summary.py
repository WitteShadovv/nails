#!/usr/bin/env python3

from __future__ import annotations

from typing import Any

from framework import CONTRACT_VERSION, finding_fingerprint


POSITIVE_CONTROL_STAGE = "active"
REQUIRED_POSITIVE_CONTROL_ANALYZERS = (
    "path_delta",
    "canary_scan",
    "indicator_scan",
)


def _stage_expectation(stage: str) -> dict[str, Any]:
    if stage == POSITIVE_CONTROL_STAGE:
        return {
            "kind": "positive-control",
            "expectedFindings": True,
            "notes": "Active stage is intentionally analyzed as a positive control and is expected to contain findings.",
        }
    if stage == "baseline":
        return {
            "kind": "baseline",
            "expectedFindings": False,
            "notes": "Baseline is analyzed only as a comparison reference and should not be mislabeled as a post-cleanup target.",
        }
    return {
        "kind": "post-cleanup",
        "expectedFindings": False,
        "notes": "Post-cleanup stages are expected to reduce observable leak evidence relative to the active positive control.",
    }


def _positive_control_contract(
    stage_results: list[dict[str, Any]],
    manifest_analyzers: list[str],
    optional_analyzers: dict[str, bool],
) -> dict[str, Any]:
    result_by_analyzer = {result["analyzer"]: result for result in stage_results}
    required_analyzers = [
        analyzer
        for analyzer in REQUIRED_POSITIVE_CONTROL_ANALYZERS
        if analyzer in manifest_analyzers
        and not optional_analyzers.get(analyzer, False)
    ]
    required_failures = []
    required_analyzer_results = []
    for analyzer in required_analyzers:
        result = result_by_analyzer.get(analyzer)
        if result is None:
            required_failures.append(
                {
                    "analyzer": analyzer,
                    "status": "missing",
                    "reason": "required analyzer result is missing",
                    "message": f"required analyzer {analyzer} produced no result",
                }
            )
            required_analyzer_results.append(
                {
                    "analyzer": analyzer,
                    "status": "missing",
                    "findingCount": 0,
                    "allowlisted": 0,
                    "satisfied": False,
                    "reason": "required analyzer result is missing",
                }
            )
            continue

        finding_count = len(result["findings"])
        allowlisted = result["metrics"].get("allowlisted", 0)
        failure_reason = None
        if result["status"] == "finding" and finding_count > 0:
            required_analyzer_results.append(
                {
                    "analyzer": analyzer,
                    "status": result["status"],
                    "findingCount": finding_count,
                    "allowlisted": allowlisted,
                    "satisfied": True,
                    "reason": None,
                }
            )
            continue

        if result["status"] in {"skipped", "error"}:
            failure_reason = (
                result["summary"].get("headline")
                or result["summary"].get("reason")
                or result["summary"].get("error")
                or f"analyzer ended as {result['status']}"
            )
            failure_message = (
                f"required analyzer {analyzer} ended as {result['status']}: "
                f"{failure_reason}"
            )
        elif allowlisted > 0:
            failure_reason = f"all findings were allowlisted ({allowlisted} suppressed)"
            failure_message = (
                f"required analyzer {analyzer} produced only allowlisted findings"
            )
        else:
            failure_reason = "no preserved non-allowlisted findings"
            failure_message = (
                f"required analyzer {analyzer} produced no preserved "
                f"non-allowlisted findings"
            )

        required_failures.append(
            {
                "analyzer": analyzer,
                "status": result["status"],
                "reason": failure_reason,
                "message": failure_message,
            }
        )
        required_analyzer_results.append(
            {
                "analyzer": analyzer,
                "status": result["status"],
                "findingCount": finding_count,
                "allowlisted": allowlisted,
                "satisfied": False,
                "reason": failure_reason,
            }
        )

    preserved_results = [
        result
        for result in stage_results
        if result["findings"] and not optional_analyzers.get(result["analyzer"], False)
    ]
    allowlist_masked = [
        {
            "analyzer": result["analyzer"],
            "allowlisted": result["metrics"].get("allowlisted", 0),
        }
        for result in stage_results
        if not optional_analyzers.get(result["analyzer"], False)
        and result["status"] == "clean"
        and result["metrics"].get("allowlisted", 0) > 0
    ]
    contract_satisfied = bool(required_analyzers) and not required_failures
    failures: list[str] = []
    for failure in required_failures:
        failures.append(failure["message"])
    if not required_analyzers:
        failures.append("positive-control stage has no required analyzers configured")

    return {
        "enforced": True,
        "requiredAnalyzers": required_analyzers,
        "satisfied": contract_satisfied,
        "requiredAnalyzerResults": required_analyzer_results,
        "preservedFindingAnalyzers": sorted(
            result["analyzer"] for result in preserved_results
        ),
        "allowlistMaskedAnalyzers": allowlist_masked,
        "requiredAnalyzerFailures": required_failures,
        "failures": failures,
    }


def build_summary(
    *,
    run_id: str,
    profile: str,
    scenario_id: str,
    iteration: int | None,
    run_dir: str,
    output_dir: str,
    stages: list[str],
    manifest: dict[str, Any],
    manifest_path: str,
    allowlist_paths: list[str],
    results: list[dict[str, Any]],
) -> dict[str, Any]:
    stage_index: dict[str, list[dict[str, Any]]] = {stage: [] for stage in stages}
    for result in results:
        stage_index.setdefault(result["stage"], []).append(result)

    manifest_analyzers = [
        entry["id"]
        for entry in manifest.get("analyzers", [])
        if entry.get("enabled", True)
    ]
    optional_analyzers = {
        entry["id"]: bool(entry.get("optional", False))
        for entry in manifest.get("analyzers", [])
        if entry.get("enabled", True)
    }

    stage_summaries = []
    totals = {
        "findings": 0,
        "errors": 0,
        "skipped": 0,
        "clean": 0,
        "analyzers": len(results),
    }
    contract_failures: list[dict[str, Any]] = []
    analyzer_coverage = {
        "expectedPerStage": len(manifest_analyzers),
        "stageCount": len(stages),
        "resultCount": len(results),
        "finding": 0,
        "clean": 0,
        "skipped": 0,
        "error": 0,
        "ran": 0,
        "analyzers": [],
    }
    analyzer_totals = {
        analyzer: {
            "analyzer": analyzer,
            "optional": optional_analyzers.get(analyzer, False),
            "finding": 0,
            "clean": 0,
            "skipped": 0,
            "error": 0,
            "ran": 0,
        }
        for analyzer in manifest_analyzers
    }
    for stage in stages:
        stage_results = stage_index.get(stage, [])
        preserved_findings = sum(len(result["findings"]) for result in stage_results)
        statuses = [result["status"] for result in stage_results]
        expectation = _stage_expectation(stage)
        positive_control = None
        if expectation["kind"] == "positive-control":
            positive_control = _positive_control_contract(
                stage_results, manifest_analyzers, optional_analyzers
            )
            if not positive_control["satisfied"]:
                contract_failures.append(
                    {
                        "stage": stage,
                        "kind": "positive-control",
                        "failures": positive_control["failures"],
                    }
                )
        for status in statuses:
            if status == "finding":
                totals["findings"] += 1
            elif status == "error":
                totals["errors"] += 1
            elif status == "skipped":
                totals["skipped"] += 1
            elif status == "clean":
                totals["clean"] += 1
            analyzer_coverage[status] += 1
            if status != "skipped":
                analyzer_coverage["ran"] += 1
        for result in stage_results:
            analyzer_totals.setdefault(
                result["analyzer"],
                {
                    "analyzer": result["analyzer"],
                    "optional": optional_analyzers.get(result["analyzer"], False),
                    "finding": 0,
                    "clean": 0,
                    "skipped": 0,
                    "error": 0,
                    "ran": 0,
                },
            )
            analyzer_totals[result["analyzer"]][result["status"]] += 1
            if result["status"] != "skipped":
                analyzer_totals[result["analyzer"]]["ran"] += 1

        stage_analyzers = [
            {
                "analyzer": result["analyzer"],
                "status": result["status"],
                "findingCount": len(result["findings"]),
                "allowlisted": result["metrics"].get("allowlisted", 0),
                "optional": optional_analyzers.get(result["analyzer"], False),
                "summaryHeadline": result["summary"].get("headline"),
                "ran": result["status"] != "skipped",
            }
            for result in stage_results
        ]
        stage_summary = {
            "stage": stage,
            "expectation": expectation,
            "resultCount": len(stage_results),
            "status": (
                "error"
                if "error" in statuses
                else "finding"
                if "finding" in statuses
                else "clean"
                if stage_results and any(status == "clean" for status in statuses)
                else "skipped"
            ),
            "findingCount": preserved_findings,
            "coverage": {
                "expected": len(manifest_analyzers),
                "ran": sum(
                    1 for result in stage_results if result["status"] != "skipped"
                ),
                "finding": sum(
                    1 for result in stage_results if result["status"] == "finding"
                ),
                "clean": sum(
                    1 for result in stage_results if result["status"] == "clean"
                ),
                "skipped": sum(
                    1 for result in stage_results if result["status"] == "skipped"
                ),
                "error": sum(
                    1 for result in stage_results if result["status"] == "error"
                ),
            },
            "analyzers": stage_analyzers,
        }
        if positive_control is not None:
            stage_summary["positiveControlContract"] = positive_control
        stage_summaries.append(stage_summary)

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
    elif contract_failures:
        overall_status = "error"
    elif any(summary["findingCount"] for summary in stage_summaries):
        overall_status = "finding"
    elif stage_summaries and all(
        summary["status"] == "skipped" for summary in stage_summaries
    ):
        overall_status = "skipped"

    analyzer_coverage["analyzers"] = [
        analyzer_totals[name] for name in sorted(analyzer_totals)
    ]

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
        "contractFailures": contract_failures,
        "stageCount": len(stages),
        "totals": totals,
        "analyzerCoverage": analyzer_coverage,
        "stages": stage_summaries,
        "findings": finding_index,
    }
