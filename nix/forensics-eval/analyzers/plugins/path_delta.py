#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path

from framework import Analyzer, AnalyzerContext, Evidence, Finding, file_inventory


class PathDeltaAnalyzer(Analyzer):
    analyzer_id = "path_delta"

    def analyze(self, ctx: AnalyzerContext, stage_name: str, stage_dir: Path):
        if ctx.baseline_dir is None or not ctx.baseline_dir.exists():
            return self.skipped_result(stage_name, "baseline directory unavailable")

        baseline = file_inventory(ctx.baseline_dir)
        current = file_inventory(stage_dir)
        added = sorted(set(current) - set(baseline))
        removed = sorted(set(baseline) - set(current))
        changed = sorted(
            path
            for path in set(current) & set(baseline)
            if current[path] != baseline[path]
        )
        findings: list[Finding] = []
        allowlisted = 0

        for path in added:
            entry = current[path]
            finding = Finding(
                id="added-path",
                title="Unexpected path added relative to baseline",
                severity="medium",
                classification="new-relative-to-baseline",
                description=f"{path} exists in {stage_name} but not in baseline.",
                evidence=[
                    Evidence(
                        type=entry["type"],
                        path=path,
                        detail="present only in target stage",
                        sha256=entry.get("sha256"),
                        size=entry.get("size"),
                    )
                ],
            )
            if ctx.allowlist.suppresses(self.analyzer_id, finding):
                allowlisted += 1
                continue
            findings.append(finding)

        for path in removed:
            entry = baseline[path]
            finding = Finding(
                id="removed-path",
                title="Baseline path missing in target stage",
                severity="low",
                classification="removed-relative-to-baseline",
                description=f"{path} exists in baseline but not in {stage_name}.",
                evidence=[
                    Evidence(
                        type=entry["type"],
                        path=path,
                        detail="present only in baseline stage",
                        sha256=entry.get("sha256"),
                        size=entry.get("size"),
                    )
                ],
            )
            if ctx.allowlist.suppresses(self.analyzer_id, finding):
                allowlisted += 1
                continue
            findings.append(finding)

        for path in changed:
            before = baseline[path]
            after = current[path]
            finding = Finding(
                id="changed-path",
                title="Path contents changed relative to baseline",
                severity="medium",
                classification="changed-relative-to-baseline",
                description=f"{path} differs between baseline and {stage_name}.",
                evidence=[
                    Evidence(
                        type=after["type"],
                        path=path,
                        detail=(
                            f"baseline={before.get('sha256', before['type'])} "
                            f"target={after.get('sha256', after['type'])}"
                        ),
                        sha256=after.get("sha256"),
                        size=after.get("size"),
                    )
                ],
            )
            if ctx.allowlist.suppresses(self.analyzer_id, finding):
                allowlisted += 1
                continue
            findings.append(finding)

        summary = {
            "headline": (
                f"{len(findings)} evidence-backed filesystem differences preserved"
                if findings
                else "No unallowlisted filesystem differences relative to baseline"
            ),
            "baselineAware": True,
            "comparedStage": stage_name,
        }
        metrics = {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "preservedFindings": len(findings),
            "allowlisted": allowlisted,
        }
        return self.clean_result(stage_name, summary, findings, metrics)
