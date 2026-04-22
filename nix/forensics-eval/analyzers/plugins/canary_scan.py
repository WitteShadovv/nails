#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path

from framework import Analyzer, AnalyzerContext, Evidence, Finding, safe_read_bytes


def _scan_tokens(root: Path, tokens: dict[str, str]) -> dict[str, list[Evidence]]:
    hits = {label: [] for label in tokens}
    token_bytes = {label: token.encode("utf-8") for label, token in tokens.items()}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        for label, token in tokens.items():
            if token in relative:
                hits[label].append(
                    Evidence(
                        type="path",
                        path=relative,
                        detail=f"token {label} present in file path",
                        snippet=token,
                    )
                )
        data = safe_read_bytes(path)
        if data is None:
            continue
        for label, token in token_bytes.items():
            if token in data:
                hits[label].append(
                    Evidence(
                        type="content",
                        path=relative,
                        detail=f"token {label} present in file content",
                        snippet=tokens[label],
                    )
                )
    return hits


class CanaryScanAnalyzer(Analyzer):
    analyzer_id = "canary_scan"

    def analyze(self, ctx: AnalyzerContext, stage_name: str, stage_dir: Path):
        canaries = (ctx.canaries or {}).get("entries", [])
        if not canaries:
            return self.skipped_result(stage_name, "canary inventory unavailable")

        tokens = {entry["label"]: entry["token"] for entry in canaries}
        baseline_hits = (
            _scan_tokens(ctx.baseline_dir, tokens) if ctx.baseline_dir else {}
        )
        stage_hits = _scan_tokens(stage_dir, tokens)
        findings: list[Finding] = []
        observed = 0
        baseline_equivalent = 0
        allowlisted = 0

        for label, evidence in stage_hits.items():
            if not evidence:
                continue
            observed += len(evidence)
            baseline_keys = {
                (item.path, item.type, item.snippet)
                for item in baseline_hits.get(label, [])
            }
            preserved = [
                item
                for item in evidence
                if (item.path, item.type, item.snippet) not in baseline_keys
            ]
            baseline_equivalent += len(evidence) - len(preserved)
            if not preserved:
                continue
            finding = Finding(
                id="canary-token",
                title=f"Run canary token leaked into {stage_name}",
                severity="high",
                classification="new-relative-to-baseline",
                description=f"Canary token '{label}' was found outside the baseline stage.",
                evidence=preserved,
            )
            if ctx.allowlist.suppresses(self.analyzer_id, finding):
                allowlisted += 1
                continue
            findings.append(finding)

        summary = {
            "headline": (
                f"{len(findings)} canary leaks preserved"
                if findings
                else "No new canary evidence found"
            ),
            "baselineAware": True,
            "canaryNamespace": (ctx.canaries or {}).get("namespace"),
        }
        metrics = {
            "tokens": len(tokens),
            "observedHits": observed,
            "baselineEquivalentHits": baseline_equivalent,
            "preservedFindings": len(findings),
            "allowlisted": allowlisted,
        }
        return self.clean_result(stage_name, summary, findings, metrics)
