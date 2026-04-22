#!/usr/bin/env python3

from __future__ import annotations

import re
from pathlib import Path

from framework import Analyzer, AnalyzerContext, Evidence, Finding, safe_read_text


DEFAULT_PATTERNS = {
    "hidden-mount": r"/mnt/hidden",
    "overlay-options": r"upperdir=.*/hidden|workdir=.*/hidden|overlay",
    "nails-command": r"nails\s+(activate|deactivate|emergency)",
    "nails-config": r"nails\.toml|nails-core",
    "hidden-backend": r"veracrypt-hidden|tcrypt-hidden|hidden\.vc",
    "browser-or-pkg": r"tor-browser|signal-desktop|keepassxc|cowsay",
    "sensitive-content": r"Operation Nightingale|transfer-alpha|financial-data|secret-project",
}


def _scan_patterns(
    root: Path, patterns: dict[str, re.Pattern[str]]
) -> dict[str, list[Evidence]]:
    hits = {name: [] for name in patterns}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        for name, pattern in patterns.items():
            if pattern.search(relative):
                hits[name].append(
                    Evidence(
                        type="path",
                        path=relative,
                        detail=f"indicator {name} matched file path",
                        snippet=relative,
                    )
                )
        text = safe_read_text(path)
        if text is None:
            continue
        for name, pattern in patterns.items():
            for match in pattern.finditer(text):
                snippet = match.group(0)
                hits[name].append(
                    Evidence(
                        type="content",
                        path=relative,
                        detail=f"indicator {name} matched file content",
                        snippet=snippet,
                    )
                )
                if len(hits[name]) >= 25:
                    break
    return hits


class IndicatorScanAnalyzer(Analyzer):
    analyzer_id = "indicator_scan"

    def analyze(self, ctx: AnalyzerContext, stage_name: str, stage_dir: Path):
        patterns = {
            name: re.compile(value)
            for name, value in self.options.get("patterns", DEFAULT_PATTERNS).items()
        }
        baseline_hits = (
            _scan_patterns(ctx.baseline_dir, patterns) if ctx.baseline_dir else {}
        )
        stage_hits = _scan_patterns(stage_dir, patterns)
        findings: list[Finding] = []
        baseline_equivalent = 0
        allowlisted = 0
        observed = 0

        for name, evidence in stage_hits.items():
            if not evidence:
                continue
            observed += len(evidence)
            baseline_keys = {
                (item.path, item.type, item.snippet)
                for item in baseline_hits.get(name, [])
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
                id="indicator-hit",
                title=f"Leak indicator matched in {stage_name}",
                severity="medium",
                classification="new-relative-to-baseline",
                description=f"Indicator set '{name}' matched stage evidence.",
                evidence=preserved,
            )
            if ctx.allowlist.suppresses(self.analyzer_id, finding):
                allowlisted += 1
                continue
            findings.append(finding)

        summary = {
            "headline": (
                f"{len(findings)} indicator findings preserved"
                if findings
                else "No new indicator evidence beyond baseline"
            ),
            "baselineAware": True,
            "patternCount": len(patterns),
        }
        metrics = {
            "patternCount": len(patterns),
            "observedHits": observed,
            "baselineEquivalentHits": baseline_equivalent,
            "preservedFindings": len(findings),
            "allowlisted": allowlisted,
        }
        return self.clean_result(stage_name, summary, findings, metrics)
