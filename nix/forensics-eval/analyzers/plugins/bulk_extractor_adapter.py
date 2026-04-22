#!/usr/bin/env python3

from __future__ import annotations

import re
import shutil
from pathlib import Path

from framework import Analyzer, AnalyzerContext, Evidence, Finding, safe_read_text


DEFAULT_PATTERNS = {
    "bulk-canary": r"nails\.forensics\.|NAILS_CANARY",
    "bulk-hidden": r"/mnt/hidden|veracrypt-hidden|tcrypt-hidden|hidden\.vc",
    "bulk-sensitive": r"Operation Nightingale|transfer-alpha|financial-data|secret-project",
}


def _bulk_dirs(stage_dir: Path) -> list[Path]:
    return [
        path
        for path in sorted(stage_dir.rglob("*"))
        if path.is_dir() and path.name.startswith("bulk")
    ]


class BulkExtractorAdapter(Analyzer):
    analyzer_id = "bulk_extractor_adapter"
    optional = True

    def analyze(self, ctx: AnalyzerContext, stage_name: str, stage_dir: Path):
        bulk_dirs = _bulk_dirs(stage_dir)
        bulk_available = shutil.which("bulk_extractor") is not None
        if not bulk_dirs and not bulk_available:
            return self.skipped_result(
                stage_name,
                "bulk_extractor unavailable and no bulk output supplied",
            )
        if not bulk_dirs:
            return self.skipped_result(
                stage_name,
                "bulk_extractor present but no exported bulk evidence supplied",
            )

        patterns = {
            name: re.compile(value)
            for name, value in self.options.get("patterns", DEFAULT_PATTERNS).items()
        }
        baseline_dirs = _bulk_dirs(ctx.baseline_dir) if ctx.baseline_dir else []
        baseline_lines: set[tuple[str, str]] = set()
        for directory in baseline_dirs:
            for path in directory.rglob("*"):
                if not path.is_file() or path.is_symlink():
                    continue
                text = safe_read_text(path)
                if text is None:
                    continue
                for name, pattern in patterns.items():
                    for match in pattern.finditer(text):
                        baseline_lines.add((name, match.group(0)))

        findings: list[Finding] = []
        allowlisted = 0
        observed = 0
        baseline_equivalent = 0
        for directory in bulk_dirs:
            for path in sorted(directory.rglob("*")):
                if not path.is_file() or path.is_symlink():
                    continue
                text = safe_read_text(path)
                if text is None:
                    continue
                relative = path.relative_to(stage_dir).as_posix()
                for name, pattern in patterns.items():
                    evidence: list[Evidence] = []
                    for match in pattern.finditer(text):
                        observed += 1
                        key = (name, match.group(0))
                        if key in baseline_lines:
                            baseline_equivalent += 1
                            continue
                        evidence.append(
                            Evidence(
                                type="bulk-output",
                                path=relative,
                                detail=f"bulk output matched {name}",
                                snippet=match.group(0),
                            )
                        )
                        if len(evidence) >= 10:
                            break
                    if not evidence:
                        continue
                    finding = Finding(
                        id="bulk-output-hit",
                        title="bulk_extractor export contains leak indicators",
                        severity="medium",
                        classification="new-relative-to-baseline",
                        description=f"bulk_extractor-derived evidence matched '{name}'.",
                        evidence=evidence,
                    )
                    if ctx.allowlist.suppresses(self.analyzer_id, finding):
                        allowlisted += 1
                        continue
                    findings.append(finding)

        summary = {
            "headline": (
                f"{len(findings)} bulk-output findings preserved"
                if findings
                else "No new bulk-output evidence beyond baseline"
            ),
            "baselineAware": True,
            "bulkExtractorAvailable": bulk_available,
        }
        metrics = {
            "bulkDirCount": len(bulk_dirs),
            "observedHits": observed,
            "baselineEquivalentHits": baseline_equivalent,
            "preservedFindings": len(findings),
            "allowlisted": allowlisted,
        }
        return self.clean_result(stage_name, summary, findings, metrics)
