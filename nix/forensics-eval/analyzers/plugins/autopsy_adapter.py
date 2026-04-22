#!/usr/bin/env python3

from __future__ import annotations

import re
import shutil
from pathlib import Path

from framework import Analyzer, AnalyzerContext, Evidence, Finding, safe_read_text


DEFAULT_PATTERNS = {
    "autopsy-hidden": r"/mnt/hidden|veracrypt-hidden|tcrypt-hidden|hidden\.vc",
    "autopsy-sensitive": r"Operation Nightingale|transfer-alpha|financial-data|secret-project",
}


class AutopsyAdapter(Analyzer):
    analyzer_id = "autopsy_adapter"
    optional = True

    def analyze(self, ctx: AnalyzerContext, stage_name: str, stage_dir: Path):
        export_dir = stage_dir / "autopsy-export"
        if not export_dir.is_dir():
            available = shutil.which("autopsy") is not None
            reason = (
                "autopsy export not supplied; external ingest intentionally not invoked"
                if available
                else "autopsy unavailable and no export supplied"
            )
            return self.skipped_result(stage_name, reason)

        patterns = {
            name: re.compile(value)
            for name, value in self.options.get("patterns", DEFAULT_PATTERNS).items()
        }
        findings: list[Finding] = []
        allowlisted = 0
        observed = 0
        for path in sorted(export_dir.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            text = safe_read_text(path)
            if text is None:
                continue
            relative = path.relative_to(stage_dir).as_posix()
            for name, pattern in patterns.items():
                matches = [match.group(0) for match in pattern.finditer(text)]
                observed += len(matches)
                if not matches:
                    continue
                evidence = [
                    Evidence(
                        type="autopsy-export",
                        path=relative,
                        detail=f"autopsy export matched {name}",
                        snippet=match,
                    )
                    for match in matches[:10]
                ]
                finding = Finding(
                    id="autopsy-export-hit",
                    title="Autopsy export contains leak indicators",
                    severity="medium",
                    classification="direct-evidence",
                    description=f"Autopsy export evidence matched '{name}'.",
                    evidence=evidence,
                )
                if ctx.allowlist.suppresses(self.analyzer_id, finding):
                    allowlisted += 1
                    continue
                findings.append(finding)

        summary = {
            "headline": (
                f"{len(findings)} autopsy-export findings preserved"
                if findings
                else "No autopsy-export findings preserved"
            ),
            "baselineAware": False,
        }
        metrics = {
            "observedHits": observed,
            "preservedFindings": len(findings),
            "allowlisted": allowlisted,
        }
        return self.clean_result(stage_name, summary, findings, metrics)
