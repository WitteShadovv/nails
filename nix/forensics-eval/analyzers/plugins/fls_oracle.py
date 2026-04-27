#!/usr/bin/env python3

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from framework import Analyzer, AnalyzerContext, Evidence, Finding, safe_read_text


DEFAULT_FILENAME_PATTERNS = {
    "hidden-artifact": r"(^|/)(?:\.hidden-secrets|financial-data\.csv|forensics-document\.txt|private-session-data|temp-token\.txt|keys\.txt)$",
    "forensics-workspace": r"(^|/)forensics-eval(?:/|$)",
    "sensitive-keywords": r"hidden-secrets|financial-data|forensics-document|private-session|confidential",
}

CANARY_TEMPLATE_RE = re.compile(r"\{canary:([^}]+)\}")


def _fls_output_files(root: Path | None) -> list[Path]:
    if root is None or not root.exists():
        return []
    commands_dir = root / "commands"
    if not commands_dir.is_dir():
        return []
    return sorted(commands_dir.glob("*-fls-vdb.stdout"))


def _parse_fls_paths(text: str) -> list[str]:
    paths: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        candidate = line.split(":", 1)[1].strip()
        if not candidate:
            continue
        if len(candidate) >= 2 and candidate[0] == candidate[-1] == '"':
            candidate = candidate[1:-1]
        paths.append(candidate)
    return paths


def _observed_fls_entries(
    files: Iterable[Path], stage_dir: Path | None
) -> tuple[set[str], dict[str, list[Evidence]]]:
    observed: set[str] = set()
    evidence_by_path: dict[str, list[Evidence]] = {}
    for command_output in files:
        text = safe_read_text(command_output)
        if text is None:
            continue
        relative = (
            command_output.relative_to(stage_dir).as_posix()
            if stage_dir is not None
            else command_output.name
        )
        for entry_path in _parse_fls_paths(text):
            observed.add(entry_path)
            evidence_by_path.setdefault(entry_path, []).append(
                Evidence(
                    type="fls-output",
                    path=relative,
                    detail="fls listing matched exported path",
                    snippet=entry_path,
                )
            )
    return observed, evidence_by_path


def _canary_tokens(ctx: AnalyzerContext) -> dict[str, str]:
    return {
        entry["label"]: entry["token"]
        for entry in (ctx.canaries or {}).get("entries", [])
        if isinstance(entry, dict)
        and isinstance(entry.get("label"), str)
        and isinstance(entry.get("token"), str)
    }


def _resolve_exact_path_template(template: str, tokens: dict[str, str]) -> str | None:
    def replace(match: re.Match[str]) -> str:
        label = match.group(1)
        token = tokens.get(label)
        if token is None:
            raise KeyError(label)
        return token

    try:
        return CANARY_TEMPLATE_RE.sub(replace, template)
    except KeyError:
        return None


def _exact_expectations(
    ctx: AnalyzerContext, stage_name: str
) -> tuple[bool, list[dict[str, str]], list[str]]:
    fls_oracle = ((ctx.scenario or {}).get("oracles") or {}).get("flsOracle") or {}
    exact_stage_expectations = fls_oracle.get("exactStageExpectations") or {}
    if stage_name not in exact_stage_expectations:
        return False, [], []
    stage_expectations = exact_stage_expectations.get(stage_name, [])
    if not isinstance(stage_expectations, list):
        return True, [], []

    tokens = _canary_tokens(ctx)
    resolved: list[dict[str, str]] = []
    unresolved: list[str] = []
    for index, entry in enumerate(stage_expectations):
        if not isinstance(entry, dict):
            continue
        label = entry.get("label") or f"exact-{index + 1}"
        if not isinstance(label, str):
            label = f"exact-{index + 1}"

        candidate_path = entry.get("path")
        source = "path"
        if not isinstance(candidate_path, str):
            template = entry.get("pathTemplate")
            if not isinstance(template, str):
                unresolved.append(label)
                continue
            candidate_path = _resolve_exact_path_template(template, tokens)
            source = "pathTemplate"

        if not isinstance(candidate_path, str) or not candidate_path:
            unresolved.append(label)
            continue

        resolved.append(
            {
                "label": label,
                "path": candidate_path,
                "source": source,
            }
        )
    return True, resolved, unresolved


def _compile_patterns(ctx: AnalyzerContext) -> dict[str, re.Pattern[str]]:
    patterns = {
        name: re.compile(value) for name, value in DEFAULT_FILENAME_PATTERNS.items()
    }
    namespace = (ctx.canaries or {}).get("namespace")
    if namespace:
        patterns["canary-namespace"] = re.compile(re.escape(namespace))
    for entry in (ctx.canaries or {}).get("entries", []):
        label = entry.get("label")
        token = entry.get("token")
        if isinstance(label, str) and isinstance(token, str):
            patterns[f"canary-token:{label}"] = re.compile(re.escape(token))
    return patterns


def _baseline_matches(
    paths: Iterable[Path], patterns: dict[str, re.Pattern[str]]
) -> set[tuple[str, str]]:
    observed: set[tuple[str, str]] = set()
    for path in paths:
        text = safe_read_text(path)
        if text is None:
            continue
        for entry_path in _parse_fls_paths(text):
            for name, pattern in patterns.items():
                if pattern.search(entry_path):
                    observed.add((name, entry_path))
    return observed


class FlsOracleAnalyzer(Analyzer):
    analyzer_id = "fls_oracle"

    def analyze(self, ctx: AnalyzerContext, stage_name: str, stage_dir: Path):
        output_files = _fls_output_files(stage_dir)
        if not output_files:
            return self.skipped_result(
                stage_name,
                "no exported fls command output supplied",
            )

        stage_paths, evidence_by_path = _observed_fls_entries(output_files, stage_dir)
        baseline_paths, _ = _observed_fls_entries(
            _fls_output_files(ctx.baseline_dir), ctx.baseline_dir
        )
        has_exact_expectations, exact_expectations, unresolved_exact = (
            _exact_expectations(ctx, stage_name)
        )

        exact_mode_available = has_exact_expectations and (
            bool(exact_expectations) or not unresolved_exact
        )

        if exact_mode_available:
            findings: list[Finding] = []
            allowlisted = 0
            observed = 0
            baseline_equivalent = 0

            for expectation in exact_expectations:
                entry_path = expectation["path"]
                if entry_path not in stage_paths:
                    continue
                observed += 1
                if entry_path in baseline_paths:
                    baseline_equivalent += 1
                    continue
                finding = Finding(
                    id="fls-exact-hit",
                    title="Sleuth Kit fls export contains expected positive-control path",
                    severity="medium",
                    classification="new-relative-to-baseline",
                    description=(
                        "Exported fls output matched an exact scenario/canary-derived "
                        f"expectation for '{expectation['label']}'."
                    ),
                    evidence=evidence_by_path.get(entry_path, [])[:5],
                )
                if ctx.allowlist.suppresses(self.analyzer_id, finding):
                    allowlisted += 1
                    continue
                findings.append(finding)

            summary = {
                "headline": (
                    f"{len(findings)} exact-oracle fls findings preserved"
                    if findings
                    else "No exact-oracle fls evidence beyond baseline"
                ),
                "baselineAware": True,
                "oracle": "sleuthkit-fls-export",
                "oracleMode": "exact-oracle",
            }
            metrics = {
                "flsOutputCount": len(output_files),
                "exactExpectedCount": len(exact_expectations),
                "unresolvedExactExpectations": unresolved_exact,
                "observedHits": observed,
                "baselineEquivalentHits": baseline_equivalent,
                "preservedFindings": len(findings),
                "allowlisted": allowlisted,
            }
            return self.clean_result(stage_name, summary, findings, metrics)

        patterns = _compile_patterns(ctx)
        baseline_hits = _baseline_matches(_fls_output_files(ctx.baseline_dir), patterns)
        findings: list[Finding] = []
        allowlisted = 0
        observed = 0
        baseline_equivalent = 0

        for command_output in output_files:
            text = safe_read_text(command_output)
            if text is None:
                continue
            relative = command_output.relative_to(stage_dir).as_posix()
            per_pattern: dict[str, list[Evidence]] = {name: [] for name in patterns}
            for entry_path in _parse_fls_paths(text):
                for name, pattern in patterns.items():
                    if not pattern.search(entry_path):
                        continue
                    observed += 1
                    key = (name, entry_path)
                    if key in baseline_hits:
                        baseline_equivalent += 1
                        continue
                    per_pattern[name].append(
                        Evidence(
                            type="fls-output",
                            path=relative,
                            detail=f"fls listing matched {name}",
                            snippet=entry_path,
                        )
                    )

            for name, evidence in per_pattern.items():
                if not evidence:
                    continue
                finding = Finding(
                    id="fls-output-hit",
                    title="Sleuth Kit fls export contains hidden-volume indicators",
                    severity="medium",
                    classification="new-relative-to-baseline",
                    description=f"Exported fls output matched '{name}' entries from the hidden-volume device.",
                    evidence=evidence[:10],
                )
                if ctx.allowlist.suppresses(self.analyzer_id, finding):
                    allowlisted += 1
                    continue
                findings.append(finding)

        summary = {
            "headline": (
                f"{len(findings)} fls-output findings preserved"
                if findings
                else "No new fls-output evidence beyond baseline"
            ),
            "baselineAware": True,
            "oracle": "sleuthkit-fls-export",
            "oracleMode": "heuristic-fallback",
        }
        metrics = {
            "flsOutputCount": len(output_files),
            "patternCount": len(patterns),
            "unresolvedExactExpectations": unresolved_exact,
            "observedHits": observed,
            "baselineEquivalentHits": baseline_equivalent,
            "preservedFindings": len(findings),
            "allowlisted": allowlisted,
        }
        return self.clean_result(stage_name, summary, findings, metrics)
