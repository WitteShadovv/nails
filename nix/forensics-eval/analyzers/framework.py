#!/usr/bin/env python3
"""Shared analyzer framework primitives."""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CONTRACT_VERSION = "1"
VALID_STATUSES = {"clean", "finding", "skipped", "error"}
MAX_FILE_BYTES = 10 * 1024 * 1024


class AnalyzerError(RuntimeError):
    """Raised for expected analyzer failures."""


def json_dumps(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(json_dumps(payload))
        tmp_path = Path(handle.name)
    tmp_path.replace(path)


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        handle.write(content)
        tmp_path = Path(handle.name)
    tmp_path.replace(path)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_optional_json(path: Path | None) -> Any | None:
    if path is None or not path.exists():
        return None
    return load_json(path)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compile_patterns(values: list[str]) -> list[re.Pattern[str]]:
    return [re.compile(value) for value in values]


def safe_read_bytes(path: Path, *, max_bytes: int = MAX_FILE_BYTES) -> bytes | None:
    if not path.is_file() or path.stat().st_size > max_bytes:
        return None
    return path.read_bytes()


def safe_read_text(path: Path, *, max_bytes: int = MAX_FILE_BYTES) -> str | None:
    data = safe_read_bytes(path, max_bytes=max_bytes)
    if data is None:
        return None
    return data.decode("utf-8", errors="ignore")


def file_inventory(root: Path) -> dict[str, dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            inventory[path.relative_to(root).as_posix()] = {
                "type": "symlink",
                "target": path.readlink().as_posix(),
            }
            continue
        if path.is_dir():
            inventory[path.relative_to(root).as_posix()] = {"type": "dir"}
            continue
        if path.is_file():
            inventory[path.relative_to(root).as_posix()] = {
                "type": "file",
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
    return inventory


@dataclass(frozen=True)
class Evidence:
    type: str
    path: str
    detail: str
    snippet: str | None = None
    sha256: str | None = None
    size: int | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "type": self.type,
            "path": self.path,
            "detail": self.detail,
        }
        if self.snippet is not None:
            payload["snippet"] = self.snippet
        if self.sha256 is not None:
            payload["sha256"] = self.sha256
        if self.size is not None:
            payload["size"] = self.size
        return payload


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    severity: str
    classification: str
    description: str
    evidence: list[Evidence]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "classification": self.classification,
            "description": self.description,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass
class AnalyzerResult:
    analyzer: str
    stage: str
    status: str
    summary: dict[str, Any]
    findings: list[Finding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        if self.status not in VALID_STATUSES:
            raise AnalyzerError(f"Invalid analyzer status: {self.status}")
        return {
            "contractVersion": CONTRACT_VERSION,
            "analyzer": self.analyzer,
            "stage": self.stage,
            "status": self.status,
            "summary": self.summary,
            "findings": [item.to_dict() for item in self.findings],
            "evidence": [item.to_dict() for item in self.evidence],
            "metrics": self.metrics,
        }


def flatten_evidence(findings: list[Finding]) -> list[Evidence]:
    seen: set[str] = set()
    flattened: list[Evidence] = []
    for finding in findings:
        for evidence in finding.evidence:
            key = json.dumps(evidence.to_dict(), sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            flattened.append(evidence)
    return flattened


def _normalize_finding_evidence(evidence_items: list[Any]) -> list[dict[str, Any]]:
    normalized = []
    for item in evidence_items:
        if hasattr(item, "to_dict"):
            normalized.append(item.to_dict())
        else:
            normalized.append(dict(item))
    return normalized


def finding_fingerprint(stage: str, analyzer: str, finding: Any) -> str:
    payload = {
        "stage": stage,
        "analyzer": analyzer,
        "id": finding.id,
        "title": finding.title,
        "classification": finding.classification,
        "evidence": _normalize_finding_evidence(finding.evidence),
    }
    return sha256_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))


@dataclass(frozen=True)
class AllowlistProfile:
    path_patterns: list[re.Pattern[str]]
    content_patterns: list[re.Pattern[str]]
    finding_ids: set[str]
    analyzer_path_patterns: dict[str, list[re.Pattern[str]]]
    analyzer_content_patterns: dict[str, list[re.Pattern[str]]]
    analyzer_finding_ids: dict[str, set[str]]

    @classmethod
    def empty(cls) -> "AllowlistProfile":
        return cls([], [], set(), {}, {}, {})

    def suppresses(self, analyzer: str, finding: Finding) -> bool:
        if finding.id in self.finding_ids:
            return True
        if finding.id in self.analyzer_finding_ids.get(analyzer, set()):
            return True
        path_patterns = self.path_patterns + self.analyzer_path_patterns.get(
            analyzer, []
        )
        content_patterns = self.content_patterns + self.analyzer_content_patterns.get(
            analyzer, []
        )
        for evidence in finding.evidence:
            if any(pattern.search(evidence.path) for pattern in path_patterns):
                return True
            values = [evidence.detail]
            if evidence.snippet:
                values.append(evidence.snippet)
            if any(
                pattern.search(value)
                for pattern in content_patterns
                for value in values
            ):
                return True
        return False


def _merge_allowlist_layer(
    base: dict[str, Any], layer: dict[str, Any]
) -> dict[str, Any]:
    merged = {
        "global": {
            "pathRegex": list(base.get("global", {}).get("pathRegex", [])),
            "contentRegex": list(base.get("global", {}).get("contentRegex", [])),
            "findingIds": list(base.get("global", {}).get("findingIds", [])),
        },
        "analyzers": json.loads(json.dumps(base.get("analyzers", {}))),
    }
    for key in ("pathRegex", "contentRegex", "findingIds"):
        merged["global"][key].extend(layer.get("global", {}).get(key, []))
    for analyzer, rules in layer.get("analyzers", {}).items():
        target = merged["analyzers"].setdefault(
            analyzer,
            {"pathRegex": [], "contentRegex": [], "findingIds": []},
        )
        for key in ("pathRegex", "contentRegex", "findingIds"):
            target[key].extend(rules.get(key, []))
    return merged


def load_allowlist(paths: list[Path], profile: str) -> AllowlistProfile:
    if not paths:
        return AllowlistProfile.empty()
    merged = {
        "global": {"pathRegex": [], "contentRegex": [], "findingIds": []},
        "analyzers": {},
    }
    for path in paths:
        payload = load_json(path)
        profiles = payload.get("profiles", {})
        merged = _merge_allowlist_layer(merged, profiles.get("default", {}))
        if profile != "default":
            merged = _merge_allowlist_layer(merged, profiles.get(profile, {}))
    return AllowlistProfile(
        path_patterns=compile_patterns(merged["global"]["pathRegex"]),
        content_patterns=compile_patterns(merged["global"]["contentRegex"]),
        finding_ids=set(merged["global"]["findingIds"]),
        analyzer_path_patterns={
            name: compile_patterns(rules.get("pathRegex", []))
            for name, rules in merged["analyzers"].items()
        },
        analyzer_content_patterns={
            name: compile_patterns(rules.get("contentRegex", []))
            for name, rules in merged["analyzers"].items()
        },
        analyzer_finding_ids={
            name: set(rules.get("findingIds", []))
            for name, rules in merged["analyzers"].items()
        },
    )


@dataclass(frozen=True)
class AnalyzerContext:
    run_dir: Path
    output_dir: Path
    scratch_dir: Path
    baseline_dir: Path | None
    stages: dict[str, Path]
    profile: str
    scenario_id: str
    run_id: str
    iteration: int | None
    manifest: dict[str, Any]
    scenario: dict[str, Any] | None
    canaries: dict[str, Any] | None
    allowlist: AllowlistProfile


class Analyzer:
    analyzer_id = "analyzer"
    optional = False

    def __init__(self, options: dict[str, Any] | None = None):
        self.options = options or {}

    def analyze(
        self,
        ctx: AnalyzerContext,
        stage_name: str,
        stage_dir: Path,
    ) -> AnalyzerResult:
        raise NotImplementedError

    def clean_result(
        self,
        stage_name: str,
        summary: dict[str, Any],
        findings: list[Finding],
        metrics: dict[str, Any],
    ) -> AnalyzerResult:
        evidence = flatten_evidence(findings)
        return AnalyzerResult(
            analyzer=self.analyzer_id,
            stage=stage_name,
            status="finding" if findings else "clean",
            summary=summary,
            findings=findings,
            evidence=evidence,
            metrics=metrics,
        )

    def skipped_result(
        self,
        stage_name: str,
        reason: str,
        metrics: dict[str, Any] | None = None,
    ) -> AnalyzerResult:
        return AnalyzerResult(
            analyzer=self.analyzer_id,
            stage=stage_name,
            status="skipped",
            summary={"headline": reason, "reason": reason},
            metrics=metrics or {},
        )

    def error_result(self, stage_name: str, message: str) -> AnalyzerResult:
        return AnalyzerResult(
            analyzer=self.analyzer_id,
            stage=stage_name,
            status="error",
            summary={"headline": message, "error": message},
        )


def load_manifest(path: Path) -> dict[str, Any]:
    payload = load_json(path)
    analyzers = payload.get("analyzers")
    if not isinstance(analyzers, list):
        raise AnalyzerError(f"Manifest missing analyzers list: {path}")
    return payload
