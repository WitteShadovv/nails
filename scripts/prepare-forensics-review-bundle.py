#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any


EXPECTED_LIVE_STAGES = ("baseline", "active", "post-standard", "post-emergency")
CANARY_TOKEN_RE = re.compile(
    r"nails\.forensics(?:\.[A-Za-z0-9_-]+)*(?::[A-Za-z0-9_.-]+)+"
)
CODE_SPAN_RE = re.compile(r"`([^`]*)`")


class BundleError(RuntimeError):
    pass


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def require_file(path: Path, missing: list[str], label: str | None = None) -> None:
    if not path.is_file():
        missing.append(label or str(path))


def require_glob(
    root: Path,
    pattern: str,
    missing: list[str],
    *,
    label: str | None = None,
) -> list[Path]:
    matches = sorted(path for path in root.glob(pattern) if path.is_file())
    if not matches:
        missing.append(label or f"{root}/{pattern}")
    return matches


def relative_files(paths: list[Path], root: Path) -> set[Path]:
    return {path.relative_to(root) for path in paths}


def stable_redaction(kind: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"<redacted:{kind}:{digest}:{len(value)}>"


def redact_canary_tokens(text: str) -> tuple[str, bool]:
    changed = False

    def replacer(match: re.Match[str]) -> str:
        nonlocal changed
        changed = True
        return stable_redaction("canary", match.group(0))

    return CANARY_TOKEN_RE.sub(replacer, text), changed


def redact_snippet(text: str) -> str:
    return stable_redaction("snippet", text)


def sanitize_evidence_payload(payload: Any) -> tuple[Any, bool]:
    changed = False

    def walk(value: Any) -> Any:
        nonlocal changed
        if isinstance(value, dict):
            if {"type", "path", "detail"}.issubset(value):
                updated = dict(value)
                path_value = updated.get("path")
                if isinstance(path_value, str):
                    sanitized_path, path_changed = redact_canary_tokens(path_value)
                    updated["path"] = sanitized_path
                    changed = changed or path_changed
                detail_value = updated.get("detail")
                if isinstance(detail_value, str):
                    sanitized_detail, detail_changed = redact_canary_tokens(
                        detail_value
                    )
                    updated["detail"] = sanitized_detail
                    changed = changed or detail_changed
                snippet_value = updated.get("snippet")
                if isinstance(snippet_value, str):
                    updated["snippet"] = redact_snippet(snippet_value)
                    changed = True
                for key, nested in list(updated.items()):
                    if key in {"path", "detail", "snippet"}:
                        continue
                    updated[key] = walk(nested)
                return updated
            return {key: walk(item) for key, item in value.items()}
        if isinstance(value, list):
            return [walk(item) for item in value]
        if isinstance(value, str):
            sanitized_text, text_changed = redact_canary_tokens(value)
            changed = changed or text_changed
            return sanitized_text
        return value

    return walk(payload), changed


def sanitize_markdown(content: str) -> tuple[str, bool]:
    changed = False
    sanitized_lines: list[str] = []
    for line in content.splitlines(keepends=True):
        updated_line = line
        stripped = updated_line.lstrip()
        if stripped.startswith("evidence:"):
            span_index = 0

            def replace_span(match: re.Match[str]) -> str:
                nonlocal changed, span_index
                span_index += 1
                if span_index == 1:
                    return match.group(0)
                snippet = match.group(1)
                if not snippet:
                    return match.group(0)
                changed = True
                return f"`{redact_snippet(snippet)}`"

            updated_line = CODE_SPAN_RE.sub(replace_span, updated_line)
        updated_line, token_changed = redact_canary_tokens(updated_line)
        changed = changed or token_changed
        sanitized_lines.append(updated_line)
    return "".join(sanitized_lines), changed


def sanitize_json(relpath: Path, content: str) -> tuple[str, bool]:
    payload = json.loads(content)
    if "compare" in relpath.parts and "analyzers" in relpath.parts:
        sanitized_payload, changed = sanitize_evidence_payload(payload)
    else:
        sanitized_payload, changed = payload, False
    return json.dumps(sanitized_payload, indent=2, sort_keys=True) + "\n", changed


def copy_review_file(source: Path, target: Path, relpath: Path) -> bool:
    if target.suffix == ".json":
        original = source.read_text(encoding="utf-8")
        sanitized, changed = sanitize_json(relpath, original)
        target.write_text(sanitized, encoding="utf-8")
        return changed
    if target.suffix == ".md":
        original = source.read_text(encoding="utf-8")
        sanitized, changed = sanitize_markdown(original)
        target.write_text(sanitized, encoding="utf-8")
        return changed
    shutil.copy2(source, target)
    return False


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Assert and prepare the bounded forensics review bundle."
    )
    parser.add_argument("--campaign-dir", required=True)
    parser.add_argument("--bundle-dir", required=True)
    args = parser.parse_args(argv)

    campaign_dir = Path(args.campaign_dir).expanduser().resolve()
    bundle_dir = Path(args.bundle_dir).expanduser().resolve()

    if not campaign_dir.is_dir():
        raise BundleError(f"Campaign directory does not exist: {campaign_dir}")

    run_dirs = sorted(
        path.parent
        for path in campaign_dir.glob("*/run-manifest.json")
        if path.is_file()
    )
    if not run_dirs:
        raise BundleError(
            f"No run-manifest.json files found under campaign directory: {campaign_dir}"
        )

    missing: list[str] = []
    included_relpaths: set[Path] = set()

    top_level_required = [
        campaign_dir / "campaign-summary.json",
        campaign_dir / "campaign-summary.md",
    ]
    for path in top_level_required:
        require_file(path, missing)
        if path.is_file():
            included_relpaths.add(path.relative_to(campaign_dir))

    acquisition_modes: set[str] = set()
    run_ids: list[str] = []

    for run_dir in run_dirs:
        run_rel = run_dir.relative_to(campaign_dir)
        require_file(run_dir / "summary.json", missing, label=f"{run_rel}/summary.json")
        if not (run_dir / "summary.json").is_file():
            continue
        summary = load_json(run_dir / "summary.json")
        acquisition_mode = str(summary.get("acquisitionMode", "unknown"))
        acquisition_modes.add(acquisition_mode)
        run_ids.append(str(summary.get("runId", run_rel.name)))

        common_required = [
            run_dir / "run-manifest.json",
            run_dir / "summary.json",
            run_dir / "report.md",
            run_dir / "scenario.json",
            run_dir / "compare" / "summary.json",
            run_dir / "compare" / "report.md",
            run_dir / "compare" / "findings-diff.json",
            run_dir / "compare" / "findings-diff.md",
        ]
        for path in common_required:
            require_file(path, missing)
            if path.is_file():
                included_relpaths.add(path.relative_to(campaign_dir))

        included_relpaths |= relative_files(
            require_glob(
                run_dir,
                "compare/baseline-vs-*.json",
                missing,
                label=f"{run_rel}/compare/baseline-vs-*.json",
            ),
            campaign_dir,
        )
        included_relpaths |= relative_files(
            require_glob(
                run_dir,
                "compare/stage-hashes/*.json",
                missing,
                label=f"{run_rel}/compare/stage-hashes/*.json",
            ),
            campaign_dir,
        )
        included_relpaths |= relative_files(
            require_glob(
                run_dir,
                "compare/analyzers/*/*.json",
                missing,
                label=f"{run_rel}/compare/analyzers/*/*.json",
            ),
            campaign_dir,
        )

        if acquisition_mode == "live":
            for stage_name in EXPECTED_LIVE_STAGES:
                stage_metadata = run_dir / stage_name / "metadata" / "stage.json"
                require_file(
                    stage_metadata,
                    missing,
                    label=f"{run_rel}/{stage_name}/metadata/stage.json",
                )
                if stage_metadata.is_file():
                    included_relpaths.add(stage_metadata.relative_to(campaign_dir))

            emergency_metadata = (
                run_dir / "post-emergency" / "metadata" / "emergency-command.json"
            )
            require_file(
                emergency_metadata,
                missing,
                label=f"{run_rel}/post-emergency/metadata/emergency-command.json",
            )
            if emergency_metadata.is_file():
                included_relpaths.add(emergency_metadata.relative_to(campaign_dir))

            included_relpaths |= relative_files(
                require_glob(
                    run_dir,
                    "*/commands/*.rc",
                    missing,
                    label=f"{run_rel}/*/commands/*.rc",
                ),
                campaign_dir,
            )

    if missing:
        raise BundleError(
            "Missing required review artifacts:\n - " + "\n - ".join(sorted(missing))
        )

    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)

    sanitized_files: list[str] = []

    for relpath in sorted(included_relpaths):
        source = campaign_dir / relpath
        target = bundle_dir / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        if copy_review_file(source, target, relpath):
            sanitized_files.append(str(relpath))

    manifest_path = bundle_dir / "review-bundle-manifest.json"
    manifest = {
        "campaignDir": str(campaign_dir),
        "runCount": len(run_dirs),
        "runIds": run_ids,
        "acquisitionModes": sorted(acquisition_modes),
        "includedFiles": [str(path) for path in sorted(included_relpaths)],
        "omittedByDefault": [
            "raw stage trees",
            "stage artifacts directories",
            "command stdout files",
            "command stderr files",
            "blanket runner logs",
            "disk images",
        ],
        "sanitizationApplied": bool(sanitized_files),
        "sanitizedFiles": sorted(sanitized_files),
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(__import__("sys").argv[1:]))
    except BundleError as exc:
        print(f"error: {exc}", file=__import__("sys").stderr)
        raise SystemExit(1)
