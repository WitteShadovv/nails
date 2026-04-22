#!/usr/bin/env python3
"""Automated forensic leak-evaluation orchestration entrypoint.

This runner intentionally lives outside the current hot flake/e2e conflict areas.
It provides a stable contract for later integration with dedicated scenario,
stage-export, and analyzer workstreams.

Current contract hooks:
  * --scenario-file / --scenario-cmd
      Produces a JSON object saved as scenario.json.
  * --stage-export-cmd
      Invoked once per stage with env vars describing the stage and output path.
      The command must write evidence only inside $NAILS_FORENSICS_STAGE_DIR.
  * --analyzer-cmd
      Invoked once per run after all stage directories are sealed read-only.
      The command must write analysis artifacts only under
      $NAILS_FORENSICS_COMPARE_DIR and treat stage directories as read-only.

If these commands are not provided yet, the runner still produces a complete,
contract-shaped bundle with deterministic canary metadata, empty/placeholder
evidence stages, comparison JSON, summary.json, report.md, and optional
campaign-summary.json for multi-iteration runs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from functools import lru_cache
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CONTRACT_VERSION = "1"
SUPPORTED_MODES = ("standard", "emergency")
DEFAULT_MODES = list(SUPPORTED_MODES)
DEFAULT_PROFILE = "direct-headless"
DEFAULT_SCENARIO = "direct-baseline"
DEFAULT_OUT_DIR_NAME = "tmp/forensics-eval"
MAX_SCAN_FILE_BYTES = 10 * 1024 * 1024


class RunnerError(RuntimeError):
    """Raised for expected orchestration failures."""


@dataclass(frozen=True)
class Config:
    project_root: Path
    profile: str
    scenario_id: str
    modes: list[str]
    iterations: int
    out_dir: Path
    dry_run: bool
    fail_on_findings: bool
    scenario_file: Path | None
    scenario_cmd: str | None
    stage_export_cmd: str | None
    analyzer_cmd: str | None
    fixture_run_dir: Path | None
    skip_analyzers: bool
    builtin_stage_exporter: Path | None


@dataclass(frozen=True)
class ForensicsDefinitions:
    profile_ids: tuple[str, ...]
    scenario_ids: tuple[str, ...]
    defaults: dict[str, str]
    scenario_profiles: dict[str, tuple[str, ...]]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def log(message: str) -> None:
    print(message, file=sys.stderr)


def json_loads(raw: str) -> Any:
    return json.loads(raw)


@lru_cache(maxsize=4)
def load_forensics_definitions(project_root: Path) -> ForensicsDefinitions:
    metadata_process = subprocess.run(
        ["nix", "flake", "metadata", "--json", "."],
        cwd=str(project_root),
        text=True,
        capture_output=True,
        check=False,
    )
    if metadata_process.returncode != 0:
        raise RunnerError(
            "Failed to inspect flake metadata for forensics definitions:\n"
            + metadata_process.stderr.strip()
        )
    metadata = json_loads(metadata_process.stdout)
    nixpkgs_locked = (
        metadata.get("locks", {}).get("nodes", {}).get("nixpkgs", {}).get("locked", {})
    )
    nixpkgs_path = nixpkgs_locked.get("path")
    if not nixpkgs_path:
        owner = nixpkgs_locked.get("owner")
        repo = nixpkgs_locked.get("repo")
        rev = nixpkgs_locked.get("rev")
        if not (owner and repo and rev):
            raise RunnerError("Flake metadata did not expose enough nixpkgs lock data")
        upstream_process = subprocess.run(
            ["nix", "flake", "metadata", "--json", f"github:{owner}/{repo}/{rev}"],
            cwd=str(project_root),
            text=True,
            capture_output=True,
            check=False,
        )
        if upstream_process.returncode != 0:
            raise RunnerError(
                "Failed to resolve locked nixpkgs store path:\n"
                + upstream_process.stderr.strip()
            )
        nixpkgs_path = json_loads(upstream_process.stdout).get("path")
    if not nixpkgs_path:
        raise RunnerError("Unable to resolve nixpkgs store path from flake metadata")
    expression = f"""
let
  pkgs = import {json.dumps(nixpkgs_path)} {{
    system = builtins.currentSystem;
  }};
  subsystem = import ({json.dumps(str(project_root / "nix" / "forensics-eval"))}) {{
    inherit pkgs;
    self = null;
  }};
in
builtins.toJSON {{
  profileIds = subsystem.profileIds;
  scenarioIds = subsystem.scenarioIds;
  defaults = subsystem.defaults;
  scenarioProfiles = builtins.mapAttrs (
    _: scenario: scenario.supportedProfileIds
  ) subsystem.scenarios;
}}
"""
    process = subprocess.run(
        ["nix", "eval", "--impure", "--raw", "--expr", expression],
        cwd=str(project_root),
        text=True,
        capture_output=True,
        check=False,
    )
    if process.returncode != 0:
        raise RunnerError(
            "Failed to load forensics subsystem definitions via nix eval:\n"
            + process.stderr.strip()
        )
    payload = json_loads(process.stdout)
    return ForensicsDefinitions(
        profile_ids=tuple(payload["profileIds"]),
        scenario_ids=tuple(payload["scenarioIds"]),
        defaults=dict(payload["defaults"]),
        scenario_profiles={
            key: tuple(value) for key, value in payload["scenarioProfiles"].items()
        },
    )


def resolve_builtin_stage_exporter(config: Config) -> Path | None:
    if config.fixture_run_dir or config.stage_export_cmd:
        return None
    if config.profile == DEFAULT_PROFILE and config.scenario_id == DEFAULT_SCENARIO:
        exporter = (
            config.project_root
            / "nix"
            / "forensics-eval"
            / "runners"
            / "real_stage_exporter.py"
        )
        if not exporter.is_file():
            raise RunnerError(f"Built-in real stage exporter not found: {exporter}")
        return exporter
    raise RunnerError(
        "No built-in real acquisition exporter is available for "
        f"profile={config.profile!r} scenario={config.scenario_id!r}. "
        "Use the supported default pair, provide --stage-export-cmd, or use --fixture-run-dir for demo mode."
    )


def live_mode(config: Config) -> bool:
    return config.fixture_run_dir is None


def live_export_mode(config: Config) -> bool:
    return config.fixture_run_dir is None and (
        config.stage_export_cmd is not None or config.builtin_stage_exporter is not None
    )


def validate_profile_and_scenario(
    project_root: Path, profile: str, scenario_id: str
) -> None:
    definitions = load_forensics_definitions(project_root)
    if profile not in definitions.profile_ids:
        raise RunnerError(
            f"Unknown profile '{profile}'. Supported profiles: {', '.join(definitions.profile_ids)}"
        )
    if scenario_id not in definitions.scenario_ids:
        raise RunnerError(
            f"Unknown scenario '{scenario_id}'. Supported scenarios: {', '.join(definitions.scenario_ids)}"
        )
    supported_profiles = definitions.scenario_profiles.get(scenario_id, ())
    if profile not in supported_profiles:
        raise RunnerError(
            f"Scenario '{scenario_id}' does not support profile '{profile}'. "
            f"Supported profiles: {', '.join(supported_profiles)}"
        )


def parse_args(argv: list[str]) -> Config:
    script_root = Path(__file__).resolve().parents[3]

    parser = argparse.ArgumentParser(
        description="Run automated forensic leak-evaluation campaigns.",
    )
    parser.add_argument(
        "--profile", default=DEFAULT_PROFILE, help="Profile identifier."
    )
    parser.add_argument(
        "--scenario", default=DEFAULT_SCENARIO, help="Scenario identifier."
    )
    parser.add_argument(
        "--modes",
        default=",".join(DEFAULT_MODES),
        help="Comma-separated analysis modes. Supported: standard,emergency.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1,
        help="Number of runs to execute in the campaign.",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Output root directory. Defaults to <project>/tmp/forensics-eval.",
    )
    parser.add_argument(
        "--scenario-file",
        default=None,
        help="Read scenario JSON from an existing file.",
    )
    parser.add_argument(
        "--scenario-cmd",
        default=None,
        help="Shell command that prints scenario JSON to stdout.",
    )
    parser.add_argument(
        "--stage-export-cmd",
        default=None,
        help="Shell command invoked once per stage to export evidence into the stage directory.",
    )
    parser.add_argument(
        "--analyzer-cmd",
        default=None,
        help="Shell command invoked once per run after evidence sealing.",
    )
    parser.add_argument(
        "--fixture-run-dir",
        default=None,
        help=(
            "Optional fixture run bundle used to populate stage evidence for smoke "
            "and integration verification."
        ),
    )
    parser.add_argument(
        "--skip-analyzers",
        action="store_true",
        help="Skip analyzer execution even when the built-in analyzer runner is available.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the resolved plan and exit without writing outputs.",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit non-zero when post-stage comparisons or canary findings are detected.",
    )
    parser.add_argument(
        "--project-root",
        default=str(script_root),
        help=argparse.SUPPRESS,
    )

    args = parser.parse_args(argv)

    if args.iterations < 1:
        raise RunnerError("--iterations must be >= 1")

    modes = parse_modes(args.modes)
    project_root = Path(args.project_root).expanduser().resolve()
    out_dir = (
        Path(args.out).expanduser().resolve()
        if args.out
        else (project_root / DEFAULT_OUT_DIR_NAME)
    )
    scenario_file = (
        Path(args.scenario_file).expanduser().resolve() if args.scenario_file else None
    )
    fixture_run_dir = (
        Path(args.fixture_run_dir).expanduser().resolve()
        if args.fixture_run_dir
        else None
    )

    if scenario_file and not scenario_file.is_file():
        raise RunnerError(f"Scenario file does not exist: {scenario_file}")
    if args.scenario_file and args.scenario_cmd:
        raise RunnerError("Use only one of --scenario-file or --scenario-cmd")
    if fixture_run_dir and not fixture_run_dir.is_dir():
        raise RunnerError(f"Fixture run directory does not exist: {fixture_run_dir}")

    validate_profile_and_scenario(project_root, args.profile, args.scenario)

    provisional = Config(
        project_root=project_root,
        profile=args.profile,
        scenario_id=args.scenario,
        modes=modes,
        iterations=args.iterations,
        out_dir=out_dir,
        dry_run=args.dry_run,
        fail_on_findings=args.fail_on_findings,
        scenario_file=scenario_file,
        scenario_cmd=args.scenario_cmd,
        stage_export_cmd=args.stage_export_cmd,
        analyzer_cmd=args.analyzer_cmd,
        fixture_run_dir=fixture_run_dir,
        skip_analyzers=args.skip_analyzers,
        builtin_stage_exporter=None,
    )
    return Config(
        **{
            **provisional.__dict__,
            "builtin_stage_exporter": resolve_builtin_stage_exporter(provisional),
        }
    )


def parse_modes(raw_modes: str) -> list[str]:
    modes: list[str] = []
    seen: set[str] = set()
    for chunk in raw_modes.split(","):
        mode = chunk.strip().lower()
        if not mode:
            continue
        if mode not in SUPPORTED_MODES:
            raise RunnerError(
                f"Unsupported mode '{mode}'. Supported modes: {', '.join(SUPPORTED_MODES)}"
            )
        if mode not in seen:
            seen.add(mode)
            modes.append(mode)
    if not modes:
        raise RunnerError("At least one mode must be selected")
    return modes


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


def load_json_file(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate_json_against_schema(
    project_root: Path, schema_name: str, payload: Any
) -> None:
    try:
        from schema_validation import SchemaValidationError, validate_with_schema_path  # type: ignore
    except Exception:
        schema_validator = (
            project_root
            / "nix"
            / "forensics-eval"
            / "analyzers"
            / "schema_validation.py"
        )
        if not schema_validator.is_file():
            raise RunnerError(f"Schema validator module not found: {schema_validator}")
        validator_root = schema_validator.parent
        if str(validator_root) not in sys.path:
            sys.path.insert(0, str(validator_root))
        try:
            from schema_validation import (  # type: ignore
                SchemaValidationError,
                validate_with_schema_path,
            )
        except Exception as exc:  # pragma: no cover
            raise RunnerError(f"Failed to import schema validator: {exc}") from exc

    schema_path = (
        project_root / "nix" / "forensics-eval" / "fixtures" / "schemas" / schema_name
    )
    try:
        validate_with_schema_path(schema_path, payload)
    except SchemaValidationError as exc:
        raise RunnerError(f"Schema validation failed for {schema_name}: {exc}") from exc


def bundled_analyzer_runner(project_root: Path) -> Path:
    return project_root / "nix" / "forensics-eval" / "analyzers" / "run_analyzers.py"


def bundled_campaign_renderer(project_root: Path) -> Path:
    return (
        project_root
        / "nix"
        / "forensics-eval"
        / "analyzers"
        / "render_campaign_summary.py"
    )


def run_shell_command(
    command: str,
    *,
    cwd: Path,
    env: dict[str, str],
    expect_json_stdout: bool = False,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    process = subprocess.run(
        command,
        cwd=str(cwd),
        env=env,
        shell=True,
        text=True,
        capture_output=True,
        check=False,
    )
    result = {
        "command": command,
        "cwd": str(cwd),
        "returnCode": process.returncode,
        "stdout": process.stdout,
        "stderr": process.stderr,
    }
    if process.returncode != 0:
        raise RunnerError(
            f"Command failed with exit code {process.returncode}: {command}\n{process.stderr.strip()}"
        )
    if not expect_json_stdout:
        return None, result

    try:
        payload = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RunnerError(f"Command did not emit valid JSON: {command}\n{exc}") from exc
    if not isinstance(payload, dict):
        raise RunnerError(f"Command must emit a JSON object: {command}")
    return payload, result


def run_process(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
) -> dict[str, Any]:
    process = subprocess.run(
        argv,
        cwd=str(cwd),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    result = {
        "argv": argv,
        "cwd": str(cwd),
        "returnCode": process.returncode,
        "stdout": process.stdout,
        "stderr": process.stderr,
    }
    if process.returncode != 0:
        raise RunnerError(
            f"Command failed with exit code {process.returncode}: {' '.join(argv)}\n{process.stderr.strip()}"
        )
    return result


def safe_path_component(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    return normalized.strip("-._") or "value"


def build_campaign_id(config: Config) -> str:
    timestamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    return f"{timestamp}-{uuid.uuid4().hex[:8]}"


def build_run_id(campaign_id: str, iteration: int) -> str:
    return f"{campaign_id}-run-{iteration:03d}"


def build_canary_namespace(config: Config, campaign_id: str, iteration: int) -> str:
    profile = safe_path_component(config.profile)
    scenario = safe_path_component(config.scenario_id)
    return f"nails.forensics.{profile}.{scenario}.{campaign_id}.iter{iteration:03d}"


def build_canaries(namespace: str) -> dict[str, Any]:
    labels = [
        "history",
        "temp",
        "document",
        "financial",
        "nested",
        "hidden",
        "cache",
        "session",
    ]
    entries = []
    for label in labels:
        digest = hashlib.sha256(f"{namespace}|{label}".encode("utf-8")).hexdigest()[:16]
        entries.append(
            {
                "label": label,
                "token": f"{namespace}:{label}:{digest}",
                "digestPrefix": digest,
            }
        )
    return {
        "contractVersion": CONTRACT_VERSION,
        "namespace": namespace,
        "entries": entries,
    }


def default_scenario_payload(
    config: Config,
    campaign_id: str,
    run_id: str,
    iteration: int,
    canary_namespace: str,
) -> dict[str, Any]:
    return {
        "contractVersion": CONTRACT_VERSION,
        "scenarioId": config.scenario_id,
        "profileId": config.profile,
        "campaignId": campaign_id,
        "runId": run_id,
        "iteration": iteration,
        "requestedModes": config.modes,
        "canaryNamespace": canary_namespace,
        "generatedBy": "nix/forensics-eval/runners/run_forensics_eval.py",
        "assumptions": [
            "No external scenario provider configured; generated contract placeholder.",
            "Stage export/analyzer integrations may replace placeholder behavior without changing bundle layout.",
        ],
    }


def resolve_scenario_payload(
    config: Config,
    campaign_id: str,
    run_id: str,
    iteration: int,
    canary_namespace: str,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    scenario_env = {
        **os.environ,
        "NAILS_FORENSICS_PROFILE": config.profile,
        "NAILS_FORENSICS_SCENARIO_ID": config.scenario_id,
        "NAILS_FORENSICS_CAMPAIGN_ID": campaign_id,
        "NAILS_FORENSICS_RUN_ID": run_id,
        "NAILS_FORENSICS_ITERATION": str(iteration),
        "NAILS_FORENSICS_CANARY_NAMESPACE": canary_namespace,
        "NAILS_FORENSICS_MODES": ",".join(config.modes),
    }

    command_result: dict[str, Any] | None = None
    if config.scenario_file:
        with config.scenario_file.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise RunnerError("Scenario file must contain a JSON object")
    elif config.scenario_cmd:
        payload, command_result = run_shell_command(
            config.scenario_cmd,
            cwd=config.project_root,
            env=scenario_env,
            expect_json_stdout=True,
        )
        assert payload is not None
    else:
        payload = default_scenario_payload(
            config, campaign_id, run_id, iteration, canary_namespace
        )

    payload.setdefault("contractVersion", CONTRACT_VERSION)
    payload.setdefault("scenarioId", config.scenario_id)
    payload.setdefault("profileId", config.profile)
    payload.setdefault("requestedModes", config.modes)
    payload["campaignId"] = campaign_id
    payload["runId"] = run_id
    payload["iteration"] = iteration
    payload["canaryNamespace"] = canary_namespace
    payload["orchestration"] = {
        "entrypoint": "nix/forensics-eval/runners/run_forensics_eval.py",
        "analysisOutputSeparated": True,
        "stageEvidenceSealedReadOnly": True,
    }
    return payload, command_result


def compute_stage_entries(stage_dir: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in sorted(stage_dir.rglob("*")):
        relative = path.relative_to(stage_dir).as_posix()
        metadata = path.lstat()
        mode = stat.S_IMODE(metadata.st_mode)
        if path.is_symlink():
            entries.append(
                {
                    "path": relative,
                    "type": "symlink",
                    "mode": f"0o{mode:03o}",
                    "target": os.readlink(path),
                }
            )
            continue
        if path.is_dir():
            entries.append(
                {
                    "path": relative,
                    "type": "dir",
                    "mode": f"0o{mode:03o}",
                }
            )
            continue
        if path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            entries.append(
                {
                    "path": relative,
                    "type": "file",
                    "mode": f"0o{mode:03o}",
                    "size": metadata.st_size,
                    "sha256": digest.hexdigest(),
                }
            )
    return entries


def stage_digest(entries: list[dict[str, Any]]) -> str:
    payload = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def write_stage_hash_record(
    compare_dir: Path, stage_name: str, entries: list[dict[str, Any]]
) -> dict[str, Any]:
    hash_dir = compare_dir / "stage-hashes"
    record = {
        "stage": stage_name,
        "entryCount": len(entries),
        "digestSha256": stage_digest(entries),
        "entries": entries,
    }
    write_json(hash_dir / f"{stage_name}.json", record)
    return record


def seal_stage_read_only(stage_dir: Path) -> None:
    paths = sorted(stage_dir.rglob("*"), reverse=True)
    for path in paths:
        if path.is_symlink():
            continue
        if path.is_dir():
            path.chmod(0o555)
        elif path.is_file():
            path.chmod(0o444)
    stage_dir.chmod(0o555)


def compare_stage_records(
    base_record: dict[str, Any], target_record: dict[str, Any]
) -> dict[str, Any]:
    def index_entries(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
        return {entry["path"]: entry for entry in record["entries"]}

    base_entries = index_entries(base_record)
    target_entries = index_entries(target_record)
    base_paths = set(base_entries)
    target_paths = set(target_entries)

    added = sorted(target_paths - base_paths)
    removed = sorted(base_paths - target_paths)
    changed: list[str] = []
    unchanged = 0

    for path in sorted(base_paths & target_paths):
        if base_entries[path] == target_entries[path]:
            unchanged += 1
        else:
            changed.append(path)

    return {
        "baseStage": base_record["stage"],
        "targetStage": target_record["stage"],
        "baseDigestSha256": base_record["digestSha256"],
        "targetDigestSha256": target_record["digestSha256"],
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": unchanged,
        },
        "paths": {
            "added": added,
            "removed": removed,
            "changed": changed,
        },
    }


def scan_stage_for_canaries(
    stage_dir: Path, canaries: dict[str, Any]
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    token_map = {entry["label"]: entry["token"] for entry in canaries["entries"]}
    token_bytes = {label: token.encode("utf-8") for label, token in token_map.items()}
    namespace = canaries["namespace"]
    namespace_bytes = namespace.encode("utf-8")

    for path in sorted(stage_dir.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(stage_dir).as_posix()
        path_findings: set[str] = set()
        if namespace in relative:
            path_findings.add("namespace-in-path")
        for label, token in token_map.items():
            if token in relative:
                path_findings.add(f"path:{label}")

        file_size = path.stat().st_size
        if file_size <= MAX_SCAN_FILE_BYTES:
            with path.open("rb") as handle:
                content = handle.read()
            if namespace_bytes in content:
                path_findings.add("content:namespace")
            for label, token in token_bytes.items():
                if token in content:
                    path_findings.add(f"content:{label}")
        else:
            if path_findings:
                path_findings.add("content:skipped-large-file")

        if path_findings:
            findings.append({"path": relative, "matches": sorted(path_findings)})

    return {
        "stage": stage_dir.name,
        "namespace": namespace,
        "findingCount": len(findings),
        "findings": findings,
    }


def make_stage_command_env(
    base_env: dict[str, str],
    *,
    config: Config,
    run_dir: Path,
    stage_dir: Path,
    compare_dir: Path,
    campaign_id: str,
    run_id: str,
    iteration: int,
    stage_name: str,
    mode: str | None,
    scenario_path: Path,
    canaries_path: Path,
) -> dict[str, str]:
    env = dict(base_env)
    env.update(
        {
            "NAILS_FORENSICS_PROFILE": config.profile,
            "NAILS_FORENSICS_SCENARIO_ID": config.scenario_id,
            "NAILS_FORENSICS_MODES": ",".join(config.modes),
            "NAILS_FORENSICS_CAMPAIGN_ID": campaign_id,
            "NAILS_FORENSICS_RUN_ID": run_id,
            "NAILS_FORENSICS_ITERATION": str(iteration),
            "NAILS_FORENSICS_RUN_DIR": str(run_dir),
            "NAILS_FORENSICS_COMPARE_DIR": str(compare_dir),
            "NAILS_FORENSICS_STAGE_NAME": stage_name,
            "NAILS_FORENSICS_STAGE_DIR": str(stage_dir),
            "NAILS_FORENSICS_STAGE_MODE": mode or "",
            "NAILS_FORENSICS_SCENARIO_JSON": str(scenario_path),
            "NAILS_FORENSICS_CANARIES_JSON": str(canaries_path),
            "NAILS_FORENSICS_ANALYSIS_READ_ONLY": "1",
            "NAILS_FORENSICS_STAGE_EVIDENCE_IMMUTABLE": "1",
        }
    )
    return env


def copy_stage_contents(source_dir: Path, target_dir: Path) -> int:
    return copy_stage_contents_with_rewrites(source_dir, target_dir, {})


def copy_stage_contents_with_rewrites(
    source_dir: Path,
    target_dir: Path,
    replacements: dict[bytes, bytes],
) -> int:
    copied = 0
    for source_path in sorted(source_dir.rglob("*")):
        relative = source_path.relative_to(source_dir)
        target_path = target_dir / relative
        if source_path.is_symlink():
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.symlink_to(os.readlink(source_path))
            copied += 1
            continue
        if source_path.is_dir():
            target_path.mkdir(parents=True, exist_ok=True)
            continue
        if source_path.is_file():
            target_path.parent.mkdir(parents=True, exist_ok=True)
            if replacements:
                content = source_path.read_bytes()
                for needle, replacement in replacements.items():
                    content = content.replace(needle, replacement)
                target_path.write_bytes(content)
                shutil.copystat(source_path, target_path)
            else:
                shutil.copy2(source_path, target_path)
            copied += 1
    return copied


def materialize_fixture_stage(
    fixture_run_dir: Path,
    stage_name: str,
    stage_dir: Path,
    canaries_path: Path,
) -> dict[str, Any]:
    source_dir = fixture_run_dir / stage_name
    if not source_dir.exists():
        return {
            "kind": "builtin-fixture-stage-export",
            "fixtureRunDir": str(fixture_run_dir),
            "stage": stage_name,
            "status": "missing-source-stage",
            "copiedEntries": 0,
        }

    replacements: dict[bytes, bytes] = {}
    fixture_canaries_path = fixture_run_dir / "canaries.json"
    if fixture_canaries_path.is_file() and canaries_path.is_file():
        fixture_canaries = load_json_file(fixture_canaries_path)
        current_canaries = load_json_file(canaries_path)
        fixture_tokens = {
            entry["label"]: entry["token"]
            for entry in fixture_canaries.get("entries", [])
            if isinstance(entry, dict)
            and isinstance(entry.get("label"), str)
            and isinstance(entry.get("token"), str)
        }
        current_tokens = {
            entry["label"]: entry["token"]
            for entry in current_canaries.get("entries", [])
            if isinstance(entry, dict)
            and isinstance(entry.get("label"), str)
            and isinstance(entry.get("token"), str)
        }
        for label, token in fixture_tokens.items():
            replacement = current_tokens.get(label)
            if replacement and replacement != token:
                replacements[token.encode("utf-8")] = replacement.encode("utf-8")

    copied = copy_stage_contents_with_rewrites(source_dir, stage_dir, replacements)
    return {
        "kind": "builtin-fixture-stage-export",
        "fixtureRunDir": str(fixture_run_dir),
        "stage": stage_name,
        "status": "copied",
        "copiedEntries": copied,
    }


def materialize_stage(
    *,
    config: Config,
    campaign_id: str,
    run_id: str,
    iteration: int,
    stage_name: str,
    mode: str | None,
    selected: bool,
    run_dir: Path,
    compare_dir: Path,
    scenario_path: Path,
    canaries_path: Path,
) -> dict[str, Any]:
    stage_dir = run_dir / stage_name
    stage_dir.mkdir(parents=True, exist_ok=False)
    command_result: dict[str, Any] | None = None
    status = "exported"

    if selected and config.stage_export_cmd:
        _, command_result = run_shell_command(
            config.stage_export_cmd,
            cwd=config.project_root,
            env=make_stage_command_env(
                os.environ,
                config=config,
                run_dir=run_dir,
                stage_dir=stage_dir,
                compare_dir=compare_dir,
                campaign_id=campaign_id,
                run_id=run_id,
                iteration=iteration,
                stage_name=stage_name,
                mode=mode,
                scenario_path=scenario_path,
                canaries_path=canaries_path,
            ),
        )
    elif selected and config.builtin_stage_exporter:
        command_result = run_process(
            [sys.executable, str(config.builtin_stage_exporter)],
            cwd=config.project_root,
            env=make_stage_command_env(
                os.environ,
                config=config,
                run_dir=run_dir,
                stage_dir=stage_dir,
                compare_dir=compare_dir,
                campaign_id=campaign_id,
                run_id=run_id,
                iteration=iteration,
                stage_name=stage_name,
                mode=mode,
                scenario_path=scenario_path,
                canaries_path=canaries_path,
            ),
        )
        command_result["kind"] = "builtin-real-stage-exporter"
    elif selected and config.fixture_run_dir:
        command_result = materialize_fixture_stage(
            config.fixture_run_dir,
            stage_name,
            stage_dir,
            canaries_path,
        )
        status = "exported" if command_result["status"] == "copied" else "placeholder"
    elif not selected:
        status = "skipped"
    else:
        status = "placeholder"

    seal_stage_read_only(stage_dir)
    entries = compute_stage_entries(stage_dir)
    hash_record = write_stage_hash_record(compare_dir, stage_name, entries)

    return {
        "name": stage_name,
        "mode": mode,
        "selected": selected,
        "status": status,
        "path": str(stage_dir),
        "relativePath": stage_name,
        "hashRecord": {
            "path": f"compare/stage-hashes/{stage_name}.json",
            "digestSha256": hash_record["digestSha256"],
            "entryCount": hash_record["entryCount"],
        },
        "exportCommand": command_result,
    }


def verify_stage_integrity(
    compare_dir: Path, run_dir: Path, stage_name: str
) -> dict[str, Any]:
    hash_record_path = compare_dir / "stage-hashes" / f"{stage_name}.json"
    with hash_record_path.open("r", encoding="utf-8") as handle:
        expected = json.load(handle)
    current_entries = compute_stage_entries(run_dir / stage_name)
    current_digest = stage_digest(current_entries)
    return {
        "stage": stage_name,
        "expectedDigestSha256": expected["digestSha256"],
        "currentDigestSha256": current_digest,
        "match": current_digest == expected["digestSha256"],
    }


def build_run_manifest(
    *,
    config: Config,
    campaign_id: str,
    run_id: str,
    iteration: int,
    run_dir: Path,
    canaries: dict[str, Any],
    stages: list[dict[str, Any]],
    scenario_command: dict[str, Any] | None,
    analyzer_command: dict[str, Any] | None,
    analyzer_summary_path: str | None,
    analyzer_report_path: str | None,
) -> dict[str, Any]:
    return {
        "contractVersion": CONTRACT_VERSION,
        "campaignId": campaign_id,
        "runId": run_id,
        "iteration": iteration,
        "profileId": config.profile,
        "scenarioId": config.scenario_id,
        "requestedModes": config.modes,
        "paths": {
            "runDir": str(run_dir),
            "scenario": "scenario.json",
            "canaries": "canaries.json",
            "compare": "compare",
            "summary": "summary.json",
            "report": "report.md",
        },
        "guardrails": {
            "uniqueRunId": True,
            "canaryNamespace": canaries["namespace"],
            "stageEvidenceImmutable": True,
            "analysisReadOnly": True,
            "separateAnalysisOutput": True,
            "baselineVsPostComparison": True,
        },
        "scenarioSource": scenario_command,
        "analyzerCommand": analyzer_command,
        "analyzerOutputs": {
            "summary": analyzer_summary_path,
            "report": analyzer_report_path,
        },
        "stages": stages,
    }


def generate_report(summary: dict[str, Any]) -> str:
    lines = [
        f"# Forensics Eval Report: {summary['runId']}",
        "",
        f"- Profile: `{summary['profileId']}`",
        f"- Scenario: `{summary['scenarioId']}`",
        f"- Iteration: `{summary['iteration']}`",
        f"- Modes: `{', '.join(summary['requestedModes'])}`",
        f"- Overall result: `{summary['result']}`",
        f"- Canary namespace: `{summary['canaryNamespace']}`",
        "",
        "## Stage digests",
        "",
    ]

    for stage in summary["stages"]:
        lines.append(
            f"- `{stage['name']}`: `{stage['status']}` · digest `{stage['hashRecord']['digestSha256']}`"
        )

    lines.extend(["", "## Comparisons", ""])
    for comparison in summary["comparisons"]:
        if comparison["status"] == "skipped":
            lines.append(f"- `{comparison['id']}`: skipped")
            continue
        counts = comparison["comparison"]["counts"]
        lines.append(
            "- "
            f"`{comparison['id']}`: added={counts['added']}, removed={counts['removed']}, "
            f"changed={counts['changed']}, canaryFindings={comparison['canaryScan']['findingCount']}"
        )

    if summary["integrityChecks"]:
        lines.extend(["", "## Integrity", ""])
        for check in summary["integrityChecks"]:
            lines.append(
                f"- `{check['stage']}`: {'ok' if check['match'] else 'MUTATED'}"
            )

    lines.extend(
        [
            "",
            "## Assumptions",
            "",
            "- Evidence acquisition and analysis are decoupled by contract.",
            "- External analyzers must write under `compare/` only.",
            f"- Acquisition mode: `{summary['acquisitionMode']}`.",
            "",
        ]
    )
    return "\n".join(lines)


def validate_live_stage_requirements(
    stages: list[dict[str, Any]], config: Config
) -> None:
    if not live_export_mode(config):
        return
    required = ("baseline", "active", "post-standard", "post-emergency")
    stage_map = {stage["name"]: stage for stage in stages}
    missing = [
        name
        for name in required
        if name not in stage_map or not stage_map[name]["selected"]
    ]
    if missing:
        raise RunnerError("Live runs require exported stages: " + ", ".join(missing))
    invalid = [
        name
        for name in required
        if stage_map[name]["status"] != "exported"
        or stage_map[name]["hashRecord"]["entryCount"] == 0
    ]
    if invalid:
        raise RunnerError(
            "Live runs produced missing/placeholder evidence for stages: "
            + ", ".join(invalid)
        )


def generate_campaign_report(campaign_summary: dict[str, Any]) -> str:
    lines = [
        f"# Forensics Eval Campaign Summary: {campaign_summary['campaignId']}",
        "",
        f"- Profile: `{campaign_summary['profileId']}`",
        f"- Scenario: `{campaign_summary['scenarioId']}`",
        f"- Iterations: `{campaign_summary['iterations']}`",
        f"- Modes: `{', '.join(campaign_summary['requestedModes'])}`",
        f"- Result: `{campaign_summary['result']}`",
        "",
        "## Runs",
        "",
    ]
    for run in campaign_summary["runs"]:
        lines.append(
            f"- `{run['runId']}`: `{run['result']}` · findings={run['findingCount']} · mutations={run['mutationCount']}"
        )
    lines.append("")
    return "\n".join(lines)


def execute_run(
    config: Config,
    campaign_id: str,
    iteration: int,
) -> dict[str, Any]:
    run_id = build_run_id(campaign_id, iteration)
    canary_namespace = build_canary_namespace(config, campaign_id, iteration)
    run_dir = config.out_dir / run_id
    compare_dir = run_dir / "compare"

    if run_dir.exists():
        raise RunnerError(f"Refusing to reuse existing run directory: {run_dir}")

    run_dir.mkdir(parents=True, exist_ok=False)
    compare_dir.mkdir(parents=True, exist_ok=False)

    scenario_payload, scenario_command = resolve_scenario_payload(
        config, campaign_id, run_id, iteration, canary_namespace
    )
    canaries = build_canaries(canary_namespace)

    scenario_path = run_dir / "scenario.json"
    canaries_path = run_dir / "canaries.json"
    write_json(scenario_path, scenario_payload)
    write_json(canaries_path, canaries)

    stage_specs = [
        ("baseline", None, True),
        ("active", None, True),
        ("post-standard", "standard", "standard" in config.modes),
        ("post-emergency", "emergency", "emergency" in config.modes),
    ]

    stages: list[dict[str, Any]] = []
    for stage_name, mode, selected in stage_specs:
        log(f"[{run_id}] stage: {stage_name}")
        stages.append(
            materialize_stage(
                config=config,
                campaign_id=campaign_id,
                run_id=run_id,
                iteration=iteration,
                stage_name=stage_name,
                mode=mode,
                selected=selected,
                run_dir=run_dir,
                compare_dir=compare_dir,
                scenario_path=scenario_path,
                canaries_path=canaries_path,
            )
        )

    validate_live_stage_requirements(stages, config)

    analyzer_command_result: dict[str, Any] | None = None
    analyzer_summary_path: str | None = None
    analyzer_report_path: str | None = None
    selected_analysis_stages = [
        stage["name"]
        for stage in stages
        if stage["selected"] and stage["name"].startswith("post-")
    ]
    if config.analyzer_cmd:
        log(f"[{run_id}] analyzer")
        _, analyzer_command_result = run_shell_command(
            config.analyzer_cmd,
            cwd=config.project_root,
            env=make_stage_command_env(
                os.environ,
                config=config,
                run_dir=run_dir,
                stage_dir=run_dir / "baseline",
                compare_dir=compare_dir,
                campaign_id=campaign_id,
                run_id=run_id,
                iteration=iteration,
                stage_name="baseline",
                mode=None,
                scenario_path=scenario_path,
                canaries_path=canaries_path,
            )
            | {
                "NAILS_FORENSICS_BASELINE_DIR": str(run_dir / "baseline"),
                "NAILS_FORENSICS_ACTIVE_DIR": str(run_dir / "active"),
                "NAILS_FORENSICS_POST_STANDARD_DIR": str(run_dir / "post-standard"),
                "NAILS_FORENSICS_POST_EMERGENCY_DIR": str(run_dir / "post-emergency"),
            },
        )
        analyzer_summary_path = "compare/summary.json"
        analyzer_report_path = "compare/report.md"
    elif not config.skip_analyzers:
        analyzer_runner = bundled_analyzer_runner(config.project_root)
        if analyzer_runner.is_file():
            log(f"[{run_id}] built-in analyzers")
            analyzer_argv = [
                sys.executable,
                str(analyzer_runner),
                "--run-dir",
                str(run_dir),
                "--baseline-dir",
                str(run_dir / "baseline"),
                "--output",
                str(compare_dir),
            ]
            for stage_name in selected_analysis_stages:
                analyzer_argv.extend(["--stage", stage_name])
            analyzer_command_result = run_process(
                analyzer_argv,
                cwd=config.project_root,
                env=make_stage_command_env(
                    os.environ,
                    config=config,
                    run_dir=run_dir,
                    stage_dir=run_dir / "baseline",
                    compare_dir=compare_dir,
                    campaign_id=campaign_id,
                    run_id=run_id,
                    iteration=iteration,
                    stage_name="baseline",
                    mode=None,
                    scenario_path=scenario_path,
                    canaries_path=canaries_path,
                )
                | {
                    "NAILS_FORENSICS_BASELINE_DIR": str(run_dir / "baseline"),
                    "NAILS_FORENSICS_ACTIVE_DIR": str(run_dir / "active"),
                    "NAILS_FORENSICS_POST_STANDARD_DIR": str(run_dir / "post-standard"),
                    "NAILS_FORENSICS_POST_EMERGENCY_DIR": str(
                        run_dir / "post-emergency"
                    ),
                },
            )
            analyzer_command_result["kind"] = "builtin-analyzer-runner"
            analyzer_summary_path = "compare/summary.json"
            analyzer_report_path = "compare/report.md"

    integrity_checks = [
        verify_stage_integrity(compare_dir, run_dir, stage_name)
        for stage_name, _, _ in stage_specs
    ]

    if any(not check["match"] for check in integrity_checks):
        raise RunnerError(f"Evidence mutation detected after analysis for run {run_id}")

    stage_records: dict[str, dict[str, Any]] = {}
    for stage in stages:
        with (compare_dir / "stage-hashes" / f"{stage['name']}.json").open(
            "r", encoding="utf-8"
        ) as handle:
            stage_records[stage["name"]] = json.load(handle)

    comparisons: list[dict[str, Any]] = []
    for mode in SUPPORTED_MODES:
        target_stage = f"post-{mode}"
        comparison_id = f"baseline-vs-{target_stage}"
        stage_meta = next(stage for stage in stages if stage["name"] == target_stage)
        if not stage_meta["selected"]:
            comparison_payload = {
                "id": comparison_id,
                "status": "skipped",
                "reason": f"mode '{mode}' not requested",
            }
            write_json(compare_dir / f"{comparison_id}.json", comparison_payload)
            comparisons.append(comparison_payload)
            continue

        comparison = compare_stage_records(
            stage_records["baseline"], stage_records[target_stage]
        )
        canary_scan = scan_stage_for_canaries(run_dir / target_stage, canaries)
        comparison_payload = {
            "id": comparison_id,
            "status": "complete",
            "comparison": comparison,
            "canaryScan": canary_scan,
        }
        write_json(compare_dir / f"{comparison_id}.json", comparison_payload)
        comparisons.append(comparison_payload)

    finding_count = sum(
        comparison.get("canaryScan", {}).get("findingCount", 0)
        + comparison.get("comparison", {}).get("counts", {}).get("added", 0)
        + comparison.get("comparison", {}).get("counts", {}).get("removed", 0)
        + comparison.get("comparison", {}).get("counts", {}).get("changed", 0)
        for comparison in comparisons
        if comparison["status"] == "complete"
    )
    mutation_count = sum(0 if check["match"] else 1 for check in integrity_checks)
    result = "clean" if finding_count == 0 and mutation_count == 0 else "findings"

    run_manifest = build_run_manifest(
        config=config,
        campaign_id=campaign_id,
        run_id=run_id,
        iteration=iteration,
        run_dir=run_dir,
        canaries=canaries,
        stages=stages,
        scenario_command=scenario_command,
        analyzer_command=analyzer_command_result,
        analyzer_summary_path=analyzer_summary_path,
        analyzer_report_path=analyzer_report_path,
    )

    summary = {
        "contractVersion": CONTRACT_VERSION,
        "campaignId": campaign_id,
        "runId": run_id,
        "iteration": iteration,
        "profileId": config.profile,
        "scenarioId": config.scenario_id,
        "requestedModes": config.modes,
        "canaryNamespace": canaries["namespace"],
        "result": result,
        "acquisitionMode": "fixture" if config.fixture_run_dir else "live",
        "findingCount": finding_count,
        "mutationCount": mutation_count,
        "stages": stages,
        "comparisons": comparisons,
        "integrityChecks": integrity_checks,
        "generatedAt": iso_now(),
    }

    write_json(run_dir / "run-manifest.json", run_manifest)
    write_json(run_dir / "summary.json", summary)
    write_text(run_dir / "report.md", generate_report(summary))

    compare_summary_path = compare_dir / "summary.json"
    compare_diff_path = compare_dir / "findings-diff.json"
    if compare_summary_path.is_file():
        validate_json_against_schema(
            config.project_root,
            "summary.json",
            load_json_file(compare_summary_path),
        )
    if compare_diff_path.is_file():
        validate_json_against_schema(
            config.project_root,
            "findings-diff.json",
            load_json_file(compare_diff_path),
        )

    return summary


def plan_payload(config: Config, campaign_id: str) -> dict[str, Any]:
    return {
        "contractVersion": CONTRACT_VERSION,
        "profileId": config.profile,
        "scenarioId": config.scenario_id,
        "requestedModes": config.modes,
        "iterations": config.iterations,
        "outDir": str(config.out_dir),
        "campaignId": campaign_id,
        "hooks": {
            "scenarioFile": str(config.scenario_file) if config.scenario_file else None,
            "scenarioCmd": config.scenario_cmd,
            "stageExportCmd": config.stage_export_cmd,
            "analyzerCmd": config.analyzer_cmd,
            "fixtureRunDir": str(config.fixture_run_dir)
            if config.fixture_run_dir
            else None,
            "skipAnalyzers": config.skip_analyzers,
        },
    }


def build_campaign_summary(
    config: Config, campaign_id: str, runs: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "contractVersion": CONTRACT_VERSION,
        "campaignId": campaign_id,
        "profileId": config.profile,
        "scenarioId": config.scenario_id,
        "requestedModes": config.modes,
        "iterations": len(runs),
        "result": "clean"
        if all(run["result"] == "clean" for run in runs)
        else "findings",
        "totals": {
            "findingCount": sum(run["findingCount"] for run in runs),
            "mutationCount": sum(run["mutationCount"] for run in runs),
        },
        "runs": [
            {
                "runId": run["runId"],
                "iteration": run["iteration"],
                "result": run["result"],
                "findingCount": run["findingCount"],
                "mutationCount": run["mutationCount"],
            }
            for run in runs
        ],
        "generatedAt": iso_now(),
    }


def main(argv: list[str]) -> int:
    try:
        config = parse_args(argv)
        campaign_id = build_campaign_id(config)

        if config.dry_run:
            print(json_dumps(plan_payload(config, campaign_id)).rstrip())
            return 0

        config.out_dir.mkdir(parents=True, exist_ok=True)

        summaries: list[dict[str, Any]] = []
        for iteration in range(1, config.iterations + 1):
            log(f"Starting forensics eval run {iteration}/{config.iterations}")
            summaries.append(execute_run(config, campaign_id, iteration))

        if config.iterations > 1:
            campaign_summary = build_campaign_summary(config, campaign_id, summaries)
            write_json(config.out_dir / "campaign-summary.json", campaign_summary)
            write_text(
                config.out_dir / "campaign-summary.md",
                generate_campaign_report(campaign_summary),
            )

        if not config.skip_analyzers:
            campaign_renderer = bundled_campaign_renderer(config.project_root)
            if campaign_renderer.is_file():
                run_process(
                    [
                        sys.executable,
                        str(campaign_renderer),
                        "--campaign-dir",
                        str(config.out_dir),
                    ],
                    cwd=config.project_root,
                    env=os.environ.copy(),
                )

        if config.fail_on_findings and any(
            summary["result"] != "clean" for summary in summaries
        ):
            return 2
        return 0
    except RunnerError as exc:
        log(f"error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
