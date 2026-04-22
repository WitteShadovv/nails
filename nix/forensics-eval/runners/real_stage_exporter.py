#!/usr/bin/env python3
"""Export real per-stage evidence by driving fresh NixOS test VMs."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ExporterError(RuntimeError):
    """Raised for expected export failures."""


@dataclass(frozen=True)
class ExportContext:
    project_root: Path
    run_dir: Path
    compare_dir: Path
    stage_dir: Path
    stage_name: str
    profile: str
    scenario_id: str
    run_id: str
    campaign_id: str
    iteration: int
    mode: str | None
    scenario: dict[str, Any]
    canaries: dict[str, Any]


def require_env(key: str) -> str:
    value = os.environ.get(key)
    if not value:
        raise ExporterError(f"Missing required environment variable: {key}")
    return value


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def run(argv: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        argv,
        cwd=str(cwd),
        text=True,
        capture_output=True,
        check=False,
    )
    if process.returncode != 0:
        raise ExporterError(
            f"Command failed ({process.returncode}): {' '.join(argv)}\n"
            f"stdout:\n{process.stdout}\n"
            f"stderr:\n{process.stderr}"
        )
    return process


def nix_string(value: str) -> str:
    return json.dumps(value)


def nix_indented(value: str) -> str:
    escaped = value.replace("''", "''''''")
    return "''" + escaped + "''"


def copy_contents(source_dir: Path, target_dir: Path) -> None:
    for source_path in sorted(source_dir.rglob("*")):
        relative = source_path.relative_to(source_dir)
        target_path = target_dir / relative
        if source_path.is_dir():
            target_path.mkdir(parents=True, exist_ok=True)
        elif source_path.is_symlink():
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.symlink_to(os.readlink(source_path))
        else:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, target_path)


def extract_tarball(source_tar: Path, target_dir: Path) -> None:
    with tarfile.open(source_tar, "r") as archive:
        archive.extractall(path=target_dir, filter="data")


def load_context() -> ExportContext:
    stage_dir = Path(require_env("NAILS_FORENSICS_STAGE_DIR")).resolve()
    return ExportContext(
        project_root=Path(__file__).resolve().parents[3],
        run_dir=Path(require_env("NAILS_FORENSICS_RUN_DIR")).resolve(),
        compare_dir=Path(require_env("NAILS_FORENSICS_COMPARE_DIR")).resolve(),
        stage_dir=stage_dir,
        stage_name=require_env("NAILS_FORENSICS_STAGE_NAME"),
        profile=require_env("NAILS_FORENSICS_PROFILE"),
        scenario_id=require_env("NAILS_FORENSICS_SCENARIO_ID"),
        run_id=require_env("NAILS_FORENSICS_RUN_ID"),
        campaign_id=require_env("NAILS_FORENSICS_CAMPAIGN_ID"),
        iteration=int(require_env("NAILS_FORENSICS_ITERATION")),
        mode=os.environ.get("NAILS_FORENSICS_STAGE_MODE") or None,
        scenario=load_json(Path(require_env("NAILS_FORENSICS_SCENARIO_JSON"))),
        canaries=load_json(Path(require_env("NAILS_FORENSICS_CANARIES_JSON"))),
    )


def shared_python_helpers() -> str:
    return r"""
import shlex

def _stage_root():
    return "/tmp/forensics-stage"

def _mkdir(path):
    machine.succeed("mkdir -p " + shlex.quote(path))

def _stage_path(relative):
    root = _stage_root()
    return root if not relative else root + "/" + relative

def _capture_command(name, command):
    prefix = _stage_path("commands/" + name)
    _mkdir(_stage_path("commands"))
    machine.succeed(
        "bash -lc "
        + shlex.quote(
            "set +e; "
            + command
            + " > "
            + shlex.quote(prefix + ".stdout")
            + " 2> "
            + shlex.quote(prefix + ".stderr")
            + "; rc=$?; printf \"%s\" \"$rc\" > "
            + shlex.quote(prefix + ".rc")
        )
    )

def _copy_path(src, dest_relative):
    dest = _stage_path(dest_relative)
    _mkdir("/".join(dest.split("/")[:-1]))
    machine.succeed(
        "bash -lc "
        + shlex.quote(
            "if [ -e "
            + shlex.quote(src)
            + " ]; then cp -a "
            + shlex.quote(src)
            + " "
            + shlex.quote(dest)
            + "; fi"
        )
    )

def _copy_text(path, content):
    machine.succeed(
        "python3 - <<'PY'\n"
        + "from pathlib import Path\n"
        + "path = Path(" + repr(path) + ")\n"
        + "path.parent.mkdir(parents=True, exist_ok=True)\n"
        + "path.write_text(" + repr(content) + ", encoding='utf-8')\n"
        + "PY"
    )

def _load_canaries():
    return json.loads(machine.succeed("cat /tmp/forensics-canaries.json"))

def _load_scenario():
    return json.loads(machine.succeed("cat /tmp/forensics-scenario.json"))

def _write_stage_metadata(stage_name):
    payload = {
        "stage": stage_name,
        "scenario": _load_scenario().get("scenarioId"),
        "profile": _load_scenario().get("profileId"),
        "runId": _load_scenario().get("runId"),
    }
    _copy_text(_stage_path("metadata/stage.json"), json.dumps(payload, indent=2, sort_keys=True) + "\n")

def _plant_canaries():
    canaries = _load_canaries()
    mapping = {entry["label"]: entry["token"] for entry in canaries["entries"]}
    machine.succeed("su - testuser -c 'mkdir -p ~/forensics-eval/projects/confidential ~/Documents'")
    machine.succeed("mkdir -p /tmp/forensics-eval")
    machine.succeed(
        "su - testuser -c " + shlex.quote(
            "printf '%s\\n' " + shlex.quote(mapping["document"]) + " > ~/Documents/forensics-document.txt"
        )
    )
    machine.succeed(
        "su - testuser -c " + shlex.quote(
            "printf '%s\\n' " + shlex.quote(mapping["financial"] + ",100000,CONFIDENTIAL") + " > ~/financial-data.csv"
        )
    )
    machine.succeed(
        "su - testuser -c " + shlex.quote(
            "printf '%s\\n' " + shlex.quote(mapping["nested"]) + " > ~/forensics-eval/projects/confidential/keys.txt"
        )
    )
    machine.succeed(
        "su - testuser -c " + shlex.quote(
            "printf '%s\\n' " + shlex.quote(mapping["hidden"]) + " > ~/.hidden-secrets"
        )
    )
    machine.succeed(
        "su - testuser -c " + shlex.quote(
            "printf '%s\\n' " + shlex.quote(mapping["history"]) + " >> ~/.bash_history"
        )
    )
    machine.succeed(
        "su - testuser -c " + shlex.quote(
            "history -s " + shlex.quote(mapping["session"])
        )
    )
    machine.succeed(
        "bash -lc " + shlex.quote(
            "printf '%s\\n' " + shlex.quote(mapping["temp"]) + " > /tmp/forensics-eval/temp-token.txt"
        )
    )
    machine.succeed(
        "bash -lc " + shlex.quote(
            "printf '%s\\n' " + shlex.quote(mapping["cache"]) + " > /tmp/private-session-data"
        )
    )

def _capture_common(label):
    _capture_command(label + "-status-json", "nails --config /tmp/nails-headless.yaml status --json")
    _capture_command(label + "-mounts", "mount | sort")
    _capture_command(label + "-home-tree", "find /home/testuser -maxdepth 4 -printf '%y %p\\n' | sort")
    _capture_command(label + "-tmp-tree", "find /tmp -maxdepth 3 -printf '%y %p\\n' | sort")
    _capture_command(label + "-history", "su - testuser -c 'cat ~/.bash_history 2>/dev/null || true'")

def _capture_post_cleanup(label):
    _capture_common(label)
    _capture_command(label + "-canary-scan", "timeout 20s grep -R -n 'nails.forensics.' /home /tmp /root 2>/dev/null || true")
    _capture_command(label + "-sensitive-scan", "timeout 20s grep -R -nE 'financial-data|hidden-secrets|private-session|forensics-document|forensics-eval' /home /tmp /root 2>/dev/null || true")
    _capture_command(label + "-fls-vdb", "timeout 20s fls -r /dev/vdb 2>/dev/null || true")

def _finalize():
    import base64
    from pathlib import Path

    machine.succeed("tar -C /tmp -cf /tmp/forensics-stage.tar forensics-stage")
    machine.succeed("bash -lc 'sync; test -s /tmp/forensics-stage.tar; ls -l /tmp/forensics-stage.tar >/dev/null'")
    payload = machine.succeed("base64 -w0 /tmp/forensics-stage.tar")
    Path(machine.out_dir).joinpath("forensics-stage.tar").write_bytes(base64.b64decode(payload))
"""


def stage_python_body(stage_name: str) -> str:
    if stage_name == "baseline":
        return r"""
machine.start()
machine.wait_for_unit("multi-user.target")
write_headless_config("/tmp/nails-headless.yaml")
machine.copy_from_host(CANARIES_FILE, "/tmp/forensics-canaries.json")
machine.copy_from_host(SCENARIO_FILE, "/tmp/forensics-scenario.json")
machine.succeed("mkdir -p /tmp/forensics-stage/artifacts /tmp/forensics-stage/commands /tmp/forensics-stage/metadata")
_write_stage_metadata("baseline")
_capture_common("baseline")
_capture_command("baseline-nails-help", "nails --help")
_finalize()
"""
    if stage_name == "active":
        return r'''
machine.start()
machine.wait_for_unit("multi-user.target")
write_headless_config("/tmp/nails-headless.yaml")
machine.copy_from_host(CANARIES_FILE, "/tmp/forensics-canaries.json")
machine.copy_from_host(SCENARIO_FILE, "/tmp/forensics-scenario.json")
machine.succeed("mkdir -p /tmp/forensics-stage/artifacts /tmp/forensics-stage/commands /tmp/forensics-stage/metadata")
_write_stage_metadata("active")
machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
machine.succeed("nails --config /tmp/nails-headless.yaml activate --overlay-only --no-kill-session -y")
machine.succeed("su - testuser -c 'id -un | grep -qx testuser'")
_plant_canaries()
_capture_common("active")
_capture_command("active-grep-canaries", "grep -R -n 'nails.forensics.' /home /tmp 2>/dev/null || true")
_copy_path("/home/testuser/forensics-eval", "artifacts/home-forensics-eval")
_copy_path("/home/testuser/Documents/forensics-document.txt", "artifacts/forensics-document.txt")
_copy_path("/home/testuser/financial-data.csv", "artifacts/financial-data.csv")
_copy_path("/home/testuser/.hidden-secrets", "artifacts/hidden-secrets.txt")
_copy_path("/tmp/forensics-eval", "artifacts/tmp-forensics-eval")
_copy_path("/tmp/private-session-data", "artifacts/private-session-data.txt")
_finalize()
'''
    if stage_name == "post-standard":
        return r'''
machine.start()
machine.wait_for_unit("multi-user.target")
write_headless_config("/tmp/nails-headless.yaml")
machine.copy_from_host(CANARIES_FILE, "/tmp/forensics-canaries.json")
machine.copy_from_host(SCENARIO_FILE, "/tmp/forensics-scenario.json")
machine.succeed("mkdir -p /tmp/forensics-stage/artifacts /tmp/forensics-stage/commands /tmp/forensics-stage/metadata")
_write_stage_metadata("post-standard")
machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
machine.succeed("nails --config /tmp/nails-headless.yaml activate --overlay-only --no-kill-session -y")
machine.succeed("su - testuser -c 'id -un | grep -qx testuser'")
_plant_canaries()
canonical_deactivate("/tmp/nails-headless.yaml", unit_name="nails-forensics-standard")
machine.succeed("""${hiddenVolume.unmountHiddenVolume}""")
_capture_post_cleanup("post-standard")
_finalize()
'''
    if stage_name == "post-emergency":
        return r'''
machine.start()
machine.wait_for_unit("multi-user.target")
write_headless_config("/tmp/nails-headless.yaml")
machine.copy_from_host(CANARIES_FILE, "/tmp/forensics-canaries.json")
machine.copy_from_host(SCENARIO_FILE, "/tmp/forensics-scenario.json")
machine.succeed("mkdir -p /tmp/forensics-stage/artifacts /tmp/forensics-stage/commands /tmp/forensics-stage/metadata")
_write_stage_metadata("post-emergency")
machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
machine.succeed("nails --config /tmp/nails-headless.yaml activate --overlay-only --no-kill-session -y")
machine.succeed("su - testuser -c 'id -un | grep -qx testuser'")
_plant_canaries()
result = run_shellless_transient_command(
    "/run/nails-tests/forensics-emergency",
    ["nails", "--config", "/tmp/nails-headless.yaml", "emergency", "--no-countdown"],
    unit_name="nails-forensics-emergency",
    timeout=45,
)
assert result["rc"] == 0, result
assert result["systemd"].get("Result") == "success", result
assert "Emergency deactivation complete" in result["stdout"], result
status = read_status_json(config_path="/tmp/nails-headless.yaml")
assert status["state"] == "Inactive", status
_copy_text(
    _stage_path("metadata/emergency-command.json"),
    json.dumps(result, indent=2, sort_keys=True) + "\n",
)
_capture_post_cleanup("post-emergency")
_finalize()
'''
    raise ExporterError(f"Unsupported built-in real stage: {stage_name}")


def render_test_expression(ctx: ExportContext) -> str:
    system_expr = "builtins.currentSystem"
    canaries_content = json.dumps(ctx.canaries, indent=2, sort_keys=True) + "\n"
    scenario_content = json.dumps(ctx.scenario, indent=2, sort_keys=True) + "\n"
    test_script = "\n".join(
        [
            "import json",
            'CANARIES_FILE = "${canariesFile}"',
            'SCENARIO_FILE = "${scenarioFile}"',
            "",
            "${testHelpers.writeHeadlessConfigFn}",
            "${testHelpers.readStatusJsonFn}",
            "${testHelpers.canonicalDeactivateFn}",
            "${emergency.prepareTty1ShellFn}",
            "${emergency.waitForConsoleLogFn}",
            "${emergency.rebootAfterEmergencyFn}",
            "${emergency.runEmergencyCommandFn}",
            "${securityHelpers.capturedCommandFns}",
            shared_python_helpers(),
            stage_python_body(ctx.stage_name),
        ]
    )
    repo = ctx.project_root
    return f"""
let
  flake = builtins.getFlake (toString {repo});
  system = {system_expr};
  pkgs = import flake.inputs.nixpkgs {{
    inherit system;
    overlays = [ (import flake.inputs.rust-overlay) ];
  }};
  self = flake;
  hiddenVolume = import {repo}/nix/e2e-tests/lib/hidden-volume.nix;
  testHelpers = import {repo}/nix/e2e-tests/lib/test-helpers.nix;
  emergency = import {repo}/nix/e2e-tests/lib/emergency.nix;
  securityHelpers = import {repo}/nix/e2e-tests/lib/security-helpers.nix;
  canariesFile = pkgs.writeText "forensics-canaries.json" {nix_string(canaries_content)};
  scenarioFile = pkgs.writeText "forensics-scenario.json" {nix_string(scenario_content)};
in
pkgs.testers.runNixOSTest {{
  name = {nix_string(f"forensics-{ctx.stage_name}-{ctx.run_id}")};
  nodes.machine = {{ ... }}: {{
    imports = [ {repo}/nix/e2e-tests/lib/vm-config.nix ];
    environment.systemPackages = [ self.packages.${{system}}.nails pkgs.jq pkgs.python3 ];
    services.getty.autologinUser = "root";
    systemd.services.nails-emergency-test = emergency.makeEmergencyUnit self.packages.${{system}}.nails "/tmp/nails-headless.yaml";
  }};
  testScript = {nix_indented(test_script)};
}}
"""


def build_stage_output(
    ctx: ExportContext,
) -> tuple[Path, subprocess.CompletedProcess[str]]:
    expression = render_test_expression(ctx)
    with tempfile.TemporaryDirectory(prefix=f"forensics-{ctx.stage_name}-") as tmpdir:
        expression_path = Path(tmpdir) / "stage-test.nix"
        expression_path.write_text(expression, encoding="utf-8")
        process = run(
            [
                "nix",
                "build",
                "--impure",
                "--no-link",
                "--print-out-paths",
                "-f",
                str(expression_path),
            ],
            cwd=ctx.project_root,
        )
    output_path = Path(process.stdout.strip().splitlines()[-1]).resolve()
    return output_path, process


def write_metadata(
    stage_dir: Path,
    *,
    ctx: ExportContext,
    output_path: Path,
    build_process: subprocess.CompletedProcess[str],
) -> None:
    payload = {
        "stage": ctx.stage_name,
        "profileId": ctx.profile,
        "scenarioId": ctx.scenario_id,
        "runId": ctx.run_id,
        "campaignId": ctx.campaign_id,
        "iteration": ctx.iteration,
        "mode": ctx.mode,
        "exporter": "builtin-real-stage-exporter",
        "nixOutput": str(output_path),
    }
    metadata_dir = stage_dir / "metadata"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    (metadata_dir / "host-export.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (metadata_dir / "nix-build.stdout").write_text(
        build_process.stdout,
        encoding="utf-8",
    )
    (metadata_dir / "nix-build.stderr").write_text(
        build_process.stderr,
        encoding="utf-8",
    )


def export_stage(ctx: ExportContext) -> None:
    if ctx.profile != "direct-headless" or ctx.scenario_id != "direct-baseline":
        raise ExporterError(
            "Built-in real exporter currently supports only profile=direct-headless "
            "scenario=direct-baseline"
        )
    output_path, build_process = build_stage_output(ctx)
    exported_tar = output_path / "forensics-stage.tar"
    if not exported_tar.is_file():
        raise ExporterError(
            f"Expected exported evidence tarball missing from test output: {exported_tar}"
        )
    extract_tarball(exported_tar, ctx.stage_dir)
    exported_root = ctx.stage_dir / "forensics-stage"
    if exported_root.is_dir():
        copy_contents(exported_root, ctx.stage_dir)
        shutil.rmtree(exported_root)
    write_metadata(
        ctx.stage_dir,
        ctx=ctx,
        output_path=output_path,
        build_process=build_process,
    )


def main() -> int:
    try:
        export_stage(load_context())
        return 0
    except ExporterError as exc:
        print(f"error: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
