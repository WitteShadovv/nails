// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! CLI contract tests: help/version snapshots, the machine-readable (`--json`)
//! envelope against the committed JSON Schemas, the colour/ASCII rendering
//! matrix, the error envelope, and one case per documented exit code.
//!
//! Everything here runs with no root and no VM. Each case drives the real binary
//! through a temporary hidden root, a hand-written `state.json` and `--config`,
//! so inactive, active, degraded and tampered states are all reachable without a
//! real activation. Snapshots are committed under `tests/snapshots/`; regenerate
//! them with `INSTA_UPDATE=always cargo test -p nails-cli --test cli_contract`
//! and review the diff before committing.
//!
//! Scope note: the ticket also asks for colour snapshots of `--plain`/`--no-color`.
//! Those flags were removed in favour of `--color`/`--ascii`/`NO_COLOR`, and in a
//! piped (non-TTY) harness stdout is ASCII with colour off, so the human status
//! renderings coincide. The colour *contract* is still enforced here through
//! `verify` (whose header paints regardless of ASCII) and through the assertion
//! that `--json` never carries ANSI. True PTY colour stays in the VM tier.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use chrono::{DateTime, TimeZone, Utc};
use insta_cmd::assert_cmd_snapshot;
use nails_core::{StateFile, SystemState};
use serde_json::Value;

/// A fixed overlay target used by the active/degraded fixtures. It is an
/// absolute path that is never a real mount point, so `is_mounted` reports it
/// unmounted deterministically and nothing temporary leaks into a snapshot.
const CONTRACT_TARGET: &str = "/opt/nails-contract-home";

/// Substrings that must never appear in user-facing help or version text: the
/// old acronym expansion would identify the tool's purpose on a decoy system,
/// and default hidden-storage paths would point an examiner at the backend.
const BLOCKED_SUBSTRINGS: &[&str] = &[
    "Anti-forensics",
    "anti-forensic",
    "Isolation & Layering",
    "/mnt/hidden",
    "hidden-volume",
];

/// Every `--help` surface plus `--version`, as argument lists.
const HELP_INVOCATIONS: &[&[&str]] = &[
    &["--help"],
    &["--version"],
    &["activate", "--help"],
    &["deactivate", "--help"],
    &["emergency", "--help"],
    &["recover", "--help"],
    &["status", "--help"],
    &["verify", "--help"],
    &["check", "--help"],
    &["init", "--help"],
    &["reset-upper", "--help"],
    &["rehearse", "--help"],
    &["config", "--help"],
    &["config", "path", "--help"],
    &["config", "show", "--help"],
    &["config", "validate", "--help"],
    &["completions", "--help"],
    &["transition", "--help"],
];

/// A fresh `nails` command with the colour-affecting environment cleared, so a
/// test decides rendering through explicit flags and env rather than inheriting
/// the runner's terminal.
fn nails() -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.env_remove("NO_COLOR")
        .env_remove("CLICOLOR")
        .env_remove("CLICOLOR_FORCE")
        .env_remove("TERM");
    cmd
}

/// A fixed activation instant so active-state output is deterministic.
fn fixed_instant() -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000, 0).unwrap()
}

/// An isolated hidden root plus a strict `nails.toml` pointing at it.
struct Harness {
    _dir: tempfile::TempDir,
    config: PathBuf,
    hidden_root: PathBuf,
    state_path: PathBuf,
    log_path: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let hidden_root = dir.path().join("hidden-volume");
        std::fs::create_dir_all(&hidden_root).unwrap();
        let state_path = hidden_root.join("state.json");
        let log_path = hidden_root.join("logs");
        let config = dir.path().join("nails.toml");
        std::fs::write(
            &config,
            format!(
                "hidden_volume_root = {root:?}\n\
                 state_file_path = {state:?}\n\
                 log_path = {log:?}\n\
                 show_opsec_reminders = false\n",
                root = hidden_root.display().to_string(),
                state = state_path.display().to_string(),
                log = log_path.display().to_string(),
            ),
        )
        .unwrap();
        Self {
            _dir: dir,
            config,
            hidden_root,
            state_path,
            log_path,
        }
    }

    /// Write `state` as a valid, integrity-stamped state file on the hidden root.
    fn write_state(&self, state: SystemState) {
        let file = StateFile {
            state,
            ..StateFile::default()
        };
        file.save(&self.state_path, self.hidden_root.to_str().unwrap())
            .expect("save state file on the hidden root");
    }

    /// Write a valid active state, then corrupt its integrity digest so the file
    /// loads as untrusted (`unknown`) rather than as a confident claim.
    fn write_tampered_state(&self) {
        self.write_state(active_state());
        let text = std::fs::read_to_string(&self.state_path).unwrap();
        let mut value: Value = serde_json::from_str(&text).unwrap();
        value["integrity_sha256"] = Value::String("0".repeat(64));
        std::fs::write(&self.state_path, value.to_string()).unwrap();
    }
}

/// An active state record. The live view on the test host is the plain decoy,
/// so status reports the record next to a decoy posture.
fn active_state() -> SystemState {
    SystemState::Active {
        activated_at: fixed_instant(),
    }
}

/// Persist [`active_state`].
fn write_active_harness() -> Harness {
    let harness = Harness::new();
    let file = StateFile {
        state: active_state(),
        ..StateFile::default()
    };
    file.save(&harness.state_path, harness.hidden_root.to_str().unwrap())
        .expect("save active state");
    harness
}

/// Load a committed JSON Schema (the canonical set under `docs/schemas/`, shared
/// with the E2E contract tests). `name` is the command, e.g. `"status"`.
fn load_schema(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/schemas")
        .join(format!("{name}.schema.json"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {name}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

/// Validate `instance` against `schema`, failing with every error at once.
fn assert_matches_schema(schema: &Value, instance: &Value) {
    let validator = jsonschema::validator_for(schema).expect("compile fixture schema");
    let errors: Vec<String> = validator
        .iter_errors(instance)
        .map(|error| error.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "schema violations: {errors:#?}\ninstance: {instance:#}"
    );
}

/// Run `nails` and capture the completed output.
fn run(config: &Path, envs: &[(&str, &str)], args: &[&str]) -> Output {
    let mut cmd = nails();
    cmd.arg("--no-log-file").arg("--config").arg(config);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.args(args);
    cmd.output().expect("run nails")
}

/// Run a `--json` command and return (exit code, the single parsed document).
fn run_json(config: &Path, args: &[&str]) -> (i32, Value) {
    let output = run(config, &[], &{
        let mut v = args.to_vec();
        v.push("--json");
        v
    });
    let stdout = String::from_utf8_lossy(&output.stdout);
    let last = stdout.trim().lines().next_back().unwrap_or("");
    let value: Value = serde_json::from_str(last)
        .unwrap_or_else(|e| panic!("stdout is not one JSON document ({e}): {stdout}"));
    (output.status.code().unwrap_or(-1), value)
}

// ---------------------------------------------------------------------------
// Help and version
// ---------------------------------------------------------------------------

#[test]
fn help_and_version_snapshots() {
    // clap pads blank continuation lines with spaces; strip that trailing
    // whitespace so the committed snapshot survives the trailing-whitespace lint
    // and still round-trips (the filter runs on every capture and comparison).
    insta::with_settings!({filters => vec![(r"[ \t]+\n", "\n")]}, {
        for args in HELP_INVOCATIONS {
            let name = format!("help__{}", args.join("_").replace("--", ""));
            assert_cmd_snapshot!(name, nails().args(*args));
        }
    });
}

#[test]
fn help_and_version_carry_no_blocked_substrings() {
    for args in HELP_INVOCATIONS {
        let output = nails().args(*args).output().expect("run help");
        assert!(output.status.success(), "{args:?} should exit 0");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        for blocked in BLOCKED_SUBSTRINGS {
            assert!(
                !text.contains(blocked),
                "{args:?} output contains blocked substring {blocked:?}"
            );
        }
    }
}

/// Internal commands that run but are marked `hide = true`: the watcher and the
/// notification dispatcher are started by the tool itself. No help or version
/// text a user can reach may name them.
const HIDDEN_COMMANDS: &[&str] = &["watch", "sleep-guard", "transition"];

/// Every command the public help promises; each one's long help renders an
/// EXAMPLES section.
const PUBLIC_COMMANDS: &[&str] = &[
    "init",
    "check",
    "activate",
    "deactivate",
    "emergency",
    "recover",
    "status",
    "verify",
    "reset-upper",
    "config",
];

/// Run a help or version invocation, require exit 0, and return stdout and
/// stderr together after checking that no hidden command leaked onto either.
fn public_help_text(args: &[&str]) -> String {
    let output = nails().args(args).output().expect("run help");
    assert!(output.status.success(), "{args:?} should exit 0");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for hidden in HIDDEN_COMMANDS {
        assert!(
            !text.contains(hidden),
            "{args:?}: internal command token {hidden:?} leaked into public output:\n{text}"
        );
    }
    text
}

// The help and version surface never names an internal command. The snapshots
// above pin the wording; these assert the property as a whole, so dropping a
// `hide = true` fails even after the snapshots are regenerated. They replace the
// help-version-no-leak VM test: none of it needs a kernel, root or a boot.

#[test]
fn root_help_lists_public_commands_and_no_internal_one() {
    for flag in ["--help", "-h"] {
        let root = public_help_text(&[flag]);
        for command in PUBLIC_COMMANDS {
            assert!(root.contains(command), "{flag}: {command} missing:\n{root}");
        }
    }
    let long_help = public_help_text(&["--help"]);
    for section in [
        "full path from the mounted volume",
        "The workflow has four steps",
        "EXIT STATUS:",
    ] {
        assert!(
            long_help.contains(section),
            "{section:?} missing:\n{long_help}"
        );
    }
}

#[test]
fn version_prints_only_the_name_and_semver() {
    let version = public_help_text(&["--version"]);
    let version = version.trim();
    assert!(version.starts_with("nails "), "{version:?}");
    // A leaked install path or hostname would carry a separator; the version
    // line is just "nails X.Y.Z".
    assert!(!version.contains('/'), "{version:?}");
    assert!(!version.contains('\n'), "{version:?}");
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_default();
    let host = host.trim();
    if !host.is_empty() {
        assert!(!version.contains(host), "{host:?} in {version:?}");
    }
}

#[test]
fn every_public_command_long_help_renders_examples() {
    for command in PUBLIC_COMMANDS {
        let help = public_help_text(&[command, "--help"]);
        assert!(help.contains("EXAMPLES:"), "{command}:\n{help}");
    }
}

#[test]
fn hidden_commands_still_run_they_are_only_absent_from_help() {
    // Being hidden is a help-surface property, not a removal: each internal
    // command's own --help still resolves.
    for hidden in HIDDEN_COMMANDS {
        let status = nails()
            .args([hidden, "--help"])
            .output()
            .expect("run hidden help")
            .status;
        assert!(status.success(), "{hidden} --help should exit 0");
    }
}

#[test]
fn completions_print_to_stdout_and_write_no_files() {
    for shell in ["bash", "zsh", "fish"] {
        // Run with the working directory set to a fresh empty temp dir so any
        // stray file a completion generator might write would land here and be
        // detected. `nails completions` must only print to stdout.
        let dir = tempfile::tempdir().unwrap();
        let output = nails()
            .current_dir(dir.path())
            .args(["completions", shell])
            .output()
            .expect("run completions");
        assert!(output.status.success(), "completions {shell} should exit 0");
        assert!(
            !output.stdout.is_empty(),
            "completions {shell} should print a script to stdout"
        );
        assert!(
            output.stderr.is_empty(),
            "completions {shell} should print nothing to stderr"
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert!(
            leftovers.is_empty(),
            "completions {shell} wrote files: {leftovers:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// status --json: schema + snapshot for each state shape
// ---------------------------------------------------------------------------

/// Replace the volatile parts of a status envelope (live disk figures and a
/// wall-clock uptime) with fixed placeholders, leaving the contract-bearing
/// structure deterministic for snapshotting.
fn redact_status(mut value: Value) -> Value {
    if let Some(data) = value.get_mut("data").and_then(Value::as_object_mut) {
        for key in [
            "hidden_root_total_bytes",
            "hidden_root_used_bytes",
            "hidden_root_available_bytes",
        ] {
            if data.contains_key(key) {
                data[key] = Value::String("[bytes]".to_string());
            }
        }
        // The decoy-persistence flag is probed from the live host journald/syslog
        // posture, so it varies by environment; fix it for a stable snapshot. The
        // schema (checked on the un-redacted value) still enforces its boolean type.
        if data.contains_key("decoy_persistent") {
            data["decoy_persistent"] = Value::String("[decoy_persistent]".to_string());
        }
        if data.contains_key("uptime_seconds") {
            data["uptime_seconds"] = Value::String("[uptime_s]".to_string());
        }
        if data.contains_key("uptime_formatted") {
            data["uptime_formatted"] = Value::String("[uptime]".to_string());
        }
        // The hidden root is the harness's temp directory.
        if data.contains_key("hidden_root") {
            data["hidden_root"] = Value::String("[hidden_root]".to_string());
        }
    }
    value
}

#[test]
fn status_json_missing_state_matches_schema_and_snapshot() {
    let harness = Harness::new(); // no state file written
    let (code, value) = run_json(&harness.config, &["status"]);
    assert_eq!(code, 0, "status always exits 0: {value}");
    assert_matches_schema(&load_schema("status"), &value);
    assert_eq!(value["data"]["state"]["kind"], "inactive");
    insta::assert_json_snapshot!("status_json_missing", redact_status(value));
}

#[test]
fn status_json_inactive_matches_schema_and_snapshot() {
    let harness = Harness::new();
    harness.write_state(SystemState::Inactive);
    let (code, value) = run_json(&harness.config, &["status"]);
    assert_eq!(code, 0);
    assert_matches_schema(&load_schema("status"), &value);
    assert_eq!(value["data"]["state"]["kind"], "inactive");
    insta::assert_json_snapshot!("status_json_inactive", redact_status(value));
}

#[test]
fn status_json_active_matches_schema_and_snapshot() {
    let harness = write_active_harness();
    let (code, value) = run_json(&harness.config, &["status"]);
    // The live view on the test host is the plain decoy: an active record is
    // reported next to the decoy posture, and no uptime is claimed for it.
    assert_eq!(code, 0);
    assert_matches_schema(&load_schema("status"), &value);
    assert_eq!(value["data"]["state"]["kind"], "active");
    assert_eq!(value["data"]["posture"], "decoy");
    assert!(value["data"].get("uptime_seconds").is_none());
    insta::assert_json_snapshot!("status_json_active", redact_status(value));
}

#[test]
fn status_json_tampered_state_is_unknown_and_matches_schema() {
    let harness = Harness::new();
    harness.write_tampered_state();
    let (code, value) = run_json(&harness.config, &["status"]);
    // An untrusted state file means the real state is unknown: fail closed.
    assert_eq!(code, 6, "an unknown posture exits InvalidState");
    assert_matches_schema(&load_schema("status"), &value);
    assert_eq!(value["data"]["state"]["kind"], "unknown");
    assert_eq!(value["data"]["posture"], "unknown");
    insta::assert_json_snapshot!("status_json_tampered", redact_status(value));
}

#[test]
fn status_json_degraded_matches_schema_and_snapshot() {
    let harness = Harness::new();
    harness.write_state(SystemState::Degraded {
        since: fixed_instant(),
        reason: "in the hidden root without a way back".to_string(),
    });
    let (code, value) = run_json(&harness.config, &["status"]);
    // The posture comes from the live view (the plain decoy here); the
    // degraded record is reported next to it.
    assert_eq!(code, 0);
    assert_matches_schema(&load_schema("status"), &value);
    assert_eq!(value["data"]["state"]["kind"], "degraded");
    assert_eq!(value["data"]["posture"], "decoy");
    insta::assert_json_snapshot!("status_json_degraded", redact_status(value));
}

#[test]
fn status_reports_the_last_activation_duration() {
    let harness = Harness::new();
    let file = StateFile {
        state: SystemState::Inactive,
        last_activation: Some(nails_core::LastActivation {
            duration_ms: 92_000,
            finished_at: fixed_instant(),
        }),
        ..StateFile::default()
    };
    file.save(&harness.state_path, harness.hidden_root.to_str().unwrap())
        .expect("save state");

    let (code, value) = run_json(&harness.config, &["status"]);
    assert_eq!(code, 0);
    assert_matches_schema(&load_schema("status"), &value);
    assert_eq!(value["data"]["last_activation"]["duration_ms"], 92_000);
    assert!(value["data"].get("activation_in_flight").is_none());

    let stdout = String::from_utf8(run(&harness.config, &[], &["status"]).stdout).unwrap();
    assert!(
        stdout.contains("Last activation:    took 1m32s (finished 2023-11-14 22:13:20 UTC)"),
        "{stdout}"
    );
}

// ---------------------------------------------------------------------------
// verify --json: schema + snapshot
// ---------------------------------------------------------------------------

#[test]
fn verify_json_matches_schema_and_snapshot() {
    let harness = Harness::new();
    let (code, value) = run_json(&harness.config, &["verify"]);
    // Verify scans the live system, so the headline status and the findings are
    // environment-dependent (a secure run exits 0, a warning 10, a critical 11).
    // The schema is enforced over the whole document; only the stable structural
    // envelope is snapshotted.
    assert!(matches!(code, 0 | 10 | 11), "unexpected verify exit {code}");
    assert_matches_schema(&load_schema("verify"), &value);
    assert_eq!(value["command"], "verify");
    assert_eq!(value["data"]["config_aware"], true);
    let projection = serde_json::json!({
        "schema_version": value["schema_version"],
        "command": value["command"],
        "ok": value["ok"],
        "data": {
            "config_aware": value["data"]["config_aware"],
            "scan_depth": value["data"]["scan_depth"],
            "config_paths_checked": value["data"]["config_paths_checked"],
            "state_file_status_kind": value["data"]["state_file_status"]["kind"],
        }
    });
    insta::assert_json_snapshot!("verify_json_envelope", projection);
}

#[test]
fn verify_offline_examiner_json_matches_schema_and_groups_traces() {
    let harness = Harness::new();
    let image = tempfile::tempdir().unwrap();
    let lvm = image.path().join("etc/lvm/archive");
    std::fs::create_dir_all(&lvm).unwrap();
    std::fs::write(
        lvm.join("vg_00001.vg"),
        "description = \"Created *before* executing 'vgcreate vg /dev/sdb'\"\nvg {\n}\n",
    )
    .unwrap();
    let root = image.path().to_str().unwrap();

    let (code, value) = run_json(
        &harness.config,
        &["verify", "--offline", "--root", root, "--examiner"],
    );

    // Setup traces never change the session-residue exit status.
    assert_eq!(code, 0, "{value:#}");
    assert_matches_schema(&load_schema("verify"), &value);
    let groups = value["data"]["examiner"]["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1, "{value:#}");
    assert_eq!(
        groups[0]["findings"][0]["catalog_id"],
        "lvm-metadata-archive"
    );

    // A plain offline scan carries no examiner section.
    let (_, plain) = run_json(&harness.config, &["verify", "--offline", "--root", root]);
    assert!(plain["data"].get("examiner").is_none(), "{plain:#}");
}

// ---------------------------------------------------------------------------
// activate / deactivate / emergency schemas: representative-document round-trip
//
// These commands need root and a live overlay to run for real (covered in the
// VM tier), so here we only guard that the committed schemas compile and accept
// the exact documents the renderers emit, and reject a malformed one.
// ---------------------------------------------------------------------------

#[test]
fn activate_schema_accepts_progress_result_and_error_lines() {
    let schema = load_schema("activate");
    let progress = serde_json::json!({
        "schema_version": 1, "command": "activate", "type": "progress", "phase": "preparing"
    });
    assert_matches_schema(&schema, &progress);

    let result = serde_json::json!({
        "schema_version": 1, "command": "activate", "type": "result",
        "ok": true, "status": "entering", "duration": 12.5,
        "hidden_system": "/nix/store/0000-nixos-system-hidden",
        "filesystems": ["/boot: read-only", "/home: overlaid"],
        "masked_units": ["dev-vda3.swap"],
        "message": "Prepared in 12.5s; soft-rebooting into the hidden session"
    });
    assert_matches_schema(&schema, &result);

    let refused = serde_json::json!({
        "schema_version": 1, "command": "activate", "type": "result",
        "ok": false, "status": "error", "duration": 0.2,
        "filesystems": [], "masked_units": [],
        "message": "Pre-flight checks failed",
        "failed_checks": [{"name": "systemd-version", "reason": "systemd 252 is too old", "fix": "Use Debian 13"}]
    });
    assert_matches_schema(&schema, &refused);

    let error = serde_json::json!({
        "schema_version": 1, "command": "activate", "ok": false,
        "error": {"code": "usage", "message": "no terminal to confirm on"}
    });
    assert_matches_schema(&schema, &error);

    let bad = serde_json::json!({
        "schema_version": 1, "command": "activate", "type": "result", "ok": true
    });
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(
        !validator.is_valid(&bad),
        "incomplete result must be rejected"
    );
}

#[test]
fn deactivate_schema_accepts_the_success_envelope() {
    let schema = load_schema("deactivate");
    for status in ["return_requested", "poweroff_requested"] {
        let value = serde_json::json!({
            "schema_version": 1, "command": "deactivate", "ok": true,
            "data": {"status": status}
        });
        assert_matches_schema(&schema, &value);
    }
    let error = serde_json::json!({
        "schema_version": 1, "command": "deactivate", "ok": false,
        "error": {"code": "invalid_state", "message": "not in a hidden session", "hint": "nails recover"}
    });
    assert_matches_schema(&schema, &error);
}

#[test]
fn emergency_schema_accepts_the_hot_path_report() {
    let schema = load_schema("emergency");
    let hidden = serde_json::json!({
        "schema_version": 1, "command": "emergency", "ok": true,
        "data": {
            "side": "hidden",
            "requested": "return_to_decoy",
            "dispatched": "return_to_decoy",
            "fallback": null,
            "kernel_power_off": false,
            "backend_closing": ["data"],
            "cgroups_killed": 14,
            "processes_killed": 2,
            "remaining_mounts": [],
            "phases": [
                {"name": "prepare-return", "ms": 41},
                {"name": "close-backend", "ms": 9},
                {"name": "arm", "ms": 1},
                {"name": "enqueue", "ms": 22},
                {"name": "kill", "ms": 6}
            ],
            "elapsed_ms": 80
        }
    });
    assert_matches_schema(&schema, &hidden);
    let fallback = serde_json::json!({
        "schema_version": 1, "command": "emergency", "ok": true,
        "data": {
            "side": "hidden", "requested": "return_to_decoy", "dispatched": "poweroff",
            "fallback": "could not mount the decoy root: EBUSY; powering off instead",
            "kernel_power_off": false, "backend_closing": [], "cgroups_killed": 3,
            "processes_killed": 0, "remaining_mounts": [], "phases": [], "elapsed_ms": 5
        }
    });
    assert_matches_schema(&schema, &fallback);
}

// ---------------------------------------------------------------------------
// Error envelope
// ---------------------------------------------------------------------------

#[test]
fn config_failure_is_one_error_envelope_on_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.toml");
    let (code, value) = run_json(&missing, &["status"]);
    assert_eq!(code, 3, "a missing explicit config exits Config(3)");
    assert_matches_schema(&load_schema("status"), &value);
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "config");
    insta::assert_json_snapshot!("error_envelope_config", value, {
        ".error.message" => "[message]",
    });
}

// ---------------------------------------------------------------------------
// Rendering matrix: human, ASCII, colour toggles, non-TTY
// ---------------------------------------------------------------------------

#[test]
fn status_human_default_rendering_snapshot() {
    let harness = Harness::new();
    harness.write_state(SystemState::Inactive);
    let stdout = String::from_utf8(run(&harness.config, &[], &["status"]).stdout).unwrap();
    insta::assert_snapshot!("status_human_default", redact_volume_line(&stdout));
}

/// Replace the live hidden-volume usage line (byte figures vary per filesystem)
/// with a fixed placeholder so the rendering snapshot stays deterministic.
fn redact_volume_line(text: &str) -> String {
    text.lines()
        .map(|line| {
            if line.starts_with("Hidden volume:") {
                "Hidden volume: [SIZE]".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn colour_and_ascii_toggles_do_not_change_inactive_status() {
    // In a piped run stdout is ASCII with colour off; `--color never`, `--ascii`,
    // `NO_COLOR` and `TERM=dumb` must all land on exactly that same output and
    // never emit an ANSI escape.
    let harness = Harness::new();
    harness.write_state(SystemState::Inactive);
    let baseline = run(&harness.config, &[], &["status"]).stdout;

    let check = |envs: &[(&str, &str)], args: &[&str]| {
        let out = run(&harness.config, envs, args).stdout;
        assert_eq!(
            out, baseline,
            "{args:?} with {envs:?} drifted from baseline"
        );
        assert!(
            !out.contains(&0x1b),
            "{args:?} with {envs:?} emitted an ANSI escape"
        );
    };

    check(&[], &["status", "--color", "never"]);
    check(&[], &["status", "--ascii"]);
    check(&[("NO_COLOR", "1")], &["status"]);
    check(&[("TERM", "dumb")], &["status"]);
}

#[test]
fn colour_contract_is_honoured_for_human_and_suppressed_for_json() {
    // `verify`'s header paints even in ASCII mode, so it is the vehicle for the
    // colour toggle in a non-TTY harness.
    let harness = Harness::new();
    let coloured = run(&harness.config, &[], &["verify", "--color", "always"]).stdout;
    assert!(
        coloured.contains(&0x1b),
        "--color always should emit ANSI on human output"
    );
    let plain = run(&harness.config, &[], &["verify", "--color", "never"]).stdout;
    assert!(!plain.contains(&0x1b), "--color never must not emit ANSI");
    // JSON stays machine-parseable regardless of the colour request.
    let json = run(
        &harness.config,
        &[],
        &["verify", "--color", "always", "--json"],
    )
    .stdout;
    assert!(
        !json.contains(&0x1b),
        "--json must never carry ANSI, even with --color always"
    );
}

// ---------------------------------------------------------------------------
// Exit-code table: one case per documented code, all without root or a VM
// ---------------------------------------------------------------------------

#[test]
fn exit_code_0_ok_on_status() {
    let harness = Harness::new();
    harness.write_state(SystemState::Inactive);
    let code = run(&harness.config, &[], &["status"]).status.code();
    assert_eq!(code, Some(0));
}

#[test]
fn exit_code_6_invalid_state_on_unknown_status() {
    // A tampered (untrusted) state file makes the real state unknown; status
    // fails closed with the invalid-state code.
    let harness = Harness::new();
    harness.write_tampered_state();
    let code = run(&harness.config, &[], &["status"]).status.code();
    assert_eq!(code, Some(6));
}

#[test]
fn exit_code_2_usage_on_unknown_flag() {
    let code = nails()
        .arg("--definitely-not-a-flag")
        .output()
        .unwrap()
        .status
        .code();
    assert_eq!(code, Some(2));
}

#[test]
fn exit_code_3_config_on_missing_config() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.toml");
    let code = run(&missing, &[], &["status"]).status.code();
    assert_eq!(code, Some(3));
}

#[test]
fn exit_code_4_preflight_refused_on_check() {
    // `check` runs the activation pre-flights read-only; in this unprivileged,
    // non-mounted sandbox they cannot all pass, so it refuses with code 4.
    let harness = Harness::new();
    let code = run(&harness.config, &[], &["check"]).status.code();
    assert_eq!(code, Some(4));
}

#[test]
fn exit_code_5_needs_root_on_privileged_commands_run_unprivileged() {
    // The integration binary carries `test-hooks`, so the root gate is off by
    // default (the rest of the suite drives activate/deactivate/emergency
    // unprivileged). `NAILS_TEST_ENFORCE_ROOT` turns it on for this case; the
    // sandbox runs as a non-root user, so each privileged command must refuse
    // with code 5 and a copy-pasteable sudo hint before touching anything.
    for subcommand in ["activate", "deactivate", "emergency"] {
        let harness = Harness::new();
        let output = nails()
            .arg("--config")
            .arg(&harness.config)
            .env("NAILS_TEST_ENFORCE_ROOT", "1")
            .arg(subcommand)
            .output()
            .expect("run privileged command unprivileged");

        assert_eq!(
            output.status.code(),
            Some(5),
            "{subcommand} should exit 5 when run without root",
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("must run as root") && stderr.contains("sudo"),
            "{subcommand} stderr missing sudo hint: {stderr}",
        );
        assert!(
            stderr.contains(subcommand),
            "{subcommand} hint should name the subcommand: {stderr}",
        );
        // The gate runs before logging init and before the handler, so no log or
        // state file is created on the hidden root.
        assert!(
            !harness.state_path.exists(),
            "{subcommand} must not create a state file when refused",
        );
        assert!(
            !harness.log_path.exists(),
            "{subcommand} must not create a log directory when refused",
        );
    }
}

#[test]
fn reset_upper_follows_the_live_view_not_an_active_record() {
    // reset-upper is refused only inside the hidden root. On the decoy an
    // active record left behind does not block it.
    let harness = write_active_harness();
    // The temp hidden root shares `/`'s device; declare it attached so the state
    // lock (which refuses an unmounted hidden root) lets the state check run.
    let output = run(
        &harness.config,
        &[("NAILS_TEST_FORCE_ATTACHED", "1")],
        &["reset-upper", CONTRACT_TARGET, "-y", "--json"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(stdout.trim().lines().next_back().unwrap_or(""))
        .unwrap_or_else(|e| panic!("stdout is not one JSON document ({e}): {stdout}"));
    let code = output.status.code().unwrap_or(-1);
    assert_eq!(code, 0, "{stdout}");
    assert_eq!(value["command"], "reset-upper");
    assert_eq!(value["ok"], true);
}

#[test]
#[ignore = "verify exits 10 only when the live scan finds a warning and no \
            critical; under `cargo test` a concurrent process whose argv \
            contains the project path trips the process check (critical), so a \
            clean warning is not deterministic here. The severity->exit mapping \
            is covered by the verify.rs unit tests; the critical path is \
            exercised by exit_code_11_verify_critical_on_active_state."]
fn exit_code_10_verify_warning() {
    let harness = Harness::new();
    let (code, value) = run_json(&harness.config, &["verify"]);
    assert_eq!(code, 10);
    assert_eq!(value["data"]["status"], "warning");
}

#[test]
fn exit_code_11_verify_critical_on_active_state() {
    // A state file still claiming the system is active is a critical verify
    // finding (the hidden environment was not torn down).
    let harness = write_active_harness();
    let (code, value) = run_json(&harness.config, &["verify"]);
    assert_eq!(code, 11);
    assert_eq!(value["data"]["status"], "critical");
}

// ---------------------------------------------------------------------------
// Logging is off: no log file is written
// ---------------------------------------------------------------------------

#[test]
fn no_log_file_is_written_when_logging_is_off() {
    let harness = Harness::new();
    harness.write_state(SystemState::Inactive);
    // reset-upper is a writing command; with --no-log-file it must leave no log.
    let _ = run(
        &harness.config,
        &[],
        &["reset-upper", CONTRACT_TARGET, "-y"],
    );
    let mut found = Vec::new();
    collect_logs(&harness.hidden_root, &mut found);
    collect_logs(&harness.log_path, &mut found);
    assert!(found.is_empty(), "no log file expected, found: {found:?}");
}

/// Collect any `nails.log` under `dir` (recursively), ignoring a missing dir.
fn collect_logs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_logs(&path, out);
        } else if path.file_name().and_then(|n| n.to_str()) == Some("nails.log") {
            out.push(path);
        }
    }
}
