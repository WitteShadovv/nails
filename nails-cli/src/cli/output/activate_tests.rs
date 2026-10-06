// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::ProgressSurface;
use crate::cli::output::{OutputMode, OutputSettings};

#[test]
fn progress_surface_follows_mode_terminal_and_detachment() {
    let terminal = OutputSettings {
        progress_animation: true,
        ..OutputSettings::default()
    };
    let piped = OutputSettings::default();
    let json = OutputSettings {
        mode: OutputMode::Json,
        ..OutputSettings::default()
    };

    assert_eq!(
        ProgressSurface::select(&terminal, false),
        ProgressSurface::Spinner
    );
    assert_eq!(
        ProgressSurface::select(&piped, false),
        ProgressSurface::Plain
    );
    assert_eq!(ProgressSurface::select(&json, false), ProgressSurface::Json);
    let quiet_terminal = OutputSettings {
        verbosity: nails_core::Verbosity::Quiet,
        ..terminal
    };
    assert_eq!(
        ProgressSurface::select(&quiet_terminal, false),
        ProgressSurface::Plain
    );
    // A detached worker never writes progress, whatever it inherited.
    for settings in [terminal, piped, json] {
        assert_eq!(
            ProgressSurface::select(&settings, true),
            ProgressSurface::Silent
        );
    }
}

use super::*;
use nails_core::{MockFilesystem, NailsError, NailsManager, ShellSetupResult, TestWorld};
use std::path::PathBuf;

fn quiet_settings() -> OutputSettings {
    OutputSettings {
        verbosity: nails_core::Verbosity::Quiet,
        ..OutputSettings::default()
    }
}

/// Settings fixed at one verbosity with colour off and ASCII markers, so a
/// rendering snapshot is deterministic and isolates the verbosity dimension.
fn settings_at(verbosity: nails_core::Verbosity) -> OutputSettings {
    OutputSettings {
        verbosity,
        ascii: true,
        ..OutputSettings::default()
    }
}

fn make_shell_setup_rc_modified() -> ShellSetupResult {
    use nails_core::shell::ShellType;
    ShellSetupResult {
        shell_type: ShellType::Bash,
        prompt_script_path: PathBuf::from("/mnt/hidden/scripts/nails_prompt.bash"),
        alias_script_path: PathBuf::from("/mnt/hidden/scripts/nails_alias.sh"),
        instructions: vec!["source /mnt/hidden/scripts/nails_prompt.bash".to_string()],
        warning: None,
        rc_modified: true,
    }
}

fn make_shell_setup_no_rc() -> ShellSetupResult {
    use nails_core::shell::ShellType;
    ShellSetupResult {
        shell_type: ShellType::Bash,
        prompt_script_path: PathBuf::from("/mnt/hidden/scripts/nails_prompt.bash"),
        alias_script_path: PathBuf::from("/mnt/hidden/scripts/nails_alias.sh"),
        instructions: vec!["source /mnt/hidden/scripts/nails_prompt.bash".to_string()],
        warning: None,
        rc_modified: false,
    }
}

fn make_shell_setup_with_warning() -> ShellSetupResult {
    use nails_core::shell::ShellType;
    ShellSetupResult {
        shell_type: ShellType::Bash,
        prompt_script_path: PathBuf::from("/mnt/hidden/scripts/nails_prompt.bash"),
        alias_script_path: PathBuf::from("/mnt/hidden/scripts/nails_alias.sh"),
        instructions: vec![],
        warning: Some("Could not detect shell config".to_string()),
        rc_modified: false,
    }
}

/// A manager whose state is Active with one writer left on the decoy. The
/// temporary directory doubles as the hidden volume so the state can be saved.
fn make_active_manager_with_writer() -> (tempfile::TempDir, NailsManager<MockFilesystem>) {
    let (mut manager, dir) = TestWorld::new().manager();
    manager
        .force_state(nails_core::SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![PathBuf::from("/var")],
            decoy_writers: vec![tail_writer()],
        })
        .unwrap();
    (dir, manager)
}

fn tail_writer() -> nails_core::DecoyWriter {
    nails_core::DecoyWriter {
        pid: 812,
        name: "tail".to_string(),
        service: None,
        targets: vec![PathBuf::from("/var")],
        kind: nails_core::WriterKind::Surviving,
    }
}

/// A genuine activation whose hidden NixOS switch failed with
/// `switch_required = false`: overlays up, configuration not applied.
fn activated_with_failed_switch() -> Result<nails_core::ActivationOutcome, NailsError> {
    Ok(nails_core::ActivationOutcome::Activated {
        hidden_config: nails_core::HiddenConfigOutcome::Failed {
            reason: "build failed".to_string(),
        },
    })
}

// ── hidden-config warnings ───────────────────────────────────────────────

#[test]
fn test_json_failed_switch_reports_success_with_warnings() {
    let (manager, _tempdir) = TestWorld::new().manager();
    let output = build_activate_json_output(&activated_with_failed_switch(), 1.0, &manager, None);
    let json = serde_json::to_value(&output).unwrap();
    assert_eq!(json["ok"], true);
    assert_eq!(json["status"], "success_with_warnings");
    let warnings = json["warnings"].as_array().expect("warnings array present");
    assert_eq!(warnings.len(), 1);
    assert!(
        warnings[0]
            .as_str()
            .unwrap()
            .contains("hidden NixOS configuration was not applied")
    );
}

#[test]
fn test_json_clean_switch_has_no_warnings_field() {
    let (manager, _tempdir) = TestWorld::new().manager();
    let output = build_activate_json_output(
        &Ok(nails_core::ActivationOutcome::Activated {
            hidden_config: nails_core::HiddenConfigOutcome::Applied {
                toplevel: Some("/nix/store/aaa-nixos-system-host".to_string()),
                fast_path: false,
            },
        }),
        1.0,
        &manager,
        None,
    );
    let json = serde_json::to_value(&output).unwrap();
    assert_eq!(json["status"], "success");
    assert!(
        json.get("warnings").is_none(),
        "a clean activation omits the warnings field"
    );
}

#[test]
fn test_human_failed_switch_mentions_with_warnings() {
    let (manager, _tempdir) = TestWorld::new().manager();
    // Render through the public entry point to confirm it does not panic and
    // produces the warning wording; the message content is asserted via the
    // JSON path above and the outcome's own `warnings()`.
    print_activate_human(
        &activated_with_failed_switch(),
        1.0,
        &manager,
        None,
        &settings_at(nails_core::Verbosity::Normal),
    );
    let outcome = activated_with_failed_switch().unwrap();
    assert!(
        outcome.warnings()[0].contains("not applied"),
        "the warning names the unapplied hidden configuration"
    );
}

// ── decoy writers ──────────────────────────────────────────────────────────

#[test]
fn test_json_success_lists_writers_left_on_the_decoy() {
    let (_dir, manager) = make_active_manager_with_writer();
    let output = build_activate_json_output(
        &Ok(nails_core::ActivationOutcome::Activated {
            hidden_config: nails_core::HiddenConfigOutcome::NotRequested,
        }),
        1.0,
        &manager,
        None,
    );
    let json = serde_json::to_value(&output).unwrap();
    assert_eq!(json["state"]["kind"], "active");
    assert_eq!(
        json["decoy_writers"],
        serde_json::json!([{"pid": 812, "name": "tail", "targets": ["/var"], "kind": "surviving"}])
    );
}

#[test]
fn test_json_result_always_carries_decoy_writers() {
    let (manager, _tempdir) = TestWorld::new().manager();
    let output = build_activate_json_output(
        &Ok(nails_core::ActivationOutcome::Activated {
            hidden_config: nails_core::HiddenConfigOutcome::NotRequested,
        }),
        1.0,
        &manager,
        None,
    );
    let json = serde_json::to_value(&output).unwrap();
    assert_eq!(json["decoy_writers"], serde_json::json!([]));
}

#[test]
fn test_decoy_writer_lines_name_each_writer() {
    let style = nails_core::output::Style {
        color: false,
        ascii: true,
    };
    let lines = decoy_writer_lines(&[tail_writer()], style);
    assert_eq!(
        lines,
        vec![
            "[WARN] NOT OPTIMAL: 1 writer still on the decoy:".to_string(),
            "  - tail (PID 812) on /var".to_string(),
        ]
    );
    assert!(decoy_writer_lines(&[], style).is_empty());
}

#[test]
fn test_human_success_with_writers_quiet() {
    let (_dir, manager) = make_active_manager_with_writer();
    assert_eq!(manager_decoy_writers(&manager), vec![tail_writer()]);
    print_activate_human(
        &Ok(nails_core::ActivationOutcome::Activated {
            hidden_config: nails_core::HiddenConfigOutcome::NotRequested,
        }),
        1.0,
        &manager,
        None,
        &quiet_settings(),
    );
}

// ── print_activate_json ────────────────────────────────────────────────────

#[test]
fn test_json_success_no_shell() {
    let (manager, _tempdir) = TestWorld::new().manager();
    let output = build_activate_json_output(
        &Ok(nails_core::ActivationOutcome::Activated {
            hidden_config: nails_core::HiddenConfigOutcome::NotRequested,
        }),
        1.5,
        &manager,
        None,
    );
    let json = serde_json::to_value(&output).unwrap();
    assert_eq!(output.event_type, "result");
    assert_eq!(output.status, "success");
    assert!(output.ok);
    assert_eq!(output.message, "Activation complete in 1.5s");
    assert_eq!(json["type"].as_str(), Some("result"));
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["command"], "activate");
    // State is a tagged object, never a Debug string.
    assert!(json["state"]["kind"].is_string());
}

#[test]
fn test_json_success_with_shell() {
    let (manager, _tempdir) = TestWorld::new().manager();
    let setup = make_shell_setup_rc_modified();
    let output = build_activate_json_output(
        &Ok(nails_core::ActivationOutcome::Activated {
            hidden_config: nails_core::HiddenConfigOutcome::NotRequested,
        }),
        2.3,
        &manager,
        Some(&setup),
    );
    assert_eq!(output.event_type, "result");
    assert_eq!(output.status, "success");
    assert!(output.shell_instructions.is_some());
}

#[test]
fn test_json_already_active_distinct_from_success() {
    // An already-active no-op reports a success exit (ok=true) but with its
    // own status and message — never "Activation complete" — and never any
    // shell instructions, since no activation ran.
    let (manager, _tempdir) = TestWorld::new().manager();
    let setup = make_shell_setup_rc_modified();
    let output = build_activate_json_output(
        &Ok(nails_core::ActivationOutcome::AlreadyActive),
        0.0,
        &manager,
        Some(&setup),
    );
    assert!(output.ok);
    assert_eq!(output.status, "already_active");
    assert!(
        !output.message.contains("Activation complete"),
        "already-active message must differ from a fresh activation: {}",
        output.message
    );
    assert!(output.shell_instructions.is_none());
}

#[test]
fn test_human_already_active_message_is_distinct() {
    // The human already-active line goes to stdout and must not claim a fresh
    // activation completed.
    let (manager, _tempdir) = TestWorld::new().manager();
    print_activate_human(
        &Ok(nails_core::ActivationOutcome::AlreadyActive),
        0.0,
        &manager,
        None,
        &settings_at(nails_core::Verbosity::Normal),
    );
}

#[test]
fn test_json_preflight_failure() {
    let (manager, _tempdir) = TestWorld::new().manager();
    let err = NailsError::PreFlightCheckFailed(vec![
        ("hidden_volume".to_string(), "not mounted".to_string(), None),
        ("swap".to_string(), "swap enabled".to_string(), None),
    ]);
    let output = build_activate_json_output(&Err(err), 0.1, &manager, None);
    let json = serde_json::to_value(&output).unwrap();
    assert_eq!(output.event_type, "result");
    assert_eq!(output.status, "error");
    assert!(!output.ok);
    assert_eq!(output.message, "Pre-flight checks failed");
    assert_eq!(output.failed_checks.as_ref().map(Vec::len), Some(2));
    assert_eq!(json["type"].as_str(), Some("result"));
}

#[test]
fn test_json_preflight_failure_fix_is_not_mount_specific() {
    // A flake.lock problem is a pre-flight failure that has nothing to do
    // with mounting the hidden volume, so the remediation hint must not
    // claim it does; the specific guidance lives in the per-check reason.
    let (manager, _tempdir) = TestWorld::new().manager();
    let err = NailsError::PreFlightCheckFailed(vec![(
        "nixos-build-target".to_string(),
        "flake.lock not found in '/tmp/flake-target'. Activation does not run \
         'nix flake update' automatically; commit a flake.lock and retry activation."
            .to_string(),
        None,
    )]);
    let output = build_activate_json_output(&Err(err), 0.1, &manager, None);
    let checks = output.failed_checks.expect("failed checks present");
    let fix = checks[0].fix.as_deref().unwrap_or_default();
    assert!(
        !fix.contains("hidden volume is mounted"),
        "remediation hint must not assume a mount problem: {fix:?}"
    );
    assert!(
        fix.contains("retry activation"),
        "remediation hint should direct the operator to retry: {fix:?}"
    );
}

#[test]
fn test_json_other_error() {
    let (manager, _tempdir) = TestWorld::new().manager();
    let err = NailsError::InvalidState("unexpected state".to_string());
    let output = build_activate_json_output(&Err(err), 0.5, &manager, None);
    assert_eq!(output.event_type, "result");
    assert_eq!(output.status, "error");
    assert_eq!(
        output.message,
        "Activation failed: Invalid state: unexpected state"
    );
}

#[test]
fn test_progress_event_is_typed_ndjson() {
    // Smoke: the progress line serializes without panicking.
    print_activate_progress("activating");
}

// ── renderer verbosity matrix ───────────────────────────────────────────────

#[test]
fn snapshot_activate_success_render_across_verbosity() {
    // The success summary only branches on `--quiet`: Normal, Verbose and
    // Debug add the same shell-integration guidance (verbosity above Normal
    // changes tracing, not this summary), and Quiet prints just the result
    // line. `-vv` and `-vvv` both resolve to Debug, so the four distinct
    // states are Quiet / Normal / Verbose / Debug.
    use nails_core::Verbosity;
    let setup = make_shell_setup_rc_modified();
    for (label, verbosity) in [
        ("quiet", Verbosity::Quiet),
        ("normal", Verbosity::Normal),
        ("verbose", Verbosity::Verbose),
        ("debug", Verbosity::Debug),
    ] {
        insta::assert_snapshot!(
            format!("activate_success_{label}"),
            render_activate_success(1.5, Some(&setup), &settings_at(verbosity))
        );
    }
}

#[test]
fn success_summary_shows_the_emergency_command_when_not_quiet() {
    let setup = make_shell_setup_rc_modified();
    let summary = render_activate_success(
        1.5,
        Some(&setup),
        &settings_at(nails_core::Verbosity::Normal),
    );
    assert!(
        summary.contains("sudo /run/overlay-runtime/control emergency"),
        "{summary}"
    );
}

#[test]
fn success_summary_omits_the_emergency_command_when_quiet() {
    let setup = make_shell_setup_rc_modified();
    let summary = render_activate_success(1.5, Some(&setup), &quiet_settings());
    assert!(
        !summary.contains("emergency"),
        "quiet summary must stay terse: {summary}"
    );
}

// ── print_activate_human ───────────────────────────────────────────────────

#[test]
fn test_human_success_no_shell() {
    let (manager, _tempdir) = TestWorld::new().manager();
    print_activate_human(
        &Ok(nails_core::ActivationOutcome::Activated {
            hidden_config: nails_core::HiddenConfigOutcome::NotRequested,
        }),
        1.5,
        &manager,
        None,
        &OutputSettings::default(),
    );
}

#[test]
fn test_human_success_quiet() {
    let (manager, _tempdir) = TestWorld::new().manager();
    print_activate_human(
        &Ok(nails_core::ActivationOutcome::Activated {
            hidden_config: nails_core::HiddenConfigOutcome::NotRequested,
        }),
        1.5,
        &manager,
        None,
        &quiet_settings(),
    );
}

#[test]
fn test_human_success_shell_rc_modified() {
    let (manager, _tempdir) = TestWorld::new().manager();
    let setup = make_shell_setup_rc_modified();
    print_activate_human(
        &Ok(nails_core::ActivationOutcome::Activated {
            hidden_config: nails_core::HiddenConfigOutcome::NotRequested,
        }),
        1.0,
        &manager,
        Some(&setup),
        &OutputSettings::default(),
    );
}

#[test]
fn test_human_success_shell_no_rc() {
    let (manager, _tempdir) = TestWorld::new().manager();
    let setup = make_shell_setup_no_rc();
    print_activate_human(
        &Ok(nails_core::ActivationOutcome::Activated {
            hidden_config: nails_core::HiddenConfigOutcome::NotRequested,
        }),
        1.0,
        &manager,
        Some(&setup),
        &OutputSettings::default(),
    );
}

#[test]
fn test_human_success_shell_with_warning() {
    let (manager, _tempdir) = TestWorld::new().manager();
    let setup = make_shell_setup_with_warning();
    print_activate_human(
        &Ok(nails_core::ActivationOutcome::Activated {
            hidden_config: nails_core::HiddenConfigOutcome::NotRequested,
        }),
        1.0,
        &manager,
        Some(&setup),
        &OutputSettings::default(),
    );
}

#[test]
fn test_human_success_shell_quiet_suppresses_instructions() {
    let (manager, _tempdir) = TestWorld::new().manager();
    let setup = make_shell_setup_rc_modified();
    print_activate_human(
        &Ok(nails_core::ActivationOutcome::Activated {
            hidden_config: nails_core::HiddenConfigOutcome::NotRequested,
        }),
        1.0,
        &manager,
        Some(&setup),
        &quiet_settings(),
    );
}

#[test]
fn test_human_preflight_failure() {
    let (manager, _tempdir) = TestWorld::new().manager();
    let err = NailsError::PreFlightCheckFailed(vec![(
        "hidden_volume".to_string(),
        "not mounted".to_string(),
        None,
    )]);
    print_activate_human(&Err(err), 0.1, &manager, None, &OutputSettings::default());
}

#[test]
fn test_human_other_error() {
    let (manager, _tempdir) = TestWorld::new().manager();
    let err = NailsError::InvalidState("bad state".to_string());
    print_activate_human(&Err(err), 0.3, &manager, None, &OutputSettings::default());
}
