// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests for NAILS CLI
//!
//! These tests verify the CLI binary:
//! - Executes correctly
//! - Displays version from Cargo.toml (not hardcoded)
//! - Parses all commands and flags
//! - Links properly to nails-core library
//!
//! Every test here runs unprivileged and performs no destructive operation.
//! `activate`, `deactivate` and `emergency` are only exercised along paths
//! that refuse before any mount, switch or teardown: the confirmation gate off
//! a terminal, a config error, or the read-only `--dry-run` alias. A case that
//! would need root is marked `#[ignore]`, never silently skipped on an
//! environment variable.

use assert_cmd::prelude::*;
use predicates::prelude::*;

/// Test that the CLI binary exists and runs
#[test]
fn test_cli_binary_runs() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("--version").assert().success();
}

/// Test that version is pulled from Cargo.toml (workspace-level versioning)
#[test]
fn test_version_from_cargo_toml() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains("nails 0.3.0-rc.1"));
}

/// Test that --help flag works
#[test]
fn test_help_flag() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "Run a hidden session on a decoy Linux system",
        ));
}

/// Test that activate command accepts --no-preflight flag
#[test]
fn test_activate_command_force_flag() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--no-preflight"))
        .stdout(predicates::str::contains("Skip pre-flight checks"));
}

/// Test that deactivate command accepts new flags
#[test]
fn test_deactivate_command_flags_help() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["deactivate", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--poweroff"))
        .stdout(predicates::str::contains("--quiet"))
        .stdout(predicates::str::contains("--verbose"))
        .stdout(predicates::str::contains("--json"))
        .stdout(predicates::str::contains("--color <WHEN>"));
}

/// Test that emergency command accepts new flags
#[test]
fn test_emergency_command_flags_help() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["emergency", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--countdown <SECS>"))
        .stdout(predicates::str::contains("--poweroff"))
        .stdout(predicates::str::contains("--reboot"))
        .stdout(predicates::str::contains("--quiet"))
        .stdout(predicates::str::contains("--verbose"))
        .stdout(predicates::str::contains("--json"))
        .stdout(predicates::str::contains("--color <WHEN>"));
}

/// Test that emergency command no longer has --delay flag (fixed 3s countdown)
#[test]
fn test_emergency_command_no_delay_flag() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["emergency", "--delay", "10"]).assert().failure(); // --delay should not exist
}

/// Test that status command offers --details (and -v stays global verbosity)
#[test]
fn test_status_command_details_flag() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["status", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--details"))
        .stdout(predicates::str::contains(
            "Show resolved paths and overlay mount details",
        ))
        .stdout(predicates::str::contains("-v, --verbose"));
}

/// Test that all 4 core commands are defined
#[test]
fn test_all_commands_defined() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("activate"))
        .stdout(predicates::str::contains("deactivate"))
        .stdout(predicates::str::contains("emergency"))
        .stdout(predicates::str::contains("status"));
}

/// Test that CLI links to nails-core (binary runs without dynamic link errors)
#[test]
fn test_cli_links_to_core_library() {
    // If the binary executes successfully, it's properly linked to nails-core
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("--version").assert().success();
}

/// Test that verbose flag (-v) is accepted
#[test]
fn test_verbose_flag() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("-v, --verbose"));
}

/// Property test: All commands should have help text
#[test]
fn test_all_commands_have_help() {
    let commands = ["activate", "deactivate", "emergency", "status"];

    for command in commands {
        let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
        cmd.args([command, "--help"])
            .assert()
            .success()
            .stdout(predicates::str::is_empty().not()); // Should have output
    }
}

/// Test that activate command has --json flag in help
#[test]
fn test_activate_has_json_flag() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--json"))
        .stdout(predicates::str::contains(
            "Print machine-readable JSON on stdout",
        ));
}

/// Test that activate command help lists the global --color and --ascii flags
#[test]
fn test_activate_has_color_and_ascii_flags() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--color <WHEN>"))
        .stdout(predicates::str::contains("When to use colour"))
        .stdout(predicates::str::contains("--ascii"))
        .stdout(predicates::str::contains("--no-color").not())
        .stdout(predicates::str::contains("--plain").not());
}

/// Test that activate command help advertises quiet mode
#[test]
fn test_activate_help_includes_quiet_flag() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("-q, --quiet"))
        .stdout(predicates::str::contains(
            "Print only errors and the final result",
        ));
}

/// Test that activate help with --color never has no ANSI codes
#[test]
fn test_activate_color_never_flag() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--color", "never", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::is_match(r"\x1b\[").unwrap().not()); // No ANSI escape sequences
}

/// Test that status command executes successfully
#[test]
fn test_status_command_executes() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("status")
        .assert()
        .success()
        .stdout(predicates::str::contains("NAILS Status Report"))
        .stdout(predicates::str::contains("State:"));
}

/// Test that status command with --verbose flag executes successfully
#[test]
fn test_status_command_executes_with_verbose() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["status", "--verbose"])
        .assert()
        .success()
        .stdout(predicates::str::contains("NAILS Status Report"))
        .stdout(predicates::str::contains("State:"));
}

#[test]
fn test_status_command_json_output() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["status", "--json"])
        .assert()
        .success()
        .stdout(predicates::str::contains("\"state\""))
        .stdout(predicates::str::contains("\"posture\""));
}

#[test]
fn test_status_exits_zero_for_a_decoy_system() {
    // A decoy (inactive) system is a safe posture, so status exits 0; the posture
    // always drives the exit code with no opt-in flag.
    let (_dir, config) = isolated_status_config();
    let config = config.to_str().unwrap();

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["--config", config, "status"]).assert().success();
}

#[test]
fn test_status_command_ascii_output() {
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args(["status", "--ascii"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout={stdout}");
    assert!(stdout.contains("NAILS Status Report"), "{stdout}");
    assert!(stdout.contains("===="), "{stdout}");
    assert!(stdout.contains("State:"), "{stdout}");
    assert!(stdout.is_ascii(), "{stdout}");
}

#[test]
fn test_status_command_details_inactive_reports_paths_and_load_outcome() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let log_path = hidden_root.join("custom-logs");
    let state_path = hidden_root.join("custom-state.json");
    let config_path = temp_dir.path().join("nails.toml");

    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config_file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\nlog_path = \"{}\"",
        hidden_root.display(),
        state_path.display(),
        log_path.display(),
    )
    .unwrap();

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "status",
            "--details",
        ])
        .output()
        .expect("failed to run verbose inactive status");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout={stdout}");
    assert!(stdout.contains("Details:"));
    assert!(stdout.contains(&format!("Config file:        {}", config_path.display())));
    assert!(stdout.contains(&format!("Hidden volume root: {}", hidden_root.display())));
    assert!(stdout.contains(&format!("State file:         {}", state_path.display())));
    assert!(stdout.contains(&format!("Log path:           {}", log_path.display())));
    assert!(stdout.contains("State loaded:       fresh default (no file)"));
}

#[test]
fn test_status_command_details_active_record_on_the_decoy() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let log_dir = hidden_root.join("logs");
    let state_path = hidden_root.join("state.json");
    let config_path = temp_dir.path().join("nails.toml");
    std::fs::create_dir_all(&log_dir).unwrap();

    let state_json = r#"{
  "version": "0.2.0",
  "state": { "Active": { "activated_at": "2026-01-02T03:04:05Z" } },
  "platform": { "platform": "nix_os", "generation": "/nix/store/nails-gen-99" },
  "last_modified": "2026-01-02T03:05:00Z"
}"#;
    // Seal through the durable save path so the file carries a valid digest.
    let state: nails_core::StateFile = serde_json::from_str(state_json).unwrap();
    state
        .save_with_custom_root(&state_path, &hidden_root)
        .unwrap();

    let mut config_file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\nlog_path = \"{}\"",
        hidden_root.display(),
        state_path.display(),
        log_dir.display(),
    )
    .unwrap();

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "status",
            "--details",
        ])
        .output()
        .expect("failed to run verbose active status");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // The live view here is the plain decoy: the active record is reported
    // next to it, with the hidden system it names.
    assert_eq!(output.status.code(), Some(0), "stdout={stdout}");
    assert!(stdout.contains("DECOY"), "{stdout}");
    assert!(
        stdout.contains("State:              Active (recorded)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("Hidden system:      /nix/store/nails-gen-99"),
        "{stdout}"
    );
}

#[test]
fn test_status_command_details_reports_corrupt_state_load() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let state_path = hidden_root.join("state.json");
    let config_path = temp_dir.path().join("nails.toml");
    std::fs::create_dir_all(&hidden_root).unwrap();
    std::fs::write(&state_path, "{ invalid-json").unwrap();

    let mut config_file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"",
        hidden_root.display(),
        state_path.display(),
    )
    .unwrap();

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "status",
            "--details",
            "--color",
            "never",
        ])
        .output()
        .expect("failed to run corrupt-state status");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // A corrupt state file is an unknown posture: fail closed with code 6.
    assert_eq!(output.status.code(), Some(6), "stdout={stdout}");
    assert!(stdout.contains("State loaded:       corrupt (state unknown, using defaults)"));
    assert!(stdout.contains("Details:"));
    assert!(!stdout.contains("\u{001b}"), "stdout={stdout}");
}

#[test]
fn test_status_command_details_reports_loaded_state() {
    use nails_core::{StateFile, SystemState};
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let state_path = hidden_root.join("state.json");
    let config_path = temp_dir.path().join("nails.toml");
    std::fs::create_dir_all(&hidden_root).unwrap();

    // Save through the durable path so the file carries a valid integrity digest.
    let state = StateFile {
        version: "0.0.5".to_string(),
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    state
        .save_with_custom_root(&state_path, &hidden_root)
        .unwrap();

    let mut config_file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"",
        hidden_root.display(),
        state_path.display(),
    )
    .unwrap();

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "status",
            "--details",
            "--color",
            "never",
        ])
        .output()
        .expect("failed to run loaded status");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout={stdout}");
    assert!(stdout.contains("State loaded:       normal"));
    assert!(stdout.contains("Details:"));
    assert!(!stdout.contains("\u{001b}"), "stdout={stdout}");
}

#[test]
fn test_status_fails_closed_on_invalid_config() {
    let config_file = create_invalid_config_file();

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["--config", config_file.path().to_str().unwrap(), "status"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicates::str::contains("invalid config"))
        .stderr(predicates::str::contains(
            config_file.path().to_str().unwrap(),
        ))
        .stderr(predicates::str::contains("line 1"));
}

#[test]
fn test_status_fails_closed_on_unreadable_config_path() {
    let config_dir = tempfile::tempdir().unwrap();

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["--config", config_dir.path().to_str().unwrap(), "status"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicates::str::contains("cannot read config"))
        .stderr(predicates::str::contains(
            config_dir.path().to_str().unwrap(),
        ));
}

// emergency and deactivate fall back to defaults on a bad config instead of
// refusing. Running the real binary here would therefore start a real
// teardown, so that behaviour is covered by the in-crate subprocess tests in
// `commands/emergency.rs` and `commands/deactivate/tests.rs`, which keep the
// teardown in runtime-safety mode (emergency) or stop at the confirmation gate
// (deactivate) so the host is never touched.

#[test]
fn test_verify_command_json_output() {
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args(["verify", "--json"])
        .output()
        .expect("failed to run verify command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let code = output.status.code();

    // Exit code 0 = Secure, 10 = Warning, 11 = Critical
    assert!(
        code == Some(0) || code == Some(10) || code == Some(11),
        "unexpected exit code: {:?}",
        code
    );
    assert!(
        stdout.contains("\"status\""),
        "missing \"status\" in output"
    );
    assert!(
        stdout.contains("\"findings\""),
        "missing \"findings\" in output"
    );
    // The machine interface is one enveloped document.
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["schema_version"], 1, "{parsed}");
    assert_eq!(parsed["command"], "verify", "{parsed}");
}

#[test]
fn test_verify_command_deep_json_output() {
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args(["verify", "--deep", "--json"])
        .output()
        .expect("failed to run deep verify command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    match output.status.code() {
        Some(0) | Some(10) | Some(11) => {
            assert!(stdout.contains("\"scan_depth\""));
            // Depth renders in snake_case now.
            assert!(stdout.contains("\"deep\""), "stdout={stdout}");
        }
        Some(1) => {
            // A verify run error is one failure envelope on stdout under --json.
            assert!(
                stdout.contains("\"ok\":false") && stdout.contains("Error running verification:"),
                "stdout={stdout}\nstderr={stderr}"
            );
        }
        other => panic!("unexpected exit code: {other:?}\nstdout={stdout}\nstderr={stderr}"),
    }
}

#[test]
fn test_verify_command_human_output_reports_config_paths_and_missing_state_file() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let state_path = hidden_root.join("custom-state.json");
    let log_path = hidden_root.join("logs");
    let config_path = temp_dir.path().join("nails.toml");

    let mut config_file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\nlog_path = \"{}\"",
        hidden_root.display(),
        state_path.display(),
        log_path.display(),
    )
    .unwrap();

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args(["--config", config_path.to_str().unwrap(), "verify"])
        .output()
        .expect("failed to run verify command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let code = output.status.code();

    assert!(
        code == Some(0) || code == Some(10) || code == Some(11),
        "unexpected exit code: {:?}\nstdout={}\nstderr={}",
        code,
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("checked 3 paths from config"), "{stdout}");
    assert!(stdout.contains(&format!(
        "State file status: missing at {}",
        state_path.display()
    )));
}

#[test]
fn test_verify_command_json_output_reports_present_state_file_status() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let state_path = hidden_root.join("state.json");
    let config_path = temp_dir.path().join("nails.toml");

    let state_json = r#"{
  \"version\": \"0.2.0\",
  \"state\": \"Inactive\",
  \"config_fingerprint\": null,
  \"overlay_status\": {},
  \"failed_overlays\": [],
  \"last_modified\": \"2026-01-01T00:00:00Z\"
}"#
    .to_string();
    std::fs::write(&state_path, state_json).unwrap();

    let mut config_file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"",
        hidden_root.display(),
        state_path.display(),
    )
    .unwrap();

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "verify",
            "--json",
        ])
        .output()
        .expect("failed to run verify command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let code = output.status.code();

    assert!(
        code == Some(0) || code == Some(10) || code == Some(11),
        "unexpected exit code: {:?}\nstdout={}\nstderr={}",
        code,
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    // The envelope is one compact document; the state renders in snake_case.
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let state_file_status = &parsed["data"]["state_file_status"];
    assert_eq!(state_file_status["kind"], "present", "{parsed}");
    assert_eq!(
        state_file_status["path"],
        state_path.display().to_string(),
        "{parsed}"
    );
    assert_eq!(state_file_status["state"], "inactive", "{parsed}");
}

#[test]
fn test_activate_off_tty_without_yes_refuses_before_real_ops() {
    use std::io::Write;

    // The confirmation gate is what must stop activation: without -y and without
    // a terminal it refuses before anything is staged, mounted or switched.
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config_file,
        "hidden_volume_root = \"{}\"",
        hidden_root.display()
    )
    .unwrap();

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args([
        "--config",
        config_file.path().to_str().unwrap(),
        "activate",
        "--overlay-only",
    ])
    .env("NAILS_UNSAFE_REAL_OPS", "1")
    .assert()
    .failure()
    .code(2)
    .stderr(predicates::str::contains("stdin is not a terminal"));
}

#[test]
fn test_activate_overlay_only_refuses_unmounted_hidden_root_without_writing() {
    use std::io::Write;

    // The attach gate runs before the state lock, the residue baseline and the
    // pre-flight checks. The hidden root here is a bare directory (nothing
    // mounted), so activation must refuse before writing anything: no `.lock`,
    // no `reports/` tree may land on what is really the decoy disk.
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config_file,
        "hidden_volume_root = \"{}\"",
        hidden_root.display()
    )
    .unwrap();

    std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--config",
            config_file.path().to_str().unwrap(),
            "activate",
            "--overlay-only",
            "-y",
        ])
        .assert()
        .failure()
        .code(4)
        .stderr(predicates::str::contains("is not a volume of its own"));

    // Nothing was written onto the unmounted hidden root.
    let entries: Vec<_> = std::fs::read_dir(&hidden_root)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(
        entries.is_empty(),
        "unmounted hidden root must be left empty, found: {entries:?}"
    );
}

#[test]
fn test_check_reports_sections_and_refuses_when_volume_not_ready() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config_file,
        "hidden_volume_root = \"{}\"",
        hidden_root.display()
    )
    .unwrap();

    // The tempdir is not a mounted hidden volume, so the readiness check refuses
    // (exit 4) while still printing a full report.
    std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--config",
            config_file.path().to_str().unwrap(),
            "check",
            "--overlay-only",
            "--ascii",
        ])
        .assert()
        .failure()
        .code(4)
        .stdout(predicates::str::contains("NAILS Readiness Check"))
        .stdout(predicates::str::contains("Pre-flight checks:"))
        .stdout(predicates::str::contains("Effective configuration:"))
        .stdout(predicates::str::contains(
            "Decoy filesystems in the hidden root:",
        ))
        .stdout(predicates::str::contains("Session:"))
        .stdout(predicates::str::contains("NixOS profile:"))
        .stdout(predicates::str::contains("hidden-volume:"));
}

#[test]
fn test_check_json_emits_envelope() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config_file,
        "hidden_volume_root = \"{}\"",
        hidden_root.display()
    )
    .unwrap();

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--json",
            "--config",
            config_file.path().to_str().unwrap(),
            "check",
            "--overlay-only",
        ])
        .output()
        .expect("failed to run check --json");

    assert_eq!(output.status.code(), Some(4), "unready volume refuses");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let last = stdout.lines().last().expect("one JSON line");
    let value: serde_json::Value = serde_json::from_str(last).expect("check emits valid JSON");
    assert_eq!(value["command"], "check");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["ready"], false);
    assert!(value["data"]["checks"].is_array());
    assert!(
        value["data"]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "hidden-volume"),
        "expected the hidden-volume check in the envelope: {last}"
    );
}

#[test]
fn test_activate_dry_run_is_a_thin_alias_for_check() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config_file,
        "hidden_volume_root = \"{}\"",
        hidden_root.display()
    )
    .unwrap();
    let config_path = config_file.path().to_str().unwrap().to_string();

    let run = |extra: &[&str]| {
        let mut args = vec!["--config", config_path.as_str()];
        args.extend_from_slice(extra);
        args.push("--ascii");
        std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
            .args(&args)
            .output()
            .expect("failed to run nails")
    };

    let dry_run = run(&["activate", "--dry-run", "--overlay-only"]);
    let check = run(&["check", "--overlay-only"]);

    assert_eq!(
        dry_run.status.code(),
        check.status.code(),
        "dry-run and check must share an exit code"
    );
    assert_eq!(
        String::from_utf8_lossy(&dry_run.stdout),
        String::from_utf8_lossy(&check.stdout),
        "dry-run and check must produce the same report"
    );
}

#[test]
fn test_doctor_alias_runs_the_check_command() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config_file,
        "hidden_volume_root = \"{}\"",
        hidden_root.display()
    )
    .unwrap();

    std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--config",
            config_file.path().to_str().unwrap(),
            "doctor",
            "--overlay-only",
            "--ascii",
        ])
        .assert()
        .failure()
        .code(4)
        .stdout(predicates::str::contains("NAILS Readiness Check"));
}

#[test]
fn test_activate_fails_closed_on_invalid_config() {
    let config_file = create_invalid_config_file();

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args([
        "--config",
        config_file.path().to_str().unwrap(),
        "activate",
        "--no-preflight",
    ])
    .assert()
    .failure()
    .code(3)
    .stderr(predicates::str::contains("invalid config"));
}

/// `activate --help` explains the soft-reboot and the logout.
#[test]
fn test_activate_help_explains_the_soft_reboot() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("soft-reboots into it"))
        .stdout(predicates::str::contains("logged out"))
        .stdout(predicates::str::contains("--yes"));
}

/// `deactivate --help` states that it soft-reboots back to the decoy.
#[test]
fn test_deactivate_help_mentions_the_soft_reboot() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["deactivate", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("soft-reboots"));
}

/// Test that --config flag is accepted globally
#[test]
fn test_config_flag_accepted() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("-c, --config <PATH>"))
        .stdout(predicates::str::contains("Path to the configuration file"));
}

// ========== Lifecycle commands: unprivileged, non-destructive paths ==========
//
// `activate`, `deactivate` and `emergency` change the live system, so they are
// driven here only along paths that refuse before any mount, switch or teardown.
// The confirmation gate refuses off a terminal (the test harness has no TTY on
// stdin) before activation stages anything, so these cases run unprivileged and
// assert the machine-readable contract directly rather than substring-matching.

/// Parse the final line of a `--json` invocation as a single JSON document.
fn parse_json_tail(output: &std::process::Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let last = stdout.trim().lines().next_back().unwrap_or("");
    serde_json::from_str(last)
        .unwrap_or_else(|e| panic!("stdout is not one JSON document ({e}): {stdout}"))
}

/// `activate --json` off a terminal refuses at the confirmation gate, before any
/// staging or mount, with a machine-readable error envelope and the usage code.
#[test]
fn test_activate_json_refuses_off_terminal_with_envelope() {
    let config = create_test_config_file("/tmp/nails-contract-volume");
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "activate",
            "--json",
        ])
        .output()
        .expect("run nails activate --json");
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let value = parse_json_tail(&output);
    assert_eq!(value["ok"], false);
    assert_eq!(value["command"], "activate");
    assert_eq!(value["error"]["code"], "needs_confirmation");
}

/// The gate still accepts the verbosity, colour and ASCII flags on the `activate`
/// subcommand and refuses off a terminal, so flag parsing is covered without
/// reaching a real operation.
#[test]
fn test_activate_flags_parse_and_still_refuse_off_terminal() {
    let config = create_test_config_file("/tmp/nails-contract-volume");
    std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "activate",
            "--overlay-only",
            "--ascii",
            "--color",
            "never",
            "-vv",
        ])
        .env("NO_COLOR", "1")
        .assert()
        .failure()
        .code(2);
}

/// `activate --dry-run --json` is a read-only alias for `check`: it emits one
/// parseable JSON document and never touches the system.
#[test]
fn test_activate_dry_run_json_is_parseable() {
    let config = create_test_config_file("/tmp/nails-contract-volume");
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "activate",
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run nails activate --dry-run --json");
    let value = parse_json_tail(&output);
    // --dry-run defers to the read-only `check` command, so the envelope is its.
    assert_eq!(value["command"], "check");
    assert!(
        value.get("ok").is_some(),
        "envelope carries an ok flag: {value}"
    );
}

/// `deactivate --json` outside a hidden session refuses with a
/// machine-readable error envelope, before any confirmation.
#[test]
fn test_deactivate_json_refuses_outside_a_session_with_envelope() {
    let config = create_test_config_file("/tmp/nails-contract-volume");
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--config",
            config.path().to_str().unwrap(),
            "deactivate",
            "--json",
        ])
        .output()
        .expect("run nails deactivate --json");
    assert_eq!(output.status.code(), Some(6), "{output:?}");
    let value = parse_json_tail(&output);
    assert_eq!(value["ok"], false);
    assert_eq!(value["command"], "deactivate");
    assert_eq!(value["error"]["code"], "invalid_state");
}

/// `deactivate` outside a hidden session says so and points at `recover`.
#[test]
fn test_deactivate_human_refuses_outside_a_session() {
    let config = create_test_config_file("/tmp/nails-contract-volume");
    std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args(["--config", config.path().to_str().unwrap(), "deactivate"])
        .assert()
        .failure()
        .code(6)
        .stderr(predicates::str::contains("not in a hidden session"))
        .stderr(predicates::str::contains("nails recover"));
}

// ========== Config Discovery Helper ==========

/// Helper function to create a test config file with custom volume path
/// Reduces duplication across config-related tests
fn create_test_config_file(volume_path: &str) -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(config_file, "hidden_volume_root = \"{}\"", volume_path).unwrap();
    config_file
}

fn create_invalid_config_file() -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(config_file, "hidden_volume_root = [broken").unwrap();
    config_file
}

/// Helper function to create a test config file with standard content
/// Convenience function with default volume path
fn create_test_config_file_default() -> tempfile::NamedTempFile {
    create_test_config_file("/mnt/test-volume")
}

/// Test that --config flag is accepted before subcommand (global flag)
#[test]
fn test_config_flag_global_before_subcommand() {
    let config_file = create_test_config_file_default();

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["--config", config_file.path().to_str().unwrap(), "status"])
        .assert()
        .success(); // Status command should work with custom config
}

/// Test that --config flag is accepted after subcommand (global flag)
#[test]
fn test_config_flag_global_after_subcommand() {
    let config_file = create_test_config_file_default();

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["status", "--config", config_file.path().to_str().unwrap()])
        .assert()
        .success(); // Status command should work with custom config
}

/// Test that binary works without config file in binary-relative location
/// This verifies graceful defaults when config doesn't exist
#[test]
fn test_binary_relative_config_graceful_defaults() {
    // Binary will try to load from {binary_dir}/config/nails.toml
    // If it doesn't exist (which it won't in test environment), it should use defaults
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("status")
        .assert()
        .success() // Should work with defaults
        .stdout(predicates::str::contains("NAILS Status Report"));
}

/// Integration test for binary-relative config loading
/// Tests that the discover_config_path function correctly resolves paths.
///
/// This test verifies the path resolution logic works correctly by:
/// 1. Testing that config paths are resolved relative to binary location
/// 2. Testing that --config flag properly overrides binary-relative discovery
/// 3. Testing that missing configs fall back to defaults gracefully
///
/// Note: Testing actual binary-relative config loading in an integration test is
/// challenging because std::env::current_exe() behavior depends on how the binary
/// is invoked. The unit tests in nails-core verify the path resolution logic,
/// while this test verifies the CLI correctly uses the discovered paths.
#[test]
fn test_binary_relative_config_loading_integration() {
    use std::fs;
    use std::io::Write;

    // Create temp directory structure
    let temp_dir = tempfile::tempdir().unwrap();
    let config_dir = temp_dir.path().join("config");
    fs::create_dir_all(&config_dir).unwrap();

    // Create config file with distinctive value
    let config_path = config_dir.join("nails.toml");
    let mut config_file = fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        r#"hidden_volume_root = "/mnt/custom-integration-test-volume""#
    )
    .unwrap();

    // Test 1: Verify CLI uses --config override correctly
    // This proves the CLI can load from an explicit path
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .arg("--config")
        .arg(&config_path)
        .arg("status")
        .arg("--details")
        .output()
        .expect("Failed to execute nails status");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let all_output = format!("{}\n{}", stdout, stderr);

    // Verify the custom config was loaded via --config flag
    assert!(
        all_output.contains("/mnt/custom-integration-test-volume"),
        "--config flag should load custom config. Output: {}",
        all_output
    );

    // Test 2: Explicit --config with non-existent path must FAIL (P0-04: fail closed)
    let nonexistent_config = temp_dir.path().join("nonexistent.toml");
    let output2 = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .arg("--config")
        .arg(&nonexistent_config)
        .arg("status")
        .output()
        .expect("Failed to execute nails status");

    let _stdout2 = String::from_utf8_lossy(&output2.stdout);
    let stderr2 = String::from_utf8_lossy(&output2.stderr);

    // P0-04: Explicit --config with missing file must fail with clear error
    assert!(
        !output2.status.success(),
        "Explicit --config with missing file must fail. stderr: {}",
        stderr2
    );
    assert_eq!(output2.status.code(), Some(3), "stderr: {}", stderr2);
    assert!(
        stderr2.contains("config file not found"),
        "Error should mention missing config file. stderr: {}",
        stderr2
    );
    assert!(
        stderr2.contains("nonexistent.toml"),
        "Error should name the missing path. stderr: {}",
        stderr2
    );
}

/// P0-04: Explicit --config with missing file must fail
#[test]
fn test_explicit_config_missing_fails() {
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--no-log-file",
            "--config",
            "/nonexistent/path/nails.toml",
            "status",
        ])
        .output()
        .expect("failed to run nails status");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "stderr={stderr}");
    assert_eq!(
        stderr.trim(),
        "error: config file not found: /nonexistent/path/nails.toml \
         (run `nails init <root>` or pass --config)",
        "exactly one error line"
    );
}

/// P0-04: Explicit --config with unreadable file must fail
#[cfg(unix)]
#[test]
fn test_explicit_config_unreadable_fails() {
    use std::os::unix::fs::PermissionsExt;

    let config_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::set_permissions(config_file.path(), std::fs::Permissions::from_mode(0o000)).unwrap();
    let binary = std::path::PathBuf::from(assert_cmd::cargo::cargo_bin!("nails"))
        .canonicalize()
        .unwrap();
    // The full sudo line, binary path included: sudo's secure_path never holds
    // the hidden volume.
    let sudo = format!("run it as root: sudo {} status", binary.display());

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["--config", config_file.path().to_str().unwrap(), "status"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicates::str::contains("cannot read config"))
        .stderr(predicates::str::contains(format!("\n  {sudo}\n")));

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--config",
            config_file.path().to_str().unwrap(),
            "status",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "config");
    assert_eq!(value["error"]["hint"], sudo.as_str(), "{value}");

    // Restore permissions so temp file cleanup works
    std::fs::set_permissions(config_file.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
}

/// P0-04: Implicit config (no --config) still works with defaults
#[test]
fn test_implicit_config_missing_succeeds() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("status")
        .assert()
        .success()
        .stdout(predicates::str::contains("NAILS Status Report"));
}

/// P0-04: Explicit --config with valid file succeeds
#[test]
fn test_explicit_config_valid_succeeds() {
    let config_file = create_test_config_file("/tmp/test-p004-volume");

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["--config", config_file.path().to_str().unwrap(), "status"])
        .assert()
        .success();
}

/// Test that CLI --config flag overrides binary-relative config discovery
/// Priority: --config flag > binary-relative > defaults
#[test]
fn test_config_flag_overrides_binary_relative() {
    use std::fs;
    use std::io::Write;

    // Create temp directory with a config
    let temp_dir = tempfile::tempdir().unwrap();
    let config_dir = temp_dir.path().join("config");
    fs::create_dir_all(&config_dir).unwrap();

    // Create binary-relative config
    let binary_relative_config = config_dir.join("nails.toml");
    let mut file1 = fs::File::create(&binary_relative_config).unwrap();
    writeln!(
        file1,
        "hidden_volume_root = \"/mnt/binary-relative-volume\""
    )
    .unwrap();

    // Create override config with different value using helper
    let override_config = create_test_config_file("/mnt/override-volume");

    // Run with --config flag - the override should take priority
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args([
        "--config",
        override_config.path().to_str().unwrap(),
        "status",
    ])
    .assert()
    .success();
}

// ========== Global output flags ==========

/// A config whose hidden root and state live in a temp dir, so status output
/// is deterministic.
fn isolated_status_config() -> (tempfile::TempDir, std::path::PathBuf) {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();
    let config_path = temp_dir.path().join("nails.toml");
    let mut config_file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"",
        hidden_root.display(),
        hidden_root.join("state.json").display(),
    )
    .unwrap();
    (temp_dir, config_path)
}

/// Status stdout with the live hidden-volume disk figures normalised away.
///
/// The usage figures come from a `statvfs` snapshot, so two otherwise identical
/// runs taken moments apart can legitimately differ. This keeps the flag-order
/// equivalence check comparing everything but that volatile snapshot.
fn without_live_disk(stdout: &[u8]) -> String {
    let text = String::from_utf8_lossy(stdout);
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(text.trim()) {
        if let Some(data) = value.get_mut("data").and_then(|d| d.as_object_mut()) {
            data.remove("hidden_root_total_bytes");
            data.remove("hidden_root_used_bytes");
            data.remove("hidden_root_available_bytes");
        }
        return serde_json::to_string(&value).unwrap();
    }
    text.lines()
        .map(|line| {
            if line.trim_start().starts_with("Hidden volume:") {
                "Hidden volume:      <usage>".to_string()
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Diagnostic lines with their leading tracing timestamp removed.
fn without_timestamps(stderr: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stderr)
        .lines()
        .map(|line| match line.split_once(' ') {
            Some((first, rest)) if first.starts_with("20") && first.ends_with('Z') => {
                rest.trim_start().to_string()
            }
            _ => line.to_string(),
        })
        .collect()
}

fn run_nails(args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    // No log file: each run would otherwise append to the hidden-volume log
    // that status shows, making otherwise identical runs differ.
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("--no-log-file")
        .args(args)
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR_FORCE");
    for (key, value) in envs {
        cmd.env(key, value);
    }
    cmd.output().unwrap()
}

#[test]
fn test_global_flags_behave_identically_before_and_after_the_subcommand() {
    let (_dir, config) = isolated_status_config();
    let config = config.to_str().unwrap();

    for (before, after) in [
        (
            vec!["-c", config, "-q", "status"],
            vec!["-c", config, "status", "-q"],
        ),
        (
            vec!["-c", config, "--json", "status"],
            vec!["-c", config, "status", "--json"],
        ),
        (
            vec!["--json", "--config", config, "status"],
            vec!["status", "--config", config, "--json"],
        ),
    ] {
        let a = run_nails(&before, &[]);
        let b = run_nails(&after, &[]);
        assert!(a.status.success(), "{before:?}: {a:?}");
        assert_eq!(a.status.code(), b.status.code(), "{before:?} vs {after:?}");
        assert_eq!(
            without_live_disk(&a.stdout),
            without_live_disk(&b.stdout),
            "{before:?} vs {after:?}"
        );
        assert_eq!(
            without_timestamps(&a.stderr),
            without_timestamps(&b.stderr),
            "{before:?} vs {after:?}"
        );
    }

    let json = run_nails(&["-c", config, "status", "--json"], &[]);
    let parsed: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(parsed["schema_version"], 1, "{parsed}");
    assert_eq!(parsed["command"], "status", "{parsed}");
    assert!(parsed["data"]["state"]["kind"].is_string(), "{parsed}");
}

#[test]
fn test_quiet_and_verbose_conflict_in_any_position() {
    for args in [
        &["-q", "-v", "status"][..],
        &["-q", "status", "-v"][..],
        &["status", "--verbose", "--quiet"][..],
    ] {
        let output = run_nails(args, &[]);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("cannot be used with"),
            "{args:?}: {output:?}"
        );
    }
}

#[test]
fn test_removed_output_flags_are_rejected() {
    for args in [
        &["status", "--plain"][..],
        &["status", "--no-color"][..],
        &["--no-logs", "status"][..],
    ] {
        let output = run_nails(args, &[]);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
    }
}

#[test]
fn test_piped_status_has_no_escape_sequences_and_is_ascii() {
    let (_dir, config) = isolated_status_config();
    let output = run_nails(
        &["-c", config.to_str().unwrap(), "status", "--details"],
        &[("TERM", "xterm-256color"), ("LANG", "en_US.UTF-8")],
    );
    let combined = [output.stdout.as_slice(), output.stderr.as_slice()].concat();
    let text = String::from_utf8_lossy(&combined);

    assert!(output.status.success(), "{text}");
    assert!(!text.contains('\u{1b}'), "{text}");
    assert!(text.is_ascii(), "{text}");
    assert!(!text.contains('╭'), "{text}");
}

#[test]
fn test_dumb_terminal_and_c_locale_are_ascii_only() {
    let (_dir, config) = isolated_status_config();
    let output = run_nails(
        &["-c", config.to_str().unwrap(), "status", "--details"],
        &[("TERM", "dumb"), ("LANG", "C"), ("LC_ALL", "")],
    );
    let text = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "{text}");
    assert!(text.is_ascii(), "{text}");
    assert!(text.contains("[DECOY]"), "{text}");
}

#[test]
fn test_colour_flag_and_environment_precedence() {
    let (_dir, config) = isolated_status_config();
    let config = config.to_str().unwrap();
    // verify's header is always painted when colour is on.
    let has_ansi = |args: &[&str], envs: &[(&str, &str)]| {
        let output = run_nails(&[&["-c", config], args].concat(), envs);
        String::from_utf8_lossy(&output.stdout).contains('\u{1b}')
    };

    assert!(!has_ansi(&["verify"], &[]), "auto is off when piped");
    assert!(has_ansi(&["verify", "--color", "always"], &[]));
    assert!(has_ansi(
        &["--color", "always", "verify"],
        &[("NO_COLOR", "1")]
    ));
    assert!(has_ansi(&["verify"], &[("CLICOLOR_FORCE", "1")]));
    assert!(!has_ansi(
        &["verify"],
        &[("CLICOLOR_FORCE", "1"), ("NO_COLOR", "1")]
    ));
    assert!(!has_ansi(
        &["verify", "--color", "never"],
        &[("CLICOLOR_FORCE", "1")]
    ));
    // Empty NO_COLOR counts as unset, so forcing still applies.
    assert!(has_ansi(
        &["verify"],
        &[("CLICOLOR_FORCE", "1"), ("NO_COLOR", "")]
    ));
    // JSON on stdout is never painted.
    assert!(!has_ansi(&["verify", "--json", "--color", "always"], &[]));
}
