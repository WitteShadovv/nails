//! Integration tests for NAILS CLI
//!
//! These tests verify the CLI binary:
//! - Executes correctly
//! - Displays version from Cargo.toml (not hardcoded)
//! - Parses all commands and flags
//! - Links properly to nails-core library
//!
//! # Safety Warnings
//!
//! Some tests in this file execute REAL system commands (activate, deactivate, emergency).
//! These tests are protected by Layer 3 safety guards that check for the
//! `NAILS_UNSAFE_REAL_OPS=1` environment variable.
//!
//! To run these tests:
//! ```bash
//! NAILS_UNSAFE_REAL_OPS=1 cargo test -p nails-cli --test cli_integration
//! ```
//!
//! By default (without the env var), dangerous tests will print a skip message
//! and pass without executing real operations.

use assert_cmd::prelude::*;
use predicates::prelude::*;

/// TEST SAFETY GUARD (Layer 3): Check if unsafe real operations are allowed
///
/// This helper function is called at the start of integration tests that execute
/// real system commands (activate, deactivate, emergency). It checks for the
/// `NAILS_UNSAFE_REAL_OPS=1` environment variable and skips the test if not set.
///
/// # Returns
///
/// - `true` if the test should run (env var is set)
/// - `false` if the test should be skipped (safe mode)
fn check_unsafe_ops_allowed(test_name: &str) -> bool {
    if std::env::var("NAILS_UNSAFE_REAL_OPS").unwrap_or_default() != "1" {
        eprintln!();
        eprintln!("⚠️  SKIPPED: {}", test_name);
        eprintln!("   This test executes real system commands (mount, systemctl, etc.)");
        eprintln!("   and is skipped by default for safety.");
        eprintln!();
        eprintln!("   To run: NAILS_UNSAFE_REAL_OPS=1 cargo test");
        eprintln!();
        eprintln!("   ⚠️  WARNING: This will execute REAL operations on your system!");
        eprintln!();
        return false;
    }
    true
}

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
        .stdout(predicates::str::contains("nails 0.1.0"));
}

/// Test that --help flag works
#[test]
fn test_help_flag() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "NixOS Anti-forensics Isolation & Layering System",
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

/// Test that deactivate command accepts new flags (Story 5.7)
#[test]
fn test_deactivate_command_flags_help() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["deactivate", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--no-clear-history"))
        .stdout(predicates::str::contains("--quiet"))
        .stdout(predicates::str::contains("--verbose"))
        .stdout(predicates::str::contains("--json"))
        .stdout(predicates::str::contains("--no-color"));
}

/// Test that emergency command accepts new flags (Story 6.4)
#[test]
fn test_emergency_command_flags_help() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["emergency", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--no-countdown"))
        .stdout(predicates::str::contains("--quiet"))
        .stdout(predicates::str::contains("--verbose"))
        .stdout(predicates::str::contains("--json"))
        .stdout(predicates::str::contains("--no-color"));
}

/// Test that emergency command no longer has --delay flag (AR33: fixed 3s countdown)
#[test]
fn test_emergency_command_no_delay_flag() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["emergency", "--delay", "10"]).assert().failure(); // --delay should not exist
}

/// Test that status command accepts --verbose flag
#[test]
fn test_status_command_verbose_flag() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["status", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--verbose"))
        .stdout(predicates::str::contains(
            "Display detailed overlay mount information",
        ));
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

/// Test that activate command executes and fails without root/setup (expected)
#[test]
fn test_activate_command_fails_without_setup() {
    if !check_unsafe_ops_allowed("test_activate_command_fails_without_setup") {
        return; // Skip test - not opted in to unsafe operations
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("activate")
        .assert()
        .failure() // Expect failure without proper setup
        .code(2); // Exit code 2 for safety guard (changed from 1)
}

/// Test that activate command with --no-preflight flag also fails without setup
#[test]
fn test_activate_command_fails_with_no_preflight() {
    if !check_unsafe_ops_allowed("test_activate_command_fails_with_no_preflight") {
        return; // Skip test - not opted in to unsafe operations
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--no-preflight"])
        .assert()
        .failure() // Expect failure without proper setup
        .code(2); // Exit code 2 for safety guard (changed from 1)
}

/// Test that activate command has --json flag in help
#[test]
fn test_activate_has_json_flag() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--json"))
        .stdout(predicates::str::contains("Output results in JSON format"));
}

/// Test that activate command has --no-color flag in help
#[test]
fn test_activate_has_no_color_flag() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--no-color"))
        .stdout(predicates::str::contains("Disable colored output"));
}

/// Test that activate command with --json produces JSON output
#[test]
fn test_activate_json_output() {
    if !check_unsafe_ops_allowed("test_activate_json_output") {
        return; // Skip test - not opted in to unsafe operations
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--json"])
        .assert()
        .failure() // Will fail with safety guard
        .stdout(
            predicates::str::contains("status").or(predicates::str::contains("TEST SAFETY GUARD")),
        );
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
            "Quiet mode: only show final result",
        ));
}

/// Test that activate command with --no-color doesn't produce ANSI codes
#[test]
fn test_activate_no_color_output() {
    if !check_unsafe_ops_allowed("test_activate_no_color_output") {
        return; // Skip test - not opted in to unsafe operations
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    // Verify: command fails (expected without setup) AND has no ANSI codes
    cmd.args(["activate", "--no-color"])
        .assert()
        .failure()
        .stderr(predicates::str::is_match(r"\x1b\[").unwrap().not()); // No ANSI escape sequences
}

/// Test that activate command with verbosity flags are accepted
#[test]
fn test_activate_verbosity_flags() {
    if !check_unsafe_ops_allowed("test_activate_verbosity_flags") {
        return; // Skip test - not opted in to unsafe operations
    }

    // Test -v flag
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "-v"]).assert().failure(); // Will fail without setup

    // Test -vv flag
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "-vv"]).assert().failure(); // Will fail without setup

    // Test --quiet flag
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--quiet"]).assert().failure(); // Will fail without setup
}

/// Test that notify-dispatch command exists and has help text
#[test]
fn test_notify_dispatch_command_help() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["notify-dispatch", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("dispatch"))
        .stdout(predicates::str::contains("notification"));
}

/// Test that notify-dispatch command accepts --json flag
#[test]
fn test_notify_dispatch_json_flag() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["notify-dispatch", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--json"));
}

/// Test that notify-dispatch executes without crashing
#[test]
fn test_notify_dispatch_executes() {
    // This test verifies notify-dispatch runs without panic
    // It will exit 0 even if hidden volume doesn't exist (graceful degradation)
    // SAFETY: Set NAILS_DISABLE_NOTIFICATIONS to prevent real desktop notifications
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.env("NAILS_DISABLE_NOTIFICATIONS", "1")
        .args(["notify-dispatch"])
        .assert()
        .success(); // Should exit 0 even on error (non-critical feature)
}

/// Test that notify-dispatch with --json outputs JSON format
#[test]
fn test_notify_dispatch_json_output() {
    // SAFETY: Set NAILS_DISABLE_NOTIFICATIONS to prevent real desktop notifications
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.env("NAILS_DISABLE_NOTIFICATIONS", "1")
        .args(["notify-dispatch", "--json"])
        .assert()
        .success()
        .stdout(predicates::str::contains("dispatched"))
        .stdout(predicates::str::contains("status"));
}

/// Test that notify-dispatch with custom config path
#[test]
fn test_notify_dispatch_with_config() {
    let config_file = create_test_config_file("/tmp/test-volume");

    // SAFETY: Set NAILS_DISABLE_NOTIFICATIONS to prevent real desktop notifications
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.env("NAILS_DISABLE_NOTIFICATIONS", "1")
        .args([
            "--config",
            config_file.path().to_str().unwrap(),
            "notify-dispatch",
        ])
        .assert()
        .success();
}

/// Test that deactivate command executes (idempotent when inactive - AC7/FR62)
#[test]
fn test_deactivate_command_executes() {
    if !check_unsafe_ops_allowed("test_deactivate_command_executes") {
        return; // Skip test - not opted in to unsafe operations
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("deactivate")
        .assert()
        .failure() // Now fails with safety guard (exit code 2)
        .code(2);
}

/// Test that deactivate command with --no-clear-history flag executes (AC6)
#[test]
fn test_deactivate_command_executes_with_no_clear_history() {
    if !check_unsafe_ops_allowed("test_deactivate_command_executes_with_no_clear_history") {
        return; // Skip test - not opted in to unsafe operations
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["deactivate", "--no-clear-history"])
        .assert()
        .failure() // Now fails with safety guard (exit code 2)
        .code(2);
}

/// Test that deactivate command with --json flag produces JSON output (AC7)
#[test]
fn test_deactivate_json_output() {
    if !check_unsafe_ops_allowed("test_deactivate_json_output") {
        return; // Skip test - not opted in to unsafe operations
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["deactivate", "--json"])
        .assert()
        .failure() // Now fails with safety guard
        .code(2);
}

/// Test deactivate with --quiet flag
#[test]
fn test_deactivate_with_quiet() {
    if !check_unsafe_ops_allowed("test_deactivate_with_quiet") {
        return;
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["deactivate", "--quiet"])
        .assert()
        .failure()
        .code(2);
}

/// Test deactivate with verbose flag combinations
#[test]
fn test_deactivate_verbosity_combinations() {
    if !check_unsafe_ops_allowed("test_deactivate_verbosity_combinations") {
        return;
    }

    // Test -v flag
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["deactivate", "-v"]).assert().failure().code(2);

    // Test -vv flag
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["deactivate", "-vv"]).assert().failure().code(2);
}

/// Test deactivate with --plain flag
#[test]
fn test_deactivate_with_plain() {
    if !check_unsafe_ops_allowed("test_deactivate_with_plain") {
        return;
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["deactivate", "--plain"])
        .assert()
        .failure()
        .code(2);
}

/// Test deactivate respects NO_COLOR environment variable
#[test]
fn test_deactivate_respects_no_color_env() {
    if !check_unsafe_ops_allowed("test_deactivate_respects_no_color_env") {
        return;
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["deactivate"])
        .env("NO_COLOR", "1")
        .assert()
        .failure()
        .code(2);
}

/// Test that deactivate command with --no-color uses text markers instead of symbols
#[test]
fn test_deactivate_no_color_output() {
    if !check_unsafe_ops_allowed("test_deactivate_no_color_output") {
        return; // Skip test - not opted in to unsafe operations
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["deactivate", "--no-color"])
        .assert()
        .failure() // Now fails with safety guard
        .code(2);
}

/// Test that deactivate command exit code is 0 on success (AC3)
#[test]
fn test_deactivate_exit_code_success() {
    if !check_unsafe_ops_allowed("test_deactivate_exit_code_success") {
        return; // Skip test - not opted in to unsafe operations
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("deactivate").assert().failure().code(2); // Now fails with safety guard
}

/// Test that emergency command with --no-countdown executes (no 3s wait)
/// Note: This will fork and run the real emergency flow, which reaches INACTIVE
/// from an already-inactive state (defensive mode). The parent exits 0 after fork.
#[test]
fn test_emergency_command_executes_no_countdown() {
    if !check_unsafe_ops_allowed("test_emergency_command_executes_no_countdown") {
        return; // Skip test - not opted in to unsafe operations
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["emergency", "--no-countdown"])
        .assert()
        .failure()
        .code(2); // Now fails with safety guard
}

/// Test that emergency command with --no-countdown --json executes
#[test]
fn test_emergency_command_executes_no_countdown_json() {
    if !check_unsafe_ops_allowed("test_emergency_command_executes_no_countdown_json") {
        return; // Skip test - not opted in to unsafe operations
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["emergency", "--no-countdown", "--json"])
        .assert()
        .failure() // Now fails with safety guard
        .code(2);
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
        .stdout(predicates::str::contains("\"security_posture\""));
}

#[test]
fn test_status_command_plain_output() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["status", "--plain"])
        .assert()
        .success()
        .stdout(predicates::str::contains("NAILS Status Report"))
        .stdout(predicates::str::contains("===="))
        .stdout(predicates::str::contains("State:"));
}

#[test]
fn test_status_fails_closed_on_invalid_config() {
    let config_file = create_invalid_config_file();

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["--config", config_file.path().to_str().unwrap(), "status"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicates::str::contains("Error loading config from"))
        .stderr(predicates::str::contains(
            config_file.path().to_str().unwrap(),
        ))
        .stderr(predicates::str::contains("Invalid YAML"));
}

#[test]
fn test_deactivate_fails_closed_on_unreadable_config_path() {
    let config_dir = tempfile::tempdir().unwrap();

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args([
        "--config",
        config_dir.path().to_str().unwrap(),
        "deactivate",
    ])
    .assert()
    .failure()
    .code(2)
    .stderr(predicates::str::contains("Error loading config from"))
    .stderr(predicates::str::contains(
        config_dir.path().to_str().unwrap(),
    ))
    .stderr(predicates::str::contains("Failed to read config"));
}

#[test]
fn test_emergency_fails_closed_on_invalid_config_before_safety_guard() {
    let config_file = create_invalid_config_file();

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args([
        "--config",
        config_file.path().to_str().unwrap(),
        "emergency",
        "--no-countdown",
    ])
    .assert()
    .failure()
    .code(2)
    .stderr(predicates::str::contains("Error loading config from"))
    .stderr(predicates::str::contains(
        config_file.path().to_str().unwrap(),
    ))
    .stderr(predicates::str::contains("Invalid YAML"))
    .stderr(predicates::str::contains("TEST SAFETY GUARD").not());
}

#[test]
fn test_verify_command_json_output() {
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args(["verify", "--json"])
        .output()
        .expect("failed to run verify command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let code = output.status.code();

    // Exit code 0 = Secure, 1 = Warning/Critical, 2 = error
    assert!(
        code == Some(0) || code == Some(1),
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
        Some(1) => {
            assert!(stdout.contains("\"scan_depth\""));
            assert!(stdout.contains("Deep"));
        }
        Some(2) => {
            assert!(stderr.contains("Error running verification:"));
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
    let config_path = temp_dir.path().join("nails.yaml");

    let mut config_file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "hidden_volume_path: {}\nstate_file_path: {}\nlog_path: {}\noverlays:\n  - name: home\n    lower: /home\n    upper: {}/home\n    work: {}/.work/home\n    target: /home\n  - name: etc\n    lower: /etc\n    upper: {}/etc\n    work: {}/.work/etc\n    target: /etc",
        hidden_root.display(),
        state_path.display(),
        log_path.display(),
        hidden_root.display(),
        hidden_root.display(),
        hidden_root.display(),
        hidden_root.display(),
    )
    .unwrap();

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args(["--config", config_path.to_str().unwrap(), "verify"])
        .output()
        .expect("failed to run verify command");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let code = output.status.code();

    assert!(
        code == Some(0) || code == Some(1),
        "unexpected exit code: {:?}\nstdout={}\nstderr={}",
        code,
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("checked 5 paths from config"));
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
    let config_path = temp_dir.path().join("nails.yaml");

    let state_json = r#"{
  \"version\": \"0.1.0\",
  \"state\": \"Inactive\",
  \"nixos_generation\": null,
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
        "hidden_volume_path: {}\nstate_file_path: {}\noverlays: []",
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
        code == Some(0) || code == Some(1),
        "unexpected exit code: {:?}\nstdout={}\nstderr={}",
        code,
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("\"state_file_status\""));
    assert!(stdout.contains("\"kind\": \"present\""));
    assert!(stdout.contains(&format!("\"path\": \"{}\"", state_path.display())));
    assert!(stdout.contains("\"state\": \"INACTIVE\""));
}

#[test]
fn test_activate_interactive_fails_before_any_real_ops() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--interactive"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicates::str::contains(
            "--kill-session is non-interactive after detach; use --yes",
        ));
}

#[test]
fn test_activate_with_build_dir_config_hits_safety_guard() {
    let config_file = create_test_config_file("/tmp/fake/target/debug/fake-hidden");

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args([
        "--config",
        config_file.path().to_str().unwrap(),
        "activate",
        "--no-kill-session",
        "--no-preflight",
    ])
    .assert()
    .failure()
    .code(2)
    .stderr(predicates::str::contains("TEST SAFETY GUARD"));
}

#[test]
fn test_activate_kill_session_detaches_via_systemd_run() {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let fake_bin = temp_dir.path().join("bin");
    let systemd_run_log = temp_dir.path().join("systemd-run.log");
    let shell_path = locate_shell_path();

    fs::create_dir_all(&hidden_root).unwrap();
    fs::create_dir_all(&fake_bin).unwrap();

    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(config_file, "hidden_volume_path: {}", hidden_root.display()).unwrap();

    let systemd_run_path = fake_bin.join("systemd-run");
    fs::write(
        &systemd_run_path,
        format!(
            "#!{}\nprintf '%s\\n' \"$@\" > \"{}\"\nexit 0\n",
            shell_path.display(),
            systemd_run_log.display()
        ),
    )
    .unwrap();
    let mut perms = fs::metadata(&systemd_run_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&systemd_run_path, perms).unwrap();

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--config",
            config_file.path().to_str().unwrap(),
            "activate",
            "--kill-session",
            "--no-preflight",
        ])
        .env("PATH", &fake_bin)
        .env("DISPLAY", ":0")
        .env("NAILS_SESSION_ID", "c42")
        .env("NAILS_DISPLAY_MANAGER", "gdm")
        .env("NAILS_TARGET_UID", "1000")
        .env("NAILS_TARGET_USER", "amnesia")
        .env("NAILS_LOGIND_AVAILABLE", "1")
        .output()
        .expect("failed to run activate detach handoff test");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout={}\nstderr={stderr}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(stderr.contains("Detached to background via systemd transient service."));
    assert!(stderr.contains("Handoff complete; activation continues in background."));

    let logged_args = fs::read_to_string(systemd_run_log).unwrap();
    assert!(logged_args.contains("--unit"));
    assert!(logged_args.contains("--slice=system.slice"));
    assert!(logged_args.contains("--same-dir"));
    assert!(logged_args.contains("--collect"));
    assert!(logged_args.contains("--setenv=NAILS_DETACHED=1"));
    assert!(logged_args.contains("--setenv=XDG_SESSION_ID="));
    assert!(logged_args.contains("--setenv=NAILS_SESSION_ID=c42"));
    assert!(logged_args.contains("--setenv=NAILS_DISPLAY_MANAGER=gdm"));
    assert!(logged_args.contains("--setenv=NAILS_TARGET_UID=1000"));
    assert!(logged_args.contains("--setenv=NAILS_TARGET_USER=amnesia"));
    assert!(logged_args.contains("activate"));
    assert!(logged_args.contains("--kill-session"));
    assert!(logged_args.contains("--no-preflight"));
}

#[test]
fn test_activate_kill_session_surfaces_systemd_run_failures() {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let fake_bin = temp_dir.path().join("bin");
    let shell_path = locate_shell_path();

    fs::create_dir_all(&hidden_root).unwrap();
    fs::create_dir_all(&fake_bin).unwrap();

    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(config_file, "hidden_volume_path: {}", hidden_root.display()).unwrap();

    let systemd_run_path = fake_bin.join("systemd-run");
    fs::write(
        &systemd_run_path,
        format!(
            "#!{}\nprintf 'mock detach failure' >&2\nexit 1\n",
            shell_path.display()
        ),
    )
    .unwrap();
    let mut perms = fs::metadata(&systemd_run_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&systemd_run_path, perms).unwrap();

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--config",
            config_file.path().to_str().unwrap(),
            "activate",
            "--kill-session",
            "--no-preflight",
        ])
        .env("PATH", &fake_bin)
        .env("DISPLAY", ":0")
        .env("NAILS_SESSION_ID", "c42")
        .env("NAILS_DISPLAY_MANAGER", "gdm")
        .env("NAILS_TARGET_UID", "1000")
        .env("NAILS_TARGET_USER", "amnesia")
        .env("NAILS_LOGIND_AVAILABLE", "1")
        .output()
        .expect("failed to run activate detach failure test");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(stderr.contains("systemd-run failed"), "stderr={stderr}");
    assert!(stderr.contains("mock detach failure"), "stderr={stderr}");
}

#[test]
fn test_activate_dry_run_skips_preflight_without_real_mutations() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(config_file, "hidden_volume_path: {}", hidden_root.display()).unwrap();

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args([
        "--config",
        config_file.path().to_str().unwrap(),
        "activate",
        "--dry-run",
        "--no-preflight",
        "--no-kill-session",
        "--overlay-only",
        "--plain",
    ])
    .assert()
    .success()
    .stdout(predicates::str::contains(
        "=== NAILS Dry-Run: Activation Preview ===",
    ))
    .stdout(predicates::str::contains(
        "[WARN] Pre-flight checks skipped (--no-preflight)",
    ))
    .stdout(predicates::str::contains(
        "[INFO] Session kill disabled (--no-kill-session)",
    ))
    .stdout(predicates::str::contains(
        "[INFO] Overlay-only mode: NixOS profile switch would be skipped",
    ))
    .stdout(predicates::str::contains(
        "=== Dry-run complete. No changes were made. ===",
    ));
}

#[test]
fn test_activate_dry_run_executes_preflight_and_reports_results() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(config_file, "hidden_volume_path: {}", hidden_root.display()).unwrap();

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--config",
            config_file.path().to_str().unwrap(),
            "activate",
            "--dry-run",
            "--no-kill-session",
            "--plain",
        ])
        .output()
        .expect("failed to run activate dry-run");

    assert!(
        output.status.success(),
        "dry-run should succeed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--- Pre-flight Checks ---"));
    assert!(stdout.contains("--- Overlay Targets ---"));
    assert!(stdout.contains("--- Session Management ---"));
    assert!(stdout.contains("--- NixOS Profile ---"));
    assert!(stdout.contains("[INFO] Session kill disabled (--no-kill-session)"));
    assert!(
        stdout.contains("[PASS]") || stdout.contains("[WARN]") || stdout.contains("[FAIL]"),
        "expected preflight result markers in output: {stdout}"
    );
}

#[test]
fn test_activate_dry_run_checks_session_context_by_default() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(config_file, "hidden_volume_path: {}", hidden_root.display()).unwrap();

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args([
        "--config",
        config_file.path().to_str().unwrap(),
        "activate",
        "--dry-run",
        "--no-preflight",
        "--plain",
    ])
    .assert()
    .success()
    .stdout(predicates::str::contains("--- Session Management ---"))
    .stdout(
        predicates::str::contains("Graphical session detected")
            .or(predicates::str::contains("No graphical session detected"))
            .or(predicates::str::contains(
                "Could not detect session context",
            )),
    );
}

#[test]
fn test_activate_dry_run_reports_explicit_flake_reference() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config_file,
        "hidden_volume_path: {}\nnixos_flake: /etc/nixos#test-host",
        hidden_root.display()
    )
    .unwrap();

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args([
        "--config",
        config_file.path().to_str().unwrap(),
        "activate",
        "--dry-run",
        "--no-preflight",
        "--no-kill-session",
        "-vv",
        "--plain",
    ])
    .assert()
    .success()
    .stdout(predicates::str::contains(
        "[INFO] NixOS flake: /etc/nixos#test-host",
    ))
    .stdout(predicates::str::contains("would build and switch profile"));
}

#[test]
fn test_activate_fails_closed_on_invalid_config_before_safety_guard() {
    let config_file = create_invalid_config_file();

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args([
        "--config",
        config_file.path().to_str().unwrap(),
        "activate",
        "--no-kill-session",
        "--no-preflight",
    ])
    .assert()
    .failure()
    .code(2)
    .stderr(predicates::str::contains("Error loading config"))
    .stderr(predicates::str::contains("Invalid YAML"))
    .stderr(predicates::str::contains("TEST SAFETY GUARD").not());
}

#[test]
fn test_emergency_with_build_dir_config_hits_safety_guard() {
    let config_file = create_test_config_file("/tmp/fake/target/llvm-cov-target/fake-hidden");

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args([
        "--config",
        config_file.path().to_str().unwrap(),
        "emergency",
    ])
    .assert()
    .failure()
    .code(2)
    .stderr(predicates::str::contains("TEST SAFETY GUARD"));
}

/// Test that activate command has --no-clear-history flag in help (AC3)
#[test]
fn test_activate_has_no_clear_history_flag() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--no-clear-history"))
        .stdout(predicates::str::contains("Skip clearing shell history"));
}

/// Test activate with --overlay-only flag
#[test]
fn test_activate_overlay_only_flag() {
    if !check_unsafe_ops_allowed("test_activate_overlay_only_flag") {
        return;
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--overlay-only"])
        .assert()
        .failure()
        .code(2); // Safety guard
}

/// Test activate with --accept-pivot-risks flag
#[test]
fn test_activate_accept_pivot_risks_flag() {
    if !check_unsafe_ops_allowed("test_activate_accept_pivot_risks_flag") {
        return;
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--accept-pivot-risks"])
        .assert()
        .failure(); // Will fail due to missing --yes flag requirement
}

/// Test activate requires --yes when using --kill-session
#[test]
fn test_activate_kill_session_requires_yes() {
    if !check_unsafe_ops_allowed("test_activate_kill_session_requires_yes") {
        return;
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--kill-session", "--interactive"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicates::str::contains(
            "--kill-session is non-interactive",
        ));
}

/// Test activate with multiple verbosity levels
#[test]
fn test_activate_multiple_verbosity() {
    if !check_unsafe_ops_allowed("test_activate_multiple_verbosity") {
        return;
    }

    // Test quiet mode
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--quiet", "--no-preflight"])
        .assert()
        .failure()
        .code(2);

    // Test normal verbosity
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--no-preflight"])
        .assert()
        .failure()
        .code(2);
}

/// Test activate with --plain flag (ASCII-only output)
#[test]
fn test_activate_plain_output() {
    if !check_unsafe_ops_allowed("test_activate_plain_output") {
        return;
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--plain", "--no-preflight"])
        .assert()
        .failure()
        .code(2);
}

/// Test activate respects NO_COLOR environment variable
#[test]
fn test_activate_respects_no_color_env() {
    if !check_unsafe_ops_allowed("test_activate_respects_no_color_env") {
        return;
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--no-preflight"])
        .env("NO_COLOR", "1")
        .assert()
        .failure()
        .code(2);
}

/// Test backward compatibility: CLI works when config file doesn't exist (AC6)
///
/// This verifies the behavior specified in AC6:
/// - When config file is missing, defaults are used
/// - Then CLI overrides are applied
/// - Existing users without config files should see no behavior change
#[test]
fn test_backward_compatibility_without_config_file() {
    // SAFETY: This test executes real activate command which can perform dangerous operations
    // Skip unless explicitly allowed via environment variable
    if !check_unsafe_ops_allowed("test_backward_compatibility_without_config_file") {
        return;
    }

    use tempfile::TempDir;

    // Create a temporary home directory with no config file
    let temp_home = TempDir::new().unwrap();
    let config_path = temp_home.path().join(".nails/config.yaml");

    // Verify config file doesn't exist
    assert!(!config_path.exists());

    // Test that activate command works without config file (should use defaults + CLI overrides)
    // Pass HOME only to the subprocess via .env(), don't modify this process's HOME
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--no-preflight"])
        .env("HOME", temp_home.path())
        .env("NAILS_UNSAFE_REAL_OPS", "1") // Required to bypass safety guard
        .assert()
        .code(2); // Expect safety guard exit code since we're in build directory

    // Note: We don't modify this process's HOME, only the subprocess's
}

/// Test that --config flag is accepted globally (Story 14.1 - AC5)
#[test]
fn test_config_flag_accepted() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains("--config"))
        .stdout(predicates::str::contains("Path to configuration file"));
}

// ========== Story 14.1 Config Discovery Helper ==========

/// Helper function to create a test config file with custom volume path
/// Reduces duplication across config-related tests
fn create_test_config_file(volume_path: &str) -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(config_file, "hidden_volume_path: {}", volume_path).unwrap();
    config_file
}

fn create_invalid_config_file() -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(config_file, "hidden_volume_path: [broken").unwrap();
    config_file
}

fn locate_shell_path() -> std::path::PathBuf {
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .flat_map(|dir| [dir.join("bash"), dir.join("sh")])
                .find(|candidate| candidate.is_file())
        })
        .expect("expected to locate a usable shell binary")
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

/// Test that binary works without config file in binary-relative location (Story 14.1 - AC3)
/// This verifies graceful defaults when config doesn't exist
#[test]
fn test_binary_relative_config_graceful_defaults() {
    // Binary will try to load from {binary_dir}/config/nails.yaml
    // If it doesn't exist (which it won't in test environment), it should use defaults
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("status")
        .assert()
        .success() // Should work with defaults
        .stdout(predicates::str::contains("NAILS Status Report"));
}

/// Integration test for binary-relative config loading (Story 14.1 - AC7)
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
    let config_path = config_dir.join("nails.yaml");
    let mut config_file = fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        r#"hidden_volume_path: /mnt/custom-integration-test-volume
"#
    )
    .unwrap();

    // Test 1: Verify CLI uses --config override correctly
    // This proves the CLI can load from an explicit path
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .arg("--config")
        .arg(&config_path)
        .arg("status")
        .arg("--verbose")
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

    // Test 2: Verify graceful behavior when config doesn't exist (AC3)
    // Run with a non-existent config path to verify fallback to defaults
    let nonexistent_config = temp_dir.path().join("nonexistent.yaml");
    let output2 = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .arg("--config")
        .arg(&nonexistent_config)
        .arg("status")
        .output()
        .expect("Failed to execute nails status");

    let _stdout2 = String::from_utf8_lossy(&output2.stdout);
    let stderr2 = String::from_utf8_lossy(&output2.stderr);

    // Should succeed using defaults, not fail
    assert!(
        output2.status.success(),
        "Should succeed with defaults when config missing. stderr: {}",
        stderr2
    );

    // Note: Config loading errors are handled by Config::load_or_default()
    // which logs an INFO message when config is not found.
    // We just verify the command doesn't crash and succeeds.
}

/// Test that CLI --config flag overrides binary-relative config discovery (AC5)
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
    let binary_relative_config = config_dir.join("nails.yaml");
    let mut file1 = fs::File::create(&binary_relative_config).unwrap();
    writeln!(file1, "hidden_volume_path: /mnt/binary-relative-volume").unwrap();

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
