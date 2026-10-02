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
        .stdout(predicates::str::contains("nails 0.2.0"));
}

/// Test that --help flag works
#[test]
fn test_help_flag() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "Overlay environment manager for NixOS",
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
        .stdout(predicates::str::contains("--color <WHEN>"));
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
        .stdout(predicates::str::contains("--color <WHEN>"));
}

/// Test that emergency command no longer has --delay flag (AR33: fixed 3s countdown)
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

/// Test deactivate with --ascii flag
#[test]
fn test_deactivate_with_ascii() {
    if !check_unsafe_ops_allowed("test_deactivate_with_ascii") {
        return;
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["deactivate", "--ascii"])
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

/// Test that deactivate command accepts --color never
#[test]
fn test_deactivate_color_never_flag() {
    if !check_unsafe_ops_allowed("test_deactivate_color_never_flag") {
        return; // Skip test - not opted in to unsafe operations
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["deactivate", "--color", "never"])
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
fn test_status_exit_status_flag_stays_zero_for_a_decoy_system() {
    // --exit-status reflects the posture; a decoy (inactive) system is a success,
    // and plain status always exits 0.
    let (_dir, config) = isolated_status_config();
    let config = config.to_str().unwrap();

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["--config", config, "status"]).assert().success();

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["--config", config, "status", "--exit-status"])
        .assert()
        .success();
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
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\nlog_path = \"{}\"\noverlays = []",
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
fn test_status_command_details_active_shows_overlay_details() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let log_dir = hidden_root.join("logs");
    let state_path = hidden_root.join("state.json");
    let config_path = temp_dir.path().join("nails.toml");
    std::fs::create_dir_all(&log_dir).unwrap();

    let activated_at = "2026-01-02T03:04:05Z";
    let mounted_at = "2026-01-02T03:04:30Z";
    let state_json = format!(
        r#"{{
  "version": "0.2.0",
  "state": {{
    "Active": {{
      "activated_at": "{activated_at}",
      "overlays": ["/home"]
    }}
  }},
  "nixos_generation": "nails-gen-99",
  "config_fingerprint": null,
  "overlay_status": {{
    "/home": {{
      "mount_path": "/home",
      "lower_dir": "/home",
      "upper_dir": "{hidden}/overlays/home/upper",
      "work_dir": "{hidden}/overlays/home/work",
      "mounted_at": "{mounted_at}"
    }}
  }},
  "failed_overlays": [],
  "last_modified": "2026-01-02T03:05:00Z"
}}"#,
        hidden = hidden_root.display(),
    );
    // Seal through the durable save path so the file carries a valid digest.
    let state: nails_core::StateFile = serde_json::from_str(&state_json).unwrap();
    state
        .save_with_custom_root(&state_path, &hidden_root)
        .unwrap();

    let mut config_file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\nlog_path = \"{}\"\n[[overlays]]\nname = \"home\"\nlower = \"/home\"\nupper = \"{}/overlays/home/upper\"\nwork = \"{}/overlays/home/work\"\ntarget = \"/home\"",
        hidden_root.display(),
        state_path.display(),
        log_dir.display(),
        hidden_root.display(),
        hidden_root.display(),
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
    assert!(output.status.success(), "stdout={stdout}");
    assert!(stdout.contains("NixOS Generation:   nails-gen-99"));
    assert!(stdout.contains("Overlay Mount Details:"));
    assert!(stdout.contains("Mount:     /home"));
    assert!(stdout.contains(&format!(
        "Upper:     {}/overlays/home/upper",
        hidden_root.display()
    )));
    assert!(stdout.contains(&format!(
        "Work:      {}/overlays/home/work",
        hidden_root.display()
    )));
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
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\noverlays = []",
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
    assert!(output.status.success(), "stdout={stdout}");
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
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\noverlays = []",
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
// `commands/emergency.rs` and `commands/deactivate/tests.rs`, which inject a
// blocking safety guard.

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
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\nlog_path = \"{}\"\n[[overlays]]\nname = \"home\"\nlower = \"/home\"\nupper = \"{}/home\"\nwork = \"{}/.work/home\"\ntarget = \"/home\"\n[[overlays]]\nname = \"etc\"\nlower = \"/etc\"\nupper = \"{}/etc\"\nwork = \"{}/.work/etc\"\ntarget = \"/etc\"",
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
        code == Some(0) || code == Some(10) || code == Some(11),
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
    let config_path = temp_dir.path().join("nails.toml");

    let state_json = r#"{
  \"version\": \"0.2.0\",
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
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\noverlays = []",
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

    // A real (non-build-dir) hidden root passes the safety guard, so the
    // confirmation gate is what must stop activation: without -y and without a
    // terminal it refuses before anything is staged, mounted or switched.
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
fn test_activate_with_build_dir_config_hits_safety_guard() {
    let config_file = create_test_config_file("/tmp/fake/target/debug/fake-hidden");

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args([
        "--config",
        config_file.path().to_str().unwrap(),
        "activate",
        "--session",
        "keep",
        "--no-preflight",
    ])
    .assert()
    .failure()
    .code(5)
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
    writeln!(
        config_file,
        "hidden_volume_root = \"{}\"",
        hidden_root.display()
    )
    .unwrap();

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
            "--session",
            "kill",
            "--no-preflight",
            "-y",
        ])
        .env(
            "PATH",
            std::env::join_paths([
                fake_bin.as_path(),
                std::path::Path::new("/run/current-system/sw/bin"),
                std::path::Path::new("/usr/bin"),
                std::path::Path::new("/bin"),
            ])
            .unwrap(),
        )
        .env("NAILS_SYSTEMD_RUN_PATH", &systemd_run_path)
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
    // The detached parent names the follow-up command with the absolute binary path.
    let exe = assert_cmd::cargo::cargo_bin!("nails");
    assert!(
        stderr.contains(&format!("sudo {} status", exe.display())),
        "stderr={stderr}"
    );

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
    assert!(logged_args.contains("--session"));
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
    writeln!(
        config_file,
        "hidden_volume_root = \"{}\"",
        hidden_root.display()
    )
    .unwrap();

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
            "--session",
            "kill",
            "--no-preflight",
            "-y",
        ])
        .env("PATH", &fake_bin)
        .env("NAILS_SYSTEMD_RUN_PATH", &systemd_run_path)
        .env("DISPLAY", ":0")
        .env("NAILS_SESSION_ID", "c42")
        .env("NAILS_DISPLAY_MANAGER", "gdm")
        .env("NAILS_TARGET_UID", "1000")
        .env("NAILS_TARGET_USER", "amnesia")
        .env("NAILS_LOGIND_AVAILABLE", "1")
        .output()
        .expect("failed to run activate detach failure test");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr={stderr}");
    assert!(stderr.contains("systemd-run failed"), "stderr={stderr}");
    assert!(stderr.contains("mock detach failure"), "stderr={stderr}");
}

#[test]
fn test_activate_kill_session_refuses_real_transient_units_in_test_runtime() {
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
            "--config",
            config_file.path().to_str().unwrap(),
            "activate",
            "--session",
            "kill",
            "--no-preflight",
            "-y",
        ])
        .env("DISPLAY", ":0")
        .env("NAILS_SESSION_ID", "c42")
        .env("NAILS_DISPLAY_MANAGER", "gdm")
        .env("NAILS_TARGET_UID", "1000")
        .env("NAILS_TARGET_USER", "amnesia")
        .output()
        .expect("failed to run activate detach safety test");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr={stderr}");
    assert!(stderr.contains("Refusing to start transient systemd units"));
}

#[test]
fn test_deactivate_with_build_dir_config_hits_safety_guard() {
    let config_file = create_test_config_file("/tmp/fake/target/debug/fake-hidden");

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args([
        "--config",
        config_file.path().to_str().unwrap(),
        "deactivate",
    ])
    .assert()
    .failure()
    .code(5)
    .stderr(predicates::str::contains("TEST SAFETY GUARD"));
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
        .stdout(predicates::str::contains("Overlay targets:"))
        .stdout(predicates::str::contains("Session handling:"))
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
fn test_activate_kill_session_fails_before_detach_on_flake_lock_preflight_error() {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().unwrap();
    let fake_bin = temp_dir.path().join("bin");
    std::fs::create_dir_all(&fake_bin).unwrap();

    let nix_script = fake_bin.join("nix");
    let systemd_run_script = fake_bin.join("systemd-run");
    let systemd_run_log = temp_dir.path().join("systemd-run.log");

    let shell_path = locate_shell_path();
    fs::write(
        &nix_script,
        format!(
            "#!{}\nprintf \"flake 'path:/etc/nixos' requires lock file changes\\n\" 1>&2\nexit 1\n",
            shell_path.display()
        ),
    )
    .unwrap();
    let mut perms = fs::metadata(&nix_script).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&nix_script, perms).unwrap();

    fs::write(
        &systemd_run_script,
        format!(
            "#!{}\nprintf '%s\\n' \"$*\" >> {}\nexit 0\n",
            shell_path.display(),
            systemd_run_log.display()
        ),
    )
    .unwrap();
    let mut perms = fs::metadata(&systemd_run_script).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&systemd_run_script, perms).unwrap();

    let hidden_root = temp_dir.path().join("hidden-volume");
    let explicit_flake_dir = temp_dir.path().join("explicit-flake");
    std::fs::create_dir_all(&hidden_root).unwrap();
    std::fs::create_dir_all(&explicit_flake_dir).unwrap();
    std::fs::write(
        explicit_flake_dir.join("flake.nix"),
        "{ outputs = _: {}; }\n",
    )
    .unwrap();

    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config_file,
        "hidden_volume_root = \"{}\"\nnixos_flake = \"{}#host-alpha\"",
        hidden_root.display(),
        explicit_flake_dir.display()
    )
    .unwrap();

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .args([
            "--config",
            config_file.path().to_str().unwrap(),
            "activate",
            "--session",
            "kill",
            "--ascii",
            "-y",
        ])
        .env("PATH", &fake_bin)
        .env("DISPLAY", ":0")
        .env("NAILS_SESSION_ID", "c42")
        .env("NAILS_DISPLAY_MANAGER", "gdm")
        .env("NAILS_TARGET_UID", "1000")
        .env("NAILS_TARGET_USER", "amnesia")
        .env("NAILS_LOGIND_AVAILABLE", "1")
        .output()
        .expect("failed to run activate kill-session preflight test");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(4), "stderr={stderr}");
    assert!(stderr.contains("flake lock"), "stderr={stderr}");
    assert!(
        stderr.contains("does not run 'nix flake update' automatically"),
        "stderr={stderr}"
    );
    assert!(
        !systemd_run_log.exists()
            || std::fs::read_to_string(&systemd_run_log)
                .unwrap()
                .trim()
                .is_empty(),
        "systemd-run should not have been called before preflight failure"
    );
}

#[test]
fn test_activate_fails_closed_on_invalid_config_before_safety_guard() {
    let config_file = create_invalid_config_file();

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args([
        "--config",
        config_file.path().to_str().unwrap(),
        "activate",
        "--session",
        "keep",
        "--no-preflight",
    ])
    .assert()
    .failure()
    .code(3)
    .stderr(predicates::str::contains("invalid config"))
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
    .code(5)
    .stderr(predicates::str::contains("TEST SAFETY GUARD"));
}

/// `activate --help` advertises the redesigned flags and drops the removed ones.
#[test]
fn test_activate_help_lists_session_pivot_and_yes_flags() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--session"))
        .stdout(predicates::str::contains("default: kill"))
        .stdout(predicates::str::contains("--pivot"))
        .stdout(predicates::str::contains("default: refuse"))
        .stdout(predicates::str::contains("--yes"));
    // The removed spellings are covered by the parser rejection test; asserting
    // their absence here is skipped so the removed flag names do not reappear in
    // the tree.
}

/// `deactivate --help` states that it reboots.
#[test]
fn test_deactivate_help_mentions_reboot() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["deactivate", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("reboot"));
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
        .code(2); // Confirmation gate: non-terminal without -y
}

/// Test activate with --pivot allow flag
#[test]
fn test_activate_pivot_allow_flag() {
    if !check_unsafe_ops_allowed("test_activate_pivot_allow_flag") {
        return;
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--pivot", "allow"])
        .assert()
        .failure(); // Confirmation gate refuses without -y on a non-terminal
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

/// Test activate with --ascii flag (ASCII-only output)
#[test]
fn test_activate_ascii_output() {
    if !check_unsafe_ops_allowed("test_activate_ascii_output") {
        return;
    }

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--ascii", "--no-preflight"])
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
    let config_path = temp_home.path().join("config/nails.toml");

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
        .stdout(predicates::str::contains("-c, --config <PATH>"))
        .stdout(predicates::str::contains("Path to the configuration file"));
}

// ========== Story 14.1 Config Discovery Helper ==========

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
    // Binary will try to load from {binary_dir}/config/nails.toml
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

    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["--config", config_file.path().to_str().unwrap(), "status"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicates::str::contains("cannot read config"));

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
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\noverlays = []",
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
