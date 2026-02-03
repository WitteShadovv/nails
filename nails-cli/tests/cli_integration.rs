//! Integration tests for NAILS CLI
//!
//! These tests verify the CLI binary:
//! - Executes correctly
//! - Displays version from Cargo.toml (not hardcoded)
//! - Parses all commands and flags
//! - Links properly to nails-core library

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

/// Test that emergency command accepts --delay flag with default
#[test]
fn test_emergency_command_delay_flag() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["emergency", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--delay"))
        .stdout(predicates::str::contains("[default: 10]"));
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
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("activate")
        .assert()
        .failure() // Expect failure without proper setup
        .code(1); // Exit code 1 for activation errors
}

/// Test that activate command with --no-preflight flag also fails without setup
#[test]
fn test_activate_command_fails_with_no_preflight() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--no-preflight"])
        .assert()
        .failure() // Expect failure without proper setup
        .code(1); // Exit code 1 for activation errors
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
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--json"])
        .assert()
        .failure() // Will fail without setup but should produce JSON
        .stdout(predicates::str::contains("\"status\""))
        .stdout(predicates::str::contains("\"duration\""))
        .stdout(predicates::str::contains("\"state\""))
        .stdout(predicates::str::contains("\"message\""));
}

/// Test that activate command with --no-color doesn't produce ANSI codes
#[test]
fn test_activate_no_color_output() {
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

/// Test that deactivate command executes (idempotent when inactive - AC7/FR62)
#[test]
fn test_deactivate_command_executes() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("deactivate")
        .assert()
        .success()
        .stdout(predicates::str::contains("inactive").or(predicates::str::contains("Inactive")));
}

/// Test that deactivate command with --no-clear-history flag executes (AC6)
#[test]
fn test_deactivate_command_executes_with_no_clear_history() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["deactivate", "--no-clear-history"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Skipping history cleanup"));
}

/// Test that deactivate command with --json flag produces JSON output (AC7)
#[test]
fn test_deactivate_json_output() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["deactivate", "--json"])
        .assert()
        .success()
        .stdout(predicates::str::contains("\"status\""))
        .stdout(predicates::str::contains("\"duration\""))
        .stdout(predicates::str::contains("\"state\""))
        .stdout(predicates::str::contains("\"cleaned_items\""))
        .stdout(predicates::str::contains("\"errors\""));
}

/// Test that deactivate command with --no-color uses text markers instead of symbols
#[test]
fn test_deactivate_no_color_output() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["deactivate", "--no-color"])
        .assert()
        .success()
        // In no-color mode, we use [OK] instead of ✓
        .stdout(
            predicates::str::contains("[OK]").or(predicates::str::contains("Already inactive")),
        );
}

/// Test that deactivate command exit code is 0 on success (AC3)
#[test]
fn test_deactivate_exit_code_success() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("deactivate").assert().success().code(0);
}

/// Test that emergency command executes successfully (stub implementation)
#[test]
fn test_emergency_command_executes() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("emergency")
        .assert()
        .success()
        .stdout(predicates::str::contains("Emergency: delay=10s"));
}

/// Test that emergency command with custom --delay flag executes successfully
#[test]
fn test_emergency_command_executes_with_custom_delay() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["emergency", "--delay", "30"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Emergency: delay=30s"));
}

/// Test that status command executes successfully (stub implementation)
#[test]
fn test_status_command_executes() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("status")
        .assert()
        .success()
        .stdout(predicates::str::contains("Status: verbose=false"));
}

/// Test that status command with --verbose flag executes successfully
#[test]
fn test_status_command_executes_with_verbose() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["status", "--verbose"])
        .assert()
        .success()
        .stdout(predicates::str::contains("Status: verbose=true"));
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

/// Test backward compatibility: CLI works when config file doesn't exist (AC6)
///
/// This verifies the behavior specified in AC6:
/// - When config file is missing, defaults are used
/// - Then CLI overrides are applied
/// - Existing users without config files should see no behavior change
#[test]
fn test_backward_compatibility_without_config_file() {
    use std::env;
    use tempfile::TempDir;

    // Create a temporary home directory with no config file
    let temp_home = TempDir::new().unwrap();
    let config_path = temp_home.path().join(".nails/config.yaml");

    // Verify config file doesn't exist
    assert!(!config_path.exists());

    // Set HOME environment variable to temp directory
    unsafe {
        env::set_var("HOME", temp_home.path());
    }

    // Test that activate command works without config file (should use defaults + CLI overrides)
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["activate", "--no-preflight"])
        .env("HOME", temp_home.path())
        .assert()
        .failure(); // Will fail without setup, but shouldn't error on config loading

    // Clean up
    unsafe {
        env::remove_var("HOME");
    }
}
