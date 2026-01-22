//! Integration tests for NAILS CLI
//!
//! These tests verify the CLI binary:
//! - Executes correctly
//! - Displays version from Cargo.toml (not hardcoded)
//! - Parses all commands and flags
//! - Links properly to nails-core library

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

/// Test that the CLI binary exists and runs
#[test]
fn test_cli_binary_runs() {
    let mut cmd = Command::cargo_bin("nails").expect("Failed to find nails binary");
    cmd.arg("--version").assert().success();
}

/// Test that version is pulled from Cargo.toml (workspace-level versioning)
#[test]
fn test_version_from_cargo_toml() {
    let mut cmd = Command::cargo_bin("nails").expect("Failed to find nails binary");
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains("nails 0.1.0"));
}

/// Test that --help flag works
#[test]
fn test_help_flag() {
    let mut cmd = Command::cargo_bin("nails").expect("Failed to find nails binary");
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicates::str::contains(
            "NixOS Anti-forensics Isolation & Layering System",
        ));
}

/// Test that activate command accepts --force flag
#[test]
fn test_activate_command_force_flag() {
    let mut cmd = Command::cargo_bin("nails").expect("Failed to find nails binary");
    cmd.args(["activate", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--force"))
        .stdout(predicates::str::contains(
            "Force activation even if preflight checks fail",
        ));
}

/// Test that deactivate command accepts --fast flag
#[test]
fn test_deactivate_command_fast_flag() {
    let mut cmd = Command::cargo_bin("nails").expect("Failed to find nails binary");
    cmd.args(["deactivate", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--fast"))
        .stdout(predicates::str::contains("Quick cleanup mode"));
}

/// Test that emergency command accepts --delay flag with default
#[test]
fn test_emergency_command_delay_flag() {
    let mut cmd = Command::cargo_bin("nails").expect("Failed to find nails binary");
    cmd.args(["emergency", "--help"])
        .assert()
        .success()
        .stdout(predicates::str::contains("--delay"))
        .stdout(predicates::str::contains("[default: 10]"));
}

/// Test that status command accepts --verbose flag
#[test]
fn test_status_command_verbose_flag() {
    let mut cmd = Command::cargo_bin("nails").expect("Failed to find nails binary");
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
    let mut cmd = Command::cargo_bin("nails").expect("Failed to find nails binary");
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
    let mut cmd = Command::cargo_bin("nails").expect("Failed to find nails binary");
    cmd.arg("--version").assert().success();
}

/// Test that verbose flag (-v) is accepted
#[test]
fn test_verbose_flag() {
    let mut cmd = Command::cargo_bin("nails").expect("Failed to find nails binary");
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
        let mut cmd = Command::cargo_bin("nails").expect("Failed to find nails binary");
        cmd.args([command, "--help"])
            .assert()
            .success()
            .stdout(predicates::str::is_empty().not()); // Should have output
    }
}
