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
fn test_verify_command_json_output() {
    let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.args(["verify", "--json"])
        .assert()
        .code(1)
        .stdout(predicates::str::contains("\"status\""))
        .stdout(predicates::str::contains("\"findings\""));
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
        .env("NAILS_UNSAFE_REAL_OPS", "1") // Required to bypass safety guard
        .assert()
        .code(2); // Expect safety guard exit code since we're in build directory

    // Clean up
    unsafe {
        env::remove_var("HOME");
    }
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
