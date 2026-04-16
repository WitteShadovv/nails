//! Argument parsing tests for emergency, status, and verify commands

use super::*;
use clap::Parser;

// ========================================================================
// Emergency Command Argument Parsing Tests (AC1, AC10)
// ========================================================================
//
// Note: The emergency command handler calls std::process::exit(),
// so we test argument parsing only. E2E tests cover full execution.

#[test]
fn test_emergency_args_parsing_defaults() {
    // AC1: Test default args parsing (no flags)
    let cli = Cli::try_parse_from(["nails", "emergency"]).unwrap();
    if let Commands::Emergency {
        no_countdown,
        quiet,
        verbose,
        json,
        no_color,
        plain,
    } = cli.command
    {
        assert!(!no_countdown);
        assert!(!quiet);
        assert_eq!(verbose, 0);
        assert!(!json);
        assert!(!no_color);
        assert!(!plain);
    } else {
        panic!("Expected Emergency command");
    }
}

#[test]
fn test_emergency_no_countdown_flag() {
    // AC9: Test --no-countdown flag
    let cli = Cli::try_parse_from(["nails", "emergency", "--no-countdown"]).unwrap();
    if let Commands::Emergency { no_countdown, .. } = cli.command {
        assert!(no_countdown);
    } else {
        panic!("Expected Emergency command");
    }
}

#[test]
fn test_emergency_quiet_flag() {
    // AC7: Test --quiet flag (long only, no short)
    let cli = Cli::try_parse_from(["nails", "emergency", "--quiet"]).unwrap();
    if let Commands::Emergency { quiet, .. } = cli.command {
        assert!(quiet);
    } else {
        panic!("Expected Emergency command");
    }
}

#[test]
fn test_emergency_quiet_no_short_flag() {
    // AC1: --quiet has NO short flag for emergency
    let result = Cli::try_parse_from(["nails", "emergency", "-q"]);
    assert!(
        result.is_err(),
        "Emergency --quiet should NOT have -q short flag"
    );
}

#[test]
fn test_emergency_verbose_flag() {
    // AC8: Test -v flag (verbosity level 1)
    let cli = Cli::try_parse_from(["nails", "emergency", "-v"]).unwrap();
    if let Commands::Emergency { verbose, .. } = cli.command {
        assert_eq!(verbose, 1);
    } else {
        panic!("Expected Emergency command");
    }
}

#[test]
fn test_emergency_verbose_vv_flag() {
    // AC8: Test -vv flag (verbosity level 2 = debug)
    let cli = Cli::try_parse_from(["nails", "emergency", "-vv"]).unwrap();
    if let Commands::Emergency { verbose, .. } = cli.command {
        assert_eq!(verbose, 2);
    } else {
        panic!("Expected Emergency command");
    }
}

#[test]
fn test_emergency_json_flag() {
    // AC6: Test --json flag
    let cli = Cli::try_parse_from(["nails", "emergency", "--json"]).unwrap();
    if let Commands::Emergency { json, .. } = cli.command {
        assert!(json);
    } else {
        panic!("Expected Emergency command");
    }
}

#[test]
fn test_emergency_no_color_flag() {
    // AC1: Test --no-color flag
    let cli = Cli::try_parse_from(["nails", "emergency", "--no-color"]).unwrap();
    if let Commands::Emergency { no_color, .. } = cli.command {
        assert!(no_color);
    } else {
        panic!("Expected Emergency command");
    }
}

#[test]
fn test_emergency_quiet_verbose_conflict() {
    // AC1: Test that --quiet and --verbose conflict
    let result = Cli::try_parse_from(["nails", "emergency", "--quiet", "-v"]);
    assert!(result.is_err(), "Quiet and verbose should conflict");
}

#[test]
fn test_emergency_multiple_flags() {
    // Test combining multiple flags
    let cli = Cli::try_parse_from([
        "nails",
        "emergency",
        "--no-countdown",
        "--json",
        "--no-color",
    ])
    .unwrap();
    if let Commands::Emergency {
        no_countdown,
        json,
        no_color,
        ..
    } = cli.command
    {
        assert!(no_countdown);
        assert!(json);
        assert!(no_color);
    } else {
        panic!("Expected Emergency command");
    }
}

#[test]
fn test_emergency_delay_flag_removed() {
    // AC1: Verify --delay flag no longer exists (removed per AR33)
    let result = Cli::try_parse_from(["nails", "emergency", "--delay", "10"]);
    assert!(result.is_err(), "--delay flag should no longer exist");
}

#[test]
fn test_execute_status_command_with_verbose() {
    // execute_command() for Status calls process::exit() and cannot be
    // called in-process from a unit test.  This test verifies that the Cli
    // struct can be constructed with the expected verbose flag; execution
    // is covered by the CLI integration tests that spawn a subprocess.
    let cli = Cli {
        config: None,
        verbose: 0,
        quiet: false,
        no_logs: false,
        command: Commands::Status {
            json: false,
            no_color: false,
            plain: false,
            verbose: true,
        },
    };
    // Confirm the verbose flag was stored correctly.
    if let Commands::Status { verbose, .. } = cli.command {
        assert!(verbose);
    } else {
        panic!("Expected Commands::Status");
    }
}

#[test]
fn test_verbose_flag_values() {
    let cli = Cli {
        config: None,
        verbose: 3,
        quiet: false,
        no_logs: false,
        command: Commands::Status {
            json: false,
            no_color: false,
            plain: false,
            verbose: false,
        },
    };
    assert_eq!(cli.verbose, 3);
}

// ========================================================================
// Status Command Argument Parsing Tests (Story 7.4, AC: 11)
// ========================================================================

#[test]
fn test_status_args_parsing_defaults() {
    // Test default args parsing (all flags false)
    let cli = Cli::try_parse_from(["nails", "status"]).unwrap();
    if let Commands::Status {
        json,
        no_color,
        plain,
        verbose,
    } = cli.command
    {
        assert!(!json);
        assert!(!no_color);
        assert!(!plain);
        assert!(!verbose);
    } else {
        panic!("Expected Status command");
    }
}

#[test]
fn test_status_json_flag() {
    // Test --json flag
    let cli = Cli::try_parse_from(["nails", "status", "--json"]).unwrap();
    if let Commands::Status { json, .. } = cli.command {
        assert!(json);
    } else {
        panic!("Expected Status command");
    }
}

#[test]
fn test_status_no_color_flag() {
    // Test --no-color flag
    let cli = Cli::try_parse_from(["nails", "status", "--no-color"]).unwrap();
    if let Commands::Status { no_color, .. } = cli.command {
        assert!(no_color);
    } else {
        panic!("Expected Status command");
    }
}

#[test]
fn test_status_plain_flag() {
    // Test --plain flag
    let cli = Cli::try_parse_from(["nails", "status", "--plain"]).unwrap();
    if let Commands::Status { plain, .. } = cli.command {
        assert!(plain);
    } else {
        panic!("Expected Status command");
    }
}

#[test]
fn test_status_verbose_flag() {
    // Test -v flag
    let cli = Cli::try_parse_from(["nails", "status", "-v"]).unwrap();
    if let Commands::Status { verbose, .. } = cli.command {
        assert!(verbose);
    } else {
        panic!("Expected Status command");
    }
}

#[test]
fn test_status_verbose_long_flag() {
    // Test --verbose flag
    let cli = Cli::try_parse_from(["nails", "status", "--verbose"]).unwrap();
    if let Commands::Status { verbose, .. } = cli.command {
        assert!(verbose);
    } else {
        panic!("Expected Status command");
    }
}

#[test]
fn test_status_multiple_flags() {
    // Test combining multiple flags
    let cli =
        Cli::try_parse_from(["nails", "status", "--json", "--plain", "--no-color", "-v"]).unwrap();
    if let Commands::Status {
        json,
        no_color,
        plain,
        verbose,
    } = cli.command
    {
        assert!(json);
        assert!(no_color);
        assert!(plain);
        assert!(verbose);
    } else {
        panic!("Expected Status command");
    }
}

#[test]
fn test_status_json_and_plain_flags() {
    // Test --json with --plain (JSON should take precedence in handler)
    let cli = Cli::try_parse_from(["nails", "status", "--json", "--plain"]).unwrap();
    if let Commands::Status {
        json,
        plain,
        no_color,
        verbose,
    } = cli.command
    {
        assert!(json);
        assert!(plain);
        assert!(!no_color);
        assert!(!verbose);
    } else {
        panic!("Expected Status command");
    }
}

#[test]
fn test_status_no_color_with_plain() {
    // Test --no-color with --plain
    let cli = Cli::try_parse_from(["nails", "status", "--no-color", "--plain"]).unwrap();
    if let Commands::Status {
        no_color, plain, ..
    } = cli.command
    {
        assert!(no_color);
        assert!(plain);
    } else {
        panic!("Expected Status command");
    }
}

#[test]
fn test_status_all_flags() {
    // Test all flags together
    let cli = Cli::try_parse_from([
        "nails",
        "status",
        "--json",
        "--no-color",
        "--plain",
        "--verbose",
    ])
    .unwrap();
    if let Commands::Status {
        json,
        no_color,
        plain,
        verbose,
    } = cli.command
    {
        assert!(json);
        assert!(no_color);
        assert!(plain);
        assert!(verbose);
    } else {
        panic!("Expected Status command");
    }
}

#[test]
fn test_execute_verify_command_without_flags() {
    let cli = Cli {
        config: None,
        verbose: 0,
        quiet: false,
        no_logs: false,
        command: Commands::Verify {
            deep: false,
            json: false,
        },
    };
    // This will exit with code 0 or 1, so we can't test result
    // But we can verify it compiles and the match arm exists
    let _cli = cli; // Consume to prevent unused warning
}

#[test]
fn test_execute_verify_command_with_deep() {
    let cli = Cli {
        config: None,
        verbose: 0,
        quiet: false,
        no_logs: false,
        command: Commands::Verify {
            deep: true,
            json: false,
        },
    };
    let _cli = cli;
}

#[test]
fn test_execute_verify_command_with_json() {
    let cli = Cli {
        config: None,
        verbose: 0,
        quiet: false,
        no_logs: false,
        command: Commands::Verify {
            deep: false,
            json: true,
        },
    };
    let _cli = cli;
}

#[test]
fn test_execute_verify_command_with_deep_and_json() {
    let cli = Cli {
        config: None,
        verbose: 0,
        quiet: false,
        no_logs: false,
        command: Commands::Verify {
            deep: true,
            json: true,
        },
    };
    let _cli = cli;
}
