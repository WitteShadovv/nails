//! Argument parsing tests for activate and deactivate commands

use super::*;
use clap::Parser;

#[test]
fn test_activate_defaults_to_kill_session_yes_and_no_pivot() {
    // Test that parsing activates with defaults applied
    let cli = Cli::try_parse_from(["nails", "activate"]).unwrap();
    if let Commands::Activate {
        kill_session,
        no_kill_session,
        yes,
        interactive,
        no_pivot,
        accept_pivot_risks,
        ..
    } = cli.command
    {
        // Flags default to false when not provided
        assert!(!kill_session);
        assert!(!no_kill_session);
        assert!(!yes);
        assert!(!interactive);
        assert!(!no_pivot);
        assert!(!accept_pivot_risks);
        // The actual defaults are applied in execute_command:
        // kill_session becomes true, yes becomes true, no_pivot becomes true
    } else {
        panic!("Expected Activate command");
    }
}

#[test]
fn test_activate_with_no_kill_session_flag() {
    // Test --no-kill-session flag
    let cli = Cli::try_parse_from(["nails", "activate", "--no-kill-session"]).unwrap();
    if let Commands::Activate {
        no_kill_session, ..
    } = cli.command
    {
        assert!(no_kill_session);
    } else {
        panic!("Expected Activate command");
    }
}

#[test]
fn test_activate_with_interactive_flag() {
    // Test --interactive flag
    let cli = Cli::try_parse_from(["nails", "activate", "--interactive"]).unwrap();
    if let Commands::Activate { interactive, .. } = cli.command {
        assert!(interactive);
    } else {
        panic!("Expected Activate command");
    }
}

#[test]
fn test_activate_with_accept_pivot_risks_flag() {
    // Test --accept-pivot-risks flag
    let cli = Cli::try_parse_from(["nails", "activate", "--accept-pivot-risks"]).unwrap();
    if let Commands::Activate {
        accept_pivot_risks, ..
    } = cli.command
    {
        assert!(accept_pivot_risks);
    } else {
        panic!("Expected Activate command");
    }
}

#[test]
fn test_activate_conflicts_kill_session_with_no_kill_session() {
    // Test that --kill-session and --no-kill-session conflict
    let result = Cli::try_parse_from(["nails", "activate", "--kill-session", "--no-kill-session"]);
    assert!(result.is_err());
}

#[test]
fn test_activate_conflicts_yes_with_interactive() {
    // Test that --yes and --interactive conflict
    let result = Cli::try_parse_from(["nails", "activate", "--yes", "--interactive"]);
    assert!(result.is_err());
}

#[test]
fn test_activate_conflicts_no_pivot_with_accept_pivot_risks() {
    // Test that --no-pivot and --accept-pivot-risks conflict
    let result = Cli::try_parse_from(["nails", "activate", "--no-pivot", "--accept-pivot-risks"]);
    assert!(result.is_err());
}

// ========================================================================
// Deactivate Command Argument Parsing Tests (AC1, AC6, AC8)
// ========================================================================

#[test]
fn test_deactivate_args_parsing_defaults() {
    // AC1: Test default args parsing
    let cli = Cli::try_parse_from(["nails", "deactivate"]).unwrap();
    if let Commands::Deactivate {
        no_clear_history,
        quiet,
        verbose,
        json,
        no_color,
        plain,
    } = cli.command
    {
        assert!(!no_clear_history);
        assert!(!quiet);
        assert_eq!(verbose, 0);
        assert!(!json);
        assert!(!no_color);
        assert!(!plain);
    } else {
        panic!("Expected Deactivate command");
    }
}

#[test]
fn test_deactivate_no_clear_history_flag() {
    // AC6: Test --no-clear-history flag
    let cli = Cli::try_parse_from(["nails", "deactivate", "--no-clear-history"]).unwrap();
    if let Commands::Deactivate {
        no_clear_history, ..
    } = cli.command
    {
        assert!(no_clear_history);
    } else {
        panic!("Expected Deactivate command");
    }
}

#[test]
fn test_deactivate_quiet_flag() {
    // AC1: Test --quiet flag
    let cli = Cli::try_parse_from(["nails", "deactivate", "--quiet"]).unwrap();
    if let Commands::Deactivate { quiet, .. } = cli.command {
        assert!(quiet);
    } else {
        panic!("Expected Deactivate command");
    }
}

#[test]
fn test_deactivate_quiet_short_flag() {
    // AC1: Test -q short flag
    let cli = Cli::try_parse_from(["nails", "deactivate", "-q"]).unwrap();
    if let Commands::Deactivate { quiet, .. } = cli.command {
        assert!(quiet);
    } else {
        panic!("Expected Deactivate command");
    }
}

#[test]
fn test_deactivate_verbose_flag_counting() {
    // AC8: Test -v flag (verbosity level 1)
    let cli = Cli::try_parse_from(["nails", "deactivate", "-v"]).unwrap();
    if let Commands::Deactivate { verbose, .. } = cli.command {
        assert_eq!(verbose, 1);
    } else {
        panic!("Expected Deactivate command");
    }
}

#[test]
fn test_deactivate_verbose_vv_flag() {
    // AC8: Test -vv flag (verbosity level 2 = debug)
    let cli = Cli::try_parse_from(["nails", "deactivate", "-vv"]).unwrap();
    if let Commands::Deactivate { verbose, .. } = cli.command {
        assert_eq!(verbose, 2);
    } else {
        panic!("Expected Deactivate command");
    }
}

#[test]
fn test_deactivate_json_flag() {
    // AC7: Test --json flag
    let cli = Cli::try_parse_from(["nails", "deactivate", "--json"]).unwrap();
    if let Commands::Deactivate { json, .. } = cli.command {
        assert!(json);
    } else {
        panic!("Expected Deactivate command");
    }
}

#[test]
fn test_deactivate_no_color_flag() {
    // AC1: Test --no-color flag
    let cli = Cli::try_parse_from(["nails", "deactivate", "--no-color"]).unwrap();
    if let Commands::Deactivate { no_color, .. } = cli.command {
        assert!(no_color);
    } else {
        panic!("Expected Deactivate command");
    }
}

#[test]
fn test_deactivate_multiple_flags() {
    // Test combining multiple flags
    let cli = Cli::try_parse_from([
        "nails",
        "deactivate",
        "--no-clear-history",
        "--json",
        "--no-color",
    ])
    .unwrap();
    if let Commands::Deactivate {
        no_clear_history,
        json,
        no_color,
        ..
    } = cli.command
    {
        assert!(no_clear_history);
        assert!(json);
        assert!(no_color);
    } else {
        panic!("Expected Deactivate command");
    }
}

#[test]
fn test_deactivate_quiet_verbose_conflict() {
    // AC1: Test that --quiet and --verbose conflict
    let result = Cli::try_parse_from(["nails", "deactivate", "--quiet", "-v"]);
    assert!(result.is_err());
    // Note: clap provides helpful error messages like:
    // "error: the argument '--quiet' cannot be used with '--verbose'"
    // This is validated by manual testing and integration tests
}

// ========================================================================
// Activate --flake flag tests
// ========================================================================

#[test]
fn test_activate_flake_flag() {
    let cli = Cli::try_parse_from([
        "nails",
        "activate",
        "--flake",
        "/etc/nixos#amnesia-virtualbox",
    ])
    .unwrap();
    if let Commands::Activate { nixos_flake, .. } = cli.command {
        assert_eq!(
            nixos_flake,
            Some("/etc/nixos#amnesia-virtualbox".to_string())
        );
    } else {
        panic!("Expected Activate command");
    }
}

#[test]
fn test_activate_flake_flag_path_only() {
    let cli = Cli::try_parse_from(["nails", "activate", "--flake", "/etc/nixos"]).unwrap();
    if let Commands::Activate { nixos_flake, .. } = cli.command {
        assert_eq!(nixos_flake, Some("/etc/nixos".to_string()));
    } else {
        panic!("Expected Activate command");
    }
}

#[test]
fn test_activate_without_flake_flag() {
    let cli = Cli::try_parse_from(["nails", "activate"]).unwrap();
    if let Commands::Activate { nixos_flake, .. } = cli.command {
        assert_eq!(nixos_flake, None);
    } else {
        panic!("Expected Activate command");
    }
}

#[test]
fn test_global_verbose_flag_is_preserved_for_activate_command() {
    let cli = Cli::try_parse_from(["nails", "-v", "activate", "--no-kill-session"]).unwrap();
    assert_eq!(cli.verbose, 1);

    if let Commands::Activate { verbose, .. } = cli.command {
        assert_eq!(verbose, 0);
    } else {
        panic!("Expected Activate command");
    }
}

#[test]
fn test_activate_flake_flag_with_equals_syntax() {
    let cli = Cli::try_parse_from(["nails", "activate", "--flake=/etc/nixos#my-host"]).unwrap();
    if let Commands::Activate { nixos_flake, .. } = cli.command {
        assert_eq!(nixos_flake, Some("/etc/nixos#my-host".to_string()));
    } else {
        panic!("Expected Activate command");
    }
}
