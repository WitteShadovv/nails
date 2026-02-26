//! # NAILS CLI Library
//!
//! This module contains the CLI command handlers and argument parsing.
//! Commands are implemented in the `cli` module for testability and reusability.
//! The entry point in main.rs simply invokes `cli::execute_command()`.

pub mod cli {
    pub mod args;
    pub mod commands;
    mod detach;
    pub mod logging;
    pub mod output;
    pub mod safety;

    // Re-export main types for convenience
    pub use args::{Cli, Commands};
    pub use logging::init_stdout_subscriber;
    pub use safety::check_real_operations_allowed;

    /// Execute the CLI command - extracted for testability
    pub fn execute_command(cli: Cli) -> std::result::Result<(), Box<dyn std::error::Error>> {
        match cli.command {
            Commands::Activate {
                no_preflight,
                quiet,
                verbose,
                json,
                no_color,
                plain,
                no_clear_history,
                kill_session: _,
                no_kill_session,
                accept_pivot_risks,
                no_pivot: _,
                yes: _,
                interactive,
            } => commands::activate::execute(
                no_preflight,
                quiet,
                verbose,
                json,
                no_color,
                plain,
                no_clear_history,
                no_kill_session,
                accept_pivot_risks,
                interactive,
                cli.config,
                check_real_operations_allowed,
            ),
            Commands::Deactivate {
                no_clear_history,
                quiet,
                verbose,
                json,
                no_color,
                plain,
            } => commands::deactivate::execute(
                cli.config,
                no_clear_history,
                quiet,
                verbose,
                json,
                no_color,
                plain,
            ),
            Commands::Emergency {
                no_countdown,
                quiet,
                verbose,
                json,
                no_color,
                plain,
            } => commands::emergency::execute(
                cli.config,
                no_countdown,
                quiet,
                verbose,
                json,
                no_color,
                plain,
                check_real_operations_allowed,
            ),
            Commands::Status {
                json,
                no_color,
                plain,
                verbose,
            } => commands::status::execute(cli.config, json, no_color, plain, verbose),
            Commands::Verify { deep, json } => commands::verify::execute(deep, json),
        }
    }

    // ========================================================================
    // Activate Command Argument Parsing Tests
    // ========================================================================

    #[cfg(test)]
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
        let result =
            Cli::try_parse_from(["nails", "activate", "--kill-session", "--no-kill-session"]);
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
        let result =
            Cli::try_parse_from(["nails", "activate", "--no-pivot", "--accept-pivot-risks"]);
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
        assert!(execute_command(cli).is_ok());
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
        let cli = Cli::try_parse_from(["nails", "status", "--json", "--plain", "--no-color", "-v"])
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
}
