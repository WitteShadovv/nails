//! Argument parsing tests for activate and deactivate commands

use super::args::{ActivateArgs, DeactivateArgs};
use super::*;

fn activate(args: &[&str]) -> ActivateArgs {
    let cli = Cli::try_parse_checked_from(["nails", "activate"].iter().chain(args)).unwrap();
    match cli.command {
        Commands::Activate(args) => args,
        _ => panic!("Expected Activate command"),
    }
}

fn deactivate(args: &[&str]) -> (GlobalArgs, DeactivateArgs) {
    let cli = Cli::try_parse_checked_from(["nails", "deactivate"].iter().chain(args)).unwrap();
    match cli.command {
        Commands::Deactivate(args) => (cli.global, args),
        _ => panic!("Expected Deactivate command"),
    }
}

#[test]
fn test_activate_defaults_to_kill_session_yes_and_no_pivot() {
    // Flags default to false when not provided; the handler applies the
    // effective defaults (kill session, yes, no pivot).
    assert_eq!(activate(&[]), ActivateArgs::default());
}

#[test]
fn test_activate_with_no_kill_session_flag() {
    assert!(activate(&["--no-kill-session"]).no_kill_session);
}

#[test]
fn test_activate_with_interactive_flag() {
    assert!(activate(&["--interactive"]).interactive);
}

#[test]
fn test_activate_with_accept_pivot_risks_flag() {
    assert!(activate(&["--accept-pivot-risks"]).accept_pivot_risks);
}

#[test]
fn test_activate_conflicts_kill_session_with_no_kill_session() {
    let result =
        Cli::try_parse_checked_from(["nails", "activate", "--kill-session", "--no-kill-session"]);
    assert!(result.is_err());
}

#[test]
fn test_activate_conflicts_yes_with_interactive() {
    let result = Cli::try_parse_checked_from(["nails", "activate", "--yes", "--interactive"]);
    assert!(result.is_err());
}

#[test]
fn test_activate_conflicts_no_pivot_with_accept_pivot_risks() {
    let result =
        Cli::try_parse_checked_from(["nails", "activate", "--no-pivot", "--accept-pivot-risks"]);
    assert!(result.is_err());
}

#[test]
fn test_deactivate_args_parsing_defaults() {
    let (global, args) = deactivate(&[]);
    assert_eq!(global, GlobalArgs::default());
    assert_eq!(args, DeactivateArgs::default());
}

#[test]
fn test_deactivate_no_clear_history_flag() {
    assert!(deactivate(&["--no-clear-history"]).1.no_clear_history);
}

#[test]
fn test_deactivate_accepts_global_output_flags() {
    let (global, args) = deactivate(&["--no-clear-history", "--json", "--color", "never", "-q"]);
    assert!(args.no_clear_history);
    assert!(global.json);
    assert!(global.quiet);
    assert_eq!(global.color, args::ColorChoice::Never);
}

#[test]
fn test_deactivate_verbose_flag_counting() {
    assert_eq!(deactivate(&["-v"]).0.verbose, 1);
    assert_eq!(deactivate(&["-vv"]).0.verbose, 2);
}

#[test]
fn test_deactivate_quiet_verbose_conflict() {
    let result = Cli::try_parse_checked_from(["nails", "deactivate", "--quiet", "-v"]);
    assert!(result.is_err());
}

#[test]
fn test_activate_flake_flag() {
    assert_eq!(
        activate(&["--flake", "/etc/nixos#amnesia-virtualbox"]).nixos_flake,
        Some("/etc/nixos#amnesia-virtualbox".to_string())
    );
}

#[test]
fn test_activate_flake_flag_path_only() {
    assert_eq!(
        activate(&["--flake", "/etc/nixos"]).nixos_flake,
        Some("/etc/nixos".to_string())
    );
}

#[test]
fn test_activate_without_flake_flag() {
    assert_eq!(activate(&[]).nixos_flake, None);
}

#[test]
fn test_verbosity_reaches_activate_from_either_position() {
    for argv in [
        &["nails", "-vv", "activate", "--no-kill-session"][..],
        &["nails", "activate", "--no-kill-session", "-vv"][..],
    ] {
        let cli = Cli::try_parse_checked_from(argv).unwrap();
        assert_eq!(cli.global.verbose, 2, "{argv:?}");
    }
}

#[test]
fn test_activate_flake_flag_with_equals_syntax() {
    assert_eq!(
        activate(&["--flake=/etc/nixos#my-host"]).nixos_flake,
        Some("/etc/nixos#my-host".to_string())
    );
}
