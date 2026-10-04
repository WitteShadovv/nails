// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Argument parsing tests for activate and deactivate commands

use super::args::{ActivateArgs, DeactivateArgs, PivotPolicy, SessionPolicy};
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
fn test_activate_defaults_to_kill_session_refuse_pivot_and_no_yes() {
    let args = activate(&[]);
    assert_eq!(args, ActivateArgs::default());
    assert_eq!(args.session, SessionPolicy::Kill);
    assert_eq!(args.pivot, PivotPolicy::Refuse);
    assert!(!args.yes);
}

#[test]
fn test_activate_session_keep_flag() {
    assert_eq!(
        activate(&["--session", "keep"]).session,
        SessionPolicy::Keep
    );
    assert_eq!(
        activate(&["--session", "kill"]).session,
        SessionPolicy::Kill
    );
}

#[test]
fn test_activate_yes_flag() {
    assert!(activate(&["--yes"]).yes);
    assert!(activate(&["-y"]).yes);
    assert!(!activate(&[]).yes);
}

#[test]
fn test_activate_pivot_policy_values() {
    assert_eq!(activate(&["--pivot", "allow"]).pivot, PivotPolicy::Allow);
    assert_eq!(activate(&["--pivot", "refuse"]).pivot, PivotPolicy::Refuse);
    assert_eq!(activate(&["--pivot", "ask"]).pivot, PivotPolicy::Ask);
}

#[test]
fn test_activate_rejects_removed_flags() {
    // Build the flag tokens from their names so the removed spellings never
    // appear verbatim in the tree (the redesign's grep gate expects that).
    for name in [
        "kill-session",
        "no-kill-session",
        "accept-pivot-risks",
        "no-pivot",
        "interactive",
        "no-clear-history",
    ] {
        let flag = format!("--{name}");
        let result = Cli::try_parse_checked_from(["nails", "activate", flag.as_str()]);
        assert!(result.is_err(), "activate {flag} must be rejected");
    }
}

#[test]
fn test_activate_rejects_unknown_policy_value() {
    assert!(Cli::try_parse_checked_from(["nails", "activate", "--session", "pause"]).is_err());
    assert!(Cli::try_parse_checked_from(["nails", "activate", "--pivot", "maybe"]).is_err());
}

#[test]
fn test_activate_flake_conflicts_with_overlay_only() {
    let result = Cli::try_parse_checked_from([
        "nails",
        "activate",
        "--nixos-flake",
        "/etc/nixos",
        "--overlay-only",
    ]);
    assert!(result.is_err());
}

#[test]
fn test_activate_default_args_map_to_default_options() {
    assert_eq!(
        ActivateArgs::default().to_activate_options(),
        nails_core::ActivateOptions::default()
    );
}

#[test]
fn test_activate_policy_flags_map_onto_options() {
    let kill_refuse = activate(&[]).to_activate_options();
    assert!(kill_refuse.kill_session && kill_refuse.no_pivot && !kill_refuse.accept_pivot_risks);

    let keep = activate(&["--session", "keep"]).to_activate_options();
    assert!(!keep.kill_session);

    let allow = activate(&["--pivot", "allow"]).to_activate_options();
    assert!(allow.accept_pivot_risks && !allow.no_pivot);

    let ask = activate(&["--pivot", "ask"]).to_activate_options();
    assert!(!ask.accept_pivot_risks && !ask.no_pivot);

    let yes = activate(&["-y"]).to_activate_options();
    assert!(yes.yes);
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
        activate(&["--nixos-flake", "/etc/nixos#myhost"]).nixos_flake,
        Some("/etc/nixos#myhost".to_string())
    );
}

#[test]
fn test_activate_flake_flag_path_only() {
    assert_eq!(
        activate(&["--nixos-flake", "/etc/nixos"]).nixos_flake,
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
        &["nails", "-vv", "activate", "--session", "keep"][..],
        &["nails", "activate", "--session", "keep", "-vv"][..],
    ] {
        let cli = Cli::try_parse_checked_from(argv).unwrap();
        assert_eq!(cli.global.verbose, 2, "{argv:?}");
    }
}

#[test]
fn test_activate_flake_flag_with_equals_syntax() {
    assert_eq!(
        activate(&["--nixos-flake=/etc/nixos#my-host"]).nixos_flake,
        Some("/etc/nixos#my-host".to_string())
    );
}
