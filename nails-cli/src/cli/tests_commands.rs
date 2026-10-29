// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Argument parsing tests for emergency, status, and verify commands, and
//! which commands count as mutating
//!
//! Only parsing is tested here; the CLI integration tests cover execution and
//! the exit statuses the handlers return.

use super::args::{EmergencyArgs, StatusArgs, VerifyArgs};
use super::*;
use clap::CommandFactory;
use std::collections::BTreeSet;

fn parse(argv: &[&str]) -> Cli {
    Cli::try_parse_checked_from(std::iter::once("nails").chain(argv.iter().copied())).unwrap()
}

fn emergency(argv: &[&str]) -> (GlobalArgs, EmergencyArgs) {
    let cli = parse(&[&["emergency"], argv].concat());
    match cli.command {
        Commands::Emergency(args) => (cli.global, args),
        _ => panic!("Expected Emergency command"),
    }
}

fn status(argv: &[&str]) -> (GlobalArgs, StatusArgs) {
    let cli = parse(&[&["status"], argv].concat());
    match cli.command {
        Commands::Status(args) => (cli.global, args),
        _ => panic!("Expected Status command"),
    }
}

fn verify(argv: &[&str]) -> (GlobalArgs, VerifyArgs) {
    let cli = parse(&[&["verify"], argv].concat());
    match cli.command {
        Commands::Verify(args) => (cli.global, args),
        _ => panic!("Expected Verify command"),
    }
}

#[test]
fn test_emergency_args_parsing_defaults() {
    assert_eq!(
        emergency(&[]),
        (GlobalArgs::default(), EmergencyArgs::default())
    );
}

#[test]
fn test_emergency_countdown_flag() {
    assert_eq!(emergency(&["--countdown", "5"]).1.countdown, Some(5));
}

#[test]
fn test_emergency_accepts_global_quiet_in_both_forms() {
    assert!(emergency(&["--quiet"]).0.quiet);
    assert!(emergency(&["-q"]).0.quiet);
}

#[test]
fn test_emergency_verbose_flag() {
    assert_eq!(emergency(&["-v"]).0.verbose, 1);
    assert_eq!(emergency(&["-vv"]).0.verbose, 2);
}

#[test]
fn test_emergency_quiet_verbose_conflict() {
    let result = Cli::try_parse_checked_from(["nails", "emergency", "--quiet", "-v"]);
    assert!(result.is_err(), "Quiet and verbose should conflict");
}

#[test]
fn test_emergency_multiple_flags() {
    let (global, args) = emergency(&["--poweroff", "--json", "--color", "never"]);
    assert!(args.poweroff);
    assert!(global.json);
    assert_eq!(global.color, args::ColorChoice::Never);
}

#[test]
fn test_emergency_delay_flag_removed() {
    let result = Cli::try_parse_checked_from(["nails", "emergency", "--delay", "10"]);
    assert!(result.is_err(), "--delay flag should no longer exist");
}

#[test]
fn test_status_args_parsing_defaults() {
    assert_eq!(status(&[]), (GlobalArgs::default(), StatusArgs::default()));
}

#[test]
fn test_status_details_flag() {
    assert!(status(&["--details"]).1.details);
}

#[test]
fn test_status_verbose_is_global_verbosity_not_details() {
    let (global, args) = status(&["--verbose"]);
    assert_eq!(global.verbose, 1);
    assert!(!args.details);
}

#[test]
fn test_status_json_and_ascii_flags() {
    let (global, args) = status(&["--json", "--ascii", "--details"]);
    assert!(global.json);
    assert!(global.ascii);
    assert!(args.details);
}

#[test]
fn test_status_quiet_in_either_position_is_identical() {
    assert_eq!(
        parse(&["status", "-q"]).global,
        parse(&["-q", "status"]).global
    );
    assert_eq!(
        parse(&["status", "--json"]).global,
        parse(&["--json", "status"]).global
    );
}

#[test]
fn test_verify_flags() {
    assert_eq!(verify(&[]), (GlobalArgs::default(), VerifyArgs::default()));
    let (global, args) = verify(&["--deep", "--json"]);
    assert!(args.deep);
    assert!(global.json);
}

#[test]
fn test_transition_is_a_bare_hidden_subcommand() {
    let cli = parse(&["transition"]);
    assert!(matches!(cli.command, Commands::Transition));
}

#[test]
fn test_only_the_commands_that_change_the_system_count_as_mutating() {
    // An interrupt must roll a mutating command back through its guards
    // instead of killing it halfway through a switch, so it installs the
    // cancellation handlers and sheds OOM priority. Every other command keeps
    // the default signal behaviour, so an interrupt stops it at once.
    let mutating: &[&[&str]] = &[
        &["activate"],
        &["deactivate"],
        &["emergency"],
        &["recover"],
        &["discard", "/home"],
        #[cfg(feature = "gui")]
        &["helper", "--stdio"],
    ];
    let other: &[&[&str]] = &[
        &["status"],
        &["verify"],
        &["rehearse"],
        &["check"],
        &["init", "/mnt/hidden"],
        &["config", "path"],
        &["completions", "bash"],
        &["watch"],
        &["sleep-guard"],
        &["transition"],
        &["guard-device", "/dev/sdb"],
        &["reconcile-records"],
        &["boot-writer"],
    ];
    for argv in mutating {
        assert!(command_is_mutating(&parse(argv).command), "{argv:?}");
    }
    for argv in other {
        assert!(!command_is_mutating(&parse(argv).command), "{argv:?}");
    }

    // Every subcommand is sorted into one of the two lists, so a new one has
    // to be.
    let sorted: BTreeSet<String> = mutating
        .iter()
        .chain(other)
        .map(|argv| argv[0].to_string())
        .collect();
    let subcommands: BTreeSet<String> = Cli::command()
        .get_subcommands()
        .map(|sub| sub.get_name().to_string())
        .filter(|name| name != "help")
        .collect();
    assert_eq!(sorted, subcommands);
}

/// The commands that take the system up or down catch the signals themselves;
/// every other one keeps the default action, which `--json` turns into the
/// cancel envelope of the command whose envelope it prints.
#[test]
fn only_the_commands_that_print_an_envelope_report_a_signal_as_their_cancel() {
    for argv in [
        &["activate"][..],
        &["deactivate"],
        &["emergency"],
        &["recover"],
        &["discard", "/home"],
    ] {
        let command = parse(argv).command;
        assert!(command_is_mutating(&command), "{argv:?}");
    }
    for (argv, name) in [
        (&["activate", "--dry-run"][..], Some("check")),
        (&["status"], Some("status")),
        (&["verify"], Some("verify")),
        (&["rehearse", "scan"], Some("rehearse")),
        (&["check"], Some("check")),
        (&["init", "/mnt/data"], Some("init")),
        (&["config", "path"], Some("config")),
        (&["completions", "bash"], None),
        (&["watch"], None),
        (&["transition"], None),
    ] {
        let command = parse(argv).command;
        assert!(!command_is_mutating(&command), "{argv:?}");
        assert_eq!(envelope_command(&command), name, "{argv:?}");
    }
}
