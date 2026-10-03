//! Argument parsing tests for emergency, status, and verify commands
//!
//! Only parsing is tested here; the CLI integration tests cover execution and
//! the exit statuses the handlers return.

use super::args::{EmergencyArgs, StatusArgs, VerifyArgs};
use super::*;

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
fn test_notify_dispatch_takes_global_json() {
    let cli = parse(&["notify-dispatch", "--json"]);
    assert!(matches!(cli.command, Commands::NotifyDispatch));
    assert!(cli.global.json);
}
