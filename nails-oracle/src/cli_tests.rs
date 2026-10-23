// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the CLI front end: argument parsing, the `-h`/`--help`
//! short-circuit and the exit-code mapping. These exercise the argument
//! plumbing directly (the verdict engine has its own unit tests in `tests.rs`),
//! with no policy files on disk, so each asserts an observable contract of
//! `run`.

use super::{DEFAULT_ALLOWLIST, DEFAULT_CONTROLS, Options, run, run_inner};
use std::path::PathBuf;
use std::process::ExitCode;

/// Build an owned argument vector (program name already stripped).
fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| (*s).to_string()).collect()
}

/// A single positional argument is the outputs dir, and the two policy
/// paths default. Covers the loop bound `i < args.len()` at the boundary
/// (a `==`/`>` body never runs → missing outputs; a `<=` body reads one
/// past the end → index panic) and the positional vs. option dispatch.
#[test]
fn parse_takes_a_positional_outputs_dir_and_defaults_the_policy_paths() {
    let opts = Options::parse(&args(&["scan/outputs"])).expect("a bare dir parses");
    assert_eq!(opts.outputs, PathBuf::from("scan/outputs"));
    assert_eq!(opts.allowlist, PathBuf::from(DEFAULT_ALLOWLIST));
    assert_eq!(opts.controls, PathBuf::from(DEFAULT_CONTROLS));
}

/// A leading dash with no matching flag arm is an error, not a positional:
/// this pins the `other.starts_with('-')` match guard (dropping it, or
/// forcing it false, would swallow `--bogus` as the outputs dir).
#[test]
fn parse_rejects_an_unknown_option() {
    // `Options` is not `Debug`, so match rather than `expect_err`.
    match Options::parse(&args(&["--bogus"])) {
        Ok(_) => panic!("an unknown flag must be rejected, not taken as the outputs dir"),
        Err(err) => assert!(err.contains("unknown option --bogus"), "{err}"),
    }
}

/// `--allowlist FILE` consumes the following value. The flag is first so the
/// index advance in `take` is exercised from zero: a `-=` there underflows
/// (or yields a "needs a value" error) and a `*=` re-reads the flag itself,
/// while a stubbed `take` returns an empty path — all diverge from the
/// value actually taken.
#[test]
fn parse_consumes_the_allowlist_flag_value() {
    let opts = Options::parse(&args(&["--allowlist", "my/allow.json", "scan"]))
        .expect("the flag and its value parse");
    assert_eq!(opts.allowlist, PathBuf::from("my/allow.json"));
    assert_eq!(opts.outputs, PathBuf::from("scan"));
    // The other policy path keeps its default, untouched by --allowlist.
    assert_eq!(opts.controls, PathBuf::from(DEFAULT_CONTROLS));
}

/// `--controls FILE` consumes the following value; pins the `--controls`
/// match arm (dropping it would treat the flag as an unknown option).
#[test]
fn parse_consumes_the_controls_flag_value() {
    let opts = Options::parse(&args(&["--controls", "my/ctl.json", "scan"]))
        .expect("the flag and its value parse");
    assert_eq!(opts.controls, PathBuf::from("my/ctl.json"));
    assert_eq!(opts.outputs, PathBuf::from("scan"));
    assert_eq!(opts.allowlist, PathBuf::from(DEFAULT_ALLOWLIST));
}

/// With no outputs dir, the fallible body reports a usage error rather than
/// a success code. Pins `run_inner` against a stubbed `Ok(0)`/`Ok(1)`
/// (either would silence the missing-argument failure). Parsing fails before
/// any file is touched, so this needs nothing on disk.
#[test]
fn run_inner_errors_when_the_outputs_dir_is_missing() {
    let err = run_inner(&args(&[])).expect_err("a missing outputs dir is an error");
    assert!(err.contains("missing <outputs-dir>"), "{err}");
}

/// The Debug rendering of an `ExitCode`, used below to compare exit codes
/// (`ExitCode` is not `PartialEq`). The two reference codes must render
/// differently, or the comparisons below would be vacuous.
fn exit_debug(parts: &[&str]) -> String {
    format!("{:?}", run(args(parts).into_iter()))
}

/// `-h`/`--help` short-circuit to a success exit, while a non-help
/// invocation that cannot proceed exits with code 2. Pins the help probe
/// `a == "-h" || a == "--help"` (flipping either `==` to `!=`, or `||` to
/// `&&`, misroutes at least one of these inputs) and the `ExitCode`
/// mapping in `run` (a stubbed default success would not reach code 2).
#[test]
fn run_maps_help_and_failure_to_the_right_exit_codes() {
    let success = format!("{:?}", ExitCode::SUCCESS);
    let two = format!("{:?}", ExitCode::from(2));
    assert_ne!(
        success, two,
        "ExitCode's Debug must distinguish distinct codes for this test to mean anything"
    );
    // Both help spellings short-circuit to a clean exit.
    assert_eq!(exit_debug(&["-h"]), success, "-h exits clean");
    assert_eq!(exit_debug(&["--help"]), success, "--help exits clean");
    // A non-help invocation with no outputs dir fails usage with code 2.
    assert_eq!(
        exit_debug(&[]),
        two,
        "no arguments is a usage error (code 2)"
    );
}
