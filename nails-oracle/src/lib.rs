// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # NAILS forensic oracle
//!
//! A CI tool that turns the output of disk-image analysis tools into a
//! pass/fail verdict on whether a torn-down hidden session left a trace.
//!
//! It compares three images of one host — `before` the session, a clean
//! `control` boot cycle, and `after` the session — by what `btrfs restore`,
//! `bulk_extractor` and `plaso` recover from each. A difference in `after` is a
//! leak unless it also appears in the clean control cycle (scan noise) or a
//! cited allowlist entry explains it. Two self-checks keep a clean verdict
//! honest: planted positive controls must be detected (or the scan is blind),
//! and a coverage canary must be detected (or the scan did not read the image).
//!
//! The decision lives in [`verdict::verdict`], a pure function unit-tested over
//! synthetic findings. The [`scan`] parsers that feed it are best-effort for
//! the synthetic slice; the [`catalog`] a citation resolves against is the live
//! residue catalog, linked out of `nails-forensics` so it cannot drift.
//!
//! The actual CLI logic is in this library to allow for proper unit test
//! coverage; `main.rs` only forwards the process arguments to [`run`].

// Unsafe code is denied workspace-wide (see the root Cargo.toml). Test code
// may use it freely; production code opts in per site with a scoped allow.
#![cfg_attr(test, allow(unsafe_code))]

pub mod catalog;
pub mod model;
pub mod scan;
pub mod verdict;

#[cfg(test)]
mod tests;

pub use catalog::{Catalog, CatalogRow};
pub use model::{
    AllowEntry, Allowlist, Canary, Controls, Finding, ImageLabel, OraclePolicy, PositiveControl,
    Scans, Tool,
};
pub use verdict::{ControlResult, Counts, Explained, Failure, Status, Verdict, verdict as decide};

use std::path::PathBuf;
use std::process::ExitCode;

/// Where the cited allowlist and the scan self-checks live by default,
/// relative to the repository root the CI job runs from.
const DEFAULT_ALLOWLIST: &str = "ci/oracle/allowlist.json";
const DEFAULT_CONTROLS: &str = "ci/oracle/controls.json";

const USAGE: &str = "\
usage: nails-oracle <outputs-dir> [--allowlist FILE] [--controls FILE]

Render a pass/fail forensic verdict over one scan's outputs/ tree.

  <outputs-dir>     the scan's outputs/ directory (restore/, bulk_extractor/, plaso/)
  --allowlist FILE  cited allowlist JSON (default: ci/oracle/allowlist.json)
  --controls FILE   positive-control + canary JSON (default: ci/oracle/controls.json)

Prints the verdict as JSON to stdout and a one-line summary to stderr.
Exit codes: 0 clean, 1 fail (residue / blind / canary / bad allowlist), 2 usage or I/O error.";

/// Parsed command line.
struct Options {
    outputs: PathBuf,
    allowlist: PathBuf,
    controls: PathBuf,
}

impl Options {
    /// Parse the arguments (program name already stripped).
    fn parse(args: &[String]) -> Result<Options, String> {
        let mut outputs = None;
        let mut allowlist = PathBuf::from(DEFAULT_ALLOWLIST);
        let mut controls = PathBuf::from(DEFAULT_CONTROLS);
        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];
            match arg.as_str() {
                "--allowlist" => allowlist = take(args, &mut i, "--allowlist")?,
                "--controls" => controls = take(args, &mut i, "--controls")?,
                other if other.starts_with('-') => {
                    return Err(format!("unknown option {other}\n\n{USAGE}"));
                }
                _ => {
                    if outputs.is_some() {
                        return Err(format!("unexpected argument {arg}\n\n{USAGE}"));
                    }
                    outputs = Some(PathBuf::from(arg));
                }
            }
            i += 1;
        }
        let outputs = outputs.ok_or_else(|| format!("missing <outputs-dir>\n\n{USAGE}"))?;
        Ok(Options {
            outputs,
            allowlist,
            controls,
        })
    }
}

/// Consume the value that follows a flag.
fn take(args: &[String], i: &mut usize, flag: &str) -> Result<PathBuf, String> {
    *i += 1;
    args.get(*i)
        .map(PathBuf::from)
        .ok_or_else(|| format!("{flag} needs a value"))
}

/// Run the oracle over the given process arguments (program name stripped),
/// returning the process exit code. This is the whole CLI; `main` only calls
/// it.
pub fn run(args: impl Iterator<Item = String>) -> ExitCode {
    let args: Vec<String> = args.collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    match run_inner(&args) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("nails-oracle: {message}");
            ExitCode::from(2)
        }
    }
}

/// The fallible body of [`run`].
fn run_inner(args: &[String]) -> Result<u8, String> {
    let opts = Options::parse(args)?;
    let allowlist = scan::load_allowlist(&opts.allowlist).map_err(|e| e.to_string())?;
    let controls = scan::load_controls(&opts.controls).map_err(|e| e.to_string())?;
    let scans = scan::scan_all(&opts.outputs).map_err(|e| e.to_string())?;
    let catalog = Catalog::from_forensics();
    let policy = OraclePolicy {
        allowlist,
        controls,
    };
    let verdict = verdict::verdict(&scans, &policy, &catalog);
    let json = serde_json::to_string_pretty(&verdict).map_err(|e| e.to_string())?;
    println!("{json}");
    eprintln!("{}", verdict.summary);
    Ok(verdict.exit_code())
}

/// Tests for the CLI front end: argument parsing, the `-h`/`--help`
/// short-circuit and the exit-code mapping. These exercise the argument plumbing
/// directly (the verdict engine has its own unit tests in `tests.rs`), with no
/// policy files on disk, so each asserts an observable contract of `run`.
#[cfg(test)]
mod cli_tests {
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
}
