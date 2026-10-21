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
