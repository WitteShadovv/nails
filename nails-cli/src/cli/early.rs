// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Early dispatch of the emergency hot path, before clap, the configuration,
//! the environment snapshot and tracing exist (ADR 0007).
//!
//! `main` calls [`dispatch`] first. When the command line is an `emergency`
//! that clap will accept, the process runs as root and a teardown plan is on the
//! decoy's `/run`, the whole hot path runs here: the countdown, the stop jobs,
//! the cgroup and shell kills, the plan's undo and the reconcile, through
//! [`nails_teardown`] and nothing else. Its report is parked for the emergency
//! command, which then does the bookkeeping and prints the result once the CLI
//! is initialised. In every other case `dispatch` does nothing and the normal
//! path runs unchanged (an emergency without a plan derives one there, from
//! the configured hidden root and the mount table).
//!
//! The recogniser is deliberately strict: it accepts only the global and
//! emergency options, each at most once, and leaves anything else (help, a typo,
//! an unknown flag) to clap, so the early path never runs for a command line
//! clap would refuse. A test checks the two agree.

use std::ffi::OsString;
use std::sync::Mutex;

/// The hot path's report, waiting for the emergency command.
static EARLY_REPORT: Mutex<Option<nails_teardown::HotReport>> = Mutex::new(None);

/// What the strict recogniser read from an emergency command line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EarlyArgs {
    /// `--countdown <SECS>`.
    pub countdown: Option<u64>,
}

/// The value-less global options.
const GLOBAL_FLAGS: &[&str] = &["-q", "--quiet", "--ascii", "--json", "--no-log-file"];
/// The value-less emergency options.
const EMERGENCY_FLAGS: &[&str] = &["--poweroff", "--reboot", "--lock-backend"];

/// Recognise `argv` (program name first) as an emergency command clap accepts,
/// or `None` for anything else.
pub fn recognise(argv: &[OsString]) -> Option<EarlyArgs> {
    let words: Vec<&str> = argv
        .iter()
        .skip(1)
        .map(|w| w.to_str())
        .collect::<Option<_>>()?;
    let mut seen: Vec<&str> = Vec::new();
    let mut once = |name: &'static str| {
        if seen.contains(&name) {
            return false;
        }
        seen.push(name);
        true
    };
    let mut args = EarlyArgs::default();
    let mut subcommand = false;
    let mut verbose = 0u32;
    let mut quiet = false;
    let mut iter = words.into_iter();
    while let Some(word) = iter.next() {
        if !subcommand && word == "emergency" {
            subcommand = true;
            continue;
        }
        if let Some(flag) = GLOBAL_FLAGS.iter().find(|f| **f == word) {
            let name = if *flag == "-q" { "--quiet" } else { flag };
            if !once(name) {
                return None;
            }
            quiet |= name == "--quiet";
            continue;
        }
        if subcommand && let Some(flag) = EMERGENCY_FLAGS.iter().find(|f| **f == word) {
            if !once(flag) {
                return None;
            }
            continue;
        }
        if word == "--verbose"
            || (word.len() >= 2 && word.starts_with('-') && word[1..].chars().all(|c| c == 'v'))
        {
            verbose += if word == "--verbose" {
                1
            } else {
                (word.len() - 1) as u32
            };
            continue;
        }
        let (name, inline) = match word.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value)),
            _ => (word, None),
        };
        let mut value = || {
            inline
                .map(str::to_string)
                .or_else(|| iter.next().map(str::to_string))
        };
        match name {
            "--config" | "-c" if inline.is_none() || name == "--config" => {
                let path = value()?;
                if path.is_empty() || path.starts_with('-') || !once("--config") {
                    return None;
                }
            }
            "--color" => {
                let when = value()?;
                if !matches!(when.as_str(), "auto" | "always" | "never") || !once("--color") {
                    return None;
                }
            }
            "--countdown" if subcommand => {
                let secs = value()?.parse().ok()?;
                if !once("--countdown") {
                    return None;
                }
                args.countdown = Some(secs);
            }
            _ => return None,
        }
    }
    let conflicting = seen.contains(&"--poweroff") && seen.contains(&"--reboot");
    (subcommand && !conflicting && !(quiet && verbose > 0)).then_some(args)
}

/// Whether this process may run the hot path: as root, and (in a test-hooks
/// build) not under the runtime-safety switch the test suites set.
fn may_run() -> bool {
    #[cfg(feature = "test-hooks")]
    if std::env::var_os("NAILS_TEST_RUNTIME").is_some() {
        return false;
    }
    nix::unistd::geteuid().is_root()
}

/// The host the hot path may act on: the plan's tools and, in a test-hooks
/// build, the services and pids the end-to-end harness names for sparing.
fn host(plan: &nails_teardown::Plan) -> nails_teardown::Host {
    #[cfg_attr(not(feature = "test-hooks"), allow(unused_mut))]
    let mut host = nails_teardown::Host::system(plan);
    #[cfg(feature = "test-hooks")]
    {
        let list = |key: &str| {
            std::env::var(key)
                .unwrap_or_default()
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        };
        host.spared_units = list("NAILS_SHELL_CLEANUP_PROTECTED_SERVICES")
            .into_iter()
            .map(|u| {
                if u.contains('.') {
                    u
                } else {
                    format!("{u}.service")
                }
            })
            .collect();
        host.protected_pids = list("NAILS_SHELL_CLEANUP_PROTECTED_PIDS")
            .iter()
            .filter_map(|p| p.parse().ok())
            .collect();
    }
    host
}

/// Run the emergency hot path now when the command line asks for it, the
/// process may and a recorded plan exists. See the module docs.
pub fn dispatch() -> bool {
    let argv: Vec<OsString> = std::env::args_os().collect();
    let Some(args) = recognise(&argv) else {
        return false;
    };
    if !may_run() {
        return false;
    }
    // Only a plan with steps: an empty one (an activation that stopped before
    // its first mount) leaves the no-op decision to the emergency command.
    let Ok(plan) = nails_teardown::Plan::load(&nails_teardown::plan::default_plan_path()) else {
        return false;
    };
    if plan.steps.is_empty() {
        return false;
    }
    // A cwd inside an overlay would pin it and force a lazy detach.
    let _ = std::env::set_current_dir("/");
    if let Some(secs) = args.countdown {
        crate::cli::commands::emergency::run_countdown(secs);
    }
    let host = host(&plan);
    let ops = nails_teardown::KernelMountOps::new(
        plan.hidden_root.clone(),
        plan.runtime_root.clone(),
        plan.mount_namespace,
    );
    let report = nails_teardown::emergency::run(
        &ops,
        plan,
        nails_teardown::PlanSource::Recorded,
        Some(&host),
    );
    *EARLY_REPORT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(report);
    true
}

/// Take the report of a hot path [`dispatch`] already ran, if any.
pub fn take_report() -> Option<nails_teardown::HotReport> {
    EARLY_REPORT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
}

#[cfg(test)]
#[path = "early_tests.rs"]
mod tests;
