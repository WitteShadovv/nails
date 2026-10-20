// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Early dispatch, before clap, the configuration, the environment snapshot and
//! tracing exist: these paths must act even when the hidden volume has failed
//! or the configuration cannot be read.
//!
//! `main` calls [`dispatch`] first. Two command lines are handled here:
//!
//! - **`emergency`**, run as root: the whole hot path of
//!   `nails_teardown::whole_root::emergency` runs here (the countdown, the way
//!   back, the soft-reboot or power action, the kill of all hidden userspace).
//!   Its report is parked for the emergency command, which prints and logs it
//!   once the CLI is initialised, if it is still alive by then;
//! - **`transition`**, run by systemd as the last step before each soft-reboot
//!   switch: `nails_teardown::whole_root::transition` runs and the process ends
//!   at once, with no output and no log.
//! - **`guard-device <node>`**, run by the hidden session's udev rule for every
//!   disk that appears (`[session_mounts] read_only`):
//!   `nails_teardown::whole_root::disk_guard` makes it read-only unless the
//!   session uses it, and the process ends at once, with no output and no log.
//! - **`reconcile-records`**, run by a one-shot unit the way back leaves for an
//!   FHS decoy's first start: `nails_teardown::whole_root::boot_records` makes
//!   the login and boot records read as a clean power cycle and removes itself,
//!   then the process ends at once, with no output and no log.
//!
//! In every other case `dispatch` does nothing and the normal path runs.
//!
//! The emergency recogniser is deliberately strict: it accepts only the global
//! and emergency options, each at most once, and leaves anything else (help, a
//! typo, an unknown flag) to clap, so the early path never runs for a command
//! line clap would refuse. A test checks the two agree.

use std::ffi::OsString;
use std::sync::Mutex;

use nails_teardown::whole_root::emergency::{self, Finish, HotReport};

/// The hot path's report, waiting for the emergency command.
static EARLY_REPORT: Mutex<Option<HotReport>> = Mutex::new(None);

/// What the strict recogniser read from an emergency command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EarlyArgs {
    /// `--countdown <SECS>`.
    pub countdown: Option<u64>,
    /// How the emergency ends (`--poweroff`, `--reboot`, or the way back).
    pub finish: Finish,
}

impl Default for EarlyArgs {
    fn default() -> Self {
        Self {
            countdown: None,
            finish: Finish::Return,
        }
    }
}

/// The value-less global options.
const GLOBAL_FLAGS: &[&str] = &["-q", "--quiet", "--ascii", "--json", "--no-log-file"];
/// The value-less emergency options.
const EMERGENCY_FLAGS: &[&str] = &["--poweroff", "--reboot"];

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
    if seen.contains(&"--poweroff") {
        args.finish = Finish::Poweroff;
    } else if seen.contains(&"--reboot") {
        args.finish = Finish::Reboot;
    }
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

/// The host the hot path may act on, with (in a test-hooks build) the pids
/// the end-to-end harness names for sparing.
fn host() -> emergency::Host {
    #[cfg_attr(not(feature = "test-hooks"), allow(unused_mut))]
    let mut host = emergency::Host::system();
    #[cfg(feature = "test-hooks")]
    {
        host.protected_pids = std::env::var("NAILS_SHELL_CLEANUP_PROTECTED_PIDS")
            .unwrap_or_default()
            .split(',')
            .filter_map(|p| p.trim().parse().ok())
            .collect();
    }
    host
}

/// Whether `argv` is exactly the transition step systemd runs.
pub fn is_transition(argv: &[OsString]) -> bool {
    argv.len() == 2 && argv[1] == nails_teardown::whole_root::transition::TRANSITION_ARG
}

/// Whether `argv` is exactly the boot-record reconcile step the way back leaves
/// for an FHS decoy's first start, and whether it must make `/run` `noexec`
/// again (the flag is present only when the way back cleared it).
pub fn reconcile_records(argv: &[OsString]) -> Option<bool> {
    use nails_teardown::whole_root::boot_records::{NOEXEC_FLAG, RECONCILE_ARG};
    match &argv[1..] {
        [verb] if verb == RECONCILE_ARG => Some(false),
        [verb, flag] if verb == RECONCILE_ARG && flag == NOEXEC_FLAG => Some(true),
        _ => None,
    }
}

/// The device node of exactly the read-only guard udev runs.
pub fn guarded_device(argv: &[OsString]) -> Option<&std::path::Path> {
    (argv.len() == 3
        && argv[1] == nails_teardown::whole_root::disk_guard::GUARD_ARG
        && argv[2].as_encoded_bytes().starts_with(b"/dev/"))
    .then(|| std::path::Path::new(&argv[2]))
}

/// Make `node` read-only for the session, from the plan in the runtime
/// directory. No plan, no session: nothing to do.
fn guard_device(node: &std::path::Path) {
    use nails_teardown::whole_root::{disk_guard, plan};
    let Ok(plan) = plan::Plan::load(&plan::default_plan_path()) else {
        return;
    };
    if !plan.read_only_disks {
        return;
    }
    let mounts = nails_teardown::mountinfo::read_mountinfo().unwrap_or_default();
    let _ = disk_guard::guard(
        node,
        &plan,
        &mounts,
        &disk_guard::Sysfs::system(),
        std::path::Path::new(plan::RUNTIME_DIR),
    );
}

/// Run the early paths. See the module docs. Returns whether the emergency hot
/// path ran; the transition and the device guard never return.
pub fn dispatch() -> bool {
    let argv: Vec<OsString> = std::env::args_os().collect();
    if is_transition(&argv) && nix::unistd::geteuid().is_root() {
        let _ = nails_teardown::whole_root::transition::run(
            &nails_teardown::whole_root::transition::Env::system(),
        );
        crate::cli::chokepoint::exit_process(0);
    }
    if let Some(node) = guarded_device(&argv)
        && may_run()
    {
        guard_device(node);
        crate::cli::chokepoint::exit_process(0);
    }
    if let Some(restore_noexec) = reconcile_records(&argv)
        && may_run()
    {
        nails_teardown::whole_root::boot_records::run(
            std::path::Path::new("/run"),
            std::path::Path::new("/"),
            restore_noexec,
        );
        crate::cli::chokepoint::exit_process(0);
    }
    let Some(args) = recognise(&argv) else {
        return false;
    };
    if !may_run() {
        return false;
    }
    // A cwd inside the hidden volume would pin it.
    let _ = std::env::set_current_dir("/");
    if let Some(secs) = args.countdown {
        crate::cli::commands::emergency::run_countdown(secs);
    }
    let plan = nails_teardown::whole_root::plan::Plan::load(
        &nails_teardown::whole_root::plan::default_plan_path(),
    )
    .ok();
    let report = emergency::run(plan, &host(), args.finish);
    *EARLY_REPORT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(report);
    true
}

/// Take the report of a hot path [`dispatch`] already ran, if any.
pub fn take_report() -> Option<HotReport> {
    EARLY_REPORT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
}

#[cfg(test)]
#[path = "early_tests.rs"]
mod tests;
