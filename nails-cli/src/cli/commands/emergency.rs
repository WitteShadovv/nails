// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Emergency command handler
//!
//! The hot path runs in `nails-teardown` (`whole_root::emergency`), normally
//! from `main` before the CLI is initialised (see `cli::early`). In the hidden
//! session it prepares the way back, marks the hidden backend for closing,
//! enqueues the soft-reboot to the plain decoy (or the power action) and kills
//! every hidden process at once. The machine ends at the decoy's own login
//! screen, where the operator logs in with the decoy password; with
//! `--poweroff` it powers off. On the decoy it removes what an interrupted
//! activation left in `/run`.
//!
//! This handler only reports: it prints the result and the timed phases and
//! logs them, best-effort, because the soft-reboot it enqueued is already
//! stopping userspace (the terminal may be gone by now). It then records the
//! state as inactive while the hidden volume is still reachable.

use nails_core::app::emergency as app;
use nails_core::output::{Mark, Style};
use nails_teardown::whole_root::emergency::{self, Finish, HotReport, Side};

use crate::cli::args::EmergencyArgs;
use crate::cli::output::envelope::{Envelope, EnvelopePrint, report_cancelled};
use crate::cli::output::{ExitStatus, OutputSettings};

/// What an emergency stopped during its countdown reports, from the
/// catalogue: it had done nothing yet.
const CANCELLED: &str = nails_core::catalog::CANCEL_EMERGENCY.text;

/// The finish the arguments ask for.
fn requested_finish(args: &EmergencyArgs) -> Finish {
    if args.poweroff {
        Finish::Poweroff
    } else if args.reboot {
        Finish::Reboot
    } else {
        Finish::Return
    }
}

/// Execute the emergency command.
///
/// # Returns
///
/// - [`ExitStatus::Ok`] when the way back or the power action was enqueued, or
///   there was nothing to do
/// - [`ExitStatus::DegradedReboot`] when a decoy-side cleanup left mounts below
///   `/run/nextroot`, or only the kernel could be asked to power off
/// - [`ExitStatus::Failed`] when nothing at all could be dispatched
/// - [`ExitStatus::Cancelled`] when Ctrl+C stopped the countdown, before it
///   acted
pub fn execute(
    settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    args: &EmergencyArgs,
    config_override: Option<&std::path::Path>,
) -> ExitStatus {
    let report = match crate::cli::early::take_report() {
        Some(report) => report,
        None => {
            // The early path did not run (not root): run it here. The countdown
            // is terminal UX and stays in the CLI; the hot path is the facade's.
            if let Some(status) =
                countdown(args.countdown, settings.is_json(), settings.stderr_style())
            {
                return status;
            }
            app::run_hot_path(requested_finish(args))
        }
    };
    log_report(&report);
    if settings.is_json() {
        print_json(&report);
    } else {
        render_human(settings, &report);
    }
    crate::cli::output::flush_stdio();
    app::record_inactive(env, &report, config_override);
    app::exit_status(&report)
}

/// Run the hot path in-process (the backend watcher, the sleep guard) and log
/// its report.
pub(crate) fn run_hot_path_with(finish: Finish) {
    let plan = nails_teardown::whole_root::plan::Plan::load(
        &nails_teardown::whole_root::plan::default_plan_path(),
    )
    .ok();
    let report = emergency::run(plan, &emergency::Host::system(), finish);
    log_report(&report);
}

/// Log the outcome and the phase timings (to the hidden-volume log while it is
/// still mounted).
fn log_report(report: &HotReport) {
    let phases: Vec<String> = report
        .phases
        .iter()
        .map(|(name, d)| format!("{name}={}ms", d.as_millis()))
        .collect();
    tracing::debug!(
        side = ?report.side,
        requested = ?report.requested,
        dispatched = ?report.dispatched,
        fallback = report.fallback.as_deref().unwrap_or(""),
        cgroups_killed = report.kill.cgroups.len(),
        processes_killed = report.kill.processes.len(),
        elapsed_ms = report.elapsed.as_millis() as u64,
        phases = %phases.join(" "),
        "emergency hot path finished"
    );
}

/// Wait out `--countdown`, if one was given, before the hot path acts.
///
/// Ctrl+C (or SIGTERM) during the countdown cancels the emergency before it
/// did anything: the cancel is reported as every command reports one (under
/// `--json` the cancel envelope, otherwise a neutral notice on stderr) and its
/// status returned. `None` when the countdown ran out, or there was none. A
/// terminal hangup does not cancel: the emergency still runs when the
/// countdown ends, as a teardown runs on once its terminal is gone.
fn countdown(secs: Option<u64>, json: bool, style: Style) -> Option<ExitStatus> {
    let secs = secs?;
    // The handlers set the cancel flag the countdown watches, instead of the
    // default action ending the process with nothing reported; SIGHUP they
    // catch and ignore.
    nails_core::cancel::install_handlers();
    if run_countdown(secs, nails_core::cancel::is_cancelled) {
        return None;
    }
    // End the countdown's line before the notice.
    crate::cli::output::eprintln_tolerating_broken_pipe("");
    let mut stderr = std::io::stderr();
    Some(report_cancelled(
        &mut stderr,
        json,
        style,
        "emergency",
        CANCELLED,
    ))
}

/// The countdown of the early path, which runs before the CLI exists: as
/// [`countdown`], with the style read from `--ascii` (no colour), and a cancel
/// ends the process with its exit code.
pub(crate) fn early_countdown(secs: Option<u64>, json: bool, ascii: bool) {
    let style = Style {
        color: false,
        ascii,
    };
    if let Some(status) = countdown(secs, json, style) {
        crate::cli::output::flush_stdio();
        crate::cli::chokepoint::exit_process(status.code());
    }
}

/// How often the countdown looks at the cancel flag while it waits.
const COUNTDOWN_POLL: std::time::Duration = std::time::Duration::from_millis(100);

/// Print an abortable countdown to stderr, one line per second, always ending
/// with a Ctrl+C hint. Never gated by `--quiet`/`--json`. Returns false as soon
/// as `cancelled` says so, true once the countdown ran out.
pub(crate) fn run_countdown(secs: u64, cancelled: impl Fn() -> bool) -> bool {
    for remaining in (1..=secs).rev() {
        crate::cli::output::eprint_tolerating_broken_pipe(&format!(
            "\r  Emergency in {remaining}... (Ctrl+C to abort) "
        ));
        let second = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            if cancelled() {
                return false;
            }
            let left = second.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                break;
            }
            std::thread::sleep(left.min(COUNTDOWN_POLL));
        }
    }
    if secs > 0 {
        crate::cli::output::eprintln_tolerating_broken_pipe(
            "\r  Emergency starting now!                ",
        );
    }
    true
}

fn print_json(report: &HotReport) {
    // `ok` follows the hot path's own exit code: a clean teardown is ok, a
    // degraded one (mounts left below /run/nextroot, or only the kernel could
    // be asked to power off) is not.
    let ok = app::exit_status(report).is_success();
    Envelope::outcome("emergency", ok, app::data(report)).print();
}

fn human_lines(settings: &OutputSettings, report: &HotReport) -> Vec<String> {
    let style = settings.stdout_style();
    let mut out = Vec::new();
    match report.side {
        Side::None => out.push(style.marked(Mark::Pass, "No hidden session: nothing to tear down")),
        Side::Decoy => {
            out.push(style.marked(
                Mark::Pass,
                "Removed what an interrupted activation left in /run",
            ));
            for mount in &report.remaining {
                out.push(format!("  ! still mounted: {}", mount.display()));
            }
        }
        Side::Hidden => out.push(match report.dispatched {
            Some(Finish::Return) => style.marked(
                Mark::Pass,
                "Returning to the decoy: hidden processes killed, soft-reboot under way",
            ),
            Some(Finish::Poweroff) => {
                style.marked(Mark::Pass, "Hidden processes killed, powering off")
            }
            Some(Finish::Reboot) => style.marked(Mark::Pass, "Hidden processes killed, rebooting"),
            None => style.marked(Mark::Fail, "Nothing could be enqueued"),
        }),
    }
    if report.side != Side::Hidden && report.requested != Finish::Return {
        match report.dispatched {
            Some(finish) => out.push(format!("  Power action: {}", app::finish_name(finish))),
            None => out.push("  ! The power action could not be enqueued".to_string()),
        }
    }
    if let Some(why) = &report.fallback {
        out.push(format!("  ! {why}"));
    }
    if report.kernel_power_off {
        out.push("  ! The kernel was asked to power off directly".to_string());
    }
    for name in app::backend_left_open(report) {
        out.push(format!(
            "  ! {}",
            crate::cli::output::deactivate::backend_left_open_warning(&name)
        ));
    }
    if report.side == Side::Hidden {
        out.push(format!(
            "  Killed {} and {}",
            crate::cli::output::count_noun(report.kill.cgroups.len(), "cgroup", "cgroups"),
            crate::cli::output::count_noun(report.kill.processes.len(), "process", "processes")
        ));
    }
    let phases: Vec<String> = report
        .phases
        .iter()
        .map(|(name, d)| format!("{name} {}ms", d.as_millis()))
        .collect();
    if !phases.is_empty() {
        out.push(format!(
            "  Took {}ms ({})",
            report.elapsed.as_millis(),
            phases.join(", ")
        ));
    }
    if report.side == Side::Hidden && report.dispatched == Some(Finish::Return) {
        out.push(
            "  The decoy starts at its own login screen; log in there with the decoy password \
             (a display manager set to log an account in automatically logs it in again, as at \
             boot)."
                .to_string(),
        );
    }
    out
}

/// Print the report for a person. `--quiet` silences a clean run only: one
/// that left mounts behind, or a backend device open, is still reported.
fn render_human(settings: &OutputSettings, report: &HotReport) {
    if settings.is_quiet()
        && app::exit_status(report) == ExitStatus::Ok
        && app::backend_left_open(report).is_empty()
    {
        return;
    }
    for line in human_lines(settings, report) {
        crate::cli::output::println_tolerating_broken_pipe(&line);
    }
}

#[cfg(test)]
#[path = "emergency_print_tests.rs"]
mod print_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use nails_teardown::whole_root::plan::Plan;
    use std::time::Instant;

    fn simulated(plan: Option<Plan>, finish: Finish) -> HotReport {
        let dir = tempfile::tempdir().unwrap();
        let host = emergency::Host {
            run: dir.path().join("run"),
            nextroot: dir.path().join("run/nextroot"),
            runtime_dir: dir.path().join("run/overlay-runtime"),
            cgroup_root: dir.path().join("cgroup"),
            protected_pids: Vec::new(),
            act: false,
        };
        emergency::run(plan, &host, finish)
    }

    #[test]
    fn without_a_session_emergency_succeeds_and_says_so() {
        let report = simulated(None, Finish::Return);
        assert_eq!(app::exit_status(&report), ExitStatus::Ok);
        let lines = human_lines(&OutputSettings::default(), &report);
        assert!(lines[0].contains("nothing to tear down"), "{lines:?}");
    }

    #[test]
    fn a_power_action_is_reported_in_the_human_lines() {
        let report = simulated(None, Finish::Poweroff);
        assert_eq!(report.dispatched, Some(Finish::Poweroff));
        let lines = human_lines(&OutputSettings::default(), &report);
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Power action: poweroff")),
            "{lines:?}"
        );
    }

    /// A backend device the hot path could not mark to close is named, with
    /// what that leaves: it stays open after the switch.
    #[test]
    fn a_backend_device_left_open_is_named() {
        let mut report = simulated(None, Finish::Return);
        report.side = Side::Hidden;
        report.dispatched = Some(Finish::Return);
        report.deferred = vec![
            ("hidden-crypt".to_string(), false),
            ("hidden-loop".to_string(), true),
        ];
        let lines = human_lines(&OutputSettings::default(), &report);
        let left_open: Vec<&String> = lines
            .iter()
            .filter(|line| line.contains("could not be marked to close"))
            .collect();
        assert_eq!(
            left_open,
            [
                "  ! The hidden backend device hidden-crypt could not be marked to close: it \
                 stays open after the switch, its key in RAM, until power-off"
            ],
            "{lines:?}"
        );
    }

    #[test]
    fn the_requested_finish_follows_the_flags() {
        let mut args = EmergencyArgs::default();
        assert_eq!(requested_finish(&args), Finish::Return);
        args.reboot = true;
        assert_eq!(requested_finish(&args), Finish::Reboot);
        args.reboot = false;
        args.poweroff = true;
        assert_eq!(requested_finish(&args), Finish::Poweroff);
    }

    #[test]
    fn countdown_waits_the_requested_seconds() {
        let start = Instant::now();
        assert!(run_countdown(1, || false));
        assert!(start.elapsed().as_millis() >= 1000);
        let start = Instant::now();
        assert!(run_countdown(0, || false));
        assert!(start.elapsed().as_millis() < 500);
    }

    /// Ctrl+C ends the countdown at once, before the hot path would act.
    #[test]
    fn a_cancel_ends_the_countdown_without_waiting_it_out() {
        let start = Instant::now();
        let asked = std::cell::Cell::new(0);
        let ran_out = run_countdown(5, || {
            asked.set(asked.get() + 1);
            asked.get() > 3
        });
        assert!(!ran_out, "a cancel stops the countdown");
        assert!(asked.get() > 3, "the flag was read while it waited");
        assert!(start.elapsed().as_millis() < 2000, "{:?}", start.elapsed());
    }

    const COUNTDOWN_SUBPROCESS: &str =
        "cli::commands::emergency::tests::subprocess_countdown_entrypoint";

    /// Run a one-second countdown under `--json` while a thread sends this
    /// process SIGHUP, as a closed terminal does, and exit 0 when the
    /// countdown ran out.
    #[test]
    fn subprocess_countdown_entrypoint() {
        if std::env::var_os("NAILS_COUNTDOWN_SUBPROCESS").is_none() {
            return;
        }
        std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(300));
            // Its default action would end the whole process, whichever
            // thread it is raised on.
            nix::sys::signal::raise(nix::sys::signal::Signal::SIGHUP).expect("raise SIGHUP");
        });
        let style = Style {
            color: false,
            ascii: true,
        };
        let cancelled = countdown(Some(1), true, style);
        crate::cli::chokepoint::exit_process(if cancelled.is_none() { 0 } else { 2 });
    }

    /// A terminal hangup during the countdown does not cancel the emergency:
    /// the process lives on, nothing is reported, and the countdown runs out.
    #[test]
    fn a_hangup_does_not_cancel_the_countdown() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", COUNTDOWN_SUBPROCESS, "--nocapture", "--quiet"])
            .env("NAILS_COUNTDOWN_SUBPROCESS", "1")
            .output()
            .expect("run the countdown subprocess");
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert!(
            crate::cli::output::test_support::stdout_lines(&output).is_empty(),
            "{output:?}"
        );
    }
}
