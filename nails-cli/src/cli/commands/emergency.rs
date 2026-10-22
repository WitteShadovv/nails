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
use nails_core::output::Mark;
use nails_teardown::whole_root::emergency::{self, Finish, HotReport, Side};

use crate::cli::args::EmergencyArgs;
use crate::cli::output::envelope::Envelope;
use crate::cli::output::{ExitStatus, OutputSettings};

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
            if let Some(secs) = args.countdown {
                run_countdown(secs);
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

/// Print an abortable countdown to stderr, one line per second, always ending
/// with a Ctrl+C hint. Never gated by `--quiet`/`--json`.
pub(crate) fn run_countdown(secs: u64) {
    for remaining in (1..=secs).rev() {
        crate::cli::output::eprint_tolerating_broken_pipe(&format!(
            "\r  Emergency in {remaining}... (Ctrl+C to abort) "
        ));
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    if secs > 0 {
        crate::cli::output::eprintln_tolerating_broken_pipe(
            "\r  Emergency starting now!                ",
        );
    }
}

fn print_json(report: &HotReport) {
    // `ok` follows the hot path's own exit code: a clean teardown is ok, a
    // degraded one (mounts left below /run/nextroot, or only the kernel could
    // be asked to power off) is not.
    let ok = app::exit_status(report).is_success();
    let envelope = Envelope::outcome("emergency", ok, app::data(report));
    crate::cli::output::println_tolerating_broken_pipe(&envelope.to_line());
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

fn render_human(settings: &OutputSettings, report: &HotReport) {
    if settings.is_quiet() && app::exit_status(report) == ExitStatus::Ok {
        return;
    }
    for line in human_lines(settings, report) {
        crate::cli::output::println_tolerating_broken_pipe(&line);
    }
}

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
        run_countdown(1);
        assert!(start.elapsed().as_millis() >= 1000);
        let start = Instant::now();
        run_countdown(0);
        assert!(start.elapsed().as_millis() < 500);
    }

    /// The phrase the Side::None human report always carries; distinctive enough
    /// that a parallel fd-1 writer never produces it, so a `contains` assertion
    /// over the capture file stays robust under the test harness's parallelism.
    const NO_SESSION_PHRASE: &str = "nothing to tear down";

    /// Run `f`, capturing everything it writes to the process's real stdout
    /// (fd 1).
    ///
    /// `print_json` and `render_human` write through
    /// `println_tolerating_broken_pipe`, which locks `io::stdout()` directly; the
    /// test harness's per-thread capture does not intercept that, so observing
    /// the real printers means redirecting fd 1 to a file. Mirrors the helper in
    /// `cli::output::activate_tests`; both share `crate::STDOUT_CAPTURE_LOCK` so
    /// the two never redirect fd 1 at the same time.
    fn capture_stdout(f: impl FnOnce()) -> String {
        use nix::libc;
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::os::fd::AsRawFd;

        let _guard = crate::STDOUT_CAPTURE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut tmp = tempfile::tempfile().expect("temp file for stdout capture");

        let _ = std::io::stdout().flush();
        // SAFETY: STDOUT_FILENO is always a valid descriptor; dup returns a fresh
        // owned fd or -1, which the assert on the next line checks.
        let saved = unsafe { libc::dup(libc::STDOUT_FILENO) };
        assert!(saved >= 0, "dup the real stdout");
        // SAFETY: `tmp` owns a live fd and STDOUT_FILENO is valid; dup2 only
        // rewires fd 1 onto the capture file, and its result is asserted.
        let to_file = unsafe { libc::dup2(tmp.as_raw_fd(), libc::STDOUT_FILENO) };
        assert!(to_file >= 0, "redirect fd 1 to the capture file");

        f();

        let _ = std::io::stdout().flush();
        // SAFETY: `saved` is the fd dup'd above and STDOUT_FILENO is valid; dup2
        // restores fd 1, and its result is asserted.
        let restored = unsafe { libc::dup2(saved, libc::STDOUT_FILENO) };
        assert!(restored >= 0, "restore the real stdout");
        // SAFETY: `saved` is an owned fd produced by dup above, closed exactly once.
        unsafe {
            libc::close(saved);
        }

        let mut captured = String::new();
        tmp.seek(SeekFrom::Start(0)).expect("rewind capture file");
        tmp.read_to_string(&mut captured)
            .expect("read captured stdout");
        captured
    }

    fn quiet_settings() -> OutputSettings {
        OutputSettings {
            verbosity: nails_core::Verbosity::Quiet,
            ..OutputSettings::default()
        }
    }

    /// `print_json` must actually emit the `emergency` outcome envelope, with
    /// `ok` following the hot path's own success (a Side::None return is clean).
    /// Replacing its body with `()` prints nothing, so no emergency line appears.
    #[test]
    fn print_json_emits_the_emergency_outcome_envelope() {
        let report = simulated(None, Finish::Return);
        assert_eq!(app::exit_status(&report), ExitStatus::Ok);
        let captured = capture_stdout(|| print_json(&report));
        let line = captured
            .lines()
            .find(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .ok()
                    .and_then(|v| {
                        v.get("command")
                            .and_then(serde_json::Value::as_str)
                            .map(|c| c == "emergency")
                    })
                    .unwrap_or(false)
            })
            .unwrap_or_else(|| panic!("no emergency envelope in captured stdout: {captured:?}"));
        let value: serde_json::Value =
            serde_json::from_str(line).expect("captured emergency line is JSON");
        assert_eq!(value["command"], "emergency", "{value}");
        assert_eq!(
            value["ok"], true,
            "a Side::None return is a clean teardown: {value}"
        );
    }

    /// `render_human` prints the human report when not silenced. Replacing its
    /// body with `()` — and flipping `&&` to `||`, which would silence a loud,
    /// successful run — both drop the report; capturing fd 1 catches that.
    #[test]
    fn render_human_prints_the_report_when_not_quiet() {
        let report = simulated(None, Finish::Return);
        assert_eq!(app::exit_status(&report), ExitStatus::Ok);
        let settings = OutputSettings::default();
        assert!(!settings.is_quiet());
        let captured = capture_stdout(|| render_human(&settings, &report));
        assert!(
            captured.contains(NO_SESSION_PHRASE),
            "a non-quiet successful run must print its report: {captured:?}"
        );
    }

    /// The quiet guard silences only a quiet, successful run: `is_quiet() &&
    /// exit == Ok`. Flipping `==` to `!=` makes it instead print on a quiet,
    /// *successful* run (and silence a quiet failure), so a quiet Side::None run
    /// would wrongly emit its report. The real guard prints nothing here.
    #[test]
    fn render_human_is_silent_on_a_quiet_successful_run() {
        let report = simulated(None, Finish::Return);
        assert_eq!(app::exit_status(&report), ExitStatus::Ok);
        let settings = quiet_settings();
        assert!(settings.is_quiet());
        let captured = capture_stdout(|| render_human(&settings, &report));
        assert!(
            !captured.contains(NO_SESSION_PHRASE),
            "a quiet successful run must stay silent: {captured:?}"
        );
    }
}
