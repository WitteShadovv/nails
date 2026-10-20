// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Activate command handler
//!
//! Activation runs on the decoy and prepares the whole-root session: the
//! pre-flight checks, the hidden NixOS configuration (built into the next
//! root's store), the overlay at `/run/nextroot` and the armed plan. It prints
//! its result and then enqueues the soft-reboot, which stops every program of
//! the decoy and starts the hidden userspace inside the overlay: the operator
//! is logged out and logs in again at the hidden session's login screen (a
//! display manager set to log an account in automatically logs it in again, as
//! at boot; NAILS logs nobody in). As its last step it SIGKILLs the decoy's
//! interactive shells, so none of them writes the activation command to its
//! history file on the decoy disk.

use crate::cli::args::ActivateArgs;
use crate::cli::output::envelope::{ErrorBody, report_error};
use crate::cli::output::refusal::report_refusal;
use crate::cli::output::{self, ActivateResult, ExitStatus, OutputSettings};

use nails_core::app::activate::{self, ActivateOptions, Prepared, ReadyActivation};
use nails_core::hidden_root::Refusal;
use nails_core::manager::EnterOutcome;
use nails_core::{CliOverrides, NailsError, Verbosity};
use std::io::IsTerminal;
use std::time::Instant;

/// Write the pre-mount residue baseline through the facade and report where it
/// went: a debug line under `--json`, the summary on stdout otherwise. The scan
/// and the write are the facade's; this only reports the result.
fn write_baseline(settings: &OutputSettings, ready: &ReadyActivation, json: bool) {
    if let Some(baseline) = ready.write_residue_baseline() {
        if json {
            tracing::debug!(
                path = %baseline.path.display(),
                "wrote pre-activation decoy residue report"
            );
        } else if settings.verbosity >= Verbosity::Normal {
            println!(
                "Pre-activation decoy residue baseline: {} -> {}",
                baseline_summary(&baseline.result),
                baseline.path.display()
            );
        }
    }
}

/// The progress line before the entry, naming only the steps it runs, in
/// their order: the pre-flight checks (not under `--no-preflight`), the next
/// root, and the hidden NixOS system built into it (NixOS with a build target
/// only, never with `--overlay-only` or on Debian and Ubuntu).
fn preparing_line(preflight: bool, builds_system: bool) -> String {
    let mut steps = Vec::new();
    if preflight {
        steps.push("pre-flight");
    }
    steps.push("next root");
    if builds_system {
        steps.push("hidden NixOS system");
    }
    format!("Preparing the hidden session ({})...", steps.join(", "))
}

/// What the residue baseline line says about the decoy: no count when it shows
/// no known residue, otherwise the warnings and critical findings. The
/// informational notes every scan adds (the RAM caveat, the scope of the
/// baseline, catalogue notes such as `timesync-clock`) are not findings and
/// stay in the report.
fn baseline_summary(result: &nails_core::VerifyResult) -> String {
    use crate::cli::output::count_noun;
    use nails_core::{Severity, VerifyStatus};

    let of = |severity: Severity| {
        result
            .findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count()
    };
    let warnings = of(Severity::Warn);
    match result.status {
        VerifyStatus::Secure => "no known residue".to_string(),
        VerifyStatus::Warning => count_noun(warnings, "warning", "warnings"),
        VerifyStatus::Critical => {
            let critical = of(Severity::Critical);
            let mut text = count_noun(critical, "critical finding", "critical findings");
            if warnings > 0 {
                text.push_str(&format!(
                    ", {}",
                    count_noun(warnings, "warning", "warnings")
                ));
            }
            text
        }
    }
}

/// The line activation prints before it asks for confirmation when no
/// configuration file was found: every opt-in protection then keeps its
/// built-in default, which the operator should know before the switch.
fn defaults_notice(loaded: &nails_core::LoadedConfig) -> Option<String> {
    (!loaded.file_found).then(|| {
        format!(
            "No config file at {}: activation uses the built-in defaults.",
            loaded.path.display()
        )
    })
}

/// The `check` arguments `activate --dry-run` runs with.
fn dry_run_check_args(args: &ActivateArgs) -> crate::cli::args::CheckArgs {
    crate::cli::args::CheckArgs {
        overlay_only: args.overlay_only,
        nixos_flake: args.nixos_flake.clone(),
        accept_persistent_decoy: args.accept_persistent_decoy,
        allow_decoy_storage: args.allow_decoy_storage,
    }
}

/// What the activation asks of the facade.
fn activate_options(args: &ActivateArgs) -> ActivateOptions {
    ActivateOptions {
        no_preflight: args.no_preflight,
        overlay_only: args.overlay_only,
        accept_persistent_decoy: args.accept_persistent_decoy,
        allow_decoy_storage: args.allow_decoy_storage,
    }
}

/// Execute the activate command.
///
/// # Returns
///
/// [`ExitStatus::Ok`] once the soft-reboot is enqueued (or the session was
/// already active), [`ExitStatus::SuccessWithWarnings`] when it is enqueued
/// with warnings, [`ExitStatus::PreflightRefused`] when the attach gate or a
/// pre-flight check refuses, [`ExitStatus::Unsupported`] on an unsupported host,
/// [`ExitStatus::Usage`] without confirmation off a terminal,
/// [`ExitStatus::InvalidState`] when the state file cannot be trusted,
/// [`ExitStatus::Config`] for a bad configuration and [`ExitStatus::Failed`]
/// otherwise.
pub fn execute(
    settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    args: &ActivateArgs,
    config_override: Option<&std::path::Path>,
) -> ExitStatus {
    let json = settings.is_json();
    if args.dry_run {
        return super::check::execute(settings, env, &dry_run_check_args(args), config_override);
    }

    let mut loaded = match super::load_config_or_report(config_override, "activate", json) {
        Ok(loaded) => loaded,
        Err(status) => return status,
    };
    let defaults_notice = defaults_notice(&loaded);
    loaded.apply_cli_overrides(&CliOverrides {
        nixos_flake: args.nixos_flake.clone(),
    });
    let config = loaded.into_config();

    if !args.yes && !std::io::stdin().is_terminal() {
        return report_error(
            json,
            "activate",
            ExitStatus::Usage,
            ErrorBody::new(
                "needs_confirmation",
                "activate logs you out and needs confirmation, but stdin is not a terminal; pass -y/--yes to run non-interactively",
            ),
        );
    }

    let options = activate_options(args);
    let mut ready = match activate::prepare(env, config, settings.verbosity, &options) {
        Prepared::AlreadyActive => {
            print_result(settings, &ActivateResult::AlreadyActive, 0.0);
            return ExitStatus::Ok;
        }
        Prepared::Refused(refusal) => return report_refusal(json, "activate", &refusal),
        Prepared::AttachError(e) => {
            return report_error(
                json,
                "activate",
                ExitStatus::PreflightRefused,
                ErrorBody::new("preflight", e.to_string()),
            );
        }
        Prepared::Proceed(ready) => ready,
    };

    // The attach gate raised a warning the operator overrode: show it before
    // taking the lock (the lock itself writes nothing to report).
    if let Some(warning) = ready.warning() {
        crate::cli::output::eprintln_tolerating_broken_pipe(&format!("warning: {warning}"));
    }

    let _state_lock = match super::acquire_state_lock_or_report(
        ready.hidden_root(),
        ready.allow(),
        ready.state_path(),
        "activate",
        json,
    ) {
        Ok(lock) => lock,
        Err(status) => return status,
    };
    if !ready.is_state_trusted() {
        return report_error(
            json,
            "activate",
            ExitStatus::InvalidState,
            ErrorBody::new(
                "invalid_state",
                format!(
                    "refusing to activate: the state file is corrupt or unreadable, so the \
                     current state is unknown. Run '{}' and recover the hidden volume first.",
                    nails_core::next_step::sudo_line(nails_core::next_step::NextStep::Verify)
                ),
            ),
        );
    }

    // Shown under -q too: every opt-in protection keeps its default without
    // the file, which a scripted `-y -q` activation must not hide.
    if let Some(notice) = defaults_notice {
        crate::cli::output::eprintln_tolerating_broken_pipe(&notice);
    }
    if !args.yes
        && let Some(status) = stop_status(confirm_logout(settings, ready.accepted()))
    {
        return report_cancelled(settings, status);
    }
    // Ctrl+C sets a flag that every step from here on reads (see
    // nails_core::cancel). At the prompt it ends the activation at once;
    // during the residue baseline, before the entry begins.
    if nails_core::cancel::is_cancelled() {
        return report_cancelled(settings, ExitStatus::Cancelled);
    }
    write_baseline(settings, &ready, json);
    if nails_core::cancel::is_cancelled() {
        return report_cancelled(settings, ExitStatus::Cancelled);
    }

    if json {
        output::print_activate_progress("preparing");
    } else if settings.verbosity >= Verbosity::Normal {
        crate::cli::output::eprintln_tolerating_broken_pipe(&preparing_line(
            !options.no_preflight,
            ready.builds_hidden_system(),
        ));
    }
    let start = Instant::now();
    let result = ready.enter();
    let duration = start.elapsed().as_secs_f64();

    let (entry, elapsed) = match result {
        Ok(EnterOutcome::AlreadyActive) => {
            print_result(settings, &ActivateResult::AlreadyActive, duration);
            return ExitStatus::Ok;
        }
        Ok(EnterOutcome::Prepared { entry, elapsed }) => (entry, elapsed),
        Err(error) => {
            print_result(settings, &ActivateResult::Failed(&error), duration);
            return match error {
                NailsError::PreFlightCheckFailed(_) => ExitStatus::PreflightRefused,
                NailsError::UnsupportedPlatform { .. } => ExitStatus::Unsupported,
                NailsError::Cancelled => ExitStatus::Cancelled,
                _ => ExitStatus::Failed,
            };
        }
    };
    // The time the state file records, which `status` shows as well.
    print_result(
        settings,
        &ActivateResult::Entering(&entry),
        elapsed.as_secs_f64(),
    );
    crate::cli::output::flush_stdio();

    // The point of no return: kill the decoy's shells so none writes the
    // activation command to its history, then enqueue the soft-reboot.
    // Everything above is already on the terminal; a failure below still
    // reaches the log.
    if let Err(error) = ready.commit(&entry) {
        return report_error(
            json,
            "activate",
            ExitStatus::Failed,
            ErrorBody::new("soft_reboot", error.to_string())
                .with_hint("the next root was removed again; nothing changed"),
        );
    }
    drop(_state_lock);
    if entry.warnings.is_empty() {
        ExitStatus::Ok
    } else {
        ExitStatus::SuccessWithWarnings
    }
}

/// How the answer at the prompt ends the activation, if it does: a `n` (or
/// the end of the input) with exit 1, a Ctrl+C with exit 130 as a signal's
/// cancel anywhere else. Both read alike ([`report_cancelled`]).
fn stop_status(answer: Answer) -> Option<ExitStatus> {
    match answer {
        Answer::Yes => None,
        Answer::No => Some(ExitStatus::Failed),
        Answer::Cancelled => Some(ExitStatus::Cancelled),
    }
}

/// Report an activation cancelled before it changed anything, ending with
/// `status`.
fn report_cancelled(settings: &OutputSettings, status: ExitStatus) -> ExitStatus {
    print_result(
        settings,
        &ActivateResult::Failed(&NailsError::Cancelled),
        0.0,
    );
    status
}

fn print_result(settings: &OutputSettings, result: &ActivateResult<'_>, duration: f64) {
    if settings.is_json() {
        output::print_activate_json_result(result, duration);
    } else {
        output::print_activate_human(result, duration, settings);
    }
}

/// What the operator answered at the confirmation prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// `y` or `yes`.
    Yes,
    /// Anything else, or the end of the input.
    No,
    /// Ctrl+C (or a SIGTERM) while the prompt waited.
    Cancelled,
}

/// How often the prompt looks at the cancel flag while it waits.
const PROMPT_POLL: u16 = 100;

/// Wait for a line on `input` (read through `reader`) and judge it, giving up
/// as soon as `cancelled` says so. The signal handler restarts an interrupted
/// read, so a plain read would go on until Enter and Ctrl+C would only echo
/// `^C`; polling with a timeout looks at the cancel flag in between.
fn read_answer(
    input: std::os::fd::BorrowedFd<'_>,
    reader: &mut impl std::io::BufRead,
    cancelled: impl Fn() -> bool,
) -> Answer {
    use nix::poll::{PollFd, PollFlags, poll};
    loop {
        if cancelled() {
            return Answer::Cancelled;
        }
        let mut fds = [PollFd::new(input, PollFlags::POLLIN)];
        match poll(&mut fds, PROMPT_POLL) {
            Ok(0) | Err(nix::errno::Errno::EINTR) => {}
            Ok(_) => break,
            Err(_) => return Answer::No,
        }
    }
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return if cancelled() {
            Answer::Cancelled
        } else {
            Answer::No
        };
    }
    if matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Answer::Yes
    } else {
        Answer::No
    }
}

/// Ask on the terminal before logging the operator out. `accepted` is the
/// refusal the operator overrode with `--allow-decoy-storage`, repeated here.
fn confirm_logout(settings: &OutputSettings, accepted: Option<&Refusal>) -> Answer {
    use nails_core::output::Mark;
    use std::io::Write;
    use std::os::fd::AsFd;
    let style = settings.stderr_style();
    let mut stderr = std::io::stderr();
    let _ = writeln!(
        stderr,
        "{}",
        style.marked(
            Mark::Warn,
            "Activation soft-reboots into the hidden session."
        )
    );
    let _ = writeln!(
        stderr,
        "    Every program closes and you are logged out; unsaved work is lost."
    );
    if let Some(refusal) = accepted {
        let _ = writeln!(stderr, "    {}.", refusal.warning());
    }
    let _ = write!(stderr, "    Continue? [y/N]: ");
    let _ = stderr.flush();
    let stdin = std::io::stdin();
    let answer = read_answer(
        stdin.as_fd(),
        &mut stdin.lock(),
        nails_core::cancel::is_cancelled,
    );
    if answer == Answer::Cancelled {
        // End the prompt's line before the result.
        let _ = writeln!(stderr);
    }
    answer
}

#[cfg(test)]
mod tests;
