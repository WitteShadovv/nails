// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Activate command handler
//!
//! Activation runs on the decoy and prepares the whole-root session: the
//! pre-flight checks, the hidden NixOS configuration (built into the next
//! root's store), the overlay at `/run/nextroot` and the armed plan. It prints
//! its result and enqueues the soft-reboot, which stops every program of the
//! decoy and starts the hidden userspace inside the overlay: the operator is
//! logged out and logs in again at the hidden session's login screen (a
//! display manager set to log an account in automatically logs it in again, as
//! at boot; NAILS logs nobody in). As its last step it SIGKILLs the decoy's
//! interactive shells, so none of them writes the activation command to its
//! history file on the decoy disk. A person reads the result before that last
//! step, which ends the terminal; under `--json` the one envelope follows it,
//! so it reports whether the soft-reboot was enqueued.

use super::prompt::{Answer, read_answer_from_stdin};
use crate::cli::args::ActivateArgs;
use crate::cli::output::envelope::{ErrorBody, report_error};
use crate::cli::output::refusal::report_refusal;
use crate::cli::output::{self, ActivateResult, ExitStatus, OutputSettings};

use nails_core::app::activate::{self, ActivateOptions, LockedActivation, Prepared};
use nails_core::hidden_root::Refusal;
use nails_core::manager::EnterOutcome;
use nails_core::session::Entry;
use nails_core::session::package_drift::Advisory;
use nails_core::{CliOverrides, NailsError, Verbosity};
use std::io::IsTerminal;
use std::time::Instant;

/// Write the pre-mount residue baseline through the facade and report where it
/// went: a debug line under `--json`, the summary on stdout otherwise. The scan
/// and the write are the facade's; this only reports the result.
fn write_baseline(settings: &OutputSettings, locked: &LockedActivation, json: bool) {
    if let Some(baseline) = locked.write_residue_baseline() {
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
/// their order: the pre-flight checks, the next root, and the hidden NixOS
/// system built into it (NixOS with a build target only, never with
/// `--overlay-only` or on Debian and Ubuntu).
fn preparing_line(builds_system: bool) -> String {
    let mut steps = vec!["pre-flight", "next root"];
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
        allow_persistent_decoy: args.allow_persistent_decoy,
        allow_decoy_storage: args.allow_decoy_storage,
        allow_discards: args.allow_discards,
    }
}

/// What the activation asks of the facade.
fn activate_options(args: &ActivateArgs) -> ActivateOptions {
    ActivateOptions {
        overlay_only: args.overlay_only,
        allow_persistent_decoy: args.allow_persistent_decoy,
        allow_decoy_storage: args.allow_decoy_storage,
        allow_discards: args.allow_discards,
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
/// otherwise (`state_locked` when another operation holds the state lock).
pub fn execute(
    settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    args: &ActivateArgs,
    config_override: Option<&std::path::Path>,
) -> ExitStatus {
    if args.dry_run {
        return super::check::execute(settings, env, &dry_run_check_args(args), config_override);
    }
    let begun = match begin(settings, env, args, config_override) {
        Ok(begun) => begun,
        Err(status) => return status,
    };
    // Shown under -q too: every opt-in protection keeps its default without
    // the file, which a scripted `-y -q` activation must not hide.
    if let Some(notice) = &begun.defaults_notice {
        crate::cli::output::eprintln_tolerating_broken_pipe(notice);
    }
    if !args.yes
        && let Some(status) = stop_status(confirm_logout(
            settings,
            begun.locked.accepted(),
            &begun.locked.entry_advisories(),
        ))
    {
        return report_cancelled(settings, status);
    }
    finish(settings, begun.locked, || {})
}

/// An activation past its gates and holding the state lock, waiting for the
/// operator's confirmation.
pub(crate) struct Begun {
    /// The handle that enters and commits, holding the lock until dropped.
    pub(crate) locked: LockedActivation,
    /// The warning the attach gate raised for a risk the operator allowed,
    /// already printed on stderr.
    #[cfg_attr(not(feature = "gui"), allow(dead_code))]
    pub(crate) warning: Option<String>,
    /// The line saying no configuration file was found, which the caller
    /// shows before it asks.
    pub(crate) defaults_notice: Option<String>,
}

/// The part of an activation before its confirmation: the configuration, the
/// gates and the state lock.
///
/// # Errors
///
/// The status to exit with when the activation ended before the lock, its
/// result already reported: [`ExitStatus::Ok`] when the session was already
/// active, otherwise every refusal [`execute`] names but a pre-flight check's.
pub(crate) fn begin(
    settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    args: &ActivateArgs,
    config_override: Option<&std::path::Path>,
) -> Result<Begun, ExitStatus> {
    let json = settings.is_json();
    let mut loaded = super::load_config_or_report(config_override, "activate", json)?;
    let defaults_notice = defaults_notice(&loaded);
    loaded.apply_cli_overrides(&CliOverrides {
        nixos_flake: args.nixos_flake.clone(),
    });
    let config = loaded.into_config();

    if !args.yes && !std::io::stdin().is_terminal() {
        return Err(report_error(
            json,
            "activate",
            ExitStatus::Usage,
            ErrorBody::new(
                "needs_confirmation",
                "activate logs you out and needs confirmation, but stdin is not a terminal; pass -y/--yes to run non-interactively",
            ),
        ));
    }

    let options = activate_options(args);
    let ready = match activate::prepare(env, config, settings.verbosity, &options) {
        Prepared::AlreadyActive => {
            print_result(settings, &ActivateResult::AlreadyActive, 0.0);
            return Err(ExitStatus::Ok);
        }
        Prepared::Unsupported(error) => {
            // Refused before the state lock: nothing was written to the hidden
            // volume. Reported exactly as the late path would, and exits 8.
            print_result(settings, &ActivateResult::Failed(&error), 0.0);
            return Err(ExitStatus::Unsupported);
        }
        Prepared::Refused(refusal) => return Err(report_refusal(json, "activate", &refusal)),
        Prepared::AttachError(e) => {
            return Err(report_error(
                json,
                "activate",
                ExitStatus::PreflightRefused,
                ErrorBody::new("preflight", e.to_string()),
            ));
        }
        Prepared::Proceed(ready) => ready,
    };

    // The attach gate raised a warning the operator overrode: show it before
    // taking the lock (the lock itself writes nothing to report).
    let warning = ready.warning().map(str::to_string);
    if let Some(warning) = &warning {
        crate::cli::output::eprintln_tolerating_broken_pipe(&format!("warning: {warning}"));
    }

    // The lock step takes the state lock and, holding it, refuses a state
    // file it cannot trust; the handle it hands out holds the lock until it
    // is dropped, after the commit.
    let locked = ready
        .lock()
        .map_err(|error| super::report_lock_error(error, "activate", json))?;
    Ok(Begun {
        locked,
        warning,
        defaults_notice,
    })
}

/// The part of an activation after its confirmation: the residue baseline, the
/// entry and, past the point of no return, the commit, reported as
/// [`execute`] reports them. `at_point_of_no_return` runs once the entry is
/// recorded and nothing cancels it any more, right before the commit.
pub(crate) fn finish(
    settings: &OutputSettings,
    mut locked: LockedActivation,
    at_point_of_no_return: impl FnOnce(),
) -> ExitStatus {
    let json = settings.is_json();
    // Ctrl+C sets a flag that every step from here on reads (see
    // nails_core::cancel). At the prompt it ends the activation at once;
    // during the residue baseline, before the entry begins.
    if nails_core::cancel::is_cancelled() {
        return report_cancelled(settings, ExitStatus::Cancelled);
    }
    write_baseline(settings, &locked, json);
    if nails_core::cancel::is_cancelled() {
        return report_cancelled(settings, ExitStatus::Cancelled);
    }

    // Under --json activation prints one envelope and nothing else, so there is
    // no progress line on stdout; a window watches progress on its own channel.
    if !json && settings.verbosity >= Verbosity::Normal {
        crate::cli::output::eprintln_tolerating_broken_pipe(&preparing_line(
            locked.builds_hidden_system(),
        ));
    }
    let start = Instant::now();
    let result = locked.enter();
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
    at_point_of_no_return();
    // The point of no return: kill the decoy's shells so none writes the
    // activation command to its history, then enqueue the soft-reboot. The
    // time reported is the one the state file records, which `status` shows
    // as well.
    let status = commit_and_report(settings, &entry, elapsed.as_secs_f64(), || {
        locked.commit(&entry)
    });
    drop(locked);
    status
}

/// Commit the prepared `entry` with `commit` and report it, returning the
/// status to exit with.
///
/// A person reads the result before the commit, which kills the decoy's
/// shells and ends the terminal: the lines come first, and a failure to
/// enqueue the soft-reboot follows them on stderr. Under `--json` the one
/// envelope reports the outcome instead, so it is printed only once the
/// soft-reboot is enqueued: a failure is the only envelope, never one after a
/// success. The process outlives the commit long enough to print it, since a
/// mutating command catches SIGTERM and ignores SIGHUP, but a reader the
/// switch stops first may not read it.
fn commit_and_report(
    settings: &OutputSettings,
    entry: &Entry,
    elapsed: f64,
    commit: impl FnOnce() -> Result<(), NailsError>,
) -> ExitStatus {
    let json = settings.is_json();
    let result = ActivateResult::Entering(entry);
    if !json {
        print_result(settings, &result, elapsed);
        crate::cli::output::flush_stdio();
    }
    if let Err(error) = commit() {
        return report_error(
            json,
            "activate",
            ExitStatus::Failed,
            ErrorBody::new("soft_reboot", error.to_string())
                .with_hint("the next root was removed again; nothing changed"),
        );
    }
    if json {
        print_result(settings, &result, elapsed);
        crate::cli::output::flush_stdio();
    }
    if entry.warnings.is_empty() {
        ExitStatus::Ok
    } else {
        ExitStatus::SuccessWithWarnings
    }
}

/// How the answer at the prompt ends the activation, if it does: a `n` (or the
/// end of the input) and a Ctrl+C both cancel with exit 130, so a "no" reads
/// the same as a signal's cancel. Both print alike ([`report_cancelled`]).
fn stop_status(answer: Answer) -> Option<ExitStatus> {
    match answer {
        Answer::Yes => None,
        Answer::No | Answer::Cancelled => Some(ExitStatus::Cancelled),
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

/// Ask on the terminal before logging the operator out, after the lines of
/// [`prompt_lines`].
fn confirm_logout(
    settings: &OutputSettings,
    accepted: Option<&Refusal>,
    advisories: &[Advisory],
) -> Answer {
    use std::io::Write;
    let mut stderr = std::io::stderr();
    for line in prompt_lines(settings.stderr_style(), accepted, advisories) {
        let _ = writeln!(stderr, "{line}");
    }
    let _ = write!(stderr, "    Continue? [y/N]: ");
    let _ = stderr.flush();
    let answer = read_answer_from_stdin();
    if answer == Answer::Cancelled {
        // End the prompt's line before the result.
        let _ = writeln!(stderr);
    }
    answer
}

/// What activation says before it asks to log the operator out: each of the
/// `advisories`, the risks the entry does not refuse, with its fix below it;
/// then what the switch does, with `accepted`, the refusal the operator
/// overrode with `--allow-decoy-storage`, repeated.
fn prompt_lines(
    style: nails_core::output::Style,
    accepted: Option<&Refusal>,
    advisories: &[Advisory],
) -> Vec<String> {
    use nails_core::output::Mark;
    let mut lines: Vec<String> = advisories
        .iter()
        .flat_map(|advisory| output::activate::warning_lines(style, &advisory.text()))
        .collect();
    lines.push(style.marked(
        Mark::Warn,
        "Activation soft-reboots into the hidden session.",
    ));
    lines
        .push("    Every program closes and you are logged out; unsaved work is lost.".to_string());
    if let Some(refusal) = accepted {
        lines.push(format!("    {}.", refusal.warning()));
    }
    lines
}

#[cfg(test)]
mod tests;
