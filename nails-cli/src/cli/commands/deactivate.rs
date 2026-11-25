// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Deactivate command handler
//!
//! A hidden session never goes back to the decoy's kernel: deactivation
//! records the state as inactive and powers the machine off. The orderly
//! shutdown stops every hidden program first. `--poweroff` is kept for
//! scripts and changes nothing.

use std::io::IsTerminal;
use std::path::Path;

use nails_core::NailsError;
use nails_core::app::deactivate::{LockedDeactivation, Prepared, ReadyDeactivation};
use nails_core::output::Mark;

use super::prompt::{Answer, read_answer_from_stdin};
use crate::cli::args::DeactivateArgs;
use crate::cli::output::deactivate::{
    DeactivateData, deactivate_error_body, print_deactivate_json,
};
use crate::cli::output::envelope::{ErrorBody, NextStep, report_cancelled, report_error};
use crate::cli::output::{ExitStatus, OutputSettings};

/// Execute the deactivate command.
///
/// A missing or invalid config is logged as a warning and defaults are used,
/// since a broken config must never block the end of the session.
///
/// # Returns
///
/// - [`ExitStatus::Ok`] once the power-off was enqueued
/// - [`ExitStatus::Usage`] when confirmation is needed but stdin is not a terminal
/// - [`ExitStatus::InvalidState`] outside a hidden session, before it asks
///   anything
/// - [`ExitStatus::Cancelled`] when the operator declines at the prompt or
///   presses Ctrl+C there
/// - [`ExitStatus::Failed`] when a program blocks shutdown, or logind does not
///   answer whether one does, and when the power-off could not be enqueued
pub fn execute(
    settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    args: &DeactivateArgs,
    config_override: Option<&Path>,
) -> ExitStatus {
    let prepared = nails_core::app::deactivate::prepare(env, config_override);
    deactivate_prepared(settings, args, prepared)
}

/// Go on from what [`prepare`](nails_core::app::deactivate::prepare) found:
/// report a refusal before anything is asked, else confirm, lock and leave.
fn deactivate_prepared(
    settings: &OutputSettings,
    args: &DeactivateArgs,
    prepared: Prepared,
) -> ExitStatus {
    deactivate_prepared_with(settings, args, prepared, |ready| {
        lock_and_leave(settings, ready)
    })
}

/// [`deactivate_prepared`], going on once the operator has confirmed with
/// `go_on`, which takes the ready deactivation: [`lock_and_leave`], but in
/// tests.
pub(crate) fn deactivate_prepared_with(
    settings: &OutputSettings,
    args: &DeactivateArgs,
    prepared: Prepared,
    go_on: impl FnOnce(ReadyDeactivation) -> ExitStatus,
) -> ExitStatus {
    use nails_core::next_step::{NextStep as Step, sudo_line};
    let json = settings.is_json();

    let ready = match prepared {
        Prepared::Ready(ready) => ready,
        Prepared::NotHidden => {
            return report_error(
                json,
                "deactivate",
                ExitStatus::InvalidState,
                ErrorBody::new(
                    "invalid_state",
                    "not in a hidden session; nothing to deactivate",
                )
                .with_hint(format!(
                    "an interrupted activation is cleaned up with `{}`",
                    sudo_line(Step::Recover)
                ))
                .with_next(NextStep::new(Step::Recover.command())),
            );
        }
    };
    if !args.yes && !std::io::stdin().is_terminal() {
        return report_error(
            json,
            "deactivate",
            ExitStatus::Usage,
            ErrorBody::new(
                "needs_confirmation",
                "deactivate ends the hidden session and needs confirmation, but stdin is not a terminal; pass -y/--yes to run non-interactively",
            ),
        );
    }
    if !args.yes
        && let Some(status) =
            confirm_or_cancel(settings, &mut std::io::stderr(), read_answer_from_stdin)
    {
        return status;
    }
    go_on(*ready)
}

/// Take the lock step's handle, the only one that leaves, and leave with it,
/// reporting the outcome. The handle holds the lock until it is dropped, once
/// the outcome is reported.
pub(crate) fn lock_and_leave(settings: &OutputSettings, ready: ReadyDeactivation) -> ExitStatus {
    let mut locked = match ready.lock() {
        Ok(locked) => locked,
        Err(error) => return super::report_lock_error(error, "deactivate", settings.is_json()),
    };
    leave_and_report(
        settings,
        &mut locked,
        LockedDeactivation::may_leave,
        LockedDeactivation::leave,
    )
}

/// The lines a person reads before the power-off, which stops the terminal.
pub(crate) const ENDING_LINES: [&str; 2] = [
    "Ending the hidden session and powering off",
    "  The machine powers off in a few seconds. Leave it off for a few minutes before you hand \
     it over.",
];

/// Ask the handle that leaves (`locked`) with `may_leave` whether the session
/// may end now, commit the power-off with `leave` and report it, returning
/// the status to exit with. Outside tests these are the lock step's handle
/// and its [`LockedDeactivation::may_leave`] and [`LockedDeactivation::leave`].
///
/// A power-off that may not start (a program blocks shutdown) is reported
/// before anything else, so no line announces a power-off that does not
/// come. A person reads the result before the power-off, which stops the
/// terminal: the lines come first, and a failure to enqueue it follows them
/// on stderr. Under `--json` the one envelope reports the outcome instead,
/// so it is printed only once the power-off is enqueued: a failure is the
/// only envelope, never one after a success.
fn leave_and_report<L>(
    settings: &OutputSettings,
    locked: &mut L,
    may_leave: impl FnOnce(&L) -> Result<(), NailsError>,
    leave: impl FnOnce(&mut L) -> Result<(), NailsError>,
) -> ExitStatus {
    let json = settings.is_json();
    if let Err(e) = may_leave(locked) {
        return report_error(
            json,
            "deactivate",
            error_status(&e),
            deactivate_error_body(&e),
        );
    }
    if !json {
        let style = settings.stdout_style();
        crate::cli::output::println_tolerating_broken_pipe(
            &style.marked(Mark::Pass, ENDING_LINES[0]),
        );
        crate::cli::output::println_tolerating_broken_pipe(ENDING_LINES[1]);
        crate::cli::output::flush_stdio();
    }
    match leave(locked) {
        Ok(()) => {
            tracing::debug!("the power-off is enqueued");
            if json {
                print_deactivate_json(DeactivateData::enqueued());
            }
            crate::cli::output::flush_stdio();
            ExitStatus::Ok
        }
        Err(e) => report_error(
            json,
            "deactivate",
            error_status(&e),
            deactivate_error_body(&e),
        ),
    }
}

/// The status a deactivation that did not start exits with: a refusal of a
/// check exits as activation's refusal does, so a caller can tell it from a
/// power-off that failed without parsing text. Anything else exits as a
/// failure, a program that blocks shutdown among them.
fn error_status(error: &NailsError) -> ExitStatus {
    match error {
        NailsError::PreFlightCheckFailed(_) => ExitStatus::PreflightRefused,
        _ => ExitStatus::Failed,
    }
}

/// The notice of an answer other than yes at the prompt, from the catalogue.
const CANCELLED: &str = nails_core::catalog::CANCEL_DEACTIVATE.text;

/// Ask before deactivating ([`write_prompt`]), on stderr (`err`) so stdout
/// stays clean, and take the `answer`. On an answer other than yes (a "no",
/// the end of the input, or Ctrl+C at the prompt), report the cancel, which
/// changed nothing, and return the status to exit with: the neutral notice
/// `activate` gives on `err`, or under `--json` the error envelope with the
/// code `cancelled` on stdout. `None` when the operator confirmed.
fn confirm_or_cancel(
    settings: &OutputSettings,
    err: &mut impl std::io::Write,
    answer: impl FnOnce() -> Answer,
) -> Option<ExitStatus> {
    write_prompt(settings, err);
    match answer() {
        Answer::Yes => return None,
        // Ctrl+C, or the end of the input, leaves the cursor after the
        // prompt: end its line first.
        Answer::Cancelled | Answer::EndOfInput => {
            let _ = writeln!(err);
        }
        Answer::No => {}
    }
    Some(report_cancelled(
        err,
        settings.is_json(),
        settings.stderr_style(),
        "deactivate",
        CANCELLED,
    ))
}

/// Write the prompt before deactivating to `out`: that the session ends in a
/// power-off, and the question.
fn write_prompt(settings: &OutputSettings, out: &mut impl std::io::Write) {
    let style = settings.stderr_style();
    let _ = writeln!(
        out,
        "{}",
        style.marked(
            Mark::Warn,
            "This ends the hidden session and powers off the machine now."
        )
    );
    let _ = writeln!(
        out,
        "    Every hidden program closes. Unsaved work is lost."
    );
    let _ = write!(out, "    Continue? [y/N]: ");
    let _ = out.flush();
}

#[cfg(test)]
mod tests;
