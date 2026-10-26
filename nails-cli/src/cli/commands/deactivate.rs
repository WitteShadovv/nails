// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Deactivate command handler
//!
//! In the hidden session, deactivation prepares the way back (the decoy root
//! at `/run/nextroot`, the hidden backend marked for closing), records the
//! state as inactive and enqueues the soft-reboot. The orderly shutdown stops
//! every hidden program, the transition scrubs `/run`, and the decoy starts at
//! its own login screen (a display manager set to log an account in
//! automatically logs it in again, as at boot). `--poweroff` powers off instead.

use std::io::IsTerminal;
use std::path::Path;

use nails_core::NailsError;
use nails_core::app::deactivate::{Prepared, ReadyDeactivation};
use nails_core::output::Mark;
use nails_core::session::{LeaveReport, LeaveTo};

use super::prompt::{Answer, read_answer_from_stdin};
use crate::cli::args::DeactivateArgs;
use crate::cli::output::deactivate::{
    DeactivateData, backend_left_open_warning, deactivate_error_body, print_deactivate_json,
};
use crate::cli::output::envelope::{ErrorBody, NextStep, report_cancelled, report_error};
use crate::cli::output::{ExitStatus, OutputSettings};

/// Execute the deactivate command.
///
/// A missing or invalid config is logged as a warning and defaults are used,
/// since a broken config must never block returning to the decoy.
///
/// # Returns
///
/// - [`ExitStatus::Ok`] once the soft-reboot (or power-off) was enqueued
/// - [`ExitStatus::Usage`] when confirmation is needed but stdin is not a terminal
/// - [`ExitStatus::InvalidState`] outside a hidden session, and in a hidden root
///   whose session plan cannot be read, before it asks anything
/// - [`ExitStatus::Cancelled`] when the operator declines at the prompt or
///   presses Ctrl+C there
/// - [`ExitStatus::Failed`] when the way back fails
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
/// report a refusal before anything is asked, else warn, confirm, lock and
/// leave.
fn deactivate_prepared(
    settings: &OutputSettings,
    args: &DeactivateArgs,
    prepared: Prepared,
) -> ExitStatus {
    deactivate_prepared_with(settings, args, prepared, |ready, to, warnings| {
        lock_and_leave(settings, ready, to, warnings)
    })
}

/// [`deactivate_prepared`], going on once the operator has confirmed with
/// `go_on`, which takes the ready deactivation, where it leaves to and the
/// warnings given before the question: [`lock_and_leave`], but in tests.
fn deactivate_prepared_with(
    settings: &OutputSettings,
    args: &DeactivateArgs,
    prepared: Prepared,
    go_on: impl FnOnce(ReadyDeactivation, LeaveTo, Vec<String>) -> ExitStatus,
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
        // Refused before the prompt, the lock and the lines a person reads
        // before the switch: there is no way back to take, and a plain
        // emergency, which finds no plan either, would do nothing.
        Prepared::WayBackUnknown(why) => {
            return report_error(
                json,
                "deactivate",
                ExitStatus::InvalidState,
                ErrorBody::new(
                    "invalid_state",
                    format!("in the hidden root without a way back: {why}"),
                )
                .with_hint(format!(
                    "Power off to end the session: `{}` (a plain emergency finds no session \
                     plan either, and does nothing)",
                    sudo_line(Step::EmergencyPoweroff)
                ))
                .with_next(NextStep::new(Step::EmergencyPoweroff.command())),
            );
        }
    };

    let to = if args.poweroff {
        LeaveTo::Poweroff
    } else {
        LeaveTo::Decoy
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
    // What the return will not put back, shown to a person before the
    // question, so a power-off can be chosen instead; under --json the one
    // envelope carries it once the switch is enqueued.
    let warnings = ready.warnings(to);
    if !json {
        write_warnings(settings, &warnings, &mut std::io::stderr());
    }
    if !args.yes
        && let Some(status) = confirm_or_cancel(
            settings,
            args.poweroff,
            &mut std::io::stderr(),
            read_answer_from_stdin,
        )
    {
        return status;
    }

    go_on(*ready, to, warnings)
}

/// Take the lock step's handle, the only one that leaves, and leave `to` with
/// it, reporting the outcome with the `warnings` given before the question.
/// The handle holds the lock until it is dropped, once the outcome is
/// reported.
fn lock_and_leave(
    settings: &OutputSettings,
    ready: ReadyDeactivation,
    to: LeaveTo,
    warnings: Vec<String>,
) -> ExitStatus {
    let mut locked = match ready.lock() {
        Ok(locked) => locked,
        Err(error) => return super::report_lock_error(error, "deactivate", settings.is_json()),
    };
    leave_and_report(settings, to, warnings, |to| locked.leave(to))
}

/// Write each of the `warnings` before the question, on `out` (stderr, as
/// the question).
fn write_warnings(settings: &OutputSettings, warnings: &[String], out: &mut impl std::io::Write) {
    let style = settings.stderr_style();
    for warning in warnings {
        let _ = writeln!(out, "{}", style.marked(Mark::Warn, warning));
    }
}

/// Commit the way back with `leave` and report it, returning the status to
/// exit with.
///
/// A person reads the result before the switch, which stops the terminal: the
/// lines come first, and a failure to prepare or enqueue it follows them on
/// stderr. Under `--json` the one envelope reports the outcome instead, so it
/// is printed only once the soft-reboot (or the power-off) is enqueued: a
/// failure is the only envelope, never one after a success, and a success
/// carries the `warnings` given before the question. A backend device the
/// way back could not mark to close is named after the enqueue, on both. The
/// process outlives the switch long enough to print it, since a mutating
/// command catches SIGTERM and ignores SIGHUP, but a reader the switch stops
/// first may not read it.
fn leave_and_report(
    settings: &OutputSettings,
    to: LeaveTo,
    mut warnings: Vec<String>,
    leave: impl FnOnce(LeaveTo) -> Result<LeaveReport, NailsError>,
) -> ExitStatus {
    let json = settings.is_json();
    let poweroff = to == LeaveTo::Poweroff;
    if !json {
        let style = settings.stdout_style();
        crate::cli::output::println_tolerating_broken_pipe(&style.marked(
            Mark::Pass,
            if poweroff {
                "Ending the hidden session and powering off"
            } else {
                "Ending the hidden session: soft-rebooting back to the decoy"
            },
        ));
        if !poweroff {
            crate::cli::output::println_tolerating_broken_pipe(
                "  The decoy starts at its own login screen in a few seconds (a display manager \
                 set to log an account in automatically logs it in again, as at boot).",
            );
        }
        crate::cli::output::flush_stdio();
    }
    match leave(to) {
        Ok(report) => {
            tracing::debug!(
                backend_closing = ?report.deferred,
                unmounted = ?report.unmounted,
                "the way back is enqueued"
            );
            let left_open = report.left_open();
            let left_open_warnings = left_open.iter().map(|name| backend_left_open_warning(name));
            if json {
                warnings.extend(left_open_warnings);
                print_deactivate_json(DeactivateData::enqueued(poweroff, warnings, left_open));
            } else {
                let style = settings.stdout_style();
                for warning in left_open_warnings {
                    crate::cli::output::println_tolerating_broken_pipe(
                        &style.marked(Mark::Warn, warning),
                    );
                }
            }
            crate::cli::output::flush_stdio();
            ExitStatus::Ok
        }
        Err(e) => report_error(
            json,
            "deactivate",
            ExitStatus::Failed,
            deactivate_error_body(&e),
        ),
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
    poweroff: bool,
    err: &mut impl std::io::Write,
    answer: impl FnOnce() -> Answer,
) -> Option<ExitStatus> {
    write_prompt(settings, poweroff, err);
    match answer() {
        Answer::Yes => return None,
        // Ctrl+C leaves the cursor after the prompt: end its line first.
        Answer::Cancelled => {
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

/// Write the prompt before deactivating to `out`: where the session ends,
/// and the question.
fn write_prompt(settings: &OutputSettings, poweroff: bool, out: &mut impl std::io::Write) {
    let style = settings.stderr_style();
    let (headline, detail) = if poweroff {
        (
            "This ends the hidden session and powers off now.",
            "    Every hidden program is closed; unsaved work is lost.",
        )
    } else {
        (
            "This ends the hidden session and returns to the decoy now.",
            "    Every hidden program is closed; unsaved work is lost.",
        )
    };
    let _ = writeln!(out, "{}", style.marked(Mark::Warn, headline));
    let _ = writeln!(out, "{detail}");
    let _ = write!(out, "    Continue? [y/N]: ");
    let _ = out.flush();
}

#[cfg(test)]
mod tests;
