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

use nails_core::app::deactivate::Prepared;
use nails_core::output::Mark;
use nails_core::session::LeaveTo;

use crate::cli::args::DeactivateArgs;
use crate::cli::output::deactivate::{deactivate_error_body, print_deactivate_json};
use crate::cli::output::envelope::{ErrorBody, report_cancelled, report_error};
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
/// - [`ExitStatus::InvalidState`] outside a hidden session
/// - [`ExitStatus::Failed`] when the operator declines or the way back fails
pub fn execute(
    settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    args: &DeactivateArgs,
    config_override: Option<&Path>,
) -> ExitStatus {
    let json = settings.is_json();

    let ready = match nails_core::app::deactivate::prepare(env, config_override) {
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
                    "an interrupted activation is cleaned up with '{}'",
                    nails_core::next_step::sudo_line(nails_core::next_step::NextStep::Recover)
                )),
            );
        }
    };

    if !args.yes {
        if !std::io::stdin().is_terminal() {
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
        if let Some(status) = confirm_or_cancel(
            settings,
            args.poweroff,
            &mut std::io::stderr(),
            &mut std::io::stdin().lock(),
        ) {
            return status;
        }
    }

    let _state_lock = match super::acquire_state_lock_or_report(
        ready.hidden_root(),
        nails_core::hidden_root::Allow::Nothing,
        ready.state_path(),
        "deactivate",
        json,
    ) {
        Ok(lock) => lock,
        Err(status) => return status,
    };

    let to = if args.poweroff {
        LeaveTo::Poweroff
    } else {
        LeaveTo::Decoy
    };
    // Print before enqueueing: the soft-reboot stops this terminal.
    if json {
        print_deactivate_json(args.poweroff);
    } else {
        let style = settings.stdout_style();
        crate::cli::output::println_tolerating_broken_pipe(&style.marked(
            Mark::Pass,
            if args.poweroff {
                "Ending the hidden session and powering off"
            } else {
                "Ending the hidden session: soft-rebooting back to the decoy"
            },
        ));
        if !args.poweroff {
            crate::cli::output::println_tolerating_broken_pipe(
                "  The decoy starts at its own login screen in a few seconds (a display manager \
                 set to log an account in automatically logs it in again, as at boot).",
            );
        }
    }
    crate::cli::output::flush_stdio();
    match ready.leave(to) {
        Ok(report) => {
            tracing::debug!(
                backend_closing = ?report.deferred,
                unmounted = ?report.unmounted,
                "the way back is enqueued"
            );
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

/// The notice of an answer other than yes at the prompt.
const CANCELLED: &str = "Deactivation cancelled; nothing was changed.";

/// Ask before deactivating ([`confirm_deactivate`]), on stderr (`err`) so
/// stdout stays clean. On an answer other than yes, report the cancel, which
/// changed nothing, and return the status to exit with: the neutral notice
/// `activate` gives on `err`, or under `--json` the error envelope with the
/// code `cancelled` on stdout. `None` when the operator confirmed.
fn confirm_or_cancel(
    settings: &OutputSettings,
    poweroff: bool,
    err: &mut impl std::io::Write,
    input: &mut impl std::io::BufRead,
) -> Option<ExitStatus> {
    if confirm_deactivate(settings, poweroff, err, input) {
        return None;
    }
    Some(report_cancelled(
        err,
        settings.is_json(),
        settings.stderr_style(),
        "deactivate",
        CANCELLED,
    ))
}

/// Prompt before deactivating, returning whether the operator confirmed: the
/// warning goes to `out`, the answer is read from `input`. Only `y` or `yes`
/// (any case) confirms; anything else, or a read error, declines.
fn confirm_deactivate(
    settings: &OutputSettings,
    poweroff: bool,
    out: &mut impl std::io::Write,
    input: &mut impl std::io::BufRead,
) -> bool {
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

    let mut answer = String::new();
    if input.read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests;
