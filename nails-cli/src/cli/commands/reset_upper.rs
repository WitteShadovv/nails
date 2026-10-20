// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! reset-upper command handler

use std::io::IsTerminal;
use std::path::Path;

use nails_core::app::discard_upper::DiscardData;
use nails_core::output::Mark;

use crate::cli::args::ResetUpperArgs;
use crate::cli::output::envelope::{
    Envelope, EnvelopePrint, ErrorBody, report_cancelled, report_error,
};
use crate::cli::output::{ExitStatus, OutputSettings};

/// Execute the reset-upper command.
///
/// Deletes a path's hidden copy from the root upper on the hidden volume
/// (`<upper>/<path>`), and the layers of a separate decoy filesystem mounted
/// at that path (`root/mounts/<path>`), so the decoy's own files show through
/// again at the next entry. It refuses in the hidden session (the upper is the
/// live root there), lists what it will delete, and confirms on a terminal
/// (`-y` skips the prompt).
///
/// # Returns
///
/// - [`ExitStatus::Ok`] once the upper was removed (or there was nothing to do)
/// - [`ExitStatus::Config`] when the configuration file could not be loaded
/// - [`ExitStatus::InvalidState`] in the hidden session
/// - [`ExitStatus::Usage`] when confirmation is needed but stdin is not a terminal
/// - [`ExitStatus::Cancelled`] when the operator declines
/// - [`ExitStatus::Failed`] on a lock or removal failure
pub fn execute(
    settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    args: &ResetUpperArgs,
    config_override: Option<&Path>,
) -> ExitStatus {
    use nails_core::NailsError;

    let json = settings.is_json();

    // reset-upper deletes data on the hidden volume, so it must not run against
    // a config file the operator did not mean.
    let loaded = match super::load_config_or_report(config_override, "reset-upper", json) {
        Ok(loaded) => loaded,
        Err(status) => return status,
    };
    let target = args.target.clone();
    let ready = nails_core::app::discard_upper::prepare(env, loaded.into_config());

    // Hold the exclusive state lock while we plan and delete, so a concurrent
    // activation cannot mount the target out from under the reset.
    let _state_lock = match super::acquire_state_lock_or_report(
        ready.hidden_root(),
        nails_core::hidden_root::Allow::Nothing,
        ready.state_path(),
        "reset-upper",
        json,
    ) {
        Ok(lock) => lock,
        Err(status) => return status,
    };

    let plan = match ready.plan(&target) {
        Ok(plan) => plan,
        Err(e) => {
            let status = match e {
                NailsError::InvalidState(_) => ExitStatus::InvalidState,
                _ => ExitStatus::Failed,
            };
            return report_error(
                json,
                "reset-upper",
                status,
                ErrorBody::new("reset_upper", e.to_string()),
            );
        }
    };

    if plan.is_empty() {
        if json {
            Envelope::success("reset-upper", DiscardData::from_plan(&plan)).print();
        } else {
            println!(
                "{}",
                settings.stdout_style().marked(
                    Mark::Info,
                    format_args!("Nothing to reset for {}", plan.target.display())
                )
            );
        }
        return ExitStatus::Ok;
    }

    // Confirmation gate: the removal is destructive, so without -y it lists the
    // directories and confirms on a terminal, refusing off one.
    if !args.yes {
        if std::io::stdin().is_terminal() {
            if let Some(status) = confirm_or_cancel(
                settings,
                &plan,
                &mut std::io::stderr(),
                &mut std::io::stdin().lock(),
            ) {
                return status;
            }
        } else {
            return report_error(
                json,
                "reset-upper",
                ExitStatus::Usage,
                ErrorBody::new(
                    "needs_confirmation",
                    "reset-upper deletes the target's hidden upper and needs confirmation, but stdin is not a terminal; pass -y/--yes to run non-interactively",
                ),
            );
        }
    }

    if let Err(e) = ready.apply(&plan) {
        return report_error(
            json,
            "reset-upper",
            ExitStatus::Failed,
            ErrorBody::new("reset_upper", e.to_string()),
        );
    }

    if json {
        Envelope::success("reset-upper", DiscardData::from_plan(&plan)).print();
    } else {
        let style = settings.stdout_style();
        println!(
            "{}",
            style.marked(
                Mark::Pass,
                format_args!("Reset the hidden upper for {}", plan.target.display())
            )
        );
        for path in plan.removals() {
            println!("  removed {}", path.display());
        }
        println!(
            "  {} falls back to its decoy on the next activation",
            plan.target.display()
        );
    }

    ExitStatus::Ok
}

/// The notice of an answer other than yes at the prompt, from the catalogue.
const CANCELLED: &str = nails_core::catalog::CANCEL_RESET.text;

/// Ask before deleting ([`confirm_reset`]), on stderr (`err`) so stdout stays
/// clean for `--json`. On an answer other than yes, report the cancel, which
/// removed nothing, and return the status to exit with: the neutral notice
/// `activate` gives on `err`, or under `--json` the error envelope with the
/// code `cancelled` on stdout. `None` when the operator confirmed.
fn confirm_or_cancel(
    settings: &OutputSettings,
    plan: &nails_core::ResetUpperPlan,
    err: &mut impl std::io::Write,
    input: &mut impl std::io::BufRead,
) -> Option<ExitStatus> {
    if confirm_reset(settings, plan, err, input) {
        return None;
    }
    Some(report_cancelled(
        err,
        settings.is_json(),
        settings.stderr_style(),
        "reset-upper",
        CANCELLED,
    ))
}

/// Prompt before deleting, returning whether the operator confirmed: the
/// warning and the list of directories go to `out`, the answer is read from
/// `input`. Only `y` or `yes` (any case) confirms; anything else, or a read
/// error, declines.
fn confirm_reset(
    settings: &OutputSettings,
    plan: &nails_core::ResetUpperPlan,
    out: &mut impl std::io::Write,
    input: &mut impl std::io::BufRead,
) -> bool {
    let style = settings.stderr_style();
    let _ = writeln!(
        out,
        "{}",
        style.marked(
            Mark::Warn,
            format_args!(
                "This permanently deletes the hidden upper for {}.",
                plan.target.display()
            )
        )
    );
    for path in plan.removals() {
        let _ = writeln!(out, "    remove {}", path.display());
    }
    if plan.resets_nix_store {
        let _ = writeln!(
            out,
            "    WARNING: resetting /nix drops the hidden Nix database and store paths."
        );
    }
    let _ = write!(out, "    Continue? [y/N]: ");
    let _ = out.flush();

    let mut answer = String::new();
    if input.read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
#[path = "reset_upper_tests.rs"]
mod tests;
