// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Output formatting for the activate command.
//!
//! For a person, activation prints its result *before* it enqueues the
//! soft-reboot, because the switch ends the terminal it runs in. Under `--json`
//! it is one envelope, printed once the soft-reboot is enqueued, so a failure
//! to enqueue it is the only document: the line stream of version 1 is gone,
//! so a reader sees exactly one document, as every other command gives (a
//! window watches progress on its own channel).

use nails_core::NailsError;
use nails_core::output::Mark;
use nails_core::session::Entry;
use serde::Serialize;

use super::OutputSettings;
use crate::cli::output::envelope::{Envelope, ErrorBody, error_envelope};

#[derive(Debug, Serialize)]
struct FailedCheckJson {
    name: String,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<String>,
}

/// The `data` payload for `activate --json`.
#[derive(Debug, Serialize)]
pub struct ActivateData {
    /// `entering`, `entering_with_warnings`, `already_active` or `failed`.
    status: &'static str,
    /// Seconds spent preparing the entry.
    duration: f64,
    /// The hidden NixOS toplevel entered, when one was built.
    #[serde(skip_serializing_if = "Option::is_none")]
    hidden_system: Option<String>,
    /// What happens to each decoy filesystem in the hidden root.
    filesystems: Vec<String>,
    /// Units masked in the hidden root.
    masked_units: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_checks: Option<Vec<FailedCheckJson>>,
}

/// What `activate` reports.
#[derive(Debug)]
pub enum ActivateResult<'a> {
    /// The entry is prepared; the soft-reboot follows.
    Entering(&'a Entry),
    /// Already in the hidden session.
    AlreadyActive,
    /// It failed.
    Failed(&'a NailsError),
}

/// What a cancelled activation reports, whether the operator answered `n` at
/// the prompt or pressed Ctrl+C at it or later in the entry. From the catalogue,
/// so the CLI and the window show the same words.
pub const CANCELLED: &str = nails_core::catalog::CANCEL_ACTIVATE.text;

/// `duration` (in seconds) as `status` shows the recorded activation time.
fn shown_duration(duration: f64) -> String {
    nails_core::timing::format_duration(
        std::time::Duration::try_from_secs_f64(duration).unwrap_or_default(),
    )
}

fn filesystems(entry: &Entry) -> Vec<String> {
    entry
        .decisions
        .iter()
        .filter(|d| !matches!(d, nails_core::session::policy::Decision::Leave { .. }))
        .map(nails_core::session::policy::Decision::describe)
        .collect()
}

/// The hidden NixOS system the session enters, when one was built. An
/// overlay-only entry keeps the decoy's own system, which is none.
fn hidden_system(entry: &Entry) -> Option<&std::path::Path> {
    let plan = &entry.plan;
    plan.hidden
        .system
        .as_deref()
        .filter(|system| plan.decoy.system.as_deref() != Some(*system))
}

/// Build the `data` payload for a result other than a cancel.
fn activate_data(result: &ActivateResult<'_>, duration: f64) -> ActivateData {
    let mut data = ActivateData {
        status: "already_active",
        duration,
        hidden_system: None,
        filesystems: Vec::new(),
        masked_units: Vec::new(),
        warnings: Vec::new(),
        message: "Already in the hidden session; nothing to do".to_string(),
        failed_checks: None,
    };
    match result {
        ActivateResult::AlreadyActive => {}
        ActivateResult::Entering(entry) => {
            data.status = if entry.warnings.is_empty() {
                "entering"
            } else {
                "entering_with_warnings"
            };
            data.hidden_system = hidden_system(entry).map(|p| p.display().to_string());
            data.filesystems = filesystems(entry);
            // The same list `status --json` shows for the session.
            data.masked_units = entry
                .plan
                .masks
                .iter()
                .chain(&entry.plan.boot_masks)
                .cloned()
                .collect();
            data.warnings = entry.warnings.clone();
            data.message = format!(
                "Prepared in {}; soft-rebooting into the hidden session",
                shown_duration(duration)
            );
        }
        ActivateResult::Failed(error) => {
            data.status = "failed";
            match error {
                NailsError::PreFlightCheckFailed(failures) => {
                    data.message = "Pre-flight checks failed".to_string();
                    data.failed_checks = Some(
                        failures
                            .iter()
                            .map(|(name, reason, fix)| FailedCheckJson {
                                name: name.clone(),
                                reason: reason.clone(),
                                fix: fix.clone(),
                            })
                            .collect(),
                    );
                }
                other => data.message = format!("Activation failed: {other}"),
            }
        }
    }
    data
}

/// The error body for a failed (non-cancel) result: one stable code per cause.
fn failure_error(error: &NailsError) -> ErrorBody {
    match error {
        NailsError::PreFlightCheckFailed(_) => {
            ErrorBody::new("not_ready", "Pre-flight checks failed")
        }
        NailsError::UnsupportedPlatform { .. } => ErrorBody::new("unsupported", error.to_string()),
        other => ErrorBody::new("activation_failed", format!("Activation failed: {other}")),
    }
}

/// Print the activation result as one JSON envelope. A cancel is the one cancel
/// shape every command shares (an error body with the code `cancelled`, no
/// data); every other failure keeps its data so a caller learns what was
/// prepared, with `ok` false; a success and a success-with-warnings are `ok`.
pub fn print_activate_json_result(result: &ActivateResult<'_>, duration: f64) {
    let line = match result {
        ActivateResult::Failed(NailsError::Cancelled) => {
            error_envelope("activate", ErrorBody::new("cancelled", CANCELLED)).to_line()
        }
        ActivateResult::Failed(error) => Envelope::failure_with_data(
            "activate",
            failure_error(error),
            activate_data(result, duration),
        )
        .to_line(),
        _ => Envelope::outcome("activate", true, activate_data(result, duration)).to_line(),
    };
    crate::cli::output::println_tolerating_broken_pipe(&line);
}

/// The human lines for a result: results on stdout, failures on stderr.
fn human_lines(
    result: &ActivateResult<'_>,
    duration: f64,
    settings: &OutputSettings,
) -> (Vec<String>, Vec<String>) {
    let out_style = settings.stdout_style();
    let err_style = settings.stderr_style();
    let mut out = Vec::new();
    let mut err = Vec::new();
    match result {
        ActivateResult::AlreadyActive => {
            out.push(out_style.marked(Mark::Pass, "Already in the hidden session"));
        }
        ActivateResult::Entering(entry) => {
            out.push(out_style.marked(
                Mark::Pass,
                format!("Hidden session prepared in {}", shown_duration(duration)),
            ));
            if !settings.is_quiet() {
                if let Some(system) = hidden_system(entry) {
                    out.push(format!("  Hidden system: {}", system.display()));
                }
                for line in filesystems(entry) {
                    out.push(format!("  {line}"));
                }
            }
            for warning in &entry.warnings {
                out.push(out_style.marked(Mark::Warn, warning));
            }
            out.push(String::new());
            out.push(
                "Soft-rebooting into the hidden session now: every program closes and you are \
                 logged out. Log in at the hidden session's login screen (a display manager \
                 set to log an account in automatically logs it in again, as at boot)."
                    .to_string(),
            );
        }
        ActivateResult::Failed(NailsError::Cancelled) => {
            err.push(err_style.marked(Mark::Neutral, CANCELLED));
        }
        ActivateResult::Failed(error) => {
            if let NailsError::PreFlightCheckFailed(failures) = error {
                err.push(err_style.marked(Mark::Fail, "Pre-flight checks failed"));
                for (name, reason, fix) in failures.iter() {
                    err.push(format!("  - {name}: {reason}"));
                    if let Some(fix) = fix {
                        for line in fix.lines() {
                            err.push(format!("      {line}"));
                        }
                    }
                }
            } else {
                err.push(err_style.marked(Mark::Fail, format!("Activation failed: {error}")));
            }
            err.push("  Nothing was changed: no next root is left behind.".to_string());
        }
    }
    (out, err)
}

/// Print the activation result in human-readable form.
pub fn print_activate_human(result: &ActivateResult<'_>, duration: f64, settings: &OutputSettings) {
    let (out, err) = human_lines(result, duration, settings);
    for line in out {
        crate::cli::output::println_tolerating_broken_pipe(&line);
    }
    for line in err {
        crate::cli::output::eprintln_tolerating_broken_pipe(&line);
    }
}

#[cfg(test)]
#[path = "activate_tests.rs"]
mod tests;
