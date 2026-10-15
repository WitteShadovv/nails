// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Output formatting for the activate command.
//!
//! Activation prints its result *before* it enqueues the soft-reboot, because
//! the switch ends the terminal it runs in. Under `--json` the stream is NDJSON:
//! progress lines, then one result line.

use nails_core::NailsError;
use nails_core::output::Mark;
use nails_core::session::Entry;
use serde::Serialize;

use super::OutputSettings;
use crate::cli::output::envelope::SCHEMA_VERSION;

/// A streamed progress line for `activate --json`.
#[derive(Debug, Serialize)]
struct ActivateProgressEvent {
    schema_version: u32,
    command: &'static str,
    #[serde(rename = "type")]
    event_type: &'static str,
    phase: &'static str,
}

#[derive(Debug, Serialize)]
struct FailedCheckJson {
    name: String,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fix: Option<String>,
}

/// The final NDJSON line for `activate --json`.
#[derive(Debug, Serialize)]
struct ActivateResultEvent {
    schema_version: u32,
    command: &'static str,
    #[serde(rename = "type")]
    event_type: &'static str,
    ok: bool,
    /// `entering`, `entering_with_warnings`, `already_active`, `cancelled` or
    /// `error`.
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
/// the prompt or pressed Ctrl+C at it or later in the entry.
pub const CANCELLED: &str = "Activation cancelled; nothing was changed.";

/// Emit a progress event on stdout, ahead of the final result line.
pub fn print_activate_progress(phase: &'static str) {
    let event = ActivateProgressEvent {
        schema_version: SCHEMA_VERSION,
        command: "activate",
        event_type: "progress",
        phase,
    };
    crate::cli::output::println_tolerating_broken_pipe(
        &serde_json::to_string(&event).unwrap_or_default(),
    );
}

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

fn result_event(result: &ActivateResult<'_>, duration: f64) -> ActivateResultEvent {
    let mut event = ActivateResultEvent {
        schema_version: SCHEMA_VERSION,
        command: "activate",
        event_type: "result",
        ok: true,
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
            event.status = if entry.warnings.is_empty() {
                "entering"
            } else {
                "entering_with_warnings"
            };
            event.hidden_system = hidden_system(entry).map(|p| p.display().to_string());
            event.filesystems = filesystems(entry);
            // The same list `status --json` shows for the session.
            event.masked_units = entry
                .plan
                .masks
                .iter()
                .chain(&entry.plan.boot_masks)
                .cloned()
                .collect();
            event.warnings = entry.warnings.clone();
            event.message = format!(
                "Prepared in {}; soft-rebooting into the hidden session",
                shown_duration(duration)
            );
        }
        ActivateResult::Failed(NailsError::Cancelled) => {
            event.ok = false;
            event.status = "cancelled";
            event.message = CANCELLED.to_string();
        }
        ActivateResult::Failed(error) => {
            event.ok = false;
            event.status = "error";
            match error {
                NailsError::PreFlightCheckFailed(failures) => {
                    event.message = "Pre-flight checks failed".to_string();
                    event.failed_checks = Some(
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
                other => event.message = format!("Activation failed: {other}"),
            }
        }
    }
    event
}

/// Print the final activation result line in NDJSON.
pub fn print_activate_json_result(result: &ActivateResult<'_>, duration: f64) {
    crate::cli::output::println_tolerating_broken_pipe(
        &serde_json::to_string(&result_event(result, duration)).unwrap_or_default(),
    );
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
