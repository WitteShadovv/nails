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

/// Which notice a cancelled activation prints, whether the operator answered
/// `n` at the prompt or pressed Ctrl+C at it or later in the entry. From the
/// catalogue, so the CLI and the window show the same words. What it may say
/// about this computer's disk depends on where the hidden volume lies, and
/// what it says about the hidden volume on how far the entry got.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CancelNotice {
    /// The hidden volume is a volume of its own and no hidden NixOS system
    /// was being built: the activation wrote nothing to this computer's disk.
    #[default]
    Plain,
    /// As [`Plain`](Self::Plain), but the entry of an activation that builds a
    /// hidden NixOS system had begun: what the build finished stays on the
    /// hidden volume, for the next activation.
    KeepsBuild,
    /// The hidden volume lies on storage the operator allowed with
    /// `--allow-decoy-storage`: what the activation wrote there stays.
    AllowedStorage,
}

impl CancelNotice {
    /// The notice of an activation whose hidden volume lies on storage the
    /// operator allowed (`on_allowed_storage`), or whose entry had begun to
    /// build a hidden NixOS system (`building`). Allowed storage comes first:
    /// there the activation's writes may be on this computer's own disk.
    pub fn new(on_allowed_storage: bool, building: bool) -> Self {
        if on_allowed_storage {
            Self::AllowedStorage
        } else if building {
            Self::KeepsBuild
        } else {
            Self::Plain
        }
    }

    /// The notice's words, from the catalogue.
    pub fn text(self) -> &'static str {
        use nails_core::catalog;
        match self {
            Self::Plain => catalog::CANCEL_ACTIVATE.text,
            Self::KeepsBuild => catalog::CANCEL_ACTIVATE_KEEPS_BUILD.text,
            Self::AllowedStorage => catalog::CANCEL_ACTIVATE_ALLOWED_STORAGE.text,
        }
    }
}

/// A cancelled activation as it is reported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Cancel {
    /// What it says.
    pub notice: CancelNotice,
    /// Whether the notice starts with a line break: a signal stopped the
    /// activation while no question was waiting for its answer, so the
    /// terminal echoed `^C` where the notice would begin. At the prompt the
    /// prompt ends its own line.
    pub below_echo: bool,
}

/// The cancel shape every command shares, with the notice of `cancel` as its
/// message: an error body with the code `cancelled`, no data.
fn cancel_envelope_line(cancel: Cancel) -> String {
    error_envelope(
        "activate",
        ErrorBody::new("cancelled", cancel.notice.text()),
    )
    .to_line()
}

/// The notice of `cancel` as the lines a person reads on stderr: an empty
/// line first when it starts below the terminal's `^C`, then the notice's
/// first line marked as neutral and each line after it indented below it.
fn cancel_lines(cancel: Cancel, style: nails_core::output::Style) -> Vec<String> {
    let mut lines = cancel.notice.text().lines();
    let first = style.marked(Mark::Neutral, lines.next().unwrap_or_default());
    cancel
        .below_echo
        .then(String::new)
        .into_iter()
        .chain(std::iter::once(first))
        .chain(lines.map(|line| format!("  {line}")))
        .collect()
}

/// Print a cancelled activation: under `--json` its one envelope on stdout,
/// otherwise its notice on stderr.
pub fn print_activate_cancel(cancel: Cancel, settings: &OutputSettings) {
    if settings.is_json() {
        crate::cli::output::envelope::print_envelope_line(&cancel_envelope_line(cancel));
    } else {
        for line in cancel_lines(cancel, settings.stderr_style()) {
            crate::cli::output::eprintln_tolerating_broken_pipe(&line);
        }
    }
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

/// The activation result as one JSON envelope line. A cancel is the one cancel
/// shape every command shares (an error body with the code `cancelled`, no
/// data), with the plain notice, as [`print_activate_cancel`] gives it for a
/// cancel it knows more of; every other failure keeps its data so a caller
/// learns what was prepared, with `ok` false; a success and a
/// success-with-warnings are `ok`.
pub fn activate_envelope_line(result: &ActivateResult<'_>, duration: f64) -> String {
    match result {
        ActivateResult::Failed(NailsError::Cancelled) => cancel_envelope_line(Cancel::default()),
        ActivateResult::Failed(error) => Envelope::failure_with_data(
            "activate",
            failure_error(error),
            activate_data(result, duration),
        )
        .to_line(),
        _ => Envelope::outcome("activate", true, activate_data(result, duration)).to_line(),
    }
}

/// Print the activation result as its one JSON envelope
/// ([`activate_envelope_line`]).
pub fn print_activate_json_result(result: &ActivateResult<'_>, duration: f64) {
    crate::cli::output::envelope::print_envelope_line(&activate_envelope_line(result, duration));
}

/// A warning as the lines a person reads: its first line marked as a
/// warning, and each line after it (the fix of a warning that has one)
/// indented below it.
pub fn warning_lines(style: nails_core::output::Style, warning: &str) -> Vec<String> {
    let mut lines = warning.lines();
    let first = style.marked(Mark::Warn, lines.next().unwrap_or_default());
    std::iter::once(first)
        .chain(lines.map(|line| format!("    {line}")))
        .collect()
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
                out.extend(warning_lines(out_style, warning));
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
            err.extend(cancel_lines(Cancel::default(), err_style));
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
