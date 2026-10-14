// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! JSON output for the status command.
//!
//! `posture` is the verdict from live facts; `session` is the live view the
//! verdict comes from; `state` is the record on the hidden volume, with
//! `state_source` saying how it loaded.

use serde::Serialize;

use crate::cli::output::dto::StateJson;
use crate::cli::output::envelope::Envelope;
use nails_core::status::{PolicyMountView, ReminderSeverity, StatusReport};

/// The `data` payload for `status --json`.
#[derive(Debug, Serialize)]
pub struct StatusData<'a> {
    /// The verdict: decoy, active, transitioning, degraded or unknown.
    posture: &'static str,
    /// The live view: decoy, hidden, entering, interrupted or
    /// hidden_without_plan.
    session: &'static str,
    /// Why the posture is degraded.
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    /// What to do about a degraded or unknown posture.
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<&'static str>,
    /// The recorded state.
    state: StateJson,
    /// How the state file loaded: loaded, missing, unreadable or corrupt.
    state_source: &'static str,
    /// When the hidden root was entered (ISO 8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    entered_at: Option<String>,
    /// Uptime of the hidden session in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_seconds: Option<i64>,
    /// Human-readable uptime.
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_formatted: Option<String>,
    /// The hidden NixOS toplevel.
    #[serde(skip_serializing_if = "Option::is_none")]
    hidden_system: Option<&'a str>,
    /// The decoy NixOS toplevel the way back returns to.
    #[serde(skip_serializing_if = "Option::is_none")]
    decoy_system: Option<&'a str>,
    /// The hidden volume root.
    hidden_root: String,
    /// Whether the hidden volume is mounted at its own path.
    hidden_root_mounted: bool,
    /// Why the hidden root is not a volume of its own, when the session's
    /// activation accepted that with `--allow-decoy-storage`.
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_not_separate: Option<&'a str>,
    /// The source of a filesystem mounted over the hidden volume.
    #[serde(skip_serializing_if = "Option::is_none")]
    hidden_root_covered_by: Option<&'a str>,
    /// The decoy filesystems placed in the hidden root.
    policy_mounts: &'a [PolicyMountView],
    /// The decoy units masked in the hidden root.
    masked_units: &'a [String],
    /// Whether `/run/nextroot` is populated.
    nextroot_mounted: bool,
    /// Whether the decoy keeps a persistent journal or syslog.
    decoy_persistent: bool,
    /// The persona mode.
    persona_mode: &'static str,
    /// How long the last successful activation took, and when it finished.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_activation: Option<&'a nails_core::LastActivation>,
    /// Uptime-based reminders.
    opsec_reminders: Vec<ReminderJson<'a>>,
}

/// One OpSec reminder.
#[derive(Debug, Serialize)]
struct ReminderJson<'a> {
    /// `info`, `warning` or `critical`.
    severity: &'static str,
    message: &'a str,
}

fn data(report: &StatusReport) -> StatusData<'_> {
    StatusData {
        posture: report.posture.as_str(),
        session: report.session,
        reason: report.reason.as_deref(),
        remediation: report.remediation,
        state: StateJson::from_report(&report.state, &source_outcome(report.state_source)),
        state_source: report.state_source,
        entered_at: report.entered_at.map(|t| t.to_rfc3339()),
        uptime_seconds: report.uptime.map(|u| u.num_seconds()),
        uptime_formatted: report.uptime.map(nails_core::status::format_uptime),
        hidden_system: report.hidden_system.as_deref(),
        decoy_system: report.decoy_system.as_deref(),
        hidden_root: report.hidden_root.display().to_string(),
        hidden_root_mounted: report.hidden_root_mounted,
        accepted_not_separate: report.accepted_not_separate.as_deref(),
        hidden_root_covered_by: report.hidden_root_covered_by.as_deref(),
        policy_mounts: &report.policy_mounts,
        masked_units: &report.masked_units,
        nextroot_mounted: report.nextroot_mounted,
        decoy_persistent: report.decoy_persistent,
        persona_mode: report.persona_mode.as_str(),
        last_activation: report.last_activation.as_ref(),
        opsec_reminders: report
            .opsec_reminders
            .iter()
            .map(|r| ReminderJson {
                severity: match r.severity {
                    ReminderSeverity::Info => "info",
                    ReminderSeverity::Warning => "warning",
                    ReminderSeverity::Critical => "critical",
                },
                message: &r.message,
            })
            .collect(),
    }
}

fn source_outcome(source: &str) -> nails_core::LoadOutcome {
    match source {
        "missing" => nails_core::LoadOutcome::Missing,
        "unreadable" => nails_core::LoadOutcome::Unreadable,
        "corrupt" => nails_core::LoadOutcome::Corrupt,
        _ => nails_core::LoadOutcome::Loaded,
    }
}

/// The success envelope for a report.
pub fn status_envelope(report: &StatusReport) -> Envelope<StatusData<'_>> {
    Envelope::success("status", data(report))
}

/// Print the status report as one JSON envelope.
pub fn print_status_json(report: &StatusReport) {
    status_envelope(report).print();
}

/// The failure data when the status could not be built at all.
#[derive(Debug, Serialize)]
struct UnknownData {
    posture: &'static str,
    remediation: &'static str,
}

/// Print an unknown status (the report could not be built) as a failure
/// envelope.
pub fn print_status_json_unknown(error: String) {
    Envelope::failure_with_data(
        "status",
        crate::cli::output::envelope::ErrorBody::new("unknown_state", error),
        UnknownData {
            posture: "unknown",
            remediation: "Run status with sufficient privileges or fix the state file access",
        },
    )
    .print();
}
