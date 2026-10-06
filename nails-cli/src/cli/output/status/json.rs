// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! JSON output formatting for the status command.
//!
//! The report is rendered into typed DTOs and wrapped in the shared envelope, so
//! `state` and `overlay_verification` are tagged objects rather than Rust
//! `Debug` strings. `posture` is the kernel-truth verdict; `state_source` records
//! how the state file loaded, so a consumer can tell a trusted state from a
//! defaulted one.

use serde::Serialize;

use crate::cli::output::dto::{DecoyWriterJson, StateJson, VerificationJson, decoy_writers_json};
use crate::cli::output::envelope::Envelope;

/// The `data` payload for `status --json`.
#[derive(Debug, Serialize)]
pub struct StatusData {
    /// System state as a tagged object.
    state: StateJson,
    /// How the state file loaded: loaded, missing, unreadable or corrupt.
    state_source: &'static str,
    /// Kernel-truth posture (decoy, active, degraded, inconsistent, unknown).
    posture: &'static str,
    /// Whether the decoy keeps a persistent log/audit store (persistent journald
    /// journal, or active rsyslog/syslog-ng/auditd) that a hidden session's
    /// metadata lands on. When true, an Active posture is not fully secure.
    decoy_persistent: bool,
    /// Remediation step for a dangerous or unknown posture.
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<&'static str>,
    /// Processes that kept writing to the decoy after activation (recorded at
    /// activation; empty unless the hidden environment is active).
    decoy_writers: Vec<DecoyWriterJson>,
    /// When the system was activated (ISO 8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    activated_at: Option<String>,
    /// Uptime in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_seconds: Option<i64>,
    /// Human-readable uptime string.
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_formatted: Option<String>,
    /// Overlay list with per-overlay identity.
    overlays: Vec<OverlayJsonEntry>,
    /// NAILS mounts still live that recovery must tear down (dangerous postures).
    remaining_mounts: Vec<String>,
    /// Overlay verification result as a tagged object.
    overlay_verification: VerificationJson,
    /// Persona mode (how the hidden session relates to the decoy account).
    #[serde(skip_serializing_if = "Option::is_none")]
    persona_mode: Option<&'static str>,
    /// Store path of the hidden NixOS system toplevel (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    hidden_toplevel: Option<String>,
    /// Reason the hidden NixOS configuration was not applied on the last
    /// activation (overlays up, declarative config not in force). Omitted when the
    /// hidden configuration is in force or none was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    hidden_config_warning: Option<String>,
    /// Total size of the hidden volume's filesystem in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    hidden_root_total_bytes: Option<u64>,
    /// Bytes in use on the hidden volume (total minus available).
    #[serde(skip_serializing_if = "Option::is_none")]
    hidden_root_used_bytes: Option<u64>,
    /// Bytes available on the hidden volume.
    #[serde(skip_serializing_if = "Option::is_none")]
    hidden_root_available_bytes: Option<u64>,
    /// Whether the hidden root is still a live mount point. `true` in the Decoy
    /// posture is the signature of an emergency teardown that did not close the
    /// backend: the hidden filesystem is still readable and its key is in RAM.
    hidden_root_mounted: bool,
    /// OpSec reminders.
    opsec_reminders: Vec<OpSecReminderJson>,
    /// The self-check written by the last standard deactivation, read back from
    /// the hidden volume when it is attached. Omitted when the volume is not
    /// attached or no report is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_deactivation: Option<nails_core::LastDeactivationReport>,
    /// The activation in flight (only while the state is `activating`).
    #[serde(skip_serializing_if = "Option::is_none")]
    activation_in_flight: Option<ActivationInFlightJson>,
    /// Timing of the most recent successful activation.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_activation: Option<LastActivationJson>,
}

#[derive(Debug, Serialize)]
struct ActivationInFlightJson {
    /// When the activation started (ISO 8601).
    started_at: String,
    /// Seconds the activation has been running.
    elapsed_seconds: u64,
    /// Stable identifier of the current phase, when a progress record exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    phase: Option<String>,
    /// Human-readable label of the current phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    phase_label: Option<String>,
    /// 1-based index of the current phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    step: Option<u32>,
    /// Number of phases the activation runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    total_steps: Option<u32>,
    /// Finer-grained detail within the phase.
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

impl From<&nails_core::status::ActivationInFlight> for ActivationInFlightJson {
    fn from(flight: &nails_core::status::ActivationInFlight) -> Self {
        let progress = flight.progress.as_ref();
        Self {
            started_at: flight.started_at.to_rfc3339(),
            elapsed_seconds: flight.elapsed_secs,
            phase: progress.map(|p| p.phase.clone()),
            phase_label: progress.map(|p| p.label.clone()),
            step: progress.map(|p| p.step),
            total_steps: progress.map(|p| p.total_steps),
            detail: progress.and_then(|p| p.detail.clone()),
        }
    }
}

#[derive(Debug, Serialize)]
struct LastActivationJson {
    /// How long the activation took, in milliseconds.
    duration_ms: u64,
    /// When the activation committed (ISO 8601).
    finished_at: String,
}

#[derive(Debug, Serialize)]
struct OverlayJsonEntry {
    /// Overlay mount path.
    mount_point: String,
    /// Mount status: `mounted` when it is a live NAILS overlay, else `not_mounted`.
    status: &'static str,
    /// Whether the kernel says NAILS created this mount.
    owned: bool,
    /// The overlay's upper directory, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    upperdir: Option<String>,
}

#[derive(Debug, Serialize)]
struct OpSecReminderJson {
    /// Reminder severity (info, warning, critical).
    severity: &'static str,
    /// Reminder message.
    message: String,
}

/// The stable label for how the state file loaded.
fn state_source_label(outcome: &nails_core::LoadOutcome) -> &'static str {
    use nails_core::LoadOutcome;
    match outcome {
        LoadOutcome::Loaded => "loaded",
        LoadOutcome::Missing => "missing",
        LoadOutcome::Unreadable => "unreadable",
        LoadOutcome::Corrupt => "corrupt",
    }
}

/// Build the `data` payload from a status report.
pub fn build_status_data(report: &nails_core::status::StatusReport) -> StatusData {
    use nails_core::status::ReminderSeverity;

    StatusData {
        state: StateJson::from_report(&report.state, &report.load_outcome),
        state_source: state_source_label(&report.load_outcome),
        posture: report.posture.as_str(),
        decoy_persistent: report.decoy_persistent,
        remediation: report.posture.remediation(),
        decoy_writers: decoy_writers_json(&report.state),
        activated_at: report.activated_at.map(|dt| dt.to_rfc3339()),
        uptime_seconds: report.uptime.map(|d| d.num_seconds()),
        uptime_formatted: if report.formatted_uptime.is_empty() {
            None
        } else {
            Some(report.formatted_uptime.clone())
        },
        overlays: report
            .overlay_mount_statuses
            .iter()
            .map(|status| OverlayJsonEntry {
                mount_point: status.path.display().to_string(),
                status: if status.actually_mounted {
                    "mounted"
                } else {
                    "not_mounted"
                },
                owned: status.owned,
                upperdir: status.upperdir.as_ref().map(|p| p.display().to_string()),
            })
            .collect(),
        remaining_mounts: report
            .remaining_mounts
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        overlay_verification: VerificationJson::from(&report.overlay_verification),
        persona_mode: Some(report.persona_mode.as_str()),
        hidden_toplevel: report.hidden_toplevel.clone(),
        hidden_config_warning: report.last_switch_warning.clone(),
        hidden_root_total_bytes: report.hidden_root_total,
        hidden_root_used_bytes: report.hidden_root_used,
        hidden_root_available_bytes: report.hidden_root_available,
        hidden_root_mounted: report.hidden_root_mounted,
        opsec_reminders: report
            .opsec_reminders
            .iter()
            .map(|reminder| OpSecReminderJson {
                severity: match reminder.severity {
                    ReminderSeverity::Info => "info",
                    ReminderSeverity::Warning => "warning",
                    ReminderSeverity::Critical => "critical",
                },
                message: reminder.message.clone(),
            })
            .collect(),
        last_deactivation: report.last_deactivation.clone(),
        activation_in_flight: report
            .activation_in_flight
            .as_ref()
            .map(ActivationInFlightJson::from),
        last_activation: report
            .last_activation
            .as_ref()
            .map(|last| LastActivationJson {
                duration_ms: last.duration_ms,
                finished_at: last.finished_at.to_rfc3339(),
            }),
    }
}

/// Build the `data` payload for a status run whose state file could not be read
/// or trusted: the posture is `unknown` and carries the reason.
pub fn build_status_data_unknown(reason: String) -> StatusData {
    use nails_core::status::Posture;

    StatusData {
        state: StateJson::Unknown {
            reason: reason.clone(),
        },
        state_source: "unreadable",
        posture: Posture::Unknown.as_str(),
        decoy_persistent: false,
        remediation: Posture::Unknown.remediation(),
        decoy_writers: Vec::new(),
        activated_at: None,
        uptime_seconds: None,
        uptime_formatted: None,
        overlays: Vec::new(),
        remaining_mounts: Vec::new(),
        overlay_verification: VerificationJson::NotApplicable,
        persona_mode: None,
        hidden_toplevel: None,
        hidden_config_warning: None,
        hidden_root_total_bytes: None,
        hidden_root_used_bytes: None,
        hidden_root_available_bytes: None,
        hidden_root_mounted: false,
        opsec_reminders: Vec::new(),
        last_deactivation: None,
        activation_in_flight: None,
        last_activation: None,
    }
}

/// Print the status report as one envelope on stdout.
pub fn print_status_json(report: &nails_core::status::StatusReport) {
    Envelope::success("status", build_status_data(report)).print();
}

/// Print an envelope for a status run whose state could not be trusted.
pub fn print_status_json_unknown(reason: String) {
    Envelope::success("status", build_status_data_unknown(reason)).print();
}
