//! JSON output formatting for the status command.
//!
//! The report is rendered into typed DTOs and wrapped in the shared envelope, so
//! `state` and `overlay_verification` are tagged objects rather than Rust
//! `Debug` strings.

use serde::Serialize;

use crate::cli::output::dto::{StateJson, VerificationJson};
use crate::cli::output::envelope::Envelope;

/// The `data` payload for `status --json`.
#[derive(Debug, Serialize)]
pub struct StatusData {
    /// System state as a tagged object.
    state: StateJson,
    /// Security posture level (secure, warning, critical, decoy).
    security_posture: &'static str,
    /// When the system was activated (ISO 8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    activated_at: Option<String>,
    /// Uptime in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_seconds: Option<i64>,
    /// Human-readable uptime string.
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_formatted: Option<String>,
    /// Overlay list with mount status.
    overlays: Vec<OverlayJsonEntry>,
    /// Overlay verification result as a tagged object.
    overlay_verification: VerificationJson,
    /// Persona mode (how the hidden session relates to the decoy account).
    #[serde(skip_serializing_if = "Option::is_none")]
    persona_mode: Option<&'static str>,
    /// NixOS generation (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    nixos_generation: Option<String>,
    /// Total size of the hidden volume's filesystem in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    hidden_root_total_bytes: Option<u64>,
    /// Bytes in use on the hidden volume (total minus available).
    #[serde(skip_serializing_if = "Option::is_none")]
    hidden_root_used_bytes: Option<u64>,
    /// Bytes available on the hidden volume.
    #[serde(skip_serializing_if = "Option::is_none")]
    hidden_root_available_bytes: Option<u64>,
    /// OpSec reminders.
    opsec_reminders: Vec<OpSecReminderJson>,
}

#[derive(Debug, Serialize)]
struct OverlayJsonEntry {
    /// Overlay mount path.
    path: String,
    /// Mount status.
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct OpSecReminderJson {
    /// Reminder severity (info, warning, critical).
    severity: &'static str,
    /// Reminder message.
    message: String,
}

fn posture_label(posture: nails_core::status::SecurityPosture) -> &'static str {
    use nails_core::status::SecurityPosture;
    match posture {
        SecurityPosture::Secure => "secure",
        SecurityPosture::Warning => "warning",
        SecurityPosture::Decoy => "decoy",
        SecurityPosture::Critical => "critical",
    }
}

/// Build the `data` payload from a status report.
pub fn build_status_data(report: &nails_core::status::StatusReport) -> StatusData {
    use nails_core::status::ReminderSeverity;

    StatusData {
        state: StateJson::from_report(&report.state, &report.load_outcome),
        security_posture: posture_label(report.security_posture()),
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
                path: status.path.display().to_string(),
                status: if status.actually_mounted {
                    "mounted"
                } else {
                    "not_mounted"
                },
            })
            .collect(),
        overlay_verification: VerificationJson::from(&report.overlay_verification),
        persona_mode: Some(report.persona_mode.as_str()),
        nixos_generation: report.nixos_generation.clone(),
        hidden_root_total_bytes: report.hidden_root_total,
        hidden_root_used_bytes: report.hidden_root_used,
        hidden_root_available_bytes: report.hidden_root_available,
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
    }
}

/// Build the `data` payload for a status run whose state file could not be read
/// or trusted: the state is `unknown` and carries the reason.
pub fn build_status_data_unknown(reason: String) -> StatusData {
    StatusData {
        state: StateJson::Unknown { reason },
        security_posture: "warning",
        activated_at: None,
        uptime_seconds: None,
        uptime_formatted: None,
        overlays: Vec::new(),
        overlay_verification: VerificationJson::NotApplicable,
        persona_mode: None,
        nixos_generation: None,
        hidden_root_total_bytes: None,
        hidden_root_used_bytes: None,
        hidden_root_available_bytes: None,
        opsec_reminders: Vec::new(),
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
