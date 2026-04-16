//! JSON output formatting for the status command

/// JSON output structure for status command (AC5)
#[derive(serde::Serialize)]
struct StatusJsonOutput {
    /// System state (ACTIVE, INACTIVE, etc.)
    state: String,
    /// Security posture level (secure, warning, critical)
    security_posture: String,
    /// When the system was activated (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    activated_at: Option<String>,
    /// Uptime in seconds
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_seconds: Option<i64>,
    /// Human-readable uptime string
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_formatted: Option<String>,
    /// Overlay list with status
    overlays: Vec<OverlayJsonEntry>,
    /// Overlay verification result
    overlay_verification: String,
    /// NixOS generation (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    nixos_generation: Option<String>,
    /// OpSec reminders
    opsec_reminders: Vec<OpSecReminderJson>,
}

#[derive(serde::Serialize)]
struct OverlayJsonEntry {
    /// Overlay mount path
    path: String,
    /// Mount status
    status: String,
}

#[derive(serde::Serialize)]
struct OpSecReminderJson {
    /// Reminder severity
    severity: String,
    /// Reminder message
    message: String,
}

/// Print status result in JSON format (AC5)
///
/// Outputs a JSON object with all status fields including:
/// - state (system state)
/// - security_posture (secure/warning/critical)
/// - activated_at (ISO 8601 timestamp)
/// - uptime_seconds (duration in seconds)
/// - uptime_formatted (human-readable uptime)
/// - overlays (array of overlay paths with status)
/// - overlay_verification (verification result)
/// - nixos_generation (current generation if available)
/// - opsec_reminders (array of reminders with severity and message)
///
/// # Arguments
///
/// * `report` - Status report from StatusCommand
pub fn print_status_json(report: &nails_core::status::StatusReport) {
    use nails_core::status::*;

    let output = StatusJsonOutput {
        state: format!("{:?}", report.state),
        security_posture: match report.security_posture() {
            SecurityPosture::Secure => "secure".to_string(),
            SecurityPosture::Warning => "warning".to_string(),
            SecurityPosture::Critical => "critical".to_string(),
            SecurityPosture::Decoy => "decoy".to_string(),
        },
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
                    "mounted".to_string()
                } else {
                    "not_mounted".to_string()
                },
            })
            .collect(),
        overlay_verification: format!("{:?}", report.overlay_verification),
        nixos_generation: report.nixos_generation.clone(),
        opsec_reminders: report
            .opsec_reminders
            .iter()
            .map(|reminder| OpSecReminderJson {
                severity: format!("{:?}", reminder.severity).to_lowercase(),
                message: reminder.message.clone(),
            })
            .collect(),
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&output).expect("Failed to serialize JSON")
    );
}
