//! Output formatting for the status command

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

/// Helper function to read recent log entries from the hidden volume
///
/// Filters logs by:
/// - Activation time (only show logs after activation)
/// - Log level (skip DEBUG/TRACE unless show_debug is true)
///
/// Returns formatted log lines with timestamps and colored levels (if use_color is true)
fn read_recent_logs(
    hidden_volume_root: &std::path::Path,
    activated_at: Option<chrono::DateTime<chrono::Utc>>,
    show_debug: bool,
    use_color: bool,
) -> Option<Vec<String>> {
    use colored::Colorize;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let log_path = hidden_volume_root.join("nails.log");
    if !log_path.exists() {
        return None;
    }

    let file = File::open(&log_path).ok()?;
    let reader = BufReader::new(file);

    let mut recent_logs = Vec::new();

    for line in reader.lines().map_while(Result::ok) {
        // Parse JSON log entry
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(&line) {
            // Check if log entry is after activation
            if let Some(timestamp_str) = entry.get("timestamp").and_then(|t| t.as_str())
                && let Ok(log_time) = chrono::DateTime::parse_from_rfc3339(timestamp_str)
            {
                if let Some(activation_time) = activated_at
                    && log_time.with_timezone(&chrono::Utc) < activation_time
                {
                    continue; // Skip logs from before activation
                }

                // Format log entry for human readability
                let level = entry
                    .get("level")
                    .and_then(|l| l.as_str())
                    .unwrap_or("INFO");

                // Skip DEBUG/TRACE unless show_debug is true
                if !show_debug && (level == "DEBUG" || level == "TRACE") {
                    continue;
                }

                let message = entry
                    .get("fields")
                    .and_then(|f| f.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or_else(|| entry.get("message").and_then(|m| m.as_str()).unwrap_or(""));

                let time = log_time.format("%H:%M:%S");

                // Colorize based on log level
                let formatted = if use_color {
                    let level_colored = match level {
                        "ERROR" => level.red().bold(),
                        "WARN" => level.yellow().bold(),
                        "INFO" => level.green(),
                        "DEBUG" => level.cyan(),
                        "TRACE" => level.bright_black(),
                        _ => level.normal(),
                    };
                    format!(
                        "[{}] {} {}",
                        time.to_string().bright_black(),
                        level_colored,
                        message
                    )
                } else {
                    format!("[{}] {} {}", time, level, message)
                };

                recent_logs.push(formatted);
            }
        }
    }

    if recent_logs.is_empty() {
        None
    } else {
        Some(recent_logs)
    }
}

/// When `verbose` is true, displays:
/// - Full overlay mount details (lower, upper, work directories)
/// - State file path
/// - Config file path
/// - Mount timestamps for each overlay
pub fn print_status_human(
    report: &nails_core::status::StatusReport,
    verbose: bool,
    config_path: &std::path::Path,
    state_path: &std::path::Path,
    hidden_volume_root: &std::path::Path,
) {
    use nails_core::SystemState;

    // Print header with box drawing
    println!("╭─────────────────────────────────────╮");
    println!("│  NAILS Status Report                │");
    println!("╰─────────────────────────────────────╯");
    println!();

    // Format state without emoji (AC1: emoji only on Security Posture line)
    println!("State:              {:?}", report.state);

    // Format security posture with Display trait (includes emoji)
    let posture = report.security_posture();
    println!("Security Posture:   {}", posture);

    // Print activation details for ACTIVE state
    if let SystemState::Active { .. } = report.state {
        if let Some(activated_at) = report.activated_at {
            println!(
                "Activated at:       {}",
                activated_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
        }

        if !report.formatted_uptime.is_empty() {
            println!("Uptime:             {}", report.formatted_uptime);
        }

        println!();

        // Print overlay list with per-overlay mount status (Task 3)
        if !report.overlay_mount_statuses.is_empty() {
            println!("Overlays:");
            for status in &report.overlay_mount_statuses {
                if status.actually_mounted {
                    println!("  ✓ {} (mounted)", status.path.display());
                } else {
                    println!("  ✗ {} (NOT mounted)", status.path.display());
                }
            }
        }

        // Print NixOS generation if available
        if let Some(ref generation) = report.nixos_generation {
            println!();
            println!("NixOS Generation:   {}", generation);
        }
    } else if let SystemState::Inactive = report.state {
        println!();
        println!("Run 'nails activate' to mount hidden environment");
    }

    // Verbose mode: show detailed overlay info (AC8)
    if verbose && matches!(report.state, SystemState::Active { .. }) {
        println!();
        println!("Verbose Details:");
        println!("  Config file:        {}", config_path.display());
        println!("  State file:         {}", state_path.display());
        println!();

        // Show detailed overlay mount information
        if let Some(ref overlay_details) = report.overlay_details {
            println!("  Overlay Mount Details:");
            for (mount_path, info) in overlay_details.iter() {
                println!();
                println!("    Mount:     {}", mount_path.display());
                println!("    Lower:     {}", info.lower_dir.display());
                println!("    Upper:     {}", info.upper_dir.display());
                println!("    Work:      {}", info.work_dir.display());
                println!(
                    "    Mounted:   {}",
                    info.mounted_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
            }
        }
    }

    // Print OpSec reminders if present (AC10)
    if !report.opsec_reminders.is_empty() {
        println!();
        for reminder in &report.opsec_reminders {
            println!("{}", reminder);
        }
    }

    // Display recent logs if available
    if let Some(logs) = read_recent_logs(hidden_volume_root, report.activated_at, verbose, true) {
        println!();
        println!("Recent Logs:");
        for log in logs.iter().take(20) {
            println!("  {}", log);
        }
    }
}

/// Print status result in ASCII-only format (AC6)
///
/// # Arguments
///
/// * `report` - Status report from StatusCommand
/// * `verbose` - Whether to show detailed overlay information
/// * `config_path` - Path to config file (shown in verbose mode)
/// * `state_path` - Path to state file (shown in verbose mode)
pub fn print_status_ascii(
    report: &nails_core::status::StatusReport,
    verbose: bool,
    config_path: &std::path::Path,
    state_path: &std::path::Path,
    hidden_volume_root: &std::path::Path,
) {
    use nails_core::SystemState;

    // Print ASCII header (no box drawing)
    println!("=======================================");
    println!("  NAILS Status Report");
    println!("=======================================");
    println!();

    // Format state without ASCII indicator (AC1: indicator only on Security Posture line)
    println!("State:              {:?}", report.state);

    // Format security posture with to_plain()
    let posture = report.security_posture();
    println!("Security Posture:   {}", posture.to_plain());

    // Print activation details for ACTIVE state
    if let SystemState::Active { .. } = report.state {
        if let Some(activated_at) = report.activated_at {
            println!(
                "Activated at:       {}",
                activated_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
        }

        if !report.formatted_uptime.is_empty() {
            println!("Uptime:             {}", report.formatted_uptime);
        }

        println!();

        // Print overlay list with per-overlay mount status (Task 3)
        if !report.overlay_mount_statuses.is_empty() {
            println!("Overlays:");
            for status in &report.overlay_mount_statuses {
                if status.actually_mounted {
                    println!("  [OK] {} (mounted)", status.path.display());
                } else {
                    println!("  [ERROR] {} (NOT mounted)", status.path.display());
                }
            }
        }

        // Print NixOS generation if available
        if let Some(ref generation) = report.nixos_generation {
            println!();
            println!("NixOS Generation:   {}", generation);
        }
    } else if let SystemState::Inactive = report.state {
        println!();
        println!("Run 'nails activate' to mount hidden environment");
    }

    // Verbose mode: show detailed info
    if verbose && matches!(report.state, SystemState::Active { .. }) {
        println!();
        println!("Verbose Details:");
        println!("  Config file:        {}", config_path.display());
        println!("  State file:         {}", state_path.display());
        println!();

        // Show detailed overlay mount information
        if let Some(ref overlay_details) = report.overlay_details {
            println!("  Overlay Mount Details:");
            for (mount_path, info) in overlay_details.iter() {
                println!();
                println!("    Mount:     {}", mount_path.display());
                println!("    Lower:     {}", info.lower_dir.display());
                println!("    Upper:     {}", info.upper_dir.display());
                println!("    Work:      {}", info.work_dir.display());
                println!(
                    "    Mounted:   {}",
                    info.mounted_at.format("%Y-%m-%d %H:%M:%S UTC")
                );
            }
        }
    }

    // Print OpSec reminders in ASCII format
    if !report.opsec_reminders.is_empty() {
        println!();
        for reminder in &report.opsec_reminders {
            // Format reminder in ASCII mode (no emoji)
            let severity_prefix = match reminder.severity {
                nails_core::status::ReminderSeverity::Info => "[INFO]",
                nails_core::status::ReminderSeverity::Warning => "[WARN]",
                nails_core::status::ReminderSeverity::Critical => "[CRITICAL]",
            };
            println!("{} {}", severity_prefix, reminder.message);
        }
    }

    // Display recent logs if available (no color in ASCII mode)
    if let Some(logs) = read_recent_logs(hidden_volume_root, report.activated_at, verbose, false) {
        println!();
        println!("Recent Logs:");
        for log in logs.iter().take(20) {
            println!("  {}", log);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_core::SystemState;
    use nails_core::status::{
        OpSecReminder, OverlayMountStatus, ReminderSeverity, StatusReport, VerificationStatus,
    };
    use std::path::PathBuf;

    fn inactive_report() -> StatusReport {
        StatusReport {
            state: SystemState::Inactive,
            overlays: vec![],
            overlay_verification: VerificationStatus::NotApplicable,
            nixos_generation: None,
            activated_at: None,
            uptime: None,
            formatted_uptime: String::new(),
            opsec_reminders: vec![],
            overlay_details: None,
            overlay_mount_statuses: vec![],
        }
    }

    fn active_report() -> StatusReport {
        let now = chrono::Utc::now();
        StatusReport {
            state: SystemState::Active {
                activated_at: now - chrono::Duration::hours(2),
                overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
            },
            overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
            overlay_verification: VerificationStatus::Verified,
            nixos_generation: Some("nails-gen-42".to_string()),
            activated_at: Some(now - chrono::Duration::hours(2)),
            uptime: Some(chrono::Duration::hours(2)),
            formatted_uptime: "2 hours".to_string(),
            opsec_reminders: vec![],
            overlay_details: None,
            overlay_mount_statuses: vec![
                OverlayMountStatus {
                    path: PathBuf::from("/home"),
                    expected_mounted: true,
                    actually_mounted: true,
                },
                OverlayMountStatus {
                    path: PathBuf::from("/etc"),
                    expected_mounted: true,
                    actually_mounted: false,
                },
            ],
        }
    }

    fn active_report_with_overlay_details() -> StatusReport {
        let now = chrono::Utc::now();
        let mut overlay_details = std::collections::HashMap::new();
        overlay_details.insert(
            PathBuf::from("/home"),
            nails_core::OverlayInfo {
                mount_path: PathBuf::from("/home"),
                lower_dir: PathBuf::from("/home"),
                upper_dir: PathBuf::from("/mnt/hidden/home/.upper"),
                work_dir: PathBuf::from("/mnt/hidden/home/.work"),
                mounted_at: now,
            },
        );
        StatusReport {
            state: SystemState::Active {
                activated_at: now,
                overlays: vec![PathBuf::from("/home")],
            },
            overlays: vec![PathBuf::from("/home")],
            overlay_verification: VerificationStatus::Verified,
            nixos_generation: None,
            activated_at: Some(now),
            uptime: Some(chrono::Duration::minutes(30)),
            formatted_uptime: "30 minutes".to_string(),
            opsec_reminders: vec![],
            overlay_details: Some(overlay_details),
            overlay_mount_statuses: vec![OverlayMountStatus {
                path: PathBuf::from("/home"),
                expected_mounted: true,
                actually_mounted: true,
            }],
        }
    }

    fn active_report_with_reminders() -> StatusReport {
        let now = chrono::Utc::now();
        StatusReport {
            state: SystemState::Active {
                activated_at: now - chrono::Duration::hours(26),
                overlays: vec![],
            },
            overlays: vec![],
            overlay_verification: VerificationStatus::Mismatch {
                errors: vec!["overlay mismatch".to_string()],
            },
            nixos_generation: None,
            activated_at: Some(now - chrono::Duration::hours(26)),
            uptime: Some(chrono::Duration::hours(26)),
            formatted_uptime: "1 day 2 hours".to_string(),
            opsec_reminders: vec![
                OpSecReminder {
                    severity: ReminderSeverity::Info,
                    message: "Take a break".to_string(),
                },
                OpSecReminder {
                    severity: ReminderSeverity::Warning,
                    message: "Extended session".to_string(),
                },
                OpSecReminder {
                    severity: ReminderSeverity::Critical,
                    message: "Session >24 hours".to_string(),
                },
            ],
            overlay_details: None,
            overlay_mount_statuses: vec![],
        }
    }

    fn emergency_report() -> StatusReport {
        let now = chrono::Utc::now();
        StatusReport {
            state: SystemState::Emergency { triggered_at: now },
            overlays: vec![],
            overlay_verification: VerificationStatus::Skipped,
            nixos_generation: None,
            activated_at: None,
            uptime: None,
            formatted_uptime: String::new(),
            opsec_reminders: vec![],
            overlay_details: None,
            overlay_mount_statuses: vec![],
        }
    }

    // ── print_status_json ──────────────────────────────────────────────────────

    #[test]
    fn test_print_status_json_inactive() {
        print_status_json(&inactive_report());
    }

    #[test]
    fn test_print_status_json_active() {
        print_status_json(&active_report());
    }

    #[test]
    fn test_print_status_json_active_uptime_empty() {
        let mut r = inactive_report();
        r.formatted_uptime = String::new();
        print_status_json(&r);
    }

    #[test]
    fn test_print_status_json_with_reminders() {
        print_status_json(&active_report_with_reminders());
    }

    #[test]
    fn test_print_status_json_emergency() {
        print_status_json(&emergency_report());
    }

    // ── print_status_human ─────────────────────────────────────────────────────

    #[test]
    fn test_print_status_human_inactive() {
        print_status_human(
            &inactive_report(),
            false,
            &PathBuf::from("/etc/nails.yaml"),
            &PathBuf::from("/mnt/hidden/state.json"),
            &PathBuf::from("/mnt/hidden"),
        );
    }

    #[test]
    fn test_print_status_human_active_basic() {
        print_status_human(
            &active_report(),
            false,
            &PathBuf::from("/etc/nails.yaml"),
            &PathBuf::from("/mnt/hidden/state.json"),
            &PathBuf::from("/mnt/hidden"),
        );
    }

    #[test]
    fn test_print_status_human_active_verbose_with_details() {
        print_status_human(
            &active_report_with_overlay_details(),
            true,
            &PathBuf::from("/etc/nails.yaml"),
            &PathBuf::from("/mnt/hidden/state.json"),
            &PathBuf::from("/mnt/hidden"),
        );
    }

    #[test]
    fn test_print_status_human_active_verbose_no_details() {
        print_status_human(
            &active_report(),
            true,
            &PathBuf::from("/etc/nails.yaml"),
            &PathBuf::from("/mnt/hidden/state.json"),
            &PathBuf::from("/mnt/hidden"),
        );
    }

    #[test]
    fn test_print_status_human_with_reminders() {
        print_status_human(
            &active_report_with_reminders(),
            false,
            &PathBuf::from("/etc/nails.yaml"),
            &PathBuf::from("/mnt/hidden/state.json"),
            &PathBuf::from("/mnt/hidden"),
        );
    }

    #[test]
    fn test_print_status_human_with_logs() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("nails.log");
        let now = chrono::Utc::now();

        let mut f = std::fs::File::create(&log_path).unwrap();
        for level in &["INFO", "WARN", "ERROR", "DEBUG", "TRACE"] {
            writeln!(
                f,
                r#"{{"timestamp":"{}","level":"{}","fields":{{"message":"msg {level}"}}}}"#,
                now.to_rfc3339(),
                level
            )
            .unwrap();
        }
        drop(f);

        let mut report = active_report();
        report.activated_at = Some(now - chrono::Duration::hours(1));
        print_status_human(
            &report,
            false,
            &PathBuf::from("/etc/nails.yaml"),
            &PathBuf::from("/mnt/hidden/state.json"),
            dir.path(),
        );
    }

    #[test]
    fn test_print_status_human_verbose_shows_debug_logs() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("nails.log");
        let now = chrono::Utc::now();

        let mut f = std::fs::File::create(&log_path).unwrap();
        writeln!(
            f,
            r#"{{"timestamp":"{}","level":"DEBUG","fields":{{"message":"debug msg"}}}}"#,
            now.to_rfc3339()
        )
        .unwrap();
        drop(f);

        let mut report = active_report_with_overlay_details();
        report.activated_at = Some(now - chrono::Duration::hours(1));
        print_status_human(
            &report,
            true,
            &PathBuf::from("/etc/nails.yaml"),
            &PathBuf::from("/mnt/hidden/state.json"),
            dir.path(),
        );
    }

    #[test]
    fn test_print_status_human_logs_filtered_before_activation() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("nails.log");
        let now = chrono::Utc::now();

        let mut f = std::fs::File::create(&log_path).unwrap();
        writeln!(
            f,
            r#"{{"timestamp":"{}","level":"INFO","fields":{{"message":"old"}}}}"#,
            (now - chrono::Duration::hours(5)).to_rfc3339()
        )
        .unwrap();
        drop(f);

        let mut report = active_report();
        report.activated_at = Some(now - chrono::Duration::hours(1));
        print_status_human(
            &report,
            false,
            &PathBuf::from("/etc/nails.yaml"),
            &PathBuf::from("/mnt/hidden/state.json"),
            dir.path(),
        );
    }

    #[test]
    fn test_print_status_human_logs_no_activation_time() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("nails.log");
        let now = chrono::Utc::now();

        let mut f = std::fs::File::create(&log_path).unwrap();
        writeln!(
            f,
            r#"{{"timestamp":"{}","level":"INFO","fields":{{"message":"msg"}}}}"#,
            now.to_rfc3339()
        )
        .unwrap();
        drop(f);

        let mut report = active_report();
        report.activated_at = None;
        print_status_human(
            &report,
            false,
            &PathBuf::from("/etc/nails.yaml"),
            &PathBuf::from("/mnt/hidden/state.json"),
            dir.path(),
        );
    }

    #[test]
    fn test_print_status_human_logs_invalid_json_ignored() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("nails.log");

        let mut f = std::fs::File::create(&log_path).unwrap();
        writeln!(f, "not json").unwrap();
        writeln!(f, r#"{{"no_timestamp":1}}"#).unwrap();
        drop(f);

        let mut report = active_report();
        report.activated_at = None;
        print_status_human(
            &report,
            false,
            &PathBuf::from("/etc/nails.yaml"),
            &PathBuf::from("/mnt/hidden/state.json"),
            dir.path(),
        );
    }

    // ── print_status_ascii ─────────────────────────────────────────────────────

    #[test]
    fn test_print_status_ascii_inactive() {
        print_status_ascii(
            &inactive_report(),
            false,
            &PathBuf::from("/etc/nails.yaml"),
            &PathBuf::from("/mnt/hidden/state.json"),
            &PathBuf::from("/mnt/hidden"),
        );
    }

    #[test]
    fn test_print_status_ascii_active_basic() {
        print_status_ascii(
            &active_report(),
            false,
            &PathBuf::from("/etc/nails.yaml"),
            &PathBuf::from("/mnt/hidden/state.json"),
            &PathBuf::from("/mnt/hidden"),
        );
    }

    #[test]
    fn test_print_status_ascii_active_verbose_with_details() {
        print_status_ascii(
            &active_report_with_overlay_details(),
            true,
            &PathBuf::from("/etc/nails.yaml"),
            &PathBuf::from("/mnt/hidden/state.json"),
            &PathBuf::from("/mnt/hidden"),
        );
    }

    #[test]
    fn test_print_status_ascii_verbose_no_details() {
        print_status_ascii(
            &active_report(),
            true,
            &PathBuf::from("/etc/nails.yaml"),
            &PathBuf::from("/mnt/hidden/state.json"),
            &PathBuf::from("/mnt/hidden"),
        );
    }

    #[test]
    fn test_print_status_ascii_with_all_reminder_severities() {
        print_status_ascii(
            &active_report_with_reminders(),
            false,
            &PathBuf::from("/etc/nails.yaml"),
            &PathBuf::from("/mnt/hidden/state.json"),
            &PathBuf::from("/mnt/hidden"),
        );
    }

    #[test]
    fn test_print_status_ascii_with_logs() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("nails.log");
        let now = chrono::Utc::now();

        let mut f = std::fs::File::create(&log_path).unwrap();
        writeln!(
            f,
            r#"{{"timestamp":"{}","level":"INFO","fields":{{"message":"ascii log"}}}}"#,
            now.to_rfc3339()
        )
        .unwrap();
        drop(f);

        let mut report = active_report();
        report.activated_at = Some(now - chrono::Duration::hours(1));
        print_status_ascii(
            &report,
            false,
            &PathBuf::from("/etc/nails.yaml"),
            &PathBuf::from("/mnt/hidden/state.json"),
            dir.path(),
        );
    }
}
