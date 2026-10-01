//! Output formatting for the status command

mod human;
mod json;

pub use human::print_status_human;
pub use json::print_status_json;

/// The config file path as shown in verbose status, noting when it is absent.
pub(super) fn config_file_label(config_path: &std::path::Path) -> String {
    if config_path.is_file() {
        config_path.display().to_string()
    } else {
        format!("{} (not found, using defaults)", config_path.display())
    }
}

/// Helper function to read recent log entries from the configured log path
///
/// Filters logs by:
/// - Activation time (only show logs after activation)
/// - Log level (skip DEBUG/TRACE unless show_debug is true)
///
/// Returns formatted log lines with timestamps and colored levels (if use_color is true)
fn read_recent_logs(
    log_path: &std::path::Path,
    activated_at: Option<chrono::DateTime<chrono::Utc>>,
    show_debug: bool,
    use_color: bool,
) -> Option<Vec<String>> {
    use colored::Colorize;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let log_file = log_path.join("nails.log");
    if !log_file.exists() {
        return None;
    }

    let file = File::open(&log_file).ok()?;
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
    log_path: &std::path::Path,
) {
    use nails_core::SystemState;

    // Print ASCII header (no box drawing)
    println!("=======================================");
    println!("  NAILS Status Report");
    println!("=======================================");
    println!();

    // Format state without ASCII indicator (AC1: indicator only on Security Posture line).
    // Report "Unknown" when the state file could not be read or trusted.
    let state_text = if report.load_outcome.is_unknown() {
        "Unknown".to_string()
    } else {
        format!("{:?}", report.state)
    };
    println!("State:              {}", state_text);

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
        println!("  Config file:        {}", config_file_label(config_path));
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

    // Verbose mode when inactive: show resolved paths (P1-03)
    if verbose && matches!(report.state, SystemState::Inactive) {
        use nails_core::LoadOutcome;

        println!();
        println!("Verbose Details:");
        println!("  Config file:        {}", config_file_label(config_path));
        println!("  Hidden volume root: {}", hidden_volume_root.display());
        println!("  State file:         {}", state_path.display());
        println!("  Log path:           {}", log_path.display());
        match &report.load_outcome {
            LoadOutcome::Loaded => println!("  State loaded:       normal"),
            LoadOutcome::Missing => println!("  State loaded:       fresh default (no file)"),
            LoadOutcome::Unreadable => {
                println!("  State loaded:       unreadable (state unknown, using defaults)")
            }
            LoadOutcome::Corrupt => {
                println!("  State loaded:       corrupt (state unknown, using defaults)")
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

    // Display recent logs if available (P1-03: use config log_path, no color in ASCII mode)
    if let Some(logs) = read_recent_logs(log_path, report.activated_at, verbose, false) {
        println!();
        println!("Recent Logs:");
        for log in logs.iter().take(20) {
            println!("  {}", log);
        }
    }
}

#[cfg(test)]
mod tests;
