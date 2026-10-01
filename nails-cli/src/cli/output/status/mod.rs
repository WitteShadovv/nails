//! Output formatting for the status command

mod human;
mod json;

pub use human::{print_status_header, print_status_human};
pub use json::print_status_json;

/// The config file path as shown by `status --details`, noting when it is absent.
pub(super) fn config_file_label(config_path: &std::path::Path) -> String {
    if config_path.is_file() {
        config_path.display().to_string()
    } else {
        format!("{} (not found, using defaults)", config_path.display())
    }
}

/// Read recent log entries from the configured log path
///
/// Filters logs by:
/// - Activation time (only show logs after activation)
/// - Log level (skip DEBUG/TRACE unless show_debug is true)
///
/// Returns formatted log lines with timestamps, levels painted in `style`.
fn read_recent_logs(
    log_path: &std::path::Path,
    activated_at: Option<chrono::DateTime<chrono::Utc>>,
    show_debug: bool,
    style: nails_core::output::Style,
) -> Option<Vec<String>> {
    use nails_core::output::Tone;
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

                let time = log_time.format("%H:%M:%S").to_string();
                let level_painted = match level {
                    "ERROR" => style.paint_bold(level, Tone::Red),
                    "WARN" => style.paint_bold(level, Tone::Yellow),
                    "INFO" => style.paint(level, Tone::Green),
                    "DEBUG" => style.paint(level, Tone::Cyan),
                    "TRACE" => style.paint(level, Tone::Dim),
                    _ => level.to_string(),
                };
                recent_logs.push(format!(
                    "[{}] {} {}",
                    style.paint(time, Tone::Dim),
                    level_painted,
                    message
                ));
            }
        }
    }

    if recent_logs.is_empty() {
        None
    } else {
        Some(recent_logs)
    }
}

#[cfg(test)]
mod tests;
