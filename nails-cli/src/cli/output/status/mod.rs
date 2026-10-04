// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Output formatting for the status command

mod human;
mod json;

pub use human::{print_status_header, print_status_human};
pub use json::{print_status_json, print_status_json_unknown};

/// The config file path as shown by `status --details`, noting when it is absent.
pub(super) fn config_file_label(config_path: &std::path::Path) -> String {
    if config_path.is_file() {
        config_path.display().to_string()
    } else {
        format!("{} (not found, using defaults)", config_path.display())
    }
}

/// How many of the newest matching log entries `status` shows.
const RECENT_LOG_LIMIT: usize = 20;

/// Read recent log entries from the configured log path
///
/// Filters logs by:
/// - Activation time (only show logs after activation)
/// - Log level (skip DEBUG/TRACE unless show_debug is true)
///
/// Keeps the *newest* [`RECENT_LOG_LIMIT`] matching entries, in chronological
/// order, via a bounded queue so a large log never buffers in full. Returns the
/// formatted lines with timestamps and levels painted in `style`. The file is
/// only read, never written, so its size and mtime are untouched.
fn read_recent_logs(
    log_path: &std::path::Path,
    activated_at: Option<chrono::DateTime<chrono::Utc>>,
    show_debug: bool,
    style: nails_core::output::Style,
) -> Option<Vec<String>> {
    use nails_core::output::Tone;
    use std::collections::VecDeque;
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let log_file = log_path.join("nails.log");
    if !log_file.exists() {
        return None;
    }

    let file = File::open(&log_file).ok()?;
    let reader = BufReader::new(file);

    let mut recent_logs: VecDeque<String> = VecDeque::with_capacity(RECENT_LOG_LIMIT);

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

                let raw_message = entry
                    .get("fields")
                    .and_then(|f| f.get("message"))
                    .and_then(|m| m.as_str())
                    .unwrap_or_else(|| entry.get("message").and_then(|m| m.as_str()).unwrap_or(""));
                // A log message may embed a Unicode mark glyph (for example the
                // "✓ Activation complete" line). The `--ascii` surface must stay
                // pure ASCII even when replaying such a message, so fold it down
                // to ASCII in ascii mode; the Unicode terminal keeps the glyph.
                let message: std::borrow::Cow<'_, str> = if style.ascii {
                    std::borrow::Cow::Owned(nails_core::output::ascii_fallback(raw_message))
                } else {
                    std::borrow::Cow::Borrowed(raw_message)
                };

                let time = log_time.format("%H:%M:%S").to_string();
                let level_painted = match level {
                    "ERROR" => style.paint_bold(level, Tone::Red),
                    "WARN" => style.paint_bold(level, Tone::Yellow),
                    "INFO" => style.paint(level, Tone::Green),
                    "DEBUG" => style.paint(level, Tone::Cyan),
                    "TRACE" => style.paint(level, Tone::Dim),
                    _ => level.to_string(),
                };
                recent_logs.push_back(format!(
                    "[{}] {} {}",
                    style.paint(time, Tone::Dim),
                    level_painted,
                    message
                ));
                // Keep only the newest N, discarding the oldest once full.
                if recent_logs.len() > RECENT_LOG_LIMIT {
                    recent_logs.pop_front();
                }
            }
        }
    }

    if recent_logs.is_empty() {
        None
    } else {
        Some(recent_logs.into_iter().collect())
    }
}

#[cfg(test)]
mod tests;
