//! # Status Report Types and Utilities
//!
//! Report generation, OpSec reminders, and status formatting.

mod types;

pub use types::{OverlayMountStatus, SecurityPosture, StatusReport, VerificationStatus};

use serde::{Deserialize, Serialize};
use std::fmt;

use chrono::Duration;

/// OpSec reminder with severity level
///
/// Represents an operational security reminder based on session uptime.
/// Reminders help users make informed decisions about when to deactivate
/// to minimize forensic traces.
///
/// # Fields
///
/// - **severity**: Reminder severity (Info, Warning, Critical)
/// - **message**: Human-readable reminder message
///
/// # Example
///
/// ```
/// use nails_core::status::{OpSecReminder, ReminderSeverity};
///
/// let reminder = OpSecReminder {
///     severity: ReminderSeverity::Critical,
///     message: "OPSEC WARNING: Session >24 hours - strongly recommend deactivation".to_string(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpSecReminder {
    /// Severity level for the reminder
    pub severity: ReminderSeverity,

    /// Human-readable reminder message
    pub message: String,
}

impl OpSecReminder {
    /// Get ASCII-only representation for plain output mode
    ///
    /// Returns a string without emoji indicators, suitable for:
    /// - `--plain` flag output
    /// - NO_COLOR environment variable
    /// - Terminal environments that don't support Unicode
    ///
    /// # Example
    ///
    /// ```
    /// use nails_core::status::{OpSecReminder, ReminderSeverity};
    ///
    /// let reminder = OpSecReminder {
    ///     severity: ReminderSeverity::Critical,
    ///     message: "Session >24 hours".to_string(),
    /// };
    ///
    /// assert_eq!(reminder.to_plain(), "[CRITICAL] Session >24 hours");
    /// ```
    pub fn to_plain(&self) -> String {
        format!("[{}] {}", self.severity, self.message)
    }
}

impl fmt::Display for OpSecReminder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let emoji = match self.severity {
            ReminderSeverity::Info => "\u{1f4a1}", // Info/lightbulb for awareness
            ReminderSeverity::Warning => "\u{26a0}", // Warning triangle
            ReminderSeverity::Critical => "\u{1f6d1}", // Stop sign for critical
        };
        write!(f, "{} {}", emoji, self.message)
    }
}

/// Severity level for OpSec reminders
///
/// Represents the urgency of an operational security reminder based on
/// session uptime thresholds.
///
/// # Variants
///
/// - **Info**: 6+ hours - Consider taking breaks
/// - **Warning**: 12+ hours - Forensic traces accumulate
/// - **Critical**: 24+ hours - Strongly recommend deactivation
///
/// # Example
///
/// ```
/// use nails_core::status::ReminderSeverity;
///
/// let severity = ReminderSeverity::Critical;
/// assert_eq!(format!("{}", severity), "CRITICAL");
/// assert_eq!(severity.to_plain(), "[CRITICAL]");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReminderSeverity {
    /// Informational reminder (6+ hours)
    Info,

    /// Warning reminder (12+ hours)
    Warning,

    /// Critical reminder (24+ hours)
    Critical,
}

impl fmt::Display for ReminderSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReminderSeverity::Info => write!(f, "INFO"),
            ReminderSeverity::Warning => write!(f, "WARNING"),
            ReminderSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl ReminderSeverity {
    /// Get ASCII-only representation for plain output mode
    ///
    /// Returns a string without emoji indicators.
    ///
    /// # Example
    ///
    /// ```
    /// use nails_core::status::ReminderSeverity;
    ///
    /// assert_eq!(ReminderSeverity::Info.to_plain(), "[INFO]");
    /// assert_eq!(ReminderSeverity::Warning.to_plain(), "[WARNING]");
    /// assert_eq!(ReminderSeverity::Critical.to_plain(), "[CRITICAL]");
    /// ```
    pub fn to_plain(&self) -> &'static str {
        match self {
            ReminderSeverity::Info => "[INFO]",
            ReminderSeverity::Warning => "[WARNING]",
            ReminderSeverity::Critical => "[CRITICAL]",
        }
    }
}

/// Format uptime duration as human-readable string
///
/// Converts a duration to a human-readable format with appropriate units:
/// - **<1 hour**: "X minute(s)" (e.g., "1 minute", "45 minutes")
/// - **1-24 hours**: "X hour(s) Y minute(s)" or "X hour(s)" (e.g., "1 hour", "3 hours 30 minutes")
/// - **>24 hours**: "X day(s) Y hour(s)" or "X day(s)" (e.g., "1 day", "2 days 5 hours")
///
/// # Arguments
///
/// * `duration` - Duration to format (must be non-negative)
///
/// # Returns
///
/// Human-readable string representation with proper singular/plural forms
///
/// # Edge Cases
///
/// - **Negative durations**: Returns "0 minutes" (durations < 0 are clamped to zero)
/// - **Zero duration**: Returns "0 minutes"
/// - **Large durations**: Formats days correctly (e.g., "365 days" for one year)
///
/// # Example
///
/// ```
/// use nails_core::status::format_uptime;
/// use chrono::Duration;
///
/// assert_eq!(format_uptime(Duration::minutes(1)), "1 minute");
/// assert_eq!(format_uptime(Duration::minutes(45)), "45 minutes");
/// assert_eq!(format_uptime(Duration::hours(1)), "1 hour");
/// assert_eq!(format_uptime(Duration::hours(3) + Duration::minutes(30)), "3 hours 30 minutes");
/// assert_eq!(format_uptime(Duration::hours(5)), "5 hours");
/// assert_eq!(format_uptime(Duration::days(1)), "1 day");
/// assert_eq!(format_uptime(Duration::days(2) + Duration::hours(5)), "2 days 5 hours");
/// ```
pub fn format_uptime(duration: Duration) -> String {
    // Guard against negative durations (clock skew protection)
    let total_minutes = duration.num_minutes().max(0);
    let days = total_minutes / (24 * 60);
    let hours = (total_minutes % (24 * 60)) / 60;
    let minutes = total_minutes % 60;

    // Helper to pluralize units
    let plural = |n: i64, unit: &str| {
        if n == 1 {
            format!("{} {}", n, unit)
        } else {
            format!("{} {}s", n, unit)
        }
    };

    match (days, hours, minutes) {
        (0, 0, m) => plural(m, "minute"),
        (0, h, 0) => plural(h, "hour"),
        (0, h, m) => format!("{} {}", plural(h, "hour"), plural(m, "minute")),
        (d, 0, _) => plural(d, "day"),
        (d, h, _) => format!("{} {}", plural(d, "day"), plural(h, "hour")),
    }
}

/// Generate OpSec reminders based on uptime
///
/// Returns reminders based on cumulative uptime thresholds:
/// - **6+ hours**: Info - Consider taking breaks
/// - **12+ hours**: Warning - Forensic traces accumulate
/// - **24+ hours**: Critical - Strongly recommend deactivation
///
/// Thresholds are cumulative - all applicable reminders are returned.
///
/// # Arguments
///
/// * `uptime` - Session duration
/// * `enabled` - Whether reminders are enabled
///
/// # Returns
///
/// Vector of reminders (empty if disabled or uptime <6 hours)
///
/// # Example
///
/// ```
/// use nails_core::status::{generate_opsec_reminders, ReminderSeverity};
/// use chrono::Duration;
///
/// // 6 hours - 1 reminder
/// let reminders = generate_opsec_reminders(Duration::hours(6), true);
/// assert_eq!(reminders.len(), 1);
/// assert_eq!(reminders[0].severity, ReminderSeverity::Info);
///
/// // 26 hours - all 3 reminders
/// let reminders = generate_opsec_reminders(Duration::hours(26), true);
/// assert_eq!(reminders.len(), 3);
///
/// // Disabled - no reminders
/// let reminders = generate_opsec_reminders(Duration::hours(26), false);
/// assert_eq!(reminders.len(), 0);
/// ```
pub fn generate_opsec_reminders(uptime: Duration, enabled: bool) -> Vec<OpSecReminder> {
    if !enabled {
        return Vec::new();
    }

    let hours = uptime.num_hours();
    let mut reminders = Vec::new();

    // Thresholds are cumulative - show all applicable reminders
    if hours >= 6 {
        reminders.push(OpSecReminder {
            severity: ReminderSeverity::Info,
            message: "Consider taking breaks for operational security".to_string(),
        });
    }

    if hours >= 12 {
        reminders.push(OpSecReminder {
            severity: ReminderSeverity::Warning,
            message: "Extended session - forensic traces accumulate over time".to_string(),
        });
    }

    if hours >= 24 {
        reminders.push(OpSecReminder {
            severity: ReminderSeverity::Critical,
            message: "Session >24 hours - strongly recommend deactivation".to_string(),
        });
    }

    reminders
}
