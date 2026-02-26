//! # Status Report Types and Utilities
//!
//! Report generation, OpSec reminders, and status formatting.

use crate::SystemState;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

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
            ReminderSeverity::Info => "💡",     // Info/lightbulb for awareness
            ReminderSeverity::Warning => "⚠",   // Warning triangle
            ReminderSeverity::Critical => "🛑", // Stop sign for critical
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

/// Overlay verification result
///
/// Represents the outcome of verifying that overlay mounts match the state file.
///
/// # Variants
///
/// - **Verified**: Overlays match state file exactly
/// - **Mismatch**: Overlay mismatch detected with error details
/// - **Skipped**: Transitional state - verification not meaningful
/// - **NotApplicable**: No overlays to verify (Inactive state)
///
/// # Example
///
/// ```
/// use nails_core::status::VerificationStatus;
///
/// let verified = VerificationStatus::Verified;
/// assert!(verified.is_verified());
///
/// let mismatch = VerificationStatus::Mismatch {
///     errors: vec!["/home should be mounted but is not".to_string()],
/// };
/// assert!(!mismatch.is_verified());
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// Overlays match state file exactly
    Verified,

    /// Overlay mismatch detected (with errors)
    Mismatch { errors: Vec<String> },

    /// Transitional state - verification not meaningful
    Skipped,

    /// No overlays to verify (Inactive state)
    NotApplicable,
}

impl VerificationStatus {
    /// Check if verification passed
    ///
    /// Returns `true` for `Verified`, `false` for all other variants.
    pub fn is_verified(&self) -> bool {
        matches!(self, VerificationStatus::Verified)
    }
}

/// Security posture indicator with graduated levels
///
/// Represents the overall security posture of the NAILS system based on
/// system state and overlay verification. Provides visual indicators (emoji)
/// for at-a-glance status assessment.
///
/// # Variants
///
/// - **Secure** (🟢): Hidden environment active, overlays verified
/// - **Warning** (🟡): Transitional state or overlay inconsistency detected
/// - **Critical** (🔴): No protection (inactive) or emergency state
///
/// # Example
///
/// ```
/// use nails_core::status::SecurityPosture;
///
/// let posture = SecurityPosture::Secure;
/// assert_eq!(format!("{}", posture), "🟢 SECURE: Hidden environment active, overlays verified");
/// assert_eq!(posture.to_plain(), "[SECURE] Hidden environment active, overlays verified");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityPosture {
    /// System is fully protected with verified overlays
    ///
    /// This indicates the hidden environment is active and all overlay mounts
    /// have been verified to match the expected state.
    Secure,

    /// System is in transitional state or has inconsistencies
    ///
    /// This can indicate:
    /// - System is activating (transitional)
    /// - System is deactivating (transitional)
    /// - Active state but overlay verification failed
    ///
    /// Users should investigate the cause of the warning state.
    Warning,

    /// System is in decoy mode (inactive state)
    ///
    /// This indicates:
    /// - System is inactive (decoy environment only)
    /// - No sensitive data is accessible
    /// - This is the normal, expected default state
    ///
    /// The decoy state provides plausible deniability.
    Decoy,

    /// System is in emergency state requiring immediate attention
    ///
    /// This indicates:
    /// - Emergency shutdown has been triggered
    /// - System requires reboot to restore proper functionality
    ///
    /// In critical state, emergency deactivation has occurred.
    Critical,
}

impl SecurityPosture {
    /// Get the emoji indicator for this security posture
    ///
    /// Returns the appropriate colored circle emoji for visual indication.
    fn emoji(&self) -> &'static str {
        match self {
            SecurityPosture::Secure => "🟢",
            SecurityPosture::Warning => "🟡",
            SecurityPosture::Decoy => "🔴",
            SecurityPosture::Critical => "🔴",
        }
    }

    /// Get the text level indicator
    ///
    /// Returns the uppercase text representation of the security level.
    fn level(&self) -> &'static str {
        match self {
            SecurityPosture::Secure => "SECURE",
            SecurityPosture::Warning => "WARNING",
            SecurityPosture::Decoy => "DECOY",
            SecurityPosture::Critical => "CRITICAL",
        }
    }

    /// Get the descriptive message for this security posture
    ///
    /// Returns a human-readable description of what this posture means.
    fn description(&self) -> &'static str {
        match self {
            SecurityPosture::Secure => "Hidden environment active, overlays verified",
            SecurityPosture::Warning => "System in transitional state - wait for completion",
            SecurityPosture::Decoy => "Decoy system - no sensitive data accessible",
            SecurityPosture::Critical => "Emergency deactivation occurred - reboot recommended",
        }
    }

    /// Get ASCII-only representation for plain output mode
    ///
    /// Returns a string without emoji indicators, suitable for:
    /// - `--plain` flag output
    /// - NO_COLOR environment variable (handled at CLI layer)
    /// - Terminal environments that don't support Unicode
    ///
    /// # Example
    ///
    /// ```
    /// use nails_core::status::SecurityPosture;
    ///
    /// let posture = SecurityPosture::Secure;
    /// assert_eq!(posture.to_plain(), "[SECURE] Hidden environment active, overlays verified");
    /// ```
    pub fn to_plain(&self) -> String {
        format!("[{}] {}", self.level(), self.description())
    }
}

impl fmt::Display for SecurityPosture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}: {}",
            self.emoji(),
            self.level(),
            self.description()
        )
    }
}

/// Comprehensive status report
///
/// Contains all information about the current system state including overlays,
/// verification results, uptime tracking, and OpSec reminders.
///
/// # Fields
///
/// - **state**: Current system state from state file
/// - **overlays**: List of overlay paths (empty for inactive/transitional states)
/// - **overlay_verification**: Overlay verification result
/// - **nixos_generation**: NixOS generation (if available)
/// - **activated_at**: When the system was activated (None for inactive)
/// - **uptime**: How long the system has been active (None for inactive/transitional)
/// - **formatted_uptime**: Human-readable uptime string (empty for inactive/transitional)
/// - **opsec_reminders**: OpSec reminders based on uptime thresholds
/// - **overlay_details**: Full overlay mount details (for verbose mode, None for inactive/transitional)
///
/// # Example
///
/// ```
/// use nails_core::status::StatusReport;
/// use nails_core::SystemState;
///
/// let report = StatusReport {
///     state: SystemState::Inactive,
///     overlays: vec![],
///     overlay_verification: nails_core::status::VerificationStatus::NotApplicable,
///     nixos_generation: None,
///     activated_at: None,
///     uptime: None,
///     formatted_uptime: String::new(),
///     opsec_reminders: vec![],
///     overlay_details: None,
///     overlay_mount_statuses: vec![],
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverlayMountStatus {
    /// The overlay mount path
    pub path: PathBuf,
    /// Whether the overlay should be mounted based on state
    pub expected_mounted: bool,
    /// Whether the overlay is actually mounted (checked via filesystem.is_mounted)
    pub actually_mounted: bool,
}

/// Status report for the NAILS system
///
/// Comprehensive status report containing all information about the current
/// system state including overlays, verification results, uptime tracking,
/// and OpSec reminders.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusReport {
    /// Current system state from state file
    pub state: SystemState,

    /// List of overlay paths (empty for inactive/transitional states)
    pub overlays: Vec<PathBuf>,

    /// Overlay verification result
    pub overlay_verification: VerificationStatus,

    /// NixOS generation (if available)
    pub nixos_generation: Option<String>,

    /// When the system was activated (None for inactive)
    pub activated_at: Option<DateTime<Utc>>,

    /// How long the system has been active (None for inactive/transitional)
    pub uptime: Option<Duration>,

    /// Human-readable uptime string (empty for inactive/transitional)
    pub formatted_uptime: String,

    /// OpSec reminders based on uptime thresholds
    pub opsec_reminders: Vec<OpSecReminder>,

    /// Full overlay mount details including lower/upper/work directories
    /// Only populated for Active state, None for inactive/transitional
    /// Used by CLI verbose mode to show detailed overlay information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay_details: Option<std::collections::HashMap<PathBuf, crate::OverlayInfo>>,

    /// Per-overlay mount status (Task 3: Fix status display)
    /// Contains expected vs actual mount status for each overlay
    pub overlay_mount_statuses: Vec<OverlayMountStatus>,
}

impl StatusReport {
    /// Calculate security posture from state and verification
    ///
    /// Derives the security posture based on the current system state and
    /// overlay verification status.
    ///
    /// # Returns
    ///
    /// - **Secure**: Active state with verified overlays
    /// - **Warning**: Active state with mismatched overlays, or transitional state
    /// - **Decoy**: Inactive state (normal decoy environment)
    /// - **Critical**: Emergency state requiring immediate attention
    ///
    /// # Example
    ///
    /// ```
    /// use nails_core::status::{StatusReport, VerificationStatus, SecurityPosture};
    /// use nails_core::SystemState;
    ///
    /// let report = StatusReport {
    ///     state: SystemState::Inactive,
    ///     overlays: vec![],
    ///     overlay_verification: VerificationStatus::NotApplicable,
    ///     nixos_generation: None,
    ///     activated_at: None,
    ///     uptime: None,
    ///     formatted_uptime: String::new(),
    ///     opsec_reminders: vec![],
    ///     overlay_details: None,
    ///     overlay_mount_statuses: vec![],
    /// };
    ///
    /// assert_eq!(report.security_posture(), SecurityPosture::Decoy);
    /// ```
    pub fn security_posture(&self) -> SecurityPosture {
        match (&self.state, &self.overlay_verification) {
            (SystemState::Active { .. }, VerificationStatus::Verified) => SecurityPosture::Secure,
            (SystemState::Active { .. }, VerificationStatus::Mismatch { .. }) => {
                SecurityPosture::Warning
            }
            (SystemState::Activating { .. }, _) => SecurityPosture::Warning,
            (SystemState::Deactivating { .. }, _) => SecurityPosture::Warning,
            (SystemState::Inactive, _) => SecurityPosture::Decoy,
            (SystemState::Emergency { .. }, _) => SecurityPosture::Critical,
            // Fallback for edge cases (e.g., Active with Skipped/NotApplicable verification)
            _ => SecurityPosture::Warning,
        }
    }
}
