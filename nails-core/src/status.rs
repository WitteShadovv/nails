//! # Status Command and Reporting
//!
//! Provides system status query functionality with overlay verification.
//!
//! ## Overview
//!
//! The `StatusCommand` queries the current system state from the state file
//! and verifies that overlay mounts match the expected state. This provides
//! observability and consistency validation for the NAILS system.
//!
//! ## Components
//!
//! - **[`StatusCommand`]**: Main command struct that executes status queries
//! - **[`StatusReport`]**: Comprehensive report containing state, overlays, and verification results
//! - **[`VerificationStatus`]**: Enum representing overlay verification outcomes
//! - **[`SecurityPosture`]**: Enum representing security posture with graduated levels
//!
//! ## Example
//!
//! ```no_run
//! use nails_core::{StatusCommand, Config, RealFilesystem};
//! use std::path::PathBuf;
//!
//! let filesystem = RealFilesystem;
//! let config = Config::default();
//! let state_file_path = PathBuf::from("/mnt/hidden-volume/.nails/state.json");
//!
//! let cmd = StatusCommand::new(filesystem, config, state_file_path);
//! let report = cmd.run()?;
//!
//! println!("State: {:?}", report.state);
//! println!("Verification: {:?}", report.overlay_verification);
//! println!("Posture: {}", report.security_posture());
//! # Ok::<(), nails_core::NailsError>(())
//! ```
//!
//! # Requirements
//!
//! - FR4: Status command
//! - FR14: Overlay verification
//! - FR26: Track current state
//! - FR27: Track timestamp
//! - FR28: Track overlay status
//! - FR63: Status always succeeds (even on verification failure)
//! - NFR23: State verification (overlays match reality)
//! - NFR4: Status <500ms

use crate::{Config, Filesystem, Result, StateFile, SystemState};
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

    /// System has no protection or is in emergency state
    ///
    /// This indicates:
    /// - System is inactive (decoy environment only)
    /// - Emergency shutdown has been triggered
    ///
    /// In critical state, the hidden environment is not protecting the user.
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
            SecurityPosture::Critical => "CRITICAL",
        }
    }

    /// Get the descriptive message for this security posture
    ///
    /// Returns a human-readable description of what this posture means.
    fn description(&self) -> &'static str {
        match self {
            SecurityPosture::Secure => "Hidden environment active, overlays verified",
            SecurityPosture::Warning => "System in transitional state or inconsistency detected",
            SecurityPosture::Critical => "No protection or emergency state",
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
/// };
/// ```
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
    /// - **Critical**: Inactive or Emergency state
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
    /// };
    ///
    /// assert_eq!(report.security_posture(), SecurityPosture::Critical);
    /// ```
    pub fn security_posture(&self) -> SecurityPosture {
        match (&self.state, &self.overlay_verification) {
            (SystemState::Active { .. }, VerificationStatus::Verified) => SecurityPosture::Secure,
            (SystemState::Active { .. }, VerificationStatus::Mismatch { .. }) => {
                SecurityPosture::Warning
            }
            (SystemState::Activating { .. }, _) => SecurityPosture::Warning,
            (SystemState::Deactivating { .. }, _) => SecurityPosture::Warning,
            (SystemState::Inactive, _) => SecurityPosture::Critical,
            (SystemState::Emergency { .. }, _) => SecurityPosture::Critical,
            // Fallback for edge cases (e.g., Active with Skipped/NotApplicable verification)
            _ => SecurityPosture::Warning,
        }
    }
}

/// Status command for querying system state
///
/// `StatusCommand` loads the current state from the state file and verifies
/// that overlay mounts match the expected state.
///
/// # Type Parameters
///
/// - **F**: Filesystem trait implementation (RealFilesystem or MockFilesystem)
///
/// # Example
///
/// ```no_run
/// use nails_core::{StatusCommand, Config, RealFilesystem};
/// use std::path::PathBuf;
///
/// let filesystem = RealFilesystem;
/// let config = Config::default();
/// let state_file_path = PathBuf::from("/mnt/hidden-volume/.nails/state.json");
///
/// let cmd = StatusCommand::new(filesystem, config, state_file_path);
/// let report = cmd.run()?;
/// # Ok::<(), nails_core::NailsError>(())
/// ```
pub struct StatusCommand<F: Filesystem> {
    /// Filesystem abstraction for testability
    filesystem: F,

    /// Configuration (used for show_opsec_reminders setting)
    config: Config,

    /// Path to the state file
    state_file_path: PathBuf,
}

impl<F: Filesystem> StatusCommand<F> {
    /// Create a new StatusCommand
    ///
    /// # Arguments
    ///
    /// * `filesystem` - Filesystem trait implementation
    /// * `config` - Configuration (reserved for future use)
    /// * `state_file_path` - Path to the state file
    ///
    /// # Example
    ///
    /// ```
    /// use nails_core::{StatusCommand, Config, MockFilesystem};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/tmp/state.json");
    ///
    /// let cmd = StatusCommand::new(fs, config, state_path);
    /// ```
    pub fn new(filesystem: F, config: Config, state_file_path: PathBuf) -> Self {
        Self {
            filesystem,
            config,
            state_file_path,
        }
    }

    /// Execute the status command
    ///
    /// Loads the state file, extracts system state, verifies overlay status,
    /// calculates uptime, generates formatted uptime string, and creates
    /// OpSec reminders based on uptime thresholds.
    ///
    /// # Returns
    ///
    /// * `Ok(StatusReport)` - Comprehensive status report
    /// * `Err(NailsError)` - Error loading state file
    ///
    /// # Behavior
    ///
    /// - **Inactive**: Returns report with empty overlays, NotApplicable verification
    /// - **Active**: Returns report with overlay list, verification result, uptime, formatted_uptime, and OpSec reminders
    /// - **Transitional states**: Returns report with Skipped verification
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nails_core::{StatusCommand, Config, RealFilesystem};
    /// use std::path::PathBuf;
    ///
    /// let cmd = StatusCommand::new(
    ///     RealFilesystem,
    ///     Config::default(),
    ///     PathBuf::from("/mnt/hidden-volume/.nails/state.json"),
    /// );
    ///
    /// let report = cmd.run()?;
    /// println!("System state: {:?}", report.state);
    /// println!("Uptime: {}", report.formatted_uptime);
    /// println!("Reminders: {:?}", report.opsec_reminders);
    /// # Ok::<(), nails_core::NailsError>(())
    /// ```
    pub fn run(&self) -> Result<StatusReport> {
        // Load state file
        let state_file = StateFile::load(&self.state_file_path)?;

        // Extract data from state file
        let (overlays, activated_at) = match &state_file.state {
            SystemState::Inactive => (vec![], None),
            SystemState::Active {
                activated_at,
                overlays,
            } => (overlays.clone(), Some(*activated_at)),
            SystemState::Activating { .. }
            | SystemState::Deactivating { .. }
            | SystemState::Emergency { .. } => (vec![], None),
        };

        // Calculate uptime if active
        let uptime = self.calculate_uptime(activated_at);

        // Format uptime as human-readable string
        let formatted_uptime = match uptime {
            Some(duration) => format_uptime(duration),
            None => String::new(),
        };

        // Generate OpSec reminders based on uptime
        let opsec_reminders = match uptime {
            Some(duration) => generate_opsec_reminders(duration, self.config.show_opsec_reminders),
            None => Vec::new(),
        };

        // Verify overlays
        let overlay_verification = self.verify_overlays(&state_file)?;

        // Include overlay details for Active state (used by verbose mode)
        let overlay_details = match &state_file.state {
            SystemState::Active { .. } if !state_file.overlay_status.is_empty() => {
                Some(state_file.overlay_status.clone())
            }
            _ => None,
        };

        // Build report
        let report = StatusReport {
            state: state_file.state,
            overlays,
            overlay_verification,
            nixos_generation: state_file.nixos_generation,
            activated_at,
            uptime,
            formatted_uptime,
            opsec_reminders,
            overlay_details,
        };

        Ok(report)
    }

    /// Calculate uptime for active state
    ///
    /// Returns the duration since activation if the system is active,
    /// otherwise returns None.
    ///
    /// # Arguments
    ///
    /// * `activated_at` - Optional activation timestamp
    ///
    /// # Returns
    ///
    /// * `Some(Duration)` - Time since activation (if active and timestamp is valid)
    /// * `None` - System is inactive, transitional, or timestamp is in the future (clock skew)
    fn calculate_uptime(&self, activated_at: Option<DateTime<Utc>>) -> Option<Duration> {
        match activated_at {
            Some(timestamp) => {
                let now = Utc::now();
                let duration = now.signed_duration_since(timestamp);

                // Handle clock skew: if activated_at is in the future, return None
                // This prevents negative durations from corrupted state files or clock issues
                if duration.num_seconds() < 0 {
                    None
                } else {
                    Some(duration)
                }
            }
            None => None,
        }
    }

    /// Verify overlay mounts match state file
    ///
    /// Checks that each overlay in the state file matches the actual mount status.
    ///
    /// # Arguments
    ///
    /// * `state_file` - Loaded state file
    ///
    /// # Returns
    ///
    /// * `Ok(VerificationStatus::Verified)` - Overlays match expected state
    /// * `Ok(VerificationStatus::Mismatch)` - Overlays don't match (with errors)
    /// * `Ok(VerificationStatus::Skipped)` - Transitional state, verification skipped
    /// * `Ok(VerificationStatus::NotApplicable)` - Inactive state, no overlays
    ///
    /// # Verification Logic
    ///
    /// - **Active**: All overlays in Active.overlays must be in overlay_status and mounted
    /// - **Inactive**: No overlays should be mounted
    /// - **Transitional**: Skip verification (partial state expected)
    fn verify_overlays(&self, state_file: &StateFile) -> Result<VerificationStatus> {
        match &state_file.state {
            SystemState::Active { overlays, .. } => {
                // Verify all overlays are mounted
                let mut errors = Vec::new();

                // First: Validate that Active.overlays matches overlay_status keys
                // This ensures state file consistency
                for overlay_path in overlays {
                    if !state_file.overlay_status.contains_key(overlay_path) {
                        errors.push(format!(
                            "{} is listed in Active state but missing from overlay_status tracking",
                            overlay_path.display()
                        ));
                    }
                }

                // Second: Check that all tracked overlays are actually mounted
                for (path, overlay_info) in &state_file.overlay_status {
                    // Only verify overlays that are supposed to be active
                    if !overlays.contains(path) {
                        errors.push(format!(
                            "{} is in overlay_status but not listed in Active state",
                            path.display()
                        ));
                        continue;
                    }

                    match self.filesystem.is_mounted(&overlay_info.mount_path) {
                        Ok(true) => {
                            // Overlay is mounted as expected
                        }
                        Ok(false) => {
                            errors.push(format!("{} should be mounted but is not", path.display()));
                        }
                        Err(e) => {
                            errors.push(format!(
                                "Failed to check mount status for {}: {}",
                                path.display(),
                                e
                            ));
                        }
                    }
                }

                if errors.is_empty() {
                    Ok(VerificationStatus::Verified)
                } else {
                    Ok(VerificationStatus::Mismatch { errors })
                }
            }
            SystemState::Inactive => Ok(VerificationStatus::NotApplicable),
            SystemState::Activating { .. }
            | SystemState::Deactivating { .. }
            | SystemState::Emergency { .. } => Ok(VerificationStatus::Skipped),
        }
    }
}

impl Default for StatusReport {
    fn default() -> Self {
        Self {
            state: SystemState::Inactive,
            overlays: vec![],
            overlay_verification: VerificationStatus::NotApplicable,
            nixos_generation: None,
            activated_at: None,
            uptime: None,
            formatted_uptime: String::new(),
            opsec_reminders: vec![],
            overlay_details: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::OverlayInfo;
    use crate::{MockFilesystem, StateFile};
    use std::io::Write;
    use std::path::Path;
    use tempfile::NamedTempFile;

    /// Helper to create a temporary state file
    fn create_temp_state_file(state_file: &StateFile) -> NamedTempFile {
        let mut temp_file = NamedTempFile::new().unwrap();
        let json = serde_json::to_string_pretty(state_file).unwrap();
        temp_file.write_all(json.as_bytes()).unwrap();
        temp_file.flush().unwrap();
        temp_file
    }

    /// Helper to create overlay info
    fn create_overlay_info(mount_path: &str) -> OverlayInfo {
        OverlayInfo {
            mount_path: PathBuf::from(mount_path),
            lower_dir: PathBuf::from(format!("{}-lower", mount_path)),
            upper_dir: PathBuf::from(format!("{}-upper", mount_path)),
            work_dir: PathBuf::from(format!("{}-work", mount_path)),
            mounted_at: Utc::now(),
        }
    }

    #[test]
    fn test_verification_status_is_verified() {
        assert!(VerificationStatus::Verified.is_verified());
        assert!(
            !VerificationStatus::Mismatch {
                errors: vec!["error".to_string()]
            }
            .is_verified()
        );
        assert!(!VerificationStatus::Skipped.is_verified());
        assert!(!VerificationStatus::NotApplicable.is_verified());
    }

    // Task 6: Unit tests for INACTIVE state
    #[test]
    fn test_status_command_inactive() {
        let fs = MockFilesystem::new();

        let config = Config::default();
        let state_file = StateFile {
            state: SystemState::Inactive,
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        assert_eq!(report.state, SystemState::Inactive);
        assert!(report.overlays.is_empty());
        assert_eq!(
            report.overlay_verification,
            VerificationStatus::NotApplicable
        );
        assert!(report.uptime.is_none());
        assert!(report.activated_at.is_none());
        assert!(report.nixos_generation.is_none());
    }

    // Task 7: Unit tests for ACTIVE state
    #[test]
    fn test_status_command_active_verified() {
        let fs = MockFilesystem::new();
        fs.mock_set_mounted(Path::new("/home"), true);
        fs.mock_set_mounted(Path::new("/etc"), true);

        let config = Config::default();
        let activated_at = Utc::now() - chrono::Duration::hours(2);
        let overlays = vec![PathBuf::from("/home"), PathBuf::from("/etc")];

        let mut overlay_status = std::collections::HashMap::new();
        overlay_status.insert(PathBuf::from("/home"), create_overlay_info("/home"));
        overlay_status.insert(PathBuf::from("/etc"), create_overlay_info("/etc"));

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at,
                overlays: overlays.clone(),
            },
            overlay_status,
            nixos_generation: Some("generation-123".to_string()),
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        assert!(matches!(report.state, SystemState::Active { .. }));
        assert_eq!(report.overlays, overlays);
        assert_eq!(report.overlay_verification, VerificationStatus::Verified);
        assert!(report.uptime.is_some());
        assert_eq!(report.activated_at, Some(activated_at));
        assert_eq!(report.nixos_generation, Some("generation-123".to_string()));

        // Verify uptime is approximately 2 hours
        let uptime = report.uptime.unwrap();
        assert!(uptime.num_hours() >= 1 && uptime.num_hours() <= 3);
    }

    #[test]
    fn test_status_command_active_mismatch() {
        let fs = MockFilesystem::new();
        // First overlay mounted, second not
        fs.mock_set_mounted(Path::new("/home"), true);
        fs.mock_set_mounted(Path::new("/etc"), false);

        let config = Config::default();
        let activated_at = Utc::now() - chrono::Duration::minutes(30);
        let overlays = vec![PathBuf::from("/home"), PathBuf::from("/etc")];

        let mut overlay_status = std::collections::HashMap::new();
        overlay_status.insert(PathBuf::from("/home"), create_overlay_info("/home"));
        overlay_status.insert(PathBuf::from("/etc"), create_overlay_info("/etc"));

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at,
                overlays: overlays.clone(),
            },
            overlay_status,
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        assert!(matches!(report.state, SystemState::Active { .. }));
        assert_eq!(report.overlays, overlays);

        // Should have mismatch with /etc error
        match report.overlay_verification {
            VerificationStatus::Mismatch { errors } => {
                assert_eq!(errors.len(), 1);
                assert!(errors[0].contains("/etc"));
                assert!(errors[0].contains("should be mounted"));
            }
            _ => panic!("Expected Mismatch verification status"),
        }
    }

    // Task 8: Unit tests for transitional states
    #[test]
    fn test_status_command_activating() {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let started_at = Utc::now();

        let state_file = StateFile {
            state: SystemState::Activating { started_at },
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        assert!(matches!(report.state, SystemState::Activating { .. }));
        assert!(report.overlays.is_empty());
        assert_eq!(report.overlay_verification, VerificationStatus::Skipped);
        assert!(report.uptime.is_none());
        assert!(report.activated_at.is_none());
    }

    #[test]
    fn test_status_command_deactivating() {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let started_at = Utc::now();

        let state_file = StateFile {
            state: SystemState::Deactivating { started_at },
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        assert!(matches!(report.state, SystemState::Deactivating { .. }));
        assert!(report.overlays.is_empty());
        assert_eq!(report.overlay_verification, VerificationStatus::Skipped);
        assert!(report.uptime.is_none());
        assert!(report.activated_at.is_none());
    }

    #[test]
    fn test_status_command_emergency() {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let triggered_at = Utc::now();

        let state_file = StateFile {
            state: SystemState::Emergency { triggered_at },
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        assert!(matches!(report.state, SystemState::Emergency { .. }));
        assert!(report.overlays.is_empty());
        assert_eq!(report.overlay_verification, VerificationStatus::Skipped);
        assert!(report.uptime.is_none());
        assert!(report.activated_at.is_none());
    }

    // Task 9: Unit tests for overlay verification edge cases
    #[test]
    fn test_status_command_active_all_overlays_mounted() {
        let fs = MockFilesystem::new();
        fs.mock_set_mounted(Path::new("/home"), true);
        fs.mock_set_mounted(Path::new("/etc"), true);
        fs.mock_set_mounted(Path::new("/var"), true);

        let config = Config::default();
        let overlays = vec![
            PathBuf::from("/home"),
            PathBuf::from("/etc"),
            PathBuf::from("/var"),
        ];

        let mut overlay_status = std::collections::HashMap::new();
        for overlay in &overlays {
            overlay_status.insert(
                overlay.clone(),
                create_overlay_info(overlay.to_str().unwrap()),
            );
        }

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at: Utc::now(),
                overlays: overlays.clone(),
            },
            overlay_status,
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        assert_eq!(report.overlay_verification, VerificationStatus::Verified);
        assert_eq!(report.overlays.len(), 3);
    }

    #[test]
    fn test_status_command_active_no_overlays() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![],
            },
            overlay_status: std::collections::HashMap::new(),
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        assert_eq!(report.overlay_verification, VerificationStatus::Verified);
        assert!(report.overlays.is_empty());
    }

    #[test]
    fn test_status_command_active_multiple_mismatches() {
        let fs = MockFilesystem::new();
        // None mounted
        fs.mock_set_mounted(Path::new("/home"), false);
        fs.mock_set_mounted(Path::new("/etc"), false);
        fs.mock_set_mounted(Path::new("/var"), false);

        let config = Config::default();
        let overlays = vec![
            PathBuf::from("/home"),
            PathBuf::from("/etc"),
            PathBuf::from("/var"),
        ];

        let mut overlay_status = std::collections::HashMap::new();
        for overlay in &overlays {
            overlay_status.insert(
                overlay.clone(),
                create_overlay_info(overlay.to_str().unwrap()),
            );
        }

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at: Utc::now(),
                overlays: overlays.clone(),
            },
            overlay_status,
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        match report.overlay_verification {
            VerificationStatus::Mismatch { errors } => {
                assert_eq!(errors.len(), 3);
                assert!(errors.iter().any(|e| e.contains("/home")));
                assert!(errors.iter().any(|e| e.contains("/etc")));
                assert!(errors.iter().any(|e| e.contains("/var")));
            }
            _ => panic!("Expected Mismatch with 3 errors"),
        }
    }

    #[test]
    fn test_status_report_serialization() {
        let report = StatusReport {
            state: SystemState::Inactive,
            overlays: vec![],
            overlay_verification: VerificationStatus::NotApplicable,
            nixos_generation: None,
            activated_at: None,
            uptime: None,
            formatted_uptime: String::new(),
            opsec_reminders: vec![],
            overlay_details: None,
        };

        let json = serde_json::to_string(&report).unwrap();
        let deserialized: StatusReport = serde_json::from_str(&json).unwrap();

        assert_eq!(report, deserialized);
    }

    #[test]
    fn test_uptime_calculation_with_recent_activation() {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let activated_at = Utc::now() - chrono::Duration::minutes(5);

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at,
                overlays: vec![],
            },
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        let uptime = report.uptime.unwrap();
        assert!(uptime.num_minutes() >= 4 && uptime.num_minutes() <= 6);
    }

    #[test]
    fn test_uptime_calculation_with_long_activation() {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let activated_at = Utc::now() - chrono::Duration::days(7);

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at,
                overlays: vec![],
            },
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        let uptime = report.uptime.unwrap();
        assert_eq!(uptime.num_days(), 7);
    }

    // Security posture tests (Story 7.2)

    #[test]
    fn test_security_posture_active_verified() {
        let report = StatusReport {
            state: SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![PathBuf::from("/home")],
            },
            overlay_verification: VerificationStatus::Verified,
            ..Default::default()
        };

        let posture = report.security_posture();
        assert_eq!(posture, SecurityPosture::Secure);
        assert!(format!("{}", posture).contains('🟢'));
        let plain = posture.to_plain();
        assert!(plain.contains("[SECURE]"));
    }

    #[test]
    fn test_security_posture_active_mismatch() {
        let report = StatusReport {
            state: SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![PathBuf::from("/home")],
            },
            overlay_verification: VerificationStatus::Mismatch {
                errors: vec!["Overlay not mounted".to_string()],
            },
            ..Default::default()
        };

        let posture = report.security_posture();
        assert_eq!(posture, SecurityPosture::Warning);
        assert!(format!("{}", posture).contains('🟡'));
        let plain = posture.to_plain();
        assert!(plain.contains("[WARNING]"));
    }

    #[test]
    fn test_security_posture_activating() {
        let report = StatusReport {
            state: SystemState::Activating {
                started_at: Utc::now(),
            },
            overlay_verification: VerificationStatus::Skipped,
            ..Default::default()
        };

        let posture = report.security_posture();
        assert_eq!(posture, SecurityPosture::Warning);
        assert!(format!("{}", posture).contains('🟡'));
        let plain = posture.to_plain();
        assert!(plain.contains("[WARNING]"));
    }

    #[test]
    fn test_security_posture_deactivating() {
        let report = StatusReport {
            state: SystemState::Deactivating {
                started_at: Utc::now(),
            },
            overlay_verification: VerificationStatus::Skipped,
            ..Default::default()
        };

        let posture = report.security_posture();
        assert_eq!(posture, SecurityPosture::Warning);
        assert!(format!("{}", posture).contains('🟡'));
        let plain = posture.to_plain();
        assert!(plain.contains("[WARNING]"));
    }

    #[test]
    fn test_security_posture_inactive() {
        let report = StatusReport {
            state: SystemState::Inactive,
            overlay_verification: VerificationStatus::NotApplicable,
            ..Default::default()
        };

        let posture = report.security_posture();
        assert_eq!(posture, SecurityPosture::Critical);
        assert!(format!("{}", posture).contains('🔴'));
        let plain = posture.to_plain();
        assert!(plain.contains("[CRITICAL]"));
    }

    #[test]
    fn test_security_posture_emergency() {
        let report = StatusReport {
            state: SystemState::Emergency {
                triggered_at: Utc::now(),
            },
            overlay_verification: VerificationStatus::Skipped,
            ..Default::default()
        };

        let posture = report.security_posture();
        assert_eq!(posture, SecurityPosture::Critical);
        assert!(format!("{}", posture).contains('🔴'));
        let plain = posture.to_plain();
        assert!(plain.contains("[CRITICAL]"));
    }

    #[test]
    fn test_security_posture_display_secure() {
        let posture = SecurityPosture::Secure;
        let display = format!("{}", posture);

        assert!(display.contains('🟢'));
        assert!(display.contains("SECURE"));
        assert!(display.contains("Hidden environment active"));
    }

    #[test]
    fn test_security_posture_display_warning() {
        let posture = SecurityPosture::Warning;
        let display = format!("{}", posture);

        assert!(display.contains('🟡'));
        assert!(display.contains("WARNING"));
        assert!(display.contains("transitional state") || display.contains("inconsistency"));
    }

    #[test]
    fn test_security_posture_display_critical() {
        let posture = SecurityPosture::Critical;
        let display = format!("{}", posture);

        assert!(display.contains('🔴'));
        assert!(display.contains("CRITICAL"));
        assert!(display.contains("No protection") || display.contains("emergency"));
    }

    #[test]
    fn test_security_posture_to_plain_secure() {
        let posture = SecurityPosture::Secure;
        let plain = posture.to_plain();

        assert!(!plain.contains('🟢')); // No emoji
        assert!(plain.contains("[SECURE]"));
        assert!(plain.contains("Hidden environment active"));
        assert_eq!(
            plain,
            "[SECURE] Hidden environment active, overlays verified"
        );
    }

    #[test]
    fn test_security_posture_to_plain_warning() {
        let posture = SecurityPosture::Warning;
        let plain = posture.to_plain();

        assert!(!plain.contains('🟡')); // No emoji
        assert!(plain.contains("[WARNING]"));
        assert!(plain.contains("transitional state") || plain.contains("inconsistency"));
        assert_eq!(
            plain,
            "[WARNING] System in transitional state or inconsistency detected"
        );
    }

    #[test]
    fn test_security_posture_to_plain_critical() {
        let posture = SecurityPosture::Critical;
        let plain = posture.to_plain();

        assert!(!plain.contains('🔴')); // No emoji
        assert!(plain.contains("[CRITICAL]"));
        assert!(plain.contains("No protection") || plain.contains("emergency"));
        assert_eq!(plain, "[CRITICAL] No protection or emergency state");
    }

    #[test]
    fn test_security_posture_screenreader_compatibility() {
        let postures = [
            SecurityPosture::Secure,
            SecurityPosture::Warning,
            SecurityPosture::Critical,
        ];

        for posture in postures {
            let display = format!("{}", posture);
            let plain = posture.to_plain();

            // All should have text labels (not just emoji)
            assert!(
                display.len() > 5,
                "Posture should have more than just emoji: {}",
                display
            );
            assert!(
                plain.len() > 10,
                "Plain text should be descriptive: {}",
                plain
            );
        }
    }

    // ========== Uptime Formatting Tests (Story 7.3) ==========

    #[test]
    fn test_uptime_formatting_less_than_hour() {
        // Test <1 hour: "45 minutes"
        let duration = Duration::minutes(45);
        let formatted = format_uptime(duration);
        assert_eq!(formatted, "45 minutes");
    }

    #[test]
    fn test_uptime_formatting_one_minute() {
        // Test edge case: 1 minute (singular)
        let duration = Duration::minutes(1);
        let formatted = format_uptime(duration);
        assert_eq!(formatted, "1 minute");
    }

    #[test]
    fn test_uptime_formatting_hours_only() {
        // Test 1-24 hours: "5 hours" (omits minutes if zero)
        let duration = Duration::hours(5);
        let formatted = format_uptime(duration);
        assert_eq!(formatted, "5 hours");
    }

    #[test]
    fn test_uptime_formatting_hours_and_minutes() {
        // Test 1-24 hours: "3 hours 30 minutes"
        let duration = Duration::hours(3) + Duration::minutes(30);
        let formatted = format_uptime(duration);
        assert_eq!(formatted, "3 hours 30 minutes");
    }

    #[test]
    fn test_uptime_formatting_one_hour() {
        // Test edge case: exactly 1 hour (singular)
        let duration = Duration::hours(1);
        let formatted = format_uptime(duration);
        assert_eq!(formatted, "1 hour");
    }

    #[test]
    fn test_uptime_formatting_days_only() {
        // Test >24 hours: "3 days" (omits hours if zero)
        let duration = Duration::days(3);
        let formatted = format_uptime(duration);
        assert_eq!(formatted, "3 days");
    }

    #[test]
    fn test_uptime_formatting_days_and_hours() {
        // Test >24 hours: "2 days 5 hours"
        let duration = Duration::days(2) + Duration::hours(5);
        let formatted = format_uptime(duration);
        assert_eq!(formatted, "2 days 5 hours");
    }

    #[test]
    fn test_uptime_formatting_rounding() {
        // Test rounding to nearest minute (Duration already handles this)
        let duration = Duration::seconds(90); // 1.5 minutes
        let formatted = format_uptime(duration);
        assert_eq!(formatted, "1 minute"); // rounds to 1 minute (singular)
    }

    #[test]
    fn test_uptime_formatting_one_day() {
        // Test edge case: exactly 1 day (singular)
        let duration = Duration::days(1);
        let formatted = format_uptime(duration);
        assert_eq!(formatted, "1 day");
    }

    #[test]
    fn test_uptime_formatting_one_hour_one_minute() {
        // Test edge case: 1 hour 1 minute (both singular)
        let duration = Duration::hours(1) + Duration::minutes(1);
        let formatted = format_uptime(duration);
        assert_eq!(formatted, "1 hour 1 minute");
    }

    #[test]
    fn test_uptime_formatting_negative_duration() {
        // Test negative duration protection (clock skew)
        let duration = Duration::minutes(-100);
        let formatted = format_uptime(duration);
        assert_eq!(formatted, "0 minutes"); // Clamps to zero
    }

    #[test]
    fn test_uptime_formatting_zero_duration() {
        // Test zero duration
        let duration = Duration::zero();
        let formatted = format_uptime(duration);
        assert_eq!(formatted, "0 minutes");
    }

    // ========== OpSec Reminder Generation Tests (Story 7.3) ==========

    #[test]
    fn test_opsec_reminders_less_than_6_hours() {
        // Test <6 hours → no reminders
        let uptime = Duration::hours(5);
        let reminders = generate_opsec_reminders(uptime, true);
        assert_eq!(reminders.len(), 0);
    }

    #[test]
    fn test_opsec_reminders_exactly_6_hours() {
        // Test 6+ hours → Info reminder
        let uptime = Duration::hours(6);
        let reminders = generate_opsec_reminders(uptime, true);
        assert_eq!(reminders.len(), 1);
        assert_eq!(reminders[0].severity, ReminderSeverity::Info);
        assert!(
            reminders[0]
                .message
                .contains("Consider taking breaks for operational security")
        );
    }

    #[test]
    fn test_opsec_reminders_12_hours() {
        // Test 12+ hours → Info + Warning reminders (cumulative)
        let uptime = Duration::hours(12);
        let reminders = generate_opsec_reminders(uptime, true);
        assert_eq!(reminders.len(), 2);
        assert_eq!(reminders[0].severity, ReminderSeverity::Info);
        assert_eq!(reminders[1].severity, ReminderSeverity::Warning);
    }

    #[test]
    fn test_opsec_reminders_24_hours() {
        // Test 24+ hours → All three reminders (cumulative)
        let uptime = Duration::hours(26);
        let reminders = generate_opsec_reminders(uptime, true);
        assert_eq!(reminders.len(), 3);
        assert_eq!(reminders[0].severity, ReminderSeverity::Info);
        assert_eq!(reminders[1].severity, ReminderSeverity::Warning);
        assert_eq!(reminders[2].severity, ReminderSeverity::Critical);
    }

    #[test]
    fn test_opsec_reminders_disabled() {
        // Test with show_opsec_reminders = false → no reminders
        let uptime = Duration::hours(26);
        let reminders = generate_opsec_reminders(uptime, false);
        assert_eq!(reminders.len(), 0);
    }

    // ========== OpSec Reminder Struct Tests (Story 7.3) ==========

    #[test]
    fn test_opsec_reminder_display_info() {
        let reminder = OpSecReminder {
            severity: ReminderSeverity::Info,
            message: "Test message".to_string(),
        };
        let display = format!("{}", reminder);
        assert!(display.contains('💡')); // Info uses lightbulb emoji
        assert!(display.contains("Test message"));
    }

    #[test]
    fn test_opsec_reminder_display_warning() {
        let reminder = OpSecReminder {
            severity: ReminderSeverity::Warning,
            message: "Warning message".to_string(),
        };
        let display = format!("{}", reminder);
        assert!(display.contains('⚠')); // Warning uses warning triangle
        assert!(display.contains("Warning message"));
    }

    #[test]
    fn test_opsec_reminder_display_critical() {
        let reminder = OpSecReminder {
            severity: ReminderSeverity::Critical,
            message: "Critical message".to_string(),
        };
        let display = format!("{}", reminder);
        assert!(display.contains('🛑')); // Critical uses stop sign
        assert!(display.contains("Critical message"));
    }

    #[test]
    fn test_opsec_reminder_to_plain() {
        let reminder = OpSecReminder {
            severity: ReminderSeverity::Critical,
            message: "Session >24 hours".to_string(),
        };
        let plain = reminder.to_plain();
        assert!(!plain.contains('⚠')); // No emoji
        assert!(plain.contains("[CRITICAL]"));
        assert!(plain.contains("Session >24 hours"));
    }

    #[test]
    fn test_opsec_reminder_serialization() {
        let reminder = OpSecReminder {
            severity: ReminderSeverity::Warning,
            message: "Test".to_string(),
        };

        let json = serde_json::to_string(&reminder).unwrap();
        let deserialized: OpSecReminder = serde_json::from_str(&json).unwrap();

        assert_eq!(reminder, deserialized);
    }

    // ========== ReminderSeverity Tests (Story 7.3) ==========

    #[test]
    fn test_reminder_severity_display() {
        assert_eq!(format!("{}", ReminderSeverity::Info), "INFO");
        assert_eq!(format!("{}", ReminderSeverity::Warning), "WARNING");
        assert_eq!(format!("{}", ReminderSeverity::Critical), "CRITICAL");
    }

    #[test]
    fn test_reminder_severity_to_plain() {
        assert_eq!(ReminderSeverity::Info.to_plain(), "[INFO]");
        assert_eq!(ReminderSeverity::Warning.to_plain(), "[WARNING]");
        assert_eq!(ReminderSeverity::Critical.to_plain(), "[CRITICAL]");
    }

    // ========== Integration Tests (Story 7.3) ==========

    #[test]
    fn test_status_command_includes_formatted_uptime() {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let activated_at = Utc::now() - chrono::Duration::hours(3) - chrono::Duration::minutes(30);

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at,
                overlays: vec![],
            },
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        assert_eq!(report.formatted_uptime, "3 hours 30 minutes");
        assert!(report.uptime.is_some());
    }

    #[test]
    fn test_status_command_includes_opsec_reminders_when_enabled() {
        let fs = MockFilesystem::new();
        let config = Config::default(); // show_opsec_reminders = true by default
        let activated_at = Utc::now() - chrono::Duration::hours(26);

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at,
                overlays: vec![],
            },
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        assert_eq!(report.opsec_reminders.len(), 3); // All three reminders
        assert_eq!(report.opsec_reminders[0].severity, ReminderSeverity::Info);
        assert_eq!(
            report.opsec_reminders[1].severity,
            ReminderSeverity::Warning
        );
        assert_eq!(
            report.opsec_reminders[2].severity,
            ReminderSeverity::Critical
        );
    }

    #[test]
    fn test_status_command_suppresses_opsec_reminders_when_disabled() {
        let fs = MockFilesystem::new();
        let config = Config {
            show_opsec_reminders: false,
            ..Config::default()
        };
        let activated_at = Utc::now() - chrono::Duration::hours(26);

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at,
                overlays: vec![],
            },
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        assert_eq!(report.opsec_reminders.len(), 0); // No reminders when disabled
    }

    #[test]
    fn test_status_command_no_reminders_for_short_uptime() {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let activated_at = Utc::now() - chrono::Duration::hours(3); // Only 3 hours

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at,
                overlays: vec![],
            },
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        assert_eq!(report.opsec_reminders.len(), 0); // No reminders for <6 hours
        assert_eq!(report.formatted_uptime, "3 hours");
    }

    #[test]
    fn test_status_command_inactive_has_empty_uptime() {
        let fs = MockFilesystem::new();
        let config = Config::default();

        let state_file = StateFile {
            state: SystemState::Inactive,
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        assert_eq!(report.formatted_uptime, "");
        assert!(report.uptime.is_none());
        assert_eq!(report.opsec_reminders.len(), 0);
    }

    // ========== Code Review Fixes: Additional Test Coverage ==========

    #[test]
    fn test_uptime_calculation_handles_future_timestamp() {
        // Bug fix: Handle clock skew where activated_at is in the future
        let fs = MockFilesystem::new();
        let config = Config::default();
        let future_time = Utc::now() + chrono::Duration::hours(1); // 1 hour in future

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at: future_time,
                overlays: vec![],
            },
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        // Should return None for future timestamps (clock skew protection)
        assert!(report.uptime.is_none());
        assert_eq!(report.formatted_uptime, "");
        assert_eq!(report.opsec_reminders.len(), 0);
    }

    #[test]
    fn test_verification_detects_active_overlays_missing_from_overlay_status() {
        // Bug fix: Detect when Active.overlays contains paths not in overlay_status
        let fs = MockFilesystem::new();
        fs.mock_set_mounted(Path::new("/home"), true);

        let config = Config::default();
        let activated_at = Utc::now();
        let overlays = vec![PathBuf::from("/home"), PathBuf::from("/etc")];

        let mut overlay_status = std::collections::HashMap::new();
        overlay_status.insert(PathBuf::from("/home"), create_overlay_info("/home"));
        // Missing /etc in overlay_status!

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at,
                overlays: overlays.clone(),
            },
            overlay_status,
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        // Should detect the mismatch
        match report.overlay_verification {
            VerificationStatus::Mismatch { errors } => {
                assert!(
                    errors.iter().any(|e| e.contains("/etc")
                        && e.contains("missing from overlay_status tracking"))
                );
            }
            _ => panic!("Expected Mismatch verification status"),
        }
    }

    #[test]
    fn test_verification_detects_overlay_status_not_in_active_overlays() {
        // Bug fix: Detect when overlay_status has entries not in Active.overlays
        let fs = MockFilesystem::new();
        fs.mock_set_mounted(Path::new("/home"), true);
        fs.mock_set_mounted(Path::new("/var"), true);

        let config = Config::default();
        let activated_at = Utc::now();
        let overlays = vec![PathBuf::from("/home")]; // Only /home in Active

        let mut overlay_status = std::collections::HashMap::new();
        overlay_status.insert(PathBuf::from("/home"), create_overlay_info("/home"));
        overlay_status.insert(PathBuf::from("/var"), create_overlay_info("/var")); // Extra!

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at,
                overlays: overlays.clone(),
            },
            overlay_status,
            ..StateFile::default()
        };
        let temp_file = create_temp_state_file(&state_file);

        let cmd = StatusCommand::new(fs, config, temp_file.path().to_path_buf());
        let report = cmd.run().unwrap();

        // Should detect the mismatch
        match report.overlay_verification {
            VerificationStatus::Mismatch { errors } => {
                assert!(
                    errors
                        .iter()
                        .any(|e| e.contains("/var") && e.contains("not listed in Active state"))
                );
            }
            _ => panic!("Expected Mismatch verification status"),
        }
    }
}
