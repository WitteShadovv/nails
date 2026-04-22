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
//! let state_file_path = PathBuf::from("/mnt/hidden-volume/state.json");
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

use crate::{Config, Filesystem, LoadOutcome, Result, StateFile, SystemState};
use chrono::{DateTime, Duration, Utc};
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
pub mod report;

// Re-export report types
pub use report::{
    OpSecReminder, OverlayMountStatus, ReminderSeverity, SecurityPosture, StatusReport,
    VerificationStatus, format_uptime, generate_opsec_reminders,
};

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
    ///     PathBuf::from("/mnt/hidden-volume/state.json"),
    /// );
    ///
    /// let report = cmd.run()?;
    /// println!("System state: {:?}", report.state);
    /// println!("Uptime: {}", report.formatted_uptime);
    /// println!("Reminders: {:?}", report.opsec_reminders);
    /// # Ok::<(), nails_core::NailsError>(())
    /// ```
    pub fn run(&self) -> Result<StatusReport> {
        // Load state file with outcome metadata (P1-03)
        let load_result = StateFile::load_with_outcome(&self.state_file_path)?;
        let state_file = load_result.state_file;
        let load_outcome = load_result.outcome;

        tracing::debug!(state = ?state_file.state, phase = "status", "Status query executed");

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

        tracing::debug!(
            verification_result = ?overlay_verification,
            phase = "status",
            "Overlay verification performed"
        );

        // Include overlay details for Active state (used by verbose mode)
        let overlay_details = match &state_file.state {
            SystemState::Active { .. } if !state_file.overlay_status.is_empty() => {
                Some(state_file.overlay_status.clone())
            }
            _ => None,
        };

        // Build per-overlay mount statuses for Active state
        let overlay_mount_statuses = match &state_file.state {
            SystemState::Active { overlays, .. } => {
                let mut statuses = Vec::new();
                for overlay_path in overlays {
                    if let Some(overlay_info) = state_file.overlay_status.get(overlay_path) {
                        let actually_mounted = self
                            .filesystem
                            .is_mounted(&overlay_info.mount_path)
                            .unwrap_or(false);
                        statuses.push(OverlayMountStatus {
                            path: overlay_path.clone(),
                            expected_mounted: true,
                            actually_mounted,
                        });
                    }
                }
                statuses
            }
            _ => vec![],
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
            overlay_mount_statuses,
            load_outcome,
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
            overlay_mount_statuses: vec![],
            load_outcome: LoadOutcome::FreshDefault,
        }
    }
}

#[cfg(test)]
mod tests;
