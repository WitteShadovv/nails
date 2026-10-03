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
//! - **[`Posture`]**: The kernel-truth verdict (decoy/active/degraded/inconsistent/unknown)
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
//! println!("Posture: {}", report.posture());
//! # Ok::<(), nails_core::NailsError>(())
//! ```
//!
//! # Requirements
//!
//! - Status command
//! - Overlay verification
//! - Track current state
//! - Track timestamp
//! - Track overlay status
//! - Status always succeeds (even on verification failure)
//! - State verification (overlays match reality)
//! - Status <500ms

use crate::state::{EffectiveState, reconcile};
use crate::{Config, Filesystem, LoadOutcome, Result, StateFile, SystemState};
use chrono::{DateTime, Duration, Utc};
use std::path::{Path, PathBuf};

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
    OpSecReminder, OverlayMountStatus, Posture, ReminderSeverity, StatusReport, VerificationStatus,
    format_uptime, generate_opsec_reminders,
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
        // Load state file with outcome metadata.
        let load_result = StateFile::load_with_outcome(&self.state_file_path)?;
        let state_file = load_result.state_file;
        let load_outcome = load_result.outcome;

        tracing::debug!(state = ?state_file.state, phase = "status", "Status query executed");

        // Ask the kernel what NAILS actually has mounted, independent of the
        // state file. A failed read degrades to "no NAILS mounts", which keeps
        // reconciliation fail-closed (an Active state then reads as degraded
        // rather than trusting an unreadable table). This never writes.
        let mounts = self
            .filesystem
            .discover_nails_mounts(Some(&self.config.hidden_volume_root))
            .unwrap_or_default();

        // Reconcile the persisted state against the boot id, the owner process
        // and the live mount table, then collapse it into a single posture. This
        // uses the pure reconcile(), not the manager wrapper, because the wrapper
        // resets and persists stale state and status must stay read-only.
        let boot_id = crate::state::read_boot_id();
        let owner_alive = pid_is_alive(state_file.owner_pid);
        let effective = reconcile(
            &state_file,
            &load_outcome,
            &mounts,
            boot_id.as_deref(),
            owner_alive,
        );
        let live_points = mounts.owned_mount_points();
        let posture = Posture::from_effective(&effective, !live_points.is_empty());

        tracing::debug!(
            posture = posture.as_str(),
            phase = "status",
            "Reconciled posture computed"
        );

        // Extract data from state file
        let (overlays, activated_at) = match &state_file.state {
            SystemState::Inactive => (vec![], None),
            SystemState::Active {
                activated_at,
                overlays,
                ..
            } => (overlays.clone(), Some(*activated_at)),
            SystemState::Activating { .. }
            | SystemState::Deactivating { .. }
            | SystemState::Degraded { .. } => (vec![], None),
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

        // Include overlay details for Active state (used by verbose mode)
        let overlay_details = match &state_file.state {
            SystemState::Active { .. } if !state_file.overlay_status.is_empty() => {
                Some(state_file.overlay_status.clone())
            }
            _ => None,
        };

        // Build per-overlay identities for an Active state, judging each overlay
        // by whether the kernel says NAILS owns it — an actual overlay with its
        // upperdir under the hidden root — not merely that *something* is mounted
        // there. A plain foreign mount (an ext4 `/home`) is therefore never
        // reported as a verified overlay.
        let overlay_mount_statuses = match &state_file.state {
            SystemState::Active { overlays, .. } => overlays
                .iter()
                .map(|overlay_path| {
                    let owned = mounts.is_owned(&canonical_or_self(overlay_path));
                    let upperdir = state_file
                        .overlay_status
                        .get(overlay_path)
                        .map(|info| info.upper_dir.clone())
                        .or_else(|| {
                            self.filesystem
                                .get_mount_info(overlay_path)
                                .map(|info| info.upper)
                        });
                    OverlayMountStatus {
                        path: overlay_path.clone(),
                        expected_mounted: true,
                        actually_mounted: owned,
                        owned,
                        upperdir,
                    }
                })
                .collect(),
            _ => vec![],
        };

        let overlay_verification = verification_from(&effective, &overlay_mount_statuses);

        tracing::debug!(
            verification_result = ?overlay_verification,
            phase = "status",
            "Overlay verification performed"
        );

        // Mounts a dangerous posture must account for: what recovery tears down.
        let remaining_mounts = match &effective {
            EffectiveState::Degraded { remaining, .. } => remaining.clone(),
            EffectiveState::Interrupted { .. } | EffectiveState::StaleFromPreviousBoot => {
                if posture == Posture::Decoy {
                    Vec::new()
                } else {
                    live_points.clone()
                }
            }
            _ => Vec::new(),
        };

        // Report hidden-root disk usage from a single statvfs call. This never
        // walks directories, and a failed call (e.g. the root is not mounted)
        // leaves the figures as None so the rest of the report stays truthful.
        let (hidden_root_total, hidden_root_used, hidden_root_available) =
            match self.filesystem.disk_usage(&self.config.hidden_volume_root) {
                Ok(usage) => (Some(usage.total), Some(usage.used()), Some(usage.available)),
                Err(_) => (None, None, None),
            };

        // Read the typed platform section before moving `state` out of the file,
        // so both are `Some` only on NixOS; the status surface therefore shows the
        // hidden-system generation on NixOS alone.
        let hidden_toplevel = state_file.hidden_toplevel().map(str::to_string);
        let last_switch_warning = state_file.last_switch_warning().map(str::to_string);

        // Whether the hidden root is still a live mount. Expected while active;
        // in the Decoy posture it is the signature of an emergency teardown that
        // did not close the backend, which the CLI reports as Critical.
        let hidden_root_mounted = self
            .filesystem
            .is_mounted(&self.config.hidden_volume_root)
            .unwrap_or(false);

        // Build report
        let report = StatusReport {
            state: state_file.state,
            posture,
            remaining_mounts,
            overlays,
            overlay_verification,
            hidden_toplevel,
            last_switch_warning,
            activated_at,
            uptime,
            formatted_uptime,
            opsec_reminders,
            overlay_details,
            overlay_mount_statuses,
            hidden_root_total,
            hidden_root_used,
            hidden_root_available,
            hidden_root_mounted,
            load_outcome,
            persona_mode: self.config.persona.mode,
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
}

/// Whether a recorded owner pid is still a live process.
///
/// Reconciliation only consults this for a transitional state left behind within
/// the current boot, to tell an in-flight operation from a crashed one. A pid of
/// `0` is the "unset" sentinel and is never alive. Status reads `/proc` directly
/// (not through the filesystem trait); tests drive the outcome through
/// `test_boot_id` and the reconcile logic, which is itself unit-tested as a pure
/// function, rather than through this probe.
fn pid_is_alive(pid: u32) -> bool {
    pid != 0 && Path::new(&format!("/proc/{pid}")).exists()
}

/// Canonicalize `path` for an ownership lookup, falling back to the path itself
/// when it cannot be resolved (it may not exist in a test, and mountinfo paths
/// are already canonical in production).
fn canonical_or_self(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Derive the overlay verification result from the reconciled effective state and
/// the per-overlay ownership judged against the live mount table.
///
/// This replaces trusting `state.json`: an overlay counts as verified only when
/// the kernel says NAILS owns it, so a foreign mount at an overlay target reads
/// as a mismatch, never as verified.
fn verification_from(
    effective: &EffectiveState,
    overlays: &[OverlayMountStatus],
) -> VerificationStatus {
    match effective {
        EffectiveState::VerifiedActive { .. } => VerificationStatus::Verified,
        EffectiveState::Degraded {
            kind: crate::state::DegradedKind::ActiveOverlaysMissing,
            ..
        } => {
            let errors: Vec<String> = overlays
                .iter()
                .filter(|status| !status.owned)
                .map(|status| {
                    format!(
                        "{} is not mounted as a NAILS overlay",
                        status.path.display()
                    )
                })
                .collect();
            if errors.is_empty() {
                VerificationStatus::Skipped
            } else {
                VerificationStatus::Mismatch { errors }
            }
        }
        EffectiveState::Inactive => VerificationStatus::NotApplicable,
        EffectiveState::Degraded { .. }
        | EffectiveState::Interrupted { .. }
        | EffectiveState::StaleFromPreviousBoot
        | EffectiveState::Unknown => VerificationStatus::Skipped,
    }
}

impl Default for StatusReport {
    fn default() -> Self {
        Self {
            state: SystemState::Inactive,
            posture: Posture::Decoy,
            remaining_mounts: vec![],
            overlays: vec![],
            overlay_verification: VerificationStatus::NotApplicable,
            hidden_toplevel: None,
            last_switch_warning: None,
            activated_at: None,
            uptime: None,
            formatted_uptime: String::new(),
            opsec_reminders: vec![],
            overlay_details: None,
            overlay_mount_statuses: vec![],
            hidden_root_total: None,
            hidden_root_used: None,
            hidden_root_available: None,
            hidden_root_mounted: false,
            load_outcome: LoadOutcome::Missing,
            persona_mode: crate::config::PersonaMode::SharedHome,
        }
    }
}

#[cfg(test)]
mod tests;
