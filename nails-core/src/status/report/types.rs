//! Status report types: VerificationStatus, SecurityPosture, StatusReport

use super::OpSecReminder;
use crate::{LoadOutcome, SystemState};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

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
    Secure,

    /// System is in transitional state or has inconsistencies
    Warning,

    /// System is in decoy mode (inactive state)
    Decoy,

    /// System is in emergency state requiring immediate attention
    Critical,
}

impl SecurityPosture {
    /// Get the emoji indicator for this security posture
    fn emoji(&self) -> &'static str {
        match self {
            SecurityPosture::Secure => "\u{1f7e2}",
            SecurityPosture::Warning => "\u{1f7e1}",
            SecurityPosture::Decoy => "\u{1f534}",
            SecurityPosture::Critical => "\u{1f534}",
        }
    }

    /// Get the text level indicator
    fn level(&self) -> &'static str {
        match self {
            SecurityPosture::Secure => "SECURE",
            SecurityPosture::Warning => "WARNING",
            SecurityPosture::Decoy => "DECOY",
            SecurityPosture::Critical => "CRITICAL",
        }
    }

    /// Get the descriptive message for this security posture
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

/// Per-overlay mount status for status display
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

    /// How the state file was loaded (P1-03: unified load outcome)
    #[serde(skip, default = "default_load_outcome")]
    pub load_outcome: LoadOutcome,
}

fn default_load_outcome() -> LoadOutcome {
    LoadOutcome::FreshDefault
}

impl StatusReport {
    /// Calculate security posture from state and verification
    ///
    /// # Returns
    ///
    /// - **Secure**: Active state with verified overlays
    /// - **Warning**: Active state with mismatched overlays, or transitional state
    /// - **Decoy**: Inactive state (normal decoy environment)
    /// - **Critical**: Emergency state requiring immediate attention
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
