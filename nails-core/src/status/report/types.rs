//! Status report types: VerificationStatus, SecurityPosture, StatusReport

use super::OpSecReminder;
use crate::config::PersonaMode;
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
/// system state and overlay verification, with a mark from the shared table
/// for at-a-glance assessment.
///
/// # Variants
///
/// - **Secure** (✓, green): Hidden environment active, overlays verified
/// - **Warning** (⚠, yellow): Transitional state or overlay inconsistency detected
/// - **Decoy** (○, uncoloured): Inactive; the decoy system is in use
/// - **Critical** (✗, red): Emergency or degraded state
///
/// # Example
///
/// ```
/// use nails_core::status::SecurityPosture;
///
/// let posture = SecurityPosture::Secure;
/// assert_eq!(format!("{}", posture), "✓ SECURE: Hidden environment active, overlays verified");
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
    /// The shared mark for this posture.
    ///
    /// The decoy state is neither protected nor in trouble, so it gets the
    /// neutral mark; only a critical posture is shown as a failure.
    pub fn mark(&self) -> crate::output::Mark {
        use crate::output::Mark;
        match self {
            SecurityPosture::Secure => Mark::Pass,
            SecurityPosture::Warning => Mark::Warn,
            SecurityPosture::Decoy => Mark::Neutral,
            SecurityPosture::Critical => Mark::Fail,
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

    /// Render the posture in `style`: the level label in brackets for ASCII
    /// output, otherwise the (possibly coloured) shared mark.
    pub fn render(&self, style: crate::output::Style) -> String {
        if style.ascii {
            self.to_plain()
        } else {
            format!(
                "{} {}: {}",
                style.mark(self.mark()),
                self.level(),
                self.description()
            )
        }
    }
}

impl fmt::Display for SecurityPosture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render(crate::output::Style::default()))
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

    /// Total size of the hidden volume's filesystem in bytes.
    ///
    /// All three `hidden_root_*` figures come from one `statvfs` call on the
    /// hidden volume root; the status path never walks directories to compute
    /// them. They are `None` when that call failed (for example the root is not
    /// mounted), so an unreadable figure leaves the rest of the report truthful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hidden_root_total: Option<u64>,

    /// Bytes in use on the hidden volume (`total - available`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hidden_root_used: Option<u64>,

    /// Bytes available on the hidden volume.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hidden_root_available: Option<u64>,

    /// How the state file was loaded (P1-03: unified load outcome)
    #[serde(skip, default = "default_load_outcome")]
    pub load_outcome: LoadOutcome,

    /// The configured persona mode (how the hidden session relates to the decoy
    /// account). Reported so an operator can confirm whether the decoy home is
    /// shared or hidden.
    #[serde(default)]
    pub persona_mode: PersonaMode,
}

fn default_load_outcome() -> LoadOutcome {
    LoadOutcome::Missing
}

impl StatusReport {
    /// Calculate security posture from state and verification
    ///
    /// # Returns
    ///
    /// - **Secure**: Active state with verified overlays
    /// - **Warning**: Active state with mismatched overlays, or transitional state
    /// - **Decoy**: Inactive state (normal decoy environment)
    /// - **Critical**: Degraded state requiring immediate attention
    pub fn security_posture(&self) -> SecurityPosture {
        match (&self.state, &self.overlay_verification) {
            (SystemState::Active { .. }, VerificationStatus::Verified) => SecurityPosture::Secure,
            (SystemState::Active { .. }, VerificationStatus::Mismatch { .. }) => {
                SecurityPosture::Warning
            }
            (SystemState::Activating { .. }, _) => SecurityPosture::Warning,
            (SystemState::Deactivating { .. }, _) => SecurityPosture::Warning,
            (SystemState::Inactive, _) => SecurityPosture::Decoy,
            (SystemState::Degraded { .. }, _) => SecurityPosture::Critical,
            // Fallback for edge cases (e.g., Active with Skipped/NotApplicable verification)
            _ => SecurityPosture::Warning,
        }
    }
}
