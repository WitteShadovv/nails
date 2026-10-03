//! Status report types: VerificationStatus, Posture, StatusReport

use super::OpSecReminder;
use crate::config::PersonaMode;
use crate::state::{DegradedKind, EffectiveState};
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

/// What the kernel actually has mounted, as a single at-a-glance verdict.
///
/// Unlike the old state-trusting posture, this is derived from the reconciled
/// [`EffectiveState`] (state file vs. boot id vs. the live NAILS mount table), so
/// it never reports `decoy` while hidden overlays are still serving data. The two
/// dangerous postures (`degraded`, `inconsistent`) and `unknown` fail closed.
///
/// # Variants
///
/// - **Decoy** (○, uncoloured): no hidden environment is mounted; the decoy is in use
/// - **Active** (✓, green): hidden environment active, every overlay verified against the kernel
/// - **Degraded** (✗, red): active but overlays are missing — hidden writes may reach the decoy disk
/// - **Inconsistent** (✗, red): NAILS overlays are mounted while the state is not active
/// - **Unknown** (⚠, yellow): the state file could not be read, so the real state is unknown
///
/// # Example
///
/// ```
/// use nails_core::status::Posture;
///
/// let posture = Posture::Active;
/// assert_eq!(posture.to_plain(), "[ACTIVE] Hidden environment active, all overlays verified");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Posture {
    /// No hidden environment is mounted; the decoy system is in use.
    Decoy,
    /// Hidden environment active and every tracked overlay is verified.
    Active,
    /// A NAILS activation or deactivation is in progress: the persisted state is
    /// transitional and its owner process is still alive. A benign, transient
    /// condition, distinct from a crashed transition whose owner is gone.
    Transitioning,
    /// Active but one or more overlays are missing from the kernel.
    Degraded,
    /// NAILS overlays are mounted while the persisted state is not active.
    Inconsistent,
    /// The state file could not be read or trusted; the real state is unknown.
    Unknown,
}

impl Posture {
    /// Collapse a reconciled [`EffectiveState`] into a posture.
    ///
    /// `live_mounts` is whether the kernel mount table still carries any
    /// NAILS-owned mount; it only matters for a stale-from-previous-boot file,
    /// which is otherwise the decoy but must read as inconsistent if (improbably)
    /// mounts are still live.
    pub fn from_effective(effective: &EffectiveState, live_mounts: bool) -> Self {
        match effective {
            EffectiveState::Inactive => Posture::Decoy,
            EffectiveState::VerifiedActive { .. } => Posture::Active,
            EffectiveState::Degraded { kind, .. } => match kind {
                DegradedKind::ActiveOverlaysMissing => Posture::Degraded,
                DegradedKind::InactiveMountsLive => Posture::Inconsistent,
            },
            // A transition whose owner process is still alive is genuinely in
            // progress, not a crash: report it as transitional (a safe, transient
            // posture). Only an interrupted transition whose owner is gone is the
            // dangerous, must-recover case.
            EffectiveState::Interrupted { owner_alive, .. } => {
                if *owner_alive {
                    Posture::Transitioning
                } else {
                    Posture::Inconsistent
                }
            }
            EffectiveState::StaleFromPreviousBoot => {
                if live_mounts {
                    Posture::Inconsistent
                } else {
                    Posture::Decoy
                }
            }
            EffectiveState::Unknown => Posture::Unknown,
        }
    }

    /// Whether this posture is a safe, expected outcome (exit 0). The dangerous
    /// and unknown postures all fail closed.
    pub fn is_safe(&self) -> bool {
        matches!(
            self,
            Posture::Decoy | Posture::Active | Posture::Transitioning
        )
    }

    /// The shared mark for this posture.
    ///
    /// Decoy is neutral (neither protected nor at risk). Active passes. The two
    /// dangerous postures fail; an unknown state is a warning.
    pub fn mark(&self) -> crate::output::Mark {
        use crate::output::Mark;
        match self {
            Posture::Decoy => Mark::Neutral,
            Posture::Active => Mark::Pass,
            Posture::Transitioning => Mark::Neutral,
            Posture::Degraded | Posture::Inconsistent => Mark::Fail,
            Posture::Unknown => Mark::Warn,
        }
    }

    /// The uppercase level label.
    pub fn level(&self) -> &'static str {
        match self {
            Posture::Decoy => "DECOY",
            Posture::Active => "ACTIVE",
            Posture::Transitioning => "TRANSITIONING",
            Posture::Degraded => "DEGRADED",
            Posture::Inconsistent => "INCONSISTENT",
            Posture::Unknown => "UNKNOWN",
        }
    }

    /// The stable `snake_case` label used in machine-readable output.
    pub fn as_str(&self) -> &'static str {
        match self {
            Posture::Decoy => "decoy",
            Posture::Active => "active",
            Posture::Transitioning => "transitioning",
            Posture::Degraded => "degraded",
            Posture::Inconsistent => "inconsistent",
            Posture::Unknown => "unknown",
        }
    }

    /// A one-line description of what the posture means.
    fn description(&self) -> &'static str {
        match self {
            Posture::Decoy => "Decoy system in use - no hidden environment mounted",
            Posture::Active => "Hidden environment active, all overlays verified",
            Posture::Transitioning => "A NAILS activation or deactivation is in progress",
            Posture::Degraded => {
                "Active but overlays are missing - hidden writes may reach the decoy disk"
            }
            Posture::Inconsistent => "NAILS overlays are mounted but the state is not active",
            Posture::Unknown => "State file could not be read - the real state is unknown",
        }
    }

    /// The remediation step for a dangerous or unknown posture, or `None` when
    /// the system is in a safe state.
    pub fn remediation(&self) -> Option<&'static str> {
        match self {
            Posture::Decoy | Posture::Active | Posture::Transitioning => None,
            Posture::Degraded | Posture::Inconsistent => {
                Some("Run `nails emergency` to tear down the remaining NAILS mounts")
            }
            Posture::Unknown => {
                Some("Run `nails emergency` and recover the hidden volume before activating again")
            }
        }
    }

    /// ASCII-only representation for plain output mode.
    ///
    /// # Example
    ///
    /// ```
    /// use nails_core::status::Posture;
    ///
    /// let posture = Posture::Decoy;
    /// assert_eq!(
    ///     posture.to_plain(),
    ///     "[DECOY] Decoy system in use - no hidden environment mounted"
    /// );
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

impl fmt::Display for Posture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render(crate::output::Style::default()))
    }
}

/// Per-overlay identity and verification for status display.
///
/// `owned` is the real verdict: it comes from the live NAILS mount table
/// ([`NailsMounts::is_owned`](crate::filesystem::NailsMounts::is_owned)), so a
/// plain foreign mount at an overlay target (an ext4 `/home`) reads as not owned,
/// never as a verified overlay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverlayMountStatus {
    /// The overlay mount path.
    pub path: PathBuf,
    /// Whether the overlay should be mounted based on state.
    pub expected_mounted: bool,
    /// Whether an actual NAILS overlay is mounted here (i.e. it is owned).
    pub actually_mounted: bool,
    /// Whether the live mount table says NAILS created this mount.
    pub owned: bool,
    /// The overlay's upper directory, from the state file (or a live probe).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upperdir: Option<PathBuf>,
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

    /// The posture derived from reconciling the state file against the kernel
    /// mount table. This, not `state`, is the truthful verdict a caller acts on.
    pub posture: Posture,

    /// NAILS-owned mounts still live that a dangerous posture must account for
    /// (recovery tears these down). Empty for a safe posture.
    pub remaining_mounts: Vec<PathBuf>,

    /// List of overlay paths (empty for inactive/transitional states)
    pub overlays: Vec<PathBuf>,

    /// Overlay verification result
    pub overlay_verification: VerificationStatus,

    /// Store path of the hidden NixOS system toplevel switched to on the last
    /// successful activation (if available).
    pub hidden_toplevel: Option<String>,

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

    /// Per-overlay mount status
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
    /// The posture this report carries. Computed once in
    /// [`StatusCommand::run`](crate::StatusCommand::run) from the reconciled
    /// effective state, then stored, because deriving it needs the live mount
    /// table the command holds.
    pub fn posture(&self) -> Posture {
        self.posture
    }

    /// Writers that still referenced the decoy when the hidden environment was
    /// activated (empty unless the state is Active).
    ///
    /// This is the activation-time set: the processes activation deliberately did
    /// not restart, which keep writing to the decoy for as long as they run.
    pub fn decoy_writers(&self) -> &[crate::DecoyWriter] {
        match &self.state {
            SystemState::Active { decoy_writers, .. } => decoy_writers,
            _ => &[],
        }
    }
}
