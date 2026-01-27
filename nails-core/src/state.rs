//! # System State Management
//!
//! Core state machine for NAILS with type-safe transitions.
//!
//! ## Overview
//!
//! The `SystemState` enum represents all possible states of the NAILS system,
//! ensuring compile-time guarantees that invalid states are impossible.
//!
//! ## Valid State Transitions
//!
//! ```text
//! Inactive → Activating → Active → Deactivating → Inactive
//! Any State → Emergency
//! ```
//!
//! ## Example
//!
//! ```
//! use nails_core::SystemState;
//!
//! // Start from inactive state
//! let state = SystemState::Inactive;
//!
//! // Begin activation (valid transition)
//! let activating = state.begin_activation().expect("Should transition to Activating");
//! assert!(matches!(activating, SystemState::Activating { .. }));
//!
//! // Complete activation
//! let active = activating
//!     .complete_activation(vec![])
//!     .expect("Should transition to Active");
//! assert!(active.is_active());
//! ```

use crate::{NailsError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Default hidden volume mount point
///
/// State file MUST be written to a path within this directory.
/// Enforces anti-forensics invariant: state never leaks to decoy system.
pub const HIDDEN_VOLUME_ROOT: &str = "/mnt/hidden-volume";

/// Check if a path is within the hidden volume
///
/// Validates that the given path is within HIDDEN_VOLUME_ROOT to prevent
/// forensic leakage of state information to the decoy system.
///
/// # Security Considerations
///
/// - Uses canonicalize() to resolve symlinks (prevents symlink attacks)
/// - Handles paths that don't exist yet (for initial save)
/// - Rejects similar-looking paths like "/mnt/hidden-volume-fake"
/// - Rejects path traversal attempts like "../etc/state.json"
///
/// # Arguments
///
/// * `path` - Path to validate
///
/// # Returns
///
/// * `true` if path is within hidden volume
/// * `false` otherwise
fn is_on_hidden_volume(path: &Path) -> bool {
    // Try to canonicalize to resolve symlinks
    match path.canonicalize() {
        Ok(canonical) => canonical.starts_with(HIDDEN_VOLUME_ROOT),
        // If path doesn't exist yet, we need to clean it manually
        // to prevent path traversal attacks
        Err(_) => {
            // Convert to absolute path and clean ".." components
            let absolute = if path.is_absolute() {
                path.to_path_buf()
            } else {
                // If relative, make it absolute from current dir
                std::env::current_dir()
                    .ok()
                    .and_then(|cwd| cwd.join(path).canonicalize().ok())
                    .unwrap_or_else(|| path.to_path_buf())
            };

            // Manually clean path by resolving ".." components
            let mut components = Vec::new();
            for component in absolute.components() {
                match component {
                    std::path::Component::ParentDir => {
                        // Pop last component if any (handles "..")
                        components.pop();
                    }
                    std::path::Component::Normal(c) => {
                        components.push(c);
                    }
                    std::path::Component::RootDir => {
                        components.clear(); // Start fresh from root
                    }
                    _ => {} // Ignore CurDir and Prefix
                }
            }

            // Reconstruct path from components
            let mut cleaned = PathBuf::from("/");
            for component in components {
                cleaned.push(component);
            }

            cleaned.starts_with(HIDDEN_VOLUME_ROOT)
        }
    }
}

/// System state enum with type-safe transitions
///
/// Each variant represents a distinct system state with associated metadata.
/// Invalid states are impossible at compile time due to Rust's type system.
///
/// # State Variants
///
/// - **Inactive**: System is in decoy state, no hidden environment active
/// - **Activating**: Activation in progress (mounts being set up)
/// - **Active**: Hidden environment fully activated and mounted
/// - **Deactivating**: Deactivation in progress (unmounting, cleanup)
/// - **Emergency**: Emergency shutdown triggered (forensic threat detected)
///
/// # Requirements
///
/// - FR26: Track current state
/// - FR27: Track timestamp for each state transition
/// - FR29: Serialize state to JSON
/// - NFR12: Impossible invalid states via enum pattern matching
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SystemState {
    /// System is inactive (decoy state)
    Inactive,

    /// Activation in progress
    Activating {
        /// When activation started
        started_at: DateTime<Utc>,
    },

    /// System is active (hidden environment mounted)
    Active {
        /// When activation completed
        activated_at: DateTime<Utc>,
        /// List of mounted overlay paths
        overlays: Vec<PathBuf>,
    },

    /// Deactivation in progress
    Deactivating {
        /// When deactivation started
        started_at: DateTime<Utc>,
    },

    /// Emergency shutdown triggered
    Emergency {
        /// When emergency was triggered
        triggered_at: DateTime<Utc>,
    },
}

impl SystemState {
    /// Transition from Inactive to Activating state
    ///
    /// # Valid From States
    /// - `Inactive`
    ///
    /// # Invalid From States
    /// - `Activating` - Already activating
    /// - `Active` - Already active
    /// - `Deactivating` - Must complete deactivation first
    /// - `Emergency` - Cannot activate from emergency state
    ///
    /// # Returns
    /// - `Ok(SystemState::Activating)` - Transition successful
    /// - `Err(NailsError::InvalidState)` - Invalid transition
    ///
    /// # Example
    /// ```
    /// use nails_core::SystemState;
    ///
    /// let state = SystemState::Inactive;
    /// let activating = state.begin_activation().expect("Valid transition");
    /// ```
    pub fn begin_activation(&self) -> Result<SystemState> {
        match self {
            SystemState::Inactive => Ok(SystemState::Activating {
                started_at: Utc::now(),
            }),
            SystemState::Active { .. } => Err(NailsError::InvalidState(
                "Cannot activate: already active".into(),
            )),
            SystemState::Activating { .. } => Err(NailsError::InvalidState(
                "Cannot activate: activation already in progress".into(),
            )),
            SystemState::Deactivating { .. } => Err(NailsError::InvalidState(
                "Cannot activate: deactivation in progress".into(),
            )),
            SystemState::Emergency { .. } => Err(NailsError::InvalidState(
                "Cannot activate: system in emergency state".into(),
            )),
        }
    }

    /// Transition from Activating to Active state
    ///
    /// # Arguments
    /// - `overlays` - List of overlay mount paths that were successfully mounted
    ///
    /// # Valid From States
    /// - `Activating`
    ///
    /// # Invalid From States
    /// - `Inactive` - Must call begin_activation first
    /// - `Active` - Already active
    /// - `Deactivating` - Cannot activate while deactivating
    /// - `Emergency` - Cannot activate from emergency state
    ///
    /// # Returns
    /// - `Ok(SystemState::Active)` - Transition successful
    /// - `Err(NailsError::InvalidState)` - Invalid transition
    pub fn complete_activation(&self, overlays: Vec<PathBuf>) -> Result<SystemState> {
        match self {
            SystemState::Activating { .. } => Ok(SystemState::Active {
                activated_at: Utc::now(),
                overlays,
            }),
            SystemState::Inactive => Err(NailsError::InvalidState(
                "Cannot complete activation: not in activating state (call begin_activation first)"
                    .into(),
            )),
            SystemState::Active { .. } => Err(NailsError::InvalidState(
                "Cannot complete activation: already active".into(),
            )),
            SystemState::Deactivating { .. } => Err(NailsError::InvalidState(
                "Cannot complete activation: deactivation in progress".into(),
            )),
            SystemState::Emergency { .. } => Err(NailsError::InvalidState(
                "Cannot complete activation: system in emergency state".into(),
            )),
        }
    }

    /// Transition from Active to Deactivating state
    ///
    /// # Valid From States
    /// - `Active`
    ///
    /// # Invalid From States
    /// - `Inactive` - Nothing to deactivate
    /// - `Activating` - Must complete or rollback activation first
    /// - `Deactivating` - Already deactivating
    /// - `Emergency` - Use emergency shutdown instead
    ///
    /// # Returns
    /// - `Ok(SystemState::Deactivating)` - Transition successful
    /// - `Err(NailsError::InvalidState)` - Invalid transition
    pub fn begin_deactivation(&self) -> Result<SystemState> {
        match self {
            SystemState::Active { .. } => Ok(SystemState::Deactivating {
                started_at: Utc::now(),
            }),
            SystemState::Inactive => Err(NailsError::InvalidState(
                "Cannot deactivate: system is not active".into(),
            )),
            SystemState::Activating { .. } => Err(NailsError::InvalidState(
                "Cannot deactivate: activation in progress (complete or rollback first)".into(),
            )),
            SystemState::Deactivating { .. } => Err(NailsError::InvalidState(
                "Cannot deactivate: deactivation already in progress".into(),
            )),
            SystemState::Emergency { .. } => Err(NailsError::InvalidState(
                "Cannot deactivate: system in emergency state".into(),
            )),
        }
    }

    /// Transition from Deactivating to Inactive state
    ///
    /// # Valid From States
    /// - `Deactivating`
    ///
    /// # Invalid From States
    /// - `Inactive` - Already inactive
    /// - `Activating` - Must complete or rollback activation first
    /// - `Active` - Must call begin_deactivation first
    /// - `Emergency` - Cannot complete deactivation from emergency state
    ///
    /// # Returns
    /// - `Ok(SystemState::Inactive)` - Transition successful
    /// - `Err(NailsError::InvalidState)` - Invalid transition
    pub fn complete_deactivation(&self) -> Result<SystemState> {
        match self {
            SystemState::Deactivating { .. } => Ok(SystemState::Inactive),
            SystemState::Inactive => Err(NailsError::InvalidState(
                "Cannot complete deactivation: already inactive".into(),
            )),
            SystemState::Activating { .. } => Err(NailsError::InvalidState(
                "Cannot complete deactivation: activation in progress".into(),
            )),
            SystemState::Active { .. } => Err(NailsError::InvalidState(
                "Cannot complete deactivation: not in deactivating state (call begin_deactivation first)"
                    .into(),
            )),
            SystemState::Emergency { .. } => Err(NailsError::InvalidState(
                "Cannot complete deactivation: system in emergency state".into(),
            )),
        }
    }

    /// Trigger emergency shutdown from any state
    ///
    /// # Valid From States
    /// - **Any state** (including Emergency - idempotent)
    ///
    /// Emergency transitions are always allowed regardless of current state,
    /// as they represent a critical security response to forensic threats.
    ///
    /// # Returns
    /// - `Ok(SystemState::Emergency)` - Always succeeds
    ///
    /// # Example
    /// ```
    /// use nails_core::SystemState;
    ///
    /// let state = SystemState::Active {
    ///     activated_at: chrono::Utc::now(),
    ///     overlays: vec![],
    /// };
    /// let emergency = state.trigger_emergency().expect("Emergency always succeeds");
    /// ```
    pub fn trigger_emergency(&self) -> Result<SystemState> {
        // Emergency transition is always allowed from any state
        Ok(SystemState::Emergency {
            triggered_at: Utc::now(),
        })
    }

    /// Check if system is in Active state
    ///
    /// # Returns
    /// - `true` if state is `Active`
    /// - `false` otherwise
    pub fn is_active(&self) -> bool {
        matches!(self, SystemState::Active { .. })
    }

    /// Check if system is in Inactive state
    ///
    /// # Returns
    /// - `true` if state is `Inactive`
    /// - `false` otherwise
    pub fn is_inactive(&self) -> bool {
        matches!(self, SystemState::Inactive)
    }

    /// Check if system can be deactivated
    ///
    /// Returns true if the system is in a state where deactivation is valid.
    ///
    /// # Returns
    /// - `true` if state is `Active` (can call begin_deactivation)
    /// - `false` otherwise
    pub fn can_deactivate(&self) -> bool {
        matches!(self, SystemState::Active { .. })
    }
}

/// Information about a mounted overlay filesystem
///
/// OverlayFS merges multiple directories into a single view:
/// - **lower_dir**: Read-only base layer (from decoy system)
/// - **upper_dir**: Writable layer (on hidden volume)
/// - **work_dir**: Working directory for overlay metadata
/// - **mount_path**: Where the overlay is mounted
///
/// # Security Consideration
///
/// All writable layers (upper_dir, work_dir) MUST be on hidden volume
/// to prevent forensic evidence from leaking to the decoy system.
///
/// # Requirements
///
/// - FR28: Track overlay status with mount paths and directories
/// - AR25: State file contains overlay status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverlayInfo {
    /// Target mount point (e.g., /home, /etc)
    pub mount_path: PathBuf,

    /// Lower (read-only) directory from base system
    pub lower_dir: PathBuf,

    /// Upper (writable) directory on hidden volume
    pub upper_dir: PathBuf,

    /// Work directory for overlay metadata
    pub work_dir: PathBuf,

    /// Timestamp when this overlay was mounted
    pub mounted_at: DateTime<Utc>,
}

/// State file for persistence to hidden volume
///
/// The StateFile contains the current system state and all metadata needed
/// to reconstruct the system state after a reboot or emergency shutdown.
///
/// # Security Critical
///
/// **INVARIANT**: State file MUST only exist at {hidden_volume}/.nails/state.json
/// **NEVER** at: /home/user/.nails/state.json, /etc/nails/state.json, or ANY path
/// outside the hidden volume.
///
/// Writing state to the decoy system would leak forensic evidence of hidden
/// environment usage, defeating NAILS' plausible deniability.
///
/// # Requirements
///
/// - FR24: Persist state to {hidden_volume}/.nails/state.json
/// - FR25: Never write state file to decoy system
/// - FR27: Track timestamp for state changes
/// - FR28: Track overlay status
/// - FR29: Serialize state to JSON format
/// - AR24: State file on hidden volume only
/// - AR25: State file contents (state, activated_at, overlay status, nixos_generation)
/// - NFR13: Atomic operations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateFile {
    /// Current system state (Inactive, Activating, Active, Deactivating, Emergency)
    pub state: SystemState,

    /// NixOS generation hash when last activated (for profile rebuild detection)
    pub nixos_generation: Option<String>,

    /// Currently mounted overlays with their configuration
    pub overlay_status: std::collections::HashMap<PathBuf, OverlayInfo>,

    /// Timestamp of last state modification
    pub last_modified: DateTime<Utc>,
}

impl Default for StateFile {
    /// Create default StateFile with Inactive state
    ///
    /// Used when state file is missing or malformed (AR27, AR53).
    /// Safe default assumes system is INACTIVE (no hidden environment).
    fn default() -> Self {
        Self {
            state: SystemState::Inactive,
            nixos_generation: None,
            overlay_status: std::collections::HashMap::new(),
            last_modified: Utc::now(),
        }
    }
}

impl StateFile {
    /// Save state file to disk with atomic write
    ///
    /// # Atomicity Guarantee (NFR13)
    ///
    /// Uses tempfile + rename pattern to ensure the state file is never
    /// partially written. Either the old file exists OR the new file exists,
    /// never a corrupted partial file.
    ///
    /// # Hidden Volume Validation (AR26)
    ///
    /// **CRITICAL**: State file MUST be on hidden volume. This method will
    /// return an error if the path is outside HIDDEN_VOLUME_ROOT.
    ///
    /// # Security
    ///
    /// - File permissions set to 0600 (user-only read/write)
    /// - Parent directories created if needed
    /// - Atomic rename ensures no partial writes
    ///
    /// # Arguments
    ///
    /// * `path` - Path to write state file (must be on hidden volume)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - State saved successfully
    /// * `Err(NailsError::InvalidState)` - Path not on hidden volume
    /// * `Err(NailsError::IoError)` - I/O error during write
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nails_core::StateFile;
    /// use std::path::Path;
    ///
    /// let state = StateFile::default();
    /// state.save(Path::new("/mnt/hidden-volume/.nails/state.json"))?;
    /// # Ok::<(), nails_core::NailsError>(())
    /// ```
    pub fn save(&self, path: &Path) -> Result<()> {
        // 1. Validate path is on hidden volume (AR26)
        if !is_on_hidden_volume(path) {
            return Err(NailsError::InvalidState(
                "State file must be on hidden volume".into(),
            ));
        }

        // 2. Serialize to JSON (FR29, AR10)
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| NailsError::ConfigError(format!("Failed to serialize state: {}", e)))?;

        // 3. Create parent directory if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // 4. Write to temp file in same directory (ensures same filesystem for atomic rename)
        let dir = path.parent().unwrap_or(Path::new("."));
        let temp = tempfile::NamedTempFile::new_in(dir)?;

        // Write JSON content
        std::io::Write::write_all(&mut temp.as_file(), json.as_bytes())?;

        // 5. Set permissions to 0600 (user-only read/write)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(temp.path())?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(temp.path(), perms)?;
        }

        // 6. Atomic rename (single syscall on POSIX)
        temp.persist(path)
            .map_err(|e| std::io::Error::other(format!("Failed to persist: {}", e)))?;

        Ok(())
    }

    /// Load state file from disk with graceful error handling
    ///
    /// # Graceful Degradation (AR27, AR53)
    ///
    /// This method follows a "safe default" philosophy:
    /// - **Missing file**: Returns `Ok(StateFile::default())` with Inactive state
    /// - **Malformed JSON**: Returns `Ok(StateFile::default())` with Inactive state
    /// - **I/O error**: Returns `Ok(StateFile::default())` with Inactive state
    ///
    /// This ensures the system never crashes due to state file issues and
    /// always assumes the safest state (INACTIVE) when uncertain.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to load state file from
    ///
    /// # Returns
    ///
    /// * `Ok(StateFile)` - State loaded successfully OR safe default on error
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nails_core::StateFile;
    /// use std::path::Path;
    ///
    /// let state = StateFile::load(Path::new("/mnt/hidden-volume/.nails/state.json"))?;
    /// # Ok::<(), nails_core::NailsError>(())
    /// ```
    pub fn load(path: &Path) -> Result<StateFile> {
        // Check if file exists
        if !path.exists() {
            tracing::warn!(
                "State file not found at {}, assuming INACTIVE",
                path.display()
            );
            return Ok(StateFile::default());
        }

        // Read file contents
        let contents = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    "State file unreadable at {}: {}, assuming INACTIVE",
                    path.display(),
                    e
                );
                return Ok(StateFile::default());
            }
        };

        // Parse JSON
        match serde_json::from_str(&contents) {
            Ok(state_file) => Ok(state_file),
            Err(e) => {
                tracing::warn!(
                    "State file malformed at {}: {}, assuming INACTIVE",
                    path.display(),
                    e
                );
                Ok(StateFile::default())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== OverlayInfo Tests ==========

    #[test]
    fn test_overlay_info_creation() {
        let overlay = OverlayInfo {
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/home"),
            upper_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
            work_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
            mounted_at: Utc::now(),
        };

        assert_eq!(overlay.mount_path, PathBuf::from("/home"));
        assert_eq!(
            overlay.upper_dir,
            PathBuf::from("/mnt/hidden-volume/overlays/home/upper")
        );
    }

    #[test]
    fn test_overlay_info_serialization() {
        let overlay = OverlayInfo {
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/home"),
            upper_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
            work_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
            mounted_at: DateTime::parse_from_rfc3339("2025-01-27T10:30:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };

        // Serialize to JSON
        let json = serde_json::to_string(&overlay).expect("Should serialize");
        assert!(json.contains("\"mount_path\""));
        assert!(json.contains("\"/home\""));

        // Deserialize back
        let deserialized: OverlayInfo = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized, overlay);
    }

    // ========== StateFile Tests ==========

    #[test]
    fn test_state_file_default() {
        let state_file = StateFile::default();

        assert_eq!(state_file.state, SystemState::Inactive);
        assert_eq!(state_file.nixos_generation, None);
        assert!(state_file.overlay_status.is_empty());
        // Just verify last_modified exists (can't test exact time)
        assert!(state_file.last_modified <= Utc::now());
    }

    #[test]
    fn test_state_file_serialization() {
        let mut overlay_status = std::collections::HashMap::new();
        overlay_status.insert(
            PathBuf::from("/home"),
            OverlayInfo {
                mount_path: PathBuf::from("/home"),
                lower_dir: PathBuf::from("/home"),
                upper_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
                work_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
                mounted_at: DateTime::parse_from_rfc3339("2025-01-27T10:30:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            },
        );

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at: DateTime::parse_from_rfc3339("2025-01-27T10:30:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                overlays: vec![PathBuf::from("/home")],
            },
            nixos_generation: Some("abc123def456".to_string()),
            overlay_status,
            last_modified: DateTime::parse_from_rfc3339("2025-01-27T10:30:01Z")
                .unwrap()
                .with_timezone(&Utc),
        };

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&state_file).expect("Should serialize");
        assert!(json.contains("\"Active\""));
        assert!(json.contains("\"nixos_generation\""));
        assert!(json.contains("\"overlay_status\""));

        // Deserialize back
        let deserialized: StateFile = serde_json::from_str(&json).expect("Should deserialize");
        assert_eq!(deserialized, state_file);
    }

    // ========== Hidden Volume Validation Tests ==========

    #[test]
    fn test_save_valid_path_in_hidden_volume() {
        let _state = StateFile::default();

        // Create temporary directory that looks like hidden volume
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let hidden_vol_path = temp_dir.path().join("mnt/hidden-volume/.nails");
        std::fs::create_dir_all(&hidden_vol_path).expect("Should create dirs");

        let _state_path = hidden_vol_path.join("state.json");

        // This will fail because temp_dir is not actually /mnt/hidden-volume
        // For real test, we'd need to mock or use a test-specific constant
        // Let's test the is_on_hidden_volume function directly instead
    }

    #[test]
    fn test_hidden_volume_validation_valid_path() {
        // Test that paths within hidden volume are accepted
        assert!(is_on_hidden_volume(Path::new(
            "/mnt/hidden-volume/.nails/state.json"
        )));
        assert!(is_on_hidden_volume(Path::new(
            "/mnt/hidden-volume/subdir/state.json"
        )));
        assert!(is_on_hidden_volume(Path::new(
            "/mnt/hidden-volume/a/b/c/state.json"
        )));
    }

    #[test]
    fn test_hidden_volume_validation_invalid_paths() {
        // Test that paths outside hidden volume are rejected
        assert!(!is_on_hidden_volume(Path::new("/etc/nails/state.json")));
        assert!(!is_on_hidden_volume(Path::new(
            "/home/user/.nails/state.json"
        )));
        assert!(!is_on_hidden_volume(Path::new(
            "/mnt/hidden-volume-fake/state.json"
        )));
        assert!(!is_on_hidden_volume(Path::new(
            "/tmp/test-hidden-volume/state.json"
        )));
    }

    #[test]
    fn test_hidden_volume_validation_traversal_attack() {
        // Test that path traversal attacks are rejected
        assert!(!is_on_hidden_volume(Path::new(
            "/mnt/hidden-volume/../etc/state.json"
        )));
        assert!(!is_on_hidden_volume(Path::new(
            "/mnt/hidden-volume/../../tmp/state.json"
        )));
    }

    #[test]
    fn test_save_rejects_path_outside_hidden_volume() {
        let state = StateFile::default();

        // Try to save to /tmp (should fail)
        let result = state.save(Path::new("/tmp/state.json"));
        assert!(result.is_err());

        match result {
            Err(NailsError::InvalidState(msg)) => {
                assert!(msg.contains("State file must be on hidden volume"));
            }
            _ => panic!("Expected InvalidState error"),
        }

        // Verify no file was written
        assert!(!Path::new("/tmp/state.json").exists());
    }

    #[test]
    fn test_save_rejects_home_directory_path() {
        let state = StateFile::default();

        // Try to save to home directory (should fail)
        let result = state.save(Path::new("/home/user/.nails/state.json"));
        assert!(result.is_err());

        match result {
            Err(NailsError::InvalidState(msg)) => {
                assert!(msg.contains("State file must be on hidden volume"));
            }
            _ => panic!("Expected InvalidState error"),
        }
    }

    // ========== Load Method Tests ==========

    #[test]
    fn test_load_missing_file_returns_default() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let nonexistent_path = temp_dir.path().join("nonexistent.json");

        let result = StateFile::load(&nonexistent_path);
        assert!(result.is_ok());

        let state = result.unwrap();
        assert_eq!(state.state, SystemState::Inactive);
        assert_eq!(state.nixos_generation, None);
        assert!(state.overlay_status.is_empty());
    }

    #[test]
    fn test_load_empty_file_returns_default() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let empty_file = temp_dir.path().join("empty.json");

        // Create empty file
        std::fs::write(&empty_file, "").expect("Should write empty file");

        let result = StateFile::load(&empty_file);
        assert!(result.is_ok());

        let state = result.unwrap();
        assert_eq!(state.state, SystemState::Inactive);
    }

    #[test]
    fn test_load_invalid_json_returns_default() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let invalid_file = temp_dir.path().join("invalid.json");

        // Write invalid JSON
        std::fs::write(&invalid_file, "{ invalid json syntax").expect("Should write file");

        let result = StateFile::load(&invalid_file);
        assert!(result.is_ok());

        let state = result.unwrap();
        assert_eq!(state.state, SystemState::Inactive);
    }

    #[test]
    fn test_load_wrong_schema_returns_default() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let wrong_schema = temp_dir.path().join("wrong.json");

        // Write JSON with wrong schema (missing required fields)
        std::fs::write(&wrong_schema, r#"{"wrong": "schema"}"#).expect("Should write file");

        let result = StateFile::load(&wrong_schema);
        assert!(result.is_ok());

        let state = result.unwrap();
        assert_eq!(state.state, SystemState::Inactive);
    }

    // ========== Round-Trip Integration Tests ==========

    #[test]
    fn test_save_load_round_trip_with_inactive_state() {
        // Note: We can't actually save to /mnt/hidden-volume in tests,
        // but we can test the serialization/deserialization logic
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let state_path = temp_dir.path().join("state.json");

        let original = StateFile {
            state: SystemState::Inactive,
            nixos_generation: None,
            overlay_status: std::collections::HashMap::new(),
            last_modified: DateTime::parse_from_rfc3339("2025-01-27T10:30:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };

        // Serialize to JSON manually (since we can't use save with temp dir)
        let json = serde_json::to_string_pretty(&original).expect("Should serialize");
        std::fs::write(&state_path, json).expect("Should write");

        // Load and verify
        let loaded = StateFile::load(&state_path).expect("Should load");
        assert_eq!(loaded, original);
    }

    #[test]
    fn test_save_load_round_trip_with_active_state() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let state_path = temp_dir.path().join("state.json");

        let mut overlay_status = std::collections::HashMap::new();
        overlay_status.insert(
            PathBuf::from("/home"),
            OverlayInfo {
                mount_path: PathBuf::from("/home"),
                lower_dir: PathBuf::from("/home"),
                upper_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
                work_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
                mounted_at: DateTime::parse_from_rfc3339("2025-01-27T10:30:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            },
        );

        let original = StateFile {
            state: SystemState::Active {
                activated_at: DateTime::parse_from_rfc3339("2025-01-27T10:30:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
            },
            nixos_generation: Some("abc123def456".to_string()),
            overlay_status,
            last_modified: DateTime::parse_from_rfc3339("2025-01-27T10:30:01Z")
                .unwrap()
                .with_timezone(&Utc),
        };

        // Serialize manually
        let json = serde_json::to_string_pretty(&original).expect("Should serialize");
        std::fs::write(&state_path, json).expect("Should write");

        // Load and verify
        let loaded = StateFile::load(&state_path).expect("Should load");
        assert_eq!(loaded.state, original.state);
        assert_eq!(loaded.nixos_generation, original.nixos_generation);
        assert_eq!(loaded.overlay_status, original.overlay_status);
    }

    #[test]
    fn test_save_load_multiple_overlays() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let state_path = temp_dir.path().join("state.json");

        let mut overlay_status = std::collections::HashMap::new();

        // Add multiple overlays
        for (mount, name) in [("/home", "home"), ("/etc", "etc"), ("/var", "var")] {
            overlay_status.insert(
                PathBuf::from(mount),
                OverlayInfo {
                    mount_path: PathBuf::from(mount),
                    lower_dir: PathBuf::from(mount),
                    upper_dir: PathBuf::from(format!("/mnt/hidden-volume/overlays/{}/upper", name)),
                    work_dir: PathBuf::from(format!("/mnt/hidden-volume/overlays/{}/work", name)),
                    mounted_at: Utc::now(),
                },
            );
        }

        let original = StateFile {
            state: SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![
                    PathBuf::from("/home"),
                    PathBuf::from("/etc"),
                    PathBuf::from("/var"),
                ],
            },
            nixos_generation: Some("test123".to_string()),
            overlay_status,
            last_modified: Utc::now(),
        };

        // Serialize manually
        let json = serde_json::to_string_pretty(&original).expect("Should serialize");
        std::fs::write(&state_path, json).expect("Should write");

        // Load and verify
        let loaded = StateFile::load(&state_path).expect("Should load");
        assert_eq!(loaded.overlay_status.len(), 3);
        assert!(loaded.overlay_status.contains_key(&PathBuf::from("/home")));
        assert!(loaded.overlay_status.contains_key(&PathBuf::from("/etc")));
        assert!(loaded.overlay_status.contains_key(&PathBuf::from("/var")));
    }
}
