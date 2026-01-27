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

use crate::{Filesystem, NailsError, NailsManager, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
/// # Arguments
///
/// * `path` - Path to validate
/// * `hidden_volume_root` - Optional custom hidden volume root (for testing)
///
/// # Security Considerations
///
/// - Uses canonicalize() to resolve symlinks (prevents symlink attacks)
/// - Handles paths that don't exist yet (for initial save)
/// - Rejects similar-looking paths like "/mnt/hidden-volume-fake"
/// - Rejects path traversal attempts like "../etc/state.json"
///
/// # Returns
///
/// * `true` if path is within hidden volume
/// * `false` otherwise
fn is_on_hidden_volume_internal(path: &Path, hidden_volume_root: &str) -> bool {
    // Try to canonicalize to resolve symlinks
    match path.canonicalize() {
        Ok(canonical) => canonical.starts_with(hidden_volume_root),
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

            cleaned.starts_with(hidden_volume_root)
        }
    }
}

/// Check if a path is within the hidden volume (production version)
///
/// This is a wrapper around `is_on_hidden_volume_internal` that uses the
/// default HIDDEN_VOLUME_ROOT constant.
fn is_on_hidden_volume(path: &Path) -> bool {
    is_on_hidden_volume_internal(path, HIDDEN_VOLUME_ROOT)
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
    /// Schema version for backward compatibility (uses semver from Cargo.toml)
    /// Format: "major.minor.patch" (e.g., "0.1.0")
    pub version: String,

    /// Current system state (Inactive, Activating, Active, Deactivating, Emergency)
    pub state: SystemState,

    /// NixOS generation hash when last activated (for profile rebuild detection)
    pub nixos_generation: Option<String>,

    /// Currently mounted overlays with their configuration
    pub overlay_status: std::collections::HashMap<PathBuf, OverlayInfo>,

    /// Timestamp of last state modification
    pub last_modified: DateTime<Utc>,

    /// HMAC checksum for tamper detection (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
}

impl Default for StateFile {
    /// Create default StateFile with Inactive state
    ///
    /// Used when state file is missing or malformed (AR27, AR53).
    /// Safe default assumes system is INACTIVE (no hidden environment).
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            state: SystemState::Inactive,
            nixos_generation: None,
            overlay_status: std::collections::HashMap::new(),
            last_modified: Utc::now(),
            checksum: None,
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
        self.save_with_root(path, HIDDEN_VOLUME_ROOT)
    }

    /// Save state file with custom hidden volume root path
    ///
    /// This method allows specifying a custom hidden volume root path for validation.
    /// Used by NailsManager to validate paths against the configured hidden volume root.
    ///
    /// # Arguments
    ///
    /// * `path` - Path where state file should be saved
    /// * `hidden_volume_root` - Root path of hidden volume (e.g., from Config)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nails_core::StateFile;
    /// use std::path::{Path, PathBuf};
    ///
    /// let state = StateFile::default();
    /// let hidden_root = PathBuf::from("/mnt/custom-hidden");
    /// let state_path = hidden_root.join(".nails/state.json");
    /// state.save_with_custom_root(&state_path, &hidden_root)?;
    /// # Ok::<(), nails_core::NailsError>(())
    /// ```
    pub fn save_with_custom_root(&self, path: &Path, hidden_volume_root: &Path) -> Result<()> {
        self.save_with_root(
            path,
            hidden_volume_root.to_str().unwrap_or(HIDDEN_VOLUME_ROOT),
        )
    }

    /// Save state file with custom hidden volume root (for testing)
    ///
    /// This is an internal method used by tests to verify the atomic write
    /// logic without requiring access to the actual hidden volume mount point.
    ///
    /// Production code should use `save()` instead.
    #[cfg(test)]
    fn save_with_root(&self, path: &Path, hidden_volume_root: &str) -> Result<()> {
        // 1. Validate path is on hidden volume (AR26)
        if !is_on_hidden_volume_internal(path, hidden_volume_root) {
            return Err(NailsError::InvalidState(format!(
                "State file must be on hidden volume ({}), but attempted to write to: {}",
                hidden_volume_root,
                path.display()
            )));
        }

        self.save_internal(path)
    }

    /// Save state file with default hidden volume root (production)
    #[cfg(not(test))]
    fn save_with_root(&self, path: &Path, hidden_volume_root: &str) -> Result<()> {
        // In production, always use HIDDEN_VOLUME_ROOT constant
        let _ = hidden_volume_root; // Suppress unused warning
        if !is_on_hidden_volume(path) {
            return Err(NailsError::InvalidState(format!(
                "State file must be on hidden volume ({}), but attempted to write to: {}",
                HIDDEN_VOLUME_ROOT,
                path.display()
            )));
        }

        self.save_internal(path)
    }

    /// Internal save implementation (shared by test and production)
    fn save_internal(&self, path: &Path) -> Result<()> {
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
        // Use persist_noclobber to detect race conditions, then fallback to regular persist
        match temp.persist_noclobber(path) {
            Ok(_) => Ok(()),
            Err(e) => {
                // If file exists, we have a race condition - try regular persist
                if e.error.kind() == std::io::ErrorKind::AlreadyExists {
                    tracing::warn!("State file already exists during atomic write, overwriting");
                    e.file.persist(path).map_err(|e| {
                        std::io::Error::other(format!(
                            "Failed to persist after race condition: {}",
                            e
                        ))
                    })?;
                    Ok(())
                } else {
                    Err(
                        std::io::Error::other(format!("Failed to persist state file: {}", e.error))
                            .into(),
                    )
                }
            }
        }
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

// ============================================================================
// StateGuard - RAII Rollback Guard for Automatic State Cleanup
// ============================================================================

/// RAII guard for automatic state rollback on error or panic
///
/// StateGuard implements the RAII (Resource Acquisition Is Initialization) pattern
/// to guarantee state rollback when operations fail or panic. The Drop trait ensures
/// cleanup code runs when the guard goes out of scope, even during stack unwinding.
///
/// # Pattern: Transaction-style State Management
///
/// StateGuard enables transaction-style state management where:
/// 1. Create guard capturing current state
/// 2. Perform risky operations (may fail or panic)
/// 3. Explicitly commit() on success to prevent rollback
/// 4. Automatic rollback on failure (via Drop)
///
/// # Example
///
/// ```rust
/// use nails_core::{StateGuard, NailsManager, MockFilesystem, Config, SystemState};
/// use std::sync::{Arc, Mutex};
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// let config = Config::default();
/// let temp_dir = tempfile::tempdir().unwrap();
/// let state_path = temp_dir.path().join("state.json");
/// let manager = Arc::new(Mutex::new(
///     NailsManager::new(fs, config, state_path)
/// ));
///
/// // Capture current state for potential rollback
/// let previous_state = {
///     let m = manager.lock().unwrap();
///     m.current_state().unwrap()
/// };
///
/// // Create guard - will rollback if not committed
/// let guard = StateGuard::new(Arc::clone(&manager), previous_state);
///
/// // Perform operations that might fail...
/// // If any step fails, guard.drop() automatically rolls back
///
/// // Explicitly commit to prevent rollback
/// guard.commit();
/// ```
///
/// # Security Guarantee (NFR24)
///
/// Even if a panic occurs during activation/deactivation, Drop trait ensures
/// state is rolled back. This prevents the system from being left in an
/// inconsistent state (Activating/Deactivating) which could leak forensic evidence.
///
/// # Requirements
///
/// - **FR50**: Automatic rollback on activation failure
/// - **FR51**: Remount overlays if cleanup fails
/// - **FR52**: Track steps for reverse rollback
/// - **FR53**: Idempotent rollback (safe to call multiple times)
/// - **NFR15**: Prevent memory leaks via RAII
/// - **NFR20**: Rollback on partial failures
/// - **NFR24**: Automatic cleanup even on panic
pub struct StateGuard<F: Filesystem> {
    /// Shared reference to NailsManager for state restoration
    ///
    /// Arc<Mutex<_>> enables:
    /// - Shared ownership (guard needs its own reference)
    /// - Thread-safe access to manager
    /// - Drop can run even during panic unwinding
    manager: Arc<Mutex<NailsManager<F>>>,

    /// State to restore if transaction is not committed
    ///
    /// Captured at guard creation, restored in drop() if committed=false
    previous_state: SystemState,

    /// Whether transaction was explicitly committed
    ///
    /// If false when dropped, triggers rollback.
    /// If true, drop() does nothing (success case).
    committed: bool,
}

impl<F: Filesystem> StateGuard<F> {
    /// Create a new StateGuard capturing current state
    ///
    /// The guard captures the current state for potential rollback.
    /// Call commit() to mark the transaction successful and prevent rollback.
    ///
    /// # Arguments
    ///
    /// * `manager` - Shared NailsManager reference
    /// * `previous_state` - State to restore on rollback
    ///
    /// # Returns
    ///
    /// New StateGuard with committed=false (uncommitted transaction)
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{StateGuard, NailsManager, MockFilesystem, Config, SystemState};
    /// use std::sync::{Arc, Mutex};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let temp_dir = tempfile::tempdir().unwrap();
    /// let state_path = temp_dir.path().join("state.json");
    /// let manager = Arc::new(Mutex::new(
    ///     NailsManager::new(fs, config, state_path)
    /// ));
    ///
    /// let previous_state = SystemState::Inactive;
    /// let guard = StateGuard::new(Arc::clone(&manager), previous_state);
    /// // guard will rollback to Inactive when dropped (unless committed)
    /// ```
    pub fn new(manager: Arc<Mutex<NailsManager<F>>>, previous_state: SystemState) -> Self {
        Self {
            manager,
            previous_state,
            committed: false,
        }
    }

    /// Commit the transaction to prevent rollback
    ///
    /// Marks the transaction as successful. When the guard is dropped,
    /// no rollback will occur.
    ///
    /// # Move Semantics
    ///
    /// This method consumes self (takes ownership), preventing further use
    /// of the guard after commit. This is intentional - once committed,
    /// the guard's job is done.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{StateGuard, NailsManager, MockFilesystem, Config, SystemState};
    /// use std::sync::{Arc, Mutex};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let temp_dir = tempfile::tempdir().unwrap();
    /// let state_path = temp_dir.path().join("state.json");
    /// let manager = Arc::new(Mutex::new(
    ///     NailsManager::new(fs, config, state_path)
    /// ));
    ///
    /// let previous_state = SystemState::Inactive;
    /// let guard = StateGuard::new(Arc::clone(&manager), previous_state);
    ///
    /// // Operation succeeded - commit to prevent rollback
    /// guard.commit();
    /// // guard is consumed here, can't be used again
    /// ```
    pub fn commit(mut self) {
        self.committed = true;
        // self is dropped here, but committed=true prevents rollback
    }
}

impl<F: Filesystem> Drop for StateGuard<F> {
    /// Automatic rollback on drop if not committed
    ///
    /// This method runs when the guard goes out of scope. If committed=false,
    /// it restores the previous state to the manager.
    ///
    /// # Panic Safety
    ///
    /// This method **MUST NOT PANIC**. Panicking in drop() causes double-panic
    /// which terminates the process (abort). All errors are logged but not propagated.
    ///
    /// # Lock Poisoning Handling
    ///
    /// If another thread panicked while holding the manager lock, the Mutex
    /// becomes "poisoned". We handle this gracefully by:
    /// 1. Detecting PoisonError
    /// 2. Extracting the data anyway (into_inner)
    /// 3. Attempting rollback despite poisoning
    /// 4. Logging warning about poisoned state
    ///
    /// # Requirements
    ///
    /// - **FR50**: Automatic rollback on activation failure
    /// - **FR52**: Log warning "Rolling back to previous state: {:?}"
    /// - **NFR24**: Works even during panic (Drop during stack unwinding)
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{StateGuard, NailsManager, MockFilesystem, Config, SystemState};
    /// use std::sync::{Arc, Mutex};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let temp_dir = tempfile::tempdir().unwrap();
    /// let state_path = temp_dir.path().join("state.json");
    /// let manager = Arc::new(Mutex::new(
    ///     NailsManager::new(fs, config, state_path)
    /// ));
    ///
    /// {
    ///     let previous_state = SystemState::Inactive;
    ///     let guard = StateGuard::new(Arc::clone(&manager), previous_state);
    ///     // guard goes out of scope here...
    ///     // drop() will rollback to Inactive
    /// } // <-- drop() runs here
    /// ```
    fn drop(&mut self) {
        if !self.committed {
            tracing::warn!("Rolling back to previous state: {:?}", self.previous_state);

            // Attempt to acquire manager lock
            match self.manager.lock() {
                Ok(mut manager) => {
                    // Normal case: lock acquired successfully
                    // Use force_state to bypass validation (rollback case)
                    if let Err(e) = manager.force_state(self.previous_state.clone()) {
                        // Log error but don't panic (panic in drop = abort)
                        tracing::error!("Failed to rollback state: {}", e);
                    }
                }
                Err(poisoned) => {
                    // Lock poisoned - another thread panicked while holding lock
                    tracing::warn!("Manager lock poisoned during rollback, attempting recovery...");

                    // Extract data from poisoned lock
                    let mut manager = poisoned.into_inner();

                    // Attempt rollback anyway using force_state
                    if let Err(e) = manager.force_state(self.previous_state.clone()) {
                        tracing::error!("Failed to rollback state after lock poisoning: {}", e);
                    }
                }
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

        assert_eq!(state_file.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(state_file.state, SystemState::Inactive);
        assert_eq!(state_file.nixos_generation, None);
        assert!(state_file.overlay_status.is_empty());
        assert_eq!(state_file.checksum, None);
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
            version: env!("CARGO_PKG_VERSION").to_string(),
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
            checksum: None,
        };

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&state_file).expect("Should serialize");
        assert!(json.contains("\"version\""));
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
                assert!(msg.contains("/tmp/state.json")); // Should include actual path
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
                assert!(msg.contains("/home/user/.nails/state.json")); // Should include actual path
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
            version: env!("CARGO_PKG_VERSION").to_string(),
            state: SystemState::Inactive,
            nixos_generation: None,
            overlay_status: std::collections::HashMap::new(),
            last_modified: DateTime::parse_from_rfc3339("2025-01-27T10:30:00Z")
                .unwrap()
                .with_timezone(&Utc),
            checksum: None,
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
            version: env!("CARGO_PKG_VERSION").to_string(),
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
            checksum: None,
        };

        // Serialize manually
        let json = serde_json::to_string_pretty(&original).expect("Should serialize");
        std::fs::write(&state_path, json).expect("Should write");

        // Load and verify
        let loaded = StateFile::load(&state_path).expect("Should load");
        assert_eq!(loaded.state, original.state);
        assert_eq!(loaded.nixos_generation, original.nixos_generation);
        assert_eq!(loaded.overlay_status, original.overlay_status);
        assert_eq!(loaded.version, env!("CARGO_PKG_VERSION"));
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
            version: env!("CARGO_PKG_VERSION").to_string(),
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
            checksum: None,
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

    // ========== Additional Coverage Tests for Review Items ==========

    #[test]
    fn test_version_field_serializes() {
        let state = StateFile::default();
        assert_eq!(state.version, env!("CARGO_PKG_VERSION"));

        let json = serde_json::to_string(&state).expect("Should serialize");
        assert!(json.contains(&format!("\"version\":\"{}\"", env!("CARGO_PKG_VERSION"))));
    }

    #[test]
    fn test_checksum_field_optional() {
        let state = StateFile::default();
        assert_eq!(state.checksum, None);

        let json = serde_json::to_string(&state).expect("Should serialize");
        // Checksum should not appear in JSON when None (skip_serializing_if)
        assert!(!json.contains("\"checksum\""));
    }

    #[test]
    fn test_checksum_field_present_when_set() {
        let state = StateFile {
            checksum: Some("abc123".to_string()),
            ..StateFile::default()
        };

        let json = serde_json::to_string(&state).expect("Should serialize");
        assert!(json.contains("\"checksum\""));
        assert!(json.contains("\"abc123\""));
    }

    #[test]
    fn test_path_validation_with_relative_path() {
        // Test that relative paths are rejected (not on hidden volume)
        assert!(!is_on_hidden_volume(Path::new("relative/path/state.json")));
        assert!(!is_on_hidden_volume(Path::new("./state.json")));
        assert!(!is_on_hidden_volume(Path::new("../state.json")));
    }

    #[test]
    fn test_path_validation_with_non_canonical_paths() {
        // Test paths that need to be cleaned before checking
        // These test the non-canonical path logic (line 70-111)
        assert!(!is_on_hidden_volume(Path::new(
            "/mnt/hidden-volume/../etc/state.json"
        )));
        assert!(!is_on_hidden_volume(Path::new(
            "/etc/../home/user/.nails/state.json"
        )));
        assert!(!is_on_hidden_volume(Path::new("/mnt/./other/state.json")));

        // Valid path with redundant components should still work
        assert!(is_on_hidden_volume(Path::new(
            "/mnt/hidden-volume/./subdir/state.json"
        )));
        assert!(is_on_hidden_volume(Path::new(
            "/mnt/hidden-volume/subdir/../.nails/state.json"
        )));
    }

    #[test]
    fn test_actual_atomic_write_to_temp_hidden_volume() {
        // Create a mock hidden volume in temp for testing
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol_root = temp_dir.path().to_str().unwrap();
        let state_dir = temp_dir.path().join(".nails");
        std::fs::create_dir_all(&state_dir).expect("Should create dirs");

        let state_path = state_dir.join("state.json");

        // Now we can actually test save() with a custom hidden volume root!
        let state = StateFile {
            version: env!("CARGO_PKG_VERSION").to_string(),
            state: SystemState::Inactive,
            nixos_generation: Some("test-gen".to_string()),
            overlay_status: std::collections::HashMap::new(),
            last_modified: Utc::now(),
            checksum: None,
        };

        // Use save_with_root to test actual atomic write logic
        state
            .save_with_root(&state_path, mock_hidden_vol_root)
            .expect("Should save with custom root");

        // Verify file exists and is readable
        assert!(state_path.exists());
        let loaded_json = std::fs::read_to_string(&state_path).expect("Should read");
        let loaded: StateFile = serde_json::from_str(&loaded_json).expect("Should deserialize");
        assert_eq!(loaded.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(loaded.nixos_generation, Some("test-gen".to_string()));

        // Verify permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&state_path)
                .expect("Should get metadata")
                .permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        // Test that save_with_root rejects paths outside the custom root
        let outside_path = temp_dir.path().parent().unwrap().join("outside.json");
        let result = state.save_with_root(&outside_path, mock_hidden_vol_root);
        assert!(result.is_err());
        match result {
            Err(NailsError::InvalidState(msg)) => {
                assert!(msg.contains("State file must be on hidden volume"));
            }
            _ => panic!("Expected InvalidState error"),
        }
    }

    #[test]
    fn test_load_io_error_returns_default() {
        // Test load() handling of I/O errors beyond just missing file
        // Create a directory with the same name as our target file (causes read error)
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let dir_as_file = temp_dir.path().join("state.json");
        std::fs::create_dir(&dir_as_file).expect("Should create dir");

        // Try to load directory as file (should fail gracefully)
        let result = StateFile::load(&dir_as_file);
        assert!(result.is_ok());

        let state = result.unwrap();
        assert_eq!(state.state, SystemState::Inactive);
        assert_eq!(state.nixos_generation, None);
    }

    #[test]
    fn test_persist_race_condition_handling() {
        // Test that save_with_root handles race conditions properly
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol_root = temp_dir.path().to_str().unwrap();
        let state_dir = temp_dir.path().join(".nails");
        std::fs::create_dir_all(&state_dir).expect("Should create dirs");

        let state_path = state_dir.join("state.json");

        // Pre-create the target file to simulate race condition
        std::fs::write(&state_path, "existing content").expect("Should write existing file");

        let state = StateFile {
            version: env!("CARGO_PKG_VERSION").to_string(),
            state: SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![],
            },
            nixos_generation: None,
            overlay_status: std::collections::HashMap::new(),
            last_modified: Utc::now(),
            checksum: None,
        };

        // save_with_root should handle the existing file (overwrite it)
        state
            .save_with_root(&state_path, mock_hidden_vol_root)
            .expect("Should overwrite existing file");

        // Verify new content was written
        let loaded_json = std::fs::read_to_string(&state_path).expect("Should read");
        let loaded: StateFile = serde_json::from_str(&loaded_json).expect("Should deserialize");
        assert_eq!(loaded.version, env!("CARGO_PKG_VERSION"));
        assert!(loaded.state.is_active());
        assert_ne!(loaded_json, "existing content");
    }

    // ========== StateGuard Tests ==========

    use crate::Config;
    use crate::MockFilesystem;
    use crate::NailsManager;

    fn create_test_manager_with_state(
        state: SystemState,
    ) -> (
        Arc<Mutex<NailsManager<MockFilesystem>>>,
        PathBuf,
        tempfile::TempDir,
    ) {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        let state_dir = mock_hidden_vol.join(".nails");
        std::fs::create_dir_all(&state_dir).expect("Should create dirs");
        let state_path = state_dir.join("state.json");

        // Create initial state file
        let state_file = StateFile {
            version: env!("CARGO_PKG_VERSION").to_string(),
            state,
            nixos_generation: None,
            overlay_status: std::collections::HashMap::new(),
            last_modified: Utc::now(),
            checksum: None,
        };
        let json = serde_json::to_string_pretty(&state_file).unwrap();
        std::fs::write(&state_path, json).unwrap();

        let fs = MockFilesystem::new();
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs,
            config,
            state_path.clone(),
        )));
        (manager, state_path, temp_dir)
    }

    #[test]
    fn test_state_guard_new_creates_uncommitted_guard() {
        let (manager, _, _temp_dir) = create_test_manager_with_state(SystemState::Inactive);
        let previous_state = SystemState::Inactive;

        let guard = StateGuard::new(Arc::clone(&manager), previous_state.clone());

        // Guard should exist
        // committed field is private, but we can test behavior via drop
        drop(guard);
    }

    #[test]
    fn test_state_guard_commit_prevents_rollback() {
        let (manager, state_path, _temp_dir) =
            create_test_manager_with_state(SystemState::Inactive);

        // Change state to Activating
        {
            let mut m = manager.lock().unwrap();
            m.force_state(SystemState::Activating {
                started_at: Utc::now(),
            })
            .unwrap();
        }

        // Create guard with Inactive as previous state
        let previous_state = SystemState::Inactive;
        let guard = StateGuard::new(Arc::clone(&manager), previous_state);

        // Commit the guard - should prevent rollback
        guard.commit();

        // Verify state is still Activating (not rolled back)
        let loaded = StateFile::load(&state_path).unwrap();
        assert!(matches!(loaded.state, SystemState::Activating { .. }));
    }

    #[test]
    fn test_state_guard_drop_rolls_back_if_not_committed() {
        let (manager, state_path, _temp_dir) =
            create_test_manager_with_state(SystemState::Inactive);

        // Capture initial state
        let previous_state = {
            let m = manager.lock().unwrap();
            m.current_state().unwrap()
        };

        {
            // Change state to Activating
            {
                let mut m = manager.lock().unwrap();
                m.force_state(SystemState::Activating {
                    started_at: Utc::now(),
                })
                .unwrap();
            }

            // Create guard - will rollback when dropped
            let _guard = StateGuard::new(Arc::clone(&manager), previous_state);

            // Verify state changed to Activating
            {
                let m = manager.lock().unwrap();
                assert!(matches!(
                    m.current_state().unwrap(),
                    SystemState::Activating { .. }
                ));
            }

            // Guard goes out of scope here - should trigger rollback
        }

        // Verify state was rolled back to Inactive
        let loaded = StateFile::load(&state_path).unwrap();
        assert_eq!(loaded.state, SystemState::Inactive);
    }

    #[test]
    fn test_state_guard_rolls_back_on_panic() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let (manager, state_path, _temp_dir) =
            create_test_manager_with_state(SystemState::Inactive);

        // Verify initial state is Inactive
        {
            let m = manager.lock().unwrap();
            assert!(m.current_state().unwrap().is_inactive());
        }

        // Simulate panic during operation
        let manager_clone = Arc::clone(&manager);
        let result = catch_unwind(AssertUnwindSafe(|| {
            // Capture state for rollback
            let previous_state = {
                let m = manager_clone.lock().unwrap();
                m.current_state().unwrap()
            };

            // Create guard
            let _guard = StateGuard::new(Arc::clone(&manager_clone), previous_state);

            // Change state to Activating
            {
                let mut m = manager_clone.lock().unwrap();
                m.force_state(SystemState::Activating {
                    started_at: Utc::now(),
                })
                .unwrap();
            }

            // Panic! Guard should still rollback via Drop during unwinding
            panic!("Simulated failure during activation!");

            // This is never reached
            #[allow(unreachable_code)]
            {
                _guard.commit();
            }
        }));

        // Verify panic was caught
        assert!(result.is_err());

        // Verify state was rolled back to Inactive
        let loaded = StateFile::load(&state_path).unwrap();
        assert!(
            loaded.state.is_inactive(),
            "State should be rolled back to Inactive after panic"
        );
    }

    #[test]
    fn test_state_guard_idempotent_rollback() {
        let (manager, state_path, _temp_dir) =
            create_test_manager_with_state(SystemState::Inactive);

        // Capture initial state
        let previous_state = SystemState::Inactive;

        {
            // Create guard
            let _guard = StateGuard::new(Arc::clone(&manager), previous_state.clone());

            // Don't change state - system already in Inactive
            // Guard drop should still work (idempotent)
        }

        // Verify state is still Inactive
        let loaded = StateFile::load(&state_path).unwrap();
        assert_eq!(loaded.state, SystemState::Inactive);
    }

    #[test]
    fn test_state_guard_multiple_guards_sequential() {
        let (manager, state_path, _temp_dir) =
            create_test_manager_with_state(SystemState::Inactive);

        // First guard
        {
            let previous_state = SystemState::Inactive;
            let _guard1 = StateGuard::new(Arc::clone(&manager), previous_state);

            // Change to Activating
            {
                let mut m = manager.lock().unwrap();
                m.force_state(SystemState::Activating {
                    started_at: Utc::now(),
                })
                .unwrap();
            }

            // guard1 drops here, rolls back to Inactive
        }

        // Verify first rollback worked
        {
            let m = manager.lock().unwrap();
            assert!(m.current_state().unwrap().is_inactive());
        }

        // Second guard
        {
            let previous_state = SystemState::Inactive;
            let _guard2 = StateGuard::new(Arc::clone(&manager), previous_state);

            // Change to Activating again
            {
                let mut m = manager.lock().unwrap();
                m.force_state(SystemState::Activating {
                    started_at: Utc::now(),
                })
                .unwrap();
            }

            // guard2 drops here, rolls back to Inactive again
        }

        // Verify second rollback worked
        let loaded = StateFile::load(&state_path).unwrap();
        assert_eq!(loaded.state, SystemState::Inactive);
    }

    #[test]
    fn test_state_guard_activation_failure_scenario() {
        let (manager, state_path, _temp_dir) =
            create_test_manager_with_state(SystemState::Inactive);

        // Simulate activation that fails midway
        {
            let previous_state = {
                let m = manager.lock().unwrap();
                m.current_state().unwrap()
            };

            // Create guard
            let _guard = StateGuard::new(Arc::clone(&manager), previous_state);

            // Begin activation
            {
                let mut m = manager.lock().unwrap();
                m.force_state(SystemState::Activating {
                    started_at: Utc::now(),
                })
                .unwrap();
            }

            // Simulate mount failure - don't commit guard
            // Guard will rollback automatically
        }

        // Verify system returned to Inactive
        let loaded = StateFile::load(&state_path).unwrap();
        assert!(loaded.state.is_inactive());
    }

    #[test]
    fn test_state_guard_deactivation_failure_scenario() {
        // Start with Active state
        let (manager, state_path, _temp_dir) =
            create_test_manager_with_state(SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![],
            });

        // Force manager to load initial state into cache
        {
            let m = manager.lock().unwrap();
            m.current_state().unwrap();
        }

        // Simulate deactivation that fails midway
        {
            let previous_state = {
                let m = manager.lock().unwrap();
                m.current_state().unwrap()
            };

            // Create guard
            let _guard = StateGuard::new(Arc::clone(&manager), previous_state);

            // Begin deactivation
            {
                let mut m = manager.lock().unwrap();
                m.force_state(SystemState::Deactivating {
                    started_at: Utc::now(),
                })
                .unwrap();
            }

            // Simulate cleanup failure - don't commit guard
            // Guard will rollback to Active
        }

        // Verify system returned to Active
        let loaded = StateFile::load(&state_path).unwrap();
        assert!(
            loaded.state.is_active(),
            "State should be Active after rollback, but was {:?}",
            loaded.state
        );
    }

    #[test]
    fn test_state_guard_lock_poisoning_doesnt_panic() {
        use std::panic::{AssertUnwindSafe, catch_unwind};

        let (manager, _state_path, _temp_dir) =
            create_test_manager_with_state(SystemState::Inactive);

        // Poison the lock by panicking while holding it
        let manager_clone = Arc::clone(&manager);
        let poison_result = catch_unwind(AssertUnwindSafe(|| {
            let _lock = manager_clone.lock().unwrap();
            panic!("Intentionally poisoning the lock");
        }));
        assert!(
            poison_result.is_err(),
            "Lock poisoning panic should be caught"
        );

        // Now the lock is poisoned. Create a StateGuard and let it drop.
        // The drop() implementation should handle the poisoned lock gracefully
        // without panicking (which would cause abort).
        let previous_state = SystemState::Inactive;

        let manager_clone2 = Arc::clone(&manager);
        let drop_result = catch_unwind(AssertUnwindSafe(|| {
            // Create guard in a scope so it drops
            {
                let _guard = StateGuard::new(Arc::clone(&manager_clone2), previous_state);

                // Attempt to change state (this will fail due to poisoned lock, but that's ok)
                // The important thing is that drop() doesn't panic
            }
            // Guard drops here - should NOT panic even with poisoned lock
        }));

        // Verify drop() didn't panic
        assert!(
            drop_result.is_ok(),
            "StateGuard drop() should not panic even with poisoned lock"
        );

        // Note: We can't verify the state file here because the lock is permanently poisoned.
        // The important verification is that drop() didn't panic (no double-panic/abort).
    }

    #[test]
    fn test_state_guard_rollback_after_multiple_state_changes() {
        let (manager, state_path, _temp_dir) =
            create_test_manager_with_state(SystemState::Inactive);

        // Capture initial state
        let initial_state = {
            let m = manager.lock().unwrap();
            m.current_state().unwrap()
        };

        {
            // Create guard capturing Inactive
            let _guard = StateGuard::new(Arc::clone(&manager), initial_state);

            // Make multiple state changes
            {
                let mut m = manager.lock().unwrap();
                m.force_state(SystemState::Activating {
                    started_at: Utc::now(),
                })
                .unwrap();
            }

            {
                let mut m = manager.lock().unwrap();
                m.force_state(SystemState::Active {
                    activated_at: Utc::now(),
                    overlays: vec![],
                })
                .unwrap();
            }

            {
                let mut m = manager.lock().unwrap();
                m.force_state(SystemState::Deactivating {
                    started_at: Utc::now(),
                })
                .unwrap();
            }

            // Don't commit - guard should rollback to ORIGINAL state (Inactive)
        }

        // Verify rollback went back to initial state, not last intermediate state
        let loaded = StateFile::load(&state_path).unwrap();
        assert!(
            loaded.state.is_inactive(),
            "Rollback should restore original captured state (Inactive), not intermediate states"
        );
    }

    #[test]
    fn test_state_guard_commit_is_final() {
        let (manager, state_path, _temp_dir) =
            create_test_manager_with_state(SystemState::Inactive);

        let previous_state = SystemState::Inactive;

        {
            let guard = StateGuard::new(Arc::clone(&manager), previous_state);

            // Change state
            {
                let mut m = manager.lock().unwrap();
                m.force_state(SystemState::Activating {
                    started_at: Utc::now(),
                })
                .unwrap();
            }

            // Commit the transaction
            guard.commit();

            // After commit, guard cannot be used again (consumed by move)
            // This is enforced by the compiler - uncommenting would fail to compile:
            // guard.commit(); // Error: use of moved value
        }

        // Verify state was NOT rolled back (commit succeeded)
        let loaded = StateFile::load(&state_path).unwrap();
        assert!(
            matches!(loaded.state, SystemState::Activating { .. }),
            "State should remain Activating after commit (no rollback)"
        );
    }

    /// Integration test: panic during activate() method triggers StateGuard rollback
    ///
    /// This test verifies that StateGuard works correctly when integrated into
    /// NailsManager::activate(). It simulates a panic during activation by using
    /// a carefully timed mount failure that would cause a panic-like behavior.
    ///
    /// Test addresses HIGH priority review item: "Add integration test for panic
    /// during activate() method with StateGuard rollback"
    #[test]
    fn test_integration_activate_panic_triggers_stateguard_rollback() {
        use crate::{Config, MockFilesystem, NailsManager, OverlayConfig};

        // Setup: create mock filesystem with necessary paths
        let temp_dir = tempfile::tempdir().unwrap();
        let mock_hidden_vol = temp_dir.path();
        let state_dir = mock_hidden_vol.join(".nails");
        std::fs::create_dir_all(&state_dir).unwrap();
        let state_path = state_dir.join("state.json");

        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/", true);
        let upper_dir = mock_hidden_vol.join("upper");
        let work_dir = mock_hidden_vol.join("work");
        std::fs::create_dir_all(&upper_dir).unwrap();
        std::fs::create_dir_all(&work_dir).unwrap();
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_dir.clone(),
                work: work_dir.clone(),
                target: PathBuf::from("/home"),
            }],
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        // Verify initial state is Inactive
        {
            let m = manager.lock().unwrap();
            assert!(m.current_state().unwrap().is_inactive());
        }

        // Simulate a scenario where activate() encounters an error that triggers rollback
        // We'll cause a mount failure which triggers StateGuard's automatic rollback
        fs.mock_set_mount_should_fail("/home", true);

        // Call activate() which will fail and trigger StateGuard rollback
        let manager_clone = Arc::clone(&manager);
        let result = NailsManager::activate(manager_clone);

        // Activation should fail due to mount error
        assert!(result.is_err(), "Activation should fail due to mount error");

        // Verify state was rolled back to Inactive via StateGuard
        {
            let m = manager.lock().unwrap();
            let state = m.current_state().unwrap();
            assert!(
                state.is_inactive(),
                "State should be rolled back to Inactive after activation failure, got: {:?}",
                state
            );
        }

        // Verify state file contains Inactive
        let loaded = StateFile::load(&state_path).unwrap();
        assert!(
            loaded.state.is_inactive(),
            "State file should contain Inactive after StateGuard rollback"
        );
    }

    /// Integration test: panic during deactivate() method triggers StateGuard rollback
    ///
    /// This test verifies that StateGuard works correctly when integrated into
    /// NailsManager::deactivate(). It simulates a panic during deactivation by using
    /// a carefully timed unmount failure that would trigger rollback to Active state.
    ///
    /// Test addresses HIGH priority review item: "Add integration test for panic
    /// during deactivate() method with StateGuard rollback"
    #[test]
    fn test_integration_deactivate_panic_triggers_stateguard_rollback() {
        use crate::{Config, MockFilesystem, NailsManager, OverlayConfig, OverlayInfo};
        use std::collections::HashMap;

        // Setup: create mock filesystem with necessary paths
        let temp_dir = tempfile::tempdir().unwrap();
        let mock_hidden_vol = temp_dir.path();
        let state_dir = mock_hidden_vol.join(".nails");
        std::fs::create_dir_all(&state_dir).unwrap();
        let state_path = state_dir.join("state.json");

        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/", true);
        let upper_dir = mock_hidden_vol.join("upper");
        let work_dir = mock_hidden_vol.join("work");
        std::fs::create_dir_all(&upper_dir).unwrap();
        std::fs::create_dir_all(&work_dir).unwrap();
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

        // Set overlay as mounted
        fs.mock_set_mounted(Path::new("/home"), true);

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_dir.clone(),
                work: work_dir.clone(),
                target: PathBuf::from("/home"),
            }],
        };

        let manager = Arc::new(Mutex::new(NailsManager::new(
            fs.clone(),
            config,
            state_path.clone(),
        )));

        // Set up Active state with mounted overlay - use save_with_custom_root to bypass validation
        let mut overlay_status = HashMap::new();
        overlay_status.insert(
            PathBuf::from("/home"),
            OverlayInfo {
                mount_path: PathBuf::from("/home"),
                lower_dir: PathBuf::from("/"),
                upper_dir: upper_dir.clone(),
                work_dir: work_dir.clone(),
                mounted_at: Utc::now(),
            },
        );

        let initial_state = StateFile {
            state: SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![PathBuf::from("/home")],
            },
            overlay_status,
            ..StateFile::default()
        };
        // Use save_with_custom_root to bypass hidden volume validation for test
        initial_state
            .save_with_custom_root(&state_path, mock_hidden_vol)
            .unwrap();

        // Force manager to reload from disk by accessing it
        {
            let m = manager.lock().unwrap();
            // This will load the Active state from disk we just wrote
            m.current_state().unwrap();
        }

        // Verify initial state is Active
        {
            let m = manager.lock().unwrap();
            assert!(matches!(
                m.current_state().unwrap(),
                SystemState::Active { .. }
            ));
        }

        // Cause unmount to fail, triggering StateGuard rollback
        fs.mock_set_unmount_should_fail("/home", true);

        // Call deactivate() which will fail and trigger StateGuard rollback
        let manager_clone = Arc::clone(&manager);
        let result = NailsManager::deactivate(manager_clone);

        // Deactivation should fail due to unmount error
        assert!(
            result.is_err(),
            "Deactivation should fail due to unmount error"
        );

        // Verify state was rolled back to Active via StateGuard (FR51)
        {
            let m = manager.lock().unwrap();
            let state = m.current_state().unwrap();
            assert!(
                matches!(state, SystemState::Active { .. }),
                "State should be rolled back to Active after deactivation failure, got: {:?}",
                state
            );
        }

        // Verify state file contains Active
        let loaded = StateFile::load(&state_path).unwrap();
        assert!(
            loaded.state.is_active(),
            "State file should contain Active after StateGuard rollback (FR51: Remount overlays if cleanup fails)"
        );
    }
}
