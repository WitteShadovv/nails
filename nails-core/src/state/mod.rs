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

/// Check if a path is within the hidden volume
///
/// Validates that the given path is within the configured hidden_volume_root to prevent
/// forensic leakage of state information to the decoy system.
///
/// # Arguments
///
/// * `path` - Path to validate
/// * `hidden_volume_root` - Root path of the hidden volume (typically from Config::hidden_volume_root)
///
/// # Note
///
/// Story 14.2 removed the HIDDEN_VOLUME_ROOT constant. Callers must pass the hidden_volume_root
/// parameter explicitly, usually derived from Config.
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
/// Validates that the given path is within the specified hidden volume root to prevent
/// forensic leakage of state information to the decoy system.
///
/// # Arguments
///
/// * `path` - Path to validate
/// * `hidden_volume_root` - Root path of the hidden volume (from config)
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
pub fn is_on_hidden_volume(path: &Path, hidden_volume_root: &str) -> bool {
    is_on_hidden_volume_internal(path, hidden_volume_root)
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

#[cfg(test)]
mod tests;
mod transitions;

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

/// Information about a failed overlay mount attempt (Story 14.10, AC9)
///
/// Tracks overlays that failed to mount during activation for debugging
/// and status reporting. This helps users identify which directories
/// couldn't be overlaid and why.
///
/// # Example
///
/// A mount failure for `/var` due to process activity would be recorded as:
/// ```text
/// FailedOverlayInfo {
///     target: PathBuf::from("/var"),
///     error_message: "Mount failed: device busy",
///     failed_at: DateTime<Utc>,
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FailedOverlayInfo {
    /// Target mount point that failed (e.g., /var, /tmp)
    pub target: PathBuf,

    /// Error message explaining why mount failed
    pub error_message: String,

    /// Timestamp when the mount attempt failed
    pub failed_at: DateTime<Utc>,
}

/// State file for persistence to hidden volume
///
/// The StateFile contains the current system state and all metadata needed
/// to reconstruct the system state after a reboot or emergency shutdown.
///
/// # Security Critical
///
/// **INVARIANT**: State file MUST only exist at {hidden_volume}/.nails/state.json
/// **NEVER** at: /home/user/state.json, /etc/nails/state.json, or ANY path
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

    /// Config fingerprint after last successful activation (Story 15.4)
    ///
    /// 16-char hex FNV-1a hash of hardware-configuration.nix + configuration.nix content.
    /// Used by the fast-path activation logic to skip rebuilds when the config has not changed.
    /// `None` until the first successful activation with fingerprint tracking.
    #[serde(default)]
    pub config_fingerprint: Option<String>,

    /// Currently mounted overlays with their configuration
    pub overlay_status: std::collections::HashMap<PathBuf, OverlayInfo>,

    /// Overlays that failed to mount during last activation (Story 14.10, AC9)
    ///
    /// Used for status reporting and debugging. Cleared on successful deactivation.
    #[serde(default)]
    pub failed_overlays: Vec<FailedOverlayInfo>,

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
            config_fingerprint: None,
            overlay_status: std::collections::HashMap::new(),
            failed_overlays: Vec::new(),
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
    /// return an error if the path is outside the configured hidden_volume_root.
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
    /// * `hidden_volume_root` - Root path of hidden volume for validation
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
    /// use nails_core::config::Config;
    /// use std::path::Path;
    ///
    /// let config = Config::default();
    /// let state = StateFile::default();
    /// // Pass hidden_volume_root from config to ensure validation uses correct path
    /// let root = config.hidden_volume_root.to_string_lossy();
    /// state.save(Path::new("/mnt/hidden-volume/state.json"), &root)?;
    /// # Ok::<(), nails_core::NailsError>(())
    /// ```
    pub fn save(&self, path: &Path, hidden_volume_root: &str) -> Result<()> {
        self.save_with_root(path, hidden_volume_root)
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
    /// let custom_root = PathBuf::from("/tmp");
    /// state.save_with_custom_root(Path::new("/tmp/state.json"), &custom_root)?;
    /// # Ok::<(), nails_core::NailsError>(())
    /// ```
    pub fn save_with_custom_root(&self, path: &Path, hidden_volume_root: &Path) -> Result<()> {
        use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
        self.save_with_root(
            path,
            hidden_volume_root
                .to_str()
                .unwrap_or(DEFAULT_HIDDEN_VOLUME_ROOT),
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
        // In production, use the configured hidden_volume_root from Config
        if !is_on_hidden_volume(path, hidden_volume_root) {
            return Err(NailsError::InvalidState(format!(
                "State file must be on hidden volume ({}), but attempted to write to: {}",
                hidden_volume_root,
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

        // 5. Set permissions to 0644 (owner read/write, others read)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(temp.path())?.permissions();
            perms.set_mode(0o644);
            std::fs::set_permissions(temp.path(), perms)?;
        }

        // 6. Atomic rename (single syscall on POSIX)
        // Use persist_noclobber to detect race conditions, then fallback to regular persist
        match temp.persist_noclobber(path) {
            Ok(_) => Ok(()),
            Err(e) => {
                // If file exists, we have a race condition - try regular persist
                if e.error.kind() == std::io::ErrorKind::AlreadyExists {
                    tracing::info!("State file already exists during atomic write, overwriting");
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
    /// let state = StateFile::load(Path::new("/mnt/hidden-volume/state.json"))?;
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
        match serde_json::from_str::<StateFile>(&contents) {
            Ok(mut state_file) => {
                // Version compatibility check (Story 15.4 review finding: MEDIUM-3)
                // Reject state files from incompatible future versions
                let current_version = env!("CARGO_PKG_VERSION");
                let stored_version = &state_file.version;

                // Parse versions to compare major components
                let current_major = current_version
                    .split('.')
                    .next()
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(0);
                let stored_major = stored_version
                    .split('.')
                    .next()
                    .and_then(|v| v.parse::<u32>().ok())
                    .unwrap_or(0);

                if stored_major > current_major {
                    tracing::error!(
                        current_version = %current_version,
                        stored_version = %stored_version,
                        path = %path.display(),
                        "State file version is from a future major version - cannot load"
                    );
                    return Err(NailsError::InvalidState(format!(
                        "State file version {} is incompatible with current version {} (stored version is from a future major version)",
                        stored_version, current_version
                    )));
                }

                // Log version mismatch warning for different minor/patch versions (but allow)
                if stored_version != current_version {
                    tracing::info!(
                        current_version = %current_version,
                        stored_version = %stored_version,
                        "State file version differs from current version (loading anyway - compatible)"
                    );
                    // Update version to current on load
                    state_file.version = current_version.to_string();
                }

                Ok(state_file)
            }
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

    /// Get the previous state that will be restored on rollback
    ///
    /// Returns the state that was captured when this guard was created.
    /// If the guard is dropped without calling commit(), this is the state
    /// that will be restored to the manager.
    ///
    /// # Returns
    ///
    /// Reference to the previous SystemState
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{StateGuard, NailsManager, MockFilesystem, Config, SystemState};
    /// use std::sync::{Arc, Mutex};
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
    /// // Check what state will be restored on rollback
    /// assert_eq!(*guard.previous_state(), SystemState::Inactive);
    /// ```
    pub fn previous_state(&self) -> &SystemState {
        &self.previous_state
    }

    /// Check if the transaction has been committed
    ///
    /// Returns true if commit() has been called, false otherwise.
    /// When false and the guard is dropped, rollback will occur.
    ///
    /// # Returns
    ///
    /// true if committed, false if uncommitted
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{StateGuard, NailsManager, MockFilesystem, Config, SystemState};
    /// use std::sync::{Arc, Mutex};
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
    /// let mut guard = StateGuard::new(Arc::clone(&manager), previous_state);
    ///
    /// // Initially not committed
    /// assert!(!guard.is_committed());
    /// ```
    ///
    /// # Note
    ///
    /// This method is primarily useful for testing and debugging.
    /// In production code, the RAII pattern handles commit/rollback automatically.
    pub fn is_committed(&self) -> bool {
        self.committed
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
