//! # State File Persistence
//!
//! `StateFile` struct and its save/load/checksum logic for persisting
//! system state to the hidden volume.

#[cfg(not(test))]
use super::is_on_hidden_volume;
#[cfg(test)]
use super::is_on_hidden_volume_internal;
use super::{FailedOverlayInfo, SystemState};
use crate::{NailsError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::OverlayInfo;

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
    pub overlay_status: HashMap<PathBuf, OverlayInfo>,

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
            overlay_status: HashMap::new(),
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
        use crate::obfuscate;
        self.save_with_root(
            path,
            hidden_volume_root
                .to_str()
                .unwrap_or(&obfuscate::hidden_volume_root()),
        )
    }

    /// Save state file with custom hidden volume root (for testing)
    #[cfg(test)]
    pub(crate) fn save_with_root(&self, path: &Path, hidden_volume_root: &str) -> Result<()> {
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
        // 1. Compute checksum over state with checksum=None for deterministic hashing
        let mut for_hash = self.clone();
        for_hash.checksum = None;
        let hash_value = serde_json::to_value(&for_hash).map_err(|e| {
            NailsError::ConfigError(format!("Failed to serialize state for checksum: {}", e))
        })?;
        let hash_json = hash_value.to_string();

        use sha2::Digest;
        let hash = sha2::Sha256::digest(hash_json.as_bytes());
        let hex_hash = hex::encode(hash);

        // 2. Create final version with checksum populated
        let mut final_state = self.clone();
        final_state.checksum = Some(hex_hash);

        let json = serde_json::to_string_pretty(&final_state)
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

        // 5. Set permissions to 0600 (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(temp.path())?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(temp.path(), perms)?;
        }

        // 6. Atomic rename (single syscall on POSIX)
        match temp.persist_noclobber(path) {
            Ok(_) => Ok(()),
            Err(e) => {
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
                // Version compatibility check
                let current_version = env!("CARGO_PKG_VERSION");
                let stored_version = &state_file.version;

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

                if stored_version != current_version {
                    tracing::info!(
                        current_version = %current_version,
                        stored_version = %stored_version,
                        "State file version differs from current version (loading anyway - compatible)"
                    );
                    state_file.version = current_version.to_string();
                }

                // Checksum verification for tamper detection
                match &state_file.checksum {
                    Some(stored_checksum) => {
                        let mut for_hash = state_file.clone();
                        for_hash.checksum = None;
                        let hash_value = serde_json::to_value(&for_hash).map_err(|e| {
                            NailsError::ConfigError(format!(
                                "Failed to serialize state for checksum verification: {}",
                                e
                            ))
                        })?;
                        let hash_json = hash_value.to_string();

                        use sha2::Digest;
                        let computed = hex::encode(sha2::Sha256::digest(hash_json.as_bytes()));

                        if &computed != stored_checksum {
                            return Err(NailsError::ChecksumMismatch(format!(
                                "State file at {} has been tampered with (expected {}, got {})",
                                path.display(),
                                stored_checksum,
                                computed
                            )));
                        }
                    }
                    None => {
                        tracing::warn!(
                            path = %path.display(),
                            "State file has no checksum (migration from older version) - accepting without verification"
                        );
                    }
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
