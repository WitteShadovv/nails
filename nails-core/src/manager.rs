//! # NailsManager - Core Orchestrator for NAILS Operations
//!
//! Central orchestrator that coordinates all NAILS operations including state
//! transitions, filesystem operations, and validation logic.
//!
//! # Design Pattern: Generic Manager with Dependency Injection
//!
//! NailsManager uses generic programming to enable compile-time polymorphism:
//! - Production: `NailsManager<RealFilesystem>` uses actual syscalls
//! - Testing: `NailsManager<MockFilesystem>` uses in-memory state (no root required)
//!
//! This pattern enables 99% of tests to run without root privileges (AR4, NFR37).
//!
//! # Example
//!
//! ```rust
//! use nails_core::{NailsManager, MockFilesystem, Config};
//! use std::path::PathBuf;
//!
//! // Testing: MockFilesystem (no root required)
//! let fs = MockFilesystem::new();
//! let config = Config::default();
//! let state_path = PathBuf::from("/tmp/test-state.json");
//! let manager = NailsManager::new(fs, config, state_path);
//!
//! // Production: RealFilesystem (requires root)
//! // let fs = RealFilesystem;
//! // let manager = NailsManager::new(fs, config, state_path);
//! ```

use crate::{Config, Filesystem, NailsError, OverlayInfo, Result, StateFile, SystemState};
use chrono::Utc;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Central orchestrator for all NAILS operations
///
/// NailsManager coordinates state transitions, filesystem operations,
/// and validation logic. The generic Filesystem parameter enables
/// testing without root privileges.
///
/// # Fields
///
/// - `filesystem`: Generic filesystem implementation (real or mock)
/// - `config`: Application configuration
/// - `state_file_path`: Path to state file (on hidden volume)
/// - `cached_state`: Cached state file (lazy loaded, thread-safe)
///
/// # Thread Safety
///
/// `cached_state` uses `Arc<Mutex<_>>` for thread-safe lazy loading.
/// While NAILS is single-threaded in Phase 1 (AR47), this pattern enables
/// future extensions and parallel testing.
///
/// # Requirements
///
/// - AR3: Core library contains all business logic
/// - AR4: Testable without root via trait abstraction
/// - AR44: Generic NailsManager<F: Filesystem> pattern
#[derive(Debug)]
pub struct NailsManager<F: Filesystem> {
    /// Filesystem implementation (real or mock)
    filesystem: F,

    /// Application configuration
    config: Config,

    /// Path to state file (on hidden volume)
    state_file_path: PathBuf,

    /// Cached state file (lazy loaded, thread-safe)
    /// Arc<Mutex<_>> enables thread-safe access and clone implementation
    cached_state: Arc<Mutex<Option<StateFile>>>,
}

impl<F: Filesystem> NailsManager<F> {
    /// Create a new NailsManager with lazy loading
    ///
    /// The constructor stores all parameters but does NOT load state from disk.
    /// State is loaded lazily on first access via `current_state()`.
    ///
    /// # Arguments
    ///
    /// * `filesystem` - Filesystem implementation (RealFilesystem or MockFilesystem)
    /// * `config` - Application configuration
    /// * `state_file_path` - Path to state file (must be on hidden volume)
    ///
    /// # Returns
    ///
    /// New NailsManager instance with unloaded state (None).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/mnt/hidden-volume/.nails/state.json");
    /// let manager = NailsManager::new(fs, config, state_path);
    /// ```
    pub fn new(filesystem: F, config: Config, state_file_path: PathBuf) -> Self {
        Self {
            filesystem,
            config,
            state_file_path,
            cached_state: Arc::new(Mutex::new(None)),
        }
    }

    /// Get current system state with lazy loading
    ///
    /// First call loads from disk and caches result.
    /// Subsequent calls return cached value.
    ///
    /// # Graceful Degradation (AR27, AR53)
    ///
    /// Returns Inactive if file missing or malformed (safe default).
    /// Logs warning when using default Inactive state.
    ///
    /// # Returns
    ///
    /// * `Ok(SystemState)` - Current state or Inactive if file missing/malformed
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config, SystemState};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/mnt/hidden-volume/.nails/state.json");
    /// let manager = NailsManager::new(fs, config, state_path);
    ///
    /// // First call loads from disk (lazy)
    /// let state = manager.current_state().unwrap();
    /// assert_eq!(state, SystemState::Inactive); // Default if file missing
    ///
    /// // Second call uses cache
    /// let state2 = manager.current_state().unwrap();
    /// assert_eq!(state, state2);
    /// ```
    pub fn current_state(&self) -> Result<SystemState> {
        let mut cached = self.cached_state.lock().unwrap();

        // If cached, return immediately
        if let Some(ref state_file) = *cached {
            return Ok(state_file.state.clone());
        }

        // Lazy load from disk
        // Note: StateFile::load() handles warning logs for missing/malformed files
        // and returns default Inactive state per AR27, AR53. This keeps the logging
        // logic centralized in the StateFile module.
        let state_file = StateFile::load(&self.state_file_path)?;
        let state = state_file.state.clone();

        // Cache for future calls
        *cached = Some(state_file);

        Ok(state)
    }

    /// Update system state with validation
    ///
    /// Validates the transition is legal before persisting.
    /// Updates cached state after successful save.
    ///
    /// # Arguments
    ///
    /// * `new_state` - Target state to transition to
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Transition successful, state saved
    /// * `Err(NailsError::InvalidState)` - Invalid transition
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nails_core::{NailsManager, MockFilesystem, Config, SystemState};
    /// use std::path::PathBuf;
    ///
    /// let temp_dir = tempfile::tempdir().unwrap();
    /// let mock_hidden_vol = temp_dir.path();
    /// let state_dir = mock_hidden_vol.join(".nails");
    /// std::fs::create_dir_all(&state_dir).unwrap();
    /// let state_path = state_dir.join("state.json");
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config {
    ///     hidden_volume_root: mock_hidden_vol.to_path_buf(),
    ///     state_file_path: state_path.clone(),
    ///     overlays: vec![],
    /// };
    /// let mut manager = NailsManager::new(fs, config, state_path);
    ///
    /// // Valid transition: Inactive -> Activating
    /// let result = manager.update_state(SystemState::Activating {
    ///     started_at: chrono::Utc::now(),
    /// });
    /// assert!(result.is_ok());
    /// ```
    pub fn update_state(&mut self, new_state: SystemState) -> Result<()> {
        // Load current state (uses cache if available)
        let current = self.current_state()?;

        // Validate transition using the same rules as SystemState transition methods
        // (begin_activation, complete_activation, begin_deactivation, complete_deactivation, trigger_emergency)
        //
        // Note: We can't use the transition methods directly here because they create
        // the new state with timestamps. This method accepts pre-constructed states,
        // which is necessary for testing and special cases.
        let is_valid = match (&current, &new_state) {
            (SystemState::Inactive, SystemState::Activating { .. }) => true,
            (SystemState::Activating { .. }, SystemState::Active { .. }) => true,
            (SystemState::Active { .. }, SystemState::Deactivating { .. }) => true,
            (SystemState::Deactivating { .. }, SystemState::Inactive) => true,
            (_, SystemState::Emergency { .. }) => true, // Emergency always allowed
            _ if current == new_state => true,          // Same state is allowed (idempotent)
            _ => false,
        };

        if !is_valid {
            return Err(NailsError::InvalidState(format!(
                "Invalid state transition: {:?} -> {:?}",
                current, new_state
            )));
        }

        // Update state file
        let mut cached = self.cached_state.lock().unwrap();
        let mut state_file = cached.take().unwrap_or_default();
        state_file.state = new_state;
        state_file.last_modified = Utc::now();

        // Save to disk with configured hidden volume root
        state_file.save_with_custom_root(&self.state_file_path, &self.config.hidden_volume_root)?;

        // Update cache
        *cached = Some(state_file);

        Ok(())
    }

    /// Verify state file matches actual system state
    ///
    /// Checks that all overlays listed in state file are actually
    /// mounted (for Active) or unmounted (for Inactive).
    ///
    /// # Returns
    ///
    /// * `Ok(())` - State file matches actual system state
    /// * `Err(NailsError::InvalidState)` - Mismatch detected with details
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config};
    /// use std::path::{Path, PathBuf};
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/tmp/test-state.json");
    /// let manager = NailsManager::new(fs, config, state_path);
    ///
    /// // Verify state matches reality
    /// let result = manager.verify_state();
    /// assert!(result.is_ok());
    /// ```
    pub fn verify_state(&self) -> Result<()> {
        // Fresh read from disk (bypass cache)
        let state_file = StateFile::load(&self.state_file_path)?;

        // Check each overlay
        for (path, overlay_info) in &state_file.overlay_status {
            let is_mounted = self.filesystem.is_mounted(&overlay_info.mount_path)?;

            match &state_file.state {
                SystemState::Active { .. } => {
                    if !is_mounted {
                        return Err(NailsError::InvalidState(format!(
                            "State mismatch: {} should be mounted but is not",
                            path.display()
                        )));
                    }
                }
                SystemState::Inactive => {
                    if is_mounted {
                        return Err(NailsError::InvalidState(format!(
                            "State mismatch: {} should not be mounted but is",
                            path.display()
                        )));
                    }
                }
                _ => {
                    // Transitional states (Activating, Deactivating, Emergency) are skipped
                    // because:
                    // - Activating: Overlays are being mounted, partial state is expected
                    // - Deactivating: Overlays are being unmounted, partial state is expected
                    // - Emergency: System may be in inconsistent state by definition
                    //
                    // These states are short-lived and verification is meaningless during
                    // the transition. Verification is only useful for stable states
                    // (Active, Inactive) to detect drift.
                }
            }
        }

        Ok(())
    }

    /// Placeholder activate() method (full implementation in Epic 4)
    ///
    /// Validates current state is Inactive, transitions through Activating,
    /// mounts overlays, and transitions to Active.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Activation successful
    /// * `Err(NailsError::InvalidState)` - Cannot activate from current state
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nails_core::{NailsManager, MockFilesystem, Config, OverlayConfig};
    /// use std::path::PathBuf;
    ///
    /// let temp_dir = tempfile::tempdir().unwrap();
    /// let mock_hidden_vol = temp_dir.path();
    /// let state_dir = mock_hidden_vol.join(".nails");
    /// std::fs::create_dir_all(&state_dir).unwrap();
    /// let state_path = state_dir.join("state.json");
    ///
    /// let fs = MockFilesystem::new();
    ///
    /// // Set up paths to exist
    /// fs.mock_set_path_exists("/", true);
    /// let upper_dir = mock_hidden_vol.join("overlays/home/upper");
    /// let work_dir = mock_hidden_vol.join("overlays/home/work");
    /// std::fs::create_dir_all(&upper_dir).unwrap();
    /// std::fs::create_dir_all(&work_dir).unwrap();
    /// fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    /// fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);
    ///
    /// let config = Config {
    ///     hidden_volume_root: mock_hidden_vol.to_path_buf(),
    ///     state_file_path: state_path.clone(),
    ///     overlays: vec![OverlayConfig {
    ///         name: "home".to_string(),
    ///         lower: PathBuf::from("/"),
    ///         upper: upper_dir.clone(),
    ///         work: work_dir.clone(),
    ///         target: PathBuf::from("/home"),
    ///     }],
    /// };
    ///
    /// let mut manager = NailsManager::new(fs, config, state_path);
    ///
    /// // Activate should mount the overlay
    /// let result = manager.activate();
    /// assert!(result.is_ok());
    /// ```
    pub fn activate(&mut self) -> Result<()> {
        // Load current state
        let current = self.current_state()?;

        // Use SystemState transition method to validate and transition to Activating
        let activating_state = current.begin_activation()?;
        self.update_state(activating_state)?;

        // Mount overlays
        // Note: Error handling is intentional per AC6 - we log errors but continue.
        // Full rollback logic will be implemented in Story 2.4.
        let mut mounted_overlays = Vec::new();
        for overlay in &self.config.overlays {
            match self.filesystem.mount_overlay(
                &overlay.lower,
                &overlay.upper,
                &overlay.work,
                &overlay.target,
            ) {
                Ok(()) => {
                    mounted_overlays.push(overlay.target.clone());
                }
                Err(e) => {
                    // AC6: Log error but continue (rollback in Story 2.4)
                    tracing::error!("Failed to mount overlay {}: {}", overlay.name, e);
                }
            }
        }

        // Populate overlay_status BEFORE transitioning to Active (fixes double-save bug)
        let mut overlay_status = HashMap::new();
        for overlay in &self.config.overlays {
            if mounted_overlays.contains(&overlay.target) {
                overlay_status.insert(
                    overlay.target.clone(),
                    OverlayInfo {
                        mount_path: overlay.target.clone(),
                        lower_dir: overlay.lower.clone(),
                        upper_dir: overlay.upper.clone(),
                        work_dir: overlay.work.clone(),
                        mounted_at: Utc::now(),
                    },
                );
            }
        }

        // Update overlay_status in cached state BEFORE calling complete_activation
        {
            let mut cached = self.cached_state.lock().unwrap();
            if let Some(ref mut state_file) = *cached {
                state_file.overlay_status = overlay_status;
            }
        }

        // Use SystemState transition method to transition to Active
        let current = self.current_state()?;
        let active_state = current.complete_activation(mounted_overlays)?;
        self.update_state(active_state)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockFilesystem;
    use std::collections::HashMap;
    use std::path::Path;

    fn create_test_manager() -> NailsManager<MockFilesystem> {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let state_path = PathBuf::from("/mnt/hidden-volume/.nails/state.json");
        NailsManager::new(fs, config, state_path)
    }

    // ========== Task 3: Constructor Tests ==========

    #[test]
    fn test_new_stores_all_parameters() {
        let fs = MockFilesystem::new();
        let config = Config {
            hidden_volume_root: PathBuf::from("/mnt/test-hidden"),
            state_file_path: PathBuf::from("/mnt/test-hidden/.nails/state.json"),
            overlays: vec![],
        };
        let state_path = PathBuf::from("/mnt/test-hidden/.nails/state.json");

        let manager = NailsManager::new(fs, config.clone(), state_path.clone());

        // Verify fields are stored (we can't directly access private fields,
        // but we can verify behavior in other tests)
        assert_eq!(manager.state_file_path, state_path);
        assert_eq!(manager.config, config);
    }

    #[test]
    fn test_new_does_not_load_state() {
        let fs = MockFilesystem::new();
        let config = Config::default();
        let state_path = PathBuf::from("/nonexistent/path/state.json");

        // Constructor should NOT fail even with invalid path
        // because it doesn't load state (lazy loading)
        let manager = NailsManager::new(fs, config, state_path);

        // State is not loaded yet
        let cached = manager.cached_state.lock().unwrap();
        assert!(cached.is_none());
    }

    #[test]
    fn test_new_initializes_cached_state_to_none() {
        let manager = create_test_manager();

        // Verify cached_state is None (not yet loaded)
        let cached = manager.cached_state.lock().unwrap();
        assert!(cached.is_none());
    }

    #[test]
    fn test_new_with_different_filesystem_implementations() {
        // Test with MockFilesystem
        let mock_fs = MockFilesystem::new();
        let config = Config::default();
        let state_path = PathBuf::from("/mnt/hidden-volume/.nails/state.json");
        let _mock_manager = NailsManager::new(mock_fs, config.clone(), state_path.clone());

        // Test with RealFilesystem (just verify compilation)
        use crate::RealFilesystem;
        let real_fs = RealFilesystem;
        let _real_manager = NailsManager::new(real_fs, config, state_path);
    }

    // ========== Task 4: current_state() Tests ==========

    #[test]
    fn test_current_state_lazy_loads_on_first_access() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let state_path = temp_dir.path().join("state.json");

        let fs = MockFilesystem::new();
        let config = Config::default();
        let manager = NailsManager::new(fs, config, state_path);

        // Verify state not loaded yet
        {
            let cached = manager.cached_state.lock().unwrap();
            assert!(cached.is_none());
        }

        // First call should load state
        let state = manager.current_state().expect("Should return state");

        // Verify state is now cached
        {
            let cached = manager.cached_state.lock().unwrap();
            assert!(cached.is_some());
        }

        // Should be Inactive (default for missing file)
        assert_eq!(state, SystemState::Inactive);
    }

    #[test]
    fn test_current_state_uses_cache_on_subsequent_calls() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let state_path = temp_dir.path().join("state.json");

        let fs = MockFilesystem::new();
        let config = Config::default();
        let manager = NailsManager::new(fs, config, state_path.clone());

        // First call loads and caches
        let state1 = manager.current_state().expect("Should return state");

        // Modify file on disk (to verify cache is used, not re-read)
        let different_state = StateFile {
            state: SystemState::Active {
                activated_at: chrono::Utc::now(),
                overlays: vec![],
            },
            ..StateFile::default()
        };
        let json = serde_json::to_string_pretty(&different_state).unwrap();
        std::fs::write(&state_path, json).unwrap();

        // Second call should use cache (not re-read file)
        let state2 = manager.current_state().expect("Should return state");

        // Both should be Inactive (from cache, not re-reading modified file)
        assert_eq!(state1, state2);
        assert_eq!(state2, SystemState::Inactive);
    }

    #[test]
    fn test_current_state_missing_file_returns_inactive() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let nonexistent_path = temp_dir.path().join("nonexistent.json");

        let fs = MockFilesystem::new();
        let config = Config::default();
        let manager = NailsManager::new(fs, config, nonexistent_path);

        // Should return Inactive (safe default)
        let state = manager.current_state().expect("Should return state");
        assert_eq!(state, SystemState::Inactive);
    }

    #[test]
    fn test_current_state_malformed_file_returns_inactive() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let malformed_path = temp_dir.path().join("malformed.json");

        // Write invalid JSON
        std::fs::write(&malformed_path, "{ invalid json syntax").unwrap();

        let fs = MockFilesystem::new();
        let config = Config::default();
        let manager = NailsManager::new(fs, config, malformed_path);

        // Should return Inactive (safe default)
        let state = manager.current_state().expect("Should return state");
        assert_eq!(state, SystemState::Inactive);
    }

    // ========== Task 5: update_state() Tests ==========

    #[test]
    fn test_update_state_valid_transition_succeeds() {
        // Use /tmp for testing (bypass hidden volume check for unit tests)
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        let state_dir = mock_hidden_vol.join(".nails");
        std::fs::create_dir_all(&state_dir).unwrap();
        let state_path = state_dir.join("state.json");

        let fs = MockFilesystem::new();
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
        };
        let mut manager = NailsManager::new(fs, config, state_path.clone());

        // Manually create initial state file in temp (simulating hidden volume)
        let initial_state = StateFile::default();
        let json = serde_json::to_string_pretty(&initial_state).unwrap();
        std::fs::write(&state_path, json).unwrap();

        // Valid transition: Inactive -> Activating
        let result = manager.update_state(SystemState::Activating {
            started_at: Utc::now(),
        });
        assert!(result.is_ok());

        // Verify state was updated
        let state = manager.current_state().unwrap();
        assert!(matches!(state, SystemState::Activating { .. }));
    }

    #[test]
    fn test_update_state_invalid_transition_returns_error() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        let state_dir = mock_hidden_vol.join(".nails");
        std::fs::create_dir_all(&state_dir).unwrap();
        let state_path = state_dir.join("state.json");

        let fs = MockFilesystem::new();
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
        };
        let mut manager = NailsManager::new(fs, config, state_path.clone());

        // Manually create initial state file
        let initial_state = StateFile::default();
        let json = serde_json::to_string_pretty(&initial_state).unwrap();
        std::fs::write(&state_path, json).unwrap();

        // Invalid transition: Inactive -> Active (must go through Activating)
        let result = manager.update_state(SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![],
        });
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NailsError::InvalidState(_)));
    }

    #[test]
    fn test_update_state_saves_to_disk() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        let state_dir = mock_hidden_vol.join(".nails");
        std::fs::create_dir_all(&state_dir).unwrap();
        let state_path = state_dir.join("state.json");

        let fs = MockFilesystem::new();
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
        };
        let mut manager = NailsManager::new(fs, config, state_path.clone());

        // Manually create initial state file
        let initial_state = StateFile::default();
        let json = serde_json::to_string_pretty(&initial_state).unwrap();
        std::fs::write(&state_path, json).unwrap();

        // Update state
        manager
            .update_state(SystemState::Activating {
                started_at: Utc::now(),
            })
            .unwrap();

        // Verify file was written (by loading directly)
        let loaded = StateFile::load(&state_path).unwrap();
        assert!(matches!(loaded.state, SystemState::Activating { .. }));
    }

    #[test]
    fn test_update_state_updates_cache() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        let state_dir = mock_hidden_vol.join(".nails");
        std::fs::create_dir_all(&state_dir).unwrap();
        let state_path = state_dir.join("state.json");

        let fs = MockFilesystem::new();
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
        };
        let mut manager = NailsManager::new(fs, config, state_path.clone());

        // Manually create initial state file
        let initial_state = StateFile::default();
        let json = serde_json::to_string_pretty(&initial_state).unwrap();
        std::fs::write(&state_path, json).unwrap();

        // Update state
        manager
            .update_state(SystemState::Activating {
                started_at: Utc::now(),
            })
            .unwrap();

        // Verify cache was updated
        let state = manager.current_state().unwrap();
        assert!(matches!(state, SystemState::Activating { .. }));
    }

    // ========== Task 6: verify_state() Tests ==========

    #[test]
    fn test_verify_state_active_with_mounted_overlays_ok() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let state_path = temp_dir.path().join("state.json");

        let fs = MockFilesystem::new();

        // Set up mounted overlay
        fs.mock_set_mounted(Path::new("/home"), true);

        let config = Config::default();
        let manager = NailsManager::new(fs, config, state_path.clone());

        // Create Active state file with mounted overlay
        let mut overlay_status = HashMap::new();
        overlay_status.insert(
            PathBuf::from("/home"),
            OverlayInfo {
                mount_path: PathBuf::from("/home"),
                lower_dir: PathBuf::from("/home"),
                upper_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
                work_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
                mounted_at: Utc::now(),
            },
        );

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![PathBuf::from("/home")],
            },
            overlay_status,
            ..StateFile::default()
        };

        // Save manually
        let json = serde_json::to_string_pretty(&state_file).unwrap();
        std::fs::write(&state_path, json).unwrap();

        // Verify should succeed
        let result = manager.verify_state();
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_state_active_with_missing_overlay_error() {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let state_path = temp_dir.path().join("state.json");

        let fs = MockFilesystem::new();
        // Overlay is NOT mounted

        let config = Config::default();
        let manager = NailsManager::new(fs, config, state_path.clone());

        // Create Active state file claiming overlay is mounted
        let mut overlay_status = HashMap::new();
        overlay_status.insert(
            PathBuf::from("/home"),
            OverlayInfo {
                mount_path: PathBuf::from("/home"),
                lower_dir: PathBuf::from("/home"),
                upper_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
                work_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
                mounted_at: Utc::now(),
            },
        );

        let state_file = StateFile {
            state: SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![PathBuf::from("/home")],
            },
            overlay_status,
            ..StateFile::default()
        };

        // Save manually
        let json = serde_json::to_string_pretty(&state_file).unwrap();
        std::fs::write(&state_path, json).unwrap();

        // Verify should fail (state claims mounted but it's not)
        let result = manager.verify_state();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NailsError::InvalidState(_)));
    }

    // ========== Task 7: activate() Tests ==========

    #[test]
    fn test_activate_successful_activation_transitions_through_states() {
        use crate::OverlayConfig;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        let state_dir = mock_hidden_vol.join(".nails");
        std::fs::create_dir_all(&state_dir).unwrap();
        let state_path = state_dir.join("state.json");

        let fs = MockFilesystem::new();

        // Set up paths to exist
        fs.mock_set_path_exists("/", true);
        let upper_dir = mock_hidden_vol.join("overlays/home/upper");
        let work_dir = mock_hidden_vol.join("overlays/home/work");
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

        let mut manager = NailsManager::new(fs, config, state_path);

        // Activate should succeed
        let result = manager.activate();
        assert!(result.is_ok());

        // Final state should be Active
        let state = manager.current_state().unwrap();
        assert!(matches!(state, SystemState::Active { .. }));
    }

    #[test]
    fn test_activate_from_non_inactive_returns_error() {
        use crate::StateFile;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        let state_dir = mock_hidden_vol.join(".nails");
        std::fs::create_dir_all(&state_dir).unwrap();
        let state_path = state_dir.join("state.json");

        let fs = MockFilesystem::new();
        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
        };
        let mut manager = NailsManager::new(fs, config, state_path.clone());

        // Manually write Active state to file (bypass transition validation)
        let state_file = StateFile {
            state: SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![],
            },
            ..StateFile::default()
        };
        let json = serde_json::to_string_pretty(&state_file).unwrap();
        std::fs::write(&state_path, json).unwrap();

        // Force manager to reload state from disk
        *manager.cached_state.lock().unwrap() = None;

        // activate() should fail from Active state
        let result = manager.activate();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NailsError::InvalidState(_)));
    }

    #[test]
    fn test_activate_calls_mount_overlay_for_each_configured_overlay() {
        use crate::OverlayConfig;

        // Create mock hidden volume structure in temp dir
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        let state_dir = mock_hidden_vol.join(".nails");
        std::fs::create_dir_all(&state_dir).unwrap();
        let state_path = state_dir.join("state.json");

        let fs = MockFilesystem::new();

        // Set up paths to exist
        fs.mock_set_path_exists("/", true);
        let upper_dir = mock_hidden_vol.join("overlays/home/upper");
        let work_dir = mock_hidden_vol.join("overlays/home/work");
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

        let fs_clone = fs.clone();
        let mut manager = NailsManager::new(fs, config, state_path);

        // Activate
        manager.activate().unwrap();

        // Verify mount was called
        assert!(fs_clone.is_mounted(Path::new("/home")).unwrap());
    }
}
