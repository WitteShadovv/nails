//! State Management for NailsManager
//!
//! This module implements state management operations for NailsManager including:
//! - State loading and caching (lazy loading pattern)
//! - State transitions with validation
//! - Force state updates for rollback scenarios
//! - State verification against actual system state
//! - Preflight checks before activation

use super::NailsManager;
use crate::{Filesystem, NailsError, Result, StateFile, SystemState};
use chrono::Utc;

impl<F: Filesystem> NailsManager<F> {
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
    /// let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
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
        let mut cached = self
            .cached_state
            .lock()
            .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;

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

    /// Force state transition without validation (for rollback use only)
    ///
    /// **⚠️ WARNING: This method bypasses ALL state transition validation.**
    ///
    /// This method directly sets the system state without checking if the
    /// transition is legal according to the state machine rules. Using this
    /// method incorrectly WILL corrupt your state machine and cause undefined
    /// behavior.
    ///
    /// # ⚠️ Safety - State Machine Corruption Risk
    ///
    /// This method is intentionally **NOT** marked as `unsafe` in Rust terms
    /// (it doesn't violate memory safety), but it IS unsafe from a **state
    /// machine correctness** perspective.
    ///
    /// ## When State Machine Corruption Occurs
    ///
    /// Using `force_state()` outside of rollback scenarios can create invalid
    /// state transitions that violate the system's invariants:
    ///
    /// ### Example 1: Skipping Required Cleanup
    /// ```text
    /// // DANGER: Forcing Active → Inactive without cleanup
    /// manager.force_state(SystemState::Inactive);
    /// // Result: Overlays remain mounted but state says Inactive
    /// // Next activation will fail or double-mount
    /// ```
    ///
    /// ### Example 2: Bypassing Validation Checks
    /// ```text
    /// // DANGER: Forcing Inactive → Active without mounting
    /// manager.force_state(SystemState::Active { ... });
    /// // Result: State says Active but nothing is mounted
    /// // System thinks it's protected but it's not
    /// ```
    ///
    /// ### Example 3: Creating Impossible Transitions
    /// ```text
    /// // DANGER: Jumping from Error to Activating
    /// manager.force_state(SystemState::Activating);
    /// // Result: State machine thinks activation is in progress
    /// // but prerequisites from Inactive weren't completed
    /// ```
    ///
    /// ## Safe Use Case: Rollback After Partial Failure
    ///
    /// The ONLY safe use of `force_state()` is in StateGuard::drop() to restore
    /// a previous known-good state after a partial operation failure:
    ///
    /// ```text
    /// // SAFE: Rollback in StateGuard::drop()
    /// // We were in Active, tried to deactivate, unmount failed
    /// // Roll back to Active (remount what we can)
    /// self.manager.lock().map_err(|e| NailsError::LockPoisoned(e.to_string()))?
    ///     .force_state(self.previous_state.clone());
    /// // State machine returns to consistent Active state
    /// ```
    ///
    /// # When to Use This Method
    ///
    /// **ONLY use `force_state()` in these scenarios:**
    /// 1. **StateGuard::drop() for rollback** - Restoring previous state after failure
    /// 2. **Test setup/teardown** - Forcing known states for testing
    /// 3. **Recovery operations** - Manual state repair by advanced users
    ///
    /// **NEVER use `force_state()` in:**
    /// - Normal activation/deactivation flows (use `update_state()` instead)
    /// - CLI commands (they should use high-level APIs)
    /// - Error handling outside of rollback (fix the root cause instead)
    ///
    /// # Arguments
    ///
    /// * `new_state` - State to force (no validation performed)
    ///
    /// # Returns
    ///
    /// * `Ok(())` - State forced successfully
    /// * `Err(NailsError::IoError)` - Failed to save state file
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nails_core::{NailsManager, MockFilesystem, Config, SystemState};
    /// use std::path::PathBuf;
    ///
    /// let temp_dir = tempfile::tempdir().unwrap();
    /// let mock_hidden_vol = temp_dir.path();
    /// std::fs::create_dir_all(mock_hidden_vol).unwrap();
    /// let state_path = mock_hidden_vol.join("state.json");
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config {
    ///     hidden_volume_root: mock_hidden_vol.to_path_buf(),
    ///     state_file_path: state_path.clone(),
    ///     overlays: vec![],
    ///     ..Config::default()
    /// };
    /// let mut manager = NailsManager::new(fs, config, state_path);
    ///
    /// // Force state without validation (rollback use case)
    /// manager.force_state(SystemState::Inactive).unwrap();
    /// ```
    pub fn force_state(&mut self, new_state: SystemState) -> Result<()> {
        // Update state file without validation
        let mut cached = self
            .cached_state
            .lock()
            .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
        let mut state_file = cached.take().unwrap_or_default();
        state_file.state = new_state.clone();
        state_file.last_modified = Utc::now();

        // Task 5 (AC4): Clear overlay_status and nixos_generation when rolling back to Inactive
        // This ensures the state file doesn't retain stale activation metadata after rollback
        if let SystemState::Inactive = new_state {
            state_file.overlay_status.clear();
            state_file.nixos_generation = None;
            tracing::debug!(
                action = "rollback",
                target_state = "Inactive",
                fields_cleared = "overlay_status,nixos_generation",
                "Rollback to Inactive"
            );
        }

        // Save to disk with configured hidden volume root
        state_file.save_with_custom_root(&self.state_file_path, &self.config.hidden_volume_root)?;

        // Update cache
        *cached = Some(state_file);

        Ok(())
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
    /// std::fs::create_dir_all(mock_hidden_vol).unwrap();
    /// let state_path = mock_hidden_vol.join("state.json");
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config {
    ///     hidden_volume_root: mock_hidden_vol.to_path_buf(),
    ///     state_file_path: state_path.clone(),
    ///     overlays: vec![],
    ///     ..Config::default()
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
        let mut cached = self
            .cached_state
            .lock()
            .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
        let mut state_file = cached.take().unwrap_or_default();
        state_file.state = new_state;
        state_file.last_modified = Utc::now();

        // Save to disk with configured hidden volume root
        state_file.save_with_custom_root(&self.state_file_path, &self.config.hidden_volume_root)?;

        // Update cache
        *cached = Some(state_file);

        Ok(())
    }

    /// Save cached state to disk without validation
    ///
    /// Helper method to persist the current cached state to disk.
    /// Used during incremental state updates (Story 4.7, AC1, AC2).
    ///
    /// # Returns
    ///
    /// * `Ok(())` - State saved successfully
    /// * `Err(NailsError::StateFileError)` - Failed to write state file
    pub(crate) fn save_cached_state(&self) -> Result<()> {
        let mut cached = self
            .cached_state
            .lock()
            .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
        if let Some(ref mut state_file) = *cached {
            state_file.last_modified = Utc::now();
            state_file
                .save_with_custom_root(&self.state_file_path, &self.config.hidden_volume_root)?;
        }
        Ok(())
    }

    /// Clear overlay_status in cached state without altering other fields.
    ///
    /// Used during deactivation to avoid losing nixos_generation/config_fingerprint.
    pub(crate) fn clear_overlay_status_in_cache(&self) -> Result<()> {
        let mut cached = self
            .cached_state
            .lock()
            .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
        if let Some(ref mut state_file) = *cached {
            state_file.overlay_status.clear();
        }
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
    /// let result = manager.verify_overlay_status();
    /// assert!(result.is_ok());
    /// ```
    pub fn verify_overlay_status(&self) -> Result<()> {
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
}
