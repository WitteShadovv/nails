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
use std::path::{Path, PathBuf};

/// What a `reset-upper` would delete for a single target.
///
/// OverlayFS copies lower files up on first write, and the persistent upper and
/// work directories on the hidden volume keep every session's copy-ups and
/// whiteouts. `reset-upper` deletes them so the target falls back to its decoy
/// lower on the next activation. This plan is computed first so the caller can
/// show the operator exactly what will be removed before anything is deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetUpperPlan {
    /// The overlay target whose upper is being reset (e.g. `/home`).
    pub target: PathBuf,
    /// The upper directory on the hidden volume (`<root>/<dir>`).
    pub upper: PathBuf,
    /// The work directory on the hidden volume (`<root>/.work/<dir>`).
    pub work: PathBuf,
    /// Whether the upper directory currently exists.
    pub upper_exists: bool,
    /// Whether the work directory currently exists.
    pub work_exists: bool,
    /// True when the target is `/nix`: resetting it drops the hidden Nix
    /// database and store paths, so the caller must warn especially loudly.
    pub resets_nix_store: bool,
}

impl ResetUpperPlan {
    /// The directories that actually exist and would therefore be removed.
    pub fn removals(&self) -> Vec<&Path> {
        let mut removals = Vec::new();
        if self.upper_exists {
            removals.push(self.upper.as_path());
        }
        if self.work_exists {
            removals.push(self.work.as_path());
        }
        removals
    }

    /// True when neither directory exists, so there is nothing to remove.
    pub fn is_empty(&self) -> bool {
        !self.upper_exists && !self.work_exists
    }
}

/// A short, human-readable label for the current system state, used in the
/// `reset-upper` refusal message.
fn state_label(state: &SystemState) -> &'static str {
    match state {
        SystemState::Inactive => "Inactive",
        SystemState::Activating { .. } => "Activating",
        SystemState::Active { .. } => "Active",
        SystemState::Deactivating { .. } => "Deactivating",
        SystemState::Degraded { .. } => "Degraded",
    }
}

impl<F: Filesystem> NailsManager<F> {
    /// Get current system state with lazy loading
    ///
    /// First call loads from disk and caches result.
    /// Subsequent calls return cached value.
    ///
    /// # Graceful Degradation
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
        let mut cached = self.cached_state.borrow_mut();

        // If cached, return immediately
        if let Some(ref state_file) = *cached {
            return Ok(state_file.state.clone());
        }

        // Lazy load from disk
        // Note: StateFile::load() handles warning logs for missing/malformed files
        // and returns default Inactive state. This keeps the logging
        // logic centralized in the StateFile module.
        let state_file = StateFile::load(&self.state_file_path)?;
        let state = state_file.state.clone();

        // Cache for future calls
        *cached = Some(state_file);

        Ok(state)
    }

    /// Load the current state together with how it was obtained, bypassing the cache.
    ///
    /// Unlike [`current_state`](Self::current_state) this does not hide a damaged
    /// file behind the safe default: when the outcome
    /// [`is_unknown`](crate::LoadOutcome::is_unknown) the caller can refuse to
    /// mutate, or fall back to the live mount table, instead of trusting a state
    /// that could not be read. Intended for mutating commands that have just
    /// taken the inter-process lock and need the freshest, most honest state.
    pub fn current_state_with_outcome(&self) -> Result<(SystemState, crate::LoadOutcome)> {
        let result = StateFile::load_with_outcome(&self.state_file_path)?;
        Ok((result.state_file.state.clone(), result.outcome))
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
    /// self.manager.force_state(self.previous_state.clone());
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
        let mut cached = self.cached_state.borrow_mut();
        let mut state_file = cached.take().unwrap_or_default();
        state_file.state = new_state.clone();
        state_file.last_modified = Utc::now();

        // Clear overlay_status and nixos_generation when rolling back to Inactive
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
            // Partial teardown/rollback can degrade from any live state.
            (
                SystemState::Activating { .. }
                | SystemState::Active { .. }
                | SystemState::Deactivating { .. }
                | SystemState::Degraded { .. },
                SystemState::Degraded { .. },
            ) => true,
            // Recovery (or a completed emergency teardown) returns to Inactive.
            (SystemState::Degraded { .. }, SystemState::Inactive) => true,
            _ if current == new_state => true, // Same state is allowed (idempotent)
            _ => false,
        };

        if !is_valid {
            return Err(NailsError::InvalidState(format!(
                "Invalid state transition: {:?} -> {:?}",
                current, new_state
            )));
        }

        // Update state file
        let mut cached = self.cached_state.borrow_mut();
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
    /// Used during incremental state updates.
    ///
    /// # Returns
    ///
    /// * `Ok(())` - State saved successfully
    /// * `Err(NailsError::StateFileError)` - Failed to write state file
    pub(crate) fn save_cached_state(&self) -> Result<()> {
        let mut cached = self.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file.last_modified = Utc::now();
            state_file
                .save_with_custom_root(&self.state_file_path, &self.config.hidden_volume_root)?;
        }
        Ok(())
    }

    /// Clear transient mount-tracking state in cached state without altering other fields.
    ///
    /// Used during deactivation to avoid losing nixos_generation/config_fingerprint
    /// while still returning to a clean inactive tracker state.
    pub(crate) fn clear_overlay_status_in_cache(&self) -> Result<()> {
        let mut cached = self.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file.overlay_status.clear();
            state_file.failed_overlays.clear();
            state_file.nix_store_init_namespace_bound = false;
        }
        Ok(())
    }

    /// Plan a `reset-upper` for `target`: validate it is safe, derive the upper
    /// and work directories, and record which of them exist.
    ///
    /// Refuses unless the system is `Inactive` and `target` is not currently
    /// mounted, so a reset can never delete a layer out from under a live
    /// overlay. The returned [`ResetUpperPlan`] lists what would be deleted;
    /// nothing is removed until [`apply_reset_upper`](Self::apply_reset_upper).
    pub fn plan_reset_upper(&self, target: &Path) -> Result<ResetUpperPlan> {
        let state = self.current_state()?;
        if !matches!(state, SystemState::Inactive) {
            return Err(NailsError::InvalidState(format!(
                "reset-upper requires the system to be Inactive, but it is {}; \
                 deactivate before resetting an upper",
                state_label(&state)
            )));
        }

        if self.filesystem.is_mounted(target)? {
            return Err(NailsError::InvalidState(format!(
                "{} is currently mounted; unmount it before resetting its upper",
                target.display()
            )));
        }

        let (upper, work) =
            super::helpers::derive_upper_work_paths(target, &self.config.hidden_volume_root)?;
        let upper_exists = self.filesystem.path_exists(&upper)?;
        let work_exists = self.filesystem.path_exists(&work)?;

        Ok(ResetUpperPlan {
            resets_nix_store: target == Path::new("/nix"),
            target: target.to_path_buf(),
            upper,
            work,
            upper_exists,
            work_exists,
        })
    }

    /// Apply a [`ResetUpperPlan`]: remove the upper and work directories that
    /// exist.
    ///
    /// Only directories the plan found are removed, so a stale plan never
    /// deletes something that reappeared. This performs no whiteout pruning and
    /// touches nothing but the two derived directories.
    pub fn apply_reset_upper(&self, plan: &ResetUpperPlan) -> Result<()> {
        if plan.upper_exists {
            self.filesystem.remove_dir_all(&plan.upper)?;
        }
        if plan.work_exists {
            self.filesystem.remove_dir_all(&plan.work)?;
        }
        Ok(())
    }

    /// Return tracked overlay paths ordered by original mount time.
    pub(crate) fn tracked_overlay_paths_by_mount_order(&self) -> Result<Vec<PathBuf>> {
        let cached = self.cached_state.borrow();

        let mut ordered: Vec<_> = cached
            .as_ref()
            .map(|state_file| {
                state_file
                    .overlay_status
                    .values()
                    .map(|info| (info.mounted_at, info.mount_path.clone()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        ordered.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        Ok(ordered.into_iter().map(|(_, path)| path).collect())
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
                    // Transitional states (Activating, Deactivating, Degraded) are skipped
                    // because:
                    // - Activating: Overlays are being mounted, partial state is expected
                    // - Deactivating: Overlays are being unmounted, partial state is expected
                    // - Degraded: System is partly torn down by definition
                    //
                    // These states are short-lived and verification is meaningless during
                    // the transition. Verification is only useful for stable states
                    // (Active, Inactive) to detect drift.
                }
            }
        }

        Ok(())
    }

    /// Reconcile the persisted state against the current boot and the live kernel
    /// mount table, returning the [`EffectiveState`](crate::state::EffectiveState)
    /// the commands act on.
    ///
    /// This is the manager-side wrapper around the pure
    /// [`reconcile`](crate::state::reconcile) function. It loads the state file
    /// fresh (bypassing the cache), discovers the NAILS-owned mounts from
    /// `/proc/self/mountinfo`, reads the current kernel boot id and probes whether
    /// the recorded owner process is still alive, then collapses all of that into
    /// a single effective state.
    ///
    /// A state written under a *previous* boot that no longer corresponds to any
    /// live mount is reset to Inactive and persisted here — the cached build
    /// metadata (`nixos_generation`, `config_fingerprint`) survives the reset
    /// because it is still valid across a reboot. Every other disagreement
    /// (overlays missing, mounts live while inactive, a crashed transitional
    /// state, an unreadable file) is reported and never auto-reset, so an
    /// inconsistent system fails closed.
    pub(crate) fn reconcile_state(&self) -> Result<crate::state::EffectiveState> {
        use crate::state::{EffectiveState, reconcile};

        let load = StateFile::load_with_outcome(&self.state_file_path)?;
        let mounts = discover_reconcile_mounts(&self.config.hidden_volume_root);
        let current_boot_id = crate::state::read_boot_id();
        let owner_alive = pid_is_alive(load.state_file.owner_pid);

        let effective = reconcile(
            &load.state_file,
            &load.outcome,
            &mounts,
            current_boot_id.as_deref(),
            owner_alive,
        );

        if matches!(effective, EffectiveState::StaleFromPreviousBoot) {
            self.reset_stale_state_to_inactive(&load.state_file)?;
        }

        Ok(effective)
    }

    /// Reset a stale-from-previous-boot state file to Inactive, keeping the cached
    /// build metadata, and update the in-memory cache to match.
    ///
    /// `nixos_generation` and `config_fingerprint` are deliberately preserved:
    /// they describe the hidden build, which outlives a reboot, so the next
    /// activation can still take its fast path. The overlay tracking is cleared
    /// because nothing is mounted.
    fn reset_stale_state_to_inactive(&self, previous: &StateFile) -> Result<()> {
        let mut reset = previous.clone();
        reset.state = SystemState::Inactive;
        reset.overlay_status.clear();
        reset.failed_overlays.clear();
        reset.nix_store_init_namespace_bound = false;
        reset.last_modified = Utc::now();
        reset.save_with_custom_root(&self.state_file_path, &self.config.hidden_volume_root)?;
        *self.cached_state.borrow_mut() = Some(reset);
        tracing::warn!(
            event = "stale_state_reset",
            "Persisted active state was written under a previous boot and nothing is mounted; \
             reset to Inactive (kept cached build metadata)"
        );
        Ok(())
    }
}

/// Whether a recorded owner pid is still a live process.
///
/// Reconciliation only consults this for a transitional state (Activating /
/// Deactivating) left behind within the current boot, to tell an in-flight
/// operation from a crashed one once the exclusive state lock is held. A pid of
/// `0` is the "unset" sentinel and is never alive.
fn pid_is_alive(pid: u32) -> bool {
    pid != 0 && Path::new(&format!("/proc/{pid}")).exists()
}

/// Discover the NAILS-owned mounts for reconciliation.
///
/// Reads the real `/proc/self/mountinfo` in production; a read failure degrades
/// to "no NAILS mounts", which keeps reconciliation fail-closed (an Active state
/// then reconciles to Degraded rather than trusting an unreadable table).
#[cfg(not(test))]
fn discover_reconcile_mounts(hidden_root: &Path) -> crate::filesystem::NailsMounts {
    crate::filesystem::NailsMounts::discover(Some(hidden_root)).unwrap_or_else(|e| {
        tracing::warn!(
            error = %e,
            "Could not read the mount table during reconcile; treating no overlays as live"
        );
        crate::filesystem::NailsMounts::default()
    })
}

/// Test build: consult the injected mount-table override so reconcile tests can
/// drive the verified/degraded/inconsistent cases without a real overlay, and
/// otherwise read the real table (empty of NAILS overlays in a test run).
#[cfg(test)]
fn discover_reconcile_mounts(hidden_root: &Path) -> crate::filesystem::NailsMounts {
    if let Some(mounts) = reconcile_mounts_override::get() {
        return mounts;
    }
    crate::filesystem::NailsMounts::discover(Some(hidden_root)).unwrap_or_default()
}

/// Test-only override for the mount table that [`NailsManager::reconcile_state`]
/// reads. Thread-local with a drop guard so it never leaks into another test
/// sharing the worker thread.
#[cfg(test)]
pub(crate) mod reconcile_mounts_override {
    use crate::filesystem::NailsMounts;
    use std::cell::RefCell;

    thread_local! {
        static OVERRIDE: RefCell<Option<NailsMounts>> = const { RefCell::new(None) };
    }

    pub(crate) fn get() -> Option<NailsMounts> {
        OVERRIDE.with(|cell| cell.borrow().clone())
    }

    pub(crate) fn arm(mounts: NailsMounts) -> Guard {
        OVERRIDE.with(|cell| *cell.borrow_mut() = Some(mounts));
        Guard
    }

    pub(crate) struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            OVERRIDE.with(|cell| *cell.borrow_mut() = None);
        }
    }
}
