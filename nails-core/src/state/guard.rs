//! # State Guard
//!
//! RAII rollback guard for automatic state cleanup on error or panic.

use super::SystemState;
use crate::{Filesystem, NailsManager};
use chrono::Utc;
use std::cell::RefCell;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::rc::Rc;

/// RAII guard for automatic state rollback on error or panic
///
/// StateGuard implements the RAII (Resource Acquisition Is Initialization) pattern
/// to guarantee state rollback when operations fail or panic. The Drop trait ensures
/// cleanup code runs when the guard goes out of scope, even during stack unwinding.
///
/// # Pattern: Transaction-style State Management
///
/// StateGuard borrows the manager exclusively for the duration of a risky
/// operation and derefs to it, so every step runs against the same borrow:
/// 1. Create the guard capturing the current state.
/// 2. Perform risky operations through the guard (`&mut *guard`).
/// 3. Explicitly `commit()` on success to prevent rollback.
/// 4. Automatic rollback on failure or panic (via Drop).
///
/// Holding the manager by `&mut` (instead of an `Arc<Mutex>` clone) removes the
/// lock/poison handling and lets the activation and deactivation step functions
/// reuse the single borrow the guard already owns.
///
/// # Example
///
/// ```rust
/// use nails_core::{StateGuard, NailsManager, MockFilesystem, Config};
/// use std::path::PathBuf;
///
/// let fs = MockFilesystem::new();
/// let config = Config::default();
/// let temp_dir = tempfile::tempdir().unwrap();
/// let state_path = temp_dir.path().join("state.json");
/// let mut manager = NailsManager::new(fs, config, state_path);
///
/// // Capture current state for potential rollback
/// let previous_state = manager.current_state().unwrap();
///
/// // Create guard - will rollback if not committed
/// let guard = StateGuard::new(&mut manager, previous_state);
///
/// // Perform operations that might fail through `&mut *guard`...
/// // If any step fails, guard's Drop automatically rolls back.
///
/// // Explicitly commit to prevent rollback
/// guard.commit();
/// ```
///
/// # Security Guarantee
///
/// Even if a panic occurs during activation/deactivation, Drop trait ensures
/// state is rolled back. This prevents the system from being left in an
/// inconsistent state (Activating/Deactivating) which could leak forensic evidence.
///
/// # Requirements
///
/// - Automatic rollback on activation failure
/// - Restore the captured state when an operation fails (the guard
///   restores state only; it does not touch overlays, and teardown leaves any
///   still-mounted overlay in place rather than reattaching it)
/// - Track steps for reverse rollback
/// - Idempotent rollback (safe to call multiple times)
/// - Prevent memory leaks via RAII
/// - Rollback on partial failures
/// - Automatic cleanup even on panic
pub struct StateGuard<'a, F: Filesystem> {
    /// Exclusive borrow of the manager for state restoration
    manager: &'a mut NailsManager<F>,

    /// State to restore if transaction is not committed
    previous_state: SystemState,

    /// Whether transaction was explicitly committed
    committed: bool,

    /// Shared handle, set only by activation, into which the activation-scope
    /// overlay rollback writes any mounts it could not unmount. When it is
    /// non-empty on rollback the guard persists `Degraded` (listing those
    /// mounts) instead of the previous state, so `Inactive` is never written
    /// while NAILS overlays are still live. Deactivation leaves this `None`.
    residue: Option<Rc<RefCell<Vec<PathBuf>>>>,
}

impl<'a, F: Filesystem> StateGuard<'a, F> {
    /// Create a new StateGuard capturing current state
    ///
    /// The guard captures the current state for potential rollback and borrows
    /// the manager exclusively. Call `commit()` to mark the transaction
    /// successful and prevent rollback.
    ///
    /// # Arguments
    ///
    /// * `manager` - Exclusive borrow of the NailsManager
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
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let temp_dir = tempfile::tempdir().unwrap();
    /// let state_path = temp_dir.path().join("state.json");
    /// let mut manager = NailsManager::new(fs, config, state_path);
    ///
    /// let previous_state = SystemState::Inactive;
    /// let guard = StateGuard::new(&mut manager, previous_state);
    /// // guard will rollback to Inactive when dropped (unless committed)
    /// ```
    pub fn new(manager: &'a mut NailsManager<F>, previous_state: SystemState) -> Self {
        Self {
            manager,
            previous_state,
            committed: false,
            residue: None,
        }
    }

    /// Attach a shared residue handle (activation only).
    ///
    /// The activation-scope overlay rollback writes the mounts it could not
    /// unmount into this handle; if it is non-empty when the guard rolls back,
    /// the guard persists `Degraded` with those mounts listed instead of the
    /// previous state. Deactivation does not call this, so its rollback keeps
    /// restoring the previous state unchanged.
    pub fn with_residue(mut self, residue: Rc<RefCell<Vec<PathBuf>>>) -> Self {
        self.residue = Some(residue);
        self
    }

    /// Commit the transaction to prevent rollback
    ///
    /// Marks the transaction as successful. When the guard is dropped,
    /// no rollback will occur.
    ///
    /// # Move Semantics
    ///
    /// This method consumes self (takes ownership), preventing further use
    /// of the guard after commit and releasing the manager borrow.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{StateGuard, NailsManager, MockFilesystem, Config, SystemState};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let temp_dir = tempfile::tempdir().unwrap();
    /// let state_path = temp_dir.path().join("state.json");
    /// let mut manager = NailsManager::new(fs, config, state_path);
    ///
    /// let previous_state = SystemState::Inactive;
    /// let guard = StateGuard::new(&mut manager, previous_state);
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
    /// # Returns
    ///
    /// Reference to the previous SystemState
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{StateGuard, NailsManager, MockFilesystem, Config, SystemState};
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let temp_dir = tempfile::tempdir().unwrap();
    /// let state_path = temp_dir.path().join("state.json");
    /// let mut manager = NailsManager::new(fs, config, state_path);
    ///
    /// let previous_state = SystemState::Inactive;
    /// let guard = StateGuard::new(&mut manager, previous_state);
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
    ///
    /// # Returns
    ///
    /// true if committed, false if uncommitted
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{StateGuard, NailsManager, MockFilesystem, Config, SystemState};
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let temp_dir = tempfile::tempdir().unwrap();
    /// let state_path = temp_dir.path().join("state.json");
    /// let mut manager = NailsManager::new(fs, config, state_path);
    ///
    /// let previous_state = SystemState::Inactive;
    /// let guard = StateGuard::new(&mut manager, previous_state);
    ///
    /// // Initially not committed
    /// assert!(!guard.is_committed());
    /// ```
    ///
    /// # Note
    ///
    /// This method is primarily useful for testing and debugging.
    pub fn is_committed(&self) -> bool {
        self.committed
    }
}

impl<F: Filesystem> Deref for StateGuard<'_, F> {
    type Target = NailsManager<F>;

    fn deref(&self) -> &Self::Target {
        self.manager
    }
}

impl<F: Filesystem> DerefMut for StateGuard<'_, F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.manager
    }
}

impl<F: Filesystem> Drop for StateGuard<'_, F> {
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
    /// # Requirements
    ///
    /// - Automatic rollback on activation failure
    /// - Log warning "Rolling back to previous state: {:?}"
    /// - Works even during panic (Drop during stack unwinding)
    ///
    /// # Invariant: no lock acquisition
    ///
    /// Rollback goes through `force_state`, which takes `&mut NailsManager`
    /// through the guard's own exclusive borrow. It must never acquire a lock the
    /// unwinding caller might already hold: an earlier design kept the manager
    /// behind an `Arc<Mutex>` and re-locked it here, so a state write failing on a
    /// deactivation `?` path dropped the guard while the caller still held the
    /// guard — and the drop then blocked forever on the same mutex. Holding the
    /// manager by `&mut` makes that class of self-deadlock unrepresentable.
    /// `force_state` must also keep any interior borrow (the cached-state
    /// `RefCell`) scoped so it is released before this returns.
    fn drop(&mut self) {
        if self.committed {
            return;
        }

        // The activation-scope overlay rollback runs first (it is declared after
        // this guard, so it drops before it) and records any mount it could not
        // remove. If mounts remain, the system is not cleanly inactive, so
        // persist `Degraded` with those mounts rather than `Inactive` — which
        // `force_state` would write with `overlay_status` cleared, hiding live
        // NAILS mounts from status and recovery.
        let remaining = self
            .residue
            .as_ref()
            .map(|handle| handle.borrow().clone())
            .unwrap_or_default();

        let rollback_state = if remaining.is_empty() {
            self.previous_state.clone()
        } else {
            SystemState::Degraded {
                since: Utc::now(),
                reason: "activation rollback could not unmount all overlays".to_string(),
                remaining_mounts: remaining,
            }
        };

        tracing::warn!("Rolling back to state: {:?}", rollback_state);

        if let Err(e) = self.manager.force_state(rollback_state) {
            tracing::error!("Failed to rollback state: {}", e);
        }
    }
}
