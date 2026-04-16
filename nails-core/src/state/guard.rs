//! # State Guard
//!
//! RAII rollback guard for automatic state cleanup on error or panic.

use super::SystemState;
use crate::{Filesystem, NailsManager};
use std::sync::{Arc, Mutex};

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
///     let m = manager.lock().expect("manager mutex poisoned");
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
    manager: Arc<Mutex<NailsManager<F>>>,

    /// State to restore if transaction is not committed
    previous_state: SystemState,

    /// Whether transaction was explicitly committed
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
    /// # Requirements
    ///
    /// - **FR50**: Automatic rollback on activation failure
    /// - **FR52**: Log warning "Rolling back to previous state: {:?}"
    /// - **NFR24**: Works even during panic (Drop during stack unwinding)
    fn drop(&mut self) {
        if !self.committed {
            tracing::warn!("Rolling back to previous state: {:?}", self.previous_state);

            // Attempt to acquire manager lock
            match self.manager.lock() {
                Ok(mut manager) => {
                    if let Err(e) = manager.force_state(self.previous_state.clone()) {
                        tracing::error!("Failed to rollback state: {}", e);
                    }
                }
                Err(poisoned) => {
                    tracing::warn!("Manager lock poisoned during rollback, attempting recovery...");
                    let mut manager = poisoned.into_inner();
                    if let Err(e) = manager.force_state(self.previous_state.clone()) {
                        tracing::error!("Failed to rollback state after lock poisoning: {}", e);
                    }
                }
            }
        }
    }
}
