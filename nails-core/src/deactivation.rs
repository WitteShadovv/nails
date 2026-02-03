//! # Deactivation Orchestrator Module
//!
//! Coordinates atomic deactivation operations for NAILS, including:
//! - Artifact cleanup (history, temp files, logs)
//! - Overlay unmounting in reverse LIFO order
//! - Automatic rollback on failures (via StateGuard RAII)
//!
//! # Architecture
//!
//! DeactivationOrchestrator follows a 5-step sequence (Story 5.5, AC2):
//! 1. **State transition:** ACTIVE → DEACTIVATING with StateGuard
//! 2. **Artifact cleanup:** Call CleanupManager with Thorough mode
//! 3. **Overlay unmount:** Unmount overlays in reverse LIFO order
//! 4. **State transition:** DEACTIVATING → INACTIVE
//! 5. **Commit StateGuard:** Finalize deactivation
//!
//! If any step fails, StateGuard automatically rolls back to ACTIVE state (FR51).
//!
//! # Rollback Scenarios (TR49, TR50)
//!
//! **TR49 - Cleanup Fails:**
//! - State: ACTIVE → DEACTIVATING → (cleanup fails) → ACTIVE
//! - Overlays: Remain mounted (never unmounted)
//! - Action: StateGuard drops without commit, rolls back state
//!
//! **TR50 - Unmount Fails:**
//! - State: ACTIVE → DEACTIVATING → (unmount fails) → ACTIVE
//! - Overlays:
//!   - Successfully unmounted ones get remounted
//!   - Failed one remains mounted (was never unmounted)
//! - Action:
//!   1. Remount successfully unmounted overlays
//!   2. StateGuard drops without commit, rolls back state
//!
//! # Example
//!
//! ```rust,ignore
//! use nails_core::{DeactivationOrchestrator, DeactivationReport, CleanupConfig};
//! use std::sync::{Arc, Mutex};
//!
//! let orchestrator = DeactivationOrchestrator::new(
//!     Arc::clone(&manager),
//!     CleanupConfig::default(),
//! );
//!
//! match orchestrator.run() {
//!     Ok(report) => println!("{}", report),
//!     Err(e) => eprintln!("Deactivation failed: {}", e),
//! }
//! ```

use crate::{
    CleanupConfig, CleanupManager, CleanupMode, CleanupReport, Filesystem, NailsError,
    NailsManager, Result, StateGuard, SystemState,
};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Report of deactivation operations
///
/// Provides detailed accounting of what was cleaned, which overlays were unmounted,
/// timing information, and the final system state after deactivation.
///
/// # Fields
///
/// - `cleanup_report`: Results from CleanupManager (history, temp files, logs)
/// - `unmounted_overlays`: List of overlay paths that were successfully unmounted
/// - `duration`: Total time taken for the deactivation operation
/// - `final_state`: System state after deactivation (should be Inactive on success)
/// - `was_already_inactive`: Whether system was already inactive (idempotent case)
///
/// # Requirements
///
/// - AC3: DeactivationReport with cleanup, unmounted overlays, duration, final state
/// - FR62: Idempotent deactivation tracking
#[derive(Debug, Clone)]
pub struct DeactivationReport {
    /// Cleanup operation results
    pub cleanup_report: CleanupReport,

    /// Overlays that were unmounted
    pub unmounted_overlays: Vec<String>,

    /// Total duration of deactivation
    pub duration: Duration,

    /// Final system state after deactivation
    pub final_state: SystemState,

    /// Whether deactivation was a no-op (already inactive)
    pub was_already_inactive: bool,
}

impl DeactivationReport {
    /// Check if deactivation completed successfully
    ///
    /// Returns true if the final state is Inactive, indicating successful deactivation.
    pub fn is_successful(&self) -> bool {
        self.final_state == SystemState::Inactive
    }
}

impl std::fmt::Display for DeactivationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.was_already_inactive {
            writeln!(f, "✓ Already inactive - no action needed")?;
            return Ok(());
        }

        writeln!(f, "Deactivation Report")?;
        writeln!(f, "===================")?;
        writeln!(f, "Duration: {:?}", self.duration)?;
        writeln!(f, "Final State: {:?}", self.final_state)?;
        writeln!(f)?;

        // Cleanup summary
        writeln!(f, "Cleanup:")?;
        for item in &self.cleanup_report.cleaned_items {
            writeln!(f, "  ✓ {}", item)?;
        }

        // Unmounted overlays
        writeln!(f)?;
        writeln!(f, "Unmounted Overlays:")?;
        for overlay in &self.unmounted_overlays {
            writeln!(f, "  ✓ {}", overlay)?;
        }

        if self.is_successful() {
            writeln!(f)?;
            writeln!(f, "✓ Deactivation complete")?;
        }

        Ok(())
    }
}

/// Orchestrates the deactivation process
///
/// DeactivationOrchestrator coordinates:
/// 1. State transition (ACTIVE → DEACTIVATING)
/// 2. Artifact cleanup (history, temp files, logs)
/// 3. Overlay unmounting (reverse LIFO order)
/// 4. Final state transition (DEACTIVATING → INACTIVE)
///
/// # Rollback Guarantees
///
/// If any step fails, the orchestrator rolls back to ACTIVE state:
/// - Cleanup failure: Overlays remain mounted, state returns to ACTIVE
/// - Unmount failure: Remount any unmounted overlays, state returns to ACTIVE
///
/// # Generic Parameter
///
/// `F: Filesystem` - Abstracted filesystem operations for testability
///
/// # Requirements
///
/// - AC1: Generic struct with manager, cleanup_config
/// - AC2: run() method with 5-step sequence
/// - FR51: Remount overlays if cleanup fails
/// - FR62: Idempotent deactivation
/// - NFR13: Atomic operations
/// - NFR20: Rollback on failures
pub struct DeactivationOrchestrator<F: Filesystem> {
    manager: Arc<Mutex<NailsManager<F>>>,
    cleanup_config: CleanupConfig,
}

impl<F: Filesystem + 'static> DeactivationOrchestrator<F> {
    /// Create a new DeactivationOrchestrator
    ///
    /// # Arguments
    ///
    /// * `manager` - Shared reference to NailsManager for state management
    /// * `cleanup_config` - Configuration for cleanup operations
    ///
    /// # Returns
    ///
    /// New DeactivationOrchestrator instance
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use nails_core::{DeactivationOrchestrator, CleanupConfig};
    /// use std::sync::{Arc, Mutex};
    ///
    /// let orchestrator = DeactivationOrchestrator::new(
    ///     Arc::clone(&manager),
    ///     CleanupConfig::default(),
    /// );
    /// ```
    pub fn new(manager: Arc<Mutex<NailsManager<F>>>, cleanup_config: CleanupConfig) -> Self {
        Self {
            manager,
            cleanup_config,
        }
    }

    /// Execute deactivation
    ///
    /// # Steps
    ///
    /// 1. Check if already inactive (idempotent)
    /// 2. Transition ACTIVE → DEACTIVATING
    /// 3. Cleanup artifacts (Thorough mode)
    /// 4. Unmount overlays in reverse order
    /// 5. Transition DEACTIVATING → INACTIVE
    ///
    /// # Returns
    ///
    /// `DeactivationReport` with full details of the operation.
    ///
    /// # Errors
    ///
    /// Returns Err with details if deactivation fails. State is rolled back.
    ///
    /// # Requirements
    ///
    /// - AC2: 5-step sequence implementation
    /// - AC3: Successful deactivation report
    /// - AC4: Rollback on cleanup failure
    /// - AC5: Rollback on unmount failure
    /// - AC7: Idempotent deactivation
    pub fn run(&self) -> Result<DeactivationReport> {
        let start = Instant::now();

        // Lock manager for the duration
        let mut manager = self
            .manager
            .lock()
            .map_err(|_| NailsError::InvalidState("Failed to acquire manager lock".to_string()))?;

        // Step 0: Check if already inactive (idempotent) - AC7
        let current_state = manager.current_state()?;
        if current_state == SystemState::Inactive {
            return Ok(DeactivationReport {
                cleanup_report: CleanupReport::default(),
                unmounted_overlays: Vec::new(),
                duration: start.elapsed(),
                final_state: SystemState::Inactive,
                was_already_inactive: true,
            });
        }

        // Verify we're in ACTIVE state
        if !current_state.is_active() {
            return Err(NailsError::InvalidState(format!(
                "Cannot deactivate from state {:?}. Must be ACTIVE.",
                current_state
            )));
        }

        // Extract overlays BEFORE transitioning to DEACTIVATING state
        // This fixes the bug where get_mounted_overlay_paths() returns empty vec for Deactivating state
        let overlays_to_unmount = match &current_state {
            SystemState::Active { overlays, .. } => overlays.clone(),
            _ => {
                return Err(NailsError::InvalidState(
                    "Cannot extract overlays: not in ACTIVE state".to_string(),
                ));
            }
        };

        // Step 1: Create StateGuard for ACTIVE → DEACTIVATING transition
        // StateGuard will automatically rollback to ACTIVE if we don't call commit()
        let guard = StateGuard::new(Arc::clone(&self.manager), current_state.clone());

        // Transition to DEACTIVATING state
        let deactivating_state = SystemState::Deactivating {
            started_at: chrono::Utc::now(),
        };
        manager.update_state(deactivating_state)?;

        // Step 2: Cleanup artifacts - AC2, AC4
        let cleanup_report = match self.execute_cleanup(&manager) {
            Ok(report) => report,
            Err(e) => {
                // Cleanup failed - StateGuard will rollback to ACTIVE
                tracing::error!(
                    "Cleanup failed, keeping system ACTIVE. Overlays remain mounted: {}",
                    e
                );
                // IMPORTANT: Drop manager lock BEFORE returning so StateGuard can acquire it for rollback
                drop(manager);
                return Err(e);
            }
        };

        // Step 3: Unmount overlays - AC2, AC5, AC6
        let unmounted = match self.unmount_overlays(&manager, &overlays_to_unmount) {
            Ok(overlays) => overlays,
            Err(e) => {
                // Unmount failed - StateGuard will rollback to ACTIVE
                tracing::error!("Unmount failed, rolling back to ACTIVE: {}", e);
                // IMPORTANT: Drop manager lock BEFORE returning so StateGuard can acquire it for rollback
                drop(manager);
                return Err(e);
            }
        };

        // Step 4: Transition to INACTIVE - AC2
        manager.force_state(SystemState::Inactive)?;

        // Step 5: Commit StateGuard (prevent rollback) - AC2
        guard.commit();

        Ok(DeactivationReport {
            cleanup_report,
            unmounted_overlays: unmounted,
            duration: start.elapsed(),
            final_state: SystemState::Inactive,
            was_already_inactive: false,
        })
    }

    /// Execute cleanup operations
    ///
    /// Creates a CleanupManager and executes cleanup in Thorough mode with verification.
    ///
    /// # Arguments
    ///
    /// * `manager` - Reference to NailsManager for filesystem access
    ///
    /// # Returns
    ///
    /// CleanupReport with details of what was cleaned
    ///
    /// # Errors
    ///
    /// # Returns
    ///
    /// CleanupReport with details of what was cleaned
    ///
    /// # Errors
    ///
    /// Returns Err if cleanup fails or has critical errors that should prevent deactivation.
    /// Per AC4: cleanup failures should trigger rollback to ACTIVE state.
    fn execute_cleanup(&self, manager: &NailsManager<F>) -> Result<CleanupReport> {
        let cleanup_manager = CleanupManager::new(
            manager.filesystem().clone(),
            self.cleanup_config.clone(),
            CleanupMode::Thorough {
                verify_cleanup: true,
            },
        );

        let report = cleanup_manager.cleanup()?;

        // AC4: If cleanup has errors, treat as failure and trigger rollback
        // Forensic safety requires that we don't proceed with deactivation if
        // traces couldn't be cleaned (e.g., permission denied on history files)
        if !report.errors.is_empty() {
            let error_summary = report.errors.join("; ");
            return Err(NailsError::CleanupError(format!(
                "Cleanup had {} error(s): {}. Overlays remain mounted. State: ACTIVE",
                report.errors.len(),
                error_summary
            )));
        }

        // Also check verification result (Thorough mode)
        // If verification failed, artifacts may remain - unsafe to deactivate
        if let Some(false) = report.verification_passed {
            return Err(NailsError::CleanupError(
                "Cleanup verification failed: forensic artifacts may remain. Overlays remain mounted. State: ACTIVE".to_string()
            ));
        }

        Ok(report)
    }

    /// Unmount overlays in reverse order
    ///
    /// Unmounts the provided overlay list in reverse LIFO order. If any unmount fails,
    /// attempts rollback by remounting successfully unmounted overlays.
    ///
    /// # Arguments
    ///
    /// * `manager` - Reference to NailsManager for filesystem access
    /// * `overlays` - List of overlay paths to unmount
    ///
    /// # Returns
    ///
    /// Vec of successfully unmounted overlay paths (as strings)
    ///
    /// # Errors
    ///
    /// Returns Err if unmounting fails, after attempting rollback
    ///
    /// # Requirements
    ///
    /// - AC2: Unmount overlays in reverse order
    /// - AC5: Rollback on unmount failure with force option
    /// - AC6: Partial unmount rollback (remount)
    fn unmount_overlays(
        &self,
        manager: &NailsManager<F>,
        overlays: &[PathBuf],
    ) -> Result<Vec<String>> {
        let mut unmounted = Vec::new();

        // Reverse order (LIFO - unmount in reverse of mount order)
        let overlays_reversed: Vec<_> = overlays.iter().rev().collect();

        for overlay_path in overlays_reversed {
            match self.unmount_single_overlay(manager, overlay_path) {
                Ok(()) => {
                    unmounted.push(overlay_path.to_string_lossy().to_string());
                }
                Err(e) => {
                    // Unmount failed - need to rollback
                    tracing::error!("Unmount failed for {}: {}", overlay_path.display(), e);
                    self.rollback_unmounts(manager, &unmounted)?;
                    return Err(e);
                }
            }
        }

        Ok(unmounted)
    }

    /// Unmount a single overlay with graceful → force fallback
    ///
    /// Tries graceful unmount first. If that fails with MountBusy, tries force unmount.
    ///
    /// # Arguments
    ///
    /// * `manager` - Reference to NailsManager for filesystem access
    /// * `path` - Path to unmount
    ///
    /// # Returns
    ///
    /// Ok(()) if unmount succeeds (graceful or force)
    ///
    /// # Errors
    ///
    /// Returns Err if both graceful and force unmount fail
    ///
    /// # Requirements
    ///
    /// - AC5: Force unmount on graceful failure
    fn unmount_single_overlay(
        &self,
        manager: &NailsManager<F>,
        path: &std::path::Path,
    ) -> Result<()> {
        // Try graceful unmount first
        match manager.filesystem().unmount(path, false) {
            Ok(()) => {
                tracing::info!("✓ Gracefully unmounted {}", path.display());
                Ok(())
            }
            Err(NailsError::MountBusy { .. }) => {
                // Try force unmount
                tracing::warn!("Mount busy for {}, trying force unmount", path.display());
                manager.filesystem().unmount(path, true)
            }
            Err(e) => Err(e),
        }
    }

    /// Rollback by remounting successfully unmounted overlays
    ///
    /// When an unmount fails midway through the process, we need to remount
    /// the overlays that were already unmounted to return to ACTIVE state.
    ///
    /// This is a best-effort operation - individual remount failures are logged
    /// but don't cause the entire rollback to fail.
    ///
    /// # Arguments
    ///
    /// * `manager` - Reference to NailsManager for filesystem access
    /// * `unmounted` - List of overlay paths that were successfully unmounted
    ///
    /// # Returns
    ///
    /// Ok(()) - Rollback attempted (may have partial failures)
    ///
    /// # Errors
    ///
    /// Does not return errors - logs warnings for any remount failures
    ///
    /// # Requirements
    ///
    /// - AC6: Partial unmount rollback
    /// - AC9: rollback_on_unmount_failure() implementation
    /// - FR51: Remount overlays if cleanup fails
    fn rollback_unmounts(&self, manager: &NailsManager<F>, unmounted: &[String]) -> Result<()> {
        tracing::warn!(
            "Rolling back unmounts - attempting to remount {} overlays",
            unmounted.len()
        );

        let mut remounted_count = 0;

        // Remount in reverse order of unmounting (LIFO: last unmounted = first remounted)
        for overlay_str in unmounted.iter().rev() {
            let overlay_path = PathBuf::from(overlay_str);

            // Attempt to get mount info from the filesystem
            // MockFilesystem stores this when mount_overlay() is called
            // Note: In real scenarios, mount info should be persisted in state file
            // For now, we use the filesystem's tracking (works for MockFilesystem tests)
            if let Some(mount_info) = manager.filesystem().get_mount_info(&overlay_path) {
                tracing::info!(
                    "Rollback: Remounting {} (lower={}, upper={}, work={})",
                    overlay_str,
                    mount_info.lower.display(),
                    mount_info.upper.display(),
                    mount_info.work.display()
                );

                match manager.filesystem().mount_overlay(
                    &mount_info.lower,
                    &mount_info.upper,
                    &mount_info.work,
                    &mount_info.target,
                ) {
                    Ok(()) => {
                        tracing::info!("✓ Successfully remounted {}", overlay_str);
                        remounted_count += 1;
                    }
                    Err(e) => {
                        // Log but continue - best-effort rollback
                        tracing::warn!(
                            "Warning: Failed to remount {} during rollback: {}",
                            overlay_str,
                            e
                        );
                    }
                }
            } else {
                // No mount info available - log warning but continue
                tracing::warn!(
                    "Rollback: Cannot remount {} - mount info not available (overlay may need manual recovery)",
                    overlay_str
                );
            }
        }

        tracing::info!(
            "Rollback complete: Remounted {}/{} overlays",
            remounted_count,
            unmounted.len()
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, MockFilesystem};
    use std::path::Path;

    /// Helper function to create a test manager in ACTIVE state
    fn setup_active_manager() -> Arc<Mutex<NailsManager<MockFilesystem>>> {
        let fs = MockFilesystem::new();

        // Setup mock filesystem for active state
        fs.mock_set_path_exists("/mnt/hidden-volume", true);
        fs.mock_set_path_exists("/mnt/hidden-volume/.nails", true);
        fs.mock_set_path_type("/mnt/hidden-volume", "directory");
        fs.mock_set_path_type("/mnt/hidden-volume/.nails", "directory");

        let temp_dir = tempfile::tempdir().unwrap();
        let mock_hidden_vol = temp_dir.path();
        let state_dir = mock_hidden_vol.join(".nails");
        std::fs::create_dir_all(&state_dir).unwrap();
        let state_path = state_dir.join("state.json");

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };

        let mut manager = NailsManager::new(fs, config, state_path);

        // Set state to ACTIVE
        manager
            .force_state(SystemState::Active {
                activated_at: chrono::Utc::now(),
                overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
            })
            .unwrap();

        Arc::new(Mutex::new(manager))
    }

    #[test]
    fn test_deactivation_report_new() {
        let report = DeactivationReport {
            cleanup_report: CleanupReport::default(),
            unmounted_overlays: vec!["/home".to_string(), "/etc".to_string()],
            duration: Duration::from_millis(150),
            final_state: SystemState::Inactive,
            was_already_inactive: false,
        };

        assert!(report.is_successful());
        assert_eq!(report.unmounted_overlays.len(), 2);
        assert!(!report.was_already_inactive);
    }

    #[test]
    fn test_deactivation_report_display_already_inactive() {
        let report = DeactivationReport {
            cleanup_report: CleanupReport::default(),
            unmounted_overlays: Vec::new(),
            duration: Duration::from_millis(5),
            final_state: SystemState::Inactive,
            was_already_inactive: true,
        };

        let output = format!("{}", report);
        assert!(output.contains("Already inactive"));
    }

    #[test]
    fn test_deactivation_report_display_with_items() {
        let mut cleanup_report = CleanupReport::new(CleanupMode::Fast);
        cleanup_report.add_cleaned("Removed 3 history entries");
        cleanup_report.duration = Duration::from_millis(100);

        let report = DeactivationReport {
            cleanup_report,
            unmounted_overlays: vec!["/home".to_string(), "/etc".to_string()],
            duration: Duration::from_millis(150),
            final_state: SystemState::Inactive,
            was_already_inactive: false,
        };

        let output = format!("{}", report);
        assert!(output.contains("Deactivation Report"));
        assert!(output.contains("Removed 3 history entries"));
        assert!(output.contains("/home"));
        assert!(output.contains("/etc"));
        assert!(output.contains("Deactivation complete"));
    }

    #[test]
    fn test_deactivation_orchestrator_new() {
        let manager = setup_active_manager();
        let config = CleanupConfig::default();

        let orchestrator = DeactivationOrchestrator::new(Arc::clone(&manager), config.clone());

        // Verify orchestrator is created with correct config
        assert_eq!(
            orchestrator.cleanup_config.clear_history,
            config.clear_history
        );
    }

    #[test]
    fn test_idempotent_deactivation() {
        // Setup manager in INACTIVE state
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/hidden-volume", true);

        let temp_dir = tempfile::tempdir().unwrap();
        let mock_hidden_vol = temp_dir.path();
        let state_dir = mock_hidden_vol.join(".nails");
        std::fs::create_dir_all(&state_dir).unwrap();
        let state_path = state_dir.join("state.json");

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };

        let mut manager = NailsManager::new(fs, config, state_path);
        manager.force_state(SystemState::Inactive).unwrap();

        let manager = Arc::new(Mutex::new(manager));
        let orchestrator =
            DeactivationOrchestrator::new(Arc::clone(&manager), CleanupConfig::default());

        // Run deactivation when already inactive
        let result = orchestrator.run();
        assert!(result.is_ok());

        let report = result.unwrap();
        assert!(report.was_already_inactive);
        assert_eq!(report.final_state, SystemState::Inactive);
        assert_eq!(report.unmounted_overlays.len(), 0);
    }

    #[test]
    fn test_deactivation_from_non_active_state_fails() {
        // Setup manager in ACTIVATING state (invalid for deactivation)
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/hidden-volume", true);

        let temp_dir = tempfile::tempdir().unwrap();
        let mock_hidden_vol = temp_dir.path();
        let state_dir = mock_hidden_vol.join(".nails");
        std::fs::create_dir_all(&state_dir).unwrap();
        let state_path = state_dir.join("state.json");

        let config = Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![],
            ..Config::test_default()
        };

        let mut manager = NailsManager::new(fs, config, state_path);
        manager
            .force_state(SystemState::Activating {
                started_at: chrono::Utc::now(),
            })
            .unwrap();

        let manager = Arc::new(Mutex::new(manager));
        let orchestrator =
            DeactivationOrchestrator::new(Arc::clone(&manager), CleanupConfig::default());

        // Run deactivation from ACTIVATING state (should fail)
        let result = orchestrator.run();
        assert!(result.is_err());

        match result {
            Err(NailsError::InvalidState(msg)) => {
                assert!(msg.contains("Cannot deactivate from state"));
                assert!(msg.contains("Must be ACTIVE"));
            }
            _ => panic!("Expected InvalidState error"),
        }
    }

    #[test]
    fn test_successful_deactivation() {
        let manager = setup_active_manager();

        // Setup filesystem mocks for unmount
        {
            let m = manager.lock().unwrap();
            m.filesystem().mock_set_mounted(Path::new("/home"), true);
            m.filesystem().mock_set_mounted(Path::new("/etc"), true);
        }

        let orchestrator =
            DeactivationOrchestrator::new(Arc::clone(&manager), CleanupConfig::default());

        let result = orchestrator.run();
        assert!(result.is_ok());

        let report = result.unwrap();
        assert!(report.is_successful());
        assert_eq!(report.final_state, SystemState::Inactive);
        assert!(!report.was_already_inactive);

        // Verify state is now INACTIVE
        let m = manager.lock().unwrap();
        let state = m.current_state().unwrap();
        assert_eq!(state, SystemState::Inactive);
    }

    #[test]
    fn test_cleanup_failure_rollback() {
        let manager = setup_active_manager();

        // Configure cleanup to FAIL by making the history file write fail
        // This triggers AC4: cleanup failure → rollback to ACTIVE
        {
            let m = manager.lock().unwrap();
            let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
            let bash_history = Path::new(&home).join(".bash_history");
            let bash_history_str = bash_history.to_str().unwrap();

            // Set up history file that exists with "nails" content
            m.filesystem().mock_set_path_exists(bash_history_str, true);

            // Set up file content that contains "nails" pattern
            m.filesystem()
                .mock_set_file_content(bash_history_str, "nails activate\nsome other command\n");

            // Make write fail so cleanup can't actually clean the file
            // This simulates a permission error or filesystem issue during cleanup
            m.filesystem()
                .mock_set_write_should_fail(bash_history_str, true);
        }

        let orchestrator =
            DeactivationOrchestrator::new(Arc::clone(&manager), CleanupConfig::default());

        let result = orchestrator.run();

        // AC4: Cleanup failure should cause deactivation to fail and rollback to ACTIVE
        // This is required for forensic safety - if traces can't be cleaned, we must
        // remain in ACTIVE state with overlays mounted
        assert!(
            result.is_err(),
            "Expected cleanup to fail, got: {:?}",
            result
        );

        // Verify it's a CleanupError
        match &result {
            Err(NailsError::CleanupError(msg)) => {
                assert!(
                    msg.contains("Overlays remain mounted") || msg.contains("verification failed"),
                    "Expected error message about rollback, got: {}",
                    msg
                );
            }
            _ => panic!("Expected CleanupError, got: {:?}", result),
        }

        // Verify state rolled back to ACTIVE via StateGuard RAII
        // AC4: "StateGuard automatically rolls back to ACTIVE"
        let m = manager.lock().unwrap();
        let state = m.current_state().unwrap();
        assert!(
            state.is_active(),
            "AC4 violation: Expected ACTIVE state after cleanup failure, got {:?}",
            state
        );
    }

    #[test]
    fn test_cleanup_failure_keeps_overlays_mounted() {
        // Additional test for AC4: verify overlays remain mounted after cleanup failure
        let manager = setup_active_manager();

        // Setup overlays as mounted
        {
            let m = manager.lock().unwrap();
            m.filesystem().mock_set_mounted(Path::new("/home"), true);
            m.filesystem().mock_set_mounted(Path::new("/etc"), true);

            // Configure cleanup to fail by making write fail
            let home = std::env::var("HOME").unwrap_or_else(|_| "/home/user".to_string());
            let bash_history = Path::new(&home).join(".bash_history");
            let bash_history_str = bash_history.to_str().unwrap();
            m.filesystem().mock_set_path_exists(bash_history_str, true);
            m.filesystem()
                .mock_set_file_content(bash_history_str, "nails activate\nsome command\n");
            // Make write fail so cleanup can't actually clean the file
            m.filesystem()
                .mock_set_write_should_fail(bash_history_str, true);
        }

        let orchestrator =
            DeactivationOrchestrator::new(Arc::clone(&manager), CleanupConfig::default());

        let _result = orchestrator.run();

        // Verify overlays are still mounted (AC4: "overlays are NOT unmounted")
        let m = manager.lock().unwrap();
        let fs = m.filesystem();
        assert!(
            fs.is_mounted(Path::new("/home")).unwrap(),
            "AC4 violation: /home should remain mounted after cleanup failure"
        );
        assert!(
            fs.is_mounted(Path::new("/etc")).unwrap(),
            "AC4 violation: /etc should remain mounted after cleanup failure"
        );
    }
}
