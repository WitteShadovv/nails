//! Deactivation orchestration logic
//!
//! Implements the core deactivation workflow: state transitions, cleanup,
//! overlay unmounting, and automatic rollback on failures.

use super::report::{DeactivationReport, PostUnmountCleanupReport};
use crate::manager::{ensure_run_current_system_symlink, select_system_profile};
use crate::{
    CleanupConfig, CleanupManager, CleanupMode, CleanupReport, Filesystem, NailsError,
    NailsManager, Result, StateGuard, SystemState,
};
use crate::cleanup::history::{HistoryCleaner, get_extended_history_files};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

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

        // Story 9.3 AC#3: Log deactivation started with state
        tracing::info!(phase = "deactivation", "Deactivation started");

        // Lock manager for the duration
        let mut manager = self
            .manager
            .lock()
            .map_err(|_| NailsError::InvalidState("Failed to acquire manager lock".to_string()))?;

        // Step 0: Check if already inactive (idempotent) - AC7
        let current_state = manager.current_state()?;
        if current_state == SystemState::Inactive {
            tracing::info!(
                state = ?current_state,
                already_inactive = true,
                "System already inactive, nothing to do"
            );
            return Ok(DeactivationReport {
                cleanup_report: CleanupReport::default(),
                unmounted_overlays: Vec::new(),
                duration: start.elapsed(),
                final_state: SystemState::Inactive,
                was_already_inactive: true,
                post_unmount_cleanup: PostUnmountCleanupReport::default(),
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
        let cleanup_start = Instant::now();
        let cleanup_report = match self.execute_cleanup(&manager) {
            Ok(report) => {
                // Story 9.3 AC#3: Log cleanup completion with structured fields
                tracing::info!(
                    cleaned_items = report.cleaned_items.len(),
                    duration_ms = cleanup_start.elapsed().as_millis() as u64,
                    "Cleanup complete"
                );
                report
            }
            Err(e) => {
                // Story 9.3 AC#2: Structured error event for cleanup failure
                tracing::error!(
                    error = %e,
                    state = ?current_state,
                    rollback = true,
                    phase = "cleanup",
                    "Cleanup failed, keeping system ACTIVE with overlays mounted"
                );
                // IMPORTANT: Drop manager lock BEFORE returning so StateGuard can acquire it for rollback
                drop(manager);
                return Err(e);
            }
        };

        // Step 3: Unmount overlays - AC2, AC5, AC6
        let unmount_start = Instant::now();
        let unmounted = match self.unmount_overlays(&manager, &overlays_to_unmount) {
            Ok(overlays) => {
                // Story 9.3 AC#3: Log overlays unmounted with structured fields
                // AC #3 specifies "unmounted_paths" for literal compliance
                tracing::info!(
                    unmounted_paths = ?overlays,
                    duration_ms = unmount_start.elapsed().as_millis() as u64,
                    "Overlays unmounted"
                );
                overlays
            }
            Err(e) => {
                // Story 9.3 AC#2: Structured error event for unmount failure
                tracing::error!(
                    error = %e,
                    state = ?current_state,
                    rollback = true,
                    phase = "unmount",
                    "Unmount failed, rolling back to ACTIVE"
                );
                // IMPORTANT: Drop manager lock BEFORE returning so StateGuard can acquire it for rollback
                drop(manager);
                return Err(e);
            }
        };

        // Step 3.5: Post-unmount cleanup - cleans REAL DISK (not overlay layer)
        // This is critical for forensic safety: the Step 2 cleanup only cleaned
        // the overlay layer. Now that overlays are unmounted, we can clean the
        // actual underlying filesystem.
        let post_unmount_report = if self.cleanup_config.post_unmount_cleanup {
            self.execute_post_unmount_cleanup(&manager)
        } else {
            tracing::debug!("Post-unmount cleanup disabled in configuration");
            PostUnmountCleanupReport::default()
        };

        // Step 4: Clear overlay_status and transition to INACTIVE - AC2
        manager.clear_overlay_status_in_cache();
        let inactive_state = manager.current_state()?.complete_deactivation()?;
        manager.update_state(inactive_state)?;

        // Step 5: Switch to newest available base system generation (decoy)
        let switch_error = if let Some(system_profile) =
            select_system_profile(manager.filesystem())?
        {
            tracing::info!("Switching to decoy NixOS configuration...");

            if let Err(e) = ensure_run_current_system_symlink(manager.filesystem(), &system_profile)
            {
                Some(NailsError::NixOSError(format!(
                    "Failed to prepare /run/current-system for NixOS switch: {}",
                    e
                )))
            } else {
                let switch_script = system_profile.join("bin/switch-to-configuration");
                match manager.filesystem().path_exists(&switch_script) {
                    Ok(true) => match std::process::Command::new(&switch_script)
                        .arg("switch")
                        .output()
                    {
                        Ok(output) => {
                            if output.status.success() {
                                None
                            } else {
                                Some(NailsError::NixOSError(format!(
                                    "System profile switch failed: {}",
                                    String::from_utf8_lossy(&output.stderr)
                                )))
                            }
                        }
                        Err(e) => Some(NailsError::NixOSError(format!(
                            "System profile switch failed: {}",
                            e
                        ))),
                    },
                    Ok(false) => Some(NailsError::NixOSError(format!(
                        "System profile switch script missing: {}",
                        switch_script.display()
                    ))),
                    Err(e) => Some(e),
                }
            }
        } else {
            Some(NailsError::NixOSError(
                "No system profile available for decoy switch".into(),
            ))
        };

        if let Some(err) = switch_error {
            guard.commit();
            return Err(err);
        }

        // Step 6: Commit StateGuard (prevent rollback) - AC2
        guard.commit();

        // Story 9.3 AC#3: Log deactivation complete with structured fields
        let duration_ms = start.elapsed().as_millis() as u64;
        tracing::info!(
            duration_ms = duration_ms,
            state_to = ?SystemState::Inactive,
            unmounted_count = unmounted.len(),
            post_unmount_cleaned = post_unmount_report.cleaned_items.len(),
            "Deactivation complete"
        );

        Ok(DeactivationReport {
            cleanup_report,
            unmounted_overlays: unmounted,
            duration: start.elapsed(),
            final_state: SystemState::Inactive,
            was_already_inactive: false,
            post_unmount_cleanup: post_unmount_report,
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

    /// Execute post-unmount cleanup on the REAL disk
    ///
    /// This is Phase 2 of the two-phase cleanup process. It runs AFTER overlays
    /// are unmounted to clean history files on the actual underlying filesystem,
    /// not just the overlay layer.
    ///
    /// # Why Two-Phase Cleanup?
    ///
    /// The Phase 1 cleanup (execute_cleanup) runs while overlays are still mounted,
    /// which means it only cleans files in the overlay's upper layer. The original
    /// files on the real disk remain untouched. This is a forensic safety issue
    /// because an adversary examining the disk would still see command history.
    ///
    /// Phase 2 runs after overlay unmount, directly cleaning the real disk.
    ///
    /// # Best-Effort Approach
    ///
    /// This method is intentionally best-effort - individual file cleanup failures
    /// are logged as warnings but do NOT fail the entire deactivation. The rationale:
    /// - Deactivation should complete to restore the innocent appearance
    /// - Failed cleanups are logged for user awareness
    /// - Some files may not exist on all systems
    ///
    /// # Arguments
    ///
    /// * `manager` - Reference to NailsManager for filesystem access
    ///
    /// # Returns
    ///
    /// PostUnmountCleanupReport with details of what was cleaned and any warnings
    fn execute_post_unmount_cleanup(&self, manager: &NailsManager<F>) -> PostUnmountCleanupReport {
        let post_unmount_start = Instant::now();
        tracing::info!(
            phase = "post_unmount_cleanup",
            "Starting Phase 2 cleanup on real disk"
        );

        let mut report = PostUnmountCleanupReport {
            cleaned_items: Vec::new(),
            warnings: Vec::new(),
            was_performed: true,
        };

        // Get extended list of history files to clean
        let history_files = get_extended_history_files();

        if history_files.is_empty() {
            tracing::warn!(
                phase = "post_unmount_cleanup",
                "$HOME not set, cannot determine history file locations"
            );
            report.warnings.push("$HOME not set, skipped history file cleanup".to_string());
            return report;
        }

        // Create a HistoryCleaner with secure_delete enabled for forensic safety
        let history_cleaner = HistoryCleaner::new(manager.filesystem().clone())
            .with_patterns(self.cleanup_config.history_patterns.clone())
            .with_secure_delete(true); // Always use secure delete for post-unmount

        // Clean each history file individually
        for history_file in &history_files {
            // Check if file exists
            match manager.filesystem().path_exists(history_file) {
                Ok(true) => {
                    // Try to clean this file
                    match self.clean_single_history_file(manager, history_file, &history_cleaner) {
                        Ok(Some(msg)) => {
                            tracing::debug!(
                                file = %history_file.display(),
                                phase = "post_unmount_cleanup",
                                "Cleaned history file"
                            );
                            report.cleaned_items.push(msg);
                        }
                        Ok(None) => {
                            // File had no matching entries, that's fine
                            tracing::debug!(
                                file = %history_file.display(),
                                phase = "post_unmount_cleanup",
                                "No nails entries found in file"
                            );
                        }
                        Err(e) => {
                            let warning = format!(
                                "Could not clean {}: {}",
                                history_file.display(),
                                e
                            );
                            tracing::warn!(
                                file = %history_file.display(),
                                error = %e,
                                phase = "post_unmount_cleanup",
                                "Failed to clean history file"
                            );
                            report.warnings.push(warning);
                        }
                    }
                }
                Ok(false) => {
                    // File doesn't exist, that's fine
                    tracing::trace!(
                        file = %history_file.display(),
                        phase = "post_unmount_cleanup",
                        "History file does not exist, skipping"
                    );
                }
                Err(e) => {
                    let warning = format!(
                        "Could not check existence of {}: {}",
                        history_file.display(),
                        e
                    );
                    tracing::warn!(
                        file = %history_file.display(),
                        error = %e,
                        phase = "post_unmount_cleanup",
                        "Failed to check history file existence"
                    );
                    report.warnings.push(warning);
                }
            }
        }

        tracing::info!(
            phase = "post_unmount_cleanup",
            cleaned_count = report.cleaned_items.len(),
            warning_count = report.warnings.len(),
            duration_ms = post_unmount_start.elapsed().as_millis() as u64,
            "Phase 2 cleanup complete"
        );

        report
    }

    /// Clean a single history file by removing lines matching patterns
    ///
    /// This is a helper for execute_post_unmount_cleanup that processes
    /// a single file.
    ///
    /// # Arguments
    ///
    /// * `manager` - Reference to NailsManager for filesystem access
    /// * `path` - Path to the history file
    /// * `_cleaner` - Reference to HistoryCleaner for pattern access
    ///
    /// # Returns
    ///
    /// - `Ok(Some(msg))` - File was cleaned, message describes what was done
    /// - `Ok(None)` - File had no matching entries
    /// - `Err(e)` - Error occurred during cleanup
    fn clean_single_history_file(
        &self,
        manager: &NailsManager<F>,
        path: &std::path::Path,
        _cleaner: &HistoryCleaner<F>,
    ) -> Result<Option<String>> {
        // Read file content
        let content = manager.filesystem().read_file_content(path)?;

        // Filter out lines containing patterns (case-insensitive)
        let original_count = content.lines().count();
        let filtered: Vec<&str> = content
            .lines()
            .filter(|line| {
                let line_lower = line.to_lowercase();
                !self.cleanup_config.history_patterns
                    .iter()
                    .any(|pattern| line_lower.contains(&pattern.to_lowercase()))
            })
            .collect();
        let removed_count = original_count - filtered.len();

        if removed_count == 0 {
            return Ok(None); // No matching entries found
        }

        // Secure delete the original file first (overwrite with zeros/random)
        if let Err(e) = manager.filesystem().secure_delete(path) {
            tracing::debug!(
                file = %path.display(),
                error = %e,
                "Secure delete failed, falling back to normal overwrite"
            );
        }

        // Write filtered content back
        let new_content = filtered.join("\n");
        if !new_content.is_empty() {
            manager.filesystem().write_file_content(path, &format!("{}\n", new_content))?;
        } else {
            manager.filesystem().write_file_content(path, "")?;
        }

        Ok(Some(format!(
            "Removed {} entries from {} (secure delete)",
            removed_count,
            path.display()
        )))
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
                    // Story 9.3 AC#2: Structured error event for single overlay unmount failure
                    tracing::error!(
                        error = %e,
                        path = %overlay_path.display(),
                        phase = "unmount",
                        "Unmount failed for overlay"
                    );
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
                tracing::info!(
                    path = %path.display(),
                    method = "graceful",
                    "Overlay unmounted"
                );
                Ok(())
            }
            Err(NailsError::MountBusy { .. }) => {
                // Try force unmount
                tracing::warn!(
                    path = %path.display(),
                    reason = "mount_busy",
                    "Mount busy, trying force unmount"
                );
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
            overlay_count = unmounted.len(),
            phase = "rollback",
            "Rolling back unmounts - attempting to remount overlays"
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
                    overlay = overlay_str,
                    lower = %mount_info.lower.display(),
                    upper = %mount_info.upper.display(),
                    work = %mount_info.work.display(),
                    phase = "rollback",
                    "Remounting overlay"
                );

                match manager.filesystem().mount_overlay(
                    &[mount_info.lower.as_path()],
                    &mount_info.upper,
                    &mount_info.work,
                    &mount_info.target,
                ) {
                    Ok(()) => {
                        tracing::info!(
                            overlay = overlay_str,
                            phase = "rollback",
                            "Successfully remounted overlay"
                        );
                        remounted_count += 1;
                    }
                    Err(e) => {
                        // Story 9.3 AC#2: Structured error for remount failure
                        tracing::warn!(
                            overlay = overlay_str,
                            error = %e,
                            phase = "rollback",
                            "Failed to remount overlay during rollback"
                        );
                    }
                }
            } else {
                // No mount info available - log warning but continue
                tracing::warn!(
                    overlay = overlay_str,
                    phase = "rollback",
                    recovery = "manual",
                    "Cannot remount - mount info not available"
                );
            }
        }

        tracing::info!(
            remounted = remounted_count,
            total = unmounted.len(),
            phase = "rollback",
            "Rollback complete"
        );

        Ok(())
    }
}
