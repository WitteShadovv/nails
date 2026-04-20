//! Cleanup phase methods for DeactivationOrchestrator

use super::*;

impl<F: Filesystem + 'static> DeactivationOrchestrator<F> {
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
    /// Returns Err if cleanup fails or has critical errors that should prevent deactivation.
    /// Per AC4: cleanup failures should trigger rollback to ACTIVE state.
    pub(super) fn execute_cleanup(&self, manager: &NailsManager<F>) -> Result<CleanupReport> {
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

    /// Execute cleanup in emergency (fast, best-effort) mode.
    ///
    /// Uses `CleanupMode::Fast` and does not fail on cleanup errors.
    /// Cleanup errors are logged as warnings and included in the report
    /// but do not prevent deactivation from proceeding.
    pub(super) fn execute_emergency_cleanup(
        &self,
        manager: &NailsManager<F>,
    ) -> Result<CleanupReport> {
        let cleanup_config = CleanupConfig {
            clear_history: true,
            clear_temp_files: true,
            clear_logs: true,
            secure_delete: true,
            sanitize_memory: true,
            ..self.cleanup_config.clone()
        };

        let cleanup_manager = CleanupManager::new(
            manager.filesystem().clone(),
            cleanup_config,
            CleanupMode::Fast,
        );

        let report = cleanup_manager.cleanup()?;

        // Log errors as warnings but don't fail
        for error in &report.errors {
            tracing::warn!(error = %error, "Emergency cleanup error (non-fatal)");
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
    pub(super) fn execute_post_unmount_cleanup(
        &self,
        manager: &NailsManager<F>,
    ) -> PostUnmountCleanupReport {
        let post_unmount_start = Instant::now();
        tracing::info!(
            phase = "post_unmount_cleanup",
            "Starting Phase 2 cleanup on real disk"
        );

        // Use truncate_all_history_files for complete forensic cleanup
        // This truncates ALL history files to zero length rather than pattern-filtering,
        // ensuring ZERO commands remain visible to an adversary
        let cleaned_items = truncate_all_history_files(manager.filesystem(), true);

        let report = PostUnmountCleanupReport {
            cleaned_items,
            warnings: Vec::new(), // truncate_all_history_files handles errors internally via logging
            was_performed: true,
        };

        tracing::info!(
            phase = "post_unmount_cleanup",
            cleaned_count = report.cleaned_items.len(),
            duration_ms = post_unmount_start.elapsed().as_millis() as u64,
            "Phase 2 cleanup complete"
        );

        report
    }
}
