//! Unmount and rollback phase methods for DeactivationOrchestrator

use super::*;

impl<F: Filesystem + 'static> DeactivationOrchestrator<F> {
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
    pub(super) fn unmount_overlays(
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

    /// Unmount a single overlay with graceful -> force fallback
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
            Err(e) => {
                // Try force unmount on any graceful failure
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "Graceful unmount failed, trying force unmount"
                );
                manager.filesystem().unmount(path, true)
            }
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
    pub(super) fn rollback_unmounts(
        &self,
        manager: &NailsManager<F>,
        unmounted: &[String],
    ) -> Result<()> {
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
