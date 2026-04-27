//! Overlay Mounting Logic
//!
//! Handles mounting both persistent and ephemeral overlays with process detection
//! and automatic rollback on failure.
//!
//! Split into sub-modules:
//! - `auto_mount` - Auto mode overlay mounting (dynamic target enumeration)
//! - `explicit_mount` - Explicit mode overlay mounting (pre-configured overlays)

mod auto_mount;
mod explicit_mount;
mod restore;

#[allow(unused_imports)]
use super::{
    MountInfo, MountTracker, MountType, build_overlay_targets, clean_stale_network_config,
    create_overlay_config, start_service_and_socket,
};
use crate::{
    FailedOverlayInfo, Filesystem, NailsError, NailsManager, OverlayInfo, Result, Verbosity,
    inject_import_block,
};
use chrono::Utc;
use std::path::{Path, PathBuf};

impl<F: Filesystem> NailsManager<F> {
    /// Mount persistent and ephemeral overlays
    ///
    /// Returns: (direct_mounts, pivot_mounts, pivot_targets, mounted_overlays)
    /// Note: Tracker is committed before returning, so no rollback on drop
    pub(super) fn mount_overlays(
        &self,
        options: &crate::ActivateOptions,
        verbosity: Verbosity,
    ) -> Result<(usize, usize, Vec<PathBuf>, Vec<PathBuf>)> {
        if verbosity >= Verbosity::Normal {
            tracing::info!("Mounting overlays...");
        }

        // Create shared tracker for both persistent and ephemeral overlays (Story 4.11)
        // Tracker will be committed only after full activation succeeds.
        let mut tracker = MountTracker::new(&self.filesystem);

        // Build OverlayStrategyOptions from ActivateOptions (Story 4.15, AC8)
        let strategy_options = crate::overlay::OverlayStrategyOptions {
            auto_restart_safe: true,        // Always restart safe processes automatically
            prompt_for_risky: !options.yes, // Skip risky prompts if --yes flag
            allow_pivot: !options.no_pivot, // Respect --no-pivot flag
            auto_accept_pivot: options.accept_pivot_risks, // Auto-accept if --accept-pivot-risks
            skip_process_detection: options
                .skip_process_detection_override
                .unwrap_or(cfg!(test)), // Allow tests to override
        };

        // Track mount methods for logging
        let mut direct_mounts = 0;
        let mut pivot_mounts = 0;
        let mut pivot_targets: Vec<PathBuf> = Vec::new();

        // Step 8a: Mount persistent overlays using universal algorithm (Story 4.15)
        // Story 14.10: Use dynamic target list based on overlay_mode
        match self.config.overlay_mode {
            crate::OverlayMode::Auto => {
                self.mount_auto_overlays(
                    &mut tracker,
                    &strategy_options,
                    verbosity,
                    &mut direct_mounts,
                    &mut pivot_mounts,
                    &mut pivot_targets,
                )?;
            }
            crate::OverlayMode::Explicit => {
                self.mount_explicit_overlays(
                    &mut tracker,
                    &strategy_options,
                    verbosity,
                    &mut direct_mounts,
                    &mut pivot_mounts,
                    &mut pivot_targets,
                )?;
            }
        }

        // Extract persistent overlay paths for state file (before mounting ephemeral)
        let mounted_overlays: Vec<PathBuf> = tracker
            .mounted
            .iter()
            .filter(|info| info.mount_type == MountType::Persistent)
            .map(|info| info.target.clone())
            .collect();

        // Step 8b: Mount ephemeral overlays (/var, /tmp, /srv, /opt) - Story 4.11
        // These are RAM-backed and NOT tracked in state file (ephemeral = destroyed on unmount)
        if self.config.extended_overlays.enabled {
            self.mount_ephemeral_overlays(&mut tracker, verbosity)?;
        }

        // Story 9.3 AC#1: Log overlays mounted with structured fields
        let mounted_paths: Vec<_> = tracker
            .mounted
            .iter()
            .map(|info| info.target.clone())
            .collect();
        tracing::info!(overlays = ?mounted_paths, "Overlays mounted");

        // Commit tracker before returning to prevent rollback on drop
        tracker.commit();

        Ok((direct_mounts, pivot_mounts, pivot_targets, mounted_overlays))
    }

    /// Handle successful overlay mount with service restart and state tracking
    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_mount_success(
        &self,
        tracker: &mut MountTracker<F>,
        overlay: &crate::OverlayConfig,
        mount_result: &crate::overlay::MountResult,
        verbosity: Verbosity,
        direct_mounts: &mut usize,
        pivot_mounts: &mut usize,
        pivot_targets: &mut Vec<PathBuf>,
        nix_overlay_succeeded: &mut bool,
    ) -> Result<()> {
        use crate::overlay::MountMethod;

        // Track mount type for logging
        match mount_result.method {
            MountMethod::Direct => {
                *direct_mounts += 1;
                if verbosity >= Verbosity::Verbose {
                    tracing::info!(
                        "  ✓ {} mounted (direct, optimal security)",
                        overlay.target.display()
                    );
                }
            }
            MountMethod::Pivot => {
                *pivot_mounts += 1;
                pivot_targets.push(overlay.target.clone());
                if verbosity >= Verbosity::Verbose {
                    tracing::warn!(
                        "  ⚠️  {} mounted (pivot, degraded security)",
                        overlay.target.display()
                    );
                }
            }
        }

        // Post-mount: restart stopped services so they write to overlay
        for service in &mount_result.stopped_services {
            if overlay.target == Path::new("/nix") && service == "nix-daemon" {
                tracing::info!(
                    service = %service,
                    target = %overlay.target.display(),
                    "Deferring {} restart to post-/nix restore path",
                    service
                );
                continue;
            }

            start_service_and_socket(service);
            tracing::info!(
                service = %service,
                target = %overlay.target.display(),
                "Restarted {} (now writing to overlay)", service
            );
        }

        // Track if /nix overlay succeeded for post-mount lifecycle
        if overlay.target == Path::new("/nix") {
            *nix_overlay_succeeded = true;
        }

        // After /var overlay is mounted, unconditionally restart systemd-journald
        // to ensure all logs are written to the overlay (prevents underlay leakage)
        if overlay.target == Path::new("/var") {
            start_service_and_socket("systemd-journald");
            tracing::info!(
                "Restarted systemd-journald after /var overlay mount (prevents log leakage)"
            );
        }

        tracker.push_mount(MountInfo::persistent(overlay.target.clone()));

        // Story 15.1, AC2/AC4: After /etc overlay is mounted, inject the
        // NAILS import block into the overlayed hardware-configuration.nix.
        // Writes land in the upper layer — the base underlay is untouched (AC3).
        if overlay.target == Path::new("/etc")
            && let Err(e) = inject_import_block(&self.filesystem)
        {
            tracing::error!(
                error = %e,
                rollback = true,
                "Failed to inject NAILS import block into /etc/nixos/hardware-configuration.nix: {}",
                e
            );
            if let Err(rollback_err) = tracker.rollback_all() {
                tracing::error!(
                    error = %rollback_err,
                    context = "inject_import_block_failure",
                    rollback = true,
                    "Rollback failed after inject_import_block failure"
                );
            }
            return Err(e);
        }

        // Story 4.7, AC2, Task 4: Update overlay_status incrementally after EACH mount
        let overlay_info = OverlayInfo {
            mount_path: overlay.target.clone(),
            lower_dir: overlay.lower.clone(),
            upper_dir: overlay.upper.clone(),
            work_dir: overlay.work.clone(),
            mounted_at: Utc::now(),
        };

        // Update cached state with this mount
        let mut cached = self
            .cached_state
            .lock()
            .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
        if let Some(ref mut state_file) = *cached {
            state_file
                .overlay_status
                .insert(overlay.target.clone(), overlay_info);

            drop(cached); // Release lock before saving
            if let Err(e) = self.save_cached_state()
                && verbosity >= Verbosity::Debug
            {
                tracing::warn!("Failed to save state after mount: {}", e);
            }
        }

        Ok(())
    }

    /// Mount ephemeral overlays (RAM-backed, not persisted in state)
    fn mount_ephemeral_overlays(
        &self,
        tracker: &mut MountTracker<F>,
        verbosity: Verbosity,
    ) -> Result<()> {
        if verbosity >= Verbosity::Verbose {
            tracing::info!("Mounting ephemeral overlays...");
        }

        for ephemeral_dir in &self.config.extended_overlays.directories {
            if verbosity >= Verbosity::Debug {
                tracing::debug!(
                    "Mounting ephemeral overlay: {} (upper: {}, work: {})",
                    ephemeral_dir.path.display(),
                    ephemeral_dir.tmpfs_upper_size,
                    ephemeral_dir.tmpfs_work_size
                );
            }

            // Use pivot_ephemeral_mount for active directories (Story 4.11)
            // Direct mount fails with EINVAL on busy directories like /var
            // Pivot strategy: mount to staging → bind mount to target
            match crate::overlay::pivot_ephemeral_mount(
                &self.filesystem,
                ephemeral_dir,
                &ephemeral_dir.path,
            ) {
                Ok(mount_info) => {
                    // Track pivot mount with staging + tmpfs paths for rollback
                    // Note: staging path is also needed for proper unmount
                    tracker.push_mount(MountInfo::ephemeral(
                        mount_info.target.clone(),
                        vec![
                            mount_info.staging.clone(), // staging (overlay mount point)
                            mount_info
                                .upper
                                .parent()
                                .expect("ephemeral upper should have shared tmpfs parent")
                                .to_path_buf(), // shared tmpfs backing
                        ],
                    ));

                    if verbosity >= Verbosity::Verbose {
                        tracing::info!(
                            "  ✓ {} mounted (ephemeral, RAM-backed)",
                            ephemeral_dir.path.display()
                        );
                    }
                }
                Err(e) => {
                    // Story 9.3 AC#2: Structured error event for ephemeral mount failure
                    tracing::error!(
                        error = %e,
                        target = %ephemeral_dir.path.display(),
                        mount_type = "ephemeral",
                        rollback = true,
                        "Ephemeral overlay mount failed"
                    );

                    // Rollback all mounts (persistent + any ephemeral that succeeded)
                    if let Err(rollback_err) = tracker.rollback_all() {
                        tracing::error!(
                            error = %rollback_err,
                            context = "ephemeral_mount_failure_recovery",
                            rollback = true,
                            "Rollback failed during ephemeral mount failure recovery"
                        );
                    }
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// Record failed overlay mounts in state for status reporting
    pub(super) fn record_failed_overlays(
        &self,
        mount_failures: &[(PathBuf, NailsError)],
        verbosity: Verbosity,
    ) -> Result<()> {
        let failed_infos: Vec<FailedOverlayInfo> = mount_failures
            .iter()
            .map(|(path, error)| FailedOverlayInfo {
                target: path.clone(),
                error_message: error.to_string(),
                failed_at: Utc::now(),
            })
            .collect();

        tracing::warn!(
            failed_count = failed_infos.len(),
            "Recording {} failed overlay(s) in state for status reporting",
            failed_infos.len()
        );

        let mut cached = self
            .cached_state
            .lock()
            .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
        if let Some(ref mut state_file) = *cached {
            state_file.failed_overlays = failed_infos;
            drop(cached);
            if let Err(e) = self.save_cached_state()
                && verbosity >= Verbosity::Debug
            {
                tracing::warn!("Failed to save failed_overlays to state: {}", e);
            }
        }

        Ok(())
    }
}
