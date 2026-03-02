//! Overlay Mounting Logic
//!
//! Handles mounting both persistent and ephemeral overlays with process detection
//! and automatic rollback on failure.

use super::{
    MountInfo, MountTracker, MountType, build_overlay_targets, clean_stale_network_config,
    create_overlay_config, start_service_and_socket,
};
use crate::{
    FailedOverlayInfo, Filesystem, NailsError, NailsManager, OverlayInfo, Result, Verbosity,
    inject_import_block, verify_base_config_clean,
};
use chrono::Utc;
use std::path::{Path, PathBuf};

use super::guards::NixDaemonGuard;

impl<F: Filesystem> NailsManager<F> {
    /// Mount persistent and ephemeral overlays
    ///
    /// Returns: (direct_mounts, pivot_mounts, mounted_overlays)
    /// Note: Tracker is committed before returning, so no rollback on drop
    pub(super) fn mount_overlays(
        &self,
        options: &crate::ActivateOptions,
        verbosity: Verbosity,
    ) -> Result<(usize, usize, Vec<PathBuf>)> {
        // Story 15.1, AC1: Verify base hardware-configuration.nix is forensically clean before
        // any overlays are mounted. Fail activation if the base config already contains
        // NAILS or hidden references that would betray the overlay approach.
        match verify_base_config_clean(&self.filesystem) {
            Ok(true) => {
                tracing::debug!("Base hardware-configuration.nix is clean — proceeding");
            }
            Ok(false) => {
                tracing::error!(
                    "Base /etc/nixos/hardware-configuration.nix contains suspicious references \
                     (NAILS or hidden paths). Activation aborted to preserve forensic integrity."
                );
                return Err(NailsError::NixOSError(
                    "Base hardware-configuration.nix is not forensically clean — \
                     contains NAILS or hidden references before overlay mount"
                        .into(),
                ));
            }
            Err(e) => {
                // Treat unreadable base config as a hard failure to avoid unsafe activation.
                tracing::error!(
                    error = %e,
                    "Could not verify base hardware-configuration.nix; activation aborted"
                );
                return Err(e);
            }
        }

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
                )?;
            }
            crate::OverlayMode::Explicit => {
                self.mount_explicit_overlays(
                    &mut tracker,
                    &strategy_options,
                    verbosity,
                    &mut direct_mounts,
                    &mut pivot_mounts,
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

        Ok((direct_mounts, pivot_mounts, mounted_overlays))
    }

    /// Mount overlays in Auto mode (dynamic target enumeration)
    fn mount_auto_overlays(
        &self,
        tracker: &mut MountTracker<F>,
        strategy_options: &crate::overlay::OverlayStrategyOptions,
        verbosity: Verbosity,
        direct_mounts: &mut usize,
        pivot_mounts: &mut usize,
    ) -> Result<()> {
        // Auto mode: enumerate root + apply exclusions, create overlays dynamically
        let overlay_targets = build_overlay_targets(&self.filesystem, &self.config)?;

        // Pre-overlay: stop nix-daemon if /nix will be overlaid
        // Must happen BEFORE Phase 1 detection so nix-daemon doesn't appear
        // in the blocking process list with its mount namespace references.
        let nix_in_targets = overlay_targets.iter().any(|t| t == Path::new("/nix"));
        let mut nix_guard = NixDaemonGuard::new(nix_in_targets);
        if nix_in_targets {
            tracing::info!("Stopping nix-daemon before /nix overlay...");
            // Stop socket first (prevents socket-activation restart)
            let _ = std::process::Command::new("systemctl")
                .args(["stop", "nix-daemon.socket"])
                .output();
            let _ = std::process::Command::new("systemctl")
                .args(["stop", "nix-daemon.service"])
                .output();
        }

        // Track mount failures for best-effort mounting (Story 14.10, Task 8)
        let mut mount_failures: Vec<(PathBuf, NailsError)> = Vec::new();
        let mut nix_overlay_succeeded = false;

        for target in overlay_targets {
            // Create overlay config on-the-fly (Story 14.10, Task 6)
            let overlay = match create_overlay_config(
                &self.filesystem,
                &target,
                &self.config.hidden_volume_root,
            ) {
                Ok(config) => config,
                Err(e) => {
                    // Best-effort: log warning, track failure, continue with next overlay
                    tracing::warn!(
                        target = %target.display(),
                        error = %e,
                        "⚠ Could not create overlay config for {}: {}",
                        target.display(),
                        e
                    );
                    mount_failures.push((target.clone(), e));
                    continue;
                }
            };

            // Task 6: DNS preservation - clean stale network config before mounting /etc
            if target == Path::new("/etc")
                && let Err(e) = clean_stale_network_config(&overlay.upper, &self.filesystem)
            {
                tracing::warn!(
                    error = %e,
                    "Failed to clean stale network config from /etc upper layer: {}",
                    e
                );
                // Continue anyway - this is best-effort
            }

            // Use universal overlay mounting algorithm (Story 4.15, AC8)
            match crate::overlay::mount_overlay_with_strategy(
                &self.filesystem,
                &overlay.lower,
                &overlay.upper,
                &overlay.work,
                &overlay.target,
                strategy_options,
            ) {
                Ok(mount_result) => {
                    self.handle_mount_success(
                        tracker,
                        &overlay,
                        &mount_result,
                        verbosity,
                        direct_mounts,
                        pivot_mounts,
                        &mut nix_overlay_succeeded,
                    )?;
                }
                Err(e) => {
                    // Story 14.10, Task 8: Best-effort mounting
                    tracing::warn!(
                        error = %e,
                        target = %overlay.target.display(),
                        "⚠ Could not overlay {}: {}",
                        overlay.target.display(),
                        e
                    );
                    mount_failures.push((overlay.target.clone(), e));
                    continue;
                }
            }
        }

        // If ALL overlays failed, rollback and return error
        if tracker.mounted.is_empty() && !mount_failures.is_empty() {
            tracing::error!(
                failure_count = mount_failures.len(),
                "All overlay mounts failed - activation aborted"
            );

            if let Err(rollback_err) = tracker.rollback_all() {
                tracing::error!(
                    error = %rollback_err,
                    context = "mount_failure_recovery",
                    rollback = true,
                    "Rollback failed during mount failure recovery"
                );
            }

            // Return first failure as representative error
            return Err(mount_failures.into_iter().next().unwrap().1);
        }

        // Story 14.10, AC9: Record failed overlays in state for status reporting
        if !mount_failures.is_empty() {
            self.record_failed_overlays(&mount_failures, verbosity)?;
        }

        // Any failure should abort activation to avoid partially-active state.
        if !mount_failures.is_empty() {
            return Err(NailsError::InvalidState(format!(
                "{} overlay(s) failed to mount",
                mount_failures.len()
            )));
        }

        // Post-overlay: if /nix was successfully overlaid, restore NixOS security model
        if nix_overlay_succeeded {
            self.restore_nix_security_model(&mut nix_guard)?;
        }

        Ok(())
    }

    /// Mount overlays in Explicit mode (pre-configured overlays)
    fn mount_explicit_overlays(
        &self,
        tracker: &mut MountTracker<F>,
        strategy_options: &crate::overlay::OverlayStrategyOptions,
        verbosity: Verbosity,
        direct_mounts: &mut usize,
        pivot_mounts: &mut usize,
    ) -> Result<()> {
        // Explicit mode: use pre-configured overlays (legacy behavior)
        // Security check: fail if no overlays configured (would leave system unprotected)
        if self.config.overlays.is_empty() {
            return Err(NailsError::ConfigError(
                "Explicit mode configured but no overlays defined - system would have NO forensic protection. \
                 Add overlays to config or switch to overlay_mode: auto".to_string()
            ));
        }

        let critical = [Path::new("/bin"), Path::new("/usr")];
        for overlay in &self.config.overlays {
            if critical.contains(&overlay.target.as_path()) {
                return Err(NailsError::InvalidState(format!(
                    "Overlaying critical system root {} is blocked for safety",
                    overlay.target.display()
                )));
            }
        }

        for overlay in &self.config.overlays {
            // Task 6: DNS preservation - clean stale network config before mounting /etc
            if overlay.target == Path::new("/etc")
                && let Err(e) = clean_stale_network_config(&overlay.upper, &self.filesystem)
            {
                tracing::warn!(
                    error = %e,
                    "Failed to clean stale network config from /etc upper layer: {}",
                    e
                );
                // Continue anyway - this is best-effort
            }

            // Use universal overlay mounting algorithm (Story 4.15, AC8)
            match crate::overlay::mount_overlay_with_strategy(
                &self.filesystem,
                &overlay.lower,
                &overlay.upper,
                &overlay.work,
                &overlay.target,
                strategy_options,
            ) {
                Ok(mount_result) => {
                    let mut nix_overlay_succeeded = false;
                    self.handle_mount_success(
                        tracker,
                        overlay,
                        &mount_result,
                        verbosity,
                        direct_mounts,
                        pivot_mounts,
                        &mut nix_overlay_succeeded,
                    )?;
                }
                Err(e) => {
                    // Explicit mode: fail fast on mount errors (original behavior)
                    tracing::error!(
                        error = %e,
                        target = %overlay.target.display(),
                        rollback = true,
                        "Overlay mount failed"
                    );

                    if let Err(rollback_err) = tracker.rollback_all() {
                        tracing::error!(
                            error = %rollback_err,
                            context = "mount_failure_recovery",
                            rollback = true,
                            "Rollback failed during mount failure recovery"
                        );
                    }
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// Handle successful overlay mount with service restart and state tracking
    #[allow(clippy::too_many_arguments)]
    fn handle_mount_success(
        &self,
        tracker: &mut MountTracker<F>,
        overlay: &crate::OverlayConfig,
        mount_result: &crate::overlay::MountResult,
        verbosity: Verbosity,
        direct_mounts: &mut usize,
        pivot_mounts: &mut usize,
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
        let mut cached = self.cached_state.lock().unwrap();
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
                            mount_info.upper.clone(),   // tmpfs upper
                            mount_info.work.clone(),    // tmpfs work
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
    fn record_failed_overlays(
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

        let mut cached = self.cached_state.lock().unwrap();
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

    /// Restore NixOS security model after /nix overlay
    fn restore_nix_security_model(&self, nix_guard: &mut NixDaemonGuard) -> Result<()> {
        // Step 1: Recreate read-only bind mount on /nix/store
        // The overlay on /nix hides the boot-time bind mount; we recreate it
        // so regular processes see /nix/store as read-only (defense-in-depth)
        tracing::info!("Restoring read-only bind mount on /nix/store...");
        let nix_store = Path::new("/nix/store");
        if let Err(e) = self.filesystem.bind_mount(nix_store, nix_store) {
            tracing::warn!(
                error = %e,
                "Could not recreate /nix/store bind mount (non-fatal)"
            );
        } else {
            // Remount as read-only (uses Command since Filesystem trait lacks remount_readonly)
            let remount_result = std::process::Command::new("mount")
                .args(["-o", "remount,ro,bind", "/nix/store"])
                .output();
            match remount_result {
                Ok(output) if output.status.success() => {
                    tracing::info!("Read-only bind mount on /nix/store restored");
                }
                Ok(output) => {
                    tracing::warn!(
                        stderr = %String::from_utf8_lossy(&output.stderr),
                        "Remount /nix/store as read-only failed (non-fatal)"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "Remount /nix/store command failed (non-fatal)"
                    );
                }
            }
        }

        // Step 2: Restart nix-daemon (inherits overlay, creates own rw namespace)
        tracing::info!("Restarting nix-daemon (now writing to overlay)...");
        start_service_and_socket("nix-daemon");
        nix_guard.disarm();

        Ok(())
    }
}
