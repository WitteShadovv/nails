//! Overlay Mounting Logic
//!
//! Handles mounting persistent overlays with process detection and automatic
//! rollback on failure.
//!
//! Split into sub-modules:
//! - `auto_mount` - Auto mode overlay mounting (dynamic target enumeration)
//! - `explicit_mount` - Explicit mode overlay mounting (pre-configured overlays)

mod auto_mount;
mod explicit_mount;
mod persona;
mod restore;

#[allow(unused_imports)]
use super::{
    MountInfo, MountTracker, MountType, build_overlay_targets, clean_stale_network_config,
    create_overlay_config, start_service_and_socket,
};
use crate::platform::ConfigLayer;
use crate::{
    FailedOverlayInfo, Filesystem, NailsError, NailsManager, OverlayInfo, Result, Verbosity,
};
use chrono::Utc;
use std::path::{Path, PathBuf};

impl<F: Filesystem> NailsManager<F> {
    /// Mount persistent and ephemeral overlays.
    ///
    /// Returns `(direct_mounts, pivot_mounts, leaking_targets, mounts)` where
    /// `leaking_targets` are the targets still referenced by surviving writers
    /// after Phase 2 (the basis for the security label), independent of which
    /// mount method was used, and `mounts` is the full tracked list in mount
    /// order.
    ///
    /// The in-scope [`MountTracker`] rolls back automatically if a mount fails
    /// mid-phase. On success the mounts are *moved out* of the tracker (via
    /// [`take_mounts`](crate::MountTracker::take_mounts)) and handed to the
    /// caller, which arms an activation-scope guard over them: the tracker no
    /// longer commits here, because activation can still fail after this returns
    /// and those overlays must come down before the state is rolled back.
    pub(super) fn mount_overlays(
        &self,
        options: &crate::ActivateOptions,
        verbosity: Verbosity,
    ) -> Result<(usize, usize, Vec<PathBuf>, Vec<MountInfo>)> {
        if verbosity >= Verbosity::Normal {
            tracing::info!("Mounting overlays...");
        }

        // The tracker is the mid-mount safety net: if any mount below fails it
        // rolls back on drop. Its mounts are taken out on success instead of
        // committed, so a later activation failure can still unmount them.
        let mut tracker = MountTracker::new(&self.filesystem);

        // Build OverlayStrategyOptions from ActivateOptions. The risky-service
        // choice is resolved up front so a non-interactive run that keeps the
        // session fails fast (before anything is mounted) when no choice was made.
        let strategy_options = crate::overlay::OverlayStrategyOptions {
            auto_restart_safe: true, // Always restart safe processes automatically
            risky_services: options.resolve_risky_services()?,
            terminate_interactive: options.terminate_interactive,
            allow_pivot: !options.no_pivot, // Respect --no-pivot flag
            auto_accept_pivot: options.accept_pivot_risks, // Auto-accept if --accept-pivot-risks
            skip_process_detection: options
                .skip_process_detection_override
                .unwrap_or(cfg!(test)), // Allow tests to override
        };

        // Track mount methods for logging
        let mut direct_mounts = 0;
        let mut pivot_mounts = 0;
        let mut leaking_targets: Vec<PathBuf> = Vec::new();

        // Step 8a: Mount persistent overlays using universal algorithm
        // Use dynamic target list based on overlay_mode
        match self.config.overlay_mode {
            crate::OverlayMode::Auto => {
                self.mount_auto_overlays(
                    &mut tracker,
                    &strategy_options,
                    verbosity,
                    &mut direct_mounts,
                    &mut pivot_mounts,
                    &mut leaking_targets,
                )?;
            }
            crate::OverlayMode::Explicit => {
                self.mount_explicit_overlays(
                    &mut tracker,
                    &strategy_options,
                    verbosity,
                    &mut direct_mounts,
                    &mut pivot_mounts,
                    &mut leaking_targets,
                )?;
            }
        }

        // Fresh-home persona: bind the clean hidden home over the operator's home
        // now that the /home overlay (if any) is in place. Pushed onto the tracker
        // after the overlays, so a later failure rolls it back first; a no-op in
        // shared-home mode.
        self.mount_persona_home(&mut tracker, verbosity)?;

        // Log overlays mounted with structured fields
        let mounted_paths: Vec<_> = tracker
            .mounted
            .iter()
            .map(|info| info.target.clone())
            .collect();
        tracing::info!(overlays = ?mounted_paths, "Overlays mounted");

        // Move the mounts out of the tracker (emptying it, so its drop is inert)
        // and hand them to the caller, which owns rollback from here on.
        let mounts = tracker.take_mounts();

        Ok((direct_mounts, pivot_mounts, leaking_targets, mounts))
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
        leaking_targets: &mut Vec<PathBuf>,
        nix_overlay_succeeded: &mut bool,
    ) -> Result<()> {
        use crate::overlay::MountMethod;

        // Track the mount method for logging only. The method does not by itself
        // determine the security posture — pre-existing processes keep referencing
        // the decoy under both a direct and a pivot mount.
        match mount_result.method {
            MountMethod::Direct => {
                *direct_mounts += 1;
                if verbosity >= Verbosity::Verbose {
                    tracing::info!("  ✓ {} mounted (direct)", overlay.target.display());
                }
            }
            MountMethod::Pivot => {
                *pivot_mounts += 1;
                if verbosity >= Verbosity::Verbose {
                    tracing::info!("  ✓ {} mounted (pivot fallback)", overlay.target.display());
                }
            }
            MountMethod::SnapshotPivot => {
                *pivot_mounts += 1;
                if verbosity >= Verbosity::Verbose {
                    tracing::info!("  ✓ {} mounted (snapshot pivot)", overlay.target.display());
                }
            }
        }

        // The security-relevant signal: a target still referenced by surviving
        // writers leaks hidden-session activity into the decoy lower tree, and it
        // does so under either mount method.
        if !mount_result.survivors.is_empty() {
            leaking_targets.push(overlay.target.clone());
            if verbosity >= Verbosity::Verbose {
                tracing::warn!(
                    writers = mount_result.surviving_writers(),
                    "  ⚠️  {} has {} surviving writer(s) leaking to the decoy",
                    overlay.target.display(),
                    mount_result.surviving_writers()
                );
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

        // After /etc overlay is mounted, inject the NAILS import block into the
        // overlayed hardware-configuration.nix. Writes land in the upper layer —
        // the base underlay is untouched. The injection is a declarative-config
        // step, so it runs through the platform config layer and is skipped on a
        // host without one (FHS / Debian), where there is no hidden NixOS config.
        if overlay.target == Path::new("/etc")
            && let Some(layer) = self.config_layer()
            && let Err(e) = layer.inject_import(&self.filesystem)
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

        // Update overlay_status incrementally after EACH mount
        let overlay_info = OverlayInfo {
            mount_path: overlay.target.clone(),
            lower_dir: overlay.lower.clone(),
            upper_dir: overlay.upper.clone(),
            work_dir: overlay.work.clone(),
            mounted_at: Utc::now(),
            mount_method: mount_result.method,
        };

        // Update cached state with this mount
        let mut cached = self.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file
                .overlay_status
                .insert(overlay.target.clone(), overlay_info);

            drop(cached); // Release lock before saving
            // A per-mount state save that fails is a hard error: continuing would
            // leave an overlay mounted but unrecorded on disk, so the tracker
            // could not roll it back and status would under-report the hidden
            // mounts. Aborting here lets the in-scope tracker unmount what is
            // already mounted before activation proceeds.
            self.save_cached_state().inspect_err(|e| {
                tracing::error!(
                    error = %e,
                    target = %overlay.target.display(),
                    "Failed to persist overlay state after mount; aborting activation"
                );
            })?;
        }

        Ok(())
    }

    /// Record failed overlay mounts in state for status reporting
    pub(super) fn record_failed_overlays(
        &self,
        mount_failures: &[(PathBuf, NailsError)],
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

        let mut cached = self.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file.failed_overlays = failed_infos;
            drop(cached);
            // Persisting the failure record is a hard error for the same reason
            // as a per-mount save: if it cannot be written the on-disk state no
            // longer matches reality.
            self.save_cached_state().inspect_err(|e| {
                tracing::error!(error = %e, "Failed to persist failed overlays to state");
            })?;
        }

        Ok(())
    }
}
