//! Auto mode overlay mounting (dynamic target enumeration)

use super::{
    MountTracker, build_overlay_targets, clean_stale_network_config, create_overlay_config,
};
use crate::manager::activation::guards::NixDaemonGuard;
use crate::{Filesystem, NailsError, NailsManager, Result, Verbosity};
use std::path::{Path, PathBuf};

impl<F: Filesystem> NailsManager<F> {
    /// Mount overlays in Auto mode (dynamic target enumeration)
    pub(in crate::manager::activation) fn mount_auto_overlays(
        &self,
        tracker: &mut MountTracker<F>,
        strategy_options: &crate::overlay::OverlayStrategyOptions,
        verbosity: Verbosity,
        direct_mounts: &mut usize,
        pivot_mounts: &mut usize,
        leaking_targets: &mut Vec<PathBuf>,
    ) -> Result<()> {
        // Auto mode: enumerate root + apply exclusions, create overlays dynamically
        let overlay_targets = build_overlay_targets(&self.filesystem, &self.config)?;
        // Checked again on the exact list about to be mounted: a top-level
        // directory created since the pre-flight checks is a new target.
        crate::preflight::ensure_targets_clear(&self.filesystem, &self.config, &overlay_targets)?;

        // Pre-overlay: stop nix-daemon if /nix will be overlaid
        // Must happen BEFORE Phase 1 detection so nix-daemon doesn't appear
        // in the blocking process list with its mount namespace references.
        let nix_in_targets = overlay_targets.iter().any(|t| t == Path::new("/nix"));
        let mut nix_guard = NixDaemonGuard::new(nix_in_targets);
        if nix_in_targets && !crate::runtime_safety::should_skip_host_interaction() {
            crate::manager::helpers::cache_nix_overlay_runtime_commands().map_err(|err| {
                NailsError::NixOSError(format!(
                    "Failed to cache /nix overlay runtime commands before /nix overlay: {}",
                    err
                ))
            })?;
        }
        if nix_in_targets {
            tracing::info!("Stopping nix-daemon before /nix overlay...");
            let _ = crate::manager::helpers::ServiceController::stop_nix_daemon();
        }

        let mut var_was_overlaid = false;
        let outcome = self.mount_auto_overlays_body(
            tracker,
            &overlay_targets,
            strategy_options,
            verbosity,
            direct_mounts,
            pivot_mounts,
            leaking_targets,
            &mut nix_guard,
            &mut var_was_overlaid,
        );

        if let Err(error) = outcome {
            // Roll back every overlay that was mounted BEFORE restarting any
            // service, so nix-daemon and journald never come back up writing to
            // an overlay that is about to be torn down. nix-daemon is restarted
            // by `nix_guard` on drop, which happens after this rollback returns.
            if let Err(rollback_err) = tracker.rollback_all() {
                tracing::error!(
                    error = %rollback_err,
                    context = "activation_abort",
                    rollback = true,
                    "Rollback failed during activation abort"
                );
            }
            if var_was_overlaid {
                crate::manager::helpers::start_service_and_socket("systemd-journald");
                tracing::info!(
                    "Restarted systemd-journald after activation rollback (now writing to base /var)"
                );
            }
            return Err(error);
        }

        Ok(())
    }

    /// Body of auto-mode mounting: enumerate, mount, and restore the NixOS
    /// security model. Any error is propagated to [`mount_auto_overlays`], which
    /// performs the rollback and service restarts in the correct order.
    #[allow(clippy::too_many_arguments)]
    fn mount_auto_overlays_body(
        &self,
        tracker: &mut MountTracker<F>,
        overlay_targets: &[PathBuf],
        strategy_options: &crate::overlay::OverlayStrategyOptions,
        verbosity: Verbosity,
        direct_mounts: &mut usize,
        pivot_mounts: &mut usize,
        leaking_targets: &mut Vec<PathBuf>,
        nix_guard: &mut NixDaemonGuard,
        var_was_overlaid: &mut bool,
    ) -> Result<()> {
        // Track mount failures for best-effort mounting (Story 14.10, Task 8)
        let mut mount_failures: Vec<(PathBuf, NailsError)> = Vec::new();
        let mut nix_overlay_succeeded = false;

        for target in overlay_targets {
            let target = target.clone();
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

            // Clear stale opaque markers on NAILS-managed dirs (currently
            // /etc/nixos) so a previous cycle cannot hide lower-layer contents
            // (e.g. flake.nix under /etc/nixos). Scoped: user uppers and /nix are
            // never touched, so intended whiteouts survive.
            let stripped =
                crate::overlay::opaque::strip_managed_opaque(&overlay.upper, &overlay.target);
            if stripped > 0 {
                tracing::warn!(
                    upper = %overlay.upper.display(),
                    count = stripped,
                    "Stripped {} opaque overlay dir(s) from upper layer {}",
                    stripped,
                    overlay.upper.display()
                );
            }

            // Compute extra lower layers from bind-mounted content.
            // overlayfs cannot follow bind mounts in the lower layer — content
            // at bind mount points (e.g., /etc/nixos from /persist/etc/nixos)
            // would be invisible without adding the backing store as an extra lower.
            let extra_lowers = match self.filesystem.find_submount_sources(&target) {
                Ok(sources) if !sources.is_empty() => {
                    let extra =
                        crate::overlay::bind_sync::compute_extra_lower_dirs(&target, &sources);
                    if !extra.is_empty() {
                        tracing::info!(
                            target = %target.display(),
                            count = extra.len(),
                            extra = ?extra,
                            "Adding {} extra lower layer(s) for bind mount visibility on {}",
                            extra.len(),
                            target.display()
                        );
                    }
                    extra
                }
                Ok(_) => Vec::new(),
                Err(e) => {
                    tracing::warn!(
                        target = %target.display(),
                        error = %e,
                        "Failed to detect submount sources for {}: {}",
                        target.display(),
                        e
                    );
                    // Continue anyway — best effort
                    Vec::new()
                }
            };

            // Build lower layer refs: primary lower first, then extras
            let mut lower_refs: Vec<&std::path::Path> = vec![&overlay.lower];
            for extra in &extra_lowers {
                lower_refs.push(extra.as_path());
            }

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
                &lower_refs,
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
                        leaking_targets,
                        &mut nix_overlay_succeeded,
                    )?;
                    if target == Path::new("/var") {
                        // journald was moved onto the /var overlay; remember so a
                        // later abort can restart it against the base /var.
                        *var_was_overlaid = true;
                    }
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

        // If ALL overlays failed, abort. The caller rolls back (nothing is
        // mounted) and restarts services.
        if tracker.mounted.is_empty() && !mount_failures.is_empty() {
            tracing::error!(
                failure_count = mount_failures.len(),
                "All overlay mounts failed - activation aborted"
            );

            // Return first failure as representative error
            return Err(mount_failures.into_iter().next().unwrap().1);
        }

        // Story 14.10, AC9: Record failed overlays in state for status reporting
        if !mount_failures.is_empty() {
            self.record_failed_overlays(&mount_failures, verbosity)?;
        }

        // Any failure should abort activation to avoid partially-active state.
        // The caller rolls back the overlays already mounted and restarts
        // journald/nix-daemon after the unmounts.
        if !mount_failures.is_empty() {
            return Err(NailsError::InvalidState(format!(
                "{} overlay(s) failed to mount",
                mount_failures.len()
            )));
        }

        // Post-overlay: if /nix was successfully overlaid, restore NixOS security model
        if nix_overlay_succeeded {
            self.restore_nix_security_model(nix_guard)?;
        }

        Ok(())
    }
}
