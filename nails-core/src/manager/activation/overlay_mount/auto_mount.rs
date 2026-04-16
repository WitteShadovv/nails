//! Auto mode overlay mounting (dynamic target enumeration)

use super::{
    MountTracker, NixDaemonGuard, build_overlay_targets, clean_stale_network_config,
    create_overlay_config,
};
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
        pivot_targets: &mut Vec<PathBuf>,
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
            if crate::runtime_safety::should_skip_host_interaction() {
                tracing::debug!(
                    "Skipping nix-daemon stop commands in test/test-like context to avoid host interaction"
                );
            } else {
                // Stop socket first (prevents socket-activation restart)
                let _ = std::process::Command::new("systemctl")
                    .args(["stop", "nix-daemon.socket"])
                    .output();
                let _ = std::process::Command::new("systemctl")
                    .args(["stop", "nix-daemon.service"])
                    .output();
            }
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

            // Strip opaque xattrs from upper layer to prevent previous activation
            // cycles from hiding lower-layer contents (e.g., flake.nix under /etc/nixos)
            let stripped = crate::overlay::opaque::strip_opaque_xattrs(&overlay.upper);
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
                        pivot_targets,
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
}
