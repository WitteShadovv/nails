//! Explicit mode overlay mounting (pre-configured overlays)

use super::{MountTracker, clean_stale_network_config};
use crate::{Filesystem, NailsError, NailsManager, Result, Verbosity};
use std::path::{Path, PathBuf};

impl<F: Filesystem> NailsManager<F> {
    /// Mount overlays in Explicit mode (pre-configured overlays)
    pub(in crate::manager::activation) fn mount_explicit_overlays(
        &self,
        tracker: &mut MountTracker<F>,
        strategy_options: &crate::overlay::OverlayStrategyOptions,
        verbosity: Verbosity,
        direct_mounts: &mut usize,
        pivot_mounts: &mut usize,
        pivot_targets: &mut Vec<PathBuf>,
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
            // overlayfs cannot follow bind mounts in the lower layer.
            let extra_lowers = match self.filesystem.find_submount_sources(&overlay.target) {
                Ok(sources) if !sources.is_empty() => {
                    let extra = crate::overlay::bind_sync::compute_extra_lower_dirs(
                        &overlay.target,
                        &sources,
                    );
                    if !extra.is_empty() {
                        tracing::info!(
                            target = %overlay.target.display(),
                            count = extra.len(),
                            extra = ?extra,
                            "Adding {} extra lower layer(s) for bind mount visibility on {}",
                            extra.len(),
                            overlay.target.display()
                        );
                    }
                    extra
                }
                Ok(_) => Vec::new(),
                Err(e) => {
                    tracing::warn!(
                        target = %overlay.target.display(),
                        error = %e,
                        "Failed to detect submount sources for {}: {}",
                        overlay.target.display(),
                        e
                    );
                    Vec::new()
                }
            };

            // Build lower layer refs: primary lower first, then extras
            let mut lower_refs: Vec<&std::path::Path> = vec![&overlay.lower];
            for extra in &extra_lowers {
                lower_refs.push(extra.as_path());
            }

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
                &lower_refs,
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
                        pivot_targets,
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
}
