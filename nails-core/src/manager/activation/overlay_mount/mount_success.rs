// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What runs after a persistent overlay mounts: journald re-homing, the
//! read-only guard, and recording the mounted set (or the failed ones).

use super::journald_fd::journald_fds_resolve_into_overlay;
use super::*;

impl<F: Filesystem> NailsManager<F> {
    /// Handle successful overlay mount with service restart and state tracking
    pub(super) fn handle_mount_success(
        &self,
        tracker: &mut MountTracker<F>,
        overlay: &crate::OverlayConfig,
        mount_result: &crate::overlay::MountResult,
        verbosity: Verbosity,
        outcome: &mut OverlayMountOutcome,
        nix_overlay_succeeded: &mut bool,
    ) -> Result<()> {
        use crate::overlay::MountMethod;

        // Track the mount method for logging only. The method does not by itself
        // determine the security posture — pre-existing processes keep referencing
        // the decoy under both a direct and a pivot mount.
        match mount_result.method {
            MountMethod::Direct => {
                outcome.direct_mounts += 1;
                if verbosity >= Verbosity::Verbose {
                    tracing::info!("  ✓ {} mounted (direct)", overlay.target.display());
                }
            }
            MountMethod::Pivot => {
                outcome.pivot_mounts += 1;
                if verbosity >= Verbosity::Verbose {
                    tracing::info!("  ✓ {} mounted (pivot fallback)", overlay.target.display());
                }
            }
            MountMethod::SnapshotPivot => {
                outcome.pivot_mounts += 1;
                if verbosity >= Verbosity::Verbose {
                    tracing::info!("  ✓ {} mounted (snapshot pivot)", overlay.target.display());
                }
            }
        }

        // The security-relevant signal: a target still referenced by surviving
        // writers leaks hidden-session activity into the decoy lower tree, and it
        // does so under either mount method. Keep who they are, not just that
        // the target leaks, so the outcome, notification and status can name them.
        if !mount_result.survivors.is_empty() {
            let names = mount_result
                .survivors
                .iter()
                .map(|w| format!("{} (PID {})", w.name, w.pid))
                .collect::<Vec<_>>()
                .join(", ");
            tracing::warn!(
                target_path = %overlay.target.display(),
                writers = mount_result.surviving_writers(),
                "  ⚠️  {} still has {} writer(s) on the decoy: {}",
                overlay.target.display(),
                mount_result.surviving_writers(),
                names
            );
            super::super::record_surviving_writers(
                &mut outcome.decoy_writers,
                &overlay.target,
                &mount_result.survivors,
            );
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

            // journald on /var is re-homed by the dedicated block below, which
            // forces a real restart and verifies its fds land in the overlay. A
            // plain start here would leave it holding the pre-overlay journal fds.
            if overlay.target == Path::new("/var") && service == "systemd-journald" {
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

        tracker.push_mount(MountInfo::persistent(overlay.target.clone()));

        // After /var overlay is mounted, re-home journald onto the overlay: a real
        // restart (not a no-op start on the still-running unit) so it drops the
        // pre-overlay /var/log/journal fds and reopens under the overlay, a flush
        // so any volatile records move into the overlay, and a check that its
        // journal fds actually resolve into the overlay upper. If they do not,
        // journald is still writing to the decoy journal, so the whole activation
        // is rolled back rather than leaking the hidden session. The mount is
        // already tracked above, so the rollback unmounts the /var overlay too.
        if overlay.target == Path::new("/var")
            && let Err(e) = self.rehome_journald_onto_overlay(&overlay.upper)
        {
            tracing::error!(
                error = %e,
                rollback = true,
                "journald did not re-home onto the /var overlay; rolling back activation"
            );
            if let Err(rollback_err) = tracker.rollback_all() {
                tracing::error!(
                    error = %rollback_err,
                    context = "journald_rehome_failure",
                    rollback = true,
                    "Rollback failed after journald re-home failure"
                );
            }
            // journald was restarted above but its fds are off the overlay (or the
            // overlay is now gone); bring it back onto the base /var.
            crate::manager::helpers::start_service_and_socket("systemd-journald");
            return Err(e);
        }

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

    /// Re-home systemd-journald onto the freshly mounted `/var` overlay.
    ///
    /// Restarts journald (forcing it to drop the pre-overlay `/var/log/journal`
    /// file descriptors and reopen under the overlay), flushes any volatile
    /// records into the now-overlaid persistent journal, then verifies journald's
    /// journal fds resolve into the overlay upper. A positive mismatch — journald
    /// still holding fds on the decoy's base `/var` — is an error so the caller
    /// rolls the activation back; an indeterminate result (journald absent, or its
    /// fds not inspectable) is logged and tolerated rather than aborting a
    /// legitimate activation.
    fn rehome_journald_onto_overlay(&self, upper_dir: &Path) -> Result<()> {
        crate::manager::helpers::restart_service_and_socket("systemd-journald");
        tracing::info!(
            "Restarted systemd-journald after /var overlay mount (prevents log leakage)"
        );

        if let Err(err) = crate::manager::helpers::ServiceController::flush_journal() {
            // A failed flush leaves at most volatile records in /run (tmpfs), which
            // never reach the decoy disk, so it is logged rather than fatal.
            tracing::warn!(error = %err, "journalctl --flush after /var overlay failed");
        }

        let (check, diagnostic) = journald_fds_resolve_into_overlay(upper_dir);
        match check {
            JournaldFdCheck::InOverlay => {
                tracing::debug!("journald journal fds resolve into the /var overlay upper");
                Ok(())
            }
            JournaldFdCheck::Indeterminate => {
                tracing::warn!(
                    "could not confirm journald journal fds are on the /var overlay; continuing"
                );
                Ok(())
            }
            // The diagnostic names each offending fd with its mount id (and device)
            // and the overlay's, so a future failure in the VM log is self-
            // explanatory rather than a bare refusal.
            JournaldFdCheck::NotInOverlay => {
                let detail =
                    diagnostic.unwrap_or_else(|| format!("overlay upper {}", upper_dir.display()));
                Err(NailsError::InvalidState(format!(
                    "systemd-journald is still writing to the base /var after the overlay mount; \
                     refusing to leak the hidden session to the decoy journal ({detail})"
                )))
            }
        }
    }
}
