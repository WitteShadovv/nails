// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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
mod submount_attach;

#[allow(unused_imports)]
use super::{
    MountInfo, MountTracker, MountType, build_overlay_targets, clean_stale_network_config,
    create_overlay_config, start_service_and_socket,
};
use crate::manager::activation::guards::NixDaemonGuard;
use crate::platform::{ConfigLayer, NixRuntime};
use crate::{
    DecoyWriter, FailedOverlayInfo, Filesystem, NailsError, NailsManager, OverlayConfig,
    OverlayInfo, Result, Verbosity,
};
use chrono::Utc;
use std::path::{Path, PathBuf};

/// How a mount failure inside the shared overlay loop is handled.
///
/// This is the one behavioural difference between the former auto and explicit
/// loops: auto is best-effort, explicit fails fast. Both share the same body and
/// the same `/nix` gating; only this choice differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MountFailureMode {
    /// Auto mode: record each failed overlay and continue; abort after the loop if
    /// any overlay (or its config) failed, so activation never half-completes.
    BestEffort,
    /// Explicit mode: abort on the first overlay that fails to mount.
    FailFast,
}

/// What [`NailsManager::mount_overlays`] hands back to the activation flow.
#[derive(Debug, Default)]
pub(in crate::manager::activation) struct OverlayMountOutcome {
    /// Overlays mounted directly over their target.
    pub(in crate::manager::activation) direct_mounts: usize,
    /// Overlays mounted through the pivot fallback.
    pub(in crate::manager::activation) pivot_mounts: usize,
    /// Writers still referencing the decoy after Phase 2, one entry per process
    /// with every target it leaks to. This is the basis for the security label
    /// and is independent of which mount method was used.
    pub(in crate::manager::activation) decoy_writers: Vec<DecoyWriter>,
    /// Every tracked mount, in mount order.
    pub(in crate::manager::activation) mounts: Vec<MountInfo>,
}

/// The per-overlay progress line shown at Normal verbosity, e.g.
/// `mounting /home (3/12)`.
///
/// Mounting the overlays is the longest observable activation phase after the
/// build, so the operator sees one line per target as it goes up rather than a
/// single `Mounting overlays...` followed by silence. `index` is 1-based.
fn overlay_progress_message(target: &Path, index: usize, total: usize) -> String {
    format!("mounting {} ({index}/{total})", target.display())
}

impl<F: Filesystem> NailsManager<F> {
    /// Mount persistent and ephemeral overlays.
    ///
    /// Returns the mount counts, the writers left on the decoy and the full
    /// tracked mount list (see [`OverlayMountOutcome`]).
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
    ) -> Result<OverlayMountOutcome> {
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

        let mut outcome = OverlayMountOutcome::default();

        // Step 8a: Mount persistent overlays using universal algorithm
        // Use dynamic target list based on overlay_mode
        match self.config.overlay_mode {
            crate::OverlayMode::Auto => {
                self.mount_auto_overlays(&mut tracker, &strategy_options, verbosity, &mut outcome)?;
            }
            crate::OverlayMode::Explicit => {
                self.mount_explicit_overlays(
                    &mut tracker,
                    &strategy_options,
                    verbosity,
                    &mut outcome,
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
        outcome.mounts = tracker.take_mounts();

        Ok(outcome)
    }

    /// Mount a resolved list of overlays, gating the `/nix` runtime on the host.
    ///
    /// This is the single overlay loop both modes share. Auto and explicit differ
    /// only in how they select their targets (dynamic enumeration vs. the
    /// configured list) and in their [`MountFailureMode`]; everything else — the
    /// per-overlay opaque strip, extra-lower computation, DNS cleanup, the mount
    /// itself and the post-mount bookkeeping — runs here once.
    ///
    /// The `/nix` lifecycle is resolved from the platform, not the target name: a
    /// NixOS host runs the full stop → cache → mount → store-bind +
    /// current-system restore → restart sequence, a non-NixOS host with `/nix`
    /// overlaid only stops and restarts nix-daemon, and a run without `/nix` as a
    /// target does neither.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn mount_overlay_targets(
        &self,
        tracker: &mut MountTracker<F>,
        overlays: &[OverlayConfig],
        initial_failures: Vec<(PathBuf, NailsError)>,
        failure_mode: MountFailureMode,
        strategy_options: &crate::overlay::OverlayStrategyOptions,
        verbosity: Verbosity,
        outcome: &mut OverlayMountOutcome,
    ) -> Result<()> {
        // Resolve the /nix lifecycle from the platform before Phase-1 detection.
        let nix_in_targets = overlays.iter().any(|o| o.target == Path::new("/nix"));
        let platform = crate::platform::detect_platform(&self.filesystem)?;
        let nix_runtime = platform.nix_runtime(nix_in_targets);
        let command_dirs = platform.host_command_dirs();

        // Armed for Native and Foreign; a no-op guard for None. On an early exit
        // the guard restarts nix-daemon the way it was stopped.
        let mut nix_guard = NixDaemonGuard::new(nix_runtime, command_dirs);

        // Pre-overlay: stop nix-daemon so it does not appear as a blocking writer
        // during detection and does not keep the pre-overlay store busy. Native
        // additionally caches the runtime commands against the pre-overlay store so
        // they keep working once /nix is overlaid; Foreign does not.
        match nix_runtime {
            NixRuntime::Native => {
                if !crate::runtime_safety::should_skip_host_interaction() {
                    crate::manager::helpers::cache_nix_overlay_runtime_commands().map_err(
                        |err| {
                            NailsError::NixOSError(format!(
                                "Failed to cache /nix overlay runtime commands before /nix overlay: {err}"
                            ))
                        },
                    )?;
                }
                tracing::info!("Stopping nix-daemon before /nix overlay (NixOS)...");
                let _ = crate::manager::helpers::ServiceController::stop_nix_daemon();
            }
            NixRuntime::Foreign => {
                tracing::info!(
                    "Stopping nix-daemon before /nix overlay (Nix on a non-NixOS host)..."
                );
                if let Err(err) = crate::platform::nix_foreign::stop_nix_daemon(command_dirs) {
                    tracing::warn!(error = %err, "Failed to stop nix-daemon before /nix overlay");
                }
            }
            NixRuntime::None => {}
        }

        let mut var_was_overlaid = false;
        let body_result = self.mount_overlay_targets_body(
            tracker,
            overlays,
            initial_failures,
            failure_mode,
            strategy_options,
            verbosity,
            outcome,
            &mut nix_guard,
            nix_runtime,
            command_dirs,
            &mut var_was_overlaid,
        );

        if let Err(error) = body_result {
            // Roll back every mounted overlay BEFORE restarting any service, so
            // nix-daemon and journald never come back up writing to an overlay that
            // is about to be torn down. nix-daemon is restarted by `nix_guard` on
            // drop, after this rollback returns.
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

    /// The per-overlay loop body, shared by both modes.
    ///
    /// Any error is propagated to [`mount_overlay_targets`], which performs the
    /// rollback and service restarts in the correct order.
    #[allow(clippy::too_many_arguments)]
    fn mount_overlay_targets_body(
        &self,
        tracker: &mut MountTracker<F>,
        overlays: &[OverlayConfig],
        mut mount_failures: Vec<(PathBuf, NailsError)>,
        failure_mode: MountFailureMode,
        strategy_options: &crate::overlay::OverlayStrategyOptions,
        verbosity: Verbosity,
        outcome: &mut OverlayMountOutcome,
        nix_guard: &mut NixDaemonGuard,
        nix_runtime: NixRuntime,
        command_dirs: &'static [&'static str],
        var_was_overlaid: &mut bool,
    ) -> Result<()> {
        let mut nix_overlay_succeeded = false;
        // Walk /proc once for the whole mount phase. Every target classifies its
        // blocking processes against this single snapshot instead of re-scanning
        // /proc per target; the pivot fallback re-scans deliberately, to reflect
        // the state left by the Phase-2 service stops and restarts.
        let proc_snapshot = crate::process::detection::ProcSnapshot::capture()?;
        // Mounts created to keep host submounts visible under overlaid targets,
        // accumulated across the loop and persisted once the overlays are all in
        // place. Rollback of a mid-loop failure is driven by the tracker, which
        // each stage/re-attach also pushes onto.
        let mut submount_attachments: Vec<crate::state::SubmountAttachment> = Vec::new();

        let overlay_total = overlays.len();
        for (overlay_index, overlay) in overlays.iter().enumerate() {
            if verbosity >= Verbosity::Normal {
                tracing::info!(
                    event = "progress",
                    phase = "overlay_mount",
                    current = overlay_index + 1,
                    total = overlay_total,
                    "{}",
                    overlay_progress_message(&overlay.target, overlay_index + 1, overlay_total)
                );
            }

            // Clear stale opaque markers on NAILS-managed dirs (currently
            // /etc/nixos) so a previous cycle cannot hide lower-layer contents.
            // Scoped: user uppers and /nix are never touched, so intended whiteouts
            // survive.
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

            // Compute extra lower layers from bind-mounted content: overlayfs cannot
            // follow bind mounts in the lower layer, so the backing store of a bind
            // mount (e.g. /etc/nixos from /persist/etc/nixos) is added as an extra
            // lower to keep its content visible.
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
                    // Continue anyway — best effort.
                    Vec::new()
                }
            };

            // Build lower layer refs: primary lower first, then extras.
            let mut lower_refs: Vec<&std::path::Path> = vec![&overlay.lower];
            for extra in &extra_lowers {
                lower_refs.push(extra.as_path());
            }

            // DNS preservation: clean stale network config before mounting /etc.
            if overlay.target == Path::new("/etc")
                && let Err(e) = clean_stale_network_config(&overlay.upper, &self.filesystem)
            {
                tracing::warn!(
                    error = %e,
                    "Failed to clean stale network config from /etc upper layer: {}",
                    e
                );
                // Continue anyway — this is best-effort.
            }

            // Capture any host submount nested under this target *before* the
            // overlay hides it; the captures are re-attached once the overlay is
            // mounted. A no-op when nothing is nested under the target.
            let staged_submounts =
                self.stage_submounts(&overlay.target, tracker, &mut submount_attachments);

            // Hand the persistent journal back to volatile storage before /var is
            // overlaid, so journald is not still writing to the base
            // /var/log/journal when the overlay goes on. Covers the paths where
            // journald is not stopped as an overlay writer (e.g. a pivot mount);
            // when it was stopped, this is simply a no-op. Best-effort.
            if overlay.target == Path::new("/var")
                && let Err(e) = crate::manager::helpers::ServiceController::relinquish_journal_var()
            {
                tracing::warn!(error = %e, "journalctl --relinquish-var before /var overlay failed");
            }

            match crate::overlay::mount_overlay_with_strategy(
                &self.filesystem,
                &lower_refs,
                &overlay.upper,
                &overlay.work,
                &overlay.target,
                strategy_options,
                &proc_snapshot,
            ) {
                Ok(mount_result) => {
                    self.handle_mount_success(
                        tracker,
                        overlay,
                        &mount_result,
                        verbosity,
                        outcome,
                        &mut nix_overlay_succeeded,
                    )?;
                    if overlay.target == Path::new("/var") {
                        // journald was moved onto the /var overlay; remember so a
                        // later abort can restart it against the base /var.
                        *var_was_overlaid = true;
                    }
                    // Re-attach the staged submounts over the now-mounted overlay
                    // (read-only binds for squashfs/ESP/tmpfs, nested overlays for
                    // writable decoy-backed partitions).
                    self.reattach_staged_submounts(
                        &staged_submounts,
                        tracker,
                        &mut submount_attachments,
                    );
                }
                Err(e) => match failure_mode {
                    MountFailureMode::BestEffort => {
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
                    MountFailureMode::FailFast => {
                        tracing::error!(
                            error = %e,
                            target = %overlay.target.display(),
                            rollback = true,
                            "Overlay mount failed"
                        );
                        return Err(e);
                    }
                },
            }
        }

        // Best-effort post-processing (only reachable in BestEffort mode, where
        // `mount_failures` may carry config-build and mount failures).
        if !mount_failures.is_empty() {
            // If nothing mounted at all, abort with the first failure as the
            // representative error; the caller rolls back (nothing to undo) and
            // restarts services.
            if tracker.mounted.is_empty() {
                tracing::error!(
                    failure_count = mount_failures.len(),
                    "All overlay mounts failed - activation aborted"
                );
                return Err(mount_failures.into_iter().next().unwrap().1);
            }

            // Record the failures for status reporting, then abort to avoid a
            // partially-active state.
            self.record_failed_overlays(&mount_failures)?;
            return Err(NailsError::InvalidState(format!(
                "{} overlay(s) failed to mount",
                mount_failures.len()
            )));
        }

        // Persist the submount attachments now that every overlay is mounted, so
        // deactivation and emergency teardown undo exactly these mounts in reverse.
        self.record_submount_attachments(&submount_attachments)?;

        // Post-overlay: restore the /nix runtime when /nix was overlaid.
        if nix_overlay_succeeded {
            match nix_runtime {
                NixRuntime::Native => self.restore_nix_security_model(nix_guard)?,
                NixRuntime::Foreign => {
                    crate::platform::nix_foreign::restart_nix_daemon(command_dirs).map_err(
                        |e| {
                            NailsError::NixOSError(format!(
                                "Failed to restart nix-daemon after /nix overlay: {e}"
                            ))
                        },
                    )?;
                    nix_guard.disarm();
                }
                NixRuntime::None => {}
            }
        }

        Ok(())
    }

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
            super::record_surviving_writers(
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

        match journald_fds_resolve_into_overlay(upper_dir) {
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
            JournaldFdCheck::NotInOverlay => Err(NailsError::InvalidState(
                "systemd-journald is still writing to the base /var after the overlay mount; \
                 refusing to leak the hidden session to the decoy journal"
                    .into(),
            )),
        }
    }

    /// Keep the decoy's base-OS trees read-only for the duration of the session.
    ///
    /// Resolves the active platform's read-only policy against the live filesystem
    /// (the whole decoy root and `/usr`, plus any non-usr-merged core binary roots
    /// on an FHS host) and bind-remounts each read-only, failing closed: a tree it
    /// cannot keep read-only rolls back every guard made so far and aborts
    /// activation. Returns the trees actually guarded, for the caller to record in
    /// state and arm for teardown. A no-op (empty result) on a platform whose
    /// decoy protection comes from overlays alone, such as NixOS.
    pub(crate) fn apply_read_only_guard(&self) -> Result<Vec<PathBuf>> {
        let policy = crate::platform::detect_platform(&self.filesystem)?.overlay_policy();
        let trees = policy.resolve_read_only(&self.filesystem)?;
        if trees.is_empty() {
            return Ok(Vec::new());
        }
        crate::platform::guard_read_only_trees(&self.filesystem, &trees)
    }

    /// Persist the read-only guard set so deactivation and emergency teardown undo
    /// exactly those binds.
    pub(super) fn record_read_only_guards(&self, guards: &[PathBuf]) -> Result<()> {
        let mut cached = self.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            if state_file.read_only_guards == guards {
                return Ok(());
            }
            state_file.read_only_guards = guards.to_vec();
            drop(cached);
            self.save_cached_state()?;
        }
        Ok(())
    }

    /// Resolve the overlay set this activation mounts, for the active mode.
    ///
    /// Explicit mode uses the configured overlays verbatim; auto mode re-derives
    /// them from the live base OS the same way
    /// [`mount_auto_overlays`](Self::mount_auto_overlays) does. Shared so the
    /// post-switch re-assertion re-mounts exactly the overlays the mount phase
    /// created, in either mode. A target whose auto config cannot be rebuilt is
    /// skipped, matching the best-effort mount loop.
    fn resolve_mounted_overlay_set(&self) -> Result<Vec<OverlayConfig>> {
        match self.config.overlay_mode {
            crate::OverlayMode::Explicit => Ok(self.config.overlays.clone()),
            crate::OverlayMode::Auto => {
                let targets = build_overlay_targets(&self.filesystem, &self.config)?;
                let mut overlays = Vec::new();
                for target in &targets {
                    if let Ok(config) = create_overlay_config(
                        &self.filesystem,
                        target,
                        &self.config.hidden_volume_root,
                    ) {
                        overlays.push(config);
                    }
                }
                Ok(overlays)
            }
        }
    }

    /// Re-mount overlays that the hidden NixOS `switch-to-configuration` tore down.
    ///
    /// `switch-to-configuration test` reconciles the running system's systemd
    /// units against the new generation and, in doing so, unmounts the overlay
    /// mounts NAILS placed over the base-OS trees it manages (`/etc`, `/usr`,
    /// `/bin`, `/lib64`): afterwards those trees are the bare decoy again, so a
    /// hidden-session write there would reach the decoy disk. The data trees
    /// (`/home`, `/root`, `/srv`, `/tmp`) are left mounted. This runs right after
    /// the switch and before the session restarts, so the restarted hidden session
    /// comes up with every configured overlay back in place.
    ///
    /// An overlay still present (as an overlay, a pivot bind, or a persona home
    /// bind) is left untouched, so only the trees the switch cleared are re-mounted
    /// and nothing is ever double-stacked. Best-effort per overlay: a re-mount that
    /// fails is logged loudly (the decoy tree is then exposed) but does not abort an
    /// otherwise successful activation. Returns the targets it re-mounted.
    pub(crate) fn remount_overlays_cleared_by_switch(&self, verbosity: Verbosity) -> Vec<PathBuf> {
        let overlays = match self.resolve_mounted_overlay_set() {
            Ok(overlays) => overlays,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "Could not resolve the overlay set to re-assert after the NixOS switch"
                );
                return Vec::new();
            }
        };

        let mut remounted = Vec::new();
        for overlay in &overlays {
            let target = overlay.target.as_path();

            // Still mounted (overlay, pivot bind, or persona home bind): the switch
            // left this tree alone, so there is nothing to re-mount.
            match self.filesystem.is_mounted(target) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => {
                    tracing::warn!(
                        target = %target.display(),
                        error = %error,
                        "Could not check whether an overlay survived the NixOS switch; leaving it alone"
                    );
                    continue;
                }
            }

            // Recompute the extra lower layers for bind-mount visibility exactly as
            // the mount loop does, so a re-mount over e.g. /etc keeps a bind-mounted
            // /etc/nixos visible under the overlay.
            let extra_lowers = match self.filesystem.find_submount_sources(target) {
                Ok(sources) if !sources.is_empty() => {
                    crate::overlay::bind_sync::compute_extra_lower_dirs(target, &sources)
                }
                _ => Vec::new(),
            };
            // Clear stale opaque markers on managed dirs before re-mounting, so a
            // marker left in the upper cannot hide lower-layer contents.
            crate::overlay::opaque::strip_managed_opaque(&overlay.upper, target);

            let mut lower_refs: Vec<&Path> = vec![overlay.lower.as_path()];
            for extra in &extra_lowers {
                lower_refs.push(extra.as_path());
            }

            match self
                .filesystem
                .mount_overlay(&lower_refs, &overlay.upper, &overlay.work, target)
            {
                Ok(()) => {
                    if verbosity >= Verbosity::Normal {
                        tracing::warn!(
                            target = %target.display(),
                            "Re-mounted an overlay the hidden NixOS switch tore down; the decoy tree is protected again"
                        );
                    }
                    remounted.push(target.to_path_buf());
                }
                Err(error) => {
                    tracing::error!(
                        target = %target.display(),
                        error = %error,
                        "Failed to re-mount an overlay the NixOS switch tore down; the decoy tree is exposed for this session"
                    );
                }
            }
        }

        remounted
    }

    /// Undo the read-only guards activation recorded, returning write access to the
    /// decoy OS trees. Best-effort and idempotent: `unmount_bind` is a no-op for a
    /// tree that is not currently guarded, so a partial or repeated teardown is
    /// safe. Called from deactivation and emergency teardown.
    pub(crate) fn teardown_read_only_guards(&self, guards: &[PathBuf]) {
        for tree in guards.iter().rev() {
            if let Err(error) = self.filesystem.unmount_bind(tree) {
                tracing::warn!(
                    tree = %tree.display(),
                    error = %error,
                    "Best-effort removal of a read-only guard failed; continuing teardown"
                );
            } else {
                tracing::info!(tree = %tree.display(), "Removed read-only guard from decoy OS tree");
            }
        }
    }

    /// Undo the submount attachments activation recorded, in reverse order.
    ///
    /// Reverse order is what keeps teardown valid: a nested overlay comes off
    /// before the staging bind backing its lower layer, and every re-attach comes
    /// off before the parent overlay it was stacked on (the parent overlays are
    /// unmounted later, by the orchestrator). Best-effort and idempotent — a bind
    /// unmount is a no-op for a mount that is not present, and an overlay unmount
    /// escalates to a forced detach — so a partial or repeated teardown is safe.
    pub(crate) fn teardown_submount_attachments(
        &self,
        attachments: &[crate::state::SubmountAttachment],
    ) {
        use crate::state::SubmountAttachment;
        for attachment in attachments.iter().rev() {
            let outcome = match attachment {
                SubmountAttachment::Bind { path } => self.filesystem.unmount_bind(path),
                SubmountAttachment::Overlay { path } => self
                    .filesystem
                    .unmount(path, false)
                    .or_else(|_| self.filesystem.unmount(path, true)),
            };
            match outcome {
                Ok(()) => tracing::info!(
                    path = %attachment.path().display(),
                    "Removed submount attachment"
                ),
                Err(error) => tracing::warn!(
                    path = %attachment.path().display(),
                    error = %error,
                    "Best-effort removal of a submount attachment failed; continuing teardown"
                ),
            }
        }
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

/// Outcome of inspecting systemd-journald's open journal file descriptors after
/// the `/var` overlay is mounted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JournaldFdCheck {
    /// Every persistent-journal fd journald holds is backed by the overlay, so
    /// the hidden session's records land on the overlay upper, not the decoy.
    InOverlay,
    /// journald still holds a persistent-journal fd on the base `/var`: records
    /// are leaking to the decoy journal, so activation must roll back.
    NotInOverlay,
    /// journald could not be inspected (not running, no persistent-journal fds, or
    /// `/proc` unreadable). Tolerated rather than treated as a leak.
    Indeterminate,
}

// In a test or runtime-safety context, force the fd check to a given outcome.
// Host inspection is skipped there, so a test that needs to exercise the re-home
// rollback path pins the result to `JournaldFdCheck::NotInOverlay`.
#[cfg(test)]
thread_local! {
    static FORCED_JOURNALD_FD_CHECK: std::cell::Cell<Option<JournaldFdCheck>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_forced_journald_fd_check(value: Option<JournaldFdCheck>) {
    FORCED_JOURNALD_FD_CHECK.with(|cell| cell.set(value));
}

/// Decide whether journald's journal fds resolve into the `/var` overlay.
///
/// In a test or runtime-safety context no host is touched: the check records that
/// it ran and returns the forced outcome (if a test pinned one) or
/// [`JournaldFdCheck::Indeterminate`]. On a real host it inspects journald's open
/// file descriptors against `upper_dir`, the `/var` overlay's upper directory.
fn journald_fds_resolve_into_overlay(upper_dir: &Path) -> JournaldFdCheck {
    if crate::runtime_safety::should_skip_host_interaction() {
        #[cfg(test)]
        {
            crate::manager::helpers::record_service_action("verify-journald-fds");
            if let Some(forced) = FORCED_JOURNALD_FD_CHECK.with(std::cell::Cell::get) {
                return forced;
            }
        }
        let _ = upper_dir;
        return JournaldFdCheck::Indeterminate;
    }

    inspect_journald_journal_fds(upper_dir)
}

/// Inspect systemd-journald's open persistent-journal fds on a real host.
///
/// Finds journald by its process name, then compares the device of each open
/// `/var/log/journal/...` fd — read through `/proc/<pid>/fd/<n>`, so it reflects
/// the *open file*, not the path — against the device of the overlay's upper
/// directory (`upper_dir`), stat'ed directly rather than through the mount. A
/// fd journald writes under the overlay resolves into the upper, so its backing
/// inode is on the hidden-volume device; a fd still on the decoy's base `/var`
/// is on a different device. The reference is the upper directory, not the
/// overlaid `/var/log/journal` path: the overlay carries no `xino`, so an inode
/// reports the real device of the layer that backs it, and on a
/// persistent-journal decoy `/var/log/journal` is served from the lower (decoy)
/// layer until copy-up, which would make the directory's device the decoy's and
/// wrongly flag the correctly-upper journal fd as a leak.
fn inspect_journald_journal_fds(upper_dir: &Path) -> JournaldFdCheck {
    use std::os::unix::fs::MetadataExt;

    let Some(pid) = find_pid_by_comm("systemd-journal") else {
        return JournaldFdCheck::Indeterminate;
    };

    let overlay_dev = match std::fs::metadata(upper_dir) {
        Ok(meta) => meta.dev(),
        Err(_) => return JournaldFdCheck::Indeterminate,
    };

    let fd_dir = format!("/proc/{pid}/fd");
    let entries = match std::fs::read_dir(&fd_dir) {
        Ok(entries) => entries,
        Err(_) => return JournaldFdCheck::Indeterminate,
    };

    let mut writable_fd_devices = Vec::new();
    for entry in entries.flatten() {
        let fd_path = entry.path();
        let Ok(target) = std::fs::read_link(&fd_path) else {
            continue;
        };
        // Only persistent-journal fds matter: a volatile /run/log/journal fd is on
        // tmpfs and never reaches the decoy disk.
        if !target.to_string_lossy().starts_with("/var/log/journal/") {
            continue;
        }
        // Only a *writable* fd can leak hidden-session records onto the decoy. On a
        // persistent-journal decoy journald keeps the pre-existing journals open
        // read-only; overlayfs serves those from the lower (the decoy device)
        // without copy-up, so they are on the base device but are the decoy's own
        // history, not a leak. The active journal journald writes to is what must
        // land on the overlay, so judge the posture by the writable fds alone.
        let Some(fd_name) = fd_path.file_name() else {
            continue;
        };
        if !journald_fd_is_writable(pid, &fd_name.to_string_lossy()) {
            continue;
        }
        // Stat through /proc/<pid>/fd/<n> so the device belongs to the open file,
        // not to whatever currently occupies that path through the overlay.
        let Ok(meta) = std::fs::metadata(&fd_path) else {
            continue;
        };
        writable_fd_devices.push(meta.dev());
    }

    classify_journald_fd_devices(overlay_dev, &writable_fd_devices)
}

/// Classify journald's writable persistent-journal fds against the `/var`
/// overlay's upper device.
///
/// With no writable persistent fd the posture is [`JournaldFdCheck::Indeterminate`]
/// (journald may not have reopened its journal yet). Otherwise every writable fd
/// must sit on the upper device; one on a different device is still writing to the
/// decoy's base `/var` and is a leak ([`JournaldFdCheck::NotInOverlay`]).
fn classify_journald_fd_devices(upper_dev: u64, writable_fd_devices: &[u64]) -> JournaldFdCheck {
    if writable_fd_devices.is_empty() {
        return JournaldFdCheck::Indeterminate;
    }
    if writable_fd_devices.iter().any(|&dev| dev != upper_dev) {
        return JournaldFdCheck::NotInOverlay;
    }
    JournaldFdCheck::InOverlay
}

/// Whether journald's open fd `fd` is writable, read from `/proc/<pid>/fdinfo`.
///
/// The `flags:` line holds the octal open flags; the low two bits are the access
/// mode (`O_RDONLY` = 0, `O_WRONLY` = 1, `O_RDWR` = 2), so a non-zero access mode
/// means the fd can be written. A missing or unparsable fdinfo reads as
/// not-writable, so an unreadable fd is never treated as a leak.
fn journald_fd_is_writable(pid: u32, fd: &str) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}"))
        .ok()
        .is_some_and(|content| fdinfo_is_writable(&content))
}

/// Whether a `/proc/<pid>/fdinfo/<n>` body describes a writable fd: the octal
/// `flags:` line has a non-zero access mode (`O_WRONLY`/`O_RDWR`) or `O_APPEND`.
/// A missing or unparsable `flags:` reads as not-writable, so an unreadable fd is
/// never treated as a leak that would roll the activation back.
fn fdinfo_is_writable(content: &str) -> bool {
    crate::process::detection::parse_fdinfo_flags(content)
        .is_some_and(|flags| flags & 0o3 != 0 || flags & 0o2000 != 0)
}

/// Find the PID of the first process whose `comm` matches `name`.
///
/// `comm` is truncated by the kernel to 15 bytes, so callers pass the truncated
/// form (journald's is `systemd-journal`). Returns `None` when no match is found
/// or `/proc` cannot be read.
fn find_pid_by_comm(name: &str) -> Option<u32> {
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let comm_path = format!("/proc/{pid}/comm");
        if let Ok(comm) = std::fs::read_to_string(&comm_path)
            && comm.trim_end() == name
        {
            return Some(pid);
        }
    }
    None
}

#[cfg(test)]
mod fdinfo_tests {
    use super::{JournaldFdCheck, classify_journald_fd_devices, fdinfo_is_writable};

    #[test]
    fn journald_fds_judged_against_the_upper_device_not_the_overlaid_dir() {
        const UPPER: u64 = 42;
        const DECOY: u64 = 7;

        // No writable persistent fd yet: journald may not have reopened its
        // journal, so the posture is indeterminate rather than a leak.
        assert_eq!(
            classify_journald_fd_devices(UPPER, &[]),
            JournaldFdCheck::Indeterminate
        );
        // The re-homed journal fd sits on the overlay upper (hidden-volume)
        // device, so journald writes under the overlay. On a persistent-journal
        // decoy the overlaid `/var/log/journal` directory is served from the decoy
        // until copy-up; judging against the upper device avoids flagging this
        // correctly-placed fd as a leak.
        assert_eq!(
            classify_journald_fd_devices(UPPER, &[UPPER]),
            JournaldFdCheck::InOverlay
        );
        // A writable persistent fd still on the decoy's base `/var` is a genuine
        // leak and must roll the activation back.
        assert_eq!(
            classify_journald_fd_devices(UPPER, &[DECOY]),
            JournaldFdCheck::NotInOverlay
        );
        assert_eq!(
            classify_journald_fd_devices(UPPER, &[UPPER, DECOY]),
            JournaldFdCheck::NotInOverlay
        );
    }

    #[test]
    fn writable_fds_are_detected_from_the_octal_flags_line() {
        // O_WRONLY (0o1) and O_RDWR (0o2), with the usual extra flags, are writable.
        assert!(fdinfo_is_writable(
            "pos:\t0\nflags:\t0100002\nmnt_id:\t42\n"
        ));
        assert!(fdinfo_is_writable("flags:\t02100001\n"));
        // O_RDONLY (low two bits zero) is not writable — the decoy's own journals
        // journald keeps open for reading.
        assert!(!fdinfo_is_writable(
            "pos:\t0\nflags:\t0100000\nmnt_id:\t42\n"
        ));
        // A missing or unparsable flags line reads as not-writable.
        assert!(!fdinfo_is_writable("pos:\t0\nmnt_id:\t42\n"));
        assert!(!fdinfo_is_writable("flags:\tnope\n"));
    }
}

#[cfg(test)]
mod progress_tests {
    use super::overlay_progress_message;
    use std::path::Path;

    #[test]
    fn progress_message_is_one_based_with_target_and_count() {
        assert_eq!(
            overlay_progress_message(Path::new("/home"), 3, 12),
            "mounting /home (3/12)"
        );
    }

    #[test]
    fn progress_message_handles_first_and_last_overlay() {
        assert_eq!(
            overlay_progress_message(Path::new("/etc"), 1, 1),
            "mounting /etc (1/1)"
        );
        assert_eq!(
            overlay_progress_message(Path::new("/nix"), 5, 5),
            "mounting /nix (5/5)"
        );
    }
}

#[cfg(test)]
mod remount_after_switch_tests {
    use super::*;
    use crate::config::Config;
    use crate::manager::NailsManager;
    use crate::{MockFilesystem, OverlayConfig, Verbosity};
    use std::path::PathBuf;

    const HIDDEN_ROOT: &str = "/mnt/data";

    fn overlay(name: &str, target: &str) -> OverlayConfig {
        OverlayConfig {
            name: name.to_string(),
            lower: PathBuf::from(target),
            upper: PathBuf::from(format!("{HIDDEN_ROOT}/{name}")),
            work: PathBuf::from(format!("{HIDDEN_ROOT}/.work/{name}")),
            target: PathBuf::from(target),
        }
    }

    /// Build a manager whose explicit overlays can all be (re-)mounted on the mock:
    /// every lower, upper and work path is present so `verify_mount_preconditions`
    /// passes.
    fn manager_with_overlays(
        overlays: Vec<OverlayConfig>,
    ) -> (MockFilesystem, NailsManager<MockFilesystem>) {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(HIDDEN_ROOT, true);
        fs.mock_set_writable(HIDDEN_ROOT, true);
        for overlay in &overlays {
            for dir in [&overlay.lower, &overlay.upper, &overlay.work] {
                fs.mock_set_path_exists(dir.to_str().unwrap(), true);
                fs.mock_set_writable(dir.to_str().unwrap(), true);
            }
        }
        let config = Config {
            hidden_volume_root: PathBuf::from(HIDDEN_ROOT),
            overlay_mode: crate::OverlayMode::Explicit,
            overlays,
            ..Config::test_default()
        };
        let state_path = PathBuf::from(HIDDEN_ROOT).join("state.json");
        let manager = NailsManager::new(fs.clone(), config, state_path);
        (fs, manager)
    }

    #[test]
    fn remounts_only_the_overlays_the_switch_cleared() {
        let (fs, manager) =
            manager_with_overlays(vec![overlay("etc", "/etc"), overlay("home", "/home")]);

        // The switch tore down /etc but left /home mounted (the pattern observed on
        // a real NixOS host: base-OS trees are reconciled, data trees are not).
        fs.mock_set_mounted(PathBuf::from("/home").as_path(), true);
        fs.mock_set_mounted(PathBuf::from("/etc").as_path(), false);

        let remounted = manager.remount_overlays_cleared_by_switch(Verbosity::Normal);

        assert_eq!(
            remounted,
            vec![PathBuf::from("/etc")],
            "only the torn-down base-OS overlay is re-mounted, not the surviving data tree"
        );
        // The re-mount re-established the /etc overlay and never touched /home.
        assert!(
            fs.is_mounted(PathBuf::from("/etc").as_path()).unwrap(),
            "/etc overlay is mounted again after the re-assertion"
        );
        let remounted_targets: Vec<PathBuf> = fs
            .mock_ops()
            .into_iter()
            .filter_map(|op| match op {
                crate::filesystem::mock::MockOp::MountOverlay { target } => Some(target),
                _ => None,
            })
            .collect();
        assert_eq!(remounted_targets, vec![PathBuf::from("/etc")]);
    }

    #[test]
    fn does_nothing_when_every_overlay_survived_the_switch() {
        let (fs, manager) =
            manager_with_overlays(vec![overlay("etc", "/etc"), overlay("home", "/home")]);

        fs.mock_set_mounted(PathBuf::from("/etc").as_path(), true);
        fs.mock_set_mounted(PathBuf::from("/home").as_path(), true);

        let remounted = manager.remount_overlays_cleared_by_switch(Verbosity::Normal);

        assert!(
            remounted.is_empty(),
            "no overlay is re-mounted when the switch left them all in place"
        );
        let mounted_overlay_ops = fs
            .mock_ops()
            .into_iter()
            .filter(|op| matches!(op, crate::filesystem::mock::MockOp::MountOverlay { .. }))
            .count();
        assert_eq!(mounted_overlay_ops, 0, "no overlay mount syscall is issued");
    }
}
