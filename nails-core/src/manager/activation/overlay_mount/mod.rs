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
mod journald_fd;
mod mount_success;
mod persona;
mod restore;
mod submount_attach;
mod writer_rescan;

pub(crate) use journald_fd::JournaldFdCheck;
#[cfg(test)]
pub(crate) use journald_fd::set_forced_journald_fd_check;

#[allow(unused_imports)]
use super::{
    MountInfo, MountTracker, MountType, build_overlay_targets, clean_stale_network_config,
    create_overlay_config, start_service_and_socket,
};
use crate::manager::activation::guards::NixDaemonGuard;
use crate::platform::NixRuntime;
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

/// Create this activation's runtime scaffolding root: one random-named tmpfs
/// under `/run`, mounted `mode=0700,nosuid,nodev`, that will hold pivot staging,
/// the vfat snapshot tmpfs and the pre-overlay `/nix/store` bind.
///
/// In a test or runtime-safety build no real mount is made — the path is still
/// generated and returned so the flow records and threads it, but the mock
/// filesystem is left untouched. The returned path is pushed onto the mount
/// tracker by the caller so a mid-activation failure tears it down last.
fn create_runtime_root<F: Filesystem>(fs: &F) -> Result<PathBuf> {
    let root = crate::runtime_root::random_runtime_root();
    if crate::runtime_safety::should_skip_host_interaction() {
        return Ok(root);
    }
    fs.create_directory(&root)?;
    fs.mount_tmpfs(&root, crate::runtime_root::UMBRELLA_TMPFS_SIZE)?;
    // Private to the operator: the scaffolding never needs to be world- or
    // group-readable, and 0700 keeps another local account from enumerating it.
    fs.set_permissions(&root, 0o700)?;
    Ok(root)
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

/// Move this process's working directory to `/` before any mount, and return a
/// warning when the invoking shell's cwd (which this process inherited) was not
/// already `/`.
///
/// An open directory — including a process's `cwd` — resolves to the inode it was
/// opened against, not to whatever is later mounted over it. If nails kept its
/// cwd inside a soon-to-be-overlaid decoy directory it would itself become a decoy
/// writer; `chdir("/")` removes that reference before the first overlay goes up.
///
/// The operator's own shell holds the same cwd and nails cannot change it from
/// here, so when that cwd is off `/` the returned message tells the operator to
/// `cd /` — otherwise anything written from that shell (or a program launched in
/// it) after activation lands on the decoy.
///
/// A no-op in test/runtime-safety builds: changing the test process's cwd would
/// corrupt sibling tests, and there is no real shell to warn about.
fn chdir_root_before_mount() -> Option<String> {
    if crate::runtime_safety::should_skip_host_interaction() {
        return None;
    }
    let cwd = std::env::current_dir().ok();
    if let Err(e) = std::env::set_current_dir(Path::new("/")) {
        tracing::warn!(error = %e, "could not move to / before mounting overlays");
    }
    cwd.as_deref().and_then(decoy_cwd_warning)
}

/// The decoy-cwd warning for an invoking shell sitting off `/`, or `None` when its
/// cwd is the root and there is nothing to warn about.
fn decoy_cwd_warning(cwd: &Path) -> Option<String> {
    if cwd == Path::new("/") {
        return None;
    }
    Some(format!(
        "the shell that started this is in {} — after activation that directory still \
         resolves to the decoy, so anything written from that shell (or a program \
         launched in it) lands on the decoy. Run `cd /` in it.",
        cwd.display()
    ))
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

        // Before the first mount, drop nails's own cwd to / so it never holds a
        // reference into a soon-to-be-overlaid decoy directory, and warn when the
        // invoking shell is sitting off / (that shell keeps writing to the decoy).
        if let Some(warning) = chdir_root_before_mount() {
            tracing::warn!("{warning}");
        }

        // The tracker is the mid-mount safety net: if any mount below fails it
        // rolls back on drop. Its mounts are taken out on success instead of
        // committed, so a later activation failure can still unmount them.
        let mut tracker = MountTracker::new(&self.filesystem);

        // Create the per-activation runtime scaffolding root first and push it onto
        // the tracker before any overlay, so LIFO rollback tears it down last —
        // after every staging mount and bind placed inside it.
        let runtime_root = create_runtime_root(&self.filesystem)?;
        tracker.push_mount(MountInfo::tmpfs(runtime_root.clone()));
        // Record it in state immediately, so a trusted teardown removes exactly
        // this tree even if activation crashes before the Active transition.
        self.record_runtime_root(&runtime_root)?;

        // Build OverlayStrategyOptions from ActivateOptions. The risky-service
        // choice is resolved up front so a non-interactive run that keeps the
        // session fails fast (before anything is mounted) when no choice was made.
        let strategy_options = crate::overlay::OverlayStrategyOptions {
            auto_restart_safe: true, // Always restart safe processes automatically
            risky_services: options.resolve_risky_services()?,
            terminate_processes: options.terminate_processes,
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
                self.mount_auto_overlays(
                    &mut tracker,
                    &runtime_root,
                    &strategy_options,
                    verbosity,
                    &mut outcome,
                )?;
            }
            crate::OverlayMode::Explicit => {
                self.mount_explicit_overlays(
                    &mut tracker,
                    &runtime_root,
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

        // Post-mount rescan: walk /proc once now that every overlay is up and fold
        // any process still holding a write-capable reference to an overlaid target
        // into the decoy-writer set. This catches writers the pre-mount pass could
        // not restart or that survived a service restart, tagging each as
        // stale-lower or (for a chrooted/foreign-namespace process) unverifiable.
        // A no-op in test/runtime-safety builds, where the /proc snapshot is empty,
        // so existing detection results are unchanged.
        let persistent_targets: Vec<PathBuf> = tracker
            .mounted
            .iter()
            .filter(|info| info.mount_type == MountType::Persistent)
            .map(|info| info.target.clone())
            .collect();
        writer_rescan::rescan_post_mount_writers(&mut outcome.decoy_writers, &persistent_targets);

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
        runtime_root: &Path,
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
                    crate::manager::helpers::cache_nix_overlay_runtime_commands(runtime_root).map_err(
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
            runtime_root,
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
        runtime_root: &Path,
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
            // Reported through the activation's reporter (muted below Normal
            // verbosity there) and kept as the progress record's detail.
            crate::reporter::progress::detail(
                "overlay_mount",
                &overlay_progress_message(&overlay.target, overlay_index + 1, overlay_total),
            );

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
                runtime_root,
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
            // If no overlay mounted at all, abort with the first failure as the
            // representative error; the caller rolls back (only the runtime
            // scaffolding tmpfs, if that was created) and restarts services. The
            // runtime-root tmpfs record is scaffolding, not an overlay, so it does
            // not count as a successful mount here.
            if tracker
                .mounted
                .iter()
                .all(|m| m.mount_type == MountType::Tmpfs)
            {
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
    /// Persist the per-activation runtime scaffolding root into the cached state
    /// and save it, so a trusted teardown (deactivate/recover) unmounts and
    /// removes exactly this tree. Recorded right after the mount phase, before the
    /// Active transition, so a crash between here and `Active` still leaves the
    /// path on disk for the next teardown. A state-independent emergency teardown
    /// does not depend on it — it rediscovers the tree from the live mount table.
    pub(super) fn record_runtime_root(&self, root: &Path) -> Result<()> {
        let mut cached = self.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            if state_file.runtime_root.as_deref() == Some(root) {
                return Ok(());
            }
            state_file.runtime_root = Some(root.to_path_buf());
            drop(cached);
            self.save_cached_state()?;
        }
        Ok(())
    }

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
    /// decoy OS trees. Best-effort and idempotent: `remove_read_only_guard` is a no-op for a
    /// tree that is not currently guarded, so a partial or repeated teardown is
    /// safe. Called from deactivation and emergency teardown.
    pub(crate) fn teardown_read_only_guards(&self, guards: &[PathBuf]) {
        for tree in guards.iter().rev() {
            if let Err(error) = self.filesystem.remove_read_only_guard(tree) {
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
mod cwd_tests {
    use super::decoy_cwd_warning;
    use std::path::Path;

    #[test]
    fn a_root_cwd_produces_no_warning() {
        assert_eq!(decoy_cwd_warning(Path::new("/")), None);
    }

    #[test]
    fn a_cwd_off_root_warns_and_names_the_directory_and_the_fix() {
        let warning = decoy_cwd_warning(Path::new("/home/op/notes")).expect("expected a warning");
        assert!(warning.contains("/home/op/notes"), "{warning}");
        assert!(warning.contains("cd /"), "{warning}");
        assert!(warning.contains("decoy"), "{warning}");
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
