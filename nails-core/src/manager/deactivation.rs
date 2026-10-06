// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Deactivation logic for `NailsManager`
//!
//! Both `deactivate()` and `emergency_deactivate()` now route through
//! `DeactivationOrchestrator`, with thin wrappers for mode-specific pre/post work.

use super::NailsManager;
use super::{restart_service_and_socket, select_decoy_restore_target, start_service_and_socket};
use crate::deactivation::DeactivationReport;
#[cfg(not(test))]
use crate::deactivation::test_gate::should_skip_shell_cleanup_before_deactivation_gate;
#[cfg(not(test))]
use crate::process::kill_shells_for_teardown;
use crate::{
    CleanupConfig, CleanupManager, CleanupMode, CleanupReport, Filesystem, NailsError, Result,
    SystemState,
};
use std::path::{Path, PathBuf};

mod decoy;
mod orchestrator;
mod overlay_context;
mod process_teardown;
mod reboot;
mod session_guard;
mod unmount;

use decoy::{recorded_decoy_system, requires_decoy_restore};
pub use orchestrator::{DeactivationMode, DeactivationOrchestrator};
use overlay_context::{OverlayContext, inspect_overlay_context, overlay_context_from_mounts};
use process_teardown::{
    candidate_is_overlay_rooted, current_process_ancestry, is_own_invocation_process,
    owner_pid_to_signal, read_proc_cgroup, read_session_and_pgid, self_session_and_pgid,
    signal_pid,
};

pub use reboot::{HostEffects, PostTeardownPower};
#[cfg(any(test, feature = "test-hooks"))]
pub use reboot::{SimulatedHostEffects, SimulatedReboot};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ManagerDeactivationKind {
    Normal,
    Emergency,
    /// Operator-driven recovery of a stuck state (Interrupted/Degraded/corrupt).
    ///
    /// Always drives the mount-discovery teardown engine: it never trusts the
    /// recorded overlay list, never reboots, and ends Inactive when nothing
    /// survives. Unlike emergency it is not a panic button on a live session but
    /// a deliberate reconcile-and-clean of a system left in an inconsistent
    /// state.
    Recover,
}

impl ManagerDeactivationKind {
    fn orchestrator_mode(self) -> DeactivationMode {
        match self {
            Self::Normal => DeactivationMode::Normal,
            // Recovery reuses the fast, best-effort teardown: errors are
            // non-fatal and no thorough verification stands between it and the
            // unmounts it must finish.
            Self::Emergency | Self::Recover => DeactivationMode::Emergency,
        }
    }

    /// How long the teardown waits for a signalled activation owner to exit.
    fn owner_exit_wait(self) -> std::time::Duration {
        match self {
            Self::Emergency => std::time::Duration::from_secs(1),
            Self::Normal | Self::Recover => std::time::Duration::from_secs(3),
        }
    }

    fn reboots_on_success(self) -> bool {
        matches!(self, Self::Normal)
    }

    /// Whether this kind always tears down from the live mount table rather than
    /// the recorded overlay list.
    ///
    /// Recovery always does; emergency does only when the state file is
    /// untrusted (decided per run); normal deactivation never does.
    fn always_untrusted(self) -> bool {
        matches!(self, Self::Recover)
    }
}

/// The cleanup configuration the normal teardown runs through the still-mounted
/// overlays. Emergency and recovery run no artifact cleanup at all (see
/// [`DeactivationMode::Emergency`]), so the configuration is the same for every
/// kind.
fn build_cleanup_config<F: Filesystem>(manager: &NailsManager<F>) -> CleanupConfig {
    CleanupConfig {
        clear_history: manager.config().clear_history,
        log_path: manager.config().log_path.clone(),
        hidden_volume_root: manager.config().hidden_volume_root.clone(),
        config_file_path: manager.config().loaded_config_path.clone(),
        ..CleanupConfig::default()
    }
}

impl<F: Filesystem> NailsManager<F> {
    /// Tear down what sits on top of the parent overlays, before those come down:
    /// the read-only guards on the decoy OS trees and the submount attachments.
    fn teardown_overlay_dependents(&self, overlay_context: &OverlayContext) {
        if !overlay_context.read_only_guards.is_empty() {
            tracing::info!(
                guards = ?overlay_context.read_only_guards,
                "Removing read-only guards from decoy OS trees"
            );
            self.teardown_read_only_guards(&overlay_context.read_only_guards);
        }

        if !overlay_context.submount_attachments.is_empty() {
            tracing::info!(
                count = overlay_context.submount_attachments.len(),
                "Removing submount attachments"
            );
            self.teardown_submount_attachments(&overlay_context.submount_attachments);
        }
    }

    /// Stop the in-session backend watcher and remove the RAM-backed runtime copy.
    ///
    /// Best-effort on every teardown path (deactivate, emergency and recover): a
    /// watcher that was never started makes the stop a no-op, and a copy that was
    /// never written makes the removal a no-op, so neither can turn a teardown into
    /// a failure. The filesystem removal routes through the manager's filesystem
    /// (mockable); only stopping the systemd unit is a real host call, so only that
    /// is gated by the test-runtime skip.
    fn teardown_backend_runtime_copy(&self) {
        if let Err(e) = crate::runtime_copy::remove_runtime_copy(self.filesystem()) {
            tracing::warn!(
                error = %e,
                "Best-effort removal of the RAM-backed runtime copy failed; continuing teardown"
            );
        }
        if !crate::runtime_safety::should_skip_host_interaction() {
            crate::runtime_copy::stop_watch_unit();
            crate::sleep_guard::stop_sleep_guard_unit();
        }
    }

    /// The live NAILS overlay mount points, for the emergency overlay-rooted
    /// process scan. The read-only `/nix/store` restore bind is left out: it
    /// shares the decoy filesystem and cannot be written through, so a process
    /// using it is no writer to stop. Best-effort: a discovery error yields an
    /// empty list rather than blocking the teardown.
    fn emergency_overlay_targets(&self) -> Vec<PathBuf> {
        let hidden_root = self.config().hidden_volume_root.clone();
        match self.filesystem().discover_nails_mounts(Some(&hidden_root)) {
            Ok(discovered) => discovered
                .owned_mount_points()
                .into_iter()
                .filter(|point| discovered.nix_store_bind.as_ref() != Some(point))
                .collect(),
            Err(e) => {
                tracing::warn!(error = %e, "Could not enumerate NAILS mounts for emergency process cleanup");
                Vec::new()
            }
        }
    }

    /// Emergency only: run the pre-teardown service cleanup. A no-op for the
    /// normal and recovery kinds, which keep the thorough teardown order.
    fn prepare_emergency_pre_unmount_cleanup(&self, kind: ManagerDeactivationKind) {
        if kind != ManagerDeactivationKind::Emergency {
            return;
        }
        let overlay_targets = self.emergency_overlay_targets();
        self.stop_hidden_units_before_teardown(&overlay_targets);
    }

    /// Emergency only: stop the service units the hidden configuration added, then
    /// signal any process still able to write to the decoy *through an overlay
    /// target*, before the overlays come down.
    ///
    /// It deliberately leaves the desktop looking unchanged: emergency never logs
    /// the operator out (no logind session/user terminate) and never stops or
    /// restarts the display manager or X server. Emergency detaches the overlays
    /// from underneath the running session instead — lazily where a process still
    /// holds a path busy — and the report then names any mount or backend that
    /// could not be released. The overlay-rooted process signal is the targeted
    /// anti-leak step (a process whose references resolve onto an overlay's own
    /// device could re-dirty the decoy once the mount is lazily detached); it
    /// spares the teardown's own session and never touches the display manager.
    /// All of it is best-effort.
    fn stop_hidden_units_before_teardown(&self, overlay_targets: &[PathBuf]) {
        let added_units = self
            .cached_state
            .borrow()
            .as_ref()
            .map(|state_file| state_file.hidden_added_units.clone())
            .unwrap_or_default();

        // Enqueue every stop at once rather than waiting for each unit in turn:
        // one bounded call, so a slow unit can never hold the overlays up. The
        // jobs also keep Restart= from reviving a unit the kill below hits.
        if !added_units.is_empty() {
            let units = added_units
                .iter()
                .map(|unit| {
                    if unit.contains('.') {
                        unit.clone()
                    } else {
                        format!("{unit}.service")
                    }
                })
                .collect();
            process_teardown::enqueue_unit_stops(&units);
        }

        self.kill_overlay_rooted_processes(overlay_targets);
    }

    /// Signal any process that can still write to the decoy through an overlay
    /// target (a cwd/root inside it, a writable or directory fd, a shared-writable
    /// mapping). Reuses the capability-aware process classifier; read-only
    /// consumers are left alone. Best-effort and a no-op in test/test-like
    /// runtimes, where the `/proc` snapshot is empty.
    ///
    /// The classifier matches targets by path prefix, which cannot by itself tell
    /// a reference *inside the overlay* from one on the decoy directory the overlay
    /// is mounted over: a decoy process whose cwd is `/tmp` (set before activation)
    /// still reads back as `/tmp` and would be signalled, even though it is on the
    /// decoy and neither pins the overlay nor can write into its upper. So a
    /// path-matched candidate is kept only when a reference of its — cwd, root,
    /// any open fd or a shared-writable mapping — really lives on one of the
    /// writable NAILS mounts, judged by mount id (see [`crate::process::mount_refs`];
    /// `st_dev` cannot be used, as an overlay's non-directory files report their
    /// layer's device). An unverifiable writer (foreign mount namespace or chroot,
    /// where mount ids are not comparable) is kept fail-safe, as is every
    /// candidate when the NAILS mount ids could not be read at all.
    ///
    /// On a graphical host the whole desktop is overlay-rooted (the session logs
    /// back in under the overlays), so the display manager, X server, logind
    /// session leader/wrapper, window/session manager and user systemd manager
    /// would all match. Killing any of them logs the operator out, which emergency
    /// forbids, so [`session_guard::GraphicalSessionGuard`] spares every process in
    /// the operator's graphical session (see that module for the policy and for the
    /// residual exposure a spared process can leak after the lazy detach). Processes
    /// outside the graphical session are still killed.
    fn kill_overlay_rooted_processes(&self, targets: &[PathBuf]) {
        if targets.is_empty() || crate::runtime_safety::should_skip_host_interaction() {
            return;
        }

        let snapshot = match crate::process::detection::ProcSnapshot::capture() {
            Ok(snapshot) => snapshot,
            Err(e) => {
                tracing::warn!(error = %e, "Could not snapshot /proc for overlay-rooted process cleanup");
                return;
            }
        };

        // The mount ids of the writable NAILS mounts. A reference on one of these
        // is genuinely inside an overlay; one elsewhere only collided on the path
        // string.
        let hidden_root = self.config().hidden_volume_root.clone();
        let overlay_mount_ids = crate::filesystem::read_mountinfo()
            .map(|entries| {
                crate::filesystem::NailsMounts::owned_writable_mount_ids(
                    &entries,
                    Some(&hidden_root),
                )
            })
            .unwrap_or_default();

        // The processes that keep the operator's graphical session alive. Emergency
        // detaches the overlays from under a running desktop without logging the
        // operator out, so these are spared even though they are overlay-rooted.
        // Bounded: a hung logind must not hold the overlays up. A query that
        // runs out of budget makes the guard spare every user session, the
        // desktop-safe answer.
        let session_guard = session_guard::GraphicalSessionGuard::detect(
            &session_guard::BoundedLoginctl::new(session_guard::SESSION_DETECTION_BUDGET),
        );
        let mut spared_session_pids = std::collections::BTreeSet::new();

        // Never signal a process that belongs to this teardown's own invocation:
        // its ancestry, session or process group. A piped emergency
        // (`nails emergency | base64`) has its pipe reader in the same session
        // (and process group) with a cwd inside the full-root overlay, so without
        // this guard it would be killed and the teardown's own final stdout write
        // would hit a closed pipe.
        let ancestry = current_process_ancestry();
        let (self_sid, self_pgid) = self_session_and_pgid();
        let self_pid = std::process::id();

        let mut pids = std::collections::BTreeSet::new();
        for target in targets {
            for info in snapshot.processes_using(target) {
                if !info.is_write_blocking() || info.pid == self_pid {
                    continue;
                }
                let (sid, pgid) = read_session_and_pgid(info.pid).unwrap_or((0, 0));
                if is_own_invocation_process(info.pid, sid, pgid, &ancestry, self_sid, self_pgid) {
                    tracing::debug!(
                        pid = info.pid,
                        "Sparing a process in the teardown's own session/group from the overlay kill"
                    );
                    continue;
                }
                if read_proc_cgroup(info.pid).is_some_and(|cgroup| session_guard.covers(&cgroup)) {
                    spared_session_pids.insert(info.pid);
                    tracing::debug!(
                        pid = info.pid,
                        "Sparing a process that keeps the operator's graphical session alive"
                    );
                    continue;
                }
                let unverifiable = info.is_unverifiable_writer
                    || !crate::process::mount_refs::same_mount_namespace(info.pid);
                let on_overlay_mount = !overlay_mount_ids.is_empty()
                    && crate::process::mount_refs::process_references_mounts(
                        info.pid,
                        &overlay_mount_ids,
                    );
                if !candidate_is_overlay_rooted(
                    unverifiable,
                    on_overlay_mount,
                    !overlay_mount_ids.is_empty(),
                ) {
                    tracing::debug!(
                        pid = info.pid,
                        "Sparing a decoy-side process (path matched an overlay target but no reference lives on a NAILS mount)"
                    );
                    continue;
                }
                pids.insert(info.pid);
            }
        }

        if !spared_session_pids.is_empty() {
            // These processes keep the operator's graphical session alive and were
            // left running by design. After the lazy overlay detach a spared process
            // that reopens an absolute path onto the now-exposed decoy could still
            // write to it; emergency accepts that rather than log the operator out,
            // and the honest "hidden root still mounted" report tells them to finish
            // with a reboot/power-off.
            tracing::info!(
                spared = spared_session_pids.len(),
                "Spared processes belonging to the operator's graphical session (display manager, X server, session leader/clients, user service manager) from the overlay-rooted kill"
            );
        }

        if pids.is_empty() {
            return;
        }

        // A killed process of a `Restart=` service would be revived by systemd
        // after the overlays are gone and then write to the decoy. Enqueue a stop
        // job for every such unit first (never the unit this teardown runs in;
        // the graphical session's units were spared above), then signal.
        let own_unit = crate::process::cgroup_unit::own_service_unit();
        let units: std::collections::BTreeSet<String> = pids
            .iter()
            .filter_map(|&pid| read_proc_cgroup(pid))
            .filter(|cgroup| !session_guard.covers(cgroup))
            .filter_map(|cgroup| crate::process::cgroup_unit::service_unit_from_cgroup(&cgroup))
            .filter(|unit| crate::process::cgroup_unit::may_stop_unit(own_unit.as_deref(), unit))
            .collect();
        process_teardown::enqueue_unit_stops(&units);

        for &pid in &pids {
            signal_pid(pid, "TERM");
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        for &pid in &pids {
            if std::path::Path::new(&format!("/proc/{pid}")).exists() {
                signal_pid(pid, "KILL");
            }
        }
    }

    /// Emergency/recover only: a still-running activation owner could keep writing
    /// into the overlays while we tear them down, re-dirtying the decoy. Try-lock,
    /// not a hard gate: SIGTERM a recorded owner pid that is alive, is not us, is
    /// still the process that wrote the state (pid plus start time, same boot) and
    /// is outside the graphical session, wait briefly for it to exit, then proceed
    /// unconditionally. Never fails
    /// closed — a ptraced or uninterruptible owner must not block the panic
    /// button. Best-effort and a no-op in test/test-like runtimes.
    fn signal_owner_pid_before_teardown(&self, kind: ManagerDeactivationKind) {
        if crate::runtime_safety::should_skip_host_interaction() {
            return;
        }
        // Read the recorded owner fresh; a corrupt/unreadable state file simply
        // means no owner to signal, and the teardown continues.
        let Ok(state_file) = crate::StateFile::load(&self.state_file_path) else {
            return;
        };
        let Some(pid) = owner_pid_to_signal(kind, state_file.owner_pid, std::process::id()) else {
            return;
        };
        if !crate::manager::state_management::pid_is_alive(pid) {
            return;
        }
        // A pid alone may have been reused: signal only the very process that
        // wrote the state, identified by its start time within the same boot.
        if !process_teardown::owner_identity_matches(
            state_file.owner_start_time,
            state_file.boot_id.as_deref(),
            crate::process::proc_start_time(pid),
            crate::state::read_boot_id().as_deref(),
        ) {
            tracing::info!(
                pid,
                "Recorded owner pid now names another process; not signalling it"
            );
            return;
        }
        // Never signal a process of the operator's graphical session (emergency
        // never logs the operator out), whatever the state file claims.
        let session_guard = session_guard::GraphicalSessionGuard::detect(
            &session_guard::BoundedLoginctl::new(session_guard::SESSION_DETECTION_BUDGET),
        );
        if read_proc_cgroup(pid).is_some_and(|cgroup| session_guard.covers(&cgroup)) {
            tracing::info!(
                pid,
                "Recorded owner belongs to the graphical session; not signalling it"
            );
            return;
        }
        // PID reuse can make a stale recorded owner collide with a process in this
        // teardown's own invocation — in a piped run, the shell or reader on the
        // far end of the pipe. Signalling it would break the pipeline carrying our
        // own output, so spare any pid in our ancestry, session or process group.
        let ancestry = current_process_ancestry();
        let (self_sid, self_pgid) = self_session_and_pgid();
        let (owner_sid, owner_pgid) = read_session_and_pgid(pid).unwrap_or((0, 0));
        if is_own_invocation_process(pid, owner_sid, owner_pgid, &ancestry, self_sid, self_pgid) {
            tracing::info!(
                pid,
                "Recorded owner belongs to this invocation (likely a reused pid); not signalling it"
            );
            return;
        }

        tracing::info!(
            pid,
            "Signalling the recorded activation owner before teardown"
        );
        signal_pid(pid, "TERM");

        // Emergency keeps the wait short so the overlays come down within a few
        // seconds; recovery is no panic button and allows the owner longer.
        let wait = kind.owner_exit_wait();
        let deadline = std::time::Instant::now() + wait;
        while std::time::Instant::now() < deadline {
            if !crate::manager::state_management::pid_is_alive(pid) {
                tracing::info!(pid, "Activation owner exited before teardown");
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        tracing::warn!(
            pid,
            "Activation owner still alive after waiting; proceeding with teardown anyway"
        );
    }

    /// Fail a Normal deactivation up front if the decoy cannot be restored.
    ///
    /// A NixOS session (one with a recorded hidden toplevel) must be able to point
    /// `/run/current-system` back at a decoy system afterwards: either the one
    /// recorded at activation or the system profile. Refusing before any overlay is
    /// detached leaves the Active session intact.
    fn ensure_decoy_restore_possible(&self) -> Result<()> {
        if !requires_decoy_restore(self)? {
            return Ok(());
        }
        let recorded = recorded_decoy_system(self);
        if select_decoy_restore_target(self.filesystem(), recorded.as_deref(), self.runtime_env())?
            .is_none()
        {
            return Err(NailsError::NixOSError(
                "No recorded decoy system and no system profile found. \
                 Cannot restore decoy configuration."
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn run_deactivation(&mut self, kind: ManagerDeactivationKind) -> Result<DeactivationReport> {
        // The emergency panic button must work from every state, not only a
        // clean Active one: the state is Activating during the whole switch, it
        // is Deactivating after an interrupted teardown, and it may be a corrupt
        // or unreadable file. Only a state that is *verifiably* clean Active
        // (readable file, Active state) takes the fast trusted path with its
        // recorded overlay list; every other emergency enumerates the NAILS
        // overlays from the live mount table instead. Normal deactivation still
        // requires a trustworthy Active state.
        let untrusted_state = kind.always_untrusted()
            || (kind == ManagerDeactivationKind::Emergency
                && !self
                    .current_state_with_outcome()
                    .map(|(state, outcome)| {
                        !outcome.is_unknown() && matches!(state, SystemState::Active { .. })
                    })
                    .unwrap_or(false));

        if !untrusted_state {
            // Preconditions: both modes require an Active system; only the messages differ.
            let state = self.current_state()?;
            if !matches!(state, SystemState::Active { .. }) {
                let message = match kind {
                    // Recover is always untrusted, so this precondition block is
                    // never reached for it; the arm exists only for exhaustiveness.
                    ManagerDeactivationKind::Normal | ManagerDeactivationKind::Recover => {
                        "Cannot deactivate: system is not in Active state".to_string()
                    }
                    ManagerDeactivationKind::Emergency if state == SystemState::Inactive => {
                        "Cannot deactivate from state Inactive. Must be ACTIVE.".to_string()
                    }
                    ManagerDeactivationKind::Emergency => {
                        format!("Cannot deactivate from state {:?}. Must be ACTIVE.", state)
                    }
                };
                return Err(NailsError::InvalidState(message));
            }
        }

        // A state-independent teardown (emergency from a non-Active state, or
        // recovery) must not disturb a system that is already the decoy: with no
        // NAILS mount live and the state Inactive there is nothing to tear down,
        // so skip the shell kill, the forced state write and the service restarts
        // entirely and report a clean no-op.
        if untrusted_state {
            let hidden_root = self.config().hidden_volume_root.clone();
            let discovered = self
                .filesystem()
                .discover_nails_mounts(Some(&hidden_root))?;
            let already_inactive = self
                .current_state()
                .map(|state| state == SystemState::Inactive)
                .unwrap_or(false);
            if discovered.owned_mount_points().is_empty() && already_inactive {
                tracing::info!(
                    "Nothing to tear down: no live NAILS mounts and the state is Inactive"
                );
                return Ok(DeactivationReport {
                    cleanup_report: CleanupReport::default(),
                    unmounted_overlays: Vec::new(),
                    failed_overlays: Vec::new(),
                    remaining_mounts: Vec::new(),
                    duration: std::time::Duration::ZERO,
                    final_state: SystemState::Inactive,
                    was_already_inactive: true,
                    force_detached_overlays: Vec::new(),
                    page_cache_dropped: false,
                    runtime_journal_scrubbed: false,
                    reboot_recommended: false,
                    state_write_errors: Vec::new(),
                });
            }
        }

        // Emergency/recover: quiet a still-running activation owner before the
        // first unmount so a stale writer cannot re-dirty the overlays mid-
        // teardown. Try-lock only — it never blocks the panic button.
        self.signal_owner_pid_before_teardown(kind);

        // A swap device that reappeared while the hidden session ran would have
        // paged memory to the decoy disk; surface it before teardown. Skipped in
        // emergency mode, which must stay fast and best-effort. The same Normal-only
        // pre-teardown block refuses up front if the decoy could not be restored
        // afterwards, while the Active session is still intact.
        if kind == ManagerDeactivationKind::Normal {
            let hidden_root = self.config().hidden_volume_root.clone();
            self.recheck_swap_posture("before deactivation", &hidden_root);
            self.ensure_decoy_restore_possible()?;
        }

        let overlay_context = if untrusted_state {
            overlay_context_from_mounts(self)?
        } else {
            inspect_overlay_context(self)?
        };

        if overlay_context.nix_was_overlaid {
            // Emergency does not wait for nix-daemon to stop: the overlay-rooted
            // kill below stops (stop job first) and kills any daemon still using
            // the /nix overlay, and the unmounts fall back to a lazy detach, so
            // the overlays never wait on it.
            if kind != ManagerDeactivationKind::Emergency {
                tracing::info!("Stopping nix-daemon before /nix overlay unmount...");
                let _ = crate::manager::helpers::ServiceController::stop_nix_daemon();
            }

            tracing::info!("Unmounting /nix/store bind mount...");
            // Best-effort: a failure here must not short-circuit the teardown
            // before the service restart below, which would otherwise leave the
            // decoy without a nix-daemon. The /nix overlay unmount in the
            // orchestrator surfaces any remaining problem.
            if let Err(graceful_error) = self.filesystem.unmount(Path::new("/nix/store"), false) {
                tracing::warn!(
                    error = %graceful_error,
                    "Graceful /nix/store unmount failed, trying force unmount"
                );
                if let Err(force_error) = self.filesystem.unmount(Path::new("/nix/store"), true) {
                    tracing::warn!(
                        error = %force_error,
                        "Force /nix/store unmount failed; continuing to overlay teardown and service restart"
                    );
                }
            }

            // When activation had to bind /nix/store read-only in PID 1's mount
            // namespace as well (an invocation preflight normally refuses), the
            // manager-namespace unmount above cannot reach that bind. Undo exactly
            // the bind activation recorded; best-effort so a failure never leaves
            // the decoy without nix-daemon.
            if overlay_context.nix_store_init_namespace_bound
                && !crate::runtime_safety::should_skip_host_interaction()
                && let Err(e) = Self::teardown_nix_store_init_namespace_bind()
            {
                tracing::warn!(
                    error = %e,
                    "Best-effort init-namespace /nix/store unmount failed; continuing to overlay teardown and service restart"
                );
            }
        }

        // Emergency only: before the overlays come down, stop the service units the
        // hidden configuration added and signal any process still writing to the
        // decoy through an overlay target. It never logs the operator out and never
        // touches the display manager or X server — the desktop must look unchanged
        // while the overlays are detached underneath it (lazily where a process
        // holds a path busy).
        self.prepare_emergency_pre_unmount_cleanup(kind);

        let cleanup_config = build_cleanup_config(self);

        #[cfg(not(test))]
        if should_skip_shell_cleanup_before_deactivation_gate(self.runtime_env()) {
            tracing::info!(
                "Skipping pre-unmount shell cleanup because the deactivation test gate is armed"
            );
        } else {
            tracing::info!(
                "Killing every interactive shell (including root's) immediately before overlay teardown"
            );
            let protected = process_teardown::collect_protected_shell_pids(self.runtime_env());
            // Teardown kills root's decoy shell too, so its in-memory history is
            // never flushed; only the teardown's own invocation stays protected —
            // its ancestry plus any sibling sharing its session or process group,
            // such as the pipe reader capturing this command's output — and the
            // deactivation detach means the invoking shell is torn down with the
            // rest rather than permanently spared.
            let report = kill_shells_for_teardown(&protected, self.runtime_env());
            tracing::info!(
                killed = report.killed.len(),
                failed = report.failed.len(),
                skipped = report.skipped.len(),
                "Shell cleanup complete"
            );
        }

        let restore_decoy_profile = requires_decoy_restore(self)?;
        let orchestrator = DeactivationOrchestrator::new(cleanup_config)
            .with_mode(kind.orchestrator_mode())
            .with_decoy_profile_restore(restore_decoy_profile)
            .with_untrusted_state(untrusted_state);

        // Return write access to the decoy OS trees and undo the submount
        // attachments before the overlays they sit on come down (the orchestrator
        // unmounts the parent overlays below). Only now, after the writer kill and
        // the shell kill: lifting a read-only guard while a hidden-session writer
        // still runs would let it write to the decoy tree in the meantime.
        self.teardown_overlay_dependents(&overlay_context);

        Self::relinquish_journal_before_unmount(&overlay_context);

        let result = orchestrator.run(self);

        // Restart services on every exit path, after /nix and /var have been
        // unmounted (the orchestrator ran above), never before — so a failed
        // teardown never leaves the decoy without nix-daemon or journald.
        if overlay_context.nix_was_overlaid {
            tracing::info!("Restarting nix-daemon...");
            start_service_and_socket("nix-daemon");
        }
        if overlay_context.var_was_overlaid {
            tracing::info!("Restarting systemd-journald...");
            // A real restart, not a start: after the /var overlay is torn down
            // journald is still running with its fds on the (now unmounted)
            // overlay, so a plain start is a no-op that leaves it detached from the
            // base journal. Restarting forces it to reopen on the decoy's /var.
            restart_service_and_socket("systemd-journald");
        }

        // Stop the in-session backend watcher and remove the RAM-backed runtime
        // copy on every teardown path. Runs before the orchestrator result is
        // unwrapped so the watcher never outlives the overlays even when the
        // teardown reported a problem.
        self.teardown_backend_runtime_copy();

        let mut report = match result {
            Ok(report) => report,
            Err(error) => {
                // A teardown that failed after detaching overlays (incomplete, or a
                // late error) still scrubs the RAM-backed state: the runtime journal,
                // the pivot staging and runtime root, and the page cache. One that
                // failed before any unmount rolled back to Active and keeps running,
                // so nothing is scrubbed from under the live session.
                if !matches!(self.current_state(), Ok(SystemState::Active { .. })) {
                    orchestrator.cleanup_after_failed_teardown(self);
                    let mut scratch = DeactivationReport::default();
                    self.scrub_runtime_journal_and_warn(&overlay_context, kind, &mut scratch);
                }
                return Err(error);
            }
        };

        self.scrub_runtime_journal_and_warn(&overlay_context, kind, &mut report);

        // After the unmount every history file and temp entry a cleanup could
        // reach is on the decoy, and editing or even reading one would leave
        // fresh timestamps there. So no teardown kind writes to (or reads from)
        // any decoy filesystem after the unmount: decoy-history hygiene belongs
        // to the pre-activation cleanup, the pre-teardown shell kill stops a
        // shell from flushing its history, and hidden-session shells keep no
        // history file. Only RAM-backed state (the runtime journal, the page
        // cache, the per-activation runtime root) is scrubbed here.

        // Record the post-teardown self-check on the hidden volume before the
        // reboot. At this point the decoy configuration is restored and the
        // overlays are unmounted, yet the hidden volume is still attached and
        // writable (the state file was just written to it), so this is the last
        // moment the report can land on the hidden root. It is written only on a
        // standard deactivation that reboots, only after a real teardown, and only
        // ever to the hidden volume — never to the decoy. Best-effort: a write
        // failure is logged and the reboot proceeds.
        self.write_last_deactivation_report_before_reboot(kind, &report);

        if kind.reboots_on_success() {
            if self.verbosity() >= crate::verbosity::Verbosity::Normal {
                tracing::info!("Rebooting system...");
            }

            // The reboot step is always reached: the runtime-safety skip now lives
            // inside `HostEffects::Real` (a compile-time `false` in shipped builds)
            // rather than wrapping this call, so a `Simulated` dispatcher can
            // observe the request and a guard that refuses surfaces as an error
            // here instead of being silently swallowed.
            let host_effects = self.host_effects.clone();
            let _outcome = host_effects.reboot_into_decoy(self.filesystem(), self.runtime_env())?;
        }

        Ok(report)
    }

    /// Hand the persistent journal back to volatile storage before `/var` is
    /// unmounted, mirroring activation.
    ///
    /// `journalctl --relinquish-var` makes journald stop writing to the on-overlay
    /// `/var/log/journal`, so no further hidden-session records land there between
    /// here and the unmount. Best-effort — a host without a persistent journal has
    /// nothing to relinquish. Only when `/var` was overlaid; otherwise journald is
    /// already on the decoy's own `/var` and must not be disturbed.
    fn relinquish_journal_before_unmount(overlay_context: &OverlayContext) {
        if overlay_context.var_was_overlaid
            && let Err(e) = crate::manager::helpers::ServiceController::relinquish_journal_var()
        {
            tracing::warn!(error = %e, "journalctl --relinquish-var before /var unmount failed");
        }
    }

    /// Scrub the volatile runtime journal after unmount and warn when no reboot
    /// follows.
    ///
    /// journald's volatile store at `/run/log/journal` holds the hidden session's
    /// records in RAM; `/run` is never overlaid, so without this they survive an
    /// emergency teardown (which does not reboot). Runs on every teardown — a
    /// volatile-journal decoy keeps its records here whether or not `/var` was
    /// overlaid, and the scrub only ever touches `/run/log/journal`, never the
    /// decoy's persistent journal: rotate first so journald closes the active
    /// runtime files, then remove them. A teardown that does not reboot on its own
    /// (emergency, recovery) also raises an honest warning that only a full
    /// power-off clears kernel and RAM residue.
    fn scrub_runtime_journal_and_warn(
        &self,
        _overlay_context: &OverlayContext,
        kind: ManagerDeactivationKind,
        report: &mut DeactivationReport,
    ) {
        // The runtime journal (`/run/log/journal`) is RAM-backed and is never one
        // of the overlay targets, so the hidden session's records land there
        // regardless of whether `/var` was overlaid — and on a volatile-journal
        // decoy (`journald` Storage=volatile) it is the only place they land.
        // Scrub it on every teardown, not just when `/var` was overlaid; it only
        // ever removes `/run/log/journal`, never the decoy's persistent journal.
        if let Err(e) = crate::manager::helpers::ServiceController::rotate_journal() {
            tracing::warn!(error = %e, "journalctl --rotate before runtime journal scrub failed");
        }
        let scrubber = CleanupManager::new(
            self.filesystem.clone(),
            CleanupConfig::default(),
            CleanupMode::default(),
        );
        scrubber.scrub_runtime_journal(&mut report.cleanup_report);
        report.runtime_journal_scrubbed = true;

        if !kind.reboots_on_success() {
            report.reboot_recommended = true;
            tracing::warn!(
                "Teardown complete without a reboot: the runtime journal was scrubbed, but \
                 only a full reboot clears all kernel and RAM residue of the hidden session"
            );
        }
    }

    /// Write the post-teardown self-check report to the hidden volume before the
    /// reboot.
    ///
    /// Runs only for a standard deactivation (the kind that reboots) and only
    /// after a genuine teardown: an already-inactive no-op has nothing to report
    /// and may not even have the hidden volume attached. The report always lands
    /// on the hidden volume through the symlink-safe hidden-file API; nothing is
    /// ever written to the decoy. A write failure is logged and the teardown
    /// continues — the report is a convenience for the next `status`, not a gate
    /// on returning to the decoy.
    fn write_last_deactivation_report_before_reboot(
        &self,
        kind: ManagerDeactivationKind,
        report: &DeactivationReport,
    ) {
        if !kind.reboots_on_success() || report.was_already_inactive {
            return;
        }

        let hidden_root = self.config().hidden_volume_root.clone();
        if hidden_root.as_os_str().is_empty() {
            return;
        }

        let generated_at = chrono::Utc::now().to_rfc3339();
        let summary =
            crate::deactivation::LastDeactivationReport::from_report(report, generated_at);
        match crate::deactivation::write_last_deactivation_report(
            self.filesystem(),
            &hidden_root,
            &summary,
        ) {
            Ok(path) => {
                tracing::info!(path = %path.display(), "Wrote post-deactivation self-check report");
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Could not write the post-deactivation self-check report; continuing to reboot"
                );
            }
        }
    }

    /// Deactivate NAILS, restoring the decoy configuration, then reboot.
    pub fn deactivate(&mut self) -> Result<DeactivationReport> {
        self.run_deactivation(ManagerDeactivationKind::Normal)
    }

    /// Emergency deactivation: fast, best-effort teardown without a reboot.
    ///
    /// Returns the [`DeactivationReport`] so the caller can surface an honest
    /// account of what was detached (including overlays that needed the forced
    /// detach), what cleanup did, whether the page cache was dropped, and the
    /// history-verification result, rather than a fixed success string.
    pub fn emergency_deactivate(&mut self) -> Result<DeactivationReport> {
        self.run_deactivation(ManagerDeactivationKind::Emergency)
    }

    /// Run the operator's post-teardown power request (`--poweroff`/`--reboot`).
    ///
    /// Dispatched through the same host-effects seam as the deactivation reboot,
    /// so it is skipped in runtime-safety mode and observable in tests. Returns
    /// `true` when a power command was actually dispatched, `false` when it was
    /// skipped (runtime-safety mode). Powering off or rebooting is the only way to
    /// clear RAM, so it is offered after the teardown finishes, never before.
    pub fn run_post_teardown_power(&self, action: PostTeardownPower) -> Result<bool> {
        let host_effects = self.host_effects.clone();
        Ok(matches!(
            host_effects.run_post_teardown_power(action, self.runtime_env())?,
            reboot::PowerDispatch::Dispatched
        ))
    }

    /// Reconcile the recorded state against the live mount table and finish an
    /// interrupted, degraded, or corrupt-state teardown.
    ///
    /// Unlike [`deactivate`](Self::deactivate), recovery never requires an Active
    /// state and never reboots: it exists to clean up after a crash, a killed
    /// activation/deactivation, or a state file that can no longer be trusted. It
    /// discovers the NAILS-owned mounts from the live mount table, tears them
    /// down with the same engine emergency uses (no countdown), and resets the
    /// state to Inactive. A corrupt or unreadable state file is backed up to
    /// `state.json.bad` before the recovery overwrites it.
    ///
    /// Returns a [`RecoverOutcome`] describing what it found and did. A cleanly
    /// inactive system with no live NAILS mount is a no-op that reports
    /// [`RecoverOutcome::was_already_inactive`].
    pub fn recover(&mut self) -> Result<RecoverOutcome> {
        // Reconcile first so a cleanly inactive system is a quiet no-op rather
        // than a teardown that discovers nothing and still rewrites the state.
        let effective = self.reconcile_state()?;
        if matches!(effective, crate::state::EffectiveState::Inactive) {
            tracing::info!("Recover: system already inactive with no live NAILS mounts");
            return Ok(RecoverOutcome {
                state_backed_up: None,
                was_already_inactive: true,
            });
        }

        // Preserve a corrupt/unreadable state file before the teardown replaces
        // it, so an operator can still inspect what was recorded.
        let state_backed_up = self.backup_corrupt_state_file()?;

        tracing::info!(
            ?effective,
            backed_up = state_backed_up.is_some(),
            "Recover: reconciling and tearing down remaining NAILS mounts"
        );

        self.run_deactivation(ManagerDeactivationKind::Recover)?;

        Ok(RecoverOutcome {
            state_backed_up,
            was_already_inactive: false,
        })
    }

    /// Copy a corrupt or unreadable state file to `state.json.bad`, returning the
    /// backup path when one was made.
    ///
    /// Only a state file whose load outcome is unknown (unparseable, or a
    /// checksum mismatch) is backed up; a readable file is left in place for the
    /// teardown to update. A missing file, or any copy error, is a best-effort
    /// no-op: recovery must never fail because the broken file could not be copied
    /// aside. The copy uses `std::fs` directly, matching how the state file itself
    /// is loaded and saved (it is always a real-filesystem artifact on the hidden
    /// root, never a trait-abstracted mock path).
    fn backup_corrupt_state_file(&self) -> Result<Option<PathBuf>> {
        let (_, outcome) = match self.current_state_with_outcome() {
            Ok(pair) => pair,
            Err(_) => return Ok(None),
        };
        if !outcome.is_unknown() {
            return Ok(None);
        }

        if !self.state_file_path.exists() {
            return Ok(None);
        }

        let backup_path = {
            let mut name = self
                .state_file_path
                .file_name()
                .unwrap_or_default()
                .to_os_string();
            name.push(".bad");
            self.state_file_path.with_file_name(name)
        };

        match std::fs::copy(&self.state_file_path, &backup_path) {
            Ok(_) => {
                tracing::warn!(
                    path = %backup_path.display(),
                    "Recover: backed up corrupt state file"
                );
                Ok(Some(backup_path))
            }
            Err(e) => {
                tracing::warn!(error = %e, "Recover: could not copy corrupt state file aside (continuing)");
                Ok(None)
            }
        }
    }
}

/// What [`NailsManager::recover`](NailsManager::recover) found and did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverOutcome {
    /// Where a corrupt state file was backed up, if one was found.
    pub state_backed_up: Option<PathBuf>,
    /// True when the system was already cleanly inactive, so recovery did nothing.
    pub was_already_inactive: bool,
}

#[cfg(test)]
#[path = "deactivation_tests.rs"]
mod tests;
