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
    CleanupConfig, CleanupManager, CleanupMode, Filesystem, NailsError, Result, SystemState,
};
use std::path::{Path, PathBuf};

mod decoy;
mod emergency;
mod orchestrator;
mod overlay_context;
mod process_teardown;
mod reboot;
mod unmount;

use decoy::{recorded_decoy_system, requires_decoy_restore};
pub use emergency::harness_spares;
pub use orchestrator::{DeactivationMode, DeactivationOrchestrator};
use overlay_context::{OverlayContext, inspect_overlay_context, overlay_context_from_mounts};
use process_teardown::{
    current_process_ancestry, is_own_invocation_process, owner_pid_to_signal, read_proc_cgroup,
    read_session_and_pgid, self_session_and_pgid,
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
        let session = nails_teardown::session::SpareSet::at_panic(
            &[],
            Path::new(nails_teardown::session::SESSIONS_DIR),
        );
        if read_proc_cgroup(pid).is_some_and(|cgroup| session.covers(&cgroup)) {
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

        let Some(owner) = crate::process::identity::ProcessHandle::open(pid) else {
            return;
        };
        tracing::info!(
            pid,
            "Signalling the recorded activation owner before teardown"
        );
        owner.signal(rustix::process::Signal::TERM);

        // Emergency keeps the wait short so the overlays come down within a few
        // seconds; recovery is no panic button and allows the owner longer.
        let wait = kind.owner_exit_wait();
        let deadline = std::time::Instant::now() + wait;
        while std::time::Instant::now() < deadline {
            if !owner.is_alive() {
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

    /// Undo the steps of `plan` in `phases` through the manager's filesystem,
    /// without the reconcile, and log what was done.
    fn undo_plan_phases(&self, plan: &nails_teardown::Plan, phases: &[nails_teardown::Phase]) {
        let ops = crate::manager::teardown_plan::FsMountOps::for_plan(&self.filesystem, plan);
        let report = nails_teardown::undo::run_plan(&ops, plan, phases, false);
        crate::manager::teardown_plan::log_undo(&report);
    }

    fn run_deactivation(&mut self, kind: ManagerDeactivationKind) -> Result<DeactivationReport> {
        // Normal deactivation requires a trustworthy Active state and tears
        // down from the recorded plan. Recovery never trusts the state and
        // rebuilds the plan from the live mount table when none is recorded.
        let untrusted_state = kind.always_untrusted();

        if !untrusted_state {
            let state = self.current_state()?;
            if !matches!(state, SystemState::Active { .. }) {
                return Err(NailsError::InvalidState(
                    "Cannot deactivate: system is not in Active state".to_string(),
                ));
            }
        }

        // Recovery must not disturb a system that is already the decoy: with no
        // NAILS mount live and the state Inactive there is nothing to tear down.
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
                    final_state: SystemState::Inactive,
                    was_already_inactive: true,
                    ..DeactivationReport::default()
                });
            }
        }

        // Recovery: quiet a still-running activation owner before the first
        // unmount so a stale writer cannot re-dirty the overlays mid-teardown.
        self.signal_owner_pid_before_teardown(kind);

        // A swap device that reappeared while the hidden session ran would have
        // paged memory to the decoy disk; surface it before teardown. The same
        // Normal-only block refuses up front if the decoy could not be restored
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

        // The plan activation recorded, or the one the state file (or, for
        // recovery, the mount table) implies when no plan file is left.
        let (plan, source) = self.plan_for_teardown(!untrusted_state);
        if let nails_teardown::PlanSource::Derived(why) = &source {
            tracing::info!(reason = %why, "Tearing down from a rebuilt teardown plan");
        }

        if overlay_context.nix_was_overlaid {
            tracing::info!("Stopping nix-daemon before /nix overlay unmount...");
            let _ = crate::manager::helpers::ServiceController::stop_nix_daemon();
        }
        // The /nix/store binds (in this namespace and, when activation had to
        // make one there, in PID 1's) come off before the shell kill, as they
        // always have. Best-effort: the orchestrator's unmount surfaces anything
        // that remains, and nix-daemon is restarted below on every path.
        self.undo_plan_phases(&plan, &[nails_teardown::Phase::Store]);

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
            // such as the pipe reader capturing this command's output.
            let report = kill_shells_for_teardown(&protected, self.runtime_env());
            tracing::info!(
                killed = report.killed.len(),
                failed = report.failed.len(),
                skipped = report.skipped.len(),
                "Shell cleanup complete"
            );
        }

        let restore_decoy_profile = requires_decoy_restore(self)?;
        // Read before the teardown rewrites the state: the failed-reboot fallback
        // activates exactly this generation for the running session.
        let recorded_decoy = recorded_decoy_system(self);
        let orchestrator = DeactivationOrchestrator::new(cleanup_config)
            .with_mode(kind.orchestrator_mode())
            .with_decoy_profile_restore(restore_decoy_profile)
            .with_untrusted_state(untrusted_state)
            .with_plan(plan.clone());

        // Return write access to the decoy OS trees and undo the submount
        // attachments before the overlays they sit on come down. Only now,
        // after the shell kill: lifting a read-only guard while a hidden-session
        // writer still runs would let it write to the decoy tree in the meantime.
        self.undo_plan_phases(&plan, &[nails_teardown::Phase::Dependents]);

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
        // copy (and the plan with it) on every teardown path, except one that
        // failed before any unmount and left the session Active: that session
        // still needs its plan and its watcher.
        if !(result.is_err() && matches!(self.current_state(), Ok(SystemState::Active { .. }))) {
            self.teardown_backend_runtime_copy();
        }

        let mut report = match result {
            Ok(report) => report,
            Err(error) => {
                // A teardown that failed after detaching overlays still scrubs the
                // RAM-backed state; one that failed before any unmount rolled back
                // to Active and keeps running, so nothing is scrubbed from under
                // the live session.
                if !matches!(self.current_state(), Ok(SystemState::Active { .. })) {
                    orchestrator.cleanup_after_failed_teardown(self);
                    let mut scratch = DeactivationReport::default();
                    self.scrub_runtime_journal_and_warn(kind, &mut scratch);
                }
                return Err(error);
            }
        };

        self.scrub_runtime_journal_and_warn(kind, &mut report);

        // After the unmount every history file and temp entry a cleanup could
        // reach is on the decoy, and editing or even reading one would leave
        // fresh timestamps there. So no teardown kind writes to (or reads from)
        // any decoy filesystem after the unmount; only RAM-backed state (the
        // runtime journal, the page cache, the per-activation runtime root) is
        // scrubbed here.

        // Record the post-teardown self-check on the hidden volume before the
        // reboot, the last moment the report can land there. Only ever to the
        // hidden volume, never to the decoy; a write failure is logged.
        self.write_last_deactivation_report_before_reboot(kind, &report);

        if kind.reboots_on_success() {
            if self.verbosity() >= crate::verbosity::Verbosity::Normal {
                tracing::info!("Rebooting system...");
            }

            // The reboot step is always reached: the runtime-safety skip lives
            // inside `HostEffects::Real` rather than wrapping this call, so a
            // `Simulated` dispatcher can observe the request and a guard that
            // refuses surfaces as an error here instead of being swallowed.
            let host_effects = self.host_effects.clone();
            let _outcome = host_effects.reboot_into_decoy(
                self.filesystem(),
                recorded_decoy.as_deref(),
                self.runtime_env(),
                self.post_deactivation_power,
            )?;
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
    /// decoy's persistent journal: rotate first so journald archives the active
    /// runtime files, remove the journal files (never the directories journald
    /// rotates into), then rotate again so journald lets go of any file that was
    /// still open and continues in a fresh one. A teardown that does not reboot on
    /// its own (emergency, recovery) also raises an honest warning that only a
    /// full power-off clears kernel and RAM residue.
    fn scrub_runtime_journal_and_warn(
        &self,
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
        // A file journald still had open (the rotation above failed, or a record
        // arrived in between) is now unlinked but alive. Rotating again archives
        // it, freeing its memory once journald closes it, and opens the next file
        // in the directory the scrub kept.
        if let Err(e) = crate::manager::helpers::ServiceController::rotate_journal() {
            tracing::warn!(error = %e, "journalctl --rotate after runtime journal scrub failed");
        }
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
