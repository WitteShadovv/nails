// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Emergency teardown: the hot path in `nails-teardown`, then the bookkeeping.
//!
//! The hot path (stop jobs, `cgroup.kill`, the shell kill, the plan's undo and
//! the reconcile) runs in [`nails_teardown::emergency`]. The CLI runs it from
//! `main` before clap, the configuration and tracing exist, and hands the
//! report to [`NailsManager::finish_emergency`]; the in-process callers (the
//! backend watcher and the sleep guard) run both through
//! [`NailsManager::emergency_deactivate`].
//!
//! The bookkeeping only ever touches RAM-backed state and the hidden volume:
//! it replays what the hot path did into the log, repoints
//! `/run/current-system`, drops the page cache, records the outcome in the
//! state file (tolerating a dead or read-only backend), restarts journald and
//! nix-daemon on the decoy's own `/var` and `/nix`, removes the runtime copy,
//! and scrubs the runtime journal. Nothing is written to a decoy filesystem.

use super::decoy::{
    recorded_decoy_system, recorded_hidden_toplevel, restore_decoy_current_system,
    restore_hidden_current_system,
};
use super::{ManagerDeactivationKind, restart_service_and_socket, start_service_and_socket};
use crate::deactivation::DeactivationReport;
use crate::manager::teardown_plan::{FsMountOps, detached_overlays, log_undo};
use crate::{
    CleanupMode, CleanupReport, Filesystem, NailsError, NailsManager, Result, SystemState,
};
use nails_teardown::{Host, HotReport, PlanSource};
use std::path::{Path, PathBuf};

/// System services whose processes the emergency kill never touches, and
/// further pids it spares, named by the end-to-end harness through its
/// test-hooks knobs (the shell-cleanup protected services and pids). Shipped
/// builds spare nothing beyond the teardown's own invocation.
#[cfg(feature = "test-hooks")]
pub fn harness_spares(env: &crate::RuntimeEnv) -> (Vec<String>, Vec<u32>) {
    let units = env
        .test_hooks
        .shell_cleanup_protected_services
        .as_deref()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(|name| {
                    if name.contains('.') {
                        name.to_string()
                    } else {
                        format!("{name}.service")
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let pids = env
        .test_hooks
        .shell_cleanup_protected_pids
        .as_deref()
        .map(|value| {
            value
                .to_string_lossy()
                .split(',')
                .filter_map(|pid| pid.trim().parse().ok())
                .collect()
        })
        .unwrap_or_default();
    (units, pids)
}

/// Shipped builds spare nothing beyond the teardown's own invocation.
#[cfg(not(feature = "test-hooks"))]
pub fn harness_spares(_env: &crate::RuntimeEnv) -> (Vec<String>, Vec<u32>) {
    (Vec::new(), Vec::new())
}

impl<F: Filesystem> NailsManager<F> {
    /// Emergency deactivation: the hot path, then the bookkeeping, without a
    /// reboot. Used by the in-process callers; the CLI runs the hot path itself
    /// before anything else and calls [`finish_emergency`](Self::finish_emergency).
    ///
    /// Returns the [`DeactivationReport`] so the caller can give an honest
    /// account of what was detached (including what needed the lazy detach),
    /// whether the page cache was dropped and what could not be recorded.
    pub fn emergency_deactivate(&mut self) -> Result<DeactivationReport> {
        let hot = self.emergency_hot_path();
        self.finish_emergency(hot)
    }

    /// The host the hot path may act on, for `plan`: its recorded tools (or
    /// the ones resolved now) and the harness's spares in a test-hooks build.
    pub fn teardown_host(&self, plan: &nails_teardown::Plan) -> Host {
        let mut host = Host::system(plan);
        let tools = crate::manager::teardown_plan::teardown_tools();
        host.systemctl = host.systemctl.or(tools.systemctl);
        host.journalctl = host.journalctl.or(tools.journalctl);
        let (units, pids) = harness_spares(self.runtime_env());
        host.spared_units = units;
        host.protected_pids = pids;
        host
    }

    /// Run the hot path in this process, through the manager's filesystem. The
    /// kills are skipped in the runtime-safety mode, where only the plan's
    /// mounts are undone (against the mock filesystem in the unit tests).
    fn emergency_hot_path(&self) -> HotReport {
        let trusted = self
            .current_state_with_outcome()
            .is_ok_and(|(state, outcome)| {
                !outcome.is_unknown() && matches!(state, SystemState::Active { .. })
            });
        let (plan, source) = self.plan_for_teardown(trusted);
        // A system that is already the decoy (nothing recorded, no NAILS mount
        // live, a readable Inactive state) is left undisturbed: no kill runs.
        let idle = plan.steps.is_empty()
            && self
                .filesystem
                .discover_nails_mounts(Some(&plan.hidden_root))
                .is_ok_and(|m| m.owned_mount_points().is_empty())
            && self
                .current_state_with_outcome()
                .is_ok_and(|(state, outcome)| {
                    !outcome.is_unknown() && state == SystemState::Inactive
                });
        let mut host = (!idle && !crate::runtime_safety::should_skip_host_interaction())
            .then(|| self.teardown_host(&plan));
        // A plan rebuilt without the activation records no owner; the state
        // file names it (when the hidden volume can still be read).
        if host.is_some() && plan.owner.is_none() {
            self.signal_owner_pid_before_teardown(super::ManagerDeactivationKind::Emergency);
        }
        // Hand the journal back to /run before /var comes down. In this process
        // the service controller does it (and the unit tests observe it there),
        // so the hot path is not asked to do it again.
        let var_overlaid = plan.overlays(Path::new("/var"))
            || self
                .filesystem
                .discover_nails_mounts(Some(&plan.hidden_root))
                .is_ok_and(|m| {
                    m.persistent_overlays
                        .iter()
                        .chain(&m.ephemeral_overlays)
                        .any(|p| p == Path::new("/var"))
                });
        if var_overlaid {
            if let Some(host) = host.as_mut() {
                host.journalctl = None;
            }
            if let Err(e) = crate::manager::helpers::ServiceController::relinquish_journal_var() {
                tracing::warn!(error = %e, "journalctl --relinquish-var before /var unmount failed");
            }
        }
        let ops = FsMountOps::for_plan(&self.filesystem, &plan);
        nails_teardown::emergency::run(&ops, plan, source, host.as_ref())
    }

    /// Finish an emergency teardown whose hot path already ran: the bookkeeping
    /// (see the module docs), in an order that keeps every log line of the
    /// teardown in the runtime journal the scrub then removes.
    ///
    /// # Errors
    ///
    /// [`NailsError::DeactivationIncomplete`] when a NAILS mount survived (the
    /// state is then `Degraded`), or the decoy-restore error of a trusted
    /// teardown. The RAM-backed scrub runs either way.
    pub fn finish_emergency(&mut self, hot: HotReport) -> Result<DeactivationReport> {
        // Load the cache: the decoy and hidden systems recorded at activation
        // are read from it (a corrupt file loads as the safe default).
        let _ = self.current_state();
        let state = self.current_state_with_outcome();
        let readable = |s: &SystemState| {
            state
                .as_ref()
                .is_ok_and(|(state, outcome)| !outcome.is_unknown() && state == s)
        };
        let trusted = state.as_ref().is_ok_and(|(state, outcome)| {
            !outcome.is_unknown() && matches!(state, SystemState::Active { .. })
        });
        if hot.found_nothing() && readable(&SystemState::Inactive) {
            tracing::info!("Nothing to tear down: no live NAILS mounts and the state is Inactive");
            return Ok(DeactivationReport {
                final_state: SystemState::Inactive,
                was_already_inactive: true,
                ..DeactivationReport::default()
            });
        }
        if let Some(PlanSource::Derived(why)) = &hot.source {
            tracing::warn!(
                reason = %why,
                "No usable teardown plan; tore down the NAILS mounts found in the live mount table"
            );
        }
        self.log_hot_path(&hot);

        let (unmounted, forced) = detached_overlays(&hot.undo);
        let mut cleanup_report = CleanupReport::new(CleanupMode::Fast);
        let restore_error = self.restore_current_system_after_emergency(
            trusted,
            &hot.remaining,
            &mut cleanup_report,
        )?;
        let page_cache_dropped = self.drop_page_cache();

        let mut state_write_errors = Vec::new();
        let final_state = if hot.remaining.is_empty() {
            SystemState::Inactive
        } else {
            SystemState::Degraded {
                since: chrono::Utc::now(),
                reason: format!(
                    "emergency teardown left {} NAILS mount(s) live: {}",
                    hot.remaining.len(),
                    display_list(&hot.remaining)
                ),
                remaining_mounts: hot.remaining.clone(),
            }
        };
        self.persist_teardown_outcome(final_state.clone(), &mut state_write_errors);
        if hot.remaining.is_empty() {
            tracing::info!(
                duration_ms = hot.elapsed.as_millis() as u64,
                state_to = ?SystemState::Inactive,
                unmounted_count = unmounted.len(),
                "Deactivation complete"
            );
        } else {
            tracing::error!(
                remaining = %display_list(&hot.remaining),
                phase = "unmount",
                state_to = "Degraded",
                "Teardown incomplete; recording DEGRADED (no remount, no return to ACTIVE)"
            );
        }

        // journald and nix-daemon come back on the decoy's own /var and /nix
        // only now, after every line above went to the relinquished runtime
        // journal that the scrub below removes.
        if hot.nix_overlaid {
            tracing::info!("Restarting nix-daemon...");
            start_service_and_socket("nix-daemon");
        }
        if hot.var_overlaid {
            tracing::info!("Restarting systemd-journald...");
            restart_service_and_socket("systemd-journald");
        }
        self.teardown_backend_runtime_copy();

        let mut report = DeactivationReport {
            cleanup_report,
            unmounted_overlays: unmounted,
            failed_overlays: hot
                .undo
                .failures()
                .into_iter()
                .map(|(p, _)| p.display().to_string())
                .collect(),
            remaining_mounts: hot.remaining.clone(),
            duration: hot.elapsed,
            final_state,
            was_already_inactive: false,
            force_detached_overlays: forced,
            page_cache_dropped,
            runtime_journal_scrubbed: false,
            reboot_recommended: false,
            state_write_errors,
        };
        self.scrub_runtime_journal_and_warn(ManagerDeactivationKind::Emergency, &mut report);

        if !hot.remaining.is_empty() {
            return Err(NailsError::DeactivationIncomplete {
                remaining_mounts: hot.remaining,
            });
        }
        if let Some(error) = restore_error {
            return Err(error);
        }
        Ok(report)
    }

    /// Log what the hot path did, now that a subscriber exists.
    fn log_hot_path(&self, hot: &HotReport) {
        if !hot.units_stopped.is_empty() {
            tracing::info!(
                units = ?hot.units_stopped,
                enqueued = ?hot.stop_enqueued,
                "Enqueued stop jobs before the kill so Restart= cannot revive them"
            );
        }
        if !hot.cgroups_killed.is_empty() {
            tracing::info!(cgroups = ?hot.cgroups_killed, "Killed the cgroups pinning the overlays");
        }
        if !hot.processes_killed.is_empty() {
            tracing::info!(pids = ?hot.processes_killed, "Killed overlay-rooted processes");
        }
        if hot.session_processes_spared > 0 {
            tracing::info!(
                spared = hot.session_processes_spared,
                "Spared processes belonging to the operator's graphical session from the overlay-rooted kill"
            );
        }
        if !hot.shells_killed.is_empty() {
            tracing::info!(
                killed = hot.shells_killed.len(),
                "Killed every interactive shell before the overlay teardown"
            );
        }
        if !hot.cgroups_still_populated.is_empty() || !hot.processes_still_alive.is_empty() {
            tracing::warn!(
                cgroups = ?hot.cgroups_still_populated,
                pids = ?hot.processes_still_alive,
                "Some killed processes had not exited when the unmounts began"
            );
        }
        if hot.journal_relinquished == Some(false) {
            tracing::warn!("journalctl --relinquish-var before the /var unmount failed");
        }
        log_undo(&hot.undo);
    }

    /// Repoint `/run/current-system` after the teardown: at the recorded decoy
    /// on a clean trusted teardown (a failure is returned, the state still ends
    /// Inactive), otherwise only away from a hidden system it still names.
    fn restore_current_system_after_emergency(
        &self,
        trusted: bool,
        remaining: &[PathBuf],
        cleanup_report: &mut CleanupReport,
    ) -> Result<Option<NailsError>> {
        let recorded_decoy = recorded_decoy_system(self);
        if trusted && remaining.is_empty() {
            if !super::decoy::requires_decoy_restore(self).unwrap_or(false) {
                return Ok(None);
            }
            // A failed lookup is reported like a failed swap: the rest of the
            // bookkeeping (state, service restarts, scrub) runs either way.
            return Ok(restore_decoy_current_system(
                self.filesystem(),
                recorded_decoy.as_deref(),
                self.runtime_env(),
            )
            .unwrap_or_else(Some));
        }
        if let Some(failure) = restore_hidden_current_system(
            self.filesystem(),
            recorded_decoy.as_deref(),
            recorded_hidden_toplevel(self).as_deref(),
            self.runtime_env(),
        ) {
            cleanup_report.add_error(failure);
        }
        Ok(None)
    }

    /// Drop the page cache after the unmount (best-effort): it frees clean
    /// cached pages that may still hold decoded hidden data. It zeroes nothing.
    pub(crate) fn drop_page_cache(&self) -> bool {
        match self
            .filesystem()
            .write_kernel_tunable(Path::new("/proc/sys/vm/drop_caches"), "3")
        {
            Ok(()) => {
                tracing::info!("page cache dropped");
                true
            }
            Err(e) => {
                tracing::warn!(error = %e, "Dropping the page cache after unmount failed (best-effort)");
                false
            }
        }
    }

    /// Record the teardown's outcome in the state file on the hidden volume,
    /// tolerating a dead, full or read-only backend: the failure is collected
    /// for the report and the teardown goes on. An unreadable state file is
    /// replaced by a valid one.
    fn persist_teardown_outcome(&mut self, state: SystemState, errors: &mut Vec<String>) {
        // Load the cache from disk when it can be read, so the write keeps the
        // recorded build metadata; a corrupt file loads as the safe default.
        let _ = self.current_state();
        if matches!(state, SystemState::Inactive) {
            let _ = self.clear_overlay_status_in_cache();
        }
        let written = if self.cached_state.borrow().is_some() {
            if let Some(cached) = self.cached_state.borrow_mut().as_mut() {
                cached.state = state.clone();
            }
            self.save_cached_state()
        } else {
            self.force_state(state)
        };
        if let Err(e) = written {
            tracing::warn!(
                error = %e,
                "Emergency could not persist the teardown state (the hidden backend is \
                 unavailable); the teardown continues"
            );
            errors.push(format!("final state: {e}"));
        }
    }
}

fn display_list(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}
