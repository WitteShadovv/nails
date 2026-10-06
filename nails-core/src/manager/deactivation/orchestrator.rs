// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The single-layer deactivation sequence shared by every teardown path.

use super::decoy::{recorded_decoy_system, restore_decoy_current_system};
use super::unmount::{
    UnmountOutcome, discovered_unmount_targets, overlay_unmount_targets, remaining_nails_mounts,
};
use crate::cleanup::history::{history_cleanup_homes, truncate_all_history_files_for_homes};
use crate::deactivation::test_gate::maybe_block_after_deactivating_state_transition;
use crate::deactivation::{DeactivationReport, PostUnmountCleanupReport};
use crate::manager::NailsManager;
use crate::{
    CleanupConfig, CleanupManager, CleanupMode, CleanupReport, Filesystem, NailsError, Result,
    StateGuard, SystemState,
};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Controls deactivation behavior.
///
/// - `Normal`: Full cleanup with verification, rollback on cleanup errors.
///   Idempotent – returns `Ok` when the system is already inactive.
/// - `Emergency`: Fast cleanup (best-effort, non-fatal errors), skips
///   post-unmount cleanup. Fails if the system is not in `Active` state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeactivationMode {
    /// Run all steps including thorough cleanup with verification.
    Normal,
    /// Skip non-essential cleanup for speed; cleanup errors are non-fatal.
    Emergency,
}

/// Single-layer deactivation sequence.
///
/// Holds only the deactivation configuration; the manager is borrowed for the
/// duration of [`run`](DeactivationOrchestrator::run), which drives the whole
/// teardown against one [`StateGuard`]:
/// 1. State transition ACTIVE -> DEACTIVATING (guarded).
/// 2. Artifact cleanup (history, temp files, logs).
/// 3. Overlay unmounting in reverse LIFO order — every target is attempted.
/// 4. State transition DEACTIVATING -> INACTIVE.
/// 5. Decoy restore: re-point /run/current-system at the decoy profile (symlink
///    swap only — no `switch-to-configuration switch`, so the bootloader, ESP
///    and EFI NVRAM are never touched).
///
/// A failure in steps 1-2 (before any overlay is detached) rolls the state back
/// to ACTIVE on drop. Once step 3 has detached any overlay the teardown never
/// goes back: if some targets cannot be unmounted it records DEGRADED and
/// returns an error, and it never remounts what it has already detached (a
/// remount would route hidden-session writes onto the decoy disk).
pub struct DeactivationOrchestrator {
    cleanup_config: CleanupConfig,
    mode: DeactivationMode,
    restore_decoy_profile: bool,
    untrusted_state: bool,
}

impl DeactivationOrchestrator {
    /// Create a new orchestrator from a cleanup configuration.
    pub fn new(cleanup_config: CleanupConfig) -> Self {
        Self {
            cleanup_config,
            mode: DeactivationMode::Normal,
            restore_decoy_profile: true,
            untrusted_state: false,
        }
    }

    /// Set the deactivation mode (builder pattern).
    pub fn with_mode(mut self, mode: DeactivationMode) -> Self {
        self.mode = mode;
        self
    }

    /// Control whether the decoy profile restore path runs at all.
    pub fn with_decoy_profile_restore(mut self, restore_decoy_profile: bool) -> Self {
        self.restore_decoy_profile = restore_decoy_profile;
        self
    }

    /// Enumerate overlays from the live mount table instead of the state file.
    ///
    /// Set only by an emergency teardown that found the state file corrupt or
    /// unreadable: the recorded overlay list cannot be trusted, so the teardown
    /// discovers the NAILS-owned mounts directly. Normal deactivation leaves this
    /// `false` and keeps trusting the Active state's overlay list.
    pub fn with_untrusted_state(mut self, untrusted_state: bool) -> Self {
        self.untrusted_state = untrusted_state;
        self
    }

    /// Execute deactivation against the borrowed manager.
    ///
    /// Returns a [`DeactivationReport`] on success. On failure the state is
    /// either rolled back to ACTIVE (cleanup failed before any unmount), left
    /// INACTIVE (only the decoy restore failed), or recorded as DEGRADED with
    /// [`NailsError::DeactivationIncomplete`] (some overlays could not be
    /// unmounted) — never ACTIVE once any overlay has been detached.
    pub fn run<F: Filesystem>(&self, manager: &mut NailsManager<F>) -> Result<DeactivationReport> {
        let start = Instant::now();
        tracing::info!(phase = "deactivation", "Deactivation started");

        // When the state file is untrusted the recorded overlay list cannot be
        // read, so that teardown enumerates NAILS mounts from the live mount
        // table instead of the Active state's overlay list.
        if self.untrusted_state {
            self.run_from_untrusted_state(manager, start)
        } else {
            self.run_from_trusted_state(manager, start)
        }
    }

    /// Standard teardown driven by a trustworthy Active state and its recorded
    /// overlay list.
    /// Persist a teardown state transition, tolerating a write failure in an
    /// emergency.
    ///
    /// The state file lives on the hidden volume. A normal deactivation fails
    /// closed if it cannot be written, but emergency is the panic button: a dead
    /// or read-only backend must never stop it from detaching the overlays. In
    /// emergency mode a failed write is logged and the teardown continues (the
    /// in-memory cache still reflects the new state, so later reads keep working
    /// and the committed guard does not roll back to ACTIVE).
    fn persist_teardown_state_or_tolerate<F: Filesystem>(
        &self,
        guard: &mut StateGuard<'_, F>,
        new_state: SystemState,
        phase: &str,
    ) -> Result<()> {
        if let Err(e) = guard.update_state(new_state) {
            if self.mode != DeactivationMode::Emergency {
                return Err(e);
            }
            tracing::warn!(
                error = %e,
                phase,
                "Emergency could not persist the teardown state (the hidden backend is \
                 unavailable); the overlays are detached, so the teardown continues"
            );
        }
        Ok(())
    }

    fn run_from_trusted_state<F: Filesystem>(
        &self,
        manager: &mut NailsManager<F>,
        start: Instant,
    ) -> Result<DeactivationReport> {
        // Step 0: Check if already inactive (idempotent). Emergency mode refuses.
        let current_state = manager.current_state()?;
        if current_state == SystemState::Inactive {
            if self.mode == DeactivationMode::Emergency {
                return Err(NailsError::InvalidState(
                    "Cannot deactivate from state Inactive. Must be ACTIVE.".to_string(),
                ));
            }
            tracing::info!(
                state = ?current_state,
                already_inactive = true,
                "System already inactive, nothing to do"
            );
            return Ok(DeactivationReport {
                cleanup_report: CleanupReport::default(),
                unmounted_overlays: Vec::new(),
                failed_overlays: Vec::new(),
                remaining_mounts: Vec::new(),
                duration: start.elapsed(),
                final_state: SystemState::Inactive,
                was_already_inactive: true,
                post_unmount_cleanup: PostUnmountCleanupReport::default(),
                force_detached_overlays: Vec::new(),
                page_cache_dropped: false,
                history_truncation_verified: None,
                runtime_journal_scrubbed: false,
                reboot_recommended: false,
            });
        }

        if !current_state.is_active() {
            return Err(NailsError::InvalidState(format!(
                "Cannot deactivate from state {:?}. Must be ACTIVE.",
                current_state
            )));
        }

        // Extract overlays BEFORE transitioning away from ACTIVE.
        let overlays_to_unmount = overlay_unmount_targets(manager, &current_state)?;

        // The decoy system recorded at activation, read before the guard borrows
        // the manager mutably. Step 5 restores `/run/current-system` to it.
        let recorded_decoy = recorded_decoy_system(manager);

        // Step 1: Take the rollback guard and transition ACTIVE -> DEACTIVATING.
        let mut guard = StateGuard::new(&mut *manager, current_state.clone());
        let deactivating_state = SystemState::Deactivating {
            started_at: chrono::Utc::now(),
        };
        self.persist_teardown_state_or_tolerate(&mut guard, deactivating_state, "deactivating")?;
        maybe_block_after_deactivating_state_transition(guard.runtime_env())?;

        // The emergency and normal teardowns differ in order. Emergency detaches
        // the overlays FIRST — the one step that matters — then runs best-effort
        // cleanup and drops the page cache, so a stalled backend or a slow scrub
        // can never delay the unmount. Normal deactivation keeps the thorough
        // order: verify cleanup first (rolling back to ACTIVE if it fails) and
        // only then unmount.
        let cleanup_start = Instant::now();
        let unmount_start = Instant::now();
        let (cleanup_report, unmount_outcome, page_cache_dropped);

        if self.mode == DeactivationMode::Emergency {
            // Step 2 (emergency): detach every overlay first.
            let outcome = self.unmount_overlays(&guard, &overlays_to_unmount);
            guard =
                self.finish_or_degrade(guard, &overlays_to_unmount, "deactivation", &outcome)?;
            let unmounted = &outcome.unmounted;
            tracing::info!(
                unmounted_paths = ?unmounted,
                duration_ms = unmount_start.elapsed().as_millis() as u64,
                "Overlays unmounted"
            );

            // Step 3 (emergency): best-effort cleanup AFTER unmount.
            let report = match self.execute_emergency_cleanup(&guard) {
                Ok(report) => {
                    tracing::info!(
                        cleaned_items = report.cleaned_items.len(),
                        errors = report.errors.len(),
                        duration_ms = cleanup_start.elapsed().as_millis() as u64,
                        "Emergency cleanup complete (best-effort)"
                    );
                    report
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        phase = "cleanup",
                        "Emergency cleanup failed (non-fatal) - continuing deactivation"
                    );
                    CleanupReport::default()
                }
            };

            // Step 4 (emergency): drop the page cache, now that the overlays are
            // gone. Best-effort and never before unmount.
            let dropped = self.drop_page_cache_after_unmount(&guard);

            cleanup_report = report;
            unmount_outcome = outcome;
            page_cache_dropped = dropped;
        } else {
            // Step 2 (normal): verify cleanup; a failure rolls back to ACTIVE.
            cleanup_report = match self.execute_cleanup(&guard) {
                Ok(report) => {
                    tracing::info!(
                        cleaned_items = report.cleaned_items.len(),
                        duration_ms = cleanup_start.elapsed().as_millis() as u64,
                        "Cleanup complete"
                    );
                    report
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        state = ?current_state,
                        rollback = true,
                        phase = "cleanup",
                        "Cleanup failed, keeping system ACTIVE with overlays mounted"
                    );
                    // Guard drops here on return, rolling the state back to ACTIVE.
                    return Err(e);
                }
            };

            // Step 3 (normal): attempt every overlay unmount in reverse LIFO
            // order. Never abort on the first failure and never remount: once a
            // target is detached, returning to ACTIVE would route hidden-session
            // writes onto the decoy disk, so a teardown that cannot finish ends
            // DEGRADED instead.
            let outcome = self.unmount_overlays(&guard, &overlays_to_unmount);
            guard =
                self.finish_or_degrade(guard, &overlays_to_unmount, "deactivation", &outcome)?;
            tracing::info!(
                unmounted_paths = ?outcome.unmounted,
                duration_ms = unmount_start.elapsed().as_millis() as u64,
                "Overlays unmounted"
            );
            unmount_outcome = outcome;
            page_cache_dropped = false;
        }

        // Detach and remove any pivot staging the target unmount left behind, so a
        // pivoted (VFAT) target leaves no mount or directory under the staging base.
        self.cleanup_pivot_staging(&guard);

        let unmounted = unmount_outcome.unmounted;
        let force_detached = unmount_outcome.force_detached;

        // Step 3.5: Post-unmount cleanup on the real disk (Normal mode only).
        let post_unmount_report = if self.mode == DeactivationMode::Emergency {
            tracing::debug!("Skipping post-unmount cleanup in emergency mode");
            PostUnmountCleanupReport::default()
        } else if self.cleanup_config.post_unmount_cleanup {
            self.execute_post_unmount_cleanup(&guard)
        } else {
            tracing::debug!("Post-unmount cleanup disabled in configuration");
            PostUnmountCleanupReport::default()
        };

        // Step 4: Clear overlay_status and transition to INACTIVE.
        guard.clear_overlay_status_in_cache()?;
        let inactive_state = guard.current_state()?.complete_deactivation()?;
        self.persist_teardown_state_or_tolerate(&mut guard, inactive_state, "inactive")?;

        // Step 5: Point /run/current-system back at the decoy system (see
        // `restore_decoy_current_system`).
        let restore_error = if self.restore_decoy_profile {
            restore_decoy_current_system(
                guard.filesystem(),
                recorded_decoy.as_deref(),
                guard.runtime_env(),
            )?
        } else {
            None
        };

        if let Some(err) = restore_error {
            // State is already INACTIVE; keep it (do not roll back to ACTIVE).
            guard.commit();
            return Err(err);
        }

        // Step 6: Commit the guard (prevent rollback).
        guard.commit();

        let duration_ms = start.elapsed().as_millis() as u64;
        tracing::info!(
            duration_ms = duration_ms,
            state_to = ?SystemState::Inactive,
            unmounted_count = unmounted.len(),
            post_unmount_cleaned = post_unmount_report.cleaned_items.len(),
            "Deactivation complete"
        );

        Ok(DeactivationReport {
            cleanup_report,
            unmounted_overlays: unmounted,
            failed_overlays: Vec::new(),
            remaining_mounts: Vec::new(),
            duration: start.elapsed(),
            final_state: SystemState::Inactive,
            was_already_inactive: false,
            post_unmount_cleanup: post_unmount_report,
            force_detached_overlays: force_detached,
            page_cache_dropped,
            history_truncation_verified: None,
            runtime_journal_scrubbed: false,
            reboot_recommended: false,
        })
    }

    /// After attempting every unmount, either return the guard (clean teardown)
    /// or record `Degraded` and fail with [`NailsError::DeactivationIncomplete`].
    ///
    /// Re-reads the mount table for the attempted targets: if any NAILS mount is
    /// still live the state is recorded `Degraded` and the guard committed, so the
    /// RAII rollback never forces the state back to `Active` (a detached overlay
    /// would route hidden-session writes onto the decoy disk). A clean teardown
    /// returns the guard for the caller to finish with.
    fn finish_or_degrade<'a, F: Filesystem>(
        &self,
        mut guard: StateGuard<'a, F>,
        overlays: &[PathBuf],
        reason_prefix: &str,
        unmount_outcome: &UnmountOutcome,
    ) -> Result<StateGuard<'a, F>> {
        let remaining_mounts = remaining_nails_mounts(&guard, overlays, &unmount_outcome.failed);
        if remaining_mounts.is_empty() {
            return Ok(guard);
        }

        let remaining_display = remaining_mounts
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let reason = format!(
            "{} left {} NAILS mount(s) live: {}",
            reason_prefix,
            remaining_mounts.len(),
            remaining_display
        );

        tracing::error!(
            remaining = %remaining_display,
            unmounted = ?unmount_outcome.unmounted,
            failed = ?unmount_outcome.failed,
            phase = "unmount",
            state_to = "Degraded",
            "Teardown incomplete; recording DEGRADED (no remount, no return to ACTIVE)"
        );

        // Record DEGRADED and commit so the RAII guard does NOT force the state
        // back to ACTIVE on drop. DEACTIVATING/Degraded -> DEGRADED is allowed.
        let degraded = guard
            .current_state()?
            .enter_degraded(reason, remaining_mounts.clone());
        guard.update_state(degraded)?;
        guard.commit();

        Err(NailsError::DeactivationIncomplete { remaining_mounts })
    }

    /// Emergency teardown when the state file cannot be trusted.
    ///
    /// The recorded overlay list is unavailable (corrupt/unreadable state), so
    /// the targets come from the live mount table
    /// ([`Filesystem::discover_nails_mounts`](crate::Filesystem::discover_nails_mounts)).
    /// The teardown first replaces the untrusted state with a valid `Degraded`
    /// marker, attempts every unmount (best-effort, never remounting), and ends
    /// `Inactive` when nothing survives or `Degraded` with
    /// [`NailsError::DeactivationIncomplete`] when a mount could not be removed.
    fn run_from_untrusted_state<F: Filesystem>(
        &self,
        manager: &mut NailsManager<F>,
        start: Instant,
    ) -> Result<DeactivationReport> {
        let hidden_root = manager.config().hidden_volume_root.clone();
        let discovered = manager
            .filesystem()
            .discover_nails_mounts(Some(&hidden_root))?;
        let overlays_to_unmount = discovered_unmount_targets(&discovered);

        tracing::warn!(
            targets = ?overlays_to_unmount,
            phase = "deactivation",
            untrusted_state = true,
            "State file untrusted; tearing down NAILS overlays found in the live mount table"
        );

        // Replace the untrusted on-disk state with a valid Degraded marker so the
        // state file is trustworthy from here on, and capture it as the guard's
        // rollback baseline. force_state is the only way out of an unknown state:
        // update_state cannot validate a transition from a state it never read.
        let baseline = SystemState::Degraded {
            since: chrono::Utc::now(),
            reason: "emergency teardown from an untrusted state".to_string(),
            remaining_mounts: overlays_to_unmount.clone(),
        };
        manager.force_state(baseline.clone())?;

        let mut guard = StateGuard::new(&mut *manager, baseline);

        // Emergency order (same as the trusted path): detach the overlays first,
        // then run best-effort cleanup, then drop the page cache. The unmount is
        // the one step that matters, so nothing is allowed to run before it.
        let unmount_start = Instant::now();
        let unmount_outcome = self.unmount_overlays(&guard, &overlays_to_unmount);
        guard = self.finish_or_degrade(
            guard,
            &overlays_to_unmount,
            "emergency teardown",
            &unmount_outcome,
        )?;

        // Detach and remove any pivot staging left behind (directories survive even
        // when the staging mounts were already in the discovered unmount set).
        self.cleanup_pivot_staging(&guard);

        let unmounted = unmount_outcome.unmounted.clone();
        let force_detached = unmount_outcome.force_detached.clone();
        tracing::info!(
            unmounted_paths = ?unmounted,
            duration_ms = unmount_start.elapsed().as_millis() as u64,
            "Overlays unmounted"
        );

        // Best-effort cleanup after unmount; its failure must never abort.
        let cleanup_start = Instant::now();
        let cleanup_report = match self.execute_emergency_cleanup(&guard) {
            Ok(report) => {
                tracing::info!(
                    cleaned_items = report.cleaned_items.len(),
                    errors = report.errors.len(),
                    duration_ms = cleanup_start.elapsed().as_millis() as u64,
                    "Emergency cleanup complete (best-effort)"
                );
                report
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    phase = "cleanup",
                    "Emergency cleanup failed (non-fatal) - continuing teardown"
                );
                CleanupReport::default()
            }
        };

        // Drop the page cache after unmount (best-effort).
        let page_cache_dropped = self.drop_page_cache_after_unmount(&guard);

        // Clean teardown: clear tracking and go Degraded -> Inactive.
        guard.clear_overlay_status_in_cache()?;
        let inactive_state = guard.current_state()?.recover()?;
        guard.update_state(inactive_state)?;
        guard.commit();

        tracing::info!(
            duration_ms = start.elapsed().as_millis() as u64,
            state_to = ?SystemState::Inactive,
            unmounted_count = unmounted.len(),
            untrusted_state = true,
            "Emergency teardown from untrusted state complete"
        );

        Ok(DeactivationReport {
            cleanup_report,
            unmounted_overlays: unmounted,
            failed_overlays: Vec::new(),
            remaining_mounts: Vec::new(),
            duration: start.elapsed(),
            final_state: SystemState::Inactive,
            was_already_inactive: false,
            post_unmount_cleanup: PostUnmountCleanupReport::default(),
            force_detached_overlays: force_detached,
            page_cache_dropped,
            history_truncation_verified: None,
            runtime_journal_scrubbed: false,
            reboot_recommended: false,
        })
    }

    /// Thorough cleanup with verification; errors trigger rollback.
    fn execute_cleanup<F: Filesystem>(&self, manager: &NailsManager<F>) -> Result<CleanupReport> {
        let cleanup_manager = CleanupManager::new(
            manager.filesystem().clone(),
            self.cleanup_config.clone(),
            CleanupMode::Thorough {
                verify_cleanup: true,
            },
        )
        .with_history_homes(history_cleanup_homes(manager.runtime_env()));

        let report = cleanup_manager.cleanup()?;

        if !report.errors.is_empty() {
            let error_summary = report.errors.join("; ");
            return Err(NailsError::CleanupError(format!(
                "Cleanup had {} error(s): {}. Overlays remain mounted. State: ACTIVE",
                report.errors.len(),
                error_summary
            )));
        }

        if let Some(false) = report.verification_passed {
            return Err(NailsError::CleanupError(
                "Cleanup verification failed: forensic artifacts may remain. Overlays remain mounted. State: ACTIVE".to_string()
            ));
        }

        Ok(report)
    }

    /// Fast, best-effort cleanup; errors are logged but not fatal.
    ///
    /// The emergency cleanup configuration was already prepared by
    /// [`build_cleanup_config`]: it clears history, temp files and logs but does
    /// not secure-delete the encrypted hidden upper and does not drop the page
    /// cache (that is a dedicated post-unmount step), so this reuses
    /// `self.cleanup_config` directly rather than forcing a second config.
    fn execute_emergency_cleanup<F: Filesystem>(
        &self,
        manager: &NailsManager<F>,
    ) -> Result<CleanupReport> {
        let cleanup_manager = CleanupManager::new(
            manager.filesystem().clone(),
            self.cleanup_config.clone(),
            CleanupMode::Fast,
        )
        .with_history_homes(history_cleanup_homes(manager.runtime_env()));

        let report = cleanup_manager.cleanup()?;

        for error in &report.errors {
            tracing::warn!(error = %error, "Emergency cleanup error (non-fatal)");
        }

        Ok(report)
    }

    /// Drop the page cache after an emergency unmount.
    ///
    /// Runs only after the overlays are detached, so a stalled backend can never
    /// delay it, and releases clean cached pages that may still hold decoded
    /// hidden-session data. Best-effort: a failure (for example not running as
    /// root) is recorded but never fails the teardown. This frees only *clean*
    /// page cache — it does not zero RAM, which only a reboot does.
    fn drop_page_cache_after_unmount<F: Filesystem>(&self, manager: &NailsManager<F>) -> bool {
        let drop_caches_path = Path::new("/proc/sys/vm/drop_caches");
        match manager
            .filesystem()
            .write_kernel_tunable(drop_caches_path, "3")
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

    /// Phase 2 cleanup on the real disk after overlays are unmounted.
    fn execute_post_unmount_cleanup<F: Filesystem>(
        &self,
        manager: &NailsManager<F>,
    ) -> PostUnmountCleanupReport {
        let post_unmount_start = Instant::now();
        tracing::info!(
            phase = "post_unmount_cleanup",
            "Starting Phase 2 cleanup on real disk"
        );

        // No secure-delete / whole-file scrub by default: an opt-in post-unmount
        // edit only removes the hidden-session lines, it does not announce itself
        // by overwriting every history file on the decoy with zeros.
        let cleaned_items = truncate_all_history_files_for_homes(
            manager.filesystem(),
            &history_cleanup_homes(manager.runtime_env()),
            self.cleanup_config.secure_delete,
        );

        let report = PostUnmountCleanupReport {
            cleaned_items,
            warnings: Vec::new(),
            was_performed: true,
        };

        tracing::info!(
            phase = "post_unmount_cleanup",
            cleaned_count = report.cleaned_items.len(),
            duration_ms = post_unmount_start.elapsed().as_millis() as u64,
            "Phase 2 cleanup complete"
        );

        report
    }

    /// Attempt to unmount every overlay in reverse LIFO order.
    ///
    /// Unlike the old teardown this never aborts on the first failure and never
    /// remounts: every target is attempted (graceful, then forced) and the
    /// per-target failures are collected so the caller can decide whether the
    /// teardown is complete or must be recorded as degraded.
    /// Detach everything staged inside the per-activation runtime scaffolding
    /// root, then unmount and remove the root tmpfs itself.
    ///
    /// All of an activation's volatile scaffolding — pivot staging overlays, the
    /// vfat snapshot tmpfs, and the read-only `/nix/store` bind — lives inside one
    /// random-named umbrella tmpfs under `/run`. The main overlay unmount only
    /// takes the *target* binds down; the scaffolding stacked inside the umbrella
    /// stays behind and keeps the hidden upper on the backend busy.
    ///
    /// The root is found two ways and both are honoured: structural discovery from
    /// the live mount table (so an untrusted / emergency teardown with no state
    /// still finds it) and the path recorded in the state file (so a trusted
    /// teardown removes even an *empty* umbrella that a mount-table scan does not
    /// correlate). Scaffolding is detached snapshot-last — the staging overlay
    /// stacks on the `-snapshot` tmpfs — then the umbrella tmpfs is unmounted and
    /// its directory removed. Best-effort and a no-op when no scaffolding exists.
    pub(super) fn cleanup_pivot_staging<F: Filesystem>(&self, manager: &NailsManager<F>) {
        let fs = manager.filesystem();
        let hidden_root = manager.config().hidden_volume_root.clone();

        // The umbrella root recorded at activation (reliable even when empty).
        let recorded_root = manager
            .cached_state
            .borrow()
            .as_ref()
            .and_then(|state| state.runtime_root.clone());

        let mut discovered_root = None;
        if let Ok(mounts) = fs.discover_nails_mounts(Some(&hidden_root)) {
            discovered_root = mounts.runtime_tmpfs.clone();
            let mut staging = mounts.pivot_binds.clone();
            // Detach the staging overlay before the `-snapshot` tmpfs it stacks on.
            staging.sort_by_key(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().ends_with("-snapshot"))
                    .unwrap_or(false)
            });
            for target in &staging {
                if fs.unmount(target, false).is_err() {
                    let _ = fs.unmount(target, true);
                }
                // The snapshot tmpfs staged inside the root is a tmpfs, not an
                // overlay; unmount_tmpfs is idempotent and a no-op for the overlay
                // and bind staging, so this cleans both without knowing the fstype.
                let _ = fs.unmount_tmpfs(target);
            }
        }

        // Tear down the umbrella tmpfs last, from whichever source found it. The
        // recorded path is tried too, deduplicated, so an empty umbrella the
        // mount-table scan did not correlate is still removed.
        for root in [discovered_root, recorded_root].into_iter().flatten().fold(
            Vec::new(),
            |mut acc: Vec<PathBuf>, root| {
                if !acc.contains(&root) {
                    acc.push(root);
                }
                acc
            },
        ) {
            // Unmounting the tmpfs discards every staging directory it held, so
            // only the umbrella itself needs removing afterwards.
            let _ = fs.unmount_tmpfs(&root);
            let _ = fs.remove_directory(&root);
        }
    }

    fn unmount_overlays<F: Filesystem>(
        &self,
        manager: &NailsManager<F>,
        overlays: &[PathBuf],
    ) -> UnmountOutcome {
        let mut unmounted = Vec::new();
        let mut failed = Vec::new();
        let mut force_detached = Vec::new();

        for overlay_path in overlays.iter().rev() {
            match self.unmount_single_overlay(manager, overlay_path) {
                Ok(needed_force) => {
                    let display = overlay_path.to_string_lossy().to_string();
                    if needed_force {
                        force_detached.push(display.clone());
                    }
                    unmounted.push(display);
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        path = %overlay_path.display(),
                        phase = "unmount",
                        "Unmount failed for overlay; continuing with the remaining targets"
                    );
                    failed.push(overlay_path.clone());
                }
            }
        }

        UnmountOutcome {
            unmounted,
            failed,
            force_detached,
        }
    }

    /// Unmount a single overlay with graceful -> force fallback.
    ///
    /// Returns `Ok(true)` when the overlay only came down after the forced (lazy)
    /// detach, `Ok(false)` when the graceful unmount succeeded, and an error when
    /// both attempts failed.
    fn unmount_single_overlay<F: Filesystem>(
        &self,
        manager: &NailsManager<F>,
        path: &Path,
    ) -> Result<bool> {
        match manager.filesystem().unmount(path, false) {
            Ok(()) => {
                tracing::info!(
                    path = %path.display(),
                    method = "graceful",
                    "Overlay unmounted"
                );
                Ok(false)
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "Graceful unmount failed, trying force unmount"
                );
                manager.filesystem().unmount(path, true).map(|()| true)
            }
        }
    }
}
