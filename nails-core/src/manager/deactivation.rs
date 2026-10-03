//! Deactivation logic for `NailsManager`
//!
//! Both `deactivate()` and `emergency_deactivate()` now route through
//! `DeactivationOrchestrator`, with thin wrappers for mode-specific pre/post work.

use super::NailsManager;
use super::{
    ensure_run_current_system_symlink, restart_service_and_socket, select_system_profile,
    start_service_and_socket,
};
use crate::cleanup::history::{history_cleanup_homes, truncate_all_history_files_for_homes};
use crate::deactivation::test_gate::maybe_block_after_deactivating_state_transition;
#[cfg(not(test))]
use crate::deactivation::test_gate::should_skip_shell_cleanup_before_deactivation_gate;
use crate::deactivation::{DeactivationReport, PostUnmountCleanupReport};
use crate::filesystem::NailsMounts;
#[cfg(not(test))]
use crate::process::kill_shells_for_teardown;
use crate::{
    CleanupConfig, CleanupManager, CleanupMode, CleanupReport, Filesystem, NailsError, Result,
    StateGuard, SystemState,
};
use std::path::{Path, PathBuf};
use std::time::Instant;

mod reboot;

pub use reboot::HostEffects;
#[cfg(any(test, feature = "test-hooks"))]
pub use reboot::{SimulatedHostEffects, SimulatedReboot};

// The protected-PID handoff is a test-only injection point; nothing sets it in
// production, so it is compiled in only alongside the other hooks.
#[cfg(all(not(test), feature = "test-hooks"))]
const SHELL_CLEANUP_PROTECTED_PIDS_ENV: &str = "NAILS_SHELL_CLEANUP_PROTECTED_PIDS";

/// Merge this process's ancestry with any PIDs handed across the `systemd-run`
/// boundary by the detached invocation (via `SHELL_CLEANUP_PROTECTED_PIDS_ENV`),
/// de-duplicating while preserving order.
///
/// The merged set is the shells that must survive deactivation: the process
/// tree running the teardown plus the caller's session recorded before detach.
fn merge_protected_pids(mut ancestry: Vec<u32>, handoff: Option<&std::ffi::OsStr>) -> Vec<u32> {
    if let Some(handoff) = handoff {
        for pid in handoff
            .to_string_lossy()
            .split(',')
            .filter_map(|value| value.trim().parse::<u32>().ok())
        {
            if !ancestry.contains(&pid) {
                ancestry.push(pid);
            }
        }
    }

    ancestry
}

/// Protected PIDs for shell cleanup: this process's ancestry plus the detached
/// handoff set. Computed once per deactivation and passed explicitly to
/// [`kill_user_shells`], replacing the previous global environment variable.
#[cfg(not(test))]
fn collect_protected_shell_pids() -> Vec<u32> {
    // The handoff env var exists only in test-hooks builds; shipped builds protect
    // the teardown's own process tree and nothing else.
    #[cfg(feature = "test-hooks")]
    let handoff = std::env::var_os(SHELL_CLEANUP_PROTECTED_PIDS_ENV);
    #[cfg(not(feature = "test-hooks"))]
    let handoff: Option<std::ffi::OsString> = None;

    merge_protected_pids(current_process_ancestry(), handoff.as_deref())
}

#[cfg(not(test))]
fn current_process_ancestry() -> Vec<u32> {
    let mut lineage = Vec::new();
    let mut next = Some(std::process::id());

    while let Some(pid) = next {
        if pid == 0 || lineage.contains(&pid) {
            break;
        }

        lineage.push(pid);
        next = read_parent_pid(pid);
    }

    lineage
}

#[cfg(not(test))]
fn read_parent_pid(pid: u32) -> Option<u32> {
    let status_path = Path::new("/proc").join(pid.to_string()).join("status");
    let content = std::fs::read_to_string(status_path).ok()?;

    content.lines().find_map(|line| {
        let rest = line.strip_prefix("PPid:\t")?;
        rest.split_whitespace().next()?.parse::<u32>().ok()
    })
}

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
    /// state, so it skips the decoy-history edit a forensic teardown performs.
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

    fn requires_forensic_verification(self) -> bool {
        matches!(self, Self::Emergency)
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

#[derive(Debug, Default)]
struct OverlayContext {
    nix_was_overlaid: bool,
    var_was_overlaid: bool,
    /// Activation recorded a read-only `/nix/store` self-bind in PID 1's mount
    /// namespace (set only when the manager and init namespaces differed). The
    /// manager-namespace unmount cannot reach it, so teardown undoes it directly.
    nix_store_init_namespace_bound: bool,
    /// Decoy OS trees activation bind-remounted read-only for the session, to undo
    /// so the host regains write access (the decoy root and `/usr` on an FHS host;
    /// empty on NixOS).
    read_only_guards: Vec<PathBuf>,
    /// Mounts activation created to keep host submounts visible under overlaid
    /// targets, to undo (in reverse) before the parent overlays come down. Empty
    /// when no target had a hidden submount.
    submount_attachments: Vec<crate::state::SubmountAttachment>,
}

fn requires_decoy_restore<F: Filesystem>(manager: &NailsManager<F>) -> Result<bool> {
    let _ = manager.current_state()?;

    let cached = manager.cached_state.borrow();

    Ok(cached
        .as_ref()
        .and_then(|state_file| state_file.hidden_toplevel())
        .is_some())
}

/// Send `signal` (e.g. `TERM`, `KILL`) to `pid`, best-effort.
///
/// Routes through the shared process runner so the host-tool resolution and the
/// test-runtime guard apply exactly as they do for every other external command.
fn signal_pid(pid: u32, signal: &str) {
    use crate::process::run::{ProcessRunner, RealProcessRunner, signal_command};
    let _ = RealProcessRunner.run(&signal_command(pid, signal));
}

/// Restart the display manager after an emergency teardown so the decoy greeter
/// reappears. Best-effort; `None` (a non-graphical or non-emergency teardown)
/// does nothing.
fn restart_display_manager_after_emergency(display_manager: Option<String>) {
    if let Some(display_manager) = display_manager {
        tracing::info!(service = %display_manager, "Restarting display manager onto the decoy greeter");
        start_service_and_socket(&display_manager);
    }
}

fn build_cleanup_config<F: Filesystem>(
    manager: &NailsManager<F>,
    kind: ManagerDeactivationKind,
) -> CleanupConfig {
    let cleanup_config = CleanupConfig {
        clear_history: manager.config().clear_history,
        log_path: manager.config().log_path.clone(),
        hidden_volume_root: manager.config().hidden_volume_root.clone(),
        config_file_path: manager.config().loaded_config_path.clone(),
        ..CleanupConfig::default()
    };

    if kind == ManagerDeactivationKind::Emergency {
        CleanupConfig {
            clear_history: true,
            clear_temp_files: true,
            clear_logs: true,
            secure_delete: true,
            sanitize_memory: true,
            ..cleanup_config
        }
    } else {
        cleanup_config
    }
}

fn inspect_overlay_context<F: Filesystem>(manager: &NailsManager<F>) -> Result<OverlayContext> {
    let _ = manager.current_state()?;

    let cached = manager.cached_state.borrow();

    let overlay_paths: Vec<PathBuf> = cached
        .as_ref()
        .map(|state_file| state_file.overlay_status.keys().cloned().collect())
        .unwrap_or_default();

    let nix_store_init_namespace_bound = cached
        .as_ref()
        .map(|state_file| state_file.nix_store_init_namespace_bound)
        .unwrap_or(false);

    let read_only_guards = cached
        .as_ref()
        .map(|state_file| state_file.read_only_guards.clone())
        .unwrap_or_default();

    let submount_attachments = cached
        .as_ref()
        .map(|state_file| state_file.submount_attachments.clone())
        .unwrap_or_default();

    Ok(OverlayContext {
        nix_was_overlaid: overlay_paths.iter().any(|p| p == Path::new("/nix")),
        var_was_overlaid: overlay_paths.iter().any(|p| p == Path::new("/var")),
        nix_store_init_namespace_bound,
        read_only_guards,
        submount_attachments,
    })
}

/// Derive the service-restart context from the live mount table rather than the
/// state file, for an emergency teardown on an untrusted state.
///
/// The cached state is the safe default (empty overlay list) when the state file
/// is corrupt, so the nix-daemon / journald restart must be driven by what is
/// actually mounted: whether `/nix` is overlaid, and whether `/var` is among the
/// discovered overlays.
fn overlay_context_from_mounts<F: Filesystem>(manager: &NailsManager<F>) -> Result<OverlayContext> {
    let hidden_root = manager.config().hidden_volume_root.clone();
    let mounts = manager
        .filesystem()
        .discover_nails_mounts(Some(&hidden_root))?;

    let var_was_overlaid = mounts
        .persistent_overlays
        .iter()
        .chain(mounts.ephemeral_overlays.iter())
        .any(|p| p == Path::new("/var"));

    // The recorded guard list cannot be trusted on a corrupt state, so re-derive
    // the trees the active platform's policy would have kept read-only and undo
    // those. `unmount_bind` is idempotent, so undoing a tree that was never
    // guarded is a harmless no-op, and this makes sure an emergency teardown
    // always returns write access to the decoy.
    let read_only_guards = crate::platform::detect_platform(manager.filesystem())
        .ok()
        .map(|platform| platform.overlay_policy())
        .and_then(|policy| policy.resolve_read_only(manager.filesystem()).ok())
        .unwrap_or_default();

    Ok(OverlayContext {
        nix_was_overlaid: mounts.nix_overlay_present,
        var_was_overlaid,
        // An untrusted-state teardown cannot trust the recorded flag, and the
        // init-namespace bind is invisible in the manager's mount table, so it is
        // left for manual recovery rather than guessed at.
        nix_store_init_namespace_bound: false,
        read_only_guards,
        // The recorded attachment list cannot be trusted on a corrupt state. Nested
        // overlays are still discovered and torn down as persistent overlays below;
        // the staging/re-attach binds are left for the forced parent-overlay detach
        // rather than guessed at.
        submount_attachments: Vec::new(),
    })
}

fn verify_history_truncation<F: Filesystem>(manager: &NailsManager<F>) {
    let history_files =
        crate::cleanup::history::get_extended_history_files_for_homes(&history_cleanup_homes());
    let mut verification_passed = true;

    for path in &history_files {
        if let Ok(true) = manager.filesystem.path_exists(path)
            && let Ok(content) = manager.filesystem.read_file_content(path)
            && content.len() >= 100
        {
            tracing::warn!(
                file = %path.display(),
                size = content.len(),
                "History file unexpectedly large after truncation"
            );
            verification_passed = false;
        }
    }

    if verification_passed {
        tracing::info!("History truncation verification passed (all files < 100 bytes)");
    } else {
        tracing::warn!(
            "History truncation verification: some files may not have been fully cleaned"
        );
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
        }
    }

    /// The live NAILS overlay mount points, for the emergency overlay-rooted
    /// process scan. Best-effort: a discovery error yields an empty list rather
    /// than blocking the teardown.
    fn emergency_overlay_targets(&self) -> Vec<PathBuf> {
        let hidden_root = self.config().hidden_volume_root.clone();
        match self.filesystem().discover_nails_mounts(Some(&hidden_root)) {
            Ok(discovered) => discovered.owned_mount_points(),
            Err(e) => {
                tracing::warn!(error = %e, "Could not enumerate NAILS mounts for emergency process cleanup");
                Vec::new()
            }
        }
    }

    /// Emergency only: run the pre-teardown session/service cleanup and return the
    /// display manager to restart afterwards. A no-op returning `None` for the
    /// normal and recovery kinds, which keep the thorough teardown order.
    fn prepare_emergency_session_teardown(&self, kind: ManagerDeactivationKind) -> Option<String> {
        if kind != ManagerDeactivationKind::Emergency {
            return None;
        }
        let overlay_targets = self.emergency_overlay_targets();
        self.terminate_hidden_session_before_teardown(&overlay_targets)
    }

    /// Emergency only: end the hidden graphical session and the services the
    /// hidden configuration added, before the overlays come down.
    ///
    /// Order matters. The logind session (and its user) are terminated first so
    /// every GUI app and user unit the operator left in that slice — including
    /// those rooted in the overlays — is gone before unmount. The service units
    /// the hidden switch recorded are then stopped, and finally any remaining
    /// process still able to write through an overlay target is signalled. All of
    /// it is best-effort. Returns the display manager to restart once the overlays
    /// are gone (`Some` only when a graphical session was torn down).
    fn terminate_hidden_session_before_teardown(
        &self,
        overlay_targets: &[PathBuf],
    ) -> Option<String> {
        use crate::manager::helpers::ServiceController;

        let (hidden_session, added_units) = {
            let cached = self.cached_state.borrow();
            match cached.as_ref() {
                Some(state_file) => (
                    state_file.hidden_session.clone(),
                    state_file.hidden_added_units.clone(),
                ),
                None => (None, Vec::new()),
            }
        };

        let restart_dm = hidden_session.map(|session| {
            tracing::info!(
                uid = session.target_uid,
                "Terminating the hidden graphical session before overlay teardown"
            );
            ServiceController::terminate_logind_session(
                session.target_uid,
                session.session_id.as_deref(),
            );
            session
                .display_manager
                .unwrap_or_else(|| "display-manager.service".to_string())
        });

        for unit in &added_units {
            tracing::info!(unit, "Stopping a unit the hidden configuration added");
            let _ = ServiceController::stop_unit(unit);
        }

        self.kill_overlay_rooted_processes(overlay_targets);

        restart_dm
    }

    /// Signal any process that can still write to the decoy through an overlay
    /// target (a cwd/root inside it, a writable or directory fd, a shared-writable
    /// mapping). Reuses the capability-aware process classifier; read-only
    /// consumers are left alone. Best-effort and a no-op in test/test-like
    /// runtimes, where the `/proc` snapshot is empty.
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

        let mut pids = std::collections::BTreeSet::new();
        for target in targets {
            for info in snapshot.processes_using(target) {
                if info.is_write_blocking() {
                    pids.insert(info.pid);
                }
            }
        }

        if pids.is_empty() {
            return;
        }

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

    fn run_deactivation(&mut self, kind: ManagerDeactivationKind) -> Result<()> {
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
                return Ok(());
            }
        }

        // A swap device that reappeared while the hidden session ran would have
        // paged memory to the decoy disk; surface it before teardown. Skipped in
        // emergency mode, which must stay fast and best-effort.
        if kind == ManagerDeactivationKind::Normal {
            let hidden_root = self.config().hidden_volume_root.clone();
            self.recheck_swap_posture("before deactivation", &hidden_root);
        }

        if kind == ManagerDeactivationKind::Normal
            && requires_decoy_restore(self)?
            && select_system_profile(self.filesystem())?.is_none()
        {
            return Err(NailsError::NixOSError(
                "No system profile found. Cannot restore decoy configuration.".to_string(),
            ));
        }

        let overlay_context = if untrusted_state {
            overlay_context_from_mounts(self)?
        } else {
            inspect_overlay_context(self)?
        };

        // Return write access to the decoy OS trees and undo the submount
        // attachments before the overlays they sit on come down (the orchestrator
        // unmounts the parent overlays below).
        self.teardown_overlay_dependents(&overlay_context);

        if overlay_context.nix_was_overlaid {
            tracing::info!("Stopping nix-daemon before /nix overlay unmount...");
            let _ = crate::manager::helpers::ServiceController::stop_nix_daemon();

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

        // Emergency only: before the overlays come down, end the hidden graphical
        // session and the services the hidden configuration added. Killing the
        // logind session and the hidden units first means GUI apps and hidden
        // services rooted in the overlays are gone before unmount, so the overlays
        // are no longer pinned and the backend can later be closed. Returns the
        // display manager to restart once the overlays are gone (`Some` only when a
        // graphical session was torn down), deferred until after unmount so the
        // greeter comes from the decoy system.
        let emergency_restart_dm = self.prepare_emergency_session_teardown(kind);

        let cleanup_config = build_cleanup_config(self, kind);

        #[cfg(not(test))]
        if should_skip_shell_cleanup_before_deactivation_gate() {
            tracing::info!(
                "Skipping pre-unmount shell cleanup because the deactivation test gate is armed"
            );
        } else {
            tracing::info!(
                "Killing every interactive shell (including root's) immediately before overlay teardown"
            );
            let protected = collect_protected_shell_pids();
            // Teardown kills root's decoy shell too, so its in-memory history is
            // never flushed; only this process's own ancestry stays protected, and
            // the deactivation detach means the invoking shell is torn down with
            // the rest rather than permanently spared.
            let report = kill_shells_for_teardown(&protected);
            tracing::info!(
                killed = report.killed.len(),
                failed = report.failed.len(),
                skipped = report.skipped.len(),
                "Shell cleanup complete"
            );
        }

        // Capture the opt-in flags before the config is moved into the
        // orchestrator: the forensic-reboot path below edits decoy history only
        // when the operator opted in, and secure-delete stays off unless enabled.
        let post_unmount_opt_in = cleanup_config.post_unmount_cleanup;
        let post_unmount_secure_delete = cleanup_config.secure_delete;

        let restore_decoy_profile = requires_decoy_restore(self)?;
        let orchestrator = DeactivationOrchestrator::new(cleanup_config)
            .with_mode(kind.orchestrator_mode())
            .with_decoy_profile_restore(restore_decoy_profile)
            .with_untrusted_state(untrusted_state);

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

        // Emergency only: now that the overlays are gone, restart the display
        // manager so the login greeter comes up from the decoy system rather than
        // the torn-down hidden session. Deferred to here so it never races the
        // overlay teardown.
        restart_display_manager_after_emergency(emergency_restart_dm);

        // Stop the in-session backend watcher and remove the RAM-backed runtime
        // copy on every teardown path. Runs before the orchestrator result is
        // unwrapped so the watcher never outlives the overlays even when the
        // teardown reported a problem.
        self.teardown_backend_runtime_copy();

        let _report = result?;

        // Post-unmount history editing on the decoy disk is opt-in (see
        // [`CleanupConfig::post_unmount_cleanup`]): by default deactivation makes
        // no write to any decoy filesystem after unmount, because such a write is
        // itself a deactivation-time artifact on the decoy. The pre-teardown shell
        // kill plus an amnesic decoy base are the real defenses. When the operator
        // has opted in (decoy verified amnesic), the forensic-reboot path still
        // edits history, best-effort and without secure-delete unless separately
        // enabled.
        if kind.requires_forensic_verification() && post_unmount_opt_in {
            tracing::info!("Editing decoy history files after unmount (opt-in)");
            let truncated = truncate_all_history_files_for_homes(
                &self.filesystem,
                &history_cleanup_homes(),
                post_unmount_secure_delete,
            );
            tracing::info!(
                truncated_count = truncated.len(),
                "Post-unmount history edit complete"
            );

            verify_history_truncation(self);
        }

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
            let _outcome = host_effects.reboot_into_decoy(self.filesystem())?;
        }

        Ok(())
    }

    /// Deactivate NAILS, restoring the decoy configuration, then reboot.
    pub fn deactivate(&mut self) -> Result<()> {
        self.run_deactivation(ManagerDeactivationKind::Normal)
    }

    /// Emergency deactivation: fast, best-effort teardown without a reboot.
    pub fn emergency_deactivate(&mut self) -> Result<()> {
        self.run_deactivation(ManagerDeactivationKind::Emergency)
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

fn overlay_unmount_targets<F: Filesystem>(
    manager: &NailsManager<F>,
    current_state: &SystemState,
) -> Result<Vec<PathBuf>> {
    let active_overlays = match current_state {
        SystemState::Active { overlays, .. } => overlays.clone(),
        _ => {
            return Err(NailsError::InvalidState(
                "Cannot extract overlays: not in ACTIVE state".to_string(),
            ));
        }
    };

    let mut merged = manager.tracked_overlay_paths_by_mount_order()?;
    for path in active_overlays {
        if !merged.iter().any(|existing| existing == &path) {
            merged.push(path);
        }
    }

    Ok(merged)
}

/// Targets to unmount for an untrusted-state teardown, in mount order.
///
/// [`unmount_overlays`](DeactivationOrchestrator::unmount_overlays) reverses this
/// list, so placing the `/nix/store` restore bind last makes it come off before
/// the `/nix` overlay it sits on, and the persistent overlays come off last. The
/// `/nix/store` bind is only ours when `/nix` is overlaid, so it is included only
/// then (and only when still present — the `/nix` teardown path may already have
/// removed it before the orchestrator runs).
fn discovered_unmount_targets(mounts: &NailsMounts) -> Vec<PathBuf> {
    let mut targets = Vec::new();
    targets.extend(mounts.persistent_overlays.iter().cloned());
    targets.extend(mounts.ephemeral_overlays.iter().cloned());
    targets.extend(mounts.pivot_binds.iter().cloned());
    if mounts.nix_overlay_present
        && let Some(bind) = &mounts.nix_store_bind
    {
        targets.push(bind.clone());
    }
    targets
}

/// Result of attempting to unmount every tracked overlay.
///
/// The teardown attempts all targets rather than aborting on the first failure,
/// so both the detached and the still-failing targets are recorded.
struct UnmountOutcome {
    /// Targets detached successfully, in the order they were attempted.
    unmounted: Vec<String>,
    /// Targets whose unmount failed after both graceful and forced attempts.
    failed: Vec<PathBuf>,
}

/// Re-read the mount table and return the attempted targets that are still live.
///
/// Probing [`Filesystem::is_mounted`](crate::Filesystem::is_mounted) per target
/// behaves identically on the mock and the real filesystem and needs no new
/// trait method. A probe error is treated conservatively as "still mounted" so
/// an unreadable mount table can never be mistaken for a clean teardown.
fn remaining_nails_mounts<F: Filesystem>(
    manager: &NailsManager<F>,
    attempted: &[PathBuf],
) -> Vec<PathBuf> {
    attempted
        .iter()
        .filter(|target| match manager.filesystem().is_mounted(target) {
            Ok(mounted) => mounted,
            Err(e) => {
                tracing::warn!(
                    path = %target.display(),
                    error = %e,
                    phase = "unmount",
                    "Could not confirm unmount; treating target as still live"
                );
                true
            }
        })
        .cloned()
        .collect()
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

        // Step 1: Take the rollback guard and transition ACTIVE -> DEACTIVATING.
        let mut guard = StateGuard::new(&mut *manager, current_state.clone());
        let deactivating_state = SystemState::Deactivating {
            started_at: chrono::Utc::now(),
        };
        guard.update_state(deactivating_state)?;
        maybe_block_after_deactivating_state_transition()?;

        // Step 2: Cleanup artifacts.
        let cleanup_start = Instant::now();
        let cleanup_report = if self.mode == DeactivationMode::Emergency {
            match self.execute_emergency_cleanup(&guard) {
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
            }
        } else {
            match self.execute_cleanup(&guard) {
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
            }
        };

        // Step 3: Attempt every overlay unmount in reverse LIFO order. Never abort
        // on the first failure and never remount: once a target is detached,
        // returning to ACTIVE would route hidden-session writes onto the decoy
        // disk, so a teardown that cannot finish ends DEGRADED instead.
        let unmount_start = Instant::now();
        let unmount_outcome = self.unmount_overlays(&guard, &overlays_to_unmount);

        // Re-read the mount table: which NAILS targets are still live?
        let remaining_mounts = remaining_nails_mounts(&guard, &overlays_to_unmount);

        if !remaining_mounts.is_empty() {
            let remaining_display = remaining_mounts
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let reason = format!(
                "deactivation left {} NAILS mount(s) live: {}",
                remaining_mounts.len(),
                remaining_display
            );

            tracing::error!(
                remaining = %remaining_display,
                unmounted = ?unmount_outcome.unmounted,
                failed = ?unmount_outcome.failed,
                duration_ms = unmount_start.elapsed().as_millis() as u64,
                phase = "unmount",
                state_to = "Degraded",
                "Teardown incomplete; recording DEGRADED (no remount, no return to ACTIVE)"
            );

            // Record DEGRADED and commit so the RAII guard does NOT force the
            // state back to ACTIVE on drop. DEACTIVATING -> DEGRADED is allowed.
            let degraded = guard
                .current_state()?
                .enter_degraded(reason, remaining_mounts.clone());
            guard.update_state(degraded)?;
            guard.commit();

            return Err(NailsError::DeactivationIncomplete { remaining_mounts });
        }

        let unmounted = unmount_outcome.unmounted;
        tracing::info!(
            unmounted_paths = ?unmounted,
            duration_ms = unmount_start.elapsed().as_millis() as u64,
            "Overlays unmounted"
        );

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
        guard.update_state(inactive_state)?;

        // Step 5: Point /run/current-system back at the decoy system profile.
        //
        // We never run `switch-to-configuration switch` here. The reboot that
        // follows a Normal deactivation boots the decoy from the bootloader
        // default (activation only ever used `test`), so a real switch would be
        // pure redundancy — and it would reinstall the bootloader, write the ESP
        // and rewrite EFI NVRAM and /var/lib/nixos, leaving evidence that the
        // hidden mode existed. Swapping only the live /run/current-system symlink
        // restores the decoy for any caller that does not reboot (emergency)
        // without touching the bootloader, ESP or NVRAM.
        let restore_error = if !self.restore_decoy_profile {
            None
        } else if let Some(system_profile) = select_system_profile(guard.filesystem())? {
            tracing::info!("Restoring /run/current-system to the decoy profile...");
            ensure_run_current_system_symlink(guard.filesystem(), &system_profile)
                .err()
                .map(|e| {
                    NailsError::NixOSError(format!(
                        "Failed to restore /run/current-system to the decoy profile: {}",
                        e
                    ))
                })
        } else {
            Some(NailsError::NixOSError(
                "No system profile available for decoy restore".into(),
            ))
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
        })
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

        // Best-effort cleanup; its failure must never abort the teardown.
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

        // Attempt every unmount in reverse mount order; never abort, never remount.
        let unmount_start = Instant::now();
        let unmount_outcome = self.unmount_overlays(&guard, &overlays_to_unmount);
        let remaining_mounts = remaining_nails_mounts(&guard, &overlays_to_unmount);

        if !remaining_mounts.is_empty() {
            let remaining_display = remaining_mounts
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let reason = format!(
                "emergency teardown left {} NAILS mount(s) live: {}",
                remaining_mounts.len(),
                remaining_display
            );

            tracing::error!(
                remaining = %remaining_display,
                unmounted = ?unmount_outcome.unmounted,
                failed = ?unmount_outcome.failed,
                duration_ms = unmount_start.elapsed().as_millis() as u64,
                phase = "unmount",
                state_to = "Degraded",
                "Emergency teardown incomplete; recording DEGRADED (no remount)"
            );

            let degraded = guard
                .current_state()?
                .enter_degraded(reason, remaining_mounts.clone());
            guard.update_state(degraded)?;
            guard.commit();

            return Err(NailsError::DeactivationIncomplete { remaining_mounts });
        }

        let unmounted = unmount_outcome.unmounted;
        tracing::info!(
            unmounted_paths = ?unmounted,
            duration_ms = unmount_start.elapsed().as_millis() as u64,
            "Overlays unmounted"
        );

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
        );

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
    fn execute_emergency_cleanup<F: Filesystem>(
        &self,
        manager: &NailsManager<F>,
    ) -> Result<CleanupReport> {
        let cleanup_config = CleanupConfig {
            clear_history: true,
            clear_temp_files: true,
            clear_logs: true,
            secure_delete: true,
            sanitize_memory: true,
            ..self.cleanup_config.clone()
        };

        let cleanup_manager = CleanupManager::new(
            manager.filesystem().clone(),
            cleanup_config,
            CleanupMode::Fast,
        );

        let report = cleanup_manager.cleanup()?;

        for error in &report.errors {
            tracing::warn!(error = %error, "Emergency cleanup error (non-fatal)");
        }

        Ok(report)
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
            &history_cleanup_homes(),
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
    fn unmount_overlays<F: Filesystem>(
        &self,
        manager: &NailsManager<F>,
        overlays: &[PathBuf],
    ) -> UnmountOutcome {
        let mut unmounted = Vec::new();
        let mut failed = Vec::new();

        for overlay_path in overlays.iter().rev() {
            match self.unmount_single_overlay(manager, overlay_path) {
                Ok(()) => {
                    unmounted.push(overlay_path.to_string_lossy().to_string());
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

        UnmountOutcome { unmounted, failed }
    }

    /// Unmount a single overlay with graceful -> force fallback.
    fn unmount_single_overlay<F: Filesystem>(
        &self,
        manager: &NailsManager<F>,
        path: &Path,
    ) -> Result<()> {
        match manager.filesystem().unmount(path, false) {
            Ok(()) => {
                tracing::info!(
                    path = %path.display(),
                    method = "graceful",
                    "Overlay unmounted"
                );
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "Graceful unmount failed, trying force unmount"
                );
                manager.filesystem().unmount(path, true)
            }
        }
    }
}

#[cfg(test)]
#[path = "deactivation_tests.rs"]
mod tests;
