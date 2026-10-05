// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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

pub use reboot::{HostEffects, PostTeardownPower};
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

    let mut protected = merge_protected_pids(current_process_ancestry(), handoff.as_deref());

    // Spare every shell that shares this teardown's own session or process group,
    // not only its direct ancestry. When `nails emergency` is run in a pipeline —
    // which the NixOS test driver always does to capture output
    // (`nails emergency | ( base64 -w 0; echo )`) — the pipe-reading subshell is a
    // sibling, so it is not in the ancestry, yet killing it severs the console
    // reading the teardown's own result. It shares the session (and process group,
    // for a pipeline launched from one shell), so sparing those spares it. A
    // shipped emergency runs detached in its own session, so this spares only the
    // teardown's own invocation, never the operator's decoy shells.
    for pid in own_session_or_group_shell_pids() {
        if !protected.contains(&pid) {
            protected.push(pid);
        }
    }

    protected
}

/// Every live process sharing this teardown's session or process group.
///
/// Scanned once from `/proc` just before the pre-unmount shell kill and merged
/// into the protected set so [`kill_shells_for_teardown`] spares the teardown's
/// own invocation — in particular the sibling that reads its piped output — the
/// same way [`is_own_invocation_process`] spares it from the overlay-rooted kill.
#[cfg(not(test))]
fn own_session_or_group_shell_pids() -> Vec<u32> {
    let (self_sid, self_pgid) = self_session_and_pgid();
    if self_sid == 0 && self_pgid == 0 {
        return Vec::new();
    }

    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };

    let mut pids = Vec::new();
    for entry in proc_dir.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        if let Some((sid, pgid)) = read_session_and_pgid(pid)
            && is_own_invocation_process(pid, sid, pgid, &[], self_sid, self_pgid)
        {
            pids.push(pid);
        }
    }
    pids
}

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

fn read_parent_pid(pid: u32) -> Option<u32> {
    let status_path = Path::new("/proc").join(pid.to_string()).join("status");
    let content = std::fs::read_to_string(status_path).ok()?;

    content.lines().find_map(|line| {
        let rest = line.strip_prefix("PPid:\t")?;
        rest.split_whitespace().next()?.parse::<u32>().ok()
    })
}

/// The session id and process-group id of `pid`, read from `/proc/<pid>/stat`.
///
/// `/proc/<pid>/stat` lists these right after the `comm` field, which may itself
/// contain spaces or parentheses, so the scan starts past the final `)`. Returns
/// `None` when the process has gone or the file cannot be parsed.
fn read_session_and_pgid(pid: u32) -> Option<(u32, u32)> {
    let stat_path = Path::new("/proc").join(pid.to_string()).join("stat");
    let content = std::fs::read_to_string(stat_path).ok()?;
    let after_comm = content.get(content.rfind(')')? + 1..)?;
    // Fields after `comm`: state, ppid, pgrp, session, ...
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    let pgid = fields.get(2)?.parse::<u32>().ok()?;
    let sid = fields.get(3)?.parse::<u32>().ok()?;
    Some((sid, pgid))
}

/// Whether a process must be spared from the emergency overlay-rooted kill and
/// the owner-signalling because it belongs to this teardown's own invocation.
///
/// A process is spared when it is in the teardown's ancestry, shares its session,
/// or shares its process group. When `nails emergency` is run in a pipeline
/// (`nails emergency | base64`) the pipe reader shares the session — and, in the
/// non-interactive shell that launches the pipeline, the process group — while
/// its cwd sits inside the full-root overlay, so without this guard it is flagged
/// write-blocking and killed, and the final success line is then written into a
/// closed pipe. PID reuse can likewise make a recorded activation owner collide
/// with such a consumer, so the same guard protects the owner signal. The zero
/// sentinels guard against an unreadable self or candidate id matching by
/// accident.
fn is_own_invocation_process(
    candidate_pid: u32,
    candidate_sid: u32,
    candidate_pgid: u32,
    ancestry: &[u32],
    self_sid: u32,
    self_pgid: u32,
) -> bool {
    ancestry.contains(&candidate_pid)
        || (self_sid != 0 && candidate_sid == self_sid)
        || (self_pgid != 0 && candidate_pgid == self_pgid)
}

/// This process's session id and process-group id, best-effort (`0` when a value
/// cannot be determined, which the spare check treats as "no match").
fn self_session_and_pgid() -> (u32, u32) {
    let sid = nix::unistd::getsid(None)
        .map(|pid| pid.as_raw() as u32)
        .unwrap_or(0);
    let pgid = nix::unistd::getpgrp().as_raw() as u32;
    (sid, pgid)
}

/// Decide whether a path-matched emergency-kill candidate is genuinely rooted in
/// an overlay and so should be signalled.
///
/// The process classifier matched it to an overlay target by path prefix only.
/// That is kept when:
/// - no overlay device could be read (`!overlay_device_set_known`): fall back to
///   the path match rather than spare everything and leave the overlays pinned;
/// - the process is an unverifiable writer (a foreign mount namespace or chroot
///   whose device cannot be trusted): fail-safe, keep killing it;
/// - a reference of the process actually resolves onto an overlay device.
///
/// Otherwise the path matched the decoy directory the overlay is mounted over, not
/// the overlay itself, so the process is spared.
fn candidate_is_overlay_rooted(
    is_unverifiable_writer: bool,
    references_overlay_device: bool,
    overlay_device_set_known: bool,
) -> bool {
    if !overlay_device_set_known || is_unverifiable_writer {
        return true;
    }
    references_overlay_device
}

/// The set of device ids behind the given overlay mount points. Each overlay
/// mount carries its own anonymous `st_dev`, distinct from the decoy filesystem it
/// is stacked on, so this set identifies "inside the overlay".
fn overlay_mount_devices(targets: &[PathBuf]) -> std::collections::HashSet<u64> {
    use std::os::unix::fs::MetadataExt;
    targets
        .iter()
        .filter_map(|target| std::fs::metadata(target).ok().map(|meta| meta.dev()))
        .collect()
}

/// Whether any of a process's path references (cwd, root, or an open fd) resolves
/// onto one of `overlay_devices`.
///
/// The `/proc/<pid>/{cwd,root,fd/*}` magic links resolve to the real dentry, so a
/// `metadata` (stat, which follows the link) reports the device of the actual
/// object — the overlay's own device when the reference is inside the overlay, the
/// decoy device when it only shares the path string. A vanished process or an
/// unreadable link simply contributes no match.
fn process_references_overlay_device(
    pid: u32,
    overlay_devices: &std::collections::HashSet<u64>,
) -> bool {
    use std::os::unix::fs::MetadataExt;
    let base = format!("/proc/{pid}");
    for link in ["cwd", "root"] {
        if let Ok(meta) = std::fs::metadata(format!("{base}/{link}"))
            && overlay_devices.contains(&meta.dev())
        {
            return true;
        }
    }
    if let Ok(entries) = std::fs::read_dir(format!("{base}/fd")) {
        for entry in entries.flatten() {
            if let Ok(meta) = std::fs::metadata(entry.path())
                && overlay_devices.contains(&meta.dev())
            {
                return true;
            }
        }
    }
    false
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

/// Decide whether a recorded activation owner pid should be signalled before an
/// emergency/recover teardown.
///
/// Owner-pid signalling is a try-lock, not a hard gate: it applies only to the
/// state-independent teardowns (`Emergency`/`Recover`), never to a normal
/// Active-only deactivate which owns the state itself, and never targets the
/// unset sentinel (`0`) or our own process. The aliveness probe and the actual
/// signal happen at the call site; this function holds only the pure decision so
/// it can be unit-tested without touching `/proc` or sending a real signal.
fn owner_pid_to_signal(
    kind: ManagerDeactivationKind,
    owner_pid: u32,
    self_pid: u32,
) -> Option<u32> {
    let signals_owner = matches!(
        kind,
        ManagerDeactivationKind::Emergency | ManagerDeactivationKind::Recover
    );
    if signals_owner && owner_pid != 0 && owner_pid != self_pid {
        Some(owner_pid)
    } else {
        None
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
        // Emergency clears the forensic artifacts but does NOT secure-delete and
        // does NOT drop the page cache as part of cleanup. The hidden upper lives
        // on the encrypted backend, so overwriting its files only wastes the time
        // budget, and the page cache is dropped as a dedicated step *after*
        // unmount, never before (see `run_from_trusted_state`).
        CleanupConfig {
            clear_history: true,
            clear_temp_files: true,
            clear_logs: true,
            secure_delete: false,
            drop_page_cache: false,
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

/// Verify every decoy history file is small after the post-unmount edit.
///
/// Returns `true` when all files are below the 100-byte threshold and `false`
/// when any history file still holds enough content to carry session artifacts,
/// so the caller can surface an honest pass/fail to the operator.
fn verify_history_truncation<F: Filesystem>(manager: &NailsManager<F>) -> bool {
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

    verification_passed
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
        use crate::manager::helpers::ServiceController;

        let added_units = self
            .cached_state
            .borrow()
            .as_ref()
            .map(|state_file| state_file.hidden_added_units.clone())
            .unwrap_or_default();

        for unit in &added_units {
            tracing::info!(unit, "Stopping a unit the hidden configuration added");
            let _ = ServiceController::stop_unit(unit);
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
    /// decoy device and neither pins the overlay nor can write into its upper. So a
    /// path-matched candidate is kept only when a reference of its really resolves
    /// onto one of the overlay mounts' own devices (each overlay mount has its own
    /// anonymous `st_dev`); an unverifiable writer (foreign mount namespace or
    /// chroot, where the device cannot be trusted) is kept fail-safe, as is every
    /// candidate when no overlay device could be read at all.
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

        // The device id behind each overlay mount point. A reference that resolves
        // onto one of these is genuinely inside the overlay; one on the decoy
        // device only collided on the path string.
        let overlay_devices = overlay_mount_devices(targets);

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
                let on_overlay_device = !overlay_devices.is_empty()
                    && process_references_overlay_device(info.pid, &overlay_devices);
                if !candidate_is_overlay_rooted(
                    info.is_unverifiable_writer,
                    on_overlay_device,
                    !overlay_devices.is_empty(),
                ) {
                    tracing::debug!(
                        pid = info.pid,
                        "Sparing a decoy-side process (path matched an overlay target but its references are on the decoy device)"
                    );
                    continue;
                }
                pids.insert(info.pid);
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

    /// Emergency/recover only: a still-running activation owner could keep writing
    /// into the overlays while we tear them down, re-dirtying the decoy. Try-lock,
    /// not a hard gate: SIGTERM a recorded owner pid that is alive and is not us,
    /// wait up to ~3s for it to exit, then proceed unconditionally. Never fails
    /// closed — a ptraced or uninterruptible owner must not block the panic
    /// button. Best-effort and a no-op in test/test-like runtimes.
    fn signal_owner_pid_before_teardown(&self, kind: ManagerDeactivationKind) {
        if crate::runtime_safety::should_skip_host_interaction() {
            return;
        }
        // Read the recorded owner fresh; a corrupt/unreadable state file simply
        // means no owner to signal, and the teardown continues.
        let owner_pid = match crate::StateFile::load(&self.state_file_path) {
            Ok(state_file) => state_file.owner_pid,
            Err(_) => return,
        };
        let Some(pid) = owner_pid_to_signal(kind, owner_pid, std::process::id()) else {
            return;
        };
        if !crate::manager::state_management::pid_is_alive(pid) {
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

        for _ in 0..10 {
            if !crate::manager::state_management::pid_is_alive(pid) {
                tracing::info!(pid, "Activation owner exited before teardown");
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(300));
        }
        tracing::warn!(
            pid,
            "Activation owner still alive after waiting; proceeding with teardown anyway"
        );
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
                    post_unmount_cleanup: PostUnmountCleanupReport::default(),
                    force_detached_overlays: Vec::new(),
                    page_cache_dropped: false,
                    history_truncation_verified: None,
                    runtime_journal_scrubbed: false,
                    reboot_recommended: false,
                });
            }
        }

        // Emergency/recover: quiet a still-running activation owner before the
        // first unmount so a stale writer cannot re-dirty the overlays mid-
        // teardown. Try-lock only — it never blocks the panic button.
        self.signal_owner_pid_before_teardown(kind);

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

        // Emergency only: before the overlays come down, stop the service units the
        // hidden configuration added and signal any process still writing to the
        // decoy through an overlay target. It never logs the operator out and never
        // touches the display manager or X server — the desktop must look unchanged
        // while the overlays are detached underneath it (lazily where a process
        // holds a path busy).
        self.prepare_emergency_pre_unmount_cleanup(kind);

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
            // never flushed; only the teardown's own invocation stays protected —
            // its ancestry plus any sibling sharing its session or process group,
            // such as the pipe reader capturing this command's output — and the
            // deactivation detach means the invoking shell is torn down with the
            // rest rather than permanently spared.
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

        let mut report = result?;

        self.scrub_runtime_journal_and_warn(&overlay_context, kind, &mut report);

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

            report.history_truncation_verified = Some(verify_history_truncation(self));
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
            host_effects.run_post_teardown_power(action)?,
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
    /// Targets that only came down after the forced (lazy) detach fallback,
    /// because the graceful unmount failed. A subset of `unmounted`.
    force_detached: Vec<String>,
}

/// Re-read the mount table and return the attempted targets where a NAILS mount
/// is still live.
///
/// A target counts as live when something is still mounted there *and* that
/// mount is NAILS's own: an overlay, or a mount the live-table classifier
/// ([`Filesystem::discover_nails_mounts`](crate::Filesystem::discover_nails_mounts))
/// recognises as NAILS-created. A target that is itself a decoy mount point —
/// a VFAT `/boot`, a separate `/home` partition — stays mounted after its
/// overlay comes down, because the decoy's own filesystem is what the overlay
/// was stacked on; that mount is not a leftover and must not turn a clean
/// teardown into `Degraded`. A target whose unmount reported failure is always
/// live. A probe or discovery error is treated
/// conservatively as "still live" so an unreadable mount table can never be
/// mistaken for a clean teardown.
fn remaining_nails_mounts<F: Filesystem>(
    manager: &NailsManager<F>,
    attempted: &[PathBuf],
    failed: &[PathBuf],
) -> Vec<PathBuf> {
    let hidden_root = manager.config().hidden_volume_root.clone();
    let discovered = manager
        .filesystem()
        .discover_nails_mounts(Some(&hidden_root));
    attempted
        .iter()
        .filter(|target| {
            let mounted = match manager.filesystem().is_mounted(target) {
                Ok(mounted) => mounted,
                Err(e) => {
                    tracing::warn!(
                        path = %target.display(),
                        error = %e,
                        phase = "unmount",
                        "Could not confirm unmount; treating target as still live"
                    );
                    return true;
                }
            };
            if !mounted {
                return false;
            }
            // An unmount that reported failure leaves its NAILS mount in place.
            if failed.contains(target) {
                return true;
            }
            let overlay_still_mounted = manager
                .filesystem()
                .is_overlay_mounted(target)
                .unwrap_or(true);
            still_nails_owned(
                mounted,
                overlay_still_mounted,
                discovered.as_ref().ok(),
                target,
            )
        })
        .cloned()
        .collect()
}

/// Decide whether a still-mounted teardown target is a NAILS leftover.
///
/// Live when an overlay is still mounted there, when the live-table classifier
/// recognises the mount as NAILS-created, or when that classifier could not run
/// (`discovered` is `None`): fail closed. Otherwise the mount is the decoy's own
/// filesystem the overlay was stacked on, which is expected to remain.
fn still_nails_owned(
    mounted: bool,
    overlay_still_mounted: bool,
    discovered: Option<&crate::filesystem::NailsMounts>,
    target: &Path,
) -> bool {
    if !mounted {
        return false;
    }
    if overlay_still_mounted {
        return true;
    }
    match discovered {
        Some(mounts) => mounts.is_owned(target),
        None => true,
    }
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

        // Step 1: Take the rollback guard and transition ACTIVE -> DEACTIVATING.
        let mut guard = StateGuard::new(&mut *manager, current_state.clone());
        let deactivating_state = SystemState::Deactivating {
            started_at: chrono::Utc::now(),
        };
        guard.update_state(deactivating_state)?;
        maybe_block_after_deactivating_state_transition()?;

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
        );

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
    /// Detach and remove any pivot staging left under the staging base.
    ///
    /// An overlay-incompatible target (VFAT `/boot`) is overlaid through a
    /// snapshot pivot: a tmpfs snapshot at `/run/nails-pivot/<name>-snapshot`, an
    /// overlay at `/run/nails-pivot/<name>` using it as the lower layer, and a bind
    /// of that overlay onto the target. The main unmount only takes the target
    /// bind down; the staging overlay and the snapshot tmpfs, and the directories
    /// holding them, stay behind and keep the hidden upper on the backend busy.
    ///
    /// Discover whatever is still mounted under the staging base and detach it —
    /// the staging overlay before the `-snapshot` tmpfs it stacks on — then remove
    /// the staging directories NAILS created, so no mount or path points back at
    /// the hidden session. Best-effort and a no-op when nothing pivoted.
    fn cleanup_pivot_staging<F: Filesystem>(&self, manager: &NailsManager<F>) {
        let fs = manager.filesystem();
        let hidden_root = manager.config().hidden_volume_root.clone();

        if let Ok(mounts) = fs.discover_nails_mounts(Some(&hidden_root)) {
            let mut staging = mounts.pivot_binds.clone();
            // The staging overlay stacks on the `-snapshot` tmpfs, so detach the
            // overlay first and the snapshot last.
            staging.sort_by_key(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().ends_with("-snapshot"))
                    .unwrap_or(false)
            });
            for target in &staging {
                if fs.unmount(target, false).is_err() {
                    let _ = fs.unmount(target, true);
                }
            }
        }

        // Remove the staging directories NAILS created. Best-effort: a non-empty
        // or already-gone directory is skipped, and a missing base is a no-op.
        let base = Path::new(crate::overlay::PIVOT_STAGING_BASE);
        if let Ok(children) = fs.list_directory(base) {
            for child in children {
                let _ = fs.remove_directory(&child);
            }
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

#[cfg(test)]
#[path = "deactivation_tests.rs"]
mod tests;
