//! Deactivation logic for `NailsManager`
//!
//! Both `deactivate()` and `emergency_deactivate()` now route through
//! `DeactivationOrchestrator`, with thin wrappers for mode-specific pre/post work.

use super::NailsManager;
use super::{ensure_run_current_system_symlink, select_system_profile, start_service_and_socket};
use crate::cleanup::history::{history_cleanup_homes, truncate_all_history_files_for_homes};
use crate::deactivation::test_gate::maybe_block_after_deactivating_state_transition;
#[cfg(not(test))]
use crate::deactivation::test_gate::should_skip_shell_cleanup_before_deactivation_gate;
use crate::deactivation::{DeactivationReport, PostUnmountCleanupReport};
#[cfg(not(test))]
use crate::process::kill_user_shells;
use crate::{
    CleanupConfig, CleanupManager, CleanupMode, CleanupReport, Filesystem, NailsError, Result,
    StateGuard, SystemState,
};
use std::path::{Path, PathBuf};
use std::time::Instant;

// Test-only reboot-dispatch overrides. Compiled in only under the `test-hooks`
// feature (and this crate's own `cfg(test)` builds), so a shipped binary carries
// neither the strings nor the branch that reads them, and always dispatches the
// real reboot commands.
#[cfg(any(test, feature = "test-hooks"))]
const SYSTEMCTL_REBOOT_OVERRIDE_ENV: &str = "NAILS_SYSTEMCTL_PATH";
#[cfg(any(test, feature = "test-hooks"))]
const REBOOT_BINARY_OVERRIDE_ENV: &str = "NAILS_REBOOT_PATH";
// The protected-PID handoff is a test-only injection point; nothing sets it in
// production, so it is compiled in only alongside the other hooks.
#[cfg(all(not(test), feature = "test-hooks"))]
const SHELL_CLEANUP_PROTECTED_PIDS_ENV: &str = "NAILS_SHELL_CLEANUP_PROTECTED_PIDS";

#[derive(Debug, Clone)]
struct RebootCommand {
    program: std::ffi::OsString,
    args: Vec<std::ffi::OsString>,
}

impl RebootCommand {
    fn systemctl<P: Into<std::ffi::OsString>>(program: P) -> Self {
        Self {
            program: program.into(),
            args: vec![std::ffi::OsString::from("reboot")],
        }
    }

    fn reboot<P: Into<std::ffi::OsString>>(program: P) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
        }
    }

    fn display(&self) -> String {
        let program = std::path::Path::new(&self.program).display().to_string();
        if self.args.is_empty() {
            program
        } else {
            format!(
                "{} {}",
                program,
                self.args
                    .iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        }
    }
}

fn reboot_candidates() -> Vec<RebootCommand> {
    #[cfg(any(test, feature = "test-hooks"))]
    {
        let systemctl_override = std::env::var_os(SYSTEMCTL_REBOOT_OVERRIDE_ENV);
        let reboot_override = std::env::var_os(REBOOT_BINARY_OVERRIDE_ENV);

        if systemctl_override.is_some() || reboot_override.is_some() {
            let mut candidates = Vec::new();

            if let Some(path) = systemctl_override {
                candidates.push(RebootCommand::systemctl(path));
            }

            if let Some(path) = reboot_override {
                candidates.push(RebootCommand::reboot(path));
            }

            return candidates;
        }
    }

    vec![
        RebootCommand::systemctl("/run/current-system/sw/bin/systemctl"),
        RebootCommand::systemctl("systemctl"),
        RebootCommand::reboot("/run/current-system/sw/bin/reboot"),
        RebootCommand::reboot("reboot"),
    ]
}

fn format_command_failure(command: &RebootCommand, output: &std::process::Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    let mut details = vec![format!(
        "{} exited with status {}",
        command.display(),
        output.status
    )];

    if !stdout.is_empty() {
        details.push(format!("stdout: {}", stdout));
    }

    if !stderr.is_empty() {
        details.push(format!("stderr: {}", stderr));
    }

    details.join("; ")
}

fn dispatch_reboot_candidates(candidates: Vec<RebootCommand>) -> Result<()> {
    let mut failures = Vec::new();

    for candidate in candidates {
        let command_display = candidate.display();

        match std::process::Command::new(&candidate.program)
            .args(&candidate.args)
            .output()
        {
            Ok(output) if output.status.success() => {
                tracing::info!(command = %command_display, "Reboot command dispatched");
                return Ok(());
            }
            Ok(output) => {
                let failure = format_command_failure(&candidate, &output);
                tracing::warn!(command = %command_display, error = %failure, "Reboot command failed");
                failures.push(failure);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tracing::debug!(command = %command_display, "Reboot command not available");
            }
            Err(error) => {
                let failure = format!("{} failed to execute: {}", command_display, error);
                tracing::warn!(command = %command_display, error = %error, "Reboot command execution failed");
                failures.push(failure);
            }
        }
    }

    if failures.is_empty() {
        Err(NailsError::NixOSError(
            "Failed to trigger reboot: no usable reboot command was found".to_string(),
        ))
    } else {
        Err(NailsError::NixOSError(format!(
            "Failed to trigger reboot: {}",
            failures.join(" | ")
        )))
    }
}

fn request_reboot() -> Result<()> {
    if crate::runtime_safety::should_skip_host_interaction() {
        return Err(NailsError::NixOSError(
            "Refusing to trigger reboot in test or runtime-safety mode".to_string(),
        ));
    }

    dispatch_reboot_candidates(reboot_candidates())
}

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
}

impl ManagerDeactivationKind {
    fn orchestrator_mode(self) -> DeactivationMode {
        match self {
            Self::Normal => DeactivationMode::Normal,
            Self::Emergency => DeactivationMode::Emergency,
        }
    }

    fn requires_forensic_verification(self) -> bool {
        matches!(self, Self::Emergency)
    }

    fn reboots_on_success(self) -> bool {
        matches!(self, Self::Normal)
    }
}

#[derive(Debug, Default)]
struct OverlayContext {
    nix_was_overlaid: bool,
    var_was_overlaid: bool,
}

fn requires_decoy_restore<F: Filesystem>(manager: &NailsManager<F>) -> Result<bool> {
    let _ = manager.current_state()?;

    let cached = manager.cached_state.borrow();

    Ok(cached
        .as_ref()
        .and_then(|state_file| state_file.nixos_generation.as_ref())
        .is_some())
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

    Ok(OverlayContext {
        nix_was_overlaid: overlay_paths.iter().any(|p| p == Path::new("/nix")),
        var_was_overlaid: overlay_paths.iter().any(|p| p == Path::new("/var")),
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
    fn run_deactivation(&mut self, kind: ManagerDeactivationKind) -> Result<()> {
        // Preconditions: both modes require an Active system; only the messages differ.
        let state = self.current_state()?;
        if !matches!(state, SystemState::Active { .. }) {
            let message = match kind {
                ManagerDeactivationKind::Normal => {
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

        if kind == ManagerDeactivationKind::Normal
            && requires_decoy_restore(self)?
            && select_system_profile(self.filesystem())?.is_none()
        {
            return Err(NailsError::NixOSError(
                "No system profile found. Cannot restore decoy configuration.".to_string(),
            ));
        }

        let overlay_context = inspect_overlay_context(self)?;

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
        }

        let cleanup_config = build_cleanup_config(self, kind);

        #[cfg(not(test))]
        if should_skip_shell_cleanup_before_deactivation_gate() {
            tracing::info!(
                "Skipping pre-unmount shell cleanup because the deactivation test gate is armed"
            );
        } else {
            tracing::info!("Killing user shell processes immediately before overlay teardown");
            let protected = collect_protected_shell_pids();
            let report = kill_user_shells(&protected);
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
            .with_switch_script_execution(kind == ManagerDeactivationKind::Normal)
            .with_decoy_profile_restore(restore_decoy_profile);

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
            start_service_and_socket("systemd-journald");
        }

        let _report = result?;

        if kind.requires_forensic_verification() {
            tracing::info!("Truncating all history files for forensic safety");
            let truncated = truncate_all_history_files_for_homes(
                &self.filesystem,
                &history_cleanup_homes(),
                true,
            );
            tracing::info!(
                truncated_count = truncated.len(),
                "History truncation complete"
            );

            verify_history_truncation(self);
        }

        if kind.reboots_on_success() {
            if self.verbosity() >= crate::verbosity::Verbosity::Normal {
                tracing::info!("Rebooting system...");
            }

            if !crate::runtime_safety::should_skip_host_interaction() {
                request_reboot()?;
            }
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
/// 5. Decoy system-profile switch.
///
/// A failure in steps 1-2 (before any overlay is detached) rolls the state back
/// to ACTIVE on drop. Once step 3 has detached any overlay the teardown never
/// goes back: if some targets cannot be unmounted it records DEGRADED and
/// returns an error, and it never remounts what it has already detached (a
/// remount would route hidden-session writes onto the decoy disk).
pub struct DeactivationOrchestrator {
    cleanup_config: CleanupConfig,
    mode: DeactivationMode,
    execute_switch_script: bool,
    restore_decoy_profile: bool,
}

impl DeactivationOrchestrator {
    /// Create a new orchestrator from a cleanup configuration.
    pub fn new(cleanup_config: CleanupConfig) -> Self {
        Self {
            cleanup_config,
            mode: DeactivationMode::Normal,
            execute_switch_script: true,
            restore_decoy_profile: true,
        }
    }

    /// Set the deactivation mode (builder pattern).
    pub fn with_mode(mut self, mode: DeactivationMode) -> Self {
        self.mode = mode;
        self
    }

    /// Control whether the decoy switch script is executed after symlink preparation.
    pub(crate) fn with_switch_script_execution(mut self, execute_switch_script: bool) -> Self {
        self.execute_switch_script = execute_switch_script;
        self
    }

    /// Control whether the decoy profile restore path runs at all.
    pub fn with_decoy_profile_restore(mut self, restore_decoy_profile: bool) -> Self {
        self.restore_decoy_profile = restore_decoy_profile;
        self
    }

    /// Execute deactivation against the borrowed manager.
    ///
    /// Returns a [`DeactivationReport`] on success. On failure the state is
    /// either rolled back to ACTIVE (cleanup failed before any unmount), left
    /// INACTIVE (only the decoy switch failed), or recorded as DEGRADED with
    /// [`NailsError::DeactivationIncomplete`] (some overlays could not be
    /// unmounted) — never ACTIVE once any overlay has been detached.
    pub fn run<F: Filesystem>(&self, manager: &mut NailsManager<F>) -> Result<DeactivationReport> {
        let start = Instant::now();

        tracing::info!(phase = "deactivation", "Deactivation started");

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

        // Step 5: Switch to the newest available base system generation (decoy).
        let switch_error = if !self.restore_decoy_profile {
            None
        } else if let Some(system_profile) = select_system_profile(guard.filesystem())? {
            tracing::info!("Switching to decoy NixOS configuration...");

            if let Err(e) = ensure_run_current_system_symlink(guard.filesystem(), &system_profile) {
                Some(NailsError::NixOSError(format!(
                    "Failed to prepare /run/current-system for NixOS switch: {}",
                    e
                )))
            } else if !self.execute_switch_script {
                None
            } else {
                let switch_script = system_profile.join("bin/switch-to-configuration");
                match guard.filesystem().path_exists(&switch_script) {
                    Ok(true) => {
                        if crate::runtime_safety::should_skip_host_interaction() {
                            None
                        } else {
                            match std::process::Command::new(&switch_script)
                                .arg("switch")
                                .output()
                            {
                                Ok(output) => {
                                    if output.status.success() {
                                        None
                                    } else {
                                        Some(NailsError::NixOSError(format!(
                                            "System profile switch failed: {}",
                                            String::from_utf8_lossy(&output.stderr)
                                        )))
                                    }
                                }
                                Err(e) => Some(NailsError::NixOSError(format!(
                                    "System profile switch failed: {}",
                                    e
                                ))),
                            }
                        }
                    }
                    Ok(false) => Some(NailsError::NixOSError(format!(
                        "System profile switch script missing: {}",
                        switch_script.display()
                    ))),
                    Err(e) => Some(e),
                }
            }
        } else {
            Some(NailsError::NixOSError(
                "No system profile available for decoy switch".into(),
            ))
        };

        if let Some(err) = switch_error {
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

        let cleaned_items = truncate_all_history_files_for_homes(
            manager.filesystem(),
            &history_cleanup_homes(),
            true,
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
