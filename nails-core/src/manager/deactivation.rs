//! Deactivation logic for `NailsManager`
//!
//! Both `deactivate()` and `emergency_deactivate()` now route through
//! `DeactivationOrchestrator`, with thin wrappers for mode-specific pre/post work.

use super::{NailsManager, select_system_profile, start_service_and_socket};
use crate::cleanup::history::truncate_all_history_files;
#[cfg(not(test))]
use crate::deactivation::test_gate::should_skip_shell_cleanup_before_deactivation_gate;
#[cfg(not(test))]
use crate::process::kill_user_shells;
use crate::{CleanupConfig, DeactivationMode, Filesystem, NailsError, Result, SystemState};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const SYSTEMCTL_REBOOT_OVERRIDE_ENV: &str = "NAILS_SYSTEMCTL_PATH";
const REBOOT_BINARY_OVERRIDE_ENV: &str = "NAILS_REBOOT_PATH";
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

struct ProtectedShellPidEnvGuard {
    original: Option<std::ffi::OsString>,
}

impl ProtectedShellPidEnvGuard {
    #[cfg(not(test))]
    fn protect_current_process_tree() -> Self {
        let original = std::env::var_os(SHELL_CLEANUP_PROTECTED_PIDS_ENV);
        let mut protected_pids = current_process_ancestry();

        if let Some(existing) = &original {
            for pid in existing
                .to_string_lossy()
                .split(',')
                .filter_map(|value| value.trim().parse::<u32>().ok())
            {
                if !protected_pids.contains(&pid) {
                    protected_pids.push(pid);
                }
            }
        }

        let joined = protected_pids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");

        unsafe {
            std::env::set_var(SHELL_CLEANUP_PROTECTED_PIDS_ENV, joined);
        }

        Self { original }
    }

    #[cfg(test)]
    fn protect_current_process_tree() -> Self {
        Self {
            original: std::env::var_os(SHELL_CLEANUP_PROTECTED_PIDS_ENV),
        }
    }
}

impl Drop for ProtectedShellPidEnvGuard {
    fn drop(&mut self) {
        if let Some(value) = &self.original {
            unsafe {
                std::env::set_var(SHELL_CLEANUP_PROTECTED_PIDS_ENV, value);
            }
        } else {
            unsafe {
                std::env::remove_var(SHELL_CLEANUP_PROTECTED_PIDS_ENV);
            }
        }
    }
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
}

fn requires_decoy_restore<F: Filesystem>(manager: &NailsManager<F>) -> Result<bool> {
    let _ = manager.current_state()?;

    let cached = manager
        .cached_state
        .lock()
        .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;

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
        hidden_volume_path: manager.config().hidden_volume_root.clone(),
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

    let cached = manager
        .cached_state
        .lock()
        .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;

    let overlay_paths: Vec<PathBuf> = cached
        .as_ref()
        .map(|state_file| state_file.overlay_status.keys().cloned().collect())
        .unwrap_or_default();

    Ok(OverlayContext {
        nix_was_overlaid: overlay_paths.iter().any(|p| p == Path::new("/nix")),
    })
}

fn unmount_ephemeral_overlays<F: Filesystem>(manager: &NailsManager<F>) {
    if !manager.config.extended_overlays.enabled {
        return;
    }

    tracing::info!("Unmounting ephemeral overlays before deactivation");

    for ephemeral_dir in manager.config.extended_overlays.directories.iter().rev() {
        let dir_name = ephemeral_dir
            .path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();

        let mount_info = crate::overlay::PivotMountInfo {
            target: ephemeral_dir.path.clone(),
            staging: PathBuf::from(format!(
                "{}/{}",
                crate::overlay::PIVOT_STAGING_BASE,
                dir_name
            )),
            upper: PathBuf::from(format!("/run/nails/{}-ephemeral/upper", dir_name)),
            work: PathBuf::from(format!("/run/nails/{}-ephemeral/work", dir_name)),
            lower: ephemeral_dir.path.clone(),
            is_ephemeral: true,
        };

        if let Err(e) = crate::overlay::unmount_pivot_overlay(&manager.filesystem, &mount_info) {
            tracing::warn!(
                error = %e,
                path = %ephemeral_dir.path.display(),
                "Ephemeral overlay unmount failed (non-fatal)"
            );
        }
    }
}

fn verify_history_truncation<F: Filesystem>(manager: &NailsManager<F>) {
    let history_files = crate::cleanup::history::get_extended_history_files();
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

impl<F: Filesystem + 'static> NailsManager<F> {
    fn run_deactivation(
        manager_arc: Arc<Mutex<Self>>,
        kind: ManagerDeactivationKind,
    ) -> Result<()> {
        use crate::deactivation::DeactivationOrchestrator;

        let _protected_shell_pid_guard = ProtectedShellPidEnvGuard::protect_current_process_tree();

        if kind == ManagerDeactivationKind::Normal {
            let manager = manager_arc
                .lock()
                .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;

            let state = manager.current_state()?;
            if !matches!(state, SystemState::Active { .. }) {
                return Err(NailsError::InvalidState(
                    "Cannot deactivate: system is not in Active state".to_string(),
                ));
            }

            if requires_decoy_restore(&manager)?
                && select_system_profile(manager.filesystem())?.is_none()
            {
                return Err(NailsError::NixOSError(
                    "No system profile found. Cannot restore decoy configuration.".to_string(),
                ));
            }
        } else {
            let manager = manager_arc
                .lock()
                .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;

            let state = manager.current_state()?;
            if !matches!(state, SystemState::Active { .. }) {
                let message = if state == SystemState::Inactive {
                    "Cannot deactivate from state Inactive. Must be ACTIVE.".to_string()
                } else {
                    format!("Cannot deactivate from state {:?}. Must be ACTIVE.", state)
                };

                return Err(NailsError::InvalidState(message));
            }
        }

        let overlay_context = {
            let manager = manager_arc
                .lock()
                .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
            let context = inspect_overlay_context(&manager)?;
            unmount_ephemeral_overlays(&manager);
            context
        };

        if overlay_context.nix_was_overlaid {
            tracing::info!("Stopping nix-daemon before /nix overlay unmount...");
            let _ = crate::manager::helpers::ServiceController::stop_nix_daemon();

            tracing::info!("Unmounting /nix/store bind mount...");
            let manager = manager_arc
                .lock()
                .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
            manager
                .filesystem
                .unmount(Path::new("/nix/store"), false)
                .or_else(|graceful_error| {
                    tracing::warn!(
                        error = %graceful_error,
                        "Graceful /nix/store unmount failed, trying force unmount"
                    );
                    manager.filesystem.unmount(Path::new("/nix/store"), true)
                })?;
        }

        let cleanup_config = {
            let manager = manager_arc
                .lock()
                .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
            build_cleanup_config(&manager, kind)
        };

        #[cfg(not(test))]
        if should_skip_shell_cleanup_before_deactivation_gate() {
            tracing::info!(
                "Skipping pre-unmount shell cleanup because the deactivation test gate is armed"
            );
        } else {
            tracing::info!("Killing user shell processes immediately before overlay teardown");
            let report = kill_user_shells();
            tracing::info!(
                killed = report.killed.len(),
                failed = report.failed.len(),
                skipped = report.skipped.len(),
                "Shell cleanup complete"
            );
        }

        let orchestrator = DeactivationOrchestrator::new(Arc::clone(&manager_arc), cleanup_config)
            .with_mode(kind.orchestrator_mode())
            .with_switch_script_execution(kind == ManagerDeactivationKind::Normal)
            .with_decoy_profile_restore({
                let manager = manager_arc
                    .lock()
                    .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
                requires_decoy_restore(&manager)?
            });

        let result = orchestrator.run();

        if overlay_context.nix_was_overlaid {
            tracing::info!("Restarting nix-daemon...");
            start_service_and_socket("nix-daemon");
        }

        let _report = result?;

        if kind.requires_forensic_verification() {
            let manager = manager_arc
                .lock()
                .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;

            tracing::info!("Truncating all history files for forensic safety");
            let truncated = truncate_all_history_files(&manager.filesystem, true);
            tracing::info!(
                truncated_count = truncated.len(),
                "History truncation complete"
            );

            verify_history_truncation(&manager);
        }

        if kind.reboots_on_success() {
            let verbosity = manager_arc
                .lock()
                .map_err(|e| NailsError::LockPoisoned(e.to_string()))?
                .verbosity();

            if verbosity >= crate::verbosity::Verbosity::Normal {
                tracing::info!("Rebooting system...");
            }

            if !crate::runtime_safety::should_skip_host_interaction() {
                request_reboot()?;
            }
        }

        Ok(())
    }

    /// Deactivate NAILS using the shared deactivation orchestrator, then reboot.
    pub fn deactivate(manager_arc: Arc<Mutex<Self>>) -> Result<()> {
        Self::run_deactivation(manager_arc, ManagerDeactivationKind::Normal)
    }

    /// Emergency deactivation: thin wrapper around the shared orchestrator path.
    pub fn emergency_deactivate(manager_arc: Arc<Mutex<Self>>) -> Result<()> {
        Self::run_deactivation(manager_arc, ManagerDeactivationKind::Emergency)
    }
}

#[cfg(test)]
#[path = "deactivation_tests.rs"]
mod tests;
