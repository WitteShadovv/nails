//! Deactivation logic for `NailsManager`
//!
//! Both `deactivate()` and `emergency_deactivate()` now route through
//! `DeactivationOrchestrator`, with thin wrappers for mode-specific pre/post work.

use super::{NailsManager, select_system_profile, start_service_and_socket};
use crate::cleanup::history::truncate_all_history_files;
#[cfg(not(test))]
use crate::process::kill_user_shells;
use crate::{
    CleanupConfig, DeactivationMode, Filesystem, NailsError, Result, SystemState,
    verify_base_config_clean,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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
    etc_was_overlaid: bool,
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
        etc_was_overlaid: overlay_paths.iter().any(|p| p == Path::new("/etc")),
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
            upper: PathBuf::from(format!("/run/nails/{}-upper", dir_name)),
            work: PathBuf::from(format!("/run/nails/{}-work", dir_name)),
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
        }

        #[cfg(not(test))]
        {
            tracing::info!("Killing user shell processes before deactivation");
            let report = kill_user_shells();
            tracing::info!(
                killed = report.killed.len(),
                failed = report.failed.len(),
                skipped = report.skipped.len(),
                "Shell cleanup complete"
            );
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
            let _ = manager.filesystem.unmount(Path::new("/nix/store"), false);
        }

        let cleanup_config = {
            let manager = manager_arc
                .lock()
                .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
            build_cleanup_config(&manager, kind)
        };

        let orchestrator = DeactivationOrchestrator::new(Arc::clone(&manager_arc), cleanup_config)
            .with_mode(kind.orchestrator_mode())
            .with_switch_script_execution(kind == ManagerDeactivationKind::Emergency)
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

            if overlay_context.etc_was_overlaid {
                match verify_base_config_clean(&manager.filesystem) {
                    Ok(true) => {}
                    Ok(false) => {
                        return Err(NailsError::NixOSError(
                            "Base hardware-configuration.nix is not forensically clean".into(),
                        ));
                    }
                    Err(e) => return Err(e),
                }
            }
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
                std::process::Command::new("systemctl")
                    .arg("reboot")
                    .output()
                    .map_err(|e| {
                        NailsError::NixOSError(format!("Failed to execute reboot: {}", e))
                    })?;
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
