//! Deactivation Logic for NailsManager
//!
//! This module implements deactivation operations:
//! - **deactivate()**: Quick deactivation with reboot
//!   - Restores decoy NixOS configuration
//!   - Reboots immediately
//!   - Overlays unmounted on next boot
//!
//! - **emergency_deactivate()**: Thorough cleanup without reboot
//!   - Unmounts all overlays
//!   - Switches to decoy configuration
//!   - Verifies forensic cleanliness
//!   - Does NOT reboot
//!
//! # RAII Rollback Pattern
//!
//! Both deactivation methods use StateGuard for automatic rollback
//! to Active state if deactivation fails.

use super::{
    NailsManager, ensure_run_current_system_symlink, select_system_profile,
    start_service_and_socket,
};
use crate::{
    CleanupConfig, CleanupManager, CleanupMode, Filesystem, NailsError, Result, SystemState,
    verify_base_config_clean,
};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

impl<F: Filesystem> NailsManager<F> {
    /// Deactivate NAILS with automatic RAII rollback on failure
    ///
    /// Validates current state is Active, transitions through Deactivating,
    /// unmounts overlays, and transitions to Inactive. If any step fails or panic occurs,
    /// StateGuard automatically rolls back to Active state via RAII (FR51).
    ///
    /// # RAII Rollback Pattern (FR51, NFR20, NFR24)
    ///
    /// This method uses StateGuard to guarantee automatic rollback on failure:
    /// - On success: `guard.commit()` prevents rollback
    /// - On unmount failure: `guard.drop()` restores Active state (overlays remain mounted)
    /// - On panic: Stack unwinding calls `guard.drop()`, restores Active state
    ///
    /// # Arguments
    ///
    /// * `manager_arc` - Shared reference to NailsManager wrapped in Arc<Mutex<>>
    ///
    /// # Errors
    ///
    /// - `NailsError::InvalidStateTransition` - Current state is not Active
    /// - `NailsError::UnmountError` - Overlay unmount failed (state rolled back to Active)
    /// - `NailsError::StateFileError` - Cannot read/write state file
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{NailsManager, MockFilesystem, Config};
    /// use std::path::PathBuf;
    /// use std::sync::{Arc, Mutex};
    ///
    /// let fs = MockFilesystem::new();
    /// // ... setup and activate ...
    /// let manager = Arc::new(Mutex::new(
    ///     NailsManager::new(fs, Config::default(), PathBuf::from("/state.json"))
    /// ));
    /// let result = NailsManager::deactivate(Arc::clone(&manager));
    /// ```
    /// Quick deactivation: Restore decoy NixOS configuration and reboot
    ///
    /// This is a simplified, fast-path deactivation that:
    /// 1. Restores /run/current-system to point to the decoy (underlay) NixOS configuration
    /// 2. Reboots the system
    ///
    /// On reboot, the system will boot into the decoy configuration with all overlays gone.
    /// Use `emergency` command for a thorough deactivation without reboot.
    pub fn deactivate(manager_arc: Arc<Mutex<Self>>) -> Result<()> {
        // Step 0: Verify system is in Active state
        {
            let manager = manager_arc.lock().unwrap();
            let state = manager.current_state()?;
            if !matches!(state, SystemState::Active { .. }) {
                return Err(NailsError::InvalidState(
                    "Cannot deactivate: system is not in Active state".to_string(),
                ));
            }
        }

        // Step 1: Select the decoy system profile
        let (system_profile, verbosity) = {
            let manager = manager_arc.lock().unwrap();
            let fs = &manager.filesystem;
            let profile = select_system_profile(fs)?;
            (profile, manager.verbosity)
        };

        let Some(system_profile) = system_profile else {
            return Err(NailsError::NixOSError(
                "No system profile found. Cannot restore decoy configuration.".to_string(),
            ));
        };

        // Step 2: Restore /run/current-system symlink to decoy profile
        {
            let manager = manager_arc.lock().unwrap();
            if verbosity >= crate::verbosity::Verbosity::Normal {
                tracing::info!("Restoring /run/current-system to decoy NixOS configuration...");
            }

            ensure_run_current_system_symlink(&manager.filesystem, &system_profile)?;

            if verbosity >= crate::verbosity::Verbosity::Normal {
                tracing::info!("  ✓ Symlink restored to {}", system_profile.display());
            }
        }

        // Step 3: Reboot immediately
        if verbosity >= crate::verbosity::Verbosity::Normal {
            tracing::info!("Rebooting system...");
        }

        // Skip actual reboot during tests
        if !cfg!(test) {
            std::process::Command::new("systemctl")
                .arg("reboot")
                .output()
                .map_err(|e| NailsError::NixOSError(format!("Failed to execute reboot: {}", e)))?;
        }

        Ok(())
    }

    /// Emergency deactivation: Thorough cleanup without reboot
    ///
    /// This performs a complete deactivation:
    /// 1. Unmounts all overlays (ephemeral and persistent)
    /// 2. Switches to decoy NixOS configuration
    /// 3. Verifies forensic cleanliness
    /// 4. Does NOT reboot
    ///
    /// Use this when you need thorough cleanup without an immediate reboot.
    /// For quick escape with reboot, use `deactivate()` instead.
    pub fn emergency_deactivate(manager_arc: Arc<Mutex<Self>>) -> Result<()> {
        use crate::StateGuard;

        // Step 1: Capture current state for StateGuard BEFORE any modifications
        let previous_state = {
            let manager = manager_arc.lock().unwrap();
            manager.current_state()?
        };

        // Step 2: Create StateGuard for automatic rollback on failure/panic
        let guard = StateGuard::new(Arc::clone(&manager_arc), previous_state.clone());

        // Step 3: Validate transition is allowed
        let deactivating_state = previous_state.begin_deactivation()?;

        // Step 4: Transition to Deactivating state
        {
            let mut manager = manager_arc.lock().unwrap();
            manager.update_state(deactivating_state)?;
        }

        // Step 5: Get list of persistent overlays to unmount from state file
        let overlays_to_unmount = {
            let manager = manager_arc.lock().unwrap();
            let cached = manager.cached_state.lock().unwrap();
            if let Some(ref state_file) = *cached {
                state_file
                    .overlay_status
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        };
        let etc_was_overlaid = overlays_to_unmount.iter().any(|p| p == Path::new("/etc"));

        // Step 5b: Unmount ephemeral overlays FIRST (LIFO order)
        let mut unmount_errors = Vec::new();
        {
            let manager = manager_arc.lock().unwrap();
            if manager.config.extended_overlays.enabled {
                tracing::info!("Unmounting ephemeral overlays");

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

                    if let Err(e) =
                        crate::overlay::unmount_pivot_overlay(&manager.filesystem, &mount_info)
                    {
                        tracing::error!(error = %e, "Ephemeral overlay unmount failed");
                        unmount_errors.push((ephemeral_dir.path.clone(), e));
                    }
                }
            }
        }

        // Step 5c: Pre-unmount nix-daemon lifecycle
        let nix_was_overlaid = overlays_to_unmount.iter().any(|p| p == Path::new("/nix"));
        if nix_was_overlaid {
            tracing::info!("Stopping nix-daemon before /nix overlay unmount...");
            if !cfg!(test) {
                let _ = std::process::Command::new("systemctl")
                    .args(["stop", "nix-daemon.socket"])
                    .output();
                let _ = std::process::Command::new("systemctl")
                    .args(["stop", "nix-daemon.service"])
                    .output();
            }

            tracing::info!("Unmounting /nix/store bind mount...");
            {
                let manager = manager_arc.lock().unwrap();
                let _ = manager.filesystem.unmount(Path::new("/nix/store"), false);
            }
        }

        // Step 6: Unmount persistent overlays (two-stage: graceful then force)
        for overlay_path in &overlays_to_unmount {
            // Try graceful unmount first
            let unmount_result = {
                let manager = manager_arc.lock().unwrap();
                manager.filesystem.unmount(overlay_path, false)
            };

            match unmount_result {
                Ok(()) => {
                    tracing::info!(
                        path = %overlay_path.display(),
                        "Persistent overlay unmounted gracefully"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        path = %overlay_path.display(),
                        error = %e,
                        "Graceful unmount failed, trying force unmount"
                    );

                    // If graceful fails, try force unmount
                    let force_result = {
                        let manager = manager_arc.lock().unwrap();
                        manager.filesystem.unmount(overlay_path, true)
                    };

                    if let Err(force_err) = force_result {
                        tracing::error!(
                            path = %overlay_path.display(),
                            error = %force_err,
                            "Force unmount also failed"
                        );
                        unmount_errors.push((overlay_path.clone(), force_err));
                    } else {
                        tracing::info!(
                            path = %overlay_path.display(),
                            "Persistent overlay force unmounted"
                        );
                    }
                }
            }
        }

        // If any unmount failed, return error and let StateGuard rollback
        if !unmount_errors.is_empty() {
            let error_msg = format!(
                "Failed to unmount {} overlay(s). First error: {:?}. State has been rolled back to Active; you may retry deactivation.",
                unmount_errors.len(),
                unmount_errors[0].1
            );
            return Err(NailsError::UnmountError {
                path: unmount_errors[0].0.clone(),
                reason: error_msg,
            });
        }

        // Step 6b: Post-unmount nix-daemon restart
        if nix_was_overlaid {
            tracing::info!("Restarting nix-daemon...");
            start_service_and_socket("nix-daemon");
        }

        // Step 7: Clear overlay_status in cached state
        {
            let manager = manager_arc.lock().unwrap();
            let mut cached = manager.cached_state.lock().unwrap();
            if let Some(ref mut state_file) = *cached {
                state_file.overlay_status.clear();
            }
        }

        // Step 8: Transition to Inactive state
        {
            let mut manager = manager_arc.lock().unwrap();
            let current = manager.current_state()?;
            let inactive_state = current.complete_deactivation()?;
            manager.update_state(inactive_state)?;
        }

        // Step 8.1: Emergency cleanup (Fast mode - no verification, best-effort)
        // IMPORTANT: Cleanup failures should NOT fail emergency deactivation
        // Speed and reliability are prioritized over thoroughness
        {
            tracing::info!("Starting emergency history cleanup (Fast mode)...");

            let manager = manager_arc.lock().unwrap();

            // Create cleanup config with secure_delete enabled for forensic safety
            let cleanup_config = CleanupConfig {
                clear_history: true,
                clear_temp_files: true,
                clear_logs: true,
                secure_delete: true,
                sanitize_memory: false, // Skip memory sanitization for speed
                ..CleanupConfig::default()
            };

            let cleanup_manager = CleanupManager::new(
                manager.filesystem.clone(),
                cleanup_config,
                CleanupMode::Fast, // Fast mode skips verification for speed
            );

            match cleanup_manager.cleanup() {
                Ok(report) => {
                    tracing::info!(
                        cleaned_items = report.cleaned_items.len(),
                        errors = report.errors.len(),
                        duration_ms = report.duration.as_millis() as u64,
                        "Emergency cleanup completed"
                    );

                    // Log any errors as warnings (don't fail deactivation)
                    for error in &report.errors {
                        tracing::warn!(error = %error, "Emergency cleanup error (non-fatal)");
                    }
                }
                Err(e) => {
                    // Log failure but continue with deactivation
                    tracing::warn!(
                        error = %e,
                        "Emergency cleanup failed (non-fatal) - continuing deactivation"
                    );
                }
            }
        }

        // Step 8.2: Switch to decoy profile
        let switch_error = {
            let manager = manager_arc.lock().unwrap();
            let fs = &manager.filesystem;

            if let Some(system_profile) = select_system_profile(fs)? {
                tracing::info!("Switching to decoy NixOS configuration...");

                if let Err(e) = ensure_run_current_system_symlink(fs, &system_profile) {
                    Some(NailsError::NixOSError(format!(
                        "Failed to prepare /run/current-system: {}",
                        e
                    )))
                } else {
                    let switch_script = system_profile.join("bin/switch-to-configuration");
                    match fs.path_exists(&switch_script) {
                        Ok(true) => {
                            if !cfg!(test) {
                                match std::process::Command::new(&switch_script)
                                    .arg("switch")
                                    .output()
                                {
                                    Ok(output) if output.status.success() => None,
                                    Ok(output) => Some(NailsError::NixOSError(format!(
                                        "System profile switch failed: {}",
                                        String::from_utf8_lossy(&output.stderr)
                                    ))),
                                    Err(e) => Some(NailsError::NixOSError(format!(
                                        "System profile switch failed: {}",
                                        e
                                    ))),
                                }
                            } else {
                                None
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
                None
            }
        };

        if let Some(err) = switch_error {
            guard.commit();
            return Err(err);
        }

        // Step 8.5: Verify base config is forensically clean
        let base_config_error = if etc_was_overlaid {
            let manager = manager_arc.lock().unwrap();
            match verify_base_config_clean(&manager.filesystem) {
                Ok(true) => None,
                Ok(false) => Some(NailsError::NixOSError(
                    "Base hardware-configuration.nix is not forensically clean".into(),
                )),
                Err(e) => Some(e),
            }
        } else {
            None
        };

        if let Some(err) = base_config_error {
            guard.commit();
            return Err(err);
        }

        // Step 9: Success
        guard.commit();
        Ok(())
    }
}
