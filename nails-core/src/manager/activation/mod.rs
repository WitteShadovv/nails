//! Activation Logic for NailsManager
//!
//! This module implements the 10-step activation flow that:
//! 1. Validates system state
//! 2. Runs preflight checks
//! 3. Handles session management
//! 4. Builds NixOS configuration (if enabled)
//! 5. Mounts overlays with RAII rollback
//! 6. Switches to active NixOS generation
//! 7. Restarts services
//! 8. Updates state to Active
//!
//! # RAII Rollback Pattern
//!
//! The activation process uses StateGuard and MountTracker for automatic
//! rollback on failure, ensuring the system doesn't get left in a partially
//! activated state.

#[allow(unused_imports)]
use super::{
    MountInfo, MountType, build_overlay_targets, clean_stale_network_config, create_overlay_config,
    ensure_run_current_system_symlink, select_system_profile, start_service_and_socket,
};
#[allow(unused_imports)]
use super::{MountTracker, NailsManager};
use crate::notification::{Notification, write_notification};
use crate::{Filesystem, NailsError, Result, Verbosity};
use std::path::Path;
use std::sync::{Arc, Mutex};

mod gate;
mod guards;
mod nixos_build;
mod nixos_switch;
mod overlay_mount;
mod preflight;
mod rollback;
mod session;

#[cfg(test)]
mod tests;

use gate::maybe_block_after_activating_state_transition;
use guards::SessionRestartGuard;
use rollback::rollback_overlay_mounts_after_activation_failure;

#[cfg(not(test))]
fn restart_session_after_success(plan: &crate::process::SessionRestartPlan) -> Result<()> {
    // Starting the display manager is the authoritative restart path for a
    // killed graphical session. On real systems it will recreate the user
    // manager as part of the login/session lifecycle, so explicitly starting
    // user@UID.service first causes an observable double bounce in e2e.
    if plan.display_manager.is_none()
        && let Some(uid) = plan.target_uid
    {
        crate::process::restart_user_manager(uid)?;
    }

    if let Some(dm_name) = plan.display_manager.as_deref() {
        crate::process::restart_display_manager(dm_name)?;
    }

    Ok(())
}

#[cfg(test)]
fn restart_session_after_success(_plan: &crate::process::SessionRestartPlan) -> Result<()> {
    Ok(())
}

impl<F: Filesystem> NailsManager<F> {
    pub fn activate(manager_arc: Arc<Mutex<Self>>, no_preflight: bool) -> Result<()> {
        // Use default options for backward compatibility with tests
        let options = crate::ActivateOptions::default();
        Self::activate_with_options(manager_arc, options, no_preflight)
    }

    /// Activate overlays with custom activation options
    ///
    /// Extended version of activate() that accepts ActivateOptions for controlling:
    /// - Session management (--kill-session)
    /// - Process restart behavior (risky process prompts)
    /// - Pivot mount policy (--accept-pivot-risks, --no-pivot)
    /// - User interaction (--yes to skip prompts)
    ///
    /// Story 4.15: User Prompts and CLI Flags for Overlay Strategy
    ///
    /// # Arguments
    ///
    /// * `manager_arc` - Shared reference to NailsManager
    /// * `options` - Activation options controlling behavior
    /// * `no_preflight` - Skip pre-flight checks (expert override)
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{ActivateOptions, NailsManager, MockFilesystem, Config};
    /// use std::path::PathBuf;
    /// use std::sync::{Arc, Mutex};
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    /// let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));
    ///
    /// let options = ActivateOptions {
    ///     no_pivot: true,  // Strict security mode
    ///     ..Default::default()
    /// };
    ///
    /// let result = NailsManager::activate_with_options(Arc::clone(&manager), options, false);
    /// ```
    pub fn activate_with_options(
        manager_arc: Arc<Mutex<Self>>,
        options: crate::ActivateOptions,
        no_preflight: bool,
    ) -> Result<()> {
        use crate::{StateGuard, Stopwatch};

        let total_timer = Stopwatch::start();

        // Validate options first
        options.validate()?;

        // Step 1: Capture current state and verbosity for progress logging
        let (previous_state, verbosity) = {
            let manager = manager_arc
                .lock()
                .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
            (manager.current_state()?, manager.verbosity)
        };

        // Step 2: Idempotent check - if already active, return early (AC: 7)
        if previous_state.is_active() {
            if verbosity >= Verbosity::Normal {
                tracing::info!(event = "result", state = ?previous_state, "System already active, nothing to do");
            }
            return Ok(());
        }

        // Story 9.3 AC#1: Log activation started with structured state field
        tracing::info!(event = "activation_started", state_from = ?previous_state, "Activation started");

        // Progress: Step 1 — Preflight checks
        if verbosity >= Verbosity::Normal {
            tracing::info!(
                event = "progress",
                phase = "preflight",
                current = 1,
                total = 6,
                "[1/6] Running preflight checks..."
            );
        }

        // Step 2.75 & 3: Stage config and run preflight checks before any session disruption
        {
            let manager = manager_arc
                .lock()
                .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
            manager.run_preflight_phase(
                no_preflight,
                options.overlay_only,
                verbosity,
                options.pre_activation_cleanup,
            )?;
        }

        // Progress: Step 2 — Session management
        if verbosity >= Verbosity::Normal {
            if no_preflight {
                tracing::info!(
                    event = "progress",
                    phase = "session_management",
                    current = 2,
                    total = 6,
                    "[2/6] Preparing session management (--no-preflight)"
                );
            } else {
                tracing::info!(
                    event = "progress",
                    phase = "session_management",
                    current = 2,
                    total = 6,
                    "[2/6] Preparing session management..."
                );
            }
        }

        // Step 3.5: Handle --kill-session flag (Story 4.15, AC8)
        let restart_plan = Self::handle_session_kill(verbosity, &options)?;

        // Auto-restart session if we exit early with an error after killing it.
        let mut session_restart_guard = SessionRestartGuard::new(restart_plan.clone());

        // Step 4: Create StateGuard for automatic rollback on failure/panic
        let guard = StateGuard::new(Arc::clone(&manager_arc), previous_state.clone());

        // Step 5: Validate transition is allowed
        let activating_state = previous_state.begin_activation()?;

        // Step 6: Transition to Activating state
        {
            let mut manager = manager_arc
                .lock()
                .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
            manager.update_state(activating_state)?;
        }

        maybe_block_after_activating_state_transition()?;

        // Progress: Step 3 — Build NixOS profile
        if verbosity >= Verbosity::Normal {
            tracing::info!(
                event = "progress",
                phase = "nixos_build",
                current = 3,
                total = 6,
                "[3/6] Building NixOS configuration..."
            );
        }

        // Step 7: Build NixOS profile (if NixOSBuilder configured)
        let (generation, new_fingerprint) = {
            let manager = manager_arc
                .lock()
                .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
            manager.build_nixos_profile(verbosity)?
        };

        // Progress: Step 4 — Mount overlays
        if verbosity >= Verbosity::Normal {
            tracing::info!(
                event = "progress",
                phase = "overlay_mount",
                current = 4,
                total = 6,
                "[4/6] Mounting overlays..."
            );
        }

        // Step 8: Mount persistent and ephemeral overlays
        let mount_timer = Stopwatch::start();
        let (direct_mounts, pivot_mounts, pivot_targets, mounted_overlays) = {
            let manager = manager_arc
                .lock()
                .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
            manager.mount_overlays(&options, verbosity)?
        };

        // Paths where pivot mounts are acceptable and don't degrade security.
        // /boot is whitelisted because it contains only the bootloader and kernels,
        // which are integrity-verified at boot time.
        const PIVOT_SECURITY_WHITELIST: &[&str] = &["/boot"];

        let all_pivots_whitelisted = !pivot_targets.is_empty()
            && pivot_targets
                .iter()
                .all(|t| PIVOT_SECURITY_WHITELIST.iter().any(|w| t == Path::new(w)));

        let security_status = if pivot_mounts == 0 || all_pivots_whitelisted {
            "OPTIMAL"
        } else {
            "DEGRADED"
        };

        if verbosity >= Verbosity::Normal {
            tracing::info!(
                step = "mount_overlays",
                duration_ms = mount_timer.elapsed().as_millis() as u64,
                direct_mounts = direct_mounts,
                pivot_mounts = pivot_mounts,
                "✓ All overlays mounted ({}) – {} direct, {} pivot – Security: {}",
                mount_timer,
                direct_mounts,
                pivot_mounts,
                security_status
            );
        }

        // Write overlay status notification (best-effort)
        {
            let manager = manager_arc
                .lock()
                .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
            let notif = Notification {
                title: "NAILS Overlay Active".to_string(),
                body: format!(
                    "Security: {} — {} overlay(s) mounted ({} direct, {} pivot)",
                    security_status,
                    direct_mounts + pivot_mounts,
                    direct_mounts,
                    pivot_mounts
                ),
                urgency: "normal".to_string(),
                icon: Some(
                    if security_status == "OPTIMAL" {
                        "security-high"
                    } else {
                        "security-medium"
                    }
                    .to_string(),
                ),
                created_at: chrono::Utc::now().to_rfc3339(),
            };
            if let Err(e) = write_notification(&manager.config().hidden_volume_root, &notif) {
                tracing::warn!("Failed to write overlay status notification: {}", e);
            }
        }

        // Progress: Step 5 — Switch NixOS profile
        if verbosity >= Verbosity::Normal {
            tracing::info!(
                event = "progress",
                phase = "profile_switch",
                current = 5,
                total = 6,
                "[5/6] Switching NixOS profile..."
            );
        }

        // Step 9: Switch NixOS profile
        {
            let manager = manager_arc
                .lock()
                .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
            let switch_result =
                manager.switch_nixos_profile(&generation, &new_fingerprint, verbosity);
            let hidden_root = manager.config().hidden_volume_root.clone();
            drop(manager);

            match switch_result {
                Ok(()) => {
                    // Write rebuild success notification (best-effort)
                    let notif = Notification {
                        title: "NixOS Rebuild Complete".to_string(),
                        body: "System profile switched successfully.".to_string(),
                        urgency: "low".to_string(),
                        icon: Some("system-software-update".to_string()),
                        created_at: chrono::Utc::now().to_rfc3339(),
                    };
                    if let Err(e) = write_notification(&hidden_root, &notif) {
                        tracing::warn!("Failed to write rebuild success notification: {}", e);
                    }
                }
                Err(e) => {
                    // Write rebuild failure notification (best-effort)
                    let error_msg = e.to_string();
                    let truncated = if error_msg.len() > 200 {
                        let boundary = error_msg
                            .char_indices()
                            .map(|(i, _)| i)
                            .take_while(|&i| i <= 200)
                            .last()
                            .unwrap_or(0);
                        format!("{}…", &error_msg[..boundary])
                    } else {
                        error_msg
                    };
                    let notif = Notification {
                        title: "NixOS Rebuild Failed".to_string(),
                        body: truncated,
                        urgency: "critical".to_string(),
                        icon: Some("dialog-error".to_string()),
                        created_at: chrono::Utc::now().to_rfc3339(),
                    };
                    if let Err(write_err) = write_notification(&hidden_root, &notif) {
                        tracing::warn!(
                            "Failed to write rebuild failure notification: {}",
                            write_err
                        );
                    }

                    let cleanup_result = {
                        let manager = manager_arc
                            .lock()
                            .map_err(|lock_err| NailsError::LockPoisoned(lock_err.to_string()))?;
                        rollback_overlay_mounts_after_activation_failure(
                            &manager,
                            &mounted_overlays,
                        )
                    };
                    if let Err(cleanup_err) = cleanup_result {
                        tracing::error!(
                            error = %cleanup_err,
                            rollback = true,
                            "Activation rollback cleanup failed after NixOS switch error"
                        );
                        return Err(cleanup_err);
                    }

                    return Err(e);
                }
            }
        }

        // Progress: Step 6 — Finalize activation
        if verbosity >= Verbosity::Normal {
            tracing::info!(
                event = "progress",
                phase = "finalize",
                current = 6,
                total = 6,
                "[6/6] Finalizing activation..."
            );
        }

        // Step 10: Transition to Active state (Story 4.7, AC1, Task 3.4)
        {
            let mut manager = manager_arc
                .lock()
                .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
            let current = manager.current_state()?;
            let active_state = current.complete_activation(mounted_overlays)?;
            manager.update_state(active_state)?;
        }

        // Step 11: Success - commit guard to prevent rollback
        guard.commit();

        // In the normal NixOS path, the switch/test step owns the restart.
        // In overlay-only mode there is no switch owner, so activation must
        // restart the user/display session exactly once after success.
        if options.overlay_only {
            restart_session_after_success(&restart_plan).map_err(|e| {
                NailsError::OverlayError(format!(
                    "Activation succeeded but session restart failed: {}",
                    e
                ))
            })?;
        }

        // Once the success-path restart owner has completed, suppress the
        // error-path restart guard to avoid a second visible bounce.
        session_restart_guard.disarm();

        // Story 9.3 AC#1: Log activation complete with state transition and duration
        let final_state = {
            let manager = manager_arc
                .lock()
                .map_err(|e| NailsError::LockPoisoned(e.to_string()))?;
            manager.current_state().ok()
        };

        // Always show completion message, even in Quiet mode (AC: 3)
        if verbosity >= Verbosity::Quiet {
            tracing::info!(
                event = "activation_complete",
                duration_ms = total_timer.elapsed().as_millis() as u64,
                state_to = ?final_state,
                "✓ Activation complete in {}",
                total_timer
            );
        }

        Ok(())
    }
}
