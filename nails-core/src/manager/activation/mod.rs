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

use super::{
    MountInfo, MountTracker, MountType, NailsManager, build_overlay_targets,
    clean_stale_network_config, create_overlay_config, ensure_run_current_system_symlink,
    select_system_profile, start_service_and_socket,
};
use crate::notification::{Notification, write_notification};
use crate::{Filesystem, Result, Verbosity, obfuscate};
use std::path::Path;
use std::sync::{Arc, Mutex};

mod guards;
mod nixos_build;
mod nixos_switch;
mod overlay_mount;
mod preflight;
mod session;

use guards::SessionRestartGuard;

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
            let manager = manager_arc.lock().unwrap();
            (manager.current_state()?, manager.verbosity)
        };

        // Step 2: Idempotent check - if already active, return early (AC: 7)
        if previous_state.is_active() {
            if verbosity >= Verbosity::Normal {
                tracing::info!(state = ?previous_state, "System already active, nothing to do");
            }
            return Ok(());
        }

        // Story 9.3 AC#1: Log activation started with structured state field
        tracing::info!(state_from = ?previous_state, "Activation started");

        // Step 2.5: Handle --kill-session flag (Story 4.15, AC8)
        let restart_plan = Self::handle_session_kill(verbosity, &options)?;

        // Auto-restart session if we exit early with an error after killing it.
        let mut session_restart_guard = SessionRestartGuard::new(restart_plan.clone());

        // Step 2.75 & 3: Stage config and run preflight checks
        {
            let manager = manager_arc.lock().unwrap();
            manager.run_preflight_phase(
                no_preflight,
                options.overlay_only,
                verbosity,
                options.pre_activation_cleanup,
            )?;
        }

        // Step 4: Create StateGuard for automatic rollback on failure/panic
        let guard = StateGuard::new(Arc::clone(&manager_arc), previous_state.clone());

        // Step 5: Validate transition is allowed
        let activating_state = previous_state.begin_activation()?;

        // Step 6: Transition to Activating state
        {
            let mut manager = manager_arc.lock().unwrap();
            manager.update_state(activating_state)?;
        }

        // Step 7: Build NixOS profile (if NixOSBuilder configured)
        let (generation, new_fingerprint) = {
            let manager = manager_arc.lock().unwrap();
            manager.build_nixos_profile(verbosity)?
        };

        // Step 8: Mount persistent and ephemeral overlays
        let mount_timer = Stopwatch::start();
        let (direct_mounts, pivot_mounts, pivot_targets, mounted_overlays) = {
            let manager = manager_arc.lock().unwrap();
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
            let manager = manager_arc.lock().unwrap();
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

        // Write XDG autostart entry BEFORE display manager restart so the
        // .desktop file exists when the user logs back in (best-effort).
        // NOTE: This uses raw std::fs instead of the Filesystem trait because
        // shell_setup() (which uses the trait) runs after the DM restart —
        // too late for the autostart entry to be picked up by GNOME.
        // shell_setup() also writes this file as a backup for non-graphical paths.
        {
            let username = std::env::var("SUDO_USER")
                .or_else(|_| std::env::var(obfuscate::env_target_user()))
                .or_else(|_| std::env::var("USER"))
                .ok();

            if let Some(user) = username {
                let autostart_dir =
                    std::path::PathBuf::from(format!("/home/{}/.config/autostart", user));
                let desktop_path = autostart_dir.join("nails-notify.desktop");

                let desktop_entry = "[Desktop Entry]\n\
                    Type=Application\n\
                    Name=NAILS Notification Dispatch\n\
                    Comment=Dispatches pending NAILS notifications on login\n\
                    Exec=nails notify-dispatch\n\
                    Terminal=false\n\
                    NoDisplay=true\n\
                    X-GNOME-Autostart-enabled=true\n";

                if let Err(e) = std::fs::create_dir_all(&autostart_dir) {
                    tracing::warn!(
                        "Failed to create autostart directory {}: {} (best-effort, continuing)",
                        autostart_dir.display(),
                        e
                    );
                } else if let Err(e) = std::fs::write(&desktop_path, desktop_entry) {
                    tracing::warn!(
                        "Failed to write XDG autostart entry {}: {} (best-effort, continuing)",
                        desktop_path.display(),
                        e
                    );
                } else {
                    tracing::info!(
                        "Wrote XDG autostart entry before display manager restart: {}",
                        desktop_path.display()
                    );
                }
            } else {
                tracing::warn!(
                    "Could not determine username for XDG autostart entry (best-effort, continuing)"
                );
            }
        }

        // Step 8.5: Restart display manager BEFORE NixOS switch for better UX
        if restart_plan.display_manager.is_some() {
            use crate::process::restart_display_manager;

            if let Some(ref dm_name) = restart_plan.display_manager {
                if verbosity >= Verbosity::Normal {
                    tracing::info!("Restarting display manager ({})...", dm_name);
                }

                restart_display_manager(dm_name)?;

                if verbosity >= Verbosity::Normal {
                    tracing::info!("  ✓ Display manager restarted - login screen should appear");
                    tracing::info!("  ℹ NixOS rebuild will continue in background...");
                    tracing::info!("  ℹ User manager will start automatically when you log in");
                }
            }

            session_restart_guard.disarm();
        }

        // Step 9: Switch NixOS profile
        {
            let manager = manager_arc.lock().unwrap();
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
                    return Err(e);
                }
            }
        }

        // Step 10: Transition to Active state (Story 4.7, AC1, Task 3.4)
        {
            let mut manager = manager_arc.lock().unwrap();
            let current = manager.current_state()?;
            let active_state = current.complete_activation(mounted_overlays)?;
            manager.update_state(active_state)?;
        }

        // Step 11: Success - commit guard to prevent rollback
        guard.commit();

        // Story 9.3 AC#1: Log activation complete with state transition and duration
        let final_state = {
            let manager = manager_arc.lock().unwrap();
            manager.current_state().ok()
        };

        // Always show completion message, even in Quiet mode (AC: 3)
        if verbosity >= Verbosity::Quiet {
            tracing::info!(
                step = "activation_complete",
                duration_ms = total_timer.elapsed().as_millis() as u64,
                state_to = ?final_state,
                "✓ Activation complete in {}",
                total_timer
            );
        }

        Ok(())
    }
}
