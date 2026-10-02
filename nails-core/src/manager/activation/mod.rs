//! Activation Logic for NailsManager
//!
//! This module implements the activation flow that:
//! 1. Validates system state
//! 2. Runs preflight checks
//! 3. Handles session management
//! 4. Computes NixOS rebuild metadata (if enabled)
//! 5. Mounts overlays with RAII rollback
//! 6. Restarts the user/display session when needed
//! 7. Runs NixOS switch/rebuild
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

mod gate;
mod guards;
mod nixos_build;
mod nixos_switch;
mod overlay_mount;
mod preflight;
mod session;

#[cfg(test)]
mod tests;

use gate::maybe_block_after_activating_state_transition;
use guards::SessionRestartGuard;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionRestartPhase {
    None,
    AfterOverlayMounts,
}

fn determine_session_restart_phase(
    restart_plan: &crate::process::SessionRestartPlan,
    overlay_only: bool,
    has_nixos_switch: bool,
) -> SessionRestartPhase {
    let _ = (overlay_only, has_nixos_switch);

    if restart_plan == &crate::process::SessionRestartPlan::default() {
        return SessionRestartPhase::None;
    }

    SessionRestartPhase::AfterOverlayMounts
}

/// Overlay targets where a surviving writer does not degrade the security posture.
///
/// `/boot` holds only the bootloader and kernels, which are integrity-verified at
/// boot; a process still writing there cannot leak hidden-session activity into a
/// forensically meaningful location. The exemption is justified by that integrity
/// verification, not by how the target happened to be mounted.
const INTEGRITY_VERIFIED_TARGETS: &[&str] = &["/boot"];

/// Derive the activation security label from which overlay targets still have
/// surviving writers referencing the decoy lower tree.
///
/// The label reflects leakage, not the mount method. A process that opened a
/// target before the mount keeps resolving the original inode and keeps writing to
/// the decoy under both a direct and a pivot mount, so the method alone carries no
/// security meaning. A target counts against the posture only when it is leaking
/// and is not integrity-verified.
fn derive_security_label(
    leaking: &[std::path::PathBuf],
    integrity_verified: &[&str],
) -> &'static str {
    let has_unverified_leak = leaking
        .iter()
        .any(|t| !integrity_verified.iter().any(|w| t == Path::new(w)));

    if has_unverified_leak {
        "DEGRADED"
    } else {
        "OPTIMAL"
    }
}

fn prepare_notification_autostart_before_session_restart<F: Filesystem>(manager: &NailsManager<F>) {
    let mut shell =
        crate::ShellInstrumentation::new(manager.filesystem().clone(), manager.config().clone());

    // Attach the operator so the autostart entry is written symlink-safe and
    // owned by them. If the operator cannot be resolved the integration still
    // runs, degrading to a best-effort root-owned write.
    match crate::TargetUser::resolve() {
        Ok(user) => shell = shell.with_target_user(user),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Could not resolve the operator before session restart; the autostart entry \
                 will be written best-effort without ownership"
            );
        }
    }

    match shell.write_xdg_autostart_entry() {
        Ok(true) => {
            tracing::info!(
                "Prepared XDG autostart entry before session restart for login-time notifications"
            );
        }
        Ok(false) => {
            tracing::warn!(
                "Could not prepare XDG autostart entry before session restart (best-effort)"
            );
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                "Failed to prepare XDG autostart entry before session restart (best-effort)"
            );
        }
    }
}

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
    /// Activate overlays with default options.
    ///
    /// This convenience entry point drives the mount/switch path without
    /// touching the graphical session, so it keeps the session and allows
    /// pivot fallback regardless of the secure CLI defaults carried by
    /// [`ActivateOptions::default`].
    pub fn activate(&mut self, no_preflight: bool) -> Result<()> {
        let options = crate::ActivateOptions {
            kill_session: false,
            no_pivot: false,
            ..crate::ActivateOptions::default()
        };
        self.activate_with_options(options, no_preflight)
    }

    /// Activate overlays with custom activation options.
    ///
    /// The flow is a short sequence of named step functions run against a single
    /// borrow of the manager. A [`StateGuard`] takes that borrow for the duration
    /// of the risky steps and rolls back to `previous_state` if any step returns
    /// early or panics; `guard.commit()` disarms the rollback on success.
    ///
    /// Options control session management (`--kill-session`), process restart
    /// behaviour, pivot policy (`--accept-pivot-risks` / `--no-pivot`) and prompt
    /// skipping (`--yes`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::{ActivateOptions, NailsManager, MockFilesystem, Config};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    /// let mut manager = NailsManager::new(fs, config, state_path);
    ///
    /// let options = ActivateOptions {
    ///     no_pivot: true, // Strict security mode
    ///     ..Default::default()
    /// };
    ///
    /// let result = manager.activate_with_options(options, false);
    /// ```
    pub fn activate_with_options(
        &mut self,
        options: crate::ActivateOptions,
        no_preflight: bool,
    ) -> Result<()> {
        use crate::{StateGuard, Stopwatch};

        let total_timer = Stopwatch::start();

        // Validate options first.
        options.validate()?;

        // Step 1: Capture current state and context once.
        let previous_state = self.current_state()?;
        let verbosity = self.verbosity;

        // Step 2: Idempotent check - if already active, return early.
        if previous_state.is_active() {
            if verbosity >= Verbosity::Normal {
                tracing::info!(event = "result", state = ?previous_state, "System already active, nothing to do");
            }
            return Ok(());
        }

        tracing::info!(event = "activation_started", state_from = ?previous_state, "Activation started");

        // Step 3: Stage config and run preflight checks before any session
        // disruption (no StateGuard yet, so an early failure leaves state alone).
        emit_progress(
            verbosity,
            "preflight",
            1,
            "[1/7] Running preflight checks...",
        );
        self.run_preflight_phase(
            no_preflight,
            options.overlay_only,
            verbosity,
            options.pre_activation_cleanup,
        )?;

        // Step 4: Handle --kill-session before taking the StateGuard.
        if verbosity >= Verbosity::Normal {
            if no_preflight {
                tracing::info!(
                    event = "progress",
                    phase = "session_management",
                    current = 2,
                    total = 7,
                    "[2/7] Preparing session management (--no-preflight)"
                );
            } else {
                tracing::info!(
                    event = "progress",
                    phase = "session_management",
                    current = 2,
                    total = 7,
                    "[2/7] Preparing session management..."
                );
            }
        }
        let restart_plan = Self::handle_session_kill(verbosity, &options)?;
        let restart_phase =
            determine_session_restart_phase(&restart_plan, options.overlay_only, false);

        // Auto-restart the session if we exit early with an error after killing it.
        let mut session_restart_guard = SessionRestartGuard::new(restart_plan.clone());

        // Step 5: Take the rollback guard; every subsequent step runs through it.
        let activating_state = previous_state.begin_activation()?;
        let mut guard = StateGuard::new(&mut *self, previous_state.clone());
        guard.update_state(activating_state)?;
        maybe_block_after_activating_state_transition()?;

        // Step 6: Compute NixOS switch metadata (no rebuild yet).
        emit_progress(
            verbosity,
            "nixos_prepare",
            3,
            "[3/7] Preparing NixOS switch metadata...",
        );
        let (generation, new_fingerprint) = guard.build_nixos_profile(verbosity)?;

        // Step 7: Mount persistent and ephemeral overlays.
        emit_progress(verbosity, "overlay_mount", 4, "[4/7] Mounting overlays...");
        let mount_timer = Stopwatch::start();
        let (direct_mounts, pivot_mounts, leaking_targets, mounted_overlays) =
            guard.mount_overlays(&options, verbosity)?;

        // The posture depends on surviving writers that still leak to the decoy,
        // not on whether any overlay used the pivot method.
        let security_status = derive_security_label(&leaking_targets, INTEGRITY_VERIFIED_TARGETS);
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
        guard.emit_overlay_status_notification(security_status, direct_mounts, pivot_mounts);

        // Step 8: Restart session / display manager after overlays are in place.
        emit_progress(
            verbosity,
            "session_restart",
            5,
            "[5/7] Restarting session/display manager...",
        );
        if restart_phase == SessionRestartPhase::AfterOverlayMounts {
            prepare_notification_autostart_before_session_restart(&guard);
            restart_session_after_success(&restart_plan).map_err(|e| {
                NailsError::OverlayError(format!(
                    "Activation failed before NixOS switch because session restart failed: {}",
                    e
                ))
            })?;
        }

        // Step 9: Run NixOS switch/rebuild. Failures here are non-fatal for
        // overlay/session activation: preserve the mounted environment and
        // continue to a consistent Active state.
        emit_progress(
            verbosity,
            "profile_switch",
            6,
            "[6/7] Running NixOS switch/rebuild...",
        );
        let nixos_switch_warning =
            guard.run_post_overlay_nixos_switch(&generation, &new_fingerprint, verbosity);

        // Step 10: Finalize - transition to Active.
        emit_progress(verbosity, "finalize", 7, "[7/7] Finalizing activation...");
        let current = guard.current_state()?;
        let active_state = current.complete_activation(mounted_overlays)?;
        guard.update_state(active_state)?;

        // Step 11: Success - commit the guard (prevents rollback) and release the
        // manager borrow, then suppress the error-path session restart.
        guard.commit();
        session_restart_guard.disarm();

        let final_state = self.current_state().ok();

        // Always show the completion message, even in Quiet mode.
        if verbosity >= Verbosity::Quiet {
            tracing::info!(
                event = "activation_complete",
                duration_ms = total_timer.elapsed().as_millis() as u64,
                state_to = ?final_state,
                "✓ Activation complete in {}",
                total_timer
            );
        }

        if let Some(warning) = nixos_switch_warning {
            tracing::warn!(
                event = "activation_completed_with_warning",
                preserve_activation = true,
                warning = %warning,
                "Activation completed, but the post-overlay NixOS switch/rebuild failed; overlays and restarted session were preserved"
            );
        }

        Ok(())
    }

    /// Write the best-effort overlay-status notification after mounting.
    fn emit_overlay_status_notification(
        &self,
        security_status: &str,
        direct_mounts: usize,
        pivot_mounts: usize,
    ) {
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
        if let Err(e) = write_notification(&self.config().hidden_volume_root, &notif) {
            tracing::warn!("Failed to write overlay status notification: {}", e);
        }
    }

    /// Run the post-overlay NixOS switch/rebuild and emit the matching
    /// notification. Returns a warning string when the switch failed but the
    /// activation was preserved; `None` on success.
    fn run_post_overlay_nixos_switch(
        &self,
        generation: &Option<String>,
        new_fingerprint: &Option<String>,
        verbosity: Verbosity,
    ) -> Option<String> {
        let switch_result = self.switch_nixos_profile(generation, new_fingerprint, verbosity);
        let hidden_root = self.config().hidden_volume_root.clone();

        match switch_result {
            Ok(()) => {
                tracing::info!("NixOS profile switch complete");
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
                None
            }
            Err(e) => {
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
                    body: truncated.clone(),
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

                tracing::warn!(
                    error = %e,
                    preserve_activation = true,
                    "NixOS switch/rebuild failed after overlays were mounted; preserving active session and overlays"
                );
                Some(truncated)
            }
        }
    }
}

/// Emit a `[n/7]` progress log line at Normal verbosity or above.
fn emit_progress(verbosity: Verbosity, phase: &str, current: u8, message: &str) {
    if verbosity >= Verbosity::Normal {
        tracing::info!(
            event = "progress",
            phase = phase,
            current = current,
            total = 7,
            "{}",
            message
        );
    }
}
