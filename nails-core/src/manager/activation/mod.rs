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
pub(crate) mod rollback;
mod session;

#[cfg(test)]
mod tests;

use gate::maybe_block_after_activating_state_transition;
use guards::SessionRestartGuard;

/// What an activation call actually did.
///
/// Distinguishes a real activation (overlays mounted, state advanced to Active)
/// from a no-op on an already-verifiably-active system, so the caller can run the
/// shell integration and colour sequences only on a genuine activation and report
/// an already-active system with its own message and a success exit code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivationOutcome {
    /// The system was mounted and switched during this call.
    Activated,
    /// The system was already verifiably active; nothing was mounted or changed.
    AlreadyActive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionRestartPhase {
    None,
    AfterOverlayMounts,
}

fn determine_session_restart_phase(
    restart_plan: &crate::process::SessionRestartPlan,
) -> SessionRestartPhase {
    // The session restart always runs after the overlay mounts: a process still
    // holding the decoy session would otherwise keep writing to the lower tree.
    // The restart is skipped only when there is no plan to act on. The overlay /
    // NixOS-switch distinction no longer changes the phase, so it is not an input.
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

    // Mask the inherited decoy autostart entries and user units the operator
    // opted to hide. The overlays are mounted and the session has not restarted
    // yet, so the masks land in the hidden upper and take effect for the hidden
    // session only.
    match shell.write_persona_masks() {
        Ok(0) => {}
        Ok(count) => {
            tracing::info!(
                count,
                "Masked inherited decoy entries before session restart"
            );
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                "Failed to mask inherited decoy entries before session restart (best-effort)"
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
    if guards::test_hooks::should_fail_restart() {
        return Err(NailsError::OverlayError(
            "injected session restart failure (test seam)".to_string(),
        ));
    }
    Ok(())
}

impl<F: Filesystem> NailsManager<F> {
    /// Activate overlays with default options.
    ///
    /// This convenience entry point drives the mount/switch path without
    /// touching the graphical session, so it keeps the session and allows
    /// pivot fallback regardless of the secure CLI defaults carried by
    /// [`ActivateOptions::default`].
    pub fn activate(&mut self, no_preflight: bool) -> Result<ActivationOutcome> {
        let options = crate::ActivateOptions {
            kill_session: false,
            no_pivot: false,
            // `--no-preflight` opts out of the deferred, post-overlay flake
            // validation as well as the pre-overlay checks.
            skip_flake_validation: no_preflight,
            ..crate::ActivateOptions::default()
        };
        self.activate_with_options(options, no_preflight)
    }

    /// Decide whether activation may proceed, based on the reconciled state.
    ///
    /// `state.json` lives on the hidden root and survives reboots and crashes, so
    /// an `Active` left behind by an unclean shutdown must not make activation a
    /// silent no-op (which would then write the shell integration onto the bare
    /// decoy home). This consults [`reconcile_state`](NailsManager::reconcile_state)
    /// and maps the outcome:
    ///
    /// * `Ok(Some(AlreadyActive))` — the system is already verifiably active, so
    ///   the caller returns that outcome and does nothing.
    /// * `Ok(None)` — activation should proceed: the state is Inactive, or a stale
    ///   file from a previous boot was just reset to Inactive.
    /// * `Err(..)` — the system is inconsistent, interrupted or unreadable;
    ///   activation is refused with remediation pointing at `nails emergency`.
    fn reconcile_gate_for_activation(
        &self,
        verbosity: Verbosity,
    ) -> Result<Option<ActivationOutcome>> {
        use crate::state::EffectiveState;

        match self.reconcile_state()? {
            EffectiveState::VerifiedActive { .. } => {
                if verbosity >= Verbosity::Normal {
                    tracing::info!(
                        event = "result",
                        "System already active and verified against the mount table, nothing to do"
                    );
                }
                Ok(Some(ActivationOutcome::AlreadyActive))
            }
            EffectiveState::StaleFromPreviousBoot => {
                tracing::warn!(
                    event = "stale_state_reset",
                    "Persisted active state is from a previous boot with nothing mounted; \
                     reset to inactive, proceeding to activate"
                );
                Ok(None)
            }
            EffectiveState::Inactive => Ok(None),
            EffectiveState::Degraded { reason, remaining } => {
                Err(NailsError::InvalidState(format!(
                    "refusing to activate: {reason}. Hidden writes may be reaching the decoy disk. \
                 Run 'nails emergency' to tear down the remaining NAILS mount(s) ({}) before \
                 activating again.",
                    format_mount_list(&remaining)
                )))
            }
            EffectiveState::Interrupted { phase, .. } => Err(NailsError::InvalidState(format!(
                "refusing to activate: a previous {} was interrupted and left the system in an \
                 unknown state. Run 'nails emergency' to reset before activating again.",
                phase.as_str()
            ))),
            EffectiveState::Unknown => Err(NailsError::InvalidState(
                "refusing to activate: the persisted state is unreadable, so the current state \
                 is unknown. Run 'nails emergency' and recover the hidden volume before \
                 activating again."
                    .to_string(),
            )),
        }
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
    ) -> Result<ActivationOutcome> {
        use crate::{StateGuard, Stopwatch};

        let total_timer = Stopwatch::start();

        // Validate options first.
        options.validate()?;

        // Refuse an unsupported host before anything is staged, mounted or
        // switched. Detection is wired by the caller via `initialize_platform`;
        // when no profile was detected (unit tests, or a caller that skips
        // detection) this is a no-op, so activation stays testable without a
        // host-profile fixture.
        if let Some(profile) = self.host_profile.as_ref() {
            profile.require_supported()?;
        }

        let verbosity = self.verbosity;

        // Step 1: Reconcile the persisted state against the boot and the live
        // kernel mount table before trusting it (see `reconcile_gate_for_activation`).
        // A verifiably active system is a no-op; a stale file is reset here and we
        // proceed; an inconsistent, interrupted or unreadable state refuses rather
        // than mounting on top of possible hidden leakage.
        if let Some(outcome) = self.reconcile_gate_for_activation(verbosity)? {
            return Ok(outcome);
        }

        // The reconciled state is now Inactive (either genuinely, or just reset).
        let previous_state = self.current_state()?;

        tracing::info!(event = "activation_started", state_from = ?previous_state, "Activation started");

        // Surface the persona model. Shared-home runs the hidden session in the
        // decoy home with the decoy's accounts and secrets live, so it is warned
        // about; fresh-home is reported as the isolating mode.
        match self.config.persona.mode {
            crate::config::PersonaMode::SharedHome => {
                tracing::warn!(
                    event = "persona_mode",
                    persona_mode = "shared-home",
                    "Persona mode is shared-home: the hidden session runs in the decoy home, so the \
                     decoy's accounts, credentials and app profiles are live. Set persona.mode = \
                     \"fresh-home\" in nails.toml to start from a clean, isolated home."
                );
            }
            crate::config::PersonaMode::FreshHome => {
                tracing::info!(
                    event = "persona_mode",
                    persona_mode = "fresh-home",
                    "Persona mode is fresh-home: a clean hidden home will be bound over the \
                     operator's home, hiding the decoy home contents"
                );
            }
        }

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
        // Test seam: the session-detection stub panics, so a non-default plan
        // cannot be produced the normal way; this lets a rollback test inject one
        // to drive (and fail) the after-overlay restart path.
        #[cfg(test)]
        let restart_plan = guards::test_hooks::override_plan(restart_plan);
        let restart_phase = determine_session_restart_phase(&restart_plan);

        // Auto-restart the session if we exit early with an error after killing it.
        let mut session_restart_guard = SessionRestartGuard::new(restart_plan.clone());

        // Step 5: Take the rollback guard; every subsequent step runs through it.
        let activating_state = previous_state.begin_activation()?;
        // Shared handle for overlays the activation-scope rollback cannot unmount.
        // The StateGuard reads it on rollback to persist Degraded (listing those
        // mounts) rather than Inactive, so the state never claims the system is
        // clean while NAILS overlays are still live.
        let residue = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut guard =
            StateGuard::new(&mut *self, previous_state.clone()).with_residue(residue.clone());
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
        let (direct_mounts, pivot_mounts, leaking_targets, mounts) =
            guard.mount_overlays(&options, verbosity)?;

        // Persistent overlay paths are what the Active state records.
        let mounted_overlays: Vec<std::path::PathBuf> = mounts
            .iter()
            .filter(|info| info.mount_type == MountType::Persistent)
            .map(|info| info.target.clone())
            .collect();

        // Arm the activation-scope rollback guard over the mounts. It is declared
        // after `guard`, so on any later failure it drops first: the overlays come
        // down, then the StateGuard writes the rolled-back state, then
        // SessionRestartGuard restarts the session onto the decoy. It owns a clone
        // of the filesystem, so its drop never borrows the manager that the
        // StateGuard holds by `&mut`.
        let mut activation_mounts =
            rollback::ActivationMounts::arm(guard.filesystem().clone(), mounts, residue.clone());

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

        // Step 7.5: Validate the hidden flake now that `/nix` and `/root` are
        // overlaid. Running `nix flake metadata`/eval here — rather than before
        // the session kill and mounts — keeps the plaintext hidden configuration
        // off the decoy `/nix/store`, Nix DB and root cache: the store paths and
        // caches it creates land in the overlay upper and vanish on
        // deactivation. A broken hidden flake fails here while `activation_mounts`
        // is still armed, so the overlays are torn down and the session is never
        // restarted onto a broken state. A genuine `--no-preflight` (or
        // `--overlay-only`) run sets `skip_flake_validation` and opts out; the
        // detached worker leaves it unset so it still validates post-overlay.
        if !options.skip_flake_validation {
            guard.run_read_only_nixos_preflight(options.overlay_only)?;
        }

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

        // Step 11: Success - disarm the overlay rollback so the mounts stay, commit
        // the guard (prevents state rollback) and release the manager borrow, then
        // suppress the error-path session restart.
        activation_mounts.disarm();
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

        Ok(ActivationOutcome::Activated)
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

/// Join mount points into a comma-separated list for a refusal message, or a
/// placeholder when the kernel reported none still live.
fn format_mount_list(mounts: &[std::path::PathBuf]) -> String {
    if mounts.is_empty() {
        "none still listed".to_string()
    } else {
        mounts
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
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
