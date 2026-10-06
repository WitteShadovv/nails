// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Activation Logic for NailsManager
//!
//! This module implements the activation flow that:
//! 1. Validates system state
//! 2. Runs preflight checks
//! 3. Handles session management
//! 4. Computes NixOS rebuild metadata (if enabled)
//! 5. Mounts overlays with RAII rollback
//! 6. Builds and switches the hidden NixOS configuration
//! 7. Restarts the user/display session when needed
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
use crate::overlay::SurvivingWriter;
use crate::process::RealSessionCommandExecutor as RealSessionCommands;
use crate::reporter::progress::{Reporter, SharedReporter, Step, Tee};
use crate::{DecoyWriter, Filesystem, NailsError, Result, Verbosity};
use std::path::Path;

mod gate;
mod guards;
mod nixos_build;
mod nixos_switch;
pub(crate) mod overlay_mount;
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
///
/// A genuine activation carries [`HiddenConfigOutcome`]: the overlays can be up
/// and the session restarted while the hidden NixOS switch failed (when
/// `nixos_switch_required = false`). The caller turns that into a truthful
/// "activated with warnings" report and a distinct exit code instead of claiming
/// a clean success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActivationOutcome {
    /// The system was mounted during this call. `hidden_config` records whether
    /// the hidden NixOS configuration was applied, not requested, or failed while
    /// the overlays were kept.
    Activated {
        /// Outcome of the post-overlay hidden NixOS build + switch.
        hidden_config: HiddenConfigOutcome,
    },
    /// The system was already verifiably active; nothing was mounted or changed.
    AlreadyActive,
}

/// Outcome of the post-overlay hidden NixOS build + `switch-to-configuration
/// test` step.
///
/// Reported truthfully even when the switch fails but the overlays and the
/// restarted session are kept (`nixos_switch_required = false`): the operator is
/// then told the hidden declarative configuration was not applied rather than
/// seeing a clean success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HiddenConfigOutcome {
    /// The hidden toplevel was built (or reused on the fast path) and switched to.
    Applied {
        /// Store path of the toplevel switched to, when one is known (the flake
        /// and fast paths yield one; the legacy `nixos-rebuild test` path does not).
        toplevel: Option<String>,
        /// Whether the fast path (cached toplevel, unchanged fingerprint) was taken.
        fast_path: bool,
    },
    /// No declarative configuration was requested: an overlay-only run, or a host
    /// with no config layer (FHS / Debian).
    NotRequested,
    /// The build or switch failed; the overlays and session were kept and this
    /// reason is surfaced as an activation warning.
    Failed {
        /// Human-readable reason the switch did not apply.
        reason: String,
    },
}

impl HiddenConfigOutcome {
    /// The failure reason, when the hidden configuration was not applied.
    pub fn failure_reason(&self) -> Option<&str> {
        match self {
            HiddenConfigOutcome::Failed { reason } => Some(reason.as_str()),
            _ => None,
        }
    }
}

impl ActivationOutcome {
    /// Whether this was a no-op on an already-active system.
    pub fn is_already_active(&self) -> bool {
        matches!(self, ActivationOutcome::AlreadyActive)
    }

    /// The hidden-config outcome of a genuine activation, if any.
    pub fn hidden_config(&self) -> Option<&HiddenConfigOutcome> {
        match self {
            ActivationOutcome::Activated { hidden_config } => Some(hidden_config),
            ActivationOutcome::AlreadyActive => None,
        }
    }

    /// The operator-facing warnings this outcome carries (currently only a failed
    /// hidden NixOS switch). Empty when activation was fully clean.
    pub fn warnings(&self) -> Vec<String> {
        match self
            .hidden_config()
            .and_then(HiddenConfigOutcome::failure_reason)
        {
            Some(reason) => {
                vec![format!(
                    "hidden NixOS configuration was not applied ({reason})"
                )]
            }
            None => Vec::new(),
        }
    }
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

/// How many writers the desktop notification names before summarising the rest.
const NOTIFICATION_WRITER_LIMIT: usize = 3;

/// Fold the writers that survived Phase 2 on `target` into the activation-wide
/// list, one entry per process.
///
/// A process holding several targets (NetworkManager on `/etc` and `/var`) is
/// one writer leaking to two places, so it is merged by PID rather than counted
/// twice. Survivors on an integrity-verified target are left out: that exemption
/// is what defines a leak for the security posture, and applying it once here
/// keeps the activation label, the notification, the outcome and `status` in
/// agreement. They are still named in the per-target warning logged at mount.
fn record_surviving_writers(
    writers: &mut Vec<DecoyWriter>,
    target: &Path,
    survivors: &[SurvivingWriter],
) {
    if INTEGRITY_VERIFIED_TARGETS
        .iter()
        .any(|verified| target == Path::new(verified))
    {
        return;
    }

    for survivor in survivors {
        match writers.iter_mut().find(|w| w.pid == survivor.pid) {
            Some(writer) => {
                if !writer.targets.iter().any(|t| t == target) {
                    writer.targets.push(target.to_path_buf());
                }
            }
            None => writers.push(DecoyWriter {
                pid: survivor.pid,
                name: survivor.name.clone(),
                service: survivor.service.clone(),
                targets: vec![target.to_path_buf()],
            }),
        }
    }
}

/// Derive the activation security label from the writers still referencing the
/// decoy lower tree.
///
/// The label reflects leakage, not the mount method. A process that opened a
/// target before the mount keeps resolving the original inode and keeps writing to
/// the decoy under both a direct and a pivot mount, so the method alone carries no
/// security meaning. Integrity-verified targets never contribute writers (see
/// [`record_surviving_writers`]), so any writer at all degrades the posture.
fn derive_security_label(decoy_writers: &[DecoyWriter]) -> &'static str {
    if decoy_writers.is_empty() {
        "OPTIMAL"
    } else {
        "DEGRADED"
    }
}

/// The body of the post-mount notification: the label and mount counts, then
/// the writers still on the decoy so the operator knows what to close or restart.
fn overlay_status_body(
    security_status: &str,
    direct_mounts: usize,
    pivot_mounts: usize,
    decoy_writers: &[DecoyWriter],
) -> String {
    let mut body = format!(
        "Security: {} — {} overlay(s) mounted ({} direct, {} pivot)",
        security_status,
        direct_mounts + pivot_mounts,
        direct_mounts,
        pivot_mounts
    );
    if !decoy_writers.is_empty() {
        body.push_str(&format!(
            ". {}: {}",
            crate::decoy_writers_headline(decoy_writers.len()),
            crate::summarize_decoy_writers(decoy_writers, NOTIFICATION_WRITER_LIMIT)
        ));
    }
    // Record the RAM-backed panic button in the notification body so it survives
    // even if the backend disappears and the on-screen summary has scrolled away.
    // Uses the neutral control-copy path, never a product name.
    body.push_str(&format!(
        ". If the hidden volume fails, run: sudo {} emergency",
        crate::runtime_copy::binary_copy_path().display()
    ));
    body
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

/// The executor the activation flow restarts the killed session through. The
/// [`SessionRestartGuard`] owns it so the error-path drop and the success-path
/// call run the same code against the same runner. Production always restarts
/// through the real `systemctl` runner; tests inject a recording runner.
#[cfg_attr(test, allow(unreachable_code))]
fn session_restart_executor() -> Box<dyn crate::process::SessionCommandExecutor> {
    #[cfg(test)]
    {
        return guards::test_hooks::session_executor();
    }
    Box::new(RealSessionCommands)
}

fn restart_session_after_success(
    plan: &crate::process::SessionRestartPlan,
    executor: &dyn crate::process::SessionCommandExecutor,
) -> Result<()> {
    // Starting the display manager is the authoritative restart path for a
    // killed graphical session. On real systems it will recreate the user
    // manager as part of the login/session lifecycle, so explicitly starting
    // user@UID.service first causes an observable double bounce in e2e.
    if plan.display_manager.is_none()
        && let Some(uid) = plan.target_uid
    {
        crate::process::restart_user_manager(uid, executor)?;
    }

    if let Some(dm_name) = plan.display_manager.as_deref() {
        crate::process::restart_display_manager(dm_name, executor)?;
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

    /// Whether the system is verifiably active right now: the state file says
    /// Active and every recorded overlay is present in the live kernel mount
    /// table.
    ///
    /// The `activate` command uses this to short-circuit an already-active system
    /// to the same no-op outcome and exit code on every flag path, before the
    /// session-kill pre-flight (whose `StateCheck` would otherwise refuse with a
    /// different exit code). A read error or any non-active effective state returns
    /// `false` so activation proceeds and the in-core reconcile gate makes the
    /// authoritative decision.
    pub fn is_verified_active(&self) -> bool {
        matches!(
            self.reconcile_state(),
            Ok(crate::state::EffectiveState::VerifiedActive { .. })
        )
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
            EffectiveState::Degraded {
                reason, remaining, ..
            } => Err(NailsError::InvalidState(format!(
                "refusing to activate: {reason}. Hidden writes may be reaching the decoy disk. \
                 Run 'nails emergency' to tear down the remaining NAILS mount(s) ({}) before \
                 activating again.",
                format_mount_list(&remaining)
            ))),
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
    /// Options control session management (`--session kill`), process restart
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

        // Clear any outcome recorded by a previous activation; the activation-scope
        // rollback guard sets this handle again only if a rollback actually runs,
        // and the StateGuard copies it into the manager as it unwinds. A local
        // `Rc` (not stored on the manager) keeps `NailsManager` `Send`.
        self.reset_rollback_outcome();
        let rollback_outcome = std::rc::Rc::new(std::cell::RefCell::new(
            rollback::RollbackOutcome::NotNeeded,
        ));

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

        // Whether this activation applies a declarative configuration layer. Only
        // NixOS has one, and `--overlay-only` skips it. The progress-step total and
        // labels are derived from this, so the NixOS prepare/switch steps never
        // render on an overlay-only or Debian-family run. When no host profile was
        // detected (unit tests) assume a layer so the legacy ordering still holds.
        let host_has_layer = self
            .host_profile
            .as_ref()
            .map(|profile| profile.has_config_layer());
        let layer_runs = !options.overlay_only && host_has_layer.unwrap_or(true);
        // A host whose profile is known to carry no declarative layer (FHS /
        // Debian-family). `None` (no profile detected, e.g. unit tests) is not
        // treated as Debian-family, so no spurious platform marker is written.
        let host_is_fhs = host_has_layer == Some(false);
        let mut step = self.step_progress(layer_runs);

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
        step.emit("preflight", "Running preflight checks...");
        self.run_preflight_phase(
            no_preflight,
            options.overlay_only,
            verbosity,
            options.pre_activation_cleanup,
            options.accept_persistent_decoy,
        )?;

        // Step 4: Handle --session kill before taking the StateGuard.
        if no_preflight {
            step.emit(
                "session_management",
                "Preparing session management (--no-preflight)",
            );
        } else {
            step.emit("session_management", "Preparing session management...");
        }
        let restart_plan = Self::handle_session_kill(verbosity, &options, &RealSessionCommands)?;
        // Test seam: lets a rollback test inject a non-default plan to drive the
        // after-overlay restart path (unkillable unprivileged otherwise).
        #[cfg(test)]
        let restart_plan = guards::test_hooks::override_plan(restart_plan);
        let restart_phase = determine_session_restart_phase(&restart_plan);

        // Auto-restart the session if we exit early with an error after killing it.
        let mut session_restart_guard =
            SessionRestartGuard::new(restart_plan.clone(), session_restart_executor());

        // Step 5: Take the rollback guard; every subsequent step runs through it.
        let activating_state = previous_state.begin_activation()?;
        // Shared handle for overlays the activation-scope rollback cannot unmount.
        // The StateGuard reads it on rollback to persist Degraded (listing those
        // mounts) rather than Inactive, so the state never claims the system is
        // clean while NAILS overlays are still live.
        let residue = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let mut guard = StateGuard::new(&mut *self, previous_state.clone())
            .with_residue(residue.clone())
            .with_rollback_outcome(rollback_outcome.clone());
        guard.update_state(activating_state)?;
        // Pre-flight confirmed the hidden volume: keep the progress record that
        // `nails status` reads from here on (removed when activation returns).
        guard.attach_progress_record(&mut step);
        // Record the graphical session we took over (if any) so emergency teardown
        // can end the same logind session and bring its display manager back.
        guard.record_hidden_session(&restart_plan);
        maybe_block_after_activating_state_transition()?;

        // Step 6: Compute the hidden configuration metadata (no rebuild yet). The
        // call is cheap and returns nothing to apply off NixOS, but its progress
        // step is only shown when a layer actually runs.
        if layer_runs {
            step.emit("config_prepare", "Preparing hidden configuration...");
        }
        let (fast_path_toplevel, new_fingerprint) = guard.build_nixos_profile(verbosity)?;

        // Cancellation checkpoint before any mount (covers a SIGINT/SIGTERM during
        // staging, the gate, or the build-metadata step above): no mounts are
        // armed and the residue is empty, so the StateGuard restores the previous
        // state (Inactive) and nothing was ever created. See `crate::cancel`.
        crate::cancel::checkpoint()?;

        // Step 7: Mount persistent and ephemeral overlays.
        step.emit("overlay_mount", "Mounting overlays...");
        let mount_timer = Stopwatch::start();
        let overlay_mount::OverlayMountOutcome {
            direct_mounts,
            pivot_mounts,
            decoy_writers,
            mounts,
        } = guard.mount_overlays(&options, verbosity)?;

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
        let mut activation_mounts = rollback::ActivationMounts::arm(
            guard.filesystem().clone(),
            mounts,
            residue.clone(),
            rollback_outcome.clone(),
        );

        // The posture depends on surviving writers that still leak to the decoy,
        // not on whether any overlay used the pivot method.
        guard.report_mount_posture(
            direct_mounts,
            pivot_mounts,
            &decoy_writers,
            &mount_timer,
            verbosity,
        );

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
        // Step 7.6 also re-checks free space against the rebuild floor; either
        // failure here drops `activation_mounts` first so the overlays roll back.
        guard.run_post_mount_guards(&options, &fast_path_toplevel)?;

        // Step 8: Build and switch the hidden NixOS configuration BEFORE the
        // session restarts. Switching first means the restarted session comes up
        // under the hidden configuration and a failed switch never brings the
        // decoy session up ahead of the hidden one. With `nixos_switch_required`
        // (the default) a failure here is fatal: returning early drops the overlay
        // rollback guard, tearing the overlays down, and the session-restart guard
        // then restores the decoy session — all before any restart has run. Fail
        // closed. With `nixos_switch_required = false` the failure is only a
        // warning and activation continues with the overlays and session kept.
        // Last cancellation checkpoint: `activation_mounts` is armed, so a cancel
        // drops it first (unmounting) then the StateGuard restores the previous
        // state. None follows — a running `switch-to-configuration` is never cut.
        crate::cancel::checkpoint()?;

        if layer_runs {
            step.emit("profile_switch", "Applying hidden configuration...");
        }
        let hidden_config =
            guard.switch_recording_hidden_units(&fast_path_toplevel, &new_fingerprint, verbosity);
        if let HiddenConfigOutcome::Failed { reason } = &hidden_config
            && guard.config().nixos_switch_required
        {
            return Err(NailsError::NixOSError(format!(
                "hidden NixOS configuration was not applied: {reason}. Overlays were rolled \
                 back before any session restart (set nixos_switch_required = false to keep \
                 the overlays and session and only warn instead)."
            )));
        }

        // Record the outcome in state so `nails status` can report a hidden
        // configuration that was not applied — the detached GUI path exits before
        // the operator sees any console output, so state is the only durable
        // signal. Cleared (set to None) on a clean switch so a later success
        // overwrites a stale warning.
        guard.record_switch_warning(hidden_config.failure_reason());

        // Step 9: Restart session / display manager, now that the hidden
        // configuration is in force.
        step.emit("session_restart", "Restarting session/display manager...");
        if restart_phase == SessionRestartPhase::AfterOverlayMounts {
            prepare_notification_autostart_before_session_restart(&guard);
            restart_session_after_success(&restart_plan, session_restart_guard.executor())
                .map_err(|e| {
                    NailsError::OverlayError(format!(
                        "Activation failed after NixOS switch because session restart failed: {}",
                        e
                    ))
                })?;
        }

        // Step 9.5: Keep the decoy's base-OS trees read-only for the session. This
        // runs after every decoy-writing step (the NixOS switch above) so those
        // writes still land, then closes the decoy: on an FHS host the decoy root
        // and /usr become read-only, so a stray hidden-session write is refused
        // with EROFS instead of reaching the decoy disk. A no-op on NixOS, where
        // the overlays already carry the protection. The guards are armed on the
        // rollback so a later failure returns write access, and recorded in state
        // so deactivation and emergency teardown undo exactly these binds.
        let read_only_guards = guard.apply_read_only_guard()?;
        if !read_only_guards.is_empty() {
            activation_mounts.set_read_only_guards(read_only_guards.clone());
            guard.record_read_only_guards(&read_only_guards)?;
        }

        // Record the platform section for a host with no declarative layer, so the
        // typed marker is persisted even when no switch ran. Skipped for an
        // overlay-only run on NixOS, which leaves the platform unset rather than
        // mislabelling the host as Debian-family.
        if host_is_fhs {
            guard.record_debian_family_platform();
        }

        // Step 10: Finalize - transition to Active.
        step.emit("finalize", "Finalizing activation...");
        // Keep a copy of the overlay targets for the RAM-backed runtime copy
        // below, since the list is moved into the Active state here.
        let overlay_targets_for_copy = mounted_overlays.clone();
        let current = guard.current_state()?;
        let active_state = current.complete_activation(mounted_overlays, decoy_writers)?;
        guard.commit_active_state(active_state, total_timer.elapsed())?;

        // Step 11: Success - disarm the overlay rollback so the mounts stay, commit
        // the guard (prevents state rollback) and release the manager borrow, then
        // suppress the error-path session restart.
        activation_mounts.disarm();
        guard.commit();
        session_restart_guard.disarm();
        step.succeed();

        // Mirror the binary, config and a mount manifest into a RAM-backed copy on
        // the decoy /run, and start the in-session backend watcher, now that the
        // activation has committed. Best-effort: the copy and watcher are a safety
        // net for a backend that fails mid-session, not part of the overlay stack,
        // so a failure here must never undo a successful activation.
        // Then push the queued results straight into the operator's session.
        self.install_backend_runtime_copy(&overlay_targets_for_copy);
        self.deliver_results_to_session();

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

        if let Some(warning) = hidden_config.failure_reason() {
            tracing::warn!(
                event = "activation_completed_with_warning",
                preserve_activation = true,
                warning = %warning,
                "Activation completed, but the post-overlay NixOS switch/rebuild failed; overlays and restarted session were preserved"
            );
        }

        Ok(ActivationOutcome::Activated { hidden_config })
    }

    /// Re-run the hidden NixOS build + `switch-to-configuration test` against the
    /// current hidden configuration while the system is already active, without
    /// remounting anything.
    ///
    /// This is what `nails reapply` calls: once a fixed hidden configuration has
    /// landed in the overlaid `/etc/nixos`, the operator applies it in place
    /// instead of a full deactivate (which reboots) followed by a fresh activate.
    /// It refuses unless the system is verifiably active, re-uses the same
    /// fast-path cache as activation, and persists the outcome so `nails status`
    /// stays truthful.
    pub fn reapply_hidden_config(&self) -> Result<ActivationOutcome> {
        use crate::state::EffectiveState;

        match self.reconcile_state()? {
            EffectiveState::VerifiedActive { .. } => {}
            _ => {
                return Err(NailsError::InvalidState(
                    "reapply needs a verifiably active hidden environment; run 'nails activate' \
                     first, then reapply once the hidden configuration is fixed"
                        .to_string(),
                ));
            }
        }

        // Populate the in-memory state cache from disk before building and
        // switching. `reconcile_state` above reads the state file directly and
        // does not seed the cache, so without this every persistence step on the
        // reapply path — the fast-path fingerprint/toplevel lookup, recording the
        // new generation, and clearing the switch warning — would operate on an
        // empty cache and silently no-op. In particular a clean reapply must clear
        // any stale `last_switch_warning` from the earlier failed switch so
        // `nails status` stops reporting the hidden configuration as unapplied.
        self.current_state()?;

        let verbosity = self.verbosity;
        let (fast_path_toplevel, new_fingerprint) = self.build_nixos_profile(verbosity)?;
        let hidden_config =
            self.run_post_overlay_nixos_switch(&fast_path_toplevel, &new_fingerprint, verbosity);
        self.record_switch_warning(hidden_config.failure_reason());
        if let Err(e) = self.save_cached_state() {
            tracing::warn!("Failed to persist reapply outcome to state: {}", e);
        }

        Ok(ActivationOutcome::Activated { hidden_config })
    }

    /// Progress for one activation: seven steps when a declarative layer runs,
    /// five otherwise, reported through this manager's reporter.
    fn step_progress(&self, layer_runs: bool) -> StepProgress {
        StepProgress::new(
            self.verbosity,
            if layer_runs { 7 } else { 5 },
            self.reporter.clone(),
        )
    }

    /// Start keeping `step`'s hidden-volume progress record. Only call once the
    /// hidden volume is confirmed mounted, so the record never lands on the decoy.
    ///
    /// Also arms the activation-in-progress marker the login dispatcher polls
    /// on, removed with the progress record when the activation returns.
    fn attach_progress_record(&self, step: &mut StepProgress) {
        step.attach_file(
            self.filesystem.clone(),
            self.config.hidden_volume_root.clone(),
        );
        step.result_marker = Some(crate::notification::deliver::ResultPendingMarker::arm(
            &self.config.hidden_volume_root,
        ));
    }

    /// Write the Active state together with this activation's duration.
    ///
    /// The duration is kept across deactivation so `nails status` can report how
    /// long the last activation took. If the write fails, the previous record is
    /// put back before the rollback persists the state, so a failed activation
    /// never reports a duration.
    pub(crate) fn commit_active_state(
        &mut self,
        active_state: crate::SystemState,
        elapsed: std::time::Duration,
    ) -> Result<()> {
        let previous = self.record_last_activation(elapsed);
        self.update_state(active_state).inspect_err(|_| {
            self.restore_last_activation(previous);
        })
    }

    /// Record the duration of this activation in the cached state so it is
    /// written out with the Active state, returning the record it replaced.
    fn record_last_activation(
        &self,
        duration: std::time::Duration,
    ) -> Option<crate::state::LastActivation> {
        let mut cached = self.cached_state.borrow_mut();
        let state_file = cached.as_mut()?;
        state_file
            .last_activation
            .replace(crate::state::LastActivation {
                duration_ms: u64::try_from(duration.as_millis()).unwrap_or(u64::MAX),
                finished_at: chrono::Utc::now(),
            })
    }

    /// Put back the last-activation record replaced by
    /// [`record_last_activation`](Self::record_last_activation).
    fn restore_last_activation(&self, previous: Option<crate::state::LastActivation>) {
        if let Some(ref mut state_file) = *self.cached_state.borrow_mut() {
            state_file.last_activation = previous;
        }
    }

    /// Record (or clear) the last hidden NixOS switch warning in the cached state
    /// so it is written out with the next state save. `None` clears a prior
    /// warning after a clean switch.
    pub(crate) fn record_switch_warning(&self, warning: Option<&str>) {
        let mut cached = self.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file.set_switch_warning(warning.map(ToString::to_string));
        }
    }

    /// Record the hidden graphical session in the cached state from the
    /// session-kill restart plan, so emergency teardown can end the same logind
    /// session and restart its display manager. A no-op when activation did not
    /// take over a graphical session (no target uid in the plan).
    pub(crate) fn record_hidden_session(&self, plan: &crate::process::SessionRestartPlan) {
        let Some(target_uid) = plan.target_uid else {
            return;
        };
        let mut cached = self.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file.hidden_session = Some(crate::state::HiddenSession {
                target_uid,
                session_id: None,
                display_manager: plan.display_manager.clone(),
            });
        }
    }

    /// Record the service units the hidden switch added (units active after it
    /// that were not known at all before it — see
    /// `ServiceController::list_known_units`) in the cached state, so
    /// emergency teardown stops exactly those units instead of switching the
    /// whole decoy configuration back. A no-op when nothing was added.
    ///
    /// Only an applied hidden switch can introduce units for teardown to stop: an
    /// overlay-only run (or any host without a declarative layer) reports
    /// [`HiddenConfigOutcome::NotRequested`] and adds nothing, so recording is
    /// skipped unless the switch actually applied. This keeps the overlay-only
    /// path from ever recording the running decoy units and having emergency stop
    /// the live system.
    ///
    /// The diff is also only trustworthy when the "before" snapshot actually
    /// enumerated the host's units. An empty "before" means the enumeration
    /// returned nothing (systemctl failed, or no units were listed), and then
    /// every active unit would be mistaken for one the hidden switch introduced —
    /// so emergency would stop the entire running system, the operator's session
    /// and all. Treat an empty "before" as "unknown" and record nothing rather
    /// than risk that: a genuine hidden service is better left running than the
    /// whole decoy torn down.
    pub(crate) fn record_hidden_added_units(
        &self,
        outcome: &HiddenConfigOutcome,
        before: &[String],
        after: &[String],
    ) {
        if !matches!(outcome, HiddenConfigOutcome::Applied { .. }) {
            return;
        }
        if before.is_empty() {
            tracing::warn!(
                "Skipping the hidden-added unit snapshot: the pre-switch unit list was empty, \
                 so the added-unit diff cannot be trusted"
            );
            return;
        }
        let before_set: std::collections::HashSet<&str> =
            before.iter().map(String::as_str).collect();
        let added: Vec<String> = after
            .iter()
            .filter(|unit| !before_set.contains(unit.as_str()))
            .filter(|unit| !is_protected_base_unit(unit))
            .cloned()
            .collect();
        if added.is_empty() {
            return;
        }
        let mut cached = self.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file.hidden_added_units = added;
        }
    }

    /// Record the Debian-family platform section in the cached state so a host
    /// with no declarative layer still carries a typed platform marker. A no-op
    /// once a NixOS section is recorded (an overlay-only run on NixOS keeps the
    /// platform unset rather than claiming Debian-family).
    pub(crate) fn record_debian_family_platform(&self) {
        let mut cached = self.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file.mark_debian_family();
        }
    }

    /// Write the RAM-backed runtime copy and, when enabled, start the in-session
    /// backend watcher.
    ///
    /// The copy mirrors the running executable, the effective configuration and a
    /// manifest of the mounted overlay targets into a neutral `0700` directory on
    /// the decoy `/run` (see [`crate::runtime_copy`]), so `emergency`/`recover`
    /// stay runnable and informed even once the hidden volume is gone. The watcher
    /// ([`crate::watcher`]) is then started from that copy as a transient systemd
    /// unit. Everything here is best-effort: a failure leaves the session running
    /// without the safety net and is logged, never fatal.
    /// Push the queued result notifications into the operator's graphical
    /// session now that the activation has committed, so they do not wait for
    /// the next login. Best-effort: without a session bus (or on any failure)
    /// they stay queued for the login dispatcher, and `nails status` lists
    /// whatever is still undelivered. Only a committed activation pushes; after a
    /// rollback the operator is on the decoy session.
    fn deliver_results_to_session(&self) {
        use crate::notification::deliver::{
            PushOutcome, RealSessionNotifier, SessionUser, push_pending,
        };

        if crate::runtime_safety::should_skip_host_interaction() {
            return;
        }
        let user = crate::TargetUser::resolve().ok().map(|user| SessionUser {
            uid: user.uid,
            name: user.name,
        });
        match push_pending(
            &self.config().hidden_volume_root,
            user.as_ref(),
            &RealSessionNotifier,
        ) {
            Ok(PushOutcome::Delivered(count)) => {
                tracing::debug!(
                    count,
                    "Delivered the activation results to the operator's session"
                );
            }
            Ok(PushOutcome::NoSession) => {
                tracing::debug!(
                    "No session bus to push to; results stay queued for the next login"
                );
            }
            Ok(PushOutcome::Failed { delivered, error }) => tracing::warn!(
                delivered,
                error = %error,
                "Could not push every activation result to the session; the rest stay queued"
            ),
            Err(e) => tracing::warn!(error = %e, "Could not read the queued activation results"),
        }
    }

    fn install_backend_runtime_copy(&self, overlay_targets: &[std::path::PathBuf]) {
        if crate::runtime_safety::should_skip_host_interaction() {
            return;
        }

        let exe = match std::env::current_exe() {
            Ok(path) => path,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "Could not resolve the running executable; skipping the RAM-backed runtime copy"
                );
                return;
            }
        };

        if let Err(e) = crate::runtime_copy::write_runtime_copy(
            self.filesystem(),
            self.config(),
            &exe,
            overlay_targets,
        ) {
            tracing::warn!(
                error = %e,
                "Failed to write the RAM-backed runtime copy; emergency teardown will still work \
                 from the live mount table"
            );
            return;
        }

        // Tell the operator the panic button that survives a failed hidden volume:
        // the mirrored binary runs from tmpfs, so it stays usable once the real
        // binary on the hidden root is gone.
        tracing::info!(
            "If the hidden volume fails, run: sudo {} emergency",
            crate::runtime_copy::binary_copy_path().display()
        );

        if self.config().backend_watch.enabled {
            crate::runtime_copy::start_watch_unit();
        }

        // Start the sleep guard for block/teardown policies, so a suspend cannot
        // strand the active session resident in RAM. Warn mode starts nothing.
        if self.config().sleep_policy.mode.runs_guard() {
            crate::sleep_guard::start_sleep_guard_unit();
        }
    }

    /// Log the security label and any writers left on the decoy once the
    /// overlays are up, and write the matching login notification.
    fn report_mount_posture(
        &self,
        direct_mounts: usize,
        pivot_mounts: usize,
        decoy_writers: &[DecoyWriter],
        mount_timer: &crate::Stopwatch,
        verbosity: Verbosity,
    ) {
        let security_status = derive_security_label(decoy_writers);
        if !decoy_writers.is_empty() {
            let listed = decoy_writers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ");
            tracing::warn!(
                event = "decoy_writers",
                count = decoy_writers.len(),
                "⚠️  NOT OPTIMAL: {}: {}",
                crate::decoy_writers_headline(decoy_writers.len()),
                listed
            );
        }
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
        self.emit_overlay_status_notification(
            security_status,
            direct_mounts,
            pivot_mounts,
            decoy_writers,
        );
    }

    /// Write the best-effort overlay-status notification after mounting.
    fn emit_overlay_status_notification(
        &self,
        security_status: &str,
        direct_mounts: usize,
        pivot_mounts: usize,
        decoy_writers: &[DecoyWriter],
    ) {
        let notif = Notification {
            title: "NAILS Overlay Active".to_string(),
            body: overlay_status_body(security_status, direct_mounts, pivot_mounts, decoy_writers),
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
    /// notification. Returns the [`HiddenConfigOutcome`]: `Applied` on success,
    /// `NotRequested` when the host has no declarative layer, or `Failed` when the
    /// switch failed but the activation was preserved.
    ///
    /// The failure notification written here is the detached GUI worker's outcome
    /// signal: the worker runs this same code, so a failed switch surfaces as a
    /// login notification even though its console output went to the journal.
    fn run_post_overlay_nixos_switch(
        &self,
        fast_path_toplevel: &Option<String>,
        new_fingerprint: &Option<String>,
        verbosity: Verbosity,
    ) -> HiddenConfigOutcome {
        let switch_result =
            self.switch_nixos_profile(fast_path_toplevel, new_fingerprint, verbosity);
        let hidden_root = self.config().hidden_volume_root.clone();

        // `switch-to-configuration test` reconciles the running system's systemd
        // units and, as a side effect, unmounts the overlays NAILS placed over the
        // base-OS trees it manages (/etc, /usr, /bin, /lib64), leaving the bare
        // decoy exposed there for the hidden session about to come back. Re-mount
        // anything it cleared now, before the session restarts. A no-op when no
        // switch ran (overlay-only / FHS) or when every overlay survived; what is
        // re-mounted here the activation rollback already tracks by target, and
        // teardown rediscovers from the live mount table.
        if self.config_layer().is_some() {
            self.remount_overlays_cleared_by_switch(verbosity);
        }

        match switch_result {
            Ok(outcome @ HiddenConfigOutcome::NotRequested) => outcome,
            Ok(outcome) => {
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
                // switch-to-configuration starts swap.target and can re-enable a
                // disk swap the operator turned off to pass pre-flight. Re-classify
                // now and warn loudly if a leaking swap reappeared.
                self.recheck_swap_posture("after the NixOS switch", &hidden_root);
                // The build just wrote its store delta into the /nix upper; warn if
                // the hidden volume is now nearly full.
                self.recheck_hidden_volume_space("after the NixOS switch", &hidden_root);
                outcome
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
                HiddenConfigOutcome::Failed { reason: truncated }
            }
        }
    }

    /// Run the post-overlay hidden NixOS switch, recording the service units it
    /// added so emergency teardown can stop exactly those.
    ///
    /// The units are snapshotted around the switch: every unit the host knew
    /// beforehand (active or not), then the active units afterwards. Only a unit
    /// that is active after the switch and was unknown before counts as
    /// hidden-added, so a base service that merely restarts in the window is not
    /// recorded. Only an applied switch records anything, so when no switch can run
    /// at all (overlay-only, or no declarative layer or builder) the snapshots are
    /// not taken: enumerating every unit costs real time on a slow unit tree and
    /// could only ever be thrown away.
    fn switch_recording_hidden_units(
        &self,
        fast_path_toplevel: &Option<String>,
        new_fingerprint: &Option<String>,
        verbosity: Verbosity,
    ) -> HiddenConfigOutcome {
        use crate::manager::helpers::ServiceController;

        let snapshot_units = self.hidden_switch_configured();
        let before = if snapshot_units {
            ServiceController::list_known_units()
        } else {
            Vec::new()
        };
        let hidden_config =
            self.run_post_overlay_nixos_switch(fast_path_toplevel, new_fingerprint, verbosity);
        let after = if snapshot_units {
            ServiceController::list_active_units()
        } else {
            Vec::new()
        };
        self.record_hidden_added_units(&hidden_config, &before, &after);
        hidden_config
    }

    /// Re-classify swap and hibernation and, if a device that can leak memory to
    /// persistent storage is active, log loudly and write a critical
    /// notification. `phase` names the point in the flow for the operator.
    ///
    /// Runs after the NixOS switch (which starts `swap.target` and can re-enable
    /// a disk swap the operator turned off to pass pre-flight) and before
    /// deactivation. RAM-only zram never trips this.
    pub(crate) fn recheck_swap_posture(&self, phase: &str, hidden_root: &Path) {
        let posture = crate::preflight::classify_swap(self.filesystem());
        if posture.severity == crate::preflight::SwapSeverity::Fail {
            let detail = posture.findings.join("; ");
            tracing::error!("swap can leak memory to persistent storage {phase}: {detail}");
            let notif = Notification {
                title: "Swap re-enabled".to_string(),
                body: format!("Swap can leak memory to persistent storage {phase}: {detail}"),
                urgency: "critical".to_string(),
                icon: Some("dialog-error".to_string()),
                created_at: chrono::Utc::now().to_rfc3339(),
            };
            if let Err(e) = write_notification(hidden_root, &notif) {
                tracing::warn!("Failed to write swap re-check notification: {}", e);
            }
        }
    }

    /// Post-mount guards that run after the overlays are mounted and before the
    /// NixOS build/switch: validate the hidden flake (unless the run opted out)
    /// now that `/nix` and `/root` are overlaid, then re-check free space against
    /// the rebuild floor. Returning an error leaves the overlays to roll back
    /// before any build or session restart.
    ///
    /// The flake validation is skipped on the fast path: a carried-forward
    /// toplevel means the fingerprint matched, so the build inputs are byte-for-byte
    /// the ones a previous activation already built and validated. Re-validating
    /// them would make the fast path require the flake to still evaluate, defeating
    /// the point of reusing a cached toplevel — an operator whose flake is
    /// temporarily broken could no longer re-enter a hidden session that needs no
    /// rebuild. A changed flake invalidates the fingerprint, drops the fast path
    /// and is validated here as usual.
    pub(crate) fn run_post_mount_guards(
        &self,
        options: &crate::ActivateOptions,
        fast_path_toplevel: &Option<String>,
    ) -> Result<()> {
        if !options.skip_flake_validation && fast_path_toplevel.is_none() {
            self.run_read_only_nixos_preflight(options.overlay_only)?;
        }
        self.ensure_rebuild_space_before_build(fast_path_toplevel)
    }

    /// Whether a full hidden NixOS rebuild is expected for this activation.
    ///
    /// A rebuild runs when no cached toplevel can be reused (the fast path is
    /// absent) and the host has both a declarative config layer and a builder.
    /// An overlay-only run (no builder / no layer) or a fast-path reuse writes no
    /// large store delta, so only the base space floor applies to it.
    pub(crate) fn rebuild_expected(&self, fast_path_toplevel: &Option<String>) -> bool {
        fast_path_toplevel.is_none() && self.hidden_switch_configured()
    }

    /// Whether this activation can run the hidden NixOS switch at all: the host
    /// has a declarative config layer and a builder was wired. Mirrors the
    /// preconditions of `switch_nixos_profile`, which reports `NotRequested`
    /// without either (an overlay-only run has no builder).
    pub(crate) fn hidden_switch_configured(&self) -> bool {
        self.nixos_builder.is_some() && self.config_layer().is_some()
    }

    /// Re-check free space on the hidden volume against the rebuild floor.
    ///
    /// Called after the overlays are mounted and before the NixOS build runs. A
    /// no-op unless a full rebuild is expected (see [`rebuild_expected`]). The
    /// build writes its store delta into the overlaid `/nix` upper, so a volume
    /// that passed the base pre-flight floor can still be too small. Returns an
    /// error when short so the caller rolls the overlays back before any build or
    /// session restart.
    ///
    /// [`rebuild_expected`]: Self::rebuild_expected
    pub(crate) fn ensure_rebuild_space_before_build(
        &self,
        fast_path_toplevel: &Option<String>,
    ) -> Result<()> {
        if !self.rebuild_expected(fast_path_toplevel) {
            return Ok(());
        }
        let root = self.config().hidden_volume_root.clone();
        let available_mb = self.filesystem().disk_usage(&root)?.available / (1024 * 1024);
        let floor = self.config().rebuild_space_mb;
        if available_mb < floor {
            return Err(NailsError::NixOSError(format!(
                "hidden volume has only {} MB free but a NixOS rebuild needs at least {} MB \
                 (rebuild_space_mb). Free space or enlarge the hidden volume, then retry. \
                 Overlays were rolled back before any build or session restart.",
                available_mb, floor
            )));
        }
        Ok(())
    }

    /// Re-check free space after a successful switch and warn when the hidden
    /// volume is nearly full. The rebuild wrote its store delta into the `/nix`
    /// upper, so a volume that cleared the pre-build floor can now be low; a
    /// notification lets the operator free space before the next activation.
    pub(crate) fn recheck_hidden_volume_space(&self, phase: &str, hidden_root: &Path) {
        let floor = self.config().rebuild_space_mb;
        let available_mb = match self.filesystem().disk_usage(hidden_root) {
            Ok(usage) => usage.available / (1024 * 1024),
            Err(e) => {
                tracing::warn!("Failed to re-check hidden volume space {phase}: {e}");
                return;
            }
        };
        if available_mb < floor {
            tracing::warn!(
                "hidden volume nearly full {phase}: {available_mb} MB free (below the \
                 {floor} MB rebuild floor); free space before the next activation"
            );
            let notif = Notification {
                title: "Hidden volume nearly full".to_string(),
                body: format!(
                    "Only {available_mb} MB free on the hidden volume {phase} (below the \
                     {floor} MB rebuild floor). Free or enlarge the volume before the next \
                     activation."
                ),
                urgency: "critical".to_string(),
                icon: Some("dialog-warning".to_string()),
                created_at: chrono::Utc::now().to_rfc3339(),
            };
            if let Err(e) = write_notification(hidden_root, &notif) {
                tracing::warn!("Failed to write hidden-volume-full notification: {}", e);
            }
        }
    }
}

/// Whether `unit` is a core base-system unit that must never be recorded as
/// "hidden-added" and therefore never stopped by an emergency teardown.
///
/// The hidden-added set already excludes every unit the host knew before the
/// switch, so a base service that restarts mid-switch is not recorded. This list
/// is defence in depth for the units whose loss breaks the live decoy itself:
/// stopping udev, journald, logind, dbus, polkit, nix-daemon or a getty leaves
/// device events unhandled, logging and logins failing, the system bus and
/// polkit gone, the package store's daemon missing, or the console dead — so a
/// teardown can wedge and the operator is left at a broken decoy. A hidden NixOS
/// generation never legitimately *adds* these units (they exist in every base),
/// so excluding them can only drop false positives, never a genuine hidden
/// service.
fn is_protected_base_unit(unit: &str) -> bool {
    const PROTECTED: &[&str] = &[
        "systemd-udevd.service",
        "systemd-journald.service",
        "systemd-journald-audit.socket",
        "systemd-logind.service",
        "systemd-user-sessions.service",
        "dbus.service",
        "dbus-broker.service",
        "polkit.service",
        "nix-daemon.service",
        "console-getty.service",
        "getty.target",
    ];
    PROTECTED.contains(&unit)
        // getty/console template instances (getty@tty1.service,
        // serial-getty@ttyS0.service, autovt@…): losing these kills the console.
        || unit.starts_with("getty@")
        || unit.starts_with("serial-getty@")
        || unit.starts_with("autovt@")
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

/// Sequential activation progress whose count follows the active execution path.
///
/// The total is fixed up front from whether a declarative configuration layer
/// runs (NixOS, and not `--overlay-only`); each emitted step advances the counter
/// so the `[n/total]` numbering stays contiguous even when the layer steps are
/// skipped. A step is counted whatever the verbosity, so the numbering a quiet
/// run would show matches a verbose one.
///
/// Every step is logged at debug level (the hidden-root log) and reported
/// through a [`Tee`]: to the manager's operator-facing reporter (muted below
/// Normal verbosity) and, once attached, to the hidden-volume progress record.
/// The tee is installed as the active reporter for the activation's lifetime,
/// so heartbeats and details raised deep in the build and mount code reach it.
/// Unless [`succeed`](Self::succeed) is called, dropping the progress reports
/// the current step as failed; dropping it also removes the progress record.
struct StepProgress {
    current: u8,
    total: u8,
    /// The phase id and label most recently emitted, so a progress record
    /// attached mid-activation starts from the phase already in progress.
    last: (&'static str, String),
    /// When the activation started, recorded in the progress record.
    started_at: chrono::DateTime<chrono::Utc>,
    hub: std::sync::Arc<std::sync::Mutex<Tee>>,
    succeeded: bool,
    /// Tells the login dispatcher an activation is in progress; removed on drop.
    result_marker: Option<crate::notification::deliver::ResultPendingMarker>,
    /// Declared last so the active-reporter slot is released after `hub`.
    _scope: crate::reporter::progress::ActiveScope,
}

impl StepProgress {
    fn new(verbosity: Verbosity, total: u8, reporter: SharedReporter) -> Self {
        let hub = std::sync::Arc::new(std::sync::Mutex::new(Tee::new(
            reporter,
            verbosity >= Verbosity::Normal,
        )));
        let active: SharedReporter = hub.clone();
        Self {
            current: 0,
            total,
            last: ("", String::new()),
            started_at: chrono::Utc::now(),
            hub,
            succeeded: false,
            result_marker: None,
            _scope: crate::reporter::progress::install(active),
        }
    }

    fn hub(&self) -> std::sync::MutexGuard<'_, Tee> {
        self.hub
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The label a step message contributes: the message without its trailing
    /// ellipsis.
    fn label(message: &str) -> String {
        message.trim_end_matches('.').to_string()
    }

    /// Advance to the next step: log it and report it.
    fn emit(&mut self, phase: &'static str, message: &str) {
        self.current += 1;
        self.last = (phase, Self::label(message));
        tracing::debug!(
            event = "progress",
            phase = phase,
            current = self.current,
            total = self.total,
            "[{}/{}] {}",
            self.current,
            self.total,
            self.last.1
        );
        let (index, total) = (u32::from(self.current), u32::from(self.total));
        let label = self.last.1.clone();
        self.hub().step(Step {
            index,
            total,
            phase,
            label: &label,
        });
    }

    /// Start keeping the hidden-volume progress record, beginning with the phase
    /// already in progress. The record is removed when this progress is dropped.
    fn attach_file<F: Filesystem>(&mut self, fs: F, hidden_root: std::path::PathBuf) {
        let writer = crate::progress::ProgressFileWriter::start(
            fs,
            hidden_root,
            self.started_at,
            u32::from(self.current),
            u32::from(self.total),
            self.last.0,
            &self.last.1,
        );
        self.hub().attach(Box::new(writer));
    }

    /// The activation succeeded: report the final step as done.
    fn succeed(&mut self) {
        self.succeeded = true;
        self.hub().finish(true);
    }
}

impl Drop for StepProgress {
    fn drop(&mut self) {
        if !self.succeeded {
            self.hub().finish(false);
        }
    }
}
