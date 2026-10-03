//! RAII Guards for Activation Rollback
//!
//! This module provides RAII guard types that automatically restore system state
//! if activation fails mid-process, preventing partially-activated states.

use super::start_service_and_socket;
use crate::process::SessionRestartPlan;
#[cfg(not(test))]
use crate::process::{RealSessionCommandExecutor, restart_display_manager, restart_user_manager};

/// RAII guard: if we kill the session but exit early with an error,
/// attempt to restart the user manager and display manager.
pub(super) struct SessionRestartGuard {
    pub(super) plan: SessionRestartPlan,
    pub(super) disarmed: bool,
}

impl SessionRestartGuard {
    pub(super) fn new(plan: SessionRestartPlan) -> Self {
        Self {
            plan,
            disarmed: false,
        }
    }

    /// Prevent the guard from restarting the session (use after a successful restart).
    pub(super) fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for SessionRestartGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }

        self.restart_session();
    }
}

#[cfg(not(test))]
impl SessionRestartGuard {
    /// Best-effort restart of the user and display managers on the error path,
    /// so the decoy session comes back after a failed activation.
    fn restart_session(&mut self) {
        if let Some(uid) = self.plan.target_uid
            && let Err(e) = restart_user_manager(uid, &RealSessionCommandExecutor)
        {
            tracing::error!(
                error = %e,
                uid = uid,
                "Failed to restart user manager after activation error"
            );
        }

        if let Some(dm_name) = self.plan.display_manager.take() {
            if let Err(e) = restart_display_manager(&dm_name, &RealSessionCommandExecutor) {
                tracing::error!(
                    error = %e,
                    dm = %dm_name,
                    "Failed to restart display manager after activation error"
                );
            } else {
                tracing::warn!(
                    dm = %dm_name,
                    "Display manager restarted after activation error"
                );
            }
        }
    }
}

#[cfg(test)]
impl SessionRestartGuard {
    /// The real restart calls `systemctl` and the test stubs panic, so under
    /// test the guard only records that the error-path restart ran. This lets a
    /// rollback test prove the restart happens after the overlay unmounts
    /// without touching the host. A default (empty) plan records nothing,
    /// matching production, where there is no session to restart.
    fn restart_session(&mut self) {
        if self.plan.target_uid.is_some() || self.plan.display_manager.is_some() {
            super::rollback::test_events::record(
                super::rollback::test_events::ActivationEvent::SessionRestart,
            );
        }
    }
}

/// RAII guard: if we stop nix-daemon for the `/nix` overlay but exit early,
/// restart it so the system isn't left degraded.
///
/// The restart path matches how the daemon was stopped: a NixOS host restarts it
/// through the NixOS-resolved service controller, while a non-NixOS host (Nix on
/// Debian/Ubuntu) restarts it through its own `systemctl`, resolved from the
/// platform command directories. A guard for a host with no `/nix` overlay
/// ([`NixRuntime::None`]) does nothing.
pub(super) struct NixDaemonGuard {
    pub(super) runtime: crate::platform::NixRuntime,
    pub(super) command_dirs: &'static [&'static str],
    pub(super) disarmed: bool,
}

impl NixDaemonGuard {
    pub(super) fn new(
        runtime: crate::platform::NixRuntime,
        command_dirs: &'static [&'static str],
    ) -> Self {
        Self {
            runtime,
            command_dirs,
            disarmed: false,
        }
    }

    pub(super) fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for NixDaemonGuard {
    fn drop(&mut self) {
        use crate::platform::NixRuntime;
        if self.disarmed {
            return;
        }
        match self.runtime {
            NixRuntime::Native => start_service_and_socket("nix-daemon"),
            NixRuntime::Foreign => {
                if let Err(err) =
                    crate::platform::nix_foreign::restart_nix_daemon(self.command_dirs)
                {
                    tracing::warn!(error = %err, "Failed to restart nix-daemon on the error path");
                }
            }
            NixRuntime::None => {}
        }
    }
}

/// Test seams for the activation session-restart path.
///
/// Production derives the restart plan from live session detection, whose test
/// stub panics, so a non-default plan cannot be produced the normal way under
/// test. These hooks let a rollback regression test (1) inject a non-default
/// plan — forcing the after-overlay restart step to run — and (2) make that
/// restart fail, which is the post-mount failure the fix must handle.
#[cfg(test)]
pub(crate) mod test_hooks {
    use crate::process::SessionRestartPlan;
    use std::cell::{Cell, RefCell};

    thread_local! {
        static OVERRIDE_PLAN: RefCell<Option<SessionRestartPlan>> = const { RefCell::new(None) };
        static FAIL_RESTART: Cell<bool> = const { Cell::new(false) };
    }

    /// While held, overrides the restart plan and optionally forces the restart
    /// to fail; clears both on drop.
    pub(crate) struct SessionRestartTestGuard;

    impl SessionRestartTestGuard {
        pub(crate) fn arm(plan: SessionRestartPlan, fail: bool) -> Self {
            OVERRIDE_PLAN.with(|cell| *cell.borrow_mut() = Some(plan));
            FAIL_RESTART.with(|cell| cell.set(fail));
            Self
        }
    }

    impl Drop for SessionRestartTestGuard {
        fn drop(&mut self) {
            OVERRIDE_PLAN.with(|cell| *cell.borrow_mut() = None);
            FAIL_RESTART.with(|cell| cell.set(false));
        }
    }

    /// Return the injected plan if one is armed, otherwise the caller's plan.
    pub(crate) fn override_plan(plan: SessionRestartPlan) -> SessionRestartPlan {
        OVERRIDE_PLAN
            .with(|cell| cell.borrow().clone())
            .unwrap_or(plan)
    }

    /// Whether the after-overlay session restart should return an error.
    pub(crate) fn should_fail_restart() -> bool {
        FAIL_RESTART.with(|cell| cell.get())
    }
}
