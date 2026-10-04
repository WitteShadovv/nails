// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! RAII Guards for Activation Rollback
//!
//! This module provides RAII guard types that automatically restore system state
//! if activation fails mid-process, preventing partially-activated states.

use super::start_service_and_socket;
use crate::process::{
    SessionCommandExecutor, SessionRestartPlan, restart_display_manager, restart_user_manager,
};

/// RAII guard: if we kill the session but exit early with an error,
/// attempt to restart the user manager and display manager.
///
/// The guard owns the command executor it restarts through, so the same code
/// runs in production (a real `systemctl` runner) and under test (a recording
/// runner) — nothing is compiled out of the tested path.
pub(super) struct SessionRestartGuard {
    pub(super) plan: SessionRestartPlan,
    executor: Box<dyn SessionCommandExecutor>,
    pub(super) disarmed: bool,
}

impl SessionRestartGuard {
    pub(super) fn new(plan: SessionRestartPlan, executor: Box<dyn SessionCommandExecutor>) -> Self {
        Self {
            plan,
            executor,
            disarmed: false,
        }
    }

    /// Borrow the guard's executor so the success-path restart runs the same
    /// commands through the same runner the error-path drop would use.
    pub(super) fn executor(&self) -> &dyn SessionCommandExecutor {
        self.executor.as_ref()
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

impl SessionRestartGuard {
    /// Best-effort restart of the user and display managers on the error path,
    /// so the decoy session comes back after a failed activation. A default
    /// (empty) plan restarts nothing, matching production, where there is no
    /// session to restart.
    fn restart_session(&mut self) {
        if let Some(uid) = self.plan.target_uid
            && let Err(e) = restart_user_manager(uid, self.executor.as_ref())
        {
            tracing::error!(
                error = %e,
                uid = uid,
                "Failed to restart user manager after activation error"
            );
        }

        if let Some(dm_name) = self.plan.display_manager.take() {
            if let Err(e) = restart_display_manager(&dm_name, self.executor.as_ref()) {
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
/// plan — forcing the after-overlay restart step to run — and (2) inject a
/// recording command executor in place of the real `systemctl` runner, so the
/// production restart code runs against a hermetic runner and its exact commands
/// can be asserted. When no guard is armed, [`session_executor`] hands back the
/// real executor, so ordinary tests exercise the same construction path.
#[cfg(test)]
pub(crate) mod test_hooks {
    use crate::Result;
    use crate::process::{RealSessionCommandExecutor, SessionCommandExecutor, SessionRestartPlan};
    use std::cell::{Cell, RefCell};

    thread_local! {
        static OVERRIDE_PLAN: RefCell<Option<SessionRestartPlan>> = const { RefCell::new(None) };
        static ARMED: Cell<bool> = const { Cell::new(false) };
        static FAIL_RESTART: Cell<bool> = const { Cell::new(false) };
        static RECORDED_SYSTEMCTL: RefCell<Vec<Vec<String>>> = const { RefCell::new(Vec::new()) };
    }

    /// A hermetic executor that records every `systemctl` invocation and, when
    /// armed to fail, reports each call as unsuccessful (which drives the
    /// restart functions down their error path). `loginctl`/`kill` are inert.
    struct RecordingExecutor;

    impl SessionCommandExecutor for RecordingExecutor {
        fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
            RECORDED_SYSTEMCTL.with(|cell| {
                cell.borrow_mut()
                    .push(args.iter().map(|a| a.to_string()).collect())
            });
            if FAIL_RESTART.with(|cell| cell.get()) {
                return Ok((false, String::new(), "injected restart failure".to_string()));
            }
            // A successful `is-active` poll must report "active" so the restart
            // returns at once instead of sleeping; any other call just succeeds.
            if args.first() == Some(&"is-active") {
                Ok((true, "active".to_string(), String::new()))
            } else {
                Ok((true, String::new(), String::new()))
            }
        }

        fn execute_loginctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
            Ok((true, String::new(), String::new()))
        }

        fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
            Ok(true)
        }

        fn loginctl_available(&self) -> bool {
            false
        }
    }

    /// While held, overrides the restart plan, installs the recording executor,
    /// and optionally forces every restart command to fail; clears all of it on
    /// drop.
    pub(crate) struct SessionRestartTestGuard;

    impl SessionRestartTestGuard {
        pub(crate) fn arm(plan: SessionRestartPlan, fail: bool) -> Self {
            OVERRIDE_PLAN.with(|cell| *cell.borrow_mut() = Some(plan));
            ARMED.with(|cell| cell.set(true));
            FAIL_RESTART.with(|cell| cell.set(fail));
            RECORDED_SYSTEMCTL.with(|cell| cell.borrow_mut().clear());
            Self
        }
    }

    impl Drop for SessionRestartTestGuard {
        fn drop(&mut self) {
            OVERRIDE_PLAN.with(|cell| *cell.borrow_mut() = None);
            ARMED.with(|cell| cell.set(false));
            FAIL_RESTART.with(|cell| cell.set(false));
            RECORDED_SYSTEMCTL.with(|cell| cell.borrow_mut().clear());
        }
    }

    /// Return the injected plan if one is armed, otherwise the caller's plan.
    pub(crate) fn override_plan(plan: SessionRestartPlan) -> SessionRestartPlan {
        OVERRIDE_PLAN
            .with(|cell| cell.borrow().clone())
            .unwrap_or(plan)
    }

    /// The executor the activation flow restarts the session through: the
    /// recording executor while a guard is armed, otherwise the real one.
    pub(crate) fn session_executor() -> Box<dyn SessionCommandExecutor> {
        if ARMED.with(|cell| cell.get()) {
            Box::new(RecordingExecutor)
        } else {
            Box::new(RealSessionCommandExecutor)
        }
    }

    /// The `systemctl` invocations recorded since the guard was armed.
    pub(crate) fn recorded_systemctl() -> Vec<Vec<String>> {
        RECORDED_SYSTEMCTL.with(|cell| cell.borrow().clone())
    }
}
