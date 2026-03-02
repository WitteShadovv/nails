//! RAII Guards for Activation Rollback
//!
//! This module provides RAII guard types that automatically restore system state
//! if activation fails mid-process, preventing partially-activated states.

use super::start_service_and_socket;
use crate::process::{SessionRestartPlan, restart_display_manager, restart_user_manager};

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

        if let Some(uid) = self.plan.target_uid
            && let Err(e) = restart_user_manager(uid)
        {
            tracing::error!(
                error = %e,
                uid = uid,
                "Failed to restart user manager after activation error"
            );
        }

        if let Some(dm_name) = self.plan.display_manager.take() {
            if let Err(e) = restart_display_manager(&dm_name) {
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

/// RAII guard: if we stop nix-daemon for /nix overlay but exit early,
/// restart both socket and service so the system isn't left degraded.
pub(super) struct NixDaemonGuard {
    pub(super) active: bool,
    pub(super) disarmed: bool,
}

impl NixDaemonGuard {
    pub(super) fn new(active: bool) -> Self {
        Self {
            active,
            disarmed: false,
        }
    }

    pub(super) fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for NixDaemonGuard {
    fn drop(&mut self) {
        if !self.active || self.disarmed {
            return;
        }
        start_service_and_socket("nix-daemon");
    }
}
