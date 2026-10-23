// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `deactivate` operation: end the hidden session and return to the decoy
//! (or power off).
//!
//! The way back prepares the decoy root at `/run/nextroot`, marks the hidden
//! backend for closing, records the state inactive and enqueues the soft-reboot.
//! A front end confirms with the operator and prints before the switch (the
//! soft-reboot stops its terminal), so the operation is split: [`prepare`]
//! builds the manager and refuses outside a hidden session, and
//! [`ReadyDeactivation::leave`] commits the way back once the front end has
//! confirmed, taken the state lock and printed.

use std::path::Path;

use crate::session::{LeaveReport, LeaveTo, RealTargetHost, SessionView};
use crate::{NailsError, NailsManager, RealFilesystem, RuntimeEnv};

/// The result of preparing a deactivation.
pub enum Prepared {
    /// Not in a hidden session, so there is nothing to deactivate.
    NotHidden,
    /// In a hidden session: ready to confirm, lock and leave.
    Ready(Box<ReadyDeactivation>),
}

/// A deactivation whose preconditions hold, ready to commit.
pub struct ReadyDeactivation {
    manager: NailsManager<RealFilesystem>,
}

impl ReadyDeactivation {
    /// The hidden volume root, for taking the state lock.
    pub fn hidden_root(&self) -> &Path {
        &self.manager.config().hidden_volume_root
    }

    /// The state file path, for taking the state lock.
    pub fn state_path(&self) -> &Path {
        &self.manager.config().state_file_path
    }

    /// Commit the way back: enqueue the soft-reboot (or the power-off). The
    /// caller prints its success line first, because this stops the terminal.
    pub fn leave(mut self, to: LeaveTo) -> Result<LeaveReport, NailsError> {
        let view = self.manager.session_view();
        let host = RealTargetHost::for_plan(match &view {
            SessionView::Hidden(plan) => Some(&**plan),
            _ => None,
        });
        self.manager.leave_session(to, &host)
    }
}

/// Prepare a deactivation: load the configuration (never refusing, since a
/// broken config must not block the way back), build the manager and check that
/// a hidden session is running.
pub fn prepare(env: &RuntimeEnv, config_override: Option<&Path>) -> Prepared {
    let config = super::config::load_config_or_defaults(config_override).into_config();
    let state_path = config.state_file_path.clone();
    let manager =
        NailsManager::new(RealFilesystem, config, state_path).with_runtime_env(env.clone());
    if !manager.session_view().is_hidden() {
        return Prepared::NotHidden;
    }
    Prepared::Ready(Box::new(ReadyDeactivation { manager }))
}

#[cfg(test)]
#[path = "deactivate_tests.rs"]
mod tests;
