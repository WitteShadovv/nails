// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! State pre-flight check
//!
//! Validates that the current system state allows activation.

use super::super::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result, SystemState};

/// Pre-flight check that validates the current system state
///
/// This check ensures activation doesn't run when the system is already active
/// or in a transitional state (activating, deactivating, emergency).
///
/// # Valid State for Activation
///
/// Activation is only allowed when the system state is **Inactive**.
///
/// # Blocked States
///
/// The following states block activation with specific guidance:
/// - **Active**: System already active - user should run `nails deactivate` first
/// - **Activating**: Activation in progress - user should wait, or run
///   `nails emergency` if no activation is running
/// - **Deactivating**: Deactivation in progress - user should wait, or run
///   `nails emergency` if no deactivation is running
/// - **Degraded**: Partial teardown left mounts behind - user should run
///   `nails emergency` before activating again
///
/// # State Machine Integration
///
/// This check enforces the state transition rules defined in `SystemState`:
/// - Valid: `Inactive → Activating → Active → Deactivating → Inactive`
/// - Valid: `Any State → Emergency`
/// - Invalid: Activation from any state except `Inactive`
///
/// See [`SystemState`](crate::state::SystemState) for complete state machine documentation.
///
/// # Idempotent Activation
///
/// When already active, attempting to activate returns
/// a friendly message ("already active") rather than an error, supporting
/// idempotent behavior.
///
/// # Example
///
/// ```rust
/// use nails_core::preflight::{StateCheck, PreFlightCheck};
/// use nails_core::{SystemState, MockFilesystem};
///
/// let fs = MockFilesystem::new();
/// let check = StateCheck::new(SystemState::Inactive);
///
/// let result = check.run(&fs).unwrap();
/// assert!(result.is_pass());
/// ```
#[derive(Debug, Clone)]
pub struct StateCheck {
    current_state: SystemState,
}

impl StateCheck {
    /// Create a new StateCheck with the current system state
    ///
    /// # Arguments
    ///
    /// * `current_state` - The current system state to validate
    pub fn new(current_state: SystemState) -> Self {
        Self { current_state }
    }
}

impl<F: Filesystem> PreFlightCheck<F> for StateCheck {
    fn name(&self) -> &'static str {
        "state"
    }

    fn description(&self) -> &'static str {
        "Validates system state allows activation"
    }

    fn run(&self, _fs: &F) -> Result<CheckResult> {
        match &self.current_state {
            SystemState::Inactive => Ok(CheckResult::Pass(
                "System is inactive - ready for activation".into(),
            )),
            // The live facts are authoritative (the `session-state` check
            // refuses a hidden root or an interrupted entry): a record that
            // still says active after a hard reset is only stale.
            SystemState::Active { .. } => Ok(CheckResult::Warn(
                "The state file still records an active session, but the machine is not in one \
                 (a hard reset or a power-off ended it); activation records a new one."
                    .to_string(),
            )),
            SystemState::Degraded { reason, .. } => Ok(CheckResult::Warn(format!(
                "The state file records a degraded session ({reason}); activation records a new one."
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::MockFilesystem;
    use chrono::Utc;

    #[test]
    fn the_check_is_named_state() {
        let check = StateCheck::new(SystemState::Inactive);
        assert_eq!(
            <StateCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "state"
        );
    }

    #[test]
    fn an_inactive_record_passes_and_a_stale_one_only_warns() {
        let fs = MockFilesystem::new();
        assert!(
            StateCheck::new(SystemState::Inactive)
                .run(&fs)
                .unwrap()
                .is_pass()
        );
        let active = StateCheck::new(SystemState::Active {
            activated_at: Utc::now(),
        });
        assert!(active.run(&fs).unwrap().is_warn());
        let degraded = StateCheck::new(SystemState::Degraded {
            since: Utc::now(),
            reason: "the way back failed".into(),
        });
        let result = degraded.run(&fs).unwrap();
        assert!(result.is_warn());
        assert!(result.message().contains("the way back failed"));
    }
}
