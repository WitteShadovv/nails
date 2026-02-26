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
/// - **Activating**: Activation in progress - user should wait or reboot if stuck
/// - **Deactivating**: Deactivation in progress - user should wait for completion
/// - **Emergency**: System in emergency state - user must reboot to reset
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
/// # Idempotent Activation (FR61)
///
/// Per requirement FR61, attempting to activate when already active returns
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
            SystemState::Active { .. } => Ok(CheckResult::Fail(
                "System is already active. Run 'nails deactivate' first or use 'nails status' to check state.".into(),
            )),
            SystemState::Activating { .. } => Ok(CheckResult::Fail(
                "System is currently activating. Wait for completion or reboot if stuck.".into(),
            )),
            SystemState::Deactivating { .. } => Ok(CheckResult::Fail(
                "System is currently deactivating. Wait for completion or reboot if stuck.".into(),
            )),
            SystemState::Emergency { .. } => Ok(CheckResult::Fail(
                "System is in emergency state. Reboot to reset state.".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::preflight::PreFlightRegistry;
    use crate::{NailsError, filesystem::MockFilesystem};
    use chrono::Utc;

    #[test]
    fn test_state_check_new_constructor() {
        // AC 1: StateCheck::new() constructor accepting current state
        let _check = StateCheck::new(SystemState::Inactive);
    }

    #[test]
    fn test_state_check_trait_metadata() {
        // AC 1, 2: StateCheck implements PreFlightCheck trait with correct name and description
        let check = StateCheck::new(SystemState::Inactive);

        assert_eq!(
            <StateCheck as PreFlightCheck<MockFilesystem>>::name(&check),
            "state"
        );
        assert_eq!(
            <StateCheck as PreFlightCheck<MockFilesystem>>::description(&check),
            "Validates system state allows activation"
        );
    }

    #[test]
    fn test_state_check_inactive_state_pass() {
        // AC 3: Given current state is Inactive, When StateCheck runs, Then returns Pass
        let fs = MockFilesystem::new();
        let check = StateCheck::new(SystemState::Inactive);

        let result = check.run(&fs).unwrap();
        assert!(result.is_pass());
        assert_eq!(
            result.message(),
            "System is inactive - ready for activation"
        );
    }

    #[test]
    fn test_state_check_active_state_fail() {
        // AC 4: Given current state is Active, When StateCheck runs, Then returns Fail with deactivate guidance
        let fs = MockFilesystem::new();
        let check = StateCheck::new(SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![],
        });

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert_eq!(
            result.message(),
            "System is already active. Run 'nails deactivate' first or use 'nails status' to check state."
        );
    }

    #[test]
    fn test_state_check_activating_state_fail() {
        // AC 5: Given current state is Activating, When StateCheck runs, Then returns Fail with wait/reboot guidance
        let fs = MockFilesystem::new();
        let check = StateCheck::new(SystemState::Activating {
            started_at: Utc::now(),
        });

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert_eq!(
            result.message(),
            "System is currently activating. Wait for completion or reboot if stuck."
        );
    }

    #[test]
    fn test_state_check_deactivating_state_fail() {
        // AC 2: Deactivating state should also fail (not in story AC but in implementation requirements)
        let fs = MockFilesystem::new();
        let check = StateCheck::new(SystemState::Deactivating {
            started_at: Utc::now(),
        });

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert!(result.message().contains("deactivating"));
        assert!(
            result
                .message()
                .contains("Wait for completion or reboot if stuck")
        );
    }

    #[test]
    fn test_state_check_emergency_state_fail() {
        // AC 6: Given current state is Emergency, When StateCheck runs, Then returns Fail with reboot guidance
        let fs = MockFilesystem::new();
        let check = StateCheck::new(SystemState::Emergency {
            triggered_at: Utc::now(),
        });

        let result = check.run(&fs).unwrap();
        assert!(result.is_fail());
        assert_eq!(
            result.message(),
            "System is in emergency state. Reboot to reset state."
        );
    }

    #[test]
    fn test_state_check_all_states_coverage() {
        // AC 7: Write unit tests for all 5 state variants
        let fs = MockFilesystem::new();

        // Inactive -> Pass
        let check_inactive = StateCheck::new(SystemState::Inactive);
        assert!(check_inactive.run(&fs).unwrap().is_pass());

        // Active -> Fail
        let check_active = StateCheck::new(SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![],
        });
        assert!(check_active.run(&fs).unwrap().is_fail());

        // Activating -> Fail
        let check_activating = StateCheck::new(SystemState::Activating {
            started_at: Utc::now(),
        });
        assert!(check_activating.run(&fs).unwrap().is_fail());

        // Deactivating -> Fail
        let check_deactivating = StateCheck::new(SystemState::Deactivating {
            started_at: Utc::now(),
        });
        assert!(check_deactivating.run(&fs).unwrap().is_fail());

        // Emergency -> Fail
        let check_emergency = StateCheck::new(SystemState::Emergency {
            triggered_at: Utc::now(),
        });
        assert!(check_emergency.run(&fs).unwrap().is_fail());
    }

    #[test]
    fn test_state_check_integration_with_registry() {
        // Integration test: StateCheck works correctly with PreFlightRegistry
        let fs = MockFilesystem::new();
        let mut registry: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();

        // Test with Inactive state (should pass)
        registry.add_check(Box::new(StateCheck::new(SystemState::Inactive)));
        let result = registry.run_all(&fs);
        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "state");
        assert!(results[0].1.is_pass());

        // Test with Active state (should fail)
        let mut registry_fail: PreFlightRegistry<MockFilesystem> = PreFlightRegistry::new();
        registry_fail.add_check(Box::new(StateCheck::new(SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![],
        })));
        let result_fail = registry_fail.run_all(&fs);
        assert!(result_fail.is_err());
        assert!(matches!(
            result_fail.unwrap_err(),
            NailsError::PreFlightCheckFailed(_)
        ));
    }
}
