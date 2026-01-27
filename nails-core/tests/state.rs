//! Integration tests for SystemState enum and state transitions
//!
//! These tests verify the public API of the state machine module,
//! testing it as external consumers would use it.

use nails_core::SystemState;
use std::path::PathBuf;

// =============================================================================
// Valid State Transitions Tests
// =============================================================================

#[test]
fn test_begin_activation_from_inactive_returns_activating() {
    let state = SystemState::Inactive;
    let result = state.begin_activation();
    assert!(result.is_ok());
    match result.unwrap() {
        SystemState::Activating { .. } => {} // Expected
        _ => panic!("Expected Activating state"),
    }
}

#[test]
fn test_complete_activation_from_activating_returns_active() {
    let state = SystemState::Activating {
        started_at: chrono::Utc::now(),
    };
    let overlays = vec![PathBuf::from("/mnt/overlay1")];
    let result = state.complete_activation(overlays.clone());
    assert!(result.is_ok());
    match result.unwrap() {
        SystemState::Active {
            overlays: o,
            activated_at,
            ..
        } => {
            assert_eq!(o, overlays);
            assert!(activated_at <= chrono::Utc::now());
        }
        _ => panic!("Expected Active state"),
    }
}

#[test]
fn test_begin_deactivation_from_active_returns_deactivating() {
    let state = SystemState::Active {
        activated_at: chrono::Utc::now(),
        overlays: vec![],
    };
    let result = state.begin_deactivation();
    assert!(result.is_ok());
    match result.unwrap() {
        SystemState::Deactivating { .. } => {} // Expected
        _ => panic!("Expected Deactivating state"),
    }
}

#[test]
fn test_complete_deactivation_from_deactivating_returns_inactive() {
    let state = SystemState::Deactivating {
        started_at: chrono::Utc::now(),
    };
    let result = state.complete_deactivation();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), SystemState::Inactive);
}

#[test]
fn test_trigger_emergency_from_any_state_returns_emergency() {
    let states = vec![
        SystemState::Inactive,
        SystemState::Activating {
            started_at: chrono::Utc::now(),
        },
        SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![],
        },
        SystemState::Deactivating {
            started_at: chrono::Utc::now(),
        },
        SystemState::Emergency {
            triggered_at: chrono::Utc::now(),
        },
    ];

    for state in states {
        let result = state.trigger_emergency();
        assert!(result.is_ok());
        match result.unwrap() {
            SystemState::Emergency { .. } => {} // Expected
            _ => panic!("Expected Emergency state"),
        }
    }
}

#[test]
fn test_timestamps_are_captured_correctly() {
    let before = chrono::Utc::now();
    let state = SystemState::Inactive;
    let activating = state.begin_activation().unwrap();
    let after = chrono::Utc::now();

    match activating {
        SystemState::Activating { started_at } => {
            assert!(started_at >= before);
            assert!(started_at <= after);
        }
        _ => panic!("Expected Activating state"),
    }
}

// =============================================================================
// Invalid State Transitions Tests
// =============================================================================

#[test]
fn test_begin_activation_from_active_returns_err() {
    let state = SystemState::Active {
        activated_at: chrono::Utc::now(),
        overlays: vec![],
    };
    let result = state.begin_activation();
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Cannot activate: already active")
    );
}

#[test]
fn test_complete_activation_from_inactive_returns_err() {
    let state = SystemState::Inactive;
    let result = state.complete_activation(vec![]);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("not in activating state")
    );
}

#[test]
fn test_begin_deactivation_from_inactive_returns_err() {
    let state = SystemState::Inactive;
    let result = state.begin_deactivation();
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("system is not active")
    );
}

#[test]
fn test_complete_deactivation_from_activating_returns_err() {
    let state = SystemState::Activating {
        started_at: chrono::Utc::now(),
    };
    let result = state.complete_deactivation();
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("activation in progress")
    );
}

#[test]
fn test_state_remains_unchanged_on_invalid_transition() {
    let state = SystemState::Inactive;
    let original = state.clone();
    let _ = state.begin_deactivation(); // Invalid transition
    assert_eq!(state, original); // State unchanged
}

#[test]
fn test_error_messages_are_descriptive() {
    let state = SystemState::Active {
        activated_at: chrono::Utc::now(),
        overlays: vec![],
    };
    let result = state.begin_activation();
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("already active"));
    assert!(err_msg.contains("Cannot activate"));
}

// =============================================================================
// Helper Predicate Methods Tests
// =============================================================================

#[test]
fn test_is_active_returns_true_for_active_state() {
    let state = SystemState::Active {
        activated_at: chrono::Utc::now(),
        overlays: vec![],
    };
    assert!(state.is_active());
}

#[test]
fn test_is_active_returns_false_for_non_active_states() {
    let states = vec![
        SystemState::Inactive,
        SystemState::Activating {
            started_at: chrono::Utc::now(),
        },
        SystemState::Deactivating {
            started_at: chrono::Utc::now(),
        },
        SystemState::Emergency {
            triggered_at: chrono::Utc::now(),
        },
    ];

    for state in states {
        assert!(!state.is_active());
    }
}

#[test]
fn test_is_inactive_returns_true_for_inactive_state() {
    let state = SystemState::Inactive;
    assert!(state.is_inactive());
}

#[test]
fn test_is_inactive_returns_false_for_non_inactive_states() {
    let states = vec![
        SystemState::Activating {
            started_at: chrono::Utc::now(),
        },
        SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![],
        },
        SystemState::Deactivating {
            started_at: chrono::Utc::now(),
        },
        SystemState::Emergency {
            triggered_at: chrono::Utc::now(),
        },
    ];

    for state in states {
        assert!(!state.is_inactive());
    }
}

#[test]
fn test_can_deactivate_returns_true_for_active_state() {
    let state = SystemState::Active {
        activated_at: chrono::Utc::now(),
        overlays: vec![],
    };
    assert!(state.can_deactivate());
}

#[test]
fn test_can_deactivate_returns_false_for_non_active_states() {
    let states = vec![
        SystemState::Inactive,
        SystemState::Activating {
            started_at: chrono::Utc::now(),
        },
        SystemState::Deactivating {
            started_at: chrono::Utc::now(),
        },
        SystemState::Emergency {
            triggered_at: chrono::Utc::now(),
        },
    ];

    for state in states {
        assert!(!state.can_deactivate());
    }
}

#[test]
fn test_predicates_used_in_transition_validation() {
    // Verify that predicates correctly identify state for transitions
    let inactive = SystemState::Inactive;
    assert!(inactive.is_inactive());
    assert!(inactive.begin_activation().is_ok());

    let active = SystemState::Active {
        activated_at: chrono::Utc::now(),
        overlays: vec![],
    };
    assert!(active.is_active());
    assert!(active.can_deactivate());
    assert!(active.begin_deactivation().is_ok());
}

// =============================================================================
// Comprehensive Edge Case Tests
// =============================================================================

#[test]
fn test_serialization_roundtrip() {
    let state = SystemState::Active {
        activated_at: chrono::Utc::now(),
        overlays: vec![PathBuf::from("/mnt/test")],
    };

    let json = serde_json::to_string(&state).expect("Serialization should succeed");
    let deserialized: SystemState =
        serde_json::from_str(&json).expect("Deserialization should succeed");

    assert_eq!(state, deserialized);
}

#[test]
fn test_all_invalid_transitions_from_activating() {
    let state = SystemState::Activating {
        started_at: chrono::Utc::now(),
    };

    // Should fail
    assert!(state.begin_activation().is_err());
    assert!(state.begin_deactivation().is_err());
    assert!(state.complete_deactivation().is_err());

    // Should succeed
    assert!(state.complete_activation(vec![]).is_ok());
    assert!(state.trigger_emergency().is_ok());
}

#[test]
fn test_all_invalid_transitions_from_deactivating() {
    let state = SystemState::Deactivating {
        started_at: chrono::Utc::now(),
    };

    // Should fail
    assert!(state.begin_activation().is_err());
    assert!(state.complete_activation(vec![]).is_err());
    assert!(state.begin_deactivation().is_err());

    // Should succeed
    assert!(state.complete_deactivation().is_ok());
    assert!(state.trigger_emergency().is_ok());
}

#[test]
fn test_all_invalid_transitions_from_emergency() {
    let state = SystemState::Emergency {
        triggered_at: chrono::Utc::now(),
    };

    // All transitions should fail except emergency (which is idempotent)
    assert!(state.begin_activation().is_err());
    assert!(state.complete_activation(vec![]).is_err());
    assert!(state.begin_deactivation().is_err());
    assert!(state.complete_deactivation().is_err());

    // Emergency is idempotent
    assert!(state.trigger_emergency().is_ok());
}

#[test]
fn test_complete_state_transition_flow() {
    // Full lifecycle: Inactive → Activating → Active → Deactivating → Inactive
    let state = SystemState::Inactive;

    let state = state.begin_activation().expect("Should activate");
    assert!(matches!(state, SystemState::Activating { .. }));

    let overlays = vec![PathBuf::from("/test")];
    let state = state
        .complete_activation(overlays.clone())
        .expect("Should complete activation");
    match &state {
        SystemState::Active { overlays: o, .. } => assert_eq!(o, &overlays),
        _ => panic!("Expected Active state"),
    }

    let state = state.begin_deactivation().expect("Should deactivate");
    assert!(matches!(state, SystemState::Deactivating { .. }));

    let state = state
        .complete_deactivation()
        .expect("Should complete deactivation");
    assert_eq!(state, SystemState::Inactive);
}

#[test]
fn test_emergency_from_active_state() {
    let state = SystemState::Active {
        activated_at: chrono::Utc::now(),
        overlays: vec![PathBuf::from("/test1"), PathBuf::from("/test2")],
    };

    let emergency = state
        .trigger_emergency()
        .expect("Emergency should always work");
    assert!(matches!(emergency, SystemState::Emergency { .. }));
}

#[test]
fn test_enum_derives_debug_clone_partialeq() {
    let state1 = SystemState::Inactive;
    let state2 = state1.clone();

    // Test Debug
    let debug_str = format!("{:?}", state1);
    assert!(debug_str.contains("Inactive"));

    // Test PartialEq
    assert_eq!(state1, state2);

    // Test Clone
    let state3 = SystemState::Active {
        activated_at: chrono::Utc::now(),
        overlays: vec![],
    };
    let state4 = state3.clone();
    assert_eq!(state3, state4);
}

// =============================================================================
// Additional Edge Case Coverage Tests
// =============================================================================

#[test]
fn test_complete_activation_from_active_returns_err() {
    let state = SystemState::Active {
        activated_at: chrono::Utc::now(),
        overlays: vec![],
    };
    let result = state.complete_activation(vec![]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("already active"));
}

#[test]
fn test_complete_activation_from_deactivating_returns_err() {
    let state = SystemState::Deactivating {
        started_at: chrono::Utc::now(),
    };
    let result = state.complete_activation(vec![]);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("deactivation in progress")
    );
}

#[test]
fn test_complete_activation_from_emergency_returns_err() {
    let state = SystemState::Emergency {
        triggered_at: chrono::Utc::now(),
    };
    let result = state.complete_activation(vec![]);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("emergency state"));
}

#[test]
fn test_complete_deactivation_from_inactive_returns_err() {
    let state = SystemState::Inactive;
    let result = state.complete_deactivation();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("already inactive"));
}

#[test]
fn test_complete_deactivation_from_active_returns_err() {
    let state = SystemState::Active {
        activated_at: chrono::Utc::now(),
        overlays: vec![],
    };
    let result = state.complete_deactivation();
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("not in deactivating state")
    );
}

#[test]
fn test_complete_deactivation_from_emergency_returns_err() {
    let state = SystemState::Emergency {
        triggered_at: chrono::Utc::now(),
    };
    let result = state.complete_deactivation();
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("emergency state"));
}
