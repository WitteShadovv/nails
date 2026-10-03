//! Integration tests for NailsManager flows using MockFilesystem
//!
//! Tests cover activation, deactivation, state transitions, preflight checks,
//! and emergency deactivation — all using MockFilesystem (no root required).

use nails_core::{
    Config, MockFilesystem, NailsManager, StatusCommand, SystemState, TestWorld, Verifier,
    VerifyStatus,
};
use std::path::PathBuf;

/// Force a freshly built manager into the Active state that the deactivation,
/// status and verify flows start from.
fn force_active(manager: &mut NailsManager<MockFilesystem>) {
    manager
        .force_state(SystemState::Activating {
            started_at: chrono::Utc::now(),
        })
        .unwrap();
    manager
        .force_state(SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
            decoy_writers: Vec::new(),
        })
        .unwrap();
}

// ============================================================================
// 1. test_basic_activation_flow
// ============================================================================

#[test]
fn test_basic_activation_flow() {
    let (mut manager, _tmp) = TestWorld::new().manager();

    // Initial state is Inactive
    assert_eq!(manager.current_state().unwrap(), SystemState::Inactive);

    // Transition Inactive -> Activating
    manager
        .update_state(SystemState::Activating {
            started_at: chrono::Utc::now(),
        })
        .unwrap();
    assert!(matches!(
        manager.current_state().unwrap(),
        SystemState::Activating { .. }
    ));

    // Transition Activating -> Active
    manager
        .update_state(SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![PathBuf::from("/home")],
            decoy_writers: Vec::new(),
        })
        .unwrap();
    assert!(matches!(
        manager.current_state().unwrap(),
        SystemState::Active { .. }
    ));
}

// ============================================================================
// 2. test_activation_with_config
// ============================================================================

#[test]
fn test_activation_with_config() {
    let tmp = tempfile::tempdir().unwrap();
    let hidden_root = tmp.path().to_path_buf();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: hidden_root,
        state_file_path: state_path.clone(),
        overlays: vec![],
        clear_history: false,
        minimum_space_mb: 999,
        ..Config::default()
    };

    let mut manager = NailsManager::new(fs, config, state_path);

    // Verify config is respected
    assert!(!manager.config().clear_history);
    assert_eq!(manager.config().minimum_space_mb, 999);

    // Can still transition through states
    manager
        .update_state(SystemState::Activating {
            started_at: chrono::Utc::now(),
        })
        .unwrap();
    assert!(matches!(
        manager.current_state().unwrap(),
        SystemState::Activating { .. }
    ));
}

// ============================================================================
// 3. test_deactivation_flow
// ============================================================================

#[test]
fn test_deactivation_flow() {
    let (mut manager, _tmp) = TestWorld::new().manager();
    force_active(&mut manager);

    // Active -> Deactivating
    manager
        .update_state(SystemState::Deactivating {
            started_at: chrono::Utc::now(),
        })
        .unwrap();
    assert!(matches!(
        manager.current_state().unwrap(),
        SystemState::Deactivating { .. }
    ));

    // Deactivating -> Inactive
    manager.update_state(SystemState::Inactive).unwrap();
    assert_eq!(manager.current_state().unwrap(), SystemState::Inactive);
}

// ============================================================================
// 4. test_state_machine_round_trip
// ============================================================================

#[test]
fn test_state_machine_round_trip() {
    let (mut manager, _tmp) = TestWorld::new().manager();

    // Inactive -> Activating -> Active
    assert_eq!(manager.current_state().unwrap(), SystemState::Inactive);
    manager
        .update_state(SystemState::Activating {
            started_at: chrono::Utc::now(),
        })
        .unwrap();
    manager
        .update_state(SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![PathBuf::from("/home")],
            decoy_writers: Vec::new(),
        })
        .unwrap();

    // Active -> Deactivating -> Inactive
    manager
        .update_state(SystemState::Deactivating {
            started_at: chrono::Utc::now(),
        })
        .unwrap();
    manager.update_state(SystemState::Inactive).unwrap();
    assert_eq!(manager.current_state().unwrap(), SystemState::Inactive);
}

// ============================================================================
// 5. test_preflight_check_rejection
// ============================================================================

#[test]
fn test_preflight_check_rejection() {
    let tmp = tempfile::tempdir().unwrap();
    let hidden_root = tmp.path().to_path_buf();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();
    // Do NOT set hidden_volume_root as existing in the mock — preflight should fail
    // because the hidden volume check will find it non-existent.

    let config = Config {
        hidden_volume_root: hidden_root,
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::default()
    };

    let manager = NailsManager::new(fs, config, state_path);

    // run_preflight_checks should fail because hidden volume doesn't "exist" in the mock
    let result = manager.run_preflight_checks(false, false);
    assert!(
        result.is_err(),
        "Preflight should reject when hidden volume not present in mock"
    );
}

// ============================================================================
// 6. test_emergency_deactivation
// ============================================================================

#[test]
fn test_emergency_deactivation() {
    let (mut manager, _tmp) = TestWorld::new().manager();
    force_active(&mut manager);

    // A partial emergency teardown can degrade from any live state.
    manager
        .update_state(SystemState::Degraded {
            since: chrono::Utc::now(),
            reason: "emergency teardown left mounts".into(),
            remaining_mounts: vec![],
        })
        .unwrap();
    assert!(matches!(
        manager.current_state().unwrap(),
        SystemState::Degraded { .. }
    ));
}

// ============================================================================
// 7. test_status_from_various_states
// ============================================================================

#[test]
fn test_status_from_various_states() {
    let (mut manager, _tmp) = TestWorld::new().manager();

    // Inactive
    let state = manager.current_state().unwrap();
    assert_eq!(state, SystemState::Inactive);
    assert!(!state.is_active());

    // Activating
    manager
        .force_state(SystemState::Activating {
            started_at: chrono::Utc::now(),
        })
        .unwrap();
    let state = manager.current_state().unwrap();
    assert!(matches!(state, SystemState::Activating { .. }));
    assert!(!state.is_active());

    // Active
    manager
        .force_state(SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![],
            decoy_writers: Vec::new(),
        })
        .unwrap();
    assert!(manager.current_state().unwrap().is_active());

    // Degraded
    manager
        .force_state(SystemState::Degraded {
            since: chrono::Utc::now(),
            reason: "unmount failed".into(),
            remaining_mounts: vec![],
        })
        .unwrap();
    let state = manager.current_state().unwrap();
    assert!(matches!(state, SystemState::Degraded { .. }));
    assert!(!state.is_active());

    // Deactivating
    manager
        .force_state(SystemState::Deactivating {
            started_at: chrono::Utc::now(),
        })
        .unwrap();
    let state = manager.current_state().unwrap();
    assert!(matches!(state, SystemState::Deactivating { .. }));
    assert!(!state.is_active());
}

// ============================================================================
// 8. test_status_command_flow
// ============================================================================

#[test]
fn test_status_command_flow() {
    let (mut manager, _tmp) = TestWorld::new().manager();
    force_active(&mut manager);

    let fs = manager.filesystem().clone();
    let config = manager.config().clone();
    let state_path = config.state_file_path.clone();

    fs.mock_set_mounted(PathBuf::from("/home").as_path(), true);
    fs.mock_set_mounted(PathBuf::from("/etc").as_path(), true);

    let status = StatusCommand::new(fs, config, state_path).run().unwrap();

    assert!(matches!(status.state, SystemState::Active { .. }));
    assert_eq!(status.overlays.len(), 2);
}

// ============================================================================
// 9. test_verify_flow
// ============================================================================

#[test]
fn test_verify_flow() {
    let (manager, _tmp) = TestWorld::new().manager();
    let fs = manager.filesystem().clone();
    let config = manager.config().clone();
    let state_path = config.state_file_path.clone();

    let verifier = Verifier::with_config(
        fs,
        config,
        Some(nails_core::StateFile::load(&state_path).unwrap()),
        nails_core::StateFileStatus::NotChecked,
    );
    let result = verifier.run(false).unwrap();

    assert_eq!(result.status, VerifyStatus::Secure);
}
