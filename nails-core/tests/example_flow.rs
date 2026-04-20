//! Integration tests for NailsManager flows using MockFilesystem
//!
//! Tests cover activation, deactivation, state transitions, preflight checks,
//! and emergency deactivation — all using MockFilesystem (no root required).

use nails_core::{
    Config, MockFilesystem, NailsManager, StatusCommand, SystemState, Verifier, VerifyStatus,
};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Helper: create a NailsManager with MockFilesystem inside a tempdir-backed state path.
/// The hidden_volume_root is set to the tempdir so state file validation passes.
fn make_manager() -> (
    Arc<Mutex<NailsManager<MockFilesystem>>>,
    MockFilesystem,
    Config,
    PathBuf,
    tempfile::TempDir,
) {
    let tmp = tempfile::tempdir().unwrap();
    let hidden_root = tmp.path().to_path_buf();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: hidden_root,
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::default()
    };

    let manager = NailsManager::new(fs.clone(), config.clone(), state_path.clone());
    (Arc::new(Mutex::new(manager)), fs, config, state_path, tmp)
}

/// Helper: force the manager into Active state for deactivation tests.
fn force_active(arc: &Arc<Mutex<NailsManager<MockFilesystem>>>) {
    let mut m = arc.lock().unwrap();
    m.force_state(SystemState::Activating {
        started_at: chrono::Utc::now(),
    })
    .unwrap();
    m.force_state(SystemState::Active {
        activated_at: chrono::Utc::now(),
        overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
    })
    .unwrap();
}

// ============================================================================
// 1. test_basic_activation_flow
// ============================================================================

#[test]
fn test_basic_activation_flow() {
    let (arc, _fs, _config, _state_path, _tmp) = make_manager();

    // Initial state is Inactive
    {
        let m = arc.lock().unwrap();
        assert_eq!(m.current_state().unwrap(), SystemState::Inactive);
    }

    // Transition Inactive -> Activating
    {
        let mut m = arc.lock().unwrap();
        m.update_state(SystemState::Activating {
            started_at: chrono::Utc::now(),
        })
        .unwrap();
        assert!(matches!(
            m.current_state().unwrap(),
            SystemState::Activating { .. }
        ));
    }

    // Transition Activating -> Active
    {
        let mut m = arc.lock().unwrap();
        m.update_state(SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![PathBuf::from("/home")],
        })
        .unwrap();
        let state = m.current_state().unwrap();
        assert!(matches!(state, SystemState::Active { .. }));
    }
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
    let (arc, _fs, _config, _state_path, _tmp) = make_manager();
    force_active(&arc);

    // Active -> Deactivating
    {
        let mut m = arc.lock().unwrap();
        m.update_state(SystemState::Deactivating {
            started_at: chrono::Utc::now(),
        })
        .unwrap();
        assert!(matches!(
            m.current_state().unwrap(),
            SystemState::Deactivating { .. }
        ));
    }

    // Deactivating -> Inactive
    {
        let mut m = arc.lock().unwrap();
        m.update_state(SystemState::Inactive).unwrap();
        assert_eq!(m.current_state().unwrap(), SystemState::Inactive);
    }
}

// ============================================================================
// 4. test_state_machine_round_trip
// ============================================================================

#[test]
fn test_state_machine_round_trip() {
    let (arc, _fs, _config, _state_path, _tmp) = make_manager();

    // Inactive -> Activating -> Active
    {
        let mut m = arc.lock().unwrap();
        assert_eq!(m.current_state().unwrap(), SystemState::Inactive);

        m.update_state(SystemState::Activating {
            started_at: chrono::Utc::now(),
        })
        .unwrap();
        m.update_state(SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![PathBuf::from("/home")],
        })
        .unwrap();
    }

    // Active -> Deactivating -> Inactive
    {
        let mut m = arc.lock().unwrap();
        m.update_state(SystemState::Deactivating {
            started_at: chrono::Utc::now(),
        })
        .unwrap();
        m.update_state(SystemState::Inactive).unwrap();
        assert_eq!(m.current_state().unwrap(), SystemState::Inactive);
    }
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
    let result = manager.run_preflight_checks(false);
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
    let (arc, _fs, _config, _state_path, _tmp) = make_manager();
    force_active(&arc);

    // Emergency transition is always valid from any state
    {
        let mut m = arc.lock().unwrap();
        m.update_state(SystemState::Emergency {
            triggered_at: chrono::Utc::now(),
        })
        .unwrap();
        assert!(matches!(
            m.current_state().unwrap(),
            SystemState::Emergency { .. }
        ));
    }
}

// ============================================================================
// 7. test_status_from_various_states
// ============================================================================

#[test]
fn test_status_from_various_states() {
    let (arc, _fs, _config, _state_path, _tmp) = make_manager();

    // Inactive
    {
        let m = arc.lock().unwrap();
        let state = m.current_state().unwrap();
        assert_eq!(state, SystemState::Inactive);
        assert!(!state.is_active());
    }

    // Activating
    {
        let mut m = arc.lock().unwrap();
        m.force_state(SystemState::Activating {
            started_at: chrono::Utc::now(),
        })
        .unwrap();
        let state = m.current_state().unwrap();
        assert!(matches!(state, SystemState::Activating { .. }));
        assert!(!state.is_active());
    }

    // Active
    {
        let mut m = arc.lock().unwrap();
        m.force_state(SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![],
        })
        .unwrap();
        let state = m.current_state().unwrap();
        assert!(state.is_active());
    }

    // Emergency
    {
        let mut m = arc.lock().unwrap();
        m.force_state(SystemState::Emergency {
            triggered_at: chrono::Utc::now(),
        })
        .unwrap();
        let state = m.current_state().unwrap();
        assert!(matches!(state, SystemState::Emergency { .. }));
        assert!(!state.is_active());
    }

    // Deactivating
    {
        let mut m = arc.lock().unwrap();
        m.force_state(SystemState::Deactivating {
            started_at: chrono::Utc::now(),
        })
        .unwrap();
        let state = m.current_state().unwrap();
        assert!(matches!(state, SystemState::Deactivating { .. }));
        assert!(!state.is_active());
    }
}

// ============================================================================
// 8. test_status_command_flow
// ============================================================================

#[test]
fn test_status_command_flow() {
    let (arc, fs, config, state_path, _tmp) = make_manager();
    force_active(&arc);

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
    let (_arc, fs, config, state_path, _tmp) = make_manager();

    let verifier = Verifier::with_config(
        fs,
        config,
        Some(nails_core::StateFile::load(&state_path).unwrap()),
        nails_core::StateFileStatus::NotChecked,
    );
    let result = verifier.run(false).unwrap();

    assert_eq!(result.status, VerifyStatus::Secure);
}
