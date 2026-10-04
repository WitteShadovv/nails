// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
#[serial]
fn test_idempotent_deactivation() {
    // Setup manager in INACTIVE state
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);

    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let mut manager = NailsManager::new(fs, config, state_path);
    manager.force_state(SystemState::Inactive).unwrap();

    let manager = Arc::new(Mutex::new(manager));
    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    // Run deactivation when already inactive
    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_ok());

    let report = result.unwrap();
    assert!(report.was_already_inactive);
    assert_eq!(report.final_state, SystemState::Inactive);
    assert_eq!(report.unmounted_overlays.len(), 0);
}
#[test]
#[serial]
fn test_deactivation_from_non_active_state_fails() {
    // Setup manager in ACTIVATING state (invalid for deactivation)
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);

    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let mut manager = NailsManager::new(fs, config, state_path);
    manager
        .force_state(SystemState::Activating {
            started_at: chrono::Utc::now(),
        })
        .unwrap();

    let manager = Arc::new(Mutex::new(manager));
    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    // Run deactivation from ACTIVATING state (should fail)
    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_err());

    match result {
        Err(NailsError::InvalidState(msg)) => {
            assert!(msg.contains("Cannot deactivate from state"));
            assert!(msg.contains("Must be ACTIVE"));
        }
        _ => panic!("Expected InvalidState error"),
    }
}
#[test]
#[serial]
fn test_successful_deactivation() {
    let manager = setup_active_manager();

    // Setup filesystem mocks for unmount
    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
        m.filesystem().mock_set_mounted(Path::new("/etc"), true);
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_ok());

    let report = result.unwrap();
    assert!(report.is_successful());
    assert_eq!(report.final_state, SystemState::Inactive);
    assert!(!report.was_already_inactive);

    // Verify state is now INACTIVE
    let m = manager.lock().unwrap();
    let state = m.current_state().unwrap();
    assert_eq!(state, SystemState::Inactive);
}
#[test]
#[serial]
fn test_successful_deactivation_unmounts_all_tracked_overlays_in_lifo_order() {
    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");

    let fs = MockFilesystem::new();
    let _profile = setup_system_profile_stub(&fs);

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let overlays = [
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/tmp"),
    ];
    let mut overlay_status = std::collections::HashMap::new();
    for target in &overlays {
        let name = target
            .strip_prefix("/")
            .expect("overlay target should be absolute");
        let upper_dir = hidden_root.join("overlays").join(name).join("upper");
        let work_dir = hidden_root.join("overlays").join(name).join("work");
        std::fs::create_dir_all(&upper_dir).unwrap();
        std::fs::create_dir_all(&work_dir).unwrap();
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);
        fs.mock_set_mounted(target, true);
        overlay_status.insert(
            target.clone(),
            crate::OverlayInfo {
                mount_method: Default::default(),
                mount_path: target.clone(),
                lower_dir: PathBuf::from("/"),
                upper_dir,
                work_dir,
                mounted_at: chrono::Utc::now(),
            },
        );
    }

    StateFile {
        state: SystemState::Active {
            decoy_writers: Vec::new(),
            activated_at: chrono::Utc::now(),
            overlays: overlays.to_vec(),
        },
        overlay_status,
        ..StateFile::default()
    }
    .save_with_custom_root(&state_path, &hidden_root)
    .unwrap();

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));
    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    let report = orchestrator
        .run(&mut manager.lock().unwrap())
        .expect("deactivation should succeed");

    assert_eq!(
        report.unmounted_overlays,
        vec!["/tmp".to_string(), "/etc".to_string(), "/home".to_string()],
        "deactivation should unmount tracked overlays in reverse mount order"
    );

    let guard = manager.lock().unwrap();
    assert_eq!(guard.current_state().unwrap(), SystemState::Inactive);
    for target in &overlays {
        assert!(
            !guard.filesystem().is_mounted(target).unwrap(),
            "expected {} to be unmounted after deactivation",
            target.display()
        );
    }

    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded.state, SystemState::Inactive);
    assert!(loaded.overlay_status.is_empty());
}
#[test]
#[serial]
fn test_deactivation_clears_failed_overlays_tracker_state() {
    let fs = MockFilesystem::new();
    let _profile = setup_system_profile_stub(&fs);

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let state_file = StateFile {
        state: SystemState::Active {
            decoy_writers: Vec::new(),
            activated_at: chrono::Utc::now(),
            overlays: vec![PathBuf::from("/home")],
        },
        failed_overlays: vec![crate::FailedOverlayInfo {
            target: PathBuf::from("/etc"),
            error_message: "previous failure".to_string(),
            failed_at: chrono::Utc::now(),
        }],
        ..StateFile::default()
    };
    state_file
        .save_with_custom_root(&state_path, &hidden_root)
        .unwrap();

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));
    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
    }

    let orchestrator =
        DeactivationOrchestrator::new(CleanupConfig::default()).with_decoy_profile_restore(false);

    let report = orchestrator
        .run(&mut manager.lock().unwrap())
        .expect("deactivation should succeed");
    assert_eq!(report.final_state, SystemState::Inactive);

    let loaded = StateFile::load(&state_path).unwrap();
    assert!(loaded.failed_overlays.is_empty());
    assert!(loaded.overlay_status.is_empty());
}
#[test]
#[serial]
fn test_normal_mode_is_idempotent_on_inactive() {
    use crate::DeactivationMode;

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);

    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let mut manager = NailsManager::new(fs, config, state_path);
    manager.force_state(SystemState::Inactive).unwrap();

    let manager = Arc::new(Mutex::new(manager));
    let orchestrator =
        DeactivationOrchestrator::new(CleanupConfig::default()).with_mode(DeactivationMode::Normal);

    // Normal mode should be idempotent
    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_ok());
    assert!(result.unwrap().was_already_inactive);
}
