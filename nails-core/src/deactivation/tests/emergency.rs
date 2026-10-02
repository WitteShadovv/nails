use super::*;

#[test]
#[serial]
fn test_emergency_deactivate_from_inactive_state_returns_error() {
    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);

    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");
    let config = Config {
        hidden_volume_root: temp_dir.path().to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));

    let err = manager.lock().unwrap().emergency_deactivate().unwrap_err();
    assert!(matches!(err, NailsError::InvalidState(_)));
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );
}
#[test]
#[serial]
fn test_emergency_deactivate_from_activating_state_returns_error_without_unmounting() {
    let manager = setup_manager_in_state(SystemState::Activating {
        started_at: chrono::Utc::now(),
    });

    {
        let guard = manager.lock().unwrap();
        let fs = guard.filesystem();
        fs.mock_set_mounted(Path::new("/home"), true);
        fs.mock_set_mounted(Path::new("/etc"), true);
    }

    let err = manager.lock().unwrap().emergency_deactivate().unwrap_err();
    assert!(matches!(err, NailsError::InvalidState(_)));
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("Activating"),
        "unexpected error: {err_msg}"
    );
    assert!(
        err_msg.contains("Must be ACTIVE"),
        "unexpected error: {err_msg}"
    );

    let guard = manager.lock().unwrap();
    assert!(matches!(
        guard.current_state().unwrap(),
        SystemState::Activating { .. }
    ));
    assert!(guard.filesystem().is_mounted(Path::new("/home")).unwrap());
    assert!(guard.filesystem().is_mounted(Path::new("/etc")).unwrap());
}
#[test]
#[serial]
fn test_emergency_deactivate_from_deactivating_state_returns_error_without_unmounting() {
    let manager = setup_manager_in_state(SystemState::Deactivating {
        started_at: chrono::Utc::now(),
    });

    {
        let guard = manager.lock().unwrap();
        let fs = guard.filesystem();
        fs.mock_set_mounted(Path::new("/home"), true);
        fs.mock_set_mounted(Path::new("/etc"), true);
    }

    let err = manager.lock().unwrap().emergency_deactivate().unwrap_err();
    assert!(matches!(err, NailsError::InvalidState(_)));
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("Deactivating"),
        "unexpected error: {err_msg}"
    );
    assert!(
        err_msg.contains("Must be ACTIVE"),
        "unexpected error: {err_msg}"
    );

    let guard = manager.lock().unwrap();
    assert!(matches!(
        guard.current_state().unwrap(),
        SystemState::Deactivating { .. }
    ));
    assert!(guard.filesystem().is_mounted(Path::new("/home")).unwrap());
    assert!(guard.filesystem().is_mounted(Path::new("/etc")).unwrap());
}
#[test]
#[serial]
fn test_emergency_deactivate_force_unmount_succeeds_after_graceful_failure() {
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
    let upper_dir = hidden_root.join("overlays/home/upper");
    let work_dir = hidden_root.join("overlays/home/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    write_state_with_overlay(
        &state_path,
        &hidden_root,
        Path::new("/home"),
        &upper_dir,
        &work_dir,
    );

    let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));

    {
        let manager_guard = manager.lock().unwrap();
        let fs = manager_guard.filesystem();
        fs.mock_set_mounted(Path::new("/home"), true);
        fs.mock_set_unmount_graceful_fails("/home", true);
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);
    }

    manager
        .lock()
        .unwrap()
        .emergency_deactivate()
        .expect("deactivation should work");

    let manager_guard = manager.lock().unwrap();
    assert_eq!(
        manager_guard.current_state().unwrap(),
        SystemState::Inactive
    );
    assert!(
        !manager_guard
            .filesystem()
            .is_mounted(Path::new("/home"))
            .unwrap()
    );
    let loaded =
        StateFile::load(&manager_guard.config().hidden_volume_root.join("state.json")).unwrap();
    assert!(loaded.overlay_status.is_empty());
}
#[test]
#[serial]
fn test_emergency_deactivate_restarts_nix_daemon_when_nix_store_unmount_fails() {
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
    let upper_dir = hidden_root.join("overlays/nix/upper");
    let work_dir = hidden_root.join("overlays/nix/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    write_state_with_overlay(
        &state_path,
        &hidden_root,
        Path::new("/nix"),
        &upper_dir,
        &work_dir,
    );

    let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));

    {
        let manager_guard = manager.lock().unwrap();
        let fs = manager_guard.filesystem();
        fs.mock_set_mounted(Path::new("/nix"), true);
        fs.mock_set_mounted(Path::new("/nix/store"), true);
        // The read-only /nix/store bind refuses to unmount; teardown must treat
        // that as best-effort and still restart nix-daemon, rather than leaving
        // the decoy without a daemon.
        fs.mock_set_unmount_should_fail("/nix/store", true);
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);
    }

    // Clear any recorder residue left on this thread by earlier work.
    let _ = crate::manager::helpers::drain_recorded_service_actions();

    manager
        .lock()
        .unwrap()
        .emergency_deactivate()
        .expect("a best-effort /nix/store unmount failure must not abort deactivation");

    let actions = crate::manager::helpers::drain_recorded_service_actions();
    assert!(
        actions.iter().any(|action| action == "start:nix-daemon"),
        "nix-daemon must be restarted even when the /nix/store bind unmount fails: {actions:?}"
    );
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive,
        "deactivation should complete to Inactive once the /nix overlay is unmounted"
    );
}
#[test]
#[serial]
fn test_emergency_deactivate_missing_switch_script_keeps_inactive_state() {
    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");

    let fs = MockFilesystem::new();
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        log_path: hidden_root.join("logs"),
        overlays: vec![],
        ..Config::test_default()
    };

    let system_profile = hidden_root.join("profiles/system");
    let profiles_dir = system_profile.parent().unwrap().to_path_buf();
    let generation_dir = profiles_dir.join("system-1-link");
    std::fs::create_dir_all(&generation_dir).unwrap();
    env.set("NAILS_SYSTEM_PROFILE_PATH", &system_profile);
    fs.mock_set_path_exists(profiles_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(profiles_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_directory_contents(&profiles_dir, vec![generation_dir.clone()]);

    let upper_dir = hidden_root.join("overlays/home/upper");
    let work_dir = hidden_root.join("overlays/home/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);
    fs.mock_set_mounted(Path::new("/home"), true);

    write_state_with_overlay(
        &state_path,
        &hidden_root,
        Path::new("/home"),
        &upper_dir,
        &work_dir,
    );

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));

    manager
        .lock()
        .unwrap()
        .emergency_deactivate()
        .expect("overlay-only emergency deactivation should work");
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );

    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded.state, SystemState::Inactive);
    assert!(loaded.overlay_status.is_empty());
}
#[test]
#[serial]
fn test_emergency_deactivate_unmounts_nix_store_when_nix_overlay_present() {
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
    let upper_dir = hidden_root.join("overlays/nix/upper");
    let work_dir = hidden_root.join("overlays/nix/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    write_state_with_overlay(
        &state_path,
        &hidden_root,
        Path::new("/nix"),
        &upper_dir,
        &work_dir,
    );

    let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));

    {
        let manager_guard = manager.lock().unwrap();
        let fs = manager_guard.filesystem();
        fs.mock_set_mounted(Path::new("/nix"), true);
        fs.mock_set_mounted(Path::new("/nix/store"), true);
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);
    }

    manager
        .lock()
        .unwrap()
        .emergency_deactivate()
        .expect("deactivation should work");

    let manager_guard = manager.lock().unwrap();
    assert_eq!(
        manager_guard.current_state().unwrap(),
        SystemState::Inactive
    );
    assert!(
        !manager_guard
            .filesystem()
            .is_mounted(Path::new("/nix"))
            .unwrap()
    );
    assert!(
        !manager_guard
            .filesystem()
            .is_mounted(Path::new("/nix/store"))
            .unwrap()
    );
}
#[test]
#[serial]
fn test_emergency_mode_skips_non_essential_steps() {
    use crate::DeactivationMode;

    let manager = setup_active_manager();

    // Setup overlays as mounted
    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
        m.filesystem().mock_set_mounted(Path::new("/etc"), true);
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default())
        .with_mode(DeactivationMode::Emergency);

    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_ok(), "Emergency deactivation should succeed");

    let report = result.unwrap();
    assert!(report.is_successful());
    assert_eq!(report.final_state, SystemState::Inactive);
    assert!(!report.was_already_inactive);

    // Emergency mode should skip post-unmount cleanup
    assert!(
        !report.post_unmount_cleanup.was_performed,
        "Emergency mode should skip post-unmount cleanup"
    );
}
#[test]
#[serial]
fn test_emergency_mode_fails_on_inactive_state() {
    use crate::DeactivationMode;

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
    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default())
        .with_mode(DeactivationMode::Emergency);

    // Emergency mode should NOT be idempotent - must fail on Inactive
    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(
        result.is_err(),
        "Emergency mode should fail on Inactive state"
    );

    match result {
        Err(NailsError::InvalidState(msg)) => {
            assert!(msg.contains("Cannot deactivate"));
        }
        _ => panic!("Expected InvalidState error"),
    }
}
