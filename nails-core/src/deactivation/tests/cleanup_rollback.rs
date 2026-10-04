// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
#[serial]
fn test_emergency_cleanup_preserves_explicit_config_path() {
    let fs = MockFilesystem::new();
    let _profile = setup_system_profile_stub(&fs);

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let config_path = PathBuf::from("/tmp/nails-tracker-integrity.yaml");

    fs.mock_set_path_exists("/tmp", true);
    fs.mock_set_files_with_pattern(
        "/tmp",
        "nails",
        &[config_path.as_path(), Path::new("/tmp/nails-status.stdout")],
    );
    fs.mock_set_path_exists(config_path.to_str().unwrap(), true);
    fs.mock_set_path_type(config_path.to_str().unwrap(), PathKind::File);
    fs.mock_set_path_exists("/tmp/nails-status.stdout", true);
    fs.mock_set_path_type("/tmp/nails-status.stdout", PathKind::File);

    let state_file = StateFile {
        state: SystemState::Active {
            decoy_writers: Vec::new(),
            activated_at: chrono::Utc::now(),
            overlays: vec![PathBuf::from("/home")],
        },
        ..StateFile::default()
    };
    state_file
        .save_with_custom_root(&state_path, &hidden_root)
        .unwrap();

    let mut config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    config.loaded_config_path = Some(config_path.clone());

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));
    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
    }

    manager
        .lock()
        .unwrap()
        .emergency_deactivate()
        .expect("emergency deactivation should succeed");

    let m = manager.lock().unwrap();
    assert!(
        m.filesystem()
            .path_exists(&config_path)
            .expect("config path query should succeed"),
        "explicit config path should survive emergency cleanup"
    );
    assert!(
        !m.filesystem()
            .path_exists(Path::new("/tmp/nails-status.stdout"))
            .expect("temp status file query should succeed"),
        "other temp files should still be cleaned"
    );
}
#[test]
#[serial]
fn test_cleanup_failure_rollback() {
    let manager = setup_active_manager();
    // Cleanup resolves the history files from HOME, so it points at the fake
    // home for the whole test.
    let _home = set_safe_test_home();

    // Configure cleanup to FAIL by making the history file write fail
    // This triggers cleanup failure → rollback to ACTIVE
    {
        let m = manager.lock().unwrap();
        let bash_history = Path::new(TEST_HOME).join(".bash_history");
        let bash_history_str = bash_history.to_str().unwrap();

        // Validate path safety before using
        assert_path_is_safe(bash_history_str);

        // Set up history file that exists with "nails" content
        m.filesystem().mock_set_path_exists(bash_history_str, true);

        // Set up file content that contains "nails" pattern
        m.filesystem()
            .mock_set_file_content(bash_history_str, "nails activate\nsome other command\n");

        // Make write fail so cleanup can't actually clean the file
        // This simulates a permission error or filesystem issue during cleanup
        m.filesystem()
            .mock_set_write_should_fail(bash_history_str, true);
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    let result = orchestrator.run(&mut manager.lock().unwrap());

    // Cleanup failure should cause deactivation to fail and rollback to ACTIVE
    // This is required for forensic safety - if traces can't be cleaned, we must
    // remain in ACTIVE state with overlays mounted
    assert!(
        result.is_err(),
        "Expected cleanup to fail, got: {:?}",
        result
    );

    // Verify it's a CleanupError
    match &result {
        Err(NailsError::CleanupError(msg)) => {
            assert!(
                msg.contains("Overlays remain mounted") || msg.contains("verification failed"),
                "Expected error message about rollback, got: {}",
                msg
            );
        }
        _ => panic!("Expected CleanupError, got: {:?}", result),
    }

    // Verify state rolled back to ACTIVE via StateGuard RAII
    // "StateGuard automatically rolls back to ACTIVE"
    let m = manager.lock().unwrap();
    let state = m.current_state().unwrap();
    assert!(
        state.is_active(),
        "Expected ACTIVE state after cleanup failure, got {:?}",
        state
    );
}
#[test]
#[serial]
fn test_cleanup_failure_keeps_overlays_mounted() {
    // Additional test: verify overlays remain mounted after cleanup failure
    let manager = setup_active_manager();
    // Cleanup resolves the history files from HOME, so it points at the fake
    // home for the whole test.
    let _home = set_safe_test_home();

    // Setup overlays as mounted
    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
        m.filesystem().mock_set_mounted(Path::new("/etc"), true);

        // Configure cleanup to fail by making write fail
        let bash_history = Path::new(TEST_HOME).join(".bash_history");
        let bash_history_str = bash_history.to_str().unwrap();

        // Validate path safety before using
        assert_path_is_safe(bash_history_str);

        m.filesystem().mock_set_path_exists(bash_history_str, true);
        m.filesystem()
            .mock_set_file_content(bash_history_str, "nails activate\nsome command\n");
        // Make write fail so cleanup can't actually clean the file
        m.filesystem()
            .mock_set_write_should_fail(bash_history_str, true);
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    let _result = orchestrator.run(&mut manager.lock().unwrap());

    // Verify overlays are still mounted ("overlays are NOT unmounted")
    let m = manager.lock().unwrap();
    let fs = m.filesystem();
    assert!(
        fs.is_mounted(Path::new("/home")).unwrap(),
        "/home should remain mounted after cleanup failure"
    );
    assert!(
        fs.is_mounted(Path::new("/etc")).unwrap(),
        "/etc should remain mounted after cleanup failure"
    );
}
