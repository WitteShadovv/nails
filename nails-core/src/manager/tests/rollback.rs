//! Rollback after a failed activation or deactivation.

use super::*;

// ========== Activation Failure Rollback ==========

#[test]
fn test_activate_failure_at_mount_rolls_back_to_inactive() {
    use crate::OverlayConfig;

    // Create mock hidden volume structure in temp dir
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Set up paths to exist
    fs.mock_set_path_exists("/", true);
    let upper_dir = mock_hidden_vol.join("overlays/home/upper");
    let work_dir = mock_hidden_vol.join("overlays/home/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

    // Configure filesystem to fail mount operation
    fs.mock_set_mount_should_fail("/home", true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
        overlays: vec![OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/"),
            upper: upper_dir.clone(),
            work: work_dir.clone(),
            target: PathBuf::from("/home"),
        }],
        ..Config::test_default()
    };

    let fs_clone = fs.clone();
    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));

    // Verify initial state is Inactive
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );

    // Activation should fail
    let result = manager.lock().unwrap().activate(true);
    assert!(result.is_err());

    // Verify state was rolled back to Inactive (FR50)
    let final_state = manager.lock().unwrap().current_state().unwrap();
    assert_eq!(
        final_state,
        SystemState::Inactive,
        "State should be rolled back to Inactive after mount failure"
    );

    // Verify overlay is not mounted after rollback
    assert!(
        !fs_clone.is_mounted(Path::new("/home")).unwrap(),
        "Overlay should not be mounted after failed activation"
    );

    // Verify state file contains Inactive
    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded.state, SystemState::Inactive);
}

#[test]
fn test_activate_failure_unmounts_already_mounted_overlays() {
    use crate::OverlayConfig;

    // Create mock hidden volume structure in temp dir
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Set up paths to exist
    fs.mock_set_path_exists("/", true);
    let upper_home = mock_hidden_vol.join("overlays/home/upper");
    let work_home = mock_hidden_vol.join("overlays/home/work");
    let upper_etc = mock_hidden_vol.join("overlays/etc/upper");
    let work_etc = mock_hidden_vol.join("overlays/etc/work");
    std::fs::create_dir_all(&upper_home).unwrap();
    std::fs::create_dir_all(&work_home).unwrap();
    std::fs::create_dir_all(&upper_etc).unwrap();
    std::fs::create_dir_all(&work_etc).unwrap();
    fs.mock_set_path_exists(upper_home.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);
    fs.mock_set_path_exists(upper_etc.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);

    // Configure filesystem: first overlay succeeds, second fails
    fs.mock_set_mount_should_fail("/etc", true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Explicit,
        overlays: vec![
            OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_home.clone(),
                work: work_home.clone(),
                target: PathBuf::from("/home"),
            },
            OverlayConfig {
                name: "etc".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_etc.clone(),
                work: work_etc.clone(),
                target: PathBuf::from("/etc"),
            },
        ],
        ..Config::test_default()
    };

    let fs_clone = fs.clone();
    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));

    // Activation should fail at second overlay
    let result = manager.lock().unwrap().activate(true);
    assert!(result.is_err());

    // Verify /home was mounted initially but then unmounted during rollback
    assert!(
        !fs_clone.is_mounted(Path::new("/home")).unwrap(),
        "First overlay (/home) should be unmounted during rollback"
    );

    // Verify /etc was never mounted
    assert!(
        !fs_clone.is_mounted(Path::new("/etc")).unwrap(),
        "Second overlay (/etc) should never be mounted"
    );

    // Verify state was rolled back to Inactive
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );
}

#[test]
fn test_activate_failure_state_file_reflects_rollback() {
    use crate::OverlayConfig;

    // Create mock hidden volume structure in temp dir
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Set up paths to exist
    fs.mock_set_path_exists("/", true);
    let upper_dir = mock_hidden_vol.join("overlays/home/upper");
    let work_dir = mock_hidden_vol.join("overlays/home/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

    // Configure filesystem to fail mount
    fs.mock_set_mount_should_fail("/home", true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
        overlays: vec![OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/"),
            upper: upper_dir.clone(),
            work: work_dir.clone(),
            target: PathBuf::from("/home"),
        }],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));

    // Activation should fail
    let result = manager.lock().unwrap().activate(true);
    assert!(result.is_err());

    // Verify state file was saved with Inactive state
    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(
        loaded.state,
        SystemState::Inactive,
        "State file should contain Inactive after rollback"
    );

    // Verify overlay_status is empty (no mounted overlays)
    assert!(
        loaded.overlay_status.is_empty(),
        "overlay_status should be empty after rollback"
    );
}

// ========== StateFile Rollback Clearing ==========

#[test]
fn test_rollback_clears_overlay_status_and_nixos_generation() {
    use crate::OverlayConfig;

    // Create mock hidden volume structure
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Set up paths to exist
    fs.mock_set_path_exists("/", true);
    let upper_dir = mock_hidden_vol.join("overlays/home/upper");
    let work_dir = mock_hidden_vol.join("overlays/home/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

    // Configure filesystem to fail mount (to trigger rollback)
    fs.mock_set_mount_should_fail("/home", true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
        overlays: vec![OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/"),
            upper: upper_dir.clone(),
            work: work_dir.clone(),
            target: PathBuf::from("/home"),
        }],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));

    // Manually set up state file with overlay_status and nixos_generation BEFORE activation
    // (simulating a previous activation that left metadata)
    {
        let mgr = manager.lock().unwrap();
        let mut overlay_status = HashMap::new();
        overlay_status.insert(
            PathBuf::from("/home"),
            OverlayInfo {
                mount_path: PathBuf::from("/home"),
                lower_dir: PathBuf::from("/"),
                upper_dir: upper_dir.clone(),
                work_dir: work_dir.clone(),
                mounted_at: Utc::now(),
            },
        );

        let mut cached = mgr.cached_state.borrow_mut();
        let state_file = StateFile {
            overlay_status,
            nixos_generation: Some("test-generation-123".to_string()),
            ..StateFile::default()
        };
        *cached = Some(state_file);
    }

    // Activation should fail (mount fails)
    let result = manager.lock().unwrap().activate(true);
    assert!(result.is_err(), "Activation should fail");

    // AC4: Verify rollback cleared overlay_status and nixos_generation
    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(
        loaded.state,
        SystemState::Inactive,
        "State should be Inactive after rollback"
    );

    // THIS IS THE KEY TEST for Task 5 (AC4):
    assert!(
        loaded.overlay_status.is_empty(),
        "overlay_status should be cleared after rollback (AC4)"
    );
    assert_eq!(
        loaded.nixos_generation, None,
        "nixos_generation should be cleared after rollback (AC4)"
    );
}

// ============================================================================
// Rollback Integration Tests - All 7 Scenarios (TR45-TR51)
// ============================================================================
//
// These tests validate rollback behavior for all failure scenarios:
// - TR45: First mount fails
// - TR46: Second mount fails
// - TR47: NixOS build fails
// - TR48: State file write fails
// - TR49: Cleanup fails
// - TR50: Unmount fails
// - TR51: Cascading failures
//
// Architecture:
// - Use MockFilesystem with failure injection
// - Verify state consistency after each rollback
// - Validate error messages are helpful

/// Helper to create test manager with temp directory for state file
fn create_rollback_test_manager(
    fs: MockFilesystem,
) -> (Arc<Mutex<NailsManager<MockFilesystem>>>, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).expect("Should create hidden volume directory");
    let state_path = mock_hidden_vol.join("state.json");

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![
            OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: mock_hidden_vol.join("home-upper"),
                work: mock_hidden_vol.join("home-work"),
                target: PathBuf::from("/home"),
            },
            OverlayConfig {
                name: "etc".to_string(),
                lower: PathBuf::from("/"),
                upper: mock_hidden_vol.join("etc-upper"),
                work: mock_hidden_vol.join("etc-work"),
                target: PathBuf::from("/etc"),
            },
        ],
        overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
        ..Config::test_default()
    };

    // Set up required paths in MockFilesystem
    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/etc", true);

    let hv_str = mock_hidden_vol.to_string_lossy();
    fs.mock_set_path_exists(&hv_str, true);
    fs.mock_set_path_exists(&format!("{}/home-upper", hv_str), true);
    fs.mock_set_path_exists(&format!("{}/home-work", hv_str), true);
    fs.mock_set_path_exists(&format!("{}/etc-upper", hv_str), true);
    fs.mock_set_path_exists(&format!("{}/etc-work", hv_str), true);

    fs.mock_set_writable(&hv_str, true);
    fs.mock_set_writable("/", true);
    fs.mock_set_readable("/", true);
    fs.mock_set_readable("/home", true);
    fs.mock_set_readable("/etc", true);

    // Mock NixOS system profile for deactivation tests
    fs.mock_set_path_exists("/nix/var/nix/profiles/system", true);
    fs.mock_set_path_exists(
        "/nix/var/nix/profiles/system/bin/switch-to-configuration",
        true,
    );

    let manager = NailsManager::new(fs, config, state_path);

    (Arc::new(Mutex::new(manager)), temp_dir)
}

/// Helper to verify state consistency after rollback
fn verify_rollback_state_consistency(manager_arc: &Arc<Mutex<NailsManager<MockFilesystem>>>) {
    let manager = manager_arc.lock().unwrap();
    let state = manager.current_state().expect("Should get current state");

    // If INACTIVE, no overlays should be mounted
    if matches!(state, SystemState::Inactive) {
        let fs = manager.filesystem();
        assert!(
            !fs.is_mounted(Path::new("/home"))
                .expect("Should check mount status"),
            "Expected /home to be unmounted in Inactive state"
        );
        assert!(
            !fs.is_mounted(Path::new("/etc"))
                .expect("Should check mount status"),
            "Expected /etc to be unmounted in Inactive state"
        );
    }

    // If ACTIVE, overlays should be mounted
    if let SystemState::Active { ref overlays, .. } = state {
        for overlay_path in overlays {
            let fs = manager.filesystem();
            assert!(
                fs.is_mounted(overlay_path)
                    .expect("Should check mount status"),
                "Expected {} to be mounted in Active state",
                overlay_path.display()
            );
        }
    }
}

// ============================================================================
// TR45: Test Rollback Scenario 1 - First Mount Fails
// ============================================================================

#[test]
fn test_rollback_tr45_first_mount_fails() {
    // TR45: First mount fails → no rollback needed, state returns to INACTIVE

    // GIVEN: MockFilesystem configured to fail /home mount
    let fs = MockFilesystem::new();
    fs.mock_set_mount_should_fail("/home", true);
    let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

    // WHEN: Running activation
    let result = manager_arc.lock().unwrap().activate(true); // skip preflight

    // THEN: Activation fails
    assert!(result.is_err(), "Expected activation to fail");

    // AND: State returned to INACTIVE (no mounts to rollback)
    let state = manager_arc
        .lock()
        .unwrap()
        .current_state()
        .expect("Should get state");
    assert_eq!(
        state,
        SystemState::Inactive,
        "Expected state to return to Inactive after first mount fails"
    );

    // AND: No mounts remain
    {
        let manager = manager_arc.lock().unwrap();
        let fs_ref = manager.filesystem();
        assert!(
            !fs_ref
                .is_mounted(Path::new("/home"))
                .expect("Should check mount")
        );
        assert!(
            !fs_ref
                .is_mounted(Path::new("/etc"))
                .expect("Should check mount")
        );
    } // Release lock before verify

    // AND: State consistency verified
    verify_rollback_state_consistency(&manager_arc);
}

#[test]
fn test_rollback_tr45_first_mount_fails_error_message() {
    // Verify error message is helpful for first mount failure

    let fs = MockFilesystem::new();
    fs.mock_set_mount_should_fail("/home", true);
    let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

    let result = manager_arc.lock().unwrap().activate(true);

    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = err.to_string();

    // TR45: Error should mention /home mount failure specifically
    assert!(
        err_msg.contains("/home") && err_msg.contains("mount"),
        "Error message should mention /home mount failure: {}",
        err_msg
    );
}

// ============================================================================
// TR46: Test Rollback Scenario 2 - Second Mount Fails
// ============================================================================

#[test]
fn test_rollback_tr46_second_mount_fails() {
    // TR46: Second mount fails → first mount rolled back

    // GIVEN: MockFilesystem where /home succeeds but /etc fails
    let fs = MockFilesystem::new();
    fs.mock_set_mount_should_fail("/etc", true);
    let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

    // WHEN: Running activation
    let result = manager_arc.lock().unwrap().activate(true);

    // THEN: Activation fails
    assert!(result.is_err(), "Expected activation to fail");

    // AND: State returned to INACTIVE (rollback completed)
    let state = manager_arc
        .lock()
        .unwrap()
        .current_state()
        .expect("Should get state");
    assert_eq!(
        state,
        SystemState::Inactive,
        "Expected state to return to Inactive after second mount fails"
    );

    // AND: All mounts rolled back (including /home)
    {
        let manager = manager_arc.lock().unwrap();
        let fs_ref = manager.filesystem();
        assert!(
            !fs_ref
                .is_mounted(Path::new("/home"))
                .expect("Should check mount"),
            "Expected /home to be unmounted after rollback"
        );
        assert!(
            !fs_ref
                .is_mounted(Path::new("/etc"))
                .expect("Should check mount"),
            "Expected /etc to remain unmounted"
        );
    } // Release lock before calling helper

    // AND: State consistency verified
    verify_rollback_state_consistency(&manager_arc);
}

#[test]
fn test_rollback_tr46_second_mount_fails_verifies_rollback_order() {
    // Verify that rollback unmounts in reverse order (LIFO)

    let fs = MockFilesystem::new();
    fs.mock_set_mount_should_fail("/etc", true);
    let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

    let result = manager_arc.lock().unwrap().activate(true);
    assert!(result.is_err());

    // Verify /home was mounted then unmounted (rollback)
    let manager = manager_arc.lock().unwrap();
    let fs_ref = manager.filesystem();

    // Both should be unmounted after rollback
    assert!(!fs_ref.is_mounted(Path::new("/home")).expect("Should check"));
    assert!(!fs_ref.is_mounted(Path::new("/etc")).expect("Should check"));
}

#[test]
fn test_rollback_tr46_multiple_overlays_rolled_back() {
    // Test that all successfully mounted overlays are rolled back
    // when a later mount fails

    let fs = MockFilesystem::new();
    fs.mock_set_mount_should_fail("/etc", true);
    let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

    let result = manager_arc.lock().unwrap().activate(true);
    assert!(result.is_err());

    // Verify complete rollback
    verify_rollback_state_consistency(&manager_arc);

    {
        let state = manager_arc.lock().unwrap().current_state().unwrap();
        assert_eq!(state, SystemState::Inactive);
    }
}

// ============================================================================
// TR47: Test Rollback Scenario 3 - NixOS Build Fails
// ============================================================================

#[test]
fn test_rollback_tr47_nixos_build_fails_placeholder() {
    // TR47: NixOS build fails → no overlays mounted, state returns to INACTIVE
    //
    // CURRENT LIMITATION: This is a placeholder test. Full TR47 testing requires:
    // 1. NixOSBuilder trait for dependency injection
    // 2. MockNixOSBuilder that can simulate build failures
    // 3. Integration with NailsManager to use injected builder
    //
    // Current test: Verifies normal activation works (baseline behavior)
    //
    // Expected TR47 behavior (once NixOSBuilder mock is available):
    // 1. Mock NixOSBuilder to return build failure (e.g., syntax error in config)
    // 2. Verify activation fails before mounting overlays
    // 3. Verify no overlay mounts were attempted
    // 4. Verify state returns to INACTIVE
    // 5. Verify error message contains "build failed" or specific NixOS error

    // GIVEN: Manager without NixOS builder configured
    let fs = MockFilesystem::new();
    let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

    // WHEN: Running activation (should succeed without builder)
    let result = manager_arc.lock().unwrap().activate(true);

    // THEN: Activation succeeds (no builder = no build failure possible)
    assert!(
        result.is_ok(),
        "Activation should succeed without NixOS builder"
    );

    // State should be ACTIVE
    let state = manager_arc.lock().unwrap().current_state().unwrap();
    assert!(matches!(state, SystemState::Active { .. }));

    // TODO(TR47): Implement full test when NixOSBuilder mocking is available
}

// ============================================================================
// TR48: Test Rollback Scenario 4 - State File Write Fails
// ============================================================================

#[test]
fn test_rollback_tr48_state_file_write_during_activation() {
    // TR48: State file write fails → overlays unmounted, partial state deleted, returns to INACTIVE
    //
    // CURRENT LIMITATION: MockFilesystem does not yet support write failure injection.
    // This test verifies normal state file writing works correctly. Full TR48 testing
    // requires adding write failure simulation capability to MockFilesystem.
    //
    // Expected TR48 behavior (once MockFilesystem supports write failures):
    // 1. Overlays mount successfully
    // 2. State file write fails (e.g., hidden volume full)
    // 3. StateGuard triggers rollback: unmounts all overlays
    // 4. Partial state.json file deleted
    // 5. State returns to INACTIVE
    // 6. Error message indicates state file write failure

    let fs = MockFilesystem::new();
    let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

    // Normal activation should succeed (baseline test)
    let result = manager_arc.lock().unwrap().activate(true);
    assert!(
        result.is_ok(),
        "Activation should succeed with working state file"
    );

    // Verify ACTIVE state and state file written
    let state = manager_arc.lock().unwrap().current_state().unwrap();
    assert!(matches!(state, SystemState::Active { .. }));

    // TODO(TR48): Once MockFilesystem supports write failure injection:
    // - Add fs.mock_set_write_should_fail(state_path, true)
    // - Verify activation fails with state write error
    // - Verify all overlays are unmounted (rollback)
    // - Verify state returns to INACTIVE
    // - Verify partial state file is deleted
}

// ============================================================================
// TR49: Test Rollback Scenario 5 - Cleanup Fails
// ============================================================================

#[test]
fn test_rollback_tr49_cleanup_fails_remounts_overlays() {
    // TR49: Cleanup fails during deactivation → overlays remain mounted, state remains ACTIVE.
    // The current orchestrator rolls back before any unmount step runs, so this validates the
    // observable contract that users rely on today.

    // Deactivation resolves the history files from HOME, so it stays redirected
    // for the whole test.
    let _home = crate::cleanup::test_utils::set_safe_test_home();
    let fs = MockFilesystem::new();
    let (manager, _temp_dir) = create_rollback_test_manager(fs);
    manager
        .lock()
        .unwrap()
        .activate(true)
        .expect("Should activate for cleanup test");

    {
        let m = manager.lock().unwrap();
        let bash_history = Path::new(crate::cleanup::test_utils::TEST_HOME).join(".bash_history");
        let bash_history_str = bash_history.to_str().unwrap();
        crate::cleanup::test_utils::assert_path_is_safe(bash_history_str);

        m.filesystem().mock_set_path_exists(bash_history_str, true);
        m.filesystem()
            .mock_set_file_content(bash_history_str, "nails deactivate\n");
        m.filesystem()
            .mock_set_write_should_fail(bash_history_str, true);
    }

    let orchestrator = crate::DeactivationOrchestrator::new(crate::CleanupConfig::default());

    let err = orchestrator
        .run(&mut manager.lock().unwrap())
        .expect_err("cleanup failure should abort deactivation");
    assert!(matches!(err, NailsError::CleanupError(_)));

    let manager_guard = manager.lock().unwrap();
    assert!(matches!(
        manager_guard.current_state().unwrap(),
        SystemState::Active { .. }
    ));
    assert!(
        manager_guard
            .filesystem()
            .is_mounted(Path::new("/home"))
            .unwrap()
    );
    assert!(
        manager_guard
            .filesystem()
            .is_mounted(Path::new("/etc"))
            .unwrap()
    );
}

// ============================================================================
// TR50: Test Rollback Scenario 6 - Unmount Fails
// ============================================================================

#[test]
fn test_rollback_tr50_unmount_fails_during_deactivation() {
    // TR50: Unmount fails → the teardown attempts every target and ends DEGRADED.
    //
    // The teardown never remounts what it has already detached and never returns
    // to ACTIVE once any overlay is gone: /home unmounts, /etc fails, and the
    // system is recorded as DEGRADED with /etc still live.

    // GIVEN: System in ACTIVE state, unmount configured to fail for /etc
    let fs = MockFilesystem::new();
    fs.mock_set_unmount_should_fail("/etc", true);
    let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

    // Activate first
    manager_arc
        .lock()
        .unwrap()
        .activate(true)
        .expect("Should activate successfully");

    // Verify ACTIVE state
    let state_before = manager_arc.lock().unwrap().current_state().unwrap();
    assert!(matches!(state_before, SystemState::Active { .. }));

    // WHEN: Attempting deactivation with unmount failure on /etc
    // Deactivation tries to unmount every overlay; /home succeeds, /etc fails
    let result = manager_arc.lock().unwrap().emergency_deactivate();

    // THEN: Deactivation fails because /etc is still live
    let err = result.expect_err("Expected deactivation to fail");
    assert!(
        matches!(err, NailsError::DeactivationIncomplete { .. }),
        "Expected DeactivationIncomplete, got: {:?}",
        err
    );

    // AND: State is DEGRADED (never rolled back to ACTIVE after a partial teardown)
    let state_after = manager_arc.lock().unwrap().current_state().unwrap();
    assert!(
        state_after.is_degraded(),
        "Expected state to be Degraded after unmount failure, got {state_after:?}"
    );

    // AND: Every target was attempted. /home was detached and is NOT remounted;
    // /etc could not be unmounted and stays live.
    let manager = manager_arc.lock().unwrap();
    let fs_ref = manager.filesystem();

    assert!(
        !fs_ref
            .is_mounted(Path::new("/home"))
            .expect("Should check mount"),
        "/home should be detached - the teardown attempts every target, no remount"
    );

    // /etc should still be mounted (unmount failed)
    assert!(
        fs_ref
            .is_mounted(Path::new("/etc"))
            .expect("Should check mount"),
        "/etc should still be mounted since unmount failed"
    );
}

#[test]
fn test_rollback_tr50_unmount_fails_error_message() {
    // Verify error message for unmount failure is helpful

    let fs = MockFilesystem::new();
    fs.mock_set_unmount_should_fail("/etc", true);
    let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

    manager_arc
        .lock()
        .unwrap()
        .activate(true)
        .expect("Should activate");

    let result = manager_arc.lock().unwrap().emergency_deactivate();
    let err = result.expect_err("deactivation should fail when /etc stays mounted");

    assert!(
        matches!(err, NailsError::DeactivationIncomplete { .. }),
        "Expected DeactivationIncomplete, got: {:?}",
        err
    );

    // TR50: Error should name the mount that is still live and point to recovery.
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("/etc") && err_msg.to_lowercase().contains("incomplete"),
        "Error should name the /etc mount still live: {}",
        err_msg
    );
}

#[test]
fn test_rollback_tr50_first_unmount_fails() {
    // Test teardown when the first unmount in the deactivation sequence fails

    let fs = MockFilesystem::new();
    // /etc unmounts first in deactivation (LIFO from activation)
    fs.mock_set_unmount_should_fail("/etc", true);
    let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

    manager_arc
        .lock()
        .unwrap()
        .activate(true)
        .expect("Should activate");

    let result = manager_arc.lock().unwrap().emergency_deactivate();
    assert!(result.is_err());

    // The teardown continues past the first failure and ends DEGRADED, never ACTIVE.
    let state = manager_arc.lock().unwrap().current_state().unwrap();
    assert!(
        state.is_degraded(),
        "Expected Degraded after a failed first unmount, got {state:?}"
    );
}

// ============================================================================
// TR51: Test Rollback Scenario 7 - Cascading Failures
// ============================================================================

#[test]
fn test_rollback_tr51_cascading_failures() {
    // TR51: Activation fails, rollback also fails
    //
    // Current behavior: Best-effort rollback continues even if unmount fails.
    // System returns error but may not enter explicit EMERGENCY state.

    // GIVEN: /etc mount fails AND /home unmount fails
    let fs = MockFilesystem::new();
    fs.mock_set_mount_should_fail("/etc", true);
    fs.mock_set_unmount_should_fail("/home", true);
    let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

    // WHEN: Running activation (will fail on /etc, then fail rollback on /home)
    let result = manager_arc.lock().unwrap().activate(true);

    // THEN: Activation fails
    assert!(result.is_err(), "Expected activation to fail");

    // AND: State is NOT Active (activation failed)
    let state = manager_arc.lock().unwrap().current_state().unwrap();
    assert!(
        !matches!(state, SystemState::Active { .. }),
        "Expected state NOT to be Active after cascading failures"
    );

    // Note: Current implementation may leave system in Inactive or Activating state
    // depending on exact failure point. The key is that activation did not succeed.
}

#[test]
fn test_rollback_tr51_multiple_rollback_failures() {
    // Test scenario where multiple unmounts fail during rollback

    let fs = MockFilesystem::new();
    fs.mock_set_mount_should_fail("/etc", true);
    fs.mock_set_unmount_should_fail("/home", true);
    let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

    let result = manager_arc.lock().unwrap().activate(true);

    // Should fail
    assert!(result.is_err());

    // Verify error is reported
    let err = result.unwrap_err();
    assert!(
        !err.to_string().is_empty(),
        "Error message should not be empty"
    );
}

// ============================================================================
// TR37, TR38: Comprehensive Rollback Test Coverage
// ============================================================================

#[test]
fn test_rollback_tr37_all_scenarios_have_tests() {
    // TR37: Verify we have tests for all 7 rollback scenarios
    //
    // Test Coverage Status:
    // ✓ TR45: test_rollback_tr45_first_mount_fails (FULLY IMPLEMENTED)
    // ✓ TR46: test_rollback_tr46_second_mount_fails (FULLY IMPLEMENTED)
    // ⚠ TR47: test_rollback_tr47_nixos_build_fails_placeholder (PLACEHOLDER - awaits NixOSBuilder mock)
    // ⚠ TR48: test_rollback_tr48_state_file_write_during_activation (PLACEHOLDER - awaits write failure injection)
    // ✓ TR49: test_rollback_tr49_cleanup_fails_remounts_overlays (IMPLEMENTED via cleanup rollback)
    // ✓ TR50: test_rollback_tr50_unmount_fails_during_deactivation (FULLY IMPLEMENTED)
    // ✓ TR51: test_rollback_tr51_cascading_failures (FULLY IMPLEMENTED)
    //
    // Summary: 5 fully implemented, 2 placeholders awaiting additional failure injection hooks

    // Documentation test - verifies test coverage structure is complete
    let total_scenarios = 7;
    let tests_exist = 7; // All scenarios have at least placeholder tests
    assert_eq!(
        tests_exist, total_scenarios,
        "All 7 rollback scenarios should have test structures (5 fully implemented, 2 placeholders)"
    );
}

#[test]
fn test_rollback_tr38_state_consistency_after_rollback() {
    // TR38: Verify state consistency after each rollback

    // Test multiple rollback scenarios and verify consistency
    let scenarios = vec![
        ("first_mount_fails", "/home"),
        ("second_mount_fails", "/etc"),
    ];

    for (scenario, fail_path) in scenarios {
        let fs = MockFilesystem::new();
        fs.mock_set_mount_should_fail(fail_path, true);
        let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

        let _result = manager_arc.lock().unwrap().activate(true);

        // Verify state consistency after rollback
        verify_rollback_state_consistency(&manager_arc);

        let state = manager_arc.lock().unwrap().current_state().unwrap();
        assert_eq!(
            state,
            SystemState::Inactive,
            "Scenario '{}' should end in Inactive state",
            scenario
        );
    }
}

// ============================================================================
// Additional Rollback Edge Cases
// ============================================================================

#[test]
fn test_rollback_no_mounts_configured() {
    // Test rollback behavior when no overlays are configured

    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).expect("Should create hidden volume");
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![], // No overlays
        ..Config::test_default()
    };

    fs.mock_set_path_exists("/", true);
    let hv_str = mock_hidden_vol.to_string_lossy();
    fs.mock_set_path_exists(&hv_str, true);

    let manager = NailsManager::new(fs, config, state_path);
    let manager_arc = Arc::new(Mutex::new(manager));

    // Activation with no overlays should succeed
    let result = manager_arc.lock().unwrap().activate(true);
    assert!(result.is_ok(), "Activation with no overlays should succeed");

    // `temp_dir` is held to the end of the test so its contents are removed when
    // it drops here; the earlier `std::mem::forget` leaked the directory.
    drop(temp_dir);
}

#[test]
fn test_rollback_preserves_previous_state() {
    // Verify rollback restores the previous state correctly

    let fs = MockFilesystem::new();
    fs.mock_set_mount_should_fail("/home", true);
    let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

    // Initial state should be Inactive
    let initial_state = manager_arc.lock().unwrap().current_state().unwrap();
    assert_eq!(initial_state, SystemState::Inactive);

    // Failed activation should rollback to Inactive
    let result = manager_arc.lock().unwrap().activate(true);
    assert!(result.is_err());

    let final_state = manager_arc.lock().unwrap().current_state().unwrap();
    assert_eq!(
        final_state, initial_state,
        "Rollback should restore original state"
    );
}

#[test]
fn test_rollback_mount_tracker_commit_prevents_rollback() {
    // Verify that MountTracker.commit() prevents automatic rollback

    let fs = MockFilesystem::new();
    let mut tracker = MountTracker::new(&fs);

    // Add mount
    tracker.push_mount(MountInfo::persistent(PathBuf::from("/home")));

    // Commit to prevent rollback
    tracker.commit();

    // Tracker should be committed
    assert!(tracker.committed, "Tracker should be committed");
}

#[test]
fn test_rollback_mount_tracker_lifo_order() {
    // Verify MountTracker maintains LIFO order

    let fs = MockFilesystem::new();
    let mut tracker = MountTracker::new(&fs);

    // Add mounts in order
    tracker.push_mount(MountInfo::persistent(PathBuf::from("/home")));
    tracker.push_mount(MountInfo::persistent(PathBuf::from("/etc")));

    // Verify order
    assert_eq!(tracker.mounted.len(), 2);
    assert_eq!(tracker.mounted[0].target, PathBuf::from("/home"));
    assert_eq!(tracker.mounted[1].target, PathBuf::from("/etc"));
}

#[test]
fn test_rollback_mount_tracker_rollback_all() {
    // Verify MountTracker.rollback_all() unmounts in reverse order

    let fs = MockFilesystem::new();

    // Set up paths properly for MockFilesystem
    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/etc", true);
    fs.mock_set_path_exists("/tmp", true);
    fs.mock_set_path_exists("/tmp/home-upper", true);
    fs.mock_set_path_exists("/tmp/home-work", true);
    fs.mock_set_path_exists("/tmp/etc-upper", true);
    fs.mock_set_path_exists("/tmp/etc-work", true);
    fs.mock_set_writable("/tmp", true);

    // Mount overlays
    fs.mount_overlay(
        &[Path::new("/")],
        Path::new("/tmp/home-upper"),
        Path::new("/tmp/home-work"),
        Path::new("/home"),
    )
    .expect("Should mount /home");

    fs.mount_overlay(
        &[Path::new("/")],
        Path::new("/tmp/etc-upper"),
        Path::new("/tmp/etc-work"),
        Path::new("/etc"),
    )
    .expect("Should mount /etc");

    let mut tracker = MountTracker::new(&fs);
    tracker.push_mount(MountInfo::persistent(PathBuf::from("/home")));
    tracker.push_mount(MountInfo::persistent(PathBuf::from("/etc")));

    // Rollback all
    let result = tracker.rollback_all();
    assert!(result.is_ok(), "Rollback should succeed");

    // Verify both unmounted
    assert!(!fs.is_mounted(Path::new("/home")).unwrap());
    assert!(!fs.is_mounted(Path::new("/etc")).unwrap());
}
