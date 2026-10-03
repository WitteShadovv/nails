//! Deactivation: teardown, reboot request and the base-config check.

use super::*;

// ========== deactivate() ==========

#[test]
fn test_deactivate_failure_at_unmount_ends_degraded() {
    use crate::OverlayConfig;

    // Create mock hidden volume structure in temp dir
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Mock NixOS system profile for deactivation
    fs.mock_set_path_exists("/nix/var/nix/profiles/system", true);
    fs.mock_set_path_exists(
        "/nix/var/nix/profiles/system/bin/switch-to-configuration",
        true,
    );

    // Set up paths to exist
    fs.mock_set_path_exists("/", true);
    let upper_dir = mock_hidden_vol.join("overlays/home/upper");
    let work_dir = mock_hidden_vol.join("overlays/home/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

    // Set up overlay as mounted
    fs.mock_set_mounted(Path::new("/home"), true);

    // Configure unmount to fail
    fs.mock_set_unmount_should_fail("/home", true);

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

    // Set up Active state with mounted overlay
    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/"),
            upper_dir: upper_dir.clone(),
            work_dir: work_dir.clone(),
            mounted_at: Utc::now(),
        },
    );
    manager
        .lock()
        .unwrap()
        .force_state(SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
            decoy_writers: Vec::new(),
        })
        .unwrap();
    {
        let mgr = manager.lock().unwrap();
        let mut cached = mgr.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file.overlay_status = overlay_status;
        }
    }

    // Verify initial state is Active
    assert!(matches!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Active { .. }
    ));

    // Deactivation should fail (using emergency_deactivate for full unmount)
    let result = manager.lock().unwrap().emergency_deactivate();
    let err = result.expect_err("deactivation must fail when the overlay stays mounted");

    // The teardown attempted the unmount, it failed, and the overlay is still live.
    match err {
        NailsError::DeactivationIncomplete {
            ref remaining_mounts,
        } => {
            assert_eq!(remaining_mounts, &vec![PathBuf::from("/home")]);
        }
        other => panic!("Expected DeactivationIncomplete, got: {:?}", other),
    }

    // Never ACTIVE once a teardown has begun detaching overlays: it ends DEGRADED.
    let final_state = manager.lock().unwrap().current_state().unwrap();
    assert!(
        final_state.is_degraded(),
        "State should be Degraded after an unmount failure, got {final_state:?}"
    );

    // The overlay that could not be unmounted stays mounted; it is never remounted.
    assert!(
        fs_clone.is_mounted(Path::new("/home")).unwrap(),
        "Overlay that failed to unmount should remain mounted"
    );

    // State file persists Degraded.
    let loaded = StateFile::load(&state_path).unwrap();
    assert!(
        loaded.state.is_degraded(),
        "persisted state should be Degraded, got {:?}",
        loaded.state
    );
}

#[test]
fn test_deactivate_successful_unmounts_all_overlays() {
    use crate::OverlayConfig;

    // Create mock hidden volume structure in temp dir
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Mock NixOS system profile for deactivation
    fs.mock_set_path_exists("/nix/var/nix/profiles/system", true);
    fs.mock_set_path_exists(
        "/nix/var/nix/profiles/system/bin/switch-to-configuration",
        true,
    );

    // Set up paths to exist
    fs.mock_set_path_exists("/", true);
    let upper_dir = mock_hidden_vol.join("overlays/home/upper");
    let work_dir = mock_hidden_vol.join("overlays/home/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

    // Set up overlay as mounted
    fs.mock_set_mounted(Path::new("/home"), true);

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

    // Set up Active state with mounted overlay
    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/"),
            upper_dir: upper_dir.clone(),
            work_dir: work_dir.clone(),
            mounted_at: Utc::now(),
        },
    );
    manager
        .lock()
        .unwrap()
        .force_state(SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
            decoy_writers: Vec::new(),
        })
        .unwrap();
    {
        let mgr = manager.lock().unwrap();
        let mut cached = mgr.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file.overlay_status = overlay_status;
        }
    }

    // Deactivation should succeed (using emergency_deactivate for full unmount)
    let result = manager.lock().unwrap().emergency_deactivate();
    assert!(result.is_ok());

    // Verify overlay is unmounted
    assert!(
        !fs_clone.is_mounted(Path::new("/home")).unwrap(),
        "Overlay should be unmounted after successful deactivation"
    );

    // Verify state is Inactive
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );

    // Verify state file contains Inactive
    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded.state, SystemState::Inactive);

    // Verify overlay_status is cleared
    assert!(loaded.overlay_status.is_empty());
}

#[test]
fn test_deactivate_requests_reboot_only_after_successful_teardown() {
    use crate::OverlayConfig;

    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let hidden_root = temp_dir.path();
    std::fs::create_dir_all(hidden_root).unwrap();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/nix/var/nix/profiles/system", true);
    fs.mock_set_path_exists(
        "/nix/var/nix/profiles/system/bin/switch-to-configuration",
        true,
    );
    fs.mock_set_path_exists("/", true);

    let upper_dir = hidden_root.join("overlays/home/upper");
    let work_dir = hidden_root.join("overlays/home/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);
    fs.mock_set_mounted(Path::new("/home"), true);

    let config = Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: state_path.clone(),
        log_path: hidden_root.join("logs"),
        overlay_mode: crate::OverlayMode::Explicit,
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
        fs.clone(),
        config,
        state_path.clone(),
    )));

    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/"),
            upper_dir: upper_dir.clone(),
            work_dir: work_dir.clone(),
            mounted_at: Utc::now(),
        },
    );
    manager
        .lock()
        .unwrap()
        .force_state(SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
            decoy_writers: Vec::new(),
        })
        .unwrap();
    {
        let mgr = manager.lock().unwrap();
        let mut cached = mgr.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file.overlay_status = overlay_status;
        }
    }

    let mut env = EnvGuard::lock();
    env.set("NAILS_TEST_RUNTIME", "1");
    let result = manager.lock().unwrap().deactivate();
    drop(env);

    assert!(
        result.is_ok(),
        "deactivation should succeed without reboot in test runtime"
    );
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );
    assert!(!fs.is_mounted(Path::new("/home")).unwrap());
}

#[test]
fn test_deactivate_does_not_request_reboot_after_failed_teardown() {
    use crate::OverlayConfig;

    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let hidden_root = temp_dir.path();
    std::fs::create_dir_all(hidden_root).unwrap();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/nix/var/nix/profiles/system", true);
    fs.mock_set_path_exists(
        "/nix/var/nix/profiles/system/bin/switch-to-configuration",
        true,
    );
    fs.mock_set_path_exists("/", true);

    let upper_dir = hidden_root.join("overlays/home/upper");
    let work_dir = hidden_root.join("overlays/home/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);
    fs.mock_set_mounted(Path::new("/home"), true);
    fs.mock_set_unmount_should_fail("/home", true);

    let config = Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: state_path.clone(),
        log_path: hidden_root.join("logs"),
        overlay_mode: crate::OverlayMode::Explicit,
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
        fs.clone(),
        config,
        state_path.clone(),
    )));

    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/"),
            upper_dir: upper_dir.clone(),
            work_dir: work_dir.clone(),
            mounted_at: Utc::now(),
        },
    );
    manager
        .lock()
        .unwrap()
        .force_state(SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
            decoy_writers: Vec::new(),
        })
        .unwrap();
    {
        let mgr = manager.lock().unwrap();
        let mut cached = mgr.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file.overlay_status = overlay_status;
        }
    }

    let result = manager.lock().unwrap().deactivate();

    // A failed teardown returns Err before the reboot step, so no reboot is ever
    // requested. The system ends DEGRADED (never back to ACTIVE) with the overlay
    // that could not be unmounted still live.
    assert!(
        result.is_err(),
        "deactivation should fail when teardown fails"
    );
    assert!(
        manager
            .lock()
            .unwrap()
            .current_state()
            .unwrap()
            .is_degraded()
    );
    assert!(fs.is_mounted(Path::new("/home")).unwrap());
}

/// Build a manager in `Active` state whose teardown succeeds, so a normal
/// `deactivate()` reaches the post-teardown reboot step. Mirrors the fixture used
/// by `test_deactivate_requests_reboot_only_after_successful_teardown` above.
fn manager_ready_for_reboot_step() -> (
    Arc<Mutex<NailsManager<MockFilesystem>>>,
    MockFilesystem,
    tempfile::TempDir,
) {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let hidden_root = temp_dir.path();
    std::fs::create_dir_all(hidden_root).unwrap();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/nix/var/nix/profiles/system", true);
    fs.mock_set_path_exists(
        "/nix/var/nix/profiles/system/bin/switch-to-configuration",
        true,
    );
    fs.mock_set_path_exists("/", true);

    let upper_dir = hidden_root.join("overlays/home/upper");
    let work_dir = hidden_root.join("overlays/home/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);
    fs.mock_set_mounted(Path::new("/home"), true);

    let config = Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: state_path.clone(),
        log_path: hidden_root.join("logs"),
        overlay_mode: OverlayMode::Explicit,
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
        fs.clone(),
        config,
        state_path.clone(),
    )));

    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/"),
            upper_dir: upper_dir.clone(),
            work_dir: work_dir.clone(),
            mounted_at: Utc::now(),
        },
    );
    manager
        .lock()
        .unwrap()
        .force_state(SystemState::Active {
            decoy_writers: Vec::new(),
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
        })
        .unwrap();
    {
        let mgr = manager.lock().unwrap();
        let mut cached = mgr.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file.overlay_status = overlay_status;
        }
    }

    (manager, fs, temp_dir)
}

#[test]
#[serial]
fn deactivate_requests_reboot_through_injected_dispatcher_even_in_test_runtime() {
    // The post-teardown reboot used to be wrapped in
    // `!should_skip_host_interaction()`, so `NAILS_TEST_RUNTIME` (and this crate's
    // own test build) silently suppressed it. The dispatcher now owns that
    // decision, so an injected `Simulated` records the request even with
    // `NAILS_TEST_RUNTIME` set.
    let (manager, fs, _temp) = manager_ready_for_reboot_step();

    let recorder = SimulatedHostEffects::new(SimulatedReboot::Dispatched);
    manager
        .lock()
        .unwrap()
        .set_host_effects(HostEffects::Simulated(recorder.clone()));

    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");
    env.set("NAILS_TEST_RUNTIME", "1");
    let result = manager.lock().unwrap().deactivate();
    drop(env);

    assert!(
        result.is_ok(),
        "deactivation should succeed when the reboot dispatcher reports success: {result:?}"
    );
    assert_eq!(
        recorder.reboot_requests(),
        1,
        "the reboot must be requested through the dispatcher, not silently skipped"
    );
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );
    assert!(!fs.is_mounted(Path::new("/home")).unwrap());
}

#[test]
#[serial]
fn deactivate_surfaces_a_refusing_reboot_guard_as_an_error() {
    // A guard that refuses the destructive reboot step must surface as an error,
    // never a silent `Ok`: the dispatcher records the attempt and returns the
    // failure, which `deactivate()` propagates.
    let (manager, _fs, _temp) = manager_ready_for_reboot_step();

    let recorder = SimulatedHostEffects::new(SimulatedReboot::Refuse(
        "refusing to reboot (forced guard)".to_string(),
    ));
    manager
        .lock()
        .unwrap()
        .set_host_effects(HostEffects::Simulated(recorder.clone()));

    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");
    let err = manager
        .lock()
        .unwrap()
        .deactivate()
        .expect_err("a refusing reboot guard must surface as an error");
    drop(env);

    assert!(
        err.to_string().contains("forced guard"),
        "unexpected error: {err}"
    );
    assert_eq!(
        recorder.reboot_requests(),
        1,
        "the reboot must be attempted and the refusal surfaced, not silently skipped"
    );
}

#[test]
fn test_deactivate_from_non_active_returns_error() {
    // Create mock hidden volume structure in temp dir
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));

    // State is Inactive by default
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );

    // deactivate() should fail from Inactive state
    let result = manager.lock().unwrap().deactivate();
    assert!(result.is_err(), "Expected Err, got {:?}", result);
    assert!(matches!(result.unwrap_err(), NailsError::InvalidState(_)));
}

#[test]
fn test_deactivate_partial_failure_ends_degraded_without_remount() {
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

    // Set up both overlays as mounted
    fs.mock_set_mounted(Path::new("/home"), true);
    fs.mock_set_mounted(Path::new("/etc"), true);

    // Configure unmount to fail only for /etc
    fs.mock_set_unmount_should_fail("/etc", true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        log_path: mock_hidden_vol.join("logs"),
        clear_history: false,
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

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));

    // Set up Active state with both overlays mounted
    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/"),
            upper_dir: upper_home.clone(),
            work_dir: work_home.clone(),
            mounted_at: Utc::now(),
        },
    );
    overlay_status.insert(
        PathBuf::from("/etc"),
        OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/etc"),
            lower_dir: PathBuf::from("/"),
            upper_dir: upper_etc.clone(),
            work_dir: work_etc.clone(),
            mounted_at: Utc::now(),
        },
    );
    manager
        .lock()
        .unwrap()
        .force_state(SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
            decoy_writers: Vec::new(),
        })
        .unwrap();
    {
        let mgr = manager.lock().unwrap();
        let mut cached = mgr.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            state_file.overlay_status = overlay_status;
        }
    }

    // Deactivation attempts every target and then fails because /etc is still live.
    let err = manager.lock().unwrap().deactivate().unwrap_err();
    assert!(
        matches!(err, NailsError::DeactivationIncomplete { .. }),
        "unexpected error: {err:?}"
    );
    assert!(
        err.to_string().contains("/etc"),
        "error must name the mount still live: {err}"
    );

    // Once an overlay has been detached the teardown never returns to ACTIVE: it
    // ends DEGRADED, and the successfully unmounted target is NOT remounted.
    let manager_guard = manager.lock().unwrap();
    match manager_guard.current_state().unwrap() {
        SystemState::Degraded {
            remaining_mounts, ..
        } => {
            assert_eq!(remaining_mounts, vec![PathBuf::from("/etc")]);
        }
        other => panic!("expected Degraded, got {other:?}"),
    }
    assert!(
        !manager_guard
            .filesystem()
            .is_mounted(Path::new("/home"))
            .unwrap(),
        "/home was unmounted and must not be remounted"
    );
    assert!(
        manager_guard
            .filesystem()
            .is_mounted(Path::new("/etc"))
            .unwrap(),
        "/etc failed to unmount and stays live"
    );
}

fn setup_deactivation_system_profile(fs: &MockFilesystem) {
    fs.mock_set_path_exists("/nix/var/nix/profiles/system", true);
    fs.mock_set_path_exists(
        "/nix/var/nix/profiles/system/bin/switch-to-configuration",
        true,
    );
}

// ========== Switch to Hidden Config and Revert via Overlay Removal ==========

/// Helper: set up an Active state with a /etc overlay and /home overlay.
///
/// Returns `(manager_arc, fs_clone, state_path, temp_dir)` so the caller can
/// manipulate filesystem mock content to simulate the post-unmount view.
fn setup_active_with_etc_overlay() -> (
    Arc<Mutex<NailsManager<MockFilesystem>>>,
    MockFilesystem,
    PathBuf,
    tempfile::TempDir,
) {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path().to_path_buf();
    std::fs::create_dir_all(&mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Mock NixOS system profile for deactivation
    setup_deactivation_system_profile(&fs);

    // Overlay dirs (needed for activate path, not used by deactivate directly)
    let upper_etc = mock_hidden_vol.join("overlays/etc/upper");
    let work_etc = mock_hidden_vol.join("overlays/etc/work");
    std::fs::create_dir_all(&upper_etc).unwrap();
    std::fs::create_dir_all(&work_etc).unwrap();

    // Set up /etc overlay as mounted
    fs.mock_set_mounted(Path::new("/etc"), true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.clone(),
        state_file_path: state_path.clone(),
        overlay_mode: crate::OverlayMode::Explicit,
        overlays: vec![crate::OverlayConfig {
            name: "etc".to_string(),
            lower: PathBuf::from("/"),
            upper: upper_etc.clone(),
            work: work_etc.clone(),
            target: PathBuf::from("/etc"),
        }],
        ..Config::test_default()
    };

    let fs_clone = fs.clone();
    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));

    // Force Active state
    manager
        .lock()
        .unwrap()
        .force_state(SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/etc")],
            decoy_writers: Vec::new(),
        })
        .unwrap();

    // Register /etc overlay in cached state
    {
        let mgr = manager.lock().unwrap();
        let mut cached = mgr.cached_state.borrow_mut();
        if let Some(ref mut sf) = *cached {
            sf.overlay_status.insert(
                PathBuf::from("/etc"),
                OverlayInfo {
                    mount_method: Default::default(),
                    mount_path: PathBuf::from("/etc"),
                    lower_dir: PathBuf::from("/"),
                    upper_dir: upper_etc.clone(),
                    work_dir: work_etc.clone(),
                    mounted_at: Utc::now(),
                },
            );
        }
    }

    (manager, fs_clone, state_path, temp_dir)
}

/// Helper: set up an Active state with a /home overlay.
fn setup_active_with_home_overlay() -> (
    Arc<Mutex<NailsManager<MockFilesystem>>>,
    MockFilesystem,
    PathBuf,
    tempfile::TempDir,
) {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path().to_path_buf();
    std::fs::create_dir_all(&mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Mock NixOS system profile for deactivation
    setup_deactivation_system_profile(&fs);

    // Overlay dirs
    let upper_home = mock_hidden_vol.join("overlays/home/upper");
    let work_home = mock_hidden_vol.join("overlays/home/work");
    std::fs::create_dir_all(&upper_home).unwrap();
    std::fs::create_dir_all(&work_home).unwrap();

    // Set up /home overlay as mounted
    fs.mock_set_mounted(Path::new("/home"), true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.clone(),
        state_file_path: state_path.clone(),
        overlay_mode: crate::OverlayMode::Explicit,
        overlays: vec![crate::OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/"),
            upper: upper_home.clone(),
            work: work_home.clone(),
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

    // Force Active state
    manager
        .lock()
        .unwrap()
        .force_state(SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
            decoy_writers: Vec::new(),
        })
        .unwrap();

    // Register /home overlay in cached state
    {
        let mgr = manager.lock().unwrap();
        let mut cached = mgr.cached_state.borrow_mut();
        if let Some(ref mut sf) = *cached {
            sf.overlay_status.insert(
                PathBuf::from("/home"),
                OverlayInfo {
                    mount_method: Default::default(),
                    mount_path: PathBuf::from("/home"),
                    lower_dir: PathBuf::from("/"),
                    upper_dir: upper_home.clone(),
                    work_dir: work_home.clone(),
                    mounted_at: Utc::now(),
                },
            );
        }
    }

    (manager, fs_clone, state_path, temp_dir)
}

/// Base config reverts after the /etc overlay unmounts:
/// After deactivation, /etc overlay is unmounted, so /etc/nixos/hardware-configuration.nix
/// reverts to the base (clean) file. verify_base_config_clean() is called post-unmount and
/// confirms the base is clean. Deactivation succeeds.
#[test]
#[serial]
fn test_deactivation_succeeds_when_base_config_clean_after_unmount() {
    let (manager, fs_clone, state_path, _temp_dir) = setup_active_with_etc_overlay();

    // Simulate post-unmount view: base config is clean (no import, no hidden refs)
    fs_clone.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs_clone.mock_set_path_type("/etc/nixos/hardware-configuration.nix", PathKind::File);
    fs_clone.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ }",
    );

    let result = manager.lock().unwrap().emergency_deactivate();
    assert!(
        result.is_ok(),
        "Deactivation should succeed when base config is clean: {:?}",
        result
    );

    // State must be Inactive
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );

    // State file on disk must be Inactive
    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded.state, SystemState::Inactive);

    // /etc overlay must be unmounted
    assert!(
        !fs_clone.is_mounted(Path::new("/etc")).unwrap(),
        "/etc overlay should be unmounted after deactivation"
    );
}

/// Suspicious base-config references are now an activation-time preflight failure, not a
/// late deactivation failure. Emergency deactivation should still finish cleanly even if the
/// revealed base config is dirty, because the main safety gate already moved earlier.
#[test]
#[serial]
fn test_deactivation_succeeds_when_base_config_dirty_after_unmount() {
    let (manager, fs_clone, state_path, _temp_dir) = setup_active_with_etc_overlay();

    // Simulate a dirty base config (contains a hidden path reference — should never happen
    // in production on the base underlay, but if it does, deactivation must catch it).
    fs_clone.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs_clone.mock_set_path_type("/etc/nixos/hardware-configuration.nix", PathKind::File);
    fs_clone.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ imports = [ /mnt/hidden/nixos/configuration.nix ]; }",
    );

    let result = manager.lock().unwrap().emergency_deactivate();
    assert!(
        result.is_ok(),
        "Deactivation should not fail late on suspicious base config references"
    );

    // Overlays were unmounted and deactivation completed.
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive,
        "State should be Inactive after deactivation"
    );
    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded.state, SystemState::Inactive);
    assert!(
        !fs_clone.is_mounted(Path::new("/etc")).unwrap(),
        "/etc overlay should be unmounted after deactivation"
    );
}

/// Base config cleanliness check is only required when /etc overlay was mounted.
#[test]
#[serial]
fn test_deactivation_skips_base_check_when_etc_not_overlaid() {
    let (manager, fs_clone, _state_path, _temp_dir) = setup_active_with_home_overlay();

    // Dirty base config should not block deactivation when /etc wasn't overlaid.
    fs_clone.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs_clone.mock_set_path_type("/etc/nixos/hardware-configuration.nix", PathKind::File);
    fs_clone.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ imports = [ /mnt/hidden/nixos/configuration.nix ]; }",
    );

    let result = manager.lock().unwrap().emergency_deactivate();
    assert!(
        result.is_ok(),
        "Deactivation should succeed when /etc overlay was not mounted"
    );

    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive,
        "State should be Inactive after deactivation"
    );
}

/// Integration coverage:
/// Full activation → deactivation cycle.
/// After deactivation the base config view is clean (no hidden import).
/// Uses Explicit mode with a /home overlay (avoids Auto-mode overlay discovery complexity).
#[test]
#[serial]
fn test_full_cycle_base_config_clean_after_deactivation() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    let state_path = mock_hidden_vol.join("state.json");
    let fs = MockFilesystem::new();

    // Mock NixOS system profile for deactivation
    setup_deactivation_system_profile(&fs);

    // Base hardware config: clean (pre-condition)
    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", PathKind::File);
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ }",
    );

    // Hidden config prerequisites for stage_hidden_config_symlink
    let hidden_config = mock_hidden_vol.join("config/nixos/configuration.nix");
    std::fs::create_dir_all(hidden_config.parent().unwrap()).unwrap();
    std::fs::write(&hidden_config, "{ }").unwrap();
    fs.mock_set_path_exists(hidden_config.to_str().unwrap(), true);
    fs.mock_set_file_content(hidden_config.to_str().unwrap(), "{ }");

    let nails_dir = mock_hidden_vol.join("etc/nixos/nails");
    std::fs::create_dir_all(&nails_dir).unwrap();
    let symlink_path = nails_dir.join("configuration.nix");
    fs.mock_set_path_exists(nails_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(symlink_path.to_str().unwrap(), true);

    // Overlay dirs for /home and /etc
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
    fs.mock_set_path_exists("/", true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: crate::OverlayMode::Explicit,
        overlays: vec![
            crate::OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_home.clone(),
                work: work_home.clone(),
                target: PathBuf::from("/home"),
            },
            crate::OverlayConfig {
                name: "etc".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_etc.clone(),
                work: work_etc.clone(),
                target: PathBuf::from("/etc"),
            },
        ],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    // === Activate ===
    let activate_result = manager.lock().unwrap().activate(true);
    assert!(
        activate_result.is_ok(),
        "Activation should succeed: {:?}",
        activate_result
    );
    assert!(
        manager.lock().unwrap().current_state().unwrap().is_active(),
        "Should be Active after activation"
    );

    // Simulate post-deactivation view: base config is clean
    // (In production, unmounting /etc overlay makes the base file visible again;
    //  here we set the mock content directly since MockFs doesn't simulate overlay mechanics)
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ }",
    );

    // === Deactivate ===
    let deactivate_result = manager.lock().unwrap().emergency_deactivate();
    assert!(
        deactivate_result.is_ok(),
        "Deactivation should succeed: {:?}",
        deactivate_result
    );

    // State must be Inactive
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive,
        "State should be Inactive after deactivation"
    );

    // Base config must still be clean (verify_base_config_clean passed)
    let base_content = fs
        .read_file_content(std::path::Path::new(
            "/etc/nixos/hardware-configuration.nix",
        ))
        .unwrap();
    assert!(
        !base_content.contains("./nails/configuration.nix"),
        "Base hardware-configuration.nix must remain clean after full cycle"
    );
}

// ========== emergency_deactivate() on an untrusted (corrupt) state ==========

/// Write bytes that cannot be parsed as a state file, so the honest load outcome
/// is `Corrupt` (unknown). `current_state` would hide this behind the safe
/// `Inactive` default; `current_state_with_outcome` surfaces it.
fn write_corrupt_state(path: &Path) {
    std::fs::write(path, b"{ this is not valid state json").expect("write corrupt state");
}

/// Mount `/home` as a NAILS overlay whose upper/work live under `hidden_root`, so
/// `discover_nails_mounts(Some(hidden_root))` classifies it as a persistent NAILS
/// overlay the teardown can enumerate without a trustworthy state file.
fn mount_home_overlay_under(fs: &MockFilesystem, hidden_root: &Path) {
    let upper = hidden_root.join("overlays/home/upper");
    let work = hidden_root.join("overlays/home/work");
    std::fs::create_dir_all(&upper).unwrap();
    std::fs::create_dir_all(&work).unwrap();
    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists(upper.to_str().unwrap(), true);
    fs.mock_set_path_exists(work.to_str().unwrap(), true);
    fs.mount_overlay(&[Path::new("/")], &upper, &work, Path::new("/home"))
        .expect("mount /home overlay");
}

fn untrusted_state_config(hidden_root: &Path, state_path: &Path) -> Config {
    Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: state_path.to_path_buf(),
        log_path: hidden_root.join("logs"),
        overlay_mode: crate::OverlayMode::Explicit,
        overlays: vec![],
        ..Config::test_default()
    }
}

#[test]
fn test_emergency_on_untrusted_state_tears_down_discovered_overlays() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();
    mount_home_overlay_under(&fs, hidden_root);
    let fs_clone = fs.clone();

    let config = untrusted_state_config(hidden_root, &state_path);
    let mut manager = NailsManager::new(fs, config, state_path.clone());

    // On-disk state is corrupt: the honest load reports it as unknown.
    write_corrupt_state(&state_path);
    let (_, outcome) = manager.current_state_with_outcome().unwrap();
    assert!(outcome.is_unknown(), "corrupt state must load as unknown");

    // Emergency must tear down the live overlay rather than refuse on "Inactive".
    manager
        .emergency_deactivate()
        .expect("emergency must run on a corrupt state");

    assert!(
        !fs_clone.is_mounted(Path::new("/home")).unwrap(),
        "/home must be unmounted by the mount-table fallback"
    );
    assert_eq!(manager.current_state().unwrap(), SystemState::Inactive);

    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded.state, SystemState::Inactive);
    assert!(loaded.overlay_status.is_empty());
}

#[test]
fn test_emergency_on_untrusted_state_ends_degraded_when_unmount_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();
    mount_home_overlay_under(&fs, hidden_root);
    fs.mock_set_unmount_should_fail("/home", true);
    let fs_clone = fs.clone();

    let config = untrusted_state_config(hidden_root, &state_path);
    let mut manager = NailsManager::new(fs, config, state_path.clone());
    write_corrupt_state(&state_path);

    let err = manager
        .emergency_deactivate()
        .expect_err("teardown must fail when the discovered overlay stays mounted");
    match err {
        NailsError::DeactivationIncomplete {
            ref remaining_mounts,
        } => assert_eq!(remaining_mounts, &vec![PathBuf::from("/home")]),
        other => panic!("expected DeactivationIncomplete, got {other:?}"),
    }

    match manager.current_state().unwrap() {
        SystemState::Degraded {
            remaining_mounts, ..
        } => assert_eq!(remaining_mounts, vec![PathBuf::from("/home")]),
        other => panic!("expected Degraded, got {other:?}"),
    }
    assert!(
        fs_clone.is_mounted(Path::new("/home")).unwrap(),
        "the overlay that failed to unmount stays live and is never remounted"
    );

    let loaded = StateFile::load(&state_path).unwrap();
    assert!(
        loaded.state.is_degraded(),
        "persisted state must be Degraded"
    );
}

#[test]
fn test_normal_deactivate_on_untrusted_state_still_refuses() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();
    mount_home_overlay_under(&fs, hidden_root);
    let fs_clone = fs.clone();

    let config = untrusted_state_config(hidden_root, &state_path);
    let mut manager = NailsManager::new(fs, config, state_path.clone());
    write_corrupt_state(&state_path);

    // Normal deactivation never uses the mount-table fallback: it refuses an
    // untrusted (not Active) state and leaves every overlay in place.
    let err = manager
        .deactivate()
        .expect_err("normal deactivate must refuse an untrusted state");
    assert!(matches!(err, NailsError::InvalidState(_)), "got {err:?}");
    assert!(
        fs_clone.is_mounted(Path::new("/home")).unwrap(),
        "normal deactivate must not touch the mount table on an untrusted state"
    );
}
