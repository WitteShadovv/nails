// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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

    let result = manager.lock().unwrap().deactivate();

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
fn test_normal_deactivation_writes_last_deactivation_report() {
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

    // Track the hidden root as an existing, writable directory so the pre-reboot
    // report write (through the symlink-safe hidden-file API) can create the
    // reports dir and land the file.
    fs.mock_set_path_exists(hidden_root.to_str().unwrap(), true);
    fs.mock_set_writable(hidden_root.to_str().unwrap(), true);

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

    let result = manager.lock().unwrap().deactivate();

    assert!(result.is_ok(), "normal deactivation should succeed");

    // The self-check landed on the hidden volume, under reports/, before the
    // (test-suppressed) reboot.
    let report_path = hidden_root.join("reports/last-deactivation.json");
    let written = fs
        .get_written_content(&report_path)
        .expect("normal deactivation must write the last-deactivation self-check");
    let parsed: crate::LastDeactivationReport = serde_json::from_str(&written).unwrap();
    assert!(parsed.outcome.successful);
    assert!(!parsed.outcome.was_already_inactive);
    assert_eq!(parsed.schema_version, 1);
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

    let result = manager.lock().unwrap().deactivate();

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
fn deactivate_requests_poweroff_when_the_operator_chose_it() {
    // `deactivate --poweroff` routes the post-teardown step through the same
    // dispatcher, asking for a power-off instead of the default reboot.
    let (manager, _fs, _temp) = manager_ready_for_reboot_step();

    let recorder = SimulatedHostEffects::new(SimulatedReboot::Dispatched);
    {
        let mut mgr = manager.lock().unwrap();
        mgr.set_host_effects(HostEffects::Simulated(recorder.clone()));
        mgr.set_post_deactivation_power(crate::PostTeardownPower::Poweroff);
    }

    manager
        .lock()
        .unwrap()
        .deactivate()
        .expect("deactivation should succeed when the power-off is dispatched");

    assert_eq!(recorder.reboot_requests(), 1);
    assert_eq!(
        recorder.poweroff_requests(),
        1,
        "the post-teardown step must ask for a power-off, not a reboot"
    );
}

#[test]
fn deactivate_reboots_by_default() {
    let (manager, _fs, _temp) = manager_ready_for_reboot_step();

    let recorder = SimulatedHostEffects::new(SimulatedReboot::Dispatched);
    manager
        .lock()
        .unwrap()
        .set_host_effects(HostEffects::Simulated(recorder.clone()));

    manager.lock().unwrap().deactivate().unwrap();

    assert_eq!(recorder.reboot_requests(), 1);
    assert_eq!(recorder.poweroff_requests(), 0);
}

#[test]
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

    let err = manager
        .lock()
        .unwrap()
        .deactivate()
        .expect_err("a refusing reboot guard must surface as an error");

    assert!(
        matches!(err, NailsError::NixOSError(_)),
        "unexpected error: {err:?}"
    );
    // The guard's own refusal reason must propagate through unchanged.
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

/// Deactivation never consults the config layer: the base-config safety gate
/// runs at activation, so even a layer whose gate would refuse cannot fail a
/// teardown late, and nothing is staged or imported on the way out.
#[test]
fn test_deactivation_succeeds_when_base_config_clean_after_unmount() {
    let (manager, fs_clone, state_path, _temp_dir) = setup_active_with_etc_overlay();
    let layer = use_scripted_nixos_layer(
        &mut manager.lock().unwrap(),
        FakeConfigLayer::new().with_base_reference(FakeVerdict::Fail("dirty base".into())),
    );

    let result = manager.lock().unwrap().emergency_deactivate();
    assert!(result.is_ok(), "Deactivation should succeed: {result:?}");
    assert!(
        layer.calls().is_empty(),
        "deactivation must not call into the config layer: {:?}",
        layer.calls()
    );

    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );
    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded.state, SystemState::Inactive);
    assert!(
        !fs_clone.is_mounted(Path::new("/etc")).unwrap(),
        "/etc overlay should be unmounted after deactivation"
    );
}

/// The same holds when `/etc` was never overlaid.
#[test]
fn test_deactivation_skips_base_check_when_etc_not_overlaid() {
    let (manager, _fs_clone, _state_path, _temp_dir) = setup_active_with_home_overlay();
    let layer = use_scripted_nixos_layer(
        &mut manager.lock().unwrap(),
        FakeConfigLayer::new().with_base_reference(FakeVerdict::Fail("dirty base".into())),
    );

    let result = manager.lock().unwrap().emergency_deactivate();
    assert!(
        result.is_ok(),
        "Deactivation should succeed when /etc overlay was not mounted"
    );
    assert!(layer.calls().is_empty(), "{:?}", layer.calls());
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive,
        "State should be Inactive after deactivation"
    );
}

/// Integration coverage:
/// Full activation → deactivation cycle.
/// The hidden import lands only in the overlaid /etc, which deactivation removes.
/// Uses Explicit mode with a /home overlay (avoids Auto-mode overlay discovery complexity).
#[test]
fn test_full_cycle_base_config_clean_after_deactivation() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    let state_path = mock_hidden_vol.join("state.json");
    let fs = MockFilesystem::new();

    // Mock NixOS system profile for deactivation
    setup_deactivation_system_profile(&fs);

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

    let (manager, layer) = fake_nixos_manager(fs.clone(), config, state_path.clone());
    let manager = Arc::new(Mutex::new(manager));

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

    // Activation imported into the overlaid /etc (the only place the hidden
    // import may land), after staging the hidden config.
    let calls_after_activation = layer.calls();
    assert!(
        calls_after_activation.contains(&LayerCall::InjectImport { etc_mounted: true }),
        "{calls_after_activation:?}"
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

    // Deactivation made no further layer call, and the /etc overlay holding
    // the import is gone, so the base view is clean again.
    assert_eq!(layer.calls(), calls_after_activation);
    assert!(!fs.is_mounted(Path::new("/etc")).unwrap());
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

// ========== journal handling at teardown (T-113) ==========

/// A /var-overlaid emergency teardown relinquishes the persistent journal before
/// the unmount, restarts journald onto the decoy /var, then rotates and scrubs the
/// volatile runtime journal under /run/log/journal — in that order.
#[test]
fn emergency_teardown_handles_journal_in_order_and_scrubs_runtime_store() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();
    setup_deactivation_system_profile(&fs);
    fs.mock_set_path_exists("/", true);

    let upper_dir = mock_hidden_vol.join("overlays/var/upper");
    let work_dir = mock_hidden_vol.join("overlays/var/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);
    fs.mock_set_mounted(Path::new("/var"), true);

    // Plant a volatile runtime journal so the scrub has something to remove.
    fs.mock_set_path_type("/run/log/journal", PathKind::Dir);
    let machine_journal = PathBuf::from("/run/log/journal/abcd1234");
    fs.mock_set_path_type(machine_journal.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_directory_contents(Path::new("/run/log/journal"), vec![machine_journal.clone()]);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: crate::OverlayMode::Explicit,
        overlays: vec![OverlayConfig {
            name: "var".to_string(),
            lower: PathBuf::from("/"),
            upper: upper_dir.clone(),
            work: work_dir.clone(),
            target: PathBuf::from("/var"),
        }],
        ..Config::test_default()
    };

    let fs_clone = fs.clone();
    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));

    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/var"),
        OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/var"),
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
            overlays: vec![PathBuf::from("/var")],
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

    let _ = crate::manager::helpers::drain_recorded_service_actions();

    let report = manager.lock().unwrap().emergency_deactivate();
    assert!(
        report.is_ok(),
        "emergency teardown should succeed: {report:?}"
    );
    let report = report.unwrap();

    let actions = crate::manager::helpers::drain_recorded_service_actions();
    let idx = |needle: &str| {
        actions
            .iter()
            .position(|a| a == needle)
            .unwrap_or_else(|| panic!("missing {needle} in {actions:?}"))
    };

    let relinquish = idx("journalctl:relinquish-var");
    let restart_start = idx("start:systemd-journald");
    let rotate = idx("journalctl:rotate");

    assert!(
        relinquish < restart_start,
        "relinquish-var must precede the journald restart: {actions:?}"
    );
    assert!(
        restart_start < rotate,
        "rotate must follow the journald restart: {actions:?}"
    );

    assert!(
        report.runtime_journal_scrubbed,
        "the report must record the runtime journal scrub"
    );
    assert!(
        report
            .cleanup_report
            .cleaned_items
            .iter()
            .any(|item| item.contains("abcd1234")),
        "the machine runtime journal should be scrubbed: {:?}",
        report.cleanup_report.cleaned_items
    );
    assert!(
        !fs_clone.path_exists(&machine_journal).unwrap(),
        "the runtime journal directory must be gone after the scrub"
    );
    assert!(
        report.reboot_recommended,
        "emergency teardown does not reboot, so a reboot must be recommended"
    );
}

/// A normal (rebooting) deactivation does not set the reboot recommendation: the
/// reboot is part of the flow, so there is no residual-residue warning to raise.
#[test]
fn normal_deactivation_does_not_recommend_a_reboot() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();
    setup_deactivation_system_profile(&fs);
    fs.mock_set_path_exists("/", true);
    let upper_dir = mock_hidden_vol.join("overlays/home/upper");
    let work_dir = mock_hidden_vol.join("overlays/home/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);
    fs.mock_set_mounted(Path::new("/home"), true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        log_path: mock_hidden_vol.join("logs"),
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
        fs,
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

    // In the test runtime `deactivate()` reaches success without a real reboot.
    let report = manager.lock().unwrap().deactivate();

    assert!(report.is_ok(), "deactivation should succeed: {report:?}");
    assert!(
        !report.unwrap().reboot_recommended,
        "a rebooting deactivation must not raise the residual-residue warning"
    );
}
