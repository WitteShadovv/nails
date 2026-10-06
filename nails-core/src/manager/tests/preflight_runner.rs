// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pre-flight checks run by activation and the read-only NixOS preflight.

use super::*;

// ========== Pre-flight Integration ==========

#[test]
fn test_preflight_all_checks_pass_activation_proceeds() {
    use crate::OverlayConfig;

    // Create mock hidden volume structure
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Set up all paths for pre-flight checks to pass
    fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
    fs.mock_set_mounted(mock_hidden_vol, true);

    // Create expected directory structure
    let overlays_dir = mock_hidden_vol.join("overlays");
    let etc_dir = mock_hidden_vol.join("etc");
    let home_dir = mock_hidden_vol.join("home");
    let config_dir = mock_hidden_vol.join("config");
    let nixos_dir = mock_hidden_vol.join("nixos");
    let work_dir = mock_hidden_vol.join(".work");
    let work_etc = work_dir.join("etc");
    let work_home = work_dir.join("home");

    std::fs::create_dir_all(&overlays_dir).unwrap();
    std::fs::create_dir_all(&etc_dir).unwrap();
    std::fs::create_dir_all(&home_dir).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::create_dir_all(&nixos_dir).unwrap();
    std::fs::create_dir_all(&work_etc).unwrap();
    std::fs::create_dir_all(&work_home).unwrap();

    // Mock that MockFilesystem sees these directories
    fs.mock_set_path_exists(etc_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(etc_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_path_exists(home_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(home_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_path_exists(config_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(config_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_path_exists(nixos_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(nixos_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);
    fs.mock_set_path_type(work_etc.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);
    fs.mock_set_path_type(work_home.to_str().unwrap(), PathKind::Dir);

    // Set up overlay directories
    let upper_dir = overlays_dir.join("home").join("upper");
    let work_dir_path = work_home.clone();
    std::fs::create_dir_all(&upper_dir).unwrap();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_type("/", PathKind::Dir);
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(upper_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_path_exists(work_dir_path.to_str().unwrap(), true);
    fs.mock_set_path_type(work_dir_path.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_readable(upper_dir.to_str().unwrap(), true);
    fs.mock_set_writable(upper_dir.to_str().unwrap(), true);
    fs.mock_set_writable(work_dir_path.to_str().unwrap(), true);

    // Disable swap
    fs.mock_set_swap_enabled(false);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
        overlays: vec![OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/"),
            upper: upper_dir.clone(),
            work: work_dir_path.clone(),
            target: PathBuf::from("/home"),
        }],
        ..Config::test_default()
    };

    let (manager, layer) = fake_nixos_manager(fs.clone(), config, state_path.clone());
    let manager = Arc::new(Mutex::new(manager));

    // Activate with pre-flight checks (no_preflight = false)
    let result = manager.lock().unwrap().activate(false);
    if let Err(ref e) = result {
        eprintln!("Activation error: {:?}", e);
    }
    assert!(
        result.is_ok(),
        "Activation should succeed when all checks pass: {:?}",
        result.err()
    );

    // Verify state is Active
    assert!(matches!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Active { .. }
    ));

    // The hidden config was staged through the layer during activation.
    assert!(
        layer.calls().contains(&LayerCall::Stage {
            overlay_only: false
        }),
        "the hidden config should be staged during activation: {:?}",
        layer.calls()
    );
}

#[test]
fn test_preflight_check_fails_activation_aborted() {
    // Create mock hidden volume structure
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // DON'T mount hidden volume - this will cause HiddenVolumeCheck to fail
    fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
    fs.mock_set_mounted(mock_hidden_vol, false); // NOT MOUNTED

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(
        fake_nixos_manager(fs.clone(), config, state_path.clone()).0,
    ));

    // Verify initial state is Inactive
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );

    // Activate with pre-flight checks (should fail)
    let result = manager.lock().unwrap().activate(false);
    assert!(result.is_err(), "Activation should fail when checks fail");

    // Verify error is PreFlightCheckFailed
    match result.unwrap_err() {
        NailsError::PreFlightCheckFailed(failures) => {
            assert!(!failures.is_empty());
            // Should contain hidden-volume check failure
            assert!(failures.iter().any(|(name, _, _)| name == "hidden-volume"));
        }
        _ => panic!("Expected PreFlightCheckFailed error"),
    }

    // Verify state remains Inactive (no state changes occurred)
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive,
        "State should remain Inactive after failed preflight"
    );

    // Verify no mounts occurred
    assert!(
        fs.get_mounted_paths().is_empty(),
        "No mounts should exist after failed preflight"
    );
    assert!(
        !state_path.exists(),
        "failed preflight should not create state.json"
    );
}

#[test]
fn test_preflight_success_creates_missing_state_json_not_state_directory() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists(hidden_root.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_root.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_mounted(hidden_root, true);
    fs.mock_set_writable(hidden_root.to_str().unwrap(), true);
    fs.mock_set_supports_symlinks(hidden_root, true);
    fs.mock_set_swap_enabled(false);

    for rel in [
        "etc",
        "home",
        "config",
        "nix",
        ".work/etc",
        ".work/home",
        ".work/nix",
    ] {
        let path = hidden_root.join(rel);
        fs.mock_set_path_exists(path.to_str().unwrap(), true);
        fs.mock_set_path_type(path.to_str().unwrap(), PathKind::Dir);
        fs.mock_set_writable(path.to_str().unwrap(), true);
        fs.mock_set_readable(path.to_str().unwrap(), true);
    }

    let config = Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Explicit,
        overlays: vec![],
        ..Config::test_default()
    };

    let (manager, _layer) = fake_nixos_manager(fs, config, state_path.clone());

    manager
        .run_preflight_checks(false, false)
        .expect("preflight should create initial state.json");

    assert!(state_path.is_file(), "preflight should create state.json");
    assert!(
        !hidden_root.join("state").exists(),
        "preflight must not create state/"
    );

    let state = StateFile::load(&state_path).unwrap();
    assert_eq!(state.state, SystemState::Inactive);
}

#[test]
fn test_preflight_rejects_state_path_directory() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    std::fs::create_dir(&state_path).unwrap();
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists(hidden_root.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_root.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_mounted(hidden_root, true);
    fs.mock_set_writable(hidden_root.to_str().unwrap(), true);
    fs.mock_set_supports_symlinks(hidden_root, true);
    fs.mock_set_swap_enabled(false);

    for rel in [
        "etc",
        "home",
        "config",
        "nix",
        ".work/etc",
        ".work/home",
        ".work/nix",
    ] {
        let path = hidden_root.join(rel);
        fs.mock_set_path_exists(path.to_str().unwrap(), true);
        fs.mock_set_path_type(path.to_str().unwrap(), PathKind::Dir);
        fs.mock_set_writable(path.to_str().unwrap(), true);
        fs.mock_set_readable(path.to_str().unwrap(), true);
    }

    let config = Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Explicit,
        overlays: vec![],
        ..Config::test_default()
    };

    let (manager, _layer) = fake_nixos_manager(fs, config, state_path.clone());
    let err = manager.run_preflight_checks(false, false).unwrap_err();

    assert!(
        matches!(err, NailsError::InvalidState(_)),
        "a non-file state path must be rejected before any checks run: {err:?}"
    );
}

#[test]
fn test_preflight_multiple_checks_fail_all_reported() {
    // Create mock hidden volume structure
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Set up multiple failing conditions:
    // 1. Hidden volume not mounted
    fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
    fs.mock_set_mounted(mock_hidden_vol, false); // FAIL

    // 2. Swap enabled
    fs.mock_set_swap_enabled(true); // FAIL

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(fake_nixos_manager(fs, config, state_path).0));

    // Activate with pre-flight checks
    let result = manager.lock().unwrap().activate(false);
    assert!(result.is_err());

    // Verify error contains BOTH failures
    match result.unwrap_err() {
        NailsError::PreFlightCheckFailed(failures) => {
            assert!(
                failures.len() >= 2,
                "Should report at least 2 failures (hidden-volume and swap)"
            );

            let failure_names: Vec<&str> =
                failures.iter().map(|(name, _, _)| name.as_str()).collect();
            assert!(
                failure_names.contains(&"hidden-volume"),
                "Should report hidden-volume failure"
            );
            assert!(
                failure_names.contains(&"swap"),
                "Should report swap failure"
            );
        }
        _ => panic!("Expected PreFlightCheckFailed error"),
    }
}

#[test]
fn test_preflight_warnings_only_activation_proceeds() {
    // Create mock hidden volume structure
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Set up minimal passing conditions (may trigger warnings but not failures)
    fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
    fs.mock_set_mounted(mock_hidden_vol, true);

    // Create minimal directory structure (all required dirs for StorageReadinessCheck)
    let overlays_dir = mock_hidden_vol.join("overlays");
    let etc_dir = mock_hidden_vol.join("etc");
    let home_dir = mock_hidden_vol.join("home");
    let config_dir = mock_hidden_vol.join("config");
    let nixos_dir = mock_hidden_vol.join("nixos");
    let work_dir = mock_hidden_vol.join(".work");
    let work_etc = work_dir.join("etc");
    let work_home = work_dir.join("home");

    std::fs::create_dir_all(&overlays_dir).unwrap();
    std::fs::create_dir_all(&etc_dir).unwrap();
    std::fs::create_dir_all(&home_dir).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::create_dir_all(&nixos_dir).unwrap();
    std::fs::create_dir_all(&work_etc).unwrap();
    std::fs::create_dir_all(&work_home).unwrap();

    // Mock that MockFilesystem sees these directories
    fs.mock_set_path_exists(etc_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(etc_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_path_exists(home_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(home_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_path_exists(config_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(config_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_path_exists(nixos_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(nixos_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);
    fs.mock_set_path_type(work_etc.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);
    fs.mock_set_path_type(work_home.to_str().unwrap(), PathKind::Dir);

    // Disable swap
    fs.mock_set_swap_enabled(false);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![], // No overlays to check
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(fake_nixos_manager(fs, config, state_path).0));

    // Activate with pre-flight checks
    let result = manager.lock().unwrap().activate(false);
    if let Err(ref e) = result {
        eprintln!("Activation error: {:?}", e);
    }

    // Should succeed even if there are warnings (warnings don't block)
    assert!(
        result.is_ok(),
        "Activation should proceed when only warnings exist: {:?}",
        result.err()
    );

    // Verify state is Active
    assert!(matches!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Active { .. }
    ));
}

#[test]
fn test_preflight_skip_with_no_preflight_flag() {
    // Create mock hidden volume structure
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Set up FAILING conditions (hidden volume not mounted)
    fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
    fs.mock_set_mounted(mock_hidden_vol, false); // This WOULD fail preflight

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![], // No overlays to mount
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(fake_nixos_manager(fs, config, state_path).0));

    // Activate with no_preflight = true (skip checks)
    let result = manager.lock().unwrap().activate(true);

    // Should succeed even though checks would have failed
    assert!(
        result.is_ok(),
        "Activation should succeed when preflight is skipped"
    );

    // Verify state is Active
    assert!(matches!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Active { .. }
    ));
}

#[test]
fn test_preflight_no_filesystem_changes_on_failure() {
    use crate::OverlayConfig;

    // Create mock hidden volume structure
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Set up failing condition
    fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
    fs.mock_set_mounted(mock_hidden_vol, false); // Preflight will fail

    // Set up overlay paths
    let upper_dir = mock_hidden_vol.join("overlays/home/upper");
    let work_dir_path = mock_hidden_vol.join(".work/home");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir_path).unwrap();

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
        overlays: vec![OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/"),
            upper: upper_dir.clone(),
            work: work_dir_path.clone(),
            target: PathBuf::from("/home"),
        }],
        ..Config::test_default()
    };

    let fs_clone = fs.clone();
    let manager = Arc::new(Mutex::new(
        fake_nixos_manager(fs, config, state_path.clone()).0,
    ));

    // Attempt activation (will fail at preflight)
    let result = manager.lock().unwrap().activate(false);
    assert!(result.is_err());

    // Verify NO filesystem changes occurred:
    // 1. State is still Inactive
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );

    // 2. No mounts exist
    assert!(fs_clone.get_mounted_paths().is_empty());

    // 3. State file was not modified (or still shows Inactive)
    let loaded_state = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded_state.state, SystemState::Inactive);
}

#[test]
fn test_suspicious_reference_preflight_fails_before_activation_state_or_mounts() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let hidden_root = temp_dir.path();
    std::fs::create_dir_all(hidden_root).unwrap();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(hidden_root.to_str().unwrap(), true);
    fs.mock_set_mounted(hidden_root, true);

    let config = Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    // The layer's base-config gate reports a dirty base configuration.
    let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
    let layer = use_scripted_nixos_layer(
        &mut manager,
        FakeConfigLayer::new().with_base_reference(FakeVerdict::Fail("dirty base".into())),
    );
    let manager = Arc::new(Mutex::new(manager));

    let result = manager.lock().unwrap().activate(false);
    assert!(result.is_err(), "activation should fail in preflight");

    match result.unwrap_err() {
        NailsError::PreFlightCheckFailed(failures) => {
            assert!(
                failures
                    .iter()
                    .any(|(name, _, _)| name == crate::platform::FAKE_BASE_REFERENCE_CHECK),
                "the base-config gate failure should be reported"
            );
        }
        other => panic!("Expected PreFlightCheckFailed error, got {:?}", other),
    }

    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );
    assert_eq!(
        fs.get_mounted_paths(),
        vec![hidden_root.to_path_buf()],
        "preflight failure must not mount any activation overlays"
    );
    assert!(
        layer.calls().is_empty(),
        "the gate must refuse before any config staging: {:?}",
        layer.calls()
    );
}

#[test]
fn test_preflight_flake_builder_fails_when_default_flake_is_missing() {
    use crate::NixOSBuilder;

    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
    fs.mock_set_mounted(mock_hidden_vol, true);

    let overlays_dir = mock_hidden_vol.join("overlays");
    let etc_dir = mock_hidden_vol.join("etc");
    let home_dir = mock_hidden_vol.join("home");
    let config_dir = mock_hidden_vol.join("config");
    let nixos_dir = mock_hidden_vol.join("nixos");
    let work_dir = mock_hidden_vol.join(".work");
    let work_etc = work_dir.join("etc");
    let work_home = work_dir.join("home");

    std::fs::create_dir_all(&overlays_dir).unwrap();
    std::fs::create_dir_all(&etc_dir).unwrap();
    std::fs::create_dir_all(&home_dir).unwrap();
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::create_dir_all(&nixos_dir).unwrap();
    std::fs::create_dir_all(&work_etc).unwrap();
    std::fs::create_dir_all(&work_home).unwrap();

    fs.mock_set_path_exists(etc_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(etc_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_path_exists(home_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(home_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_path_exists(config_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(config_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_path_exists(nixos_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(nixos_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);
    fs.mock_set_path_type(work_etc.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);
    fs.mock_set_path_type(work_home.to_str().unwrap(), PathKind::Dir);

    fs.mock_set_swap_enabled(false);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let builder = NixOSBuilder::new(nixos_dir.clone(), mock_hidden_vol.join("nails-system"));
    let manager = Arc::new(Mutex::new(
        fake_nixos_manager_with_builder(fs, config, state_path, builder).0,
    ));

    let result = manager.lock().unwrap().activate(false);
    assert!(
        result.is_err(),
        "Activation should fail when flake.nix is missing"
    );

    match result.unwrap_err() {
        NailsError::PreFlightCheckFailed(failures) => {
            let (_, message, _) = failures
                .iter()
                .find(|(name, _, _)| name == "nixos-build-target")
                .expect("nixos-build-target failure should be reported");
            // Behaviour: the check must name the directory it looked in.
            assert!(message.contains(nixos_dir.to_str().unwrap()));
        }
        other => panic!("Expected PreFlightCheckFailed error, got {:?}", other),
    }
}

#[test]
fn test_preflight_fails_when_explicit_flake_is_missing() {
    use crate::NixOSBuilder;

    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    let explicit_flake_dir = temp_dir.path().join("explicit-flake");
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    std::fs::create_dir_all(&explicit_flake_dir).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
    fs.mock_set_mounted(mock_hidden_vol, true);
    fs.mock_set_path_exists(explicit_flake_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(
        &explicit_flake_dir.join("flake.nix").to_string_lossy(),
        false,
    );
    fs.mock_set_swap_enabled(false);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        nixos_flake: Some(format!("{}#host", explicit_flake_dir.display())),
        ..Config::test_default()
    };

    let builder = NixOSBuilder::new_with_flake_ref(
        format!("{}#host", explicit_flake_dir.display()),
        mock_hidden_vol.join("nails-system"),
    );
    let manager = Arc::new(Mutex::new(
        fake_nixos_manager_with_builder(fs, config, state_path, builder).0,
    ));

    let result = manager.lock().unwrap().activate(false);
    assert!(
        result.is_err(),
        "Activation should fail when explicit flake.nix is missing"
    );

    match result.unwrap_err() {
        NailsError::PreFlightCheckFailed(failures) => {
            let (_, message, _) = failures
                .iter()
                .find(|(name, _, _)| name == "nixos-build-target")
                .expect("nixos-build-target failure should be reported");
            // Behaviour: the check must name the explicit flake directory.
            assert!(message.contains(explicit_flake_dir.to_str().unwrap()));
        }
        other => panic!("Expected PreFlightCheckFailed error, got {:?}", other),
    }
}

// ========== Read-only NixOS preflight ==========

#[test]
#[serial]
fn test_run_read_only_nixos_preflight_reports_lock_file_problem_before_activation() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let explicit_flake_dir = hidden_root.join("explicit-flake");

    let fs = MockFilesystem::new();
    std::fs::create_dir_all(&explicit_flake_dir).unwrap();
    std::fs::write(
        explicit_flake_dir.join("flake.nix"),
        "{ outputs = _: {}; }\n",
    )
    .unwrap();

    let bin_dir = hidden_root.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let nix_script = bin_dir.join("nix");
    std::fs::write(
        &nix_script,
        format!(
            "#!/usr/bin/env sh\nif [ \"$1 $2\" = \"flake metadata\" ]; then\n  printf \"flake 'path:{}' requires lock file changes\\n\" 1>&2\n  exit 1\nfi\nprintf 'unexpected command: %s %s %s\\n' \"$1\" \"$2\" \"$3\" 1>&2\nexit 9\n",
            explicit_flake_dir.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&nix_script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&nix_script, perms).unwrap();
    }

    let builder = crate::nixos::NixOSBuilder::new_with_flake_ref(
        format!("{}#host-alpha", explicit_flake_dir.display()),
        hidden_root.join("nails-system"),
    )
    .with_executor(Box::new(
        crate::nixos::RealCommandExecutor::with_search_path(&bin_dir),
    ));

    let manager = NailsManager::with_nixos(
        fs,
        Config {
            hidden_volume_root: hidden_root.to_path_buf(),
            state_file_path: state_path.clone(),
            nixos_flake: Some(format!("{}#host-alpha", explicit_flake_dir.display())),
            ..Config::test_default()
        },
        state_path,
        builder,
    );

    let err = manager.run_read_only_nixos_preflight(false).unwrap_err();
    // Behaviour: the read-only preflight blocks on the nixos-build-target check
    // because the flake lock needs a manual update. Assert the failing check by
    // name rather than pinning its human-readable message.
    match err {
        NailsError::PreFlightCheckFailed(failures) => assert!(
            failures
                .iter()
                .any(|(name, _, _)| name == "nixos-build-target"),
            "nixos-build-target failure should be reported: {failures:?}"
        ),
        other => panic!("expected PreFlightCheckFailed, got {other:?}"),
    }
}

/// Build a manager whose hidden flake fails `nix flake metadata`, so the
/// post-overlay flake validation would error if it ran.
fn manager_with_unbuildable_flake(
    hidden_root: &std::path::Path,
    state_path: &std::path::Path,
) -> NailsManager<MockFilesystem> {
    let explicit_flake_dir = hidden_root.join("explicit-flake");
    std::fs::create_dir_all(&explicit_flake_dir).unwrap();
    std::fs::write(
        explicit_flake_dir.join("flake.nix"),
        "this is not valid nix\n",
    )
    .unwrap();

    let bin_dir = hidden_root.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let nix_script = bin_dir.join("nix");
    std::fs::write(
        &nix_script,
        "#!/usr/bin/env sh\nprintf 'error: flake cannot be evaluated\\n' 1>&2\nexit 1\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&nix_script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&nix_script, perms).unwrap();
    }

    let builder = crate::nixos::NixOSBuilder::new_with_flake_ref(
        format!("{}#host-alpha", explicit_flake_dir.display()),
        hidden_root.join("nails-system"),
    )
    .with_executor(Box::new(
        crate::nixos::RealCommandExecutor::with_search_path(&bin_dir),
    ));

    NailsManager::with_nixos(
        MockFilesystem::new(),
        Config {
            hidden_volume_root: hidden_root.to_path_buf(),
            state_file_path: state_path.to_path_buf(),
            nixos_flake: Some(format!("{}#host-alpha", explicit_flake_dir.display())),
            ..Config::test_default()
        },
        state_path.to_path_buf(),
        builder,
    )
}

#[test]
#[serial]
fn test_post_mount_guards_skip_flake_validation_on_fast_path() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let manager = manager_with_unbuildable_flake(hidden_root, &state_path);

    let options = crate::ActivateOptions::default();
    assert!(
        !options.skip_flake_validation,
        "the default run validates the flake unless the fast path opts out"
    );

    // Fast path (a cached toplevel is carried forward): the flake is the one a
    // previous activation already built, so it is not re-validated — even though
    // it can no longer evaluate.
    let fast_path = Some("/nix/store/0-nixos-system-host".to_string());
    manager
        .run_post_mount_guards(&options, &fast_path)
        .expect("fast-path re-activation must not re-validate the flake");

    // No fast path: a rebuild is expected, so the broken flake is caught here and
    // the overlays roll back.
    let err = manager
        .run_post_mount_guards(&options, &None)
        .expect_err("a full rebuild must still validate the flake");
    match err {
        NailsError::PreFlightCheckFailed(failures) => assert!(
            failures
                .iter()
                .any(|(name, _, _)| name == "nixos-build-target"),
            "the broken flake must fail nixos-build-target: {failures:?}"
        ),
        other => panic!("expected PreFlightCheckFailed, got {other:?}"),
    }
}

#[test]
#[serial]
fn test_run_read_only_nixos_preflight_uses_metadata_and_attr_existence_checks_without_drv_eval() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let explicit_flake_dir = hidden_root.join("explicit-flake");

    let fs = MockFilesystem::new();
    std::fs::create_dir_all(&explicit_flake_dir).unwrap();
    std::fs::write(
        explicit_flake_dir.join("flake.nix"),
        "{ outputs = _: {}; }\n",
    )
    .unwrap();

    let bin_dir = hidden_root.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let nix_script = bin_dir.join("nix");
    let log_path = hidden_root.join("nix-commands.log");
    std::fs::write(
        &nix_script,
        format!(
            "#!/usr/bin/env sh\nprintf '%s\\n' \"$*\" >> '{}'\ncase \"$1 $2 $3\" in\n  'flake metadata --json') printf '{{\"url\":\"path:{}\"}}\\n' ; exit 0 ;;\n  'eval --raw --expr') printf '1\\n' ; exit 0 ;;\n  *) printf 'unexpected command: %s %s %s\\n' \"$1\" \"$2\" \"$3\" 1>&2 ; exit 8 ;;\nesac\n",
            log_path.display(),
            explicit_flake_dir.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&nix_script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&nix_script, perms).unwrap();
    }

    let builder = crate::nixos::NixOSBuilder::new_with_flake_ref(
        format!("{}#host-alpha", explicit_flake_dir.display()),
        hidden_root.join("nails-system"),
    )
    .with_executor(Box::new(
        crate::nixos::RealCommandExecutor::with_search_path(&bin_dir),
    ));

    let manager = NailsManager::with_nixos(
        fs,
        Config {
            hidden_volume_root: hidden_root.to_path_buf(),
            state_file_path: state_path.clone(),
            nixos_flake: Some(format!("{}#host-alpha", explicit_flake_dir.display())),
            ..Config::test_default()
        },
        state_path,
        builder,
    );

    manager
        .run_read_only_nixos_preflight(false)
        .expect("fast metadata preflight should succeed");

    let command_log = std::fs::read_to_string(log_path).unwrap();
    assert!(
        command_log.contains("flake metadata --json"),
        "{command_log}"
    );
    assert!(command_log.contains("eval --raw --expr"), "{command_log}");
    assert!(
        !command_log.contains("config.system.build.toplevel.drvPath"),
        "preflight should not force toplevel drv evaluation: {command_log}"
    );
}
