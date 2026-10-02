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
    setup_nixos_config_check(&fs, mock_hidden_vol);

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
    setup_nixos_config_check(&fs, mock_hidden_vol);
    setup_nixos_config_check(&fs, mock_hidden_vol);

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

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

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

    // Verify hidden config symlink staged during activation
    let symlink_path = mock_hidden_vol.join("etc/nixos/nails/configuration.nix");
    assert!(
        fs.is_symlink(&symlink_path).unwrap(),
        "Hidden config symlink should be staged during activation"
    );
    let expected_target = mock_hidden_vol.join("config/nixos/configuration.nix");
    assert_eq!(
        fs.mock_get_symlink_target(&symlink_path),
        Some(expected_target)
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
    setup_nixos_config_check(&fs, mock_hidden_vol);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

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
            assert!(failures.iter().any(|(name, _)| name == "hidden-volume"));
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
    setup_nixos_config_check(&fs, hidden_root);

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

    let manager = NailsManager::new(fs, config, state_path.clone());

    manager
        .run_preflight_checks(false)
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
    setup_nixos_config_check(&fs, hidden_root);

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

    let manager = NailsManager::new(fs, config, state_path.clone());
    let err = manager.run_preflight_checks(false).unwrap_err();

    assert!(
        err.to_string().contains("State path must be a file"),
        "unexpected error: {err}"
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
    setup_nixos_config_check(&fs, mock_hidden_vol);

    // 2. Swap enabled
    fs.mock_set_swap_enabled(true); // FAIL

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));

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

            let failure_names: Vec<&str> = failures.iter().map(|(name, _)| name.as_str()).collect();
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
    setup_nixos_config_check(&fs, mock_hidden_vol);

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

    let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));

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
    setup_nixos_config_check(&fs, mock_hidden_vol);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![], // No overlays to mount
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));

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
    setup_nixos_config_check(&fs, mock_hidden_vol);

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
    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));

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
    setup_nixos_config_check(&fs, hidden_root);
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ imports = [ ./nails/configuration.nix ]; }",
    );

    let config = Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    let result = manager.lock().unwrap().activate(false);
    assert!(result.is_err(), "activation should fail in preflight");

    match result.unwrap_err() {
        NailsError::PreFlightCheckFailed(failures) => {
            let (_, message) = failures
                .iter()
                .find(|(name, _)| name == "suspicious-nails-reference")
                .expect("suspicious-nails-reference failure should be reported");
            assert!(message.contains("before any side effects"));
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
        fs.mock_get_symlink_target(&hidden_root.join("etc/nixos/nails/configuration.nix"))
            .is_none(),
        "preflight failure must happen before config symlink staging"
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
    setup_nixos_config_check(&fs, mock_hidden_vol);

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
    fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let builder = NixOSBuilder::new(nixos_dir.clone(), mock_hidden_vol.join("nails-system"));
    let manager = Arc::new(Mutex::new(NailsManager::with_nixos(
        fs, config, state_path, builder,
    )));

    let result = manager.lock().unwrap().activate(false);
    assert!(
        result.is_err(),
        "Activation should fail when flake.nix is missing"
    );

    match result.unwrap_err() {
        NailsError::PreFlightCheckFailed(failures) => {
            let (_, message) = failures
                .iter()
                .find(|(name, _)| name == "nixos-build-target")
                .expect("nixos-build-target failure should be reported");
            assert!(message.contains("flake.nix not found"));
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
    setup_nixos_config_check(&fs, mock_hidden_vol);
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
    let manager = Arc::new(Mutex::new(NailsManager::with_nixos(
        fs, config, state_path, builder,
    )));

    let result = manager.lock().unwrap().activate(false);
    assert!(
        result.is_err(),
        "Activation should fail when explicit flake.nix is missing"
    );

    match result.unwrap_err() {
        NailsError::PreFlightCheckFailed(failures) => {
            let (_, message) = failures
                .iter()
                .find(|(name, _)| name == "nixos-build-target")
                .expect("nixos-build-target failure should be reported");
            assert!(message.contains("flake.nix not found"));
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
    let err_text = err.to_string();
    assert!(
        err_text.contains("flake lock"),
        "unexpected error: {err_text}"
    );
    assert!(
        err_text.contains("does not run 'nix flake update' automatically"),
        "unexpected error: {err_text}"
    );
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
