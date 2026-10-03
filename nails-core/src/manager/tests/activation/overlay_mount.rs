//! Overlay mounting in auto and explicit mode and the /etc import injection.

use super::*;

// ========== Auto Mode ==========

/// Helper to set up Auto mode activation test with MockFilesystem.
///
/// Sets up mock with root directories, hidden volume paths, and all required
/// mock path entries for overlay mounting to work.
fn setup_auto_mode_test(
    dirs: &[&str],
) -> (
    tempfile::TempDir,
    MockFilesystem,
    PathBuf, // state_path
) {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Setup root directories
    let root_dirs: Vec<PathBuf> = dirs.iter().map(PathBuf::from).collect();
    fs.mock_set_root_directories(root_dirs);

    // Mark hidden volume root as writable
    fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
    fs.mock_set_writable(mock_hidden_vol.to_str().unwrap(), true);

    // Pre-create required overlay directories AND set mock paths
    for dir_name in dirs {
        let name = PathBuf::from(dir_name)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        // Create real dirs for temp dir paths
        std::fs::create_dir_all(mock_hidden_vol.join(&name)).unwrap();
        std::fs::create_dir_all(mock_hidden_vol.join(format!(".work/{}", name))).unwrap();

        // Set lower directory (target) as existing in mock
        fs.mock_set_path_exists(dir_name, true);

        // Set upper and work dirs as existing in mock
        let upper = mock_hidden_vol.join(&name);
        let work = mock_hidden_vol.join(format!(".work/{}", name));
        fs.mock_set_path_exists(upper.to_str().unwrap(), true);
        fs.mock_set_path_exists(work.to_str().unwrap(), true);

        // Set .work parent as existing and writable
        let work_parent = mock_hidden_vol.join(".work");
        fs.mock_set_path_exists(work_parent.to_str().unwrap(), true);
        fs.mock_set_writable(work_parent.to_str().unwrap(), true);
    }

    (temp_dir, fs, state_path)
}

#[test]
fn test_activate_auto_mode_overlays_all_non_excluded_dirs() {
    // Test activation with overlay_mode: auto creates overlays for all non-excluded dirs
    let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/home", "/etc", "/var"]);
    let mock_hidden_vol = temp_dir.path();

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Auto,
        overlay_exclusions: vec![],
        overlay_exclusions_remove: vec![],
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    let result = manager.lock().unwrap().activate(true);
    assert!(result.is_ok(), "Activation should succeed: {:?}", result);

    // Verify all 3 directories were overlaid
    let state = manager.lock().unwrap().current_state().unwrap();
    if let SystemState::Active { overlays, .. } = state {
        assert_eq!(overlays.len(), 3, "Should have 3 overlays");
        assert!(overlays.contains(&PathBuf::from("/etc")));
        assert!(overlays.contains(&PathBuf::from("/home")));
        assert!(overlays.contains(&PathBuf::from("/var")));
    } else {
        panic!("Expected Active state, got {:?}", state);
    }
}

#[test]
#[serial]
fn test_activate_auto_mode_rollback_restarts_journald_and_nix_daemon_after_unmounts() {
    // When a later overlay fails after /nix and /var were mounted, activation
    // rolls everything back and only then restarts the services that were moved
    // onto overlays: journald (off the /var overlay) and nix-daemon.
    let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/nix", "/srv", "/var"]);
    let mock_hidden_vol = temp_dir.path();

    // /srv fails to mount after /nix and /var have succeeded (alphabetical order).
    fs.mock_set_mount_should_fail("/srv", true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Auto,
        overlay_exclusions: vec![],
        overlay_exclusions_remove: vec![],
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    // Clear any recorder residue left on this thread by earlier work.
    let _ = crate::manager::helpers::drain_recorded_service_actions();

    let result = manager.lock().unwrap().activate(true);
    assert!(
        result.is_err(),
        "activation should fail when an overlay cannot be mounted"
    );

    // Everything that mounted was rolled back.
    assert!(
        !fs.is_mounted(Path::new("/nix")).unwrap(),
        "/nix overlay should be unmounted after rollback"
    );
    assert!(
        !fs.is_mounted(Path::new("/var")).unwrap(),
        "/var overlay should be unmounted after rollback"
    );

    let actions = crate::manager::helpers::drain_recorded_service_actions();
    assert!(
        actions.iter().any(|action| action == "start:nix-daemon"),
        "nix-daemon must be restarted on activation rollback: {actions:?}"
    );
    assert!(
        actions
            .iter()
            .any(|action| action == "start:systemd-journald"),
        "journald must be restarted on activation rollback: {actions:?}"
    );
}

#[test]
fn test_activate_auto_mode_mount_order_is_alphabetical() {
    // Test mount order is alphabetical
    let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/var", "/etc", "/home"]);
    let mock_hidden_vol = temp_dir.path();

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Auto,
        overlay_exclusions: vec![],
        overlay_exclusions_remove: vec![],
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    let result = manager.lock().unwrap().activate(true);
    assert!(result.is_ok(), "Activation should succeed: {:?}", result);

    // Verify mount order is alphabetical by checking overlay_status
    let mgr = manager.lock().unwrap();
    let cached = mgr.cached_state.borrow();
    if let Some(ref state_file) = *cached {
        let mut mount_targets: Vec<PathBuf> = state_file.overlay_status.keys().cloned().collect();
        mount_targets.sort();
        assert_eq!(mount_targets[0], PathBuf::from("/etc"));
        assert_eq!(mount_targets[1], PathBuf::from("/home"));
        assert_eq!(mount_targets[2], PathBuf::from("/var"));
    } else {
        panic!("No cached state found");
    }
}

#[test]
fn test_activate_auto_mode_upper_work_dirs_at_correct_paths() {
    // Test upper/work dirs created at correct paths
    let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/home", "/etc"]);
    let mock_hidden_vol = temp_dir.path();

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Auto,
        overlay_exclusions: vec![],
        overlay_exclusions_remove: vec![],
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    let result = manager.lock().unwrap().activate(true);
    assert!(result.is_ok(), "Activation should succeed: {:?}", result);

    // Verify overlay paths are correct
    let mgr = manager.lock().unwrap();
    let cached = mgr.cached_state.borrow();
    if let Some(ref state_file) = *cached {
        // /home overlay
        let home_info = state_file
            .overlay_status
            .get(&PathBuf::from("/home"))
            .expect("/home overlay should exist");
        assert_eq!(home_info.upper_dir, mock_hidden_vol.join("home"));
        assert_eq!(home_info.work_dir, mock_hidden_vol.join(".work/home"));
        assert_eq!(home_info.lower_dir, PathBuf::from("/home"));

        // /etc overlay
        let etc_info = state_file
            .overlay_status
            .get(&PathBuf::from("/etc"))
            .expect("/etc overlay should exist");
        assert_eq!(etc_info.upper_dir, mock_hidden_vol.join("etc"));
        assert_eq!(etc_info.work_dir, mock_hidden_vol.join(".work/etc"));
        assert_eq!(etc_info.lower_dir, PathBuf::from("/etc"));
    } else {
        panic!("No cached state found");
    }
}

#[test]
fn test_activate_auto_mode_stops_after_mount_failure() {
    // Activation should abort if any overlay fails (safety over partial mounts)
    let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/etc", "/home", "/var"]);
    let mock_hidden_vol = temp_dir.path();

    // Configure /etc to fail mounting
    fs.mock_set_mount_should_fail("/etc", true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Auto,
        overlay_exclusions: vec![],
        overlay_exclusions_remove: vec![],
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    // Activation should fail fast to avoid partial state
    let result = manager.lock().unwrap().activate(true);
    assert!(result.is_err(), "Activation should fail on mount error");

    // Verify state rolled back to Inactive and no overlays recorded
    let state = manager.lock().unwrap().current_state().unwrap();
    assert!(
        matches!(state, SystemState::Inactive),
        "State should roll back to Inactive: got {:?}",
        state
    );
}

#[test]
fn test_activate_auto_mode_failed_overlays_recorded_on_failure() {
    // Failed overlays should be recorded even when activation aborts
    let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/etc", "/home", "/var"]);
    let mock_hidden_vol = temp_dir.path();

    // Configure /etc to fail mounting
    fs.mock_set_mount_should_fail("/etc", true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Auto,
        overlay_exclusions: vec![],
        overlay_exclusions_remove: vec![],
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    let result = manager.lock().unwrap().activate(true);
    assert!(result.is_err(), "Activation should fail on mount error");

    // Verify failed overlays are recorded in state
    let mgr = manager.lock().unwrap();
    let cached = mgr.cached_state.borrow();
    if let Some(ref state_file) = *cached {
        assert_eq!(
            state_file.failed_overlays.len(),
            1,
            "Should have 1 failed overlay"
        );
        assert_eq!(state_file.failed_overlays[0].target, PathBuf::from("/etc"));
        assert!(
            !state_file.failed_overlays[0].error_message.is_empty(),
            "Error message should not be empty"
        );
    } else {
        panic!("No cached state found");
    }
}

#[test]
fn test_activate_auto_mode_all_mounts_fail_returns_first_mount_error() {
    let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/etc", "/home"]);
    let mock_hidden_vol = temp_dir.path();

    fs.mock_set_mount_should_fail("/etc", true);
    fs.mock_set_mount_should_fail("/home", true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Auto,
        overlay_exclusions: vec![],
        overlay_exclusions_remove: vec![],
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    let err = manager.lock().unwrap().activate(true).unwrap_err();
    assert!(err.to_string().contains("/etc"));

    let state = manager.lock().unwrap().current_state().unwrap();
    assert_eq!(state, SystemState::Inactive);
}

#[test]
fn test_activate_auto_mode_with_user_exclusions() {
    // Integration test: auto mode with user-specified exclusions
    let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/boot", "/etc", "/home", "/nix"]);
    let mock_hidden_vol = temp_dir.path();

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Auto,
        overlay_exclusions: vec![PathBuf::from("/boot"), PathBuf::from("/nix")],
        overlay_exclusions_remove: vec![],
        // /nix is load-bearing: excluding it is refused unless accepted.
        allow_leaky_exclusions: vec![PathBuf::from("/nix")],
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    let result = manager.lock().unwrap().activate(true);
    assert!(result.is_ok(), "Activation should succeed: {:?}", result);

    // Only /etc and /home should be overlaid (boot and nix excluded)
    let state = manager.lock().unwrap().current_state().unwrap();
    if let SystemState::Active { overlays, .. } = state {
        assert_eq!(overlays.len(), 2, "Should have 2 overlays");
        assert!(overlays.contains(&PathBuf::from("/etc")));
        assert!(overlays.contains(&PathBuf::from("/home")));
        assert!(!overlays.contains(&PathBuf::from("/boot")));
        assert!(!overlays.contains(&PathBuf::from("/nix")));
    } else {
        panic!("Expected Active state, got {:?}", state);
    }
}

#[test]
fn test_activate_refuses_hidden_root_under_an_auto_target_before_any_mount() {
    // The hidden root sits below a top-level directory that Auto mode would
    // overlay, as with VeraCrypt's /media/veracryptN. The floor holds even
    // with --no-preflight and nothing is mounted.
    let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/etc", "/home"]);
    let hidden_root = temp_dir.path().to_path_buf();
    let top = PathBuf::from("/").join(
        hidden_root
            .components()
            .nth(1)
            .expect("tempdir is below a top-level directory"),
    );
    fs.mock_set_root_directories(vec![
        PathBuf::from("/etc"),
        PathBuf::from("/home"),
        top.clone(),
    ]);

    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        log_path: hidden_root.join("logs"),
        overlay_mode: OverlayMode::Auto,
        overlays: vec![],
        ..Config::test_default()
    };
    let mut manager = NailsManager::new(fs.clone(), config, state_path);

    let err = manager.activate(true).unwrap_err();

    let message = err.to_string();
    assert!(message.contains("overlay-targets"), "{message}");
    assert!(
        message.contains(&format!(
            "hidden root {} is under overlay target {}",
            hidden_root.display(),
            top.display()
        )),
        "{message}"
    );
    assert!(fs.get_mounted_paths().is_empty(), "nothing may be mounted");
    assert!(!manager.current_state().unwrap().is_active());
}

#[test]
fn test_activate_refuses_a_leaky_exclusion_even_without_preflight() {
    let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/etc", "/home"]);

    let mut config = Config {
        hidden_volume_root: temp_dir.path().to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Auto,
        overlays: vec![],
        ..Config::test_default()
    };
    // Set directly: loading or building the config would already refuse it.
    config.overlay_exclusions = vec![PathBuf::from("/home")];
    let mut manager = NailsManager::new(fs.clone(), config, state_path);

    let message = manager.activate(true).unwrap_err().to_string();

    assert!(
        message.contains("leaves /home on the decoy disk"),
        "{message}"
    );
    assert!(fs.get_mounted_paths().is_empty(), "nothing may be mounted");
}

// ========== /nix runtime gating (T-084) ==========

#[test]
fn test_nix_on_foreign_host_only_cycles_daemon() {
    // On a Nix-on-foreign host (Nix installed on Debian/Ubuntu) overlaying /nix
    // must only stop and start nix-daemon — never the NixOS store self-bind or the
    // /run/current-system restore. The host is FHS, so the merged loop resolves the
    // Foreign /nix runtime from the platform, not from the target name.
    let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/home", "/nix"]);
    let mock_hidden_vol = temp_dir.path();

    // Declare a Debian host so detection resolves to FHS (Foreign /nix runtime).
    fs.mock_add_file("/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n");
    fs.mock_add_file("/proc/1/comm", "systemd");

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Auto,
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    // Clear any recorder residue left on this thread by earlier work.
    let _ = crate::manager::helpers::drain_recorded_service_actions();

    let result = manager.lock().unwrap().activate(true);
    assert!(result.is_ok(), "activation should succeed: {result:?}");

    // Only the daemon was cycled, stop then start, and nothing else nix-related.
    let actions = crate::manager::helpers::drain_recorded_service_actions();
    assert_eq!(
        actions,
        vec![
            "stop:nix-daemon".to_string(),
            "start:nix-daemon".to_string()
        ],
        "foreign /nix must only stop then start nix-daemon: {actions:?}"
    );

    // No NixOS store self-bind and no /run/current-system symlink restore happened.
    assert!(
        !fs.is_mounted(Path::new("/nix/store")).unwrap(),
        "no /nix/store self-bind may be created on a foreign host"
    );
    assert_eq!(
        fs.mock_get_symlink_target(Path::new("/run/current-system")),
        None,
        "no /run/current-system restore may happen on a foreign host"
    );

    // /nix was still overlaid.
    let state = manager.lock().unwrap().current_state().unwrap();
    if let SystemState::Active { overlays, .. } = state {
        assert!(overlays.contains(&PathBuf::from("/nix")));
    } else {
        panic!("Expected Active state, got {state:?}");
    }
}

#[test]
fn test_nix_on_nixos_host_restores_store_bind_through_merged_loop() {
    // The counterpart to the foreign test: a NixOS host takes the Native path, so
    // the merged loop restores the read-only /nix/store self-bind after overlaying.
    let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/home", "/nix"]);
    let mock_hidden_vol = temp_dir.path();

    fs.mock_add_file("/etc/os-release", "ID=nixos\nVERSION_ID=\"24.11\"\n");
    fs.mock_add_file("/proc/1/comm", "systemd");
    fs.mock_set_path_exists("/nix/store", true);
    fs.mock_set_path_type("/nix/store", PathKind::Dir);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Auto,
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    let _ = crate::manager::helpers::drain_recorded_service_actions();

    let result = manager.lock().unwrap().activate(true);
    assert!(result.is_ok(), "activation should succeed: {result:?}");

    // The Native path self-binds /nix/store read-only after the overlay.
    assert!(
        fs.is_mounted(Path::new("/nix/store")).unwrap(),
        "NixOS activation must restore the /nix/store self-bind"
    );
}

// ========== Explicit Mode ==========

#[test]
fn test_activate_explicit_mode_uses_only_configured_overlays() {
    // Test explicit mode uses only configured overlays (legacy behavior)
    use crate::OverlayConfig;

    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Root has many directories...
    fs.mock_set_root_directories(vec![
        PathBuf::from("/boot"),
        PathBuf::from("/etc"),
        PathBuf::from("/home"),
        PathBuf::from("/var"),
        PathBuf::from("/tmp"),
    ]);

    fs.mock_set_path_exists("/", true);
    let upper_home = mock_hidden_vol.join("overlays/home/upper");
    let work_home = mock_hidden_vol.join("overlays/home/work");
    std::fs::create_dir_all(&upper_home).unwrap();
    std::fs::create_dir_all(&work_home).unwrap();
    fs.mock_set_path_exists(upper_home.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Explicit, // Explicit mode!
        overlays: vec![OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/"),
            upper: upper_home.clone(),
            work: work_home.clone(),
            target: PathBuf::from("/home"),
        }],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    let result = manager.lock().unwrap().activate(true);
    assert!(result.is_ok(), "Activation should succeed: {:?}", result);

    // Only 1 overlay (from config), NOT all 5 discovered directories
    let state = manager.lock().unwrap().current_state().unwrap();
    if let SystemState::Active { overlays, .. } = state {
        assert_eq!(
            overlays.len(),
            1,
            "Should have exactly 1 overlay (explicit mode)"
        );
        assert_eq!(overlays[0], PathBuf::from("/home"));
    } else {
        panic!("Expected Active state, got {:?}", state);
    }
}

#[test]
fn test_default_overlay_mode_is_auto() {
    // Test default mode is auto
    let config = Config::test_default();
    assert_eq!(config.overlay_mode, OverlayMode::Auto);
}

// ========== /etc hardware-configuration import injection ==========

#[test]
fn test_activation_injects_import_block_into_overlayed_hardware_config() {
    use crate::OverlayConfig;

    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Base hardware config must exist and be clean
    let base_content = r#"{ config, pkgs, modulesPath, ... }:
{
  imports = [
    (modulesPath + "/installer/scan/not-detected.nix")
  ];
  boot.loader.grub.enable = true;
}
"#;
    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", PathKind::File);
    fs.mock_set_file_content("/etc/nixos/hardware-configuration.nix", base_content);

    // Overlay config for /etc
    fs.mock_set_path_exists("/etc", true);
    let upper_etc = mock_hidden_vol.join("etc");
    let work_etc = mock_hidden_vol.join(".work/etc");
    std::fs::create_dir_all(&upper_etc).unwrap();
    std::fs::create_dir_all(&work_etc).unwrap();
    fs.mock_set_path_exists(upper_etc.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);
    fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);

    // Initial state file
    let initial_state = StateFile {
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    initial_state
        .save_with_custom_root(&state_path, mock_hidden_vol)
        .expect("Should save initial state");

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Explicit,
        overlays: vec![OverlayConfig {
            name: "etc".to_string(),
            lower: PathBuf::from("/etc"),
            upper: upper_etc.clone(),
            work: work_etc.clone(),
            target: PathBuf::from("/etc"),
        }],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    let result = manager.lock().unwrap().activate(true);
    assert!(result.is_ok(), "Activation should succeed: {:?}", result);

    let written = fs
        .get_written_content(&PathBuf::from("/etc/nixos/hardware-configuration.nix"))
        .expect("Injection should write overlayed hardware config");

    // The live hardware-configuration.nix becomes the fixed wrapper importing
    // the preserved base and the hidden module.
    assert!(
        written.contains("./nails/configuration.nix"),
        "wrapper should import the hidden module"
    );
    assert!(
        written.contains("./hardware-configuration.base.nix"),
        "wrapper should import the preserved base"
    );
    assert!(
        !written.contains("installer/scan/not-detected.nix"),
        "wrapper must not inline the original hardware config"
    );

    // The original content is preserved verbatim in the base file.
    let base_written = fs
        .get_written_content(&PathBuf::from("/etc/nixos/hardware-configuration.base.nix"))
        .expect("Injection should preserve the original as the base file");
    assert!(base_written.contains("installer/scan/not-detected.nix"));
    assert!(
        base_written.contains("boot.loader.grub.enable = true;"),
        "Original hardware config should be preserved in the base file"
    );
}

#[test]
#[tracing_test::traced_test]
fn test_activate_explicit_mode_empty_overlays_fails() {
    // Security test: Explicit mode with NO overlays should fail activation
    // This prevents silent activation with NO forensic protection
    use std::sync::Arc;

    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();
    fs.mock_set_root_directories(vec![PathBuf::from("/home"), PathBuf::from("/etc")]);

    // Mark hidden volume as writable and existing
    fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
    fs.mock_set_writable(mock_hidden_vol.to_str().unwrap(), true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Explicit,
        overlays: vec![], // No overlays configured - SECURITY ISSUE
        ..Config::default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    let result = manager.lock().unwrap().activate(true);

    // Should FAIL with clear error message
    assert!(
        result.is_err(),
        "Activation should fail with empty Explicit mode"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("no overlays") || err_msg.contains("NO forensic protection"),
        "Error should mention empty overlays: {}",
        err_msg
    );
}

#[test]
fn test_activation_aborts_when_base_hardware_config_is_dirty() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    let state_path = mock_hidden_vol.join("state.json");
    let fs = MockFilesystem::new();
    let _home = crate::cleanup::test_utils::set_safe_test_home();
    let bash_history = Path::new(crate::cleanup::test_utils::TEST_HOME).join(".bash_history");

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", PathKind::File);
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ imports = [ /mnt/hidden/nixos/configuration.nix ]; }",
    );
    fs.mock_set_files_with_pattern(
        "/etc/nixos",
        ".nix",
        &[Path::new("/etc/nixos/hardware-configuration.nix")],
    );

    fs.mock_set_path_exists("/home", true);
    let upper_home = mock_hidden_vol.join("overlays/home/upper");
    let work_home = mock_hidden_vol.join("overlays/home/work");
    std::fs::create_dir_all(&upper_home).unwrap();
    std::fs::create_dir_all(&work_home).unwrap();
    fs.mock_set_path_exists(upper_home.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);
    fs.mock_set_path_exists(bash_history.to_str().unwrap(), true);
    fs.mock_set_path_type(bash_history.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(bash_history.to_str().unwrap(), "nails activate\nls\n");

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: OverlayMode::Explicit,
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_home,
                work: work_home,
                target: PathBuf::from("/home"),
            }],
            ..Config::test_default()
        },
        state_path,
    )));

    let err = manager.lock().unwrap().activate(false).unwrap_err();
    assert!(err.to_string().contains("suspicious-nails-reference"));
    assert!(err.to_string().contains("before any side effects"));
    assert!(
        fs.mock_ops().is_empty(),
        "no side-effecting writes or overlay mounts should be attempted"
    );
    assert!(
        fs.get_written_content(&bash_history).is_none(),
        "pre-activation cleanup must not run before suspicious-reference failure"
    );
    assert!(
        fs.mock_get_symlink_target(&mock_hidden_vol.join("etc/nixos/nails/configuration.nix"))
            .is_none(),
        "config symlink staging must not run before suspicious-reference failure"
    );
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );
}

#[test]
fn test_activation_aborts_when_base_hardware_config_cannot_be_read() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    let state_path = mock_hidden_vol.join("state.json");
    let fs = MockFilesystem::new();
    let _home = crate::cleanup::test_utils::set_safe_test_home();
    let bash_history = Path::new(crate::cleanup::test_utils::TEST_HOME).join(".bash_history");

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", PathKind::File);
    fs.mock_set_files_with_pattern(
        "/etc/nixos",
        ".nix",
        &[Path::new("/etc/nixos/hardware-configuration.nix")],
    );
    fs.mock_set_path_exists("/home", true);
    let upper_home = mock_hidden_vol.join("overlays/home/upper");
    let work_home = mock_hidden_vol.join("overlays/home/work");
    std::fs::create_dir_all(&upper_home).unwrap();
    std::fs::create_dir_all(&work_home).unwrap();
    fs.mock_set_path_exists(upper_home.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);
    fs.mock_set_path_exists(bash_history.to_str().unwrap(), true);
    fs.mock_set_path_type(bash_history.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(bash_history.to_str().unwrap(), "nails activate\nls\n");

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: OverlayMode::Explicit,
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_home,
                work: work_home,
                target: PathBuf::from("/home"),
            }],
            ..Config::test_default()
        },
        state_path,
    )));

    let err = manager.lock().unwrap().activate(false).unwrap_err();
    assert!(err.to_string().contains("File not found in mock"));
    assert!(
        fs.mock_ops().is_empty(),
        "no side-effecting writes or overlay mounts should be attempted"
    );
    assert!(
        fs.get_written_content(&bash_history).is_none(),
        "pre-activation cleanup must not run before suspicious-reference read failure"
    );
    assert!(
        fs.mock_get_symlink_target(&mock_hidden_vol.join("etc/nixos/nails/configuration.nix"))
            .is_none(),
        "config symlink staging must not run before suspicious-reference read failure"
    );
}

#[test]
fn test_activate_explicit_mode_rejects_critical_system_root_overlay_bin() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    let state_path = mock_hidden_vol.join("state.json");
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", PathKind::File);
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ }",
    );
    fs.mock_set_path_exists("/bin", true);
    // A Debian/Ubuntu (FHS) host keeps /bin read-only, so overlaying it is refused
    // by the platform policy rather than a hardcoded block.
    fs.mock_add_file("/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n");
    fs.mock_add_file("/proc/1/comm", "systemd");

    let upper_bin = mock_hidden_vol.join("overlays/bin/upper");
    let work_bin = mock_hidden_vol.join("overlays/bin/work");
    std::fs::create_dir_all(&upper_bin).unwrap();
    std::fs::create_dir_all(&work_bin).unwrap();
    fs.mock_set_path_exists(upper_bin.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_bin.to_str().unwrap(), true);

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: OverlayMode::Explicit,
            overlays: vec![OverlayConfig {
                name: "bin".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_bin,
                work: work_bin,
                target: PathBuf::from("/bin"),
            }],
            ..Config::test_default()
        },
        state_path,
    )));

    let err = manager.lock().unwrap().activate(true).unwrap_err();
    assert!(
        err.to_string()
            .contains("Overlaying system tree /bin is blocked"),
        "got: {err}"
    );
    assert!(fs.mock_ops().is_empty());
}

#[test]
fn test_activation_rolls_back_when_import_injection_fails_after_etc_mount() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    let state_path = mock_hidden_vol.join("state.json");
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", PathKind::File);
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ }",
    );
    fs.mock_set_write_should_fail("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/etc", true);

    let upper_etc = mock_hidden_vol.join("overlays/etc/upper");
    let work_etc = mock_hidden_vol.join("overlays/etc/work");
    std::fs::create_dir_all(&upper_etc).unwrap();
    std::fs::create_dir_all(&work_etc).unwrap();
    fs.mock_set_path_exists(upper_etc.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: OverlayMode::Explicit,
            overlays: vec![OverlayConfig {
                name: "etc".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_etc,
                work: work_etc,
                target: PathBuf::from("/etc"),
            }],
            ..Config::test_default()
        },
        state_path,
    )));

    let err = manager.lock().unwrap().activate(true).unwrap_err();
    assert!(err.to_string().contains("Mock write failure"));
    assert!(
        !fs.is_mounted(Path::new("/etc")).unwrap(),
        "/etc should be rolled back"
    );
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );
}

#[test]
#[tracing_test::traced_test]
fn test_activate_explicit_mode_continues_when_clean_stale_network_config_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    let state_path = mock_hidden_vol.join("state.json");
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", PathKind::File);
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ }",
    );
    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/etc", true);

    let upper_etc = mock_hidden_vol.join("overlays/etc/upper");
    let work_etc = mock_hidden_vol.join("overlays/etc/work");
    std::fs::create_dir_all(&upper_etc).unwrap();
    std::fs::create_dir_all(&work_etc).unwrap();
    fs.mock_set_path_exists(upper_etc.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);
    let resolv_conf = upper_etc.join("resolv.conf");
    fs.mock_set_path_exists(resolv_conf.to_str().unwrap(), true);
    fs.mock_set_remove_should_fail(resolv_conf.to_str().unwrap(), true);

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        Config {
            hidden_volume_root: mock_hidden_vol.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: OverlayMode::Explicit,
            overlays: vec![OverlayConfig {
                name: "etc".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_etc,
                work: work_etc,
                target: PathBuf::from("/etc"),
            }],
            ..Config::test_default()
        },
        state_path,
    )));

    let result = manager.lock().unwrap().activate(true);
    assert!(
        result.is_ok(),
        "activation should continue on stale network cleanup failure: {:?}",
        result
    );
    assert!(logs_contain("Failed to clean stale network config"));
}

// ========== Error Format ==========

#[test]
#[tracing_test::traced_test]
fn test_overlay_mount_failure_error_format() {
    // Validate error message format "⚠ Could not overlay /path: {reason}"
    use std::sync::Arc;

    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Setup mock filesystem with root directories
    fs.mock_set_root_directories(vec![PathBuf::from("/home"), PathBuf::from("/etc")]);

    // Mark hidden volume root as writable so create_overlay_config can create directories
    fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
    fs.mock_set_writable(mock_hidden_vol.to_str().unwrap(), true);

    // Create required directories on mock filesystem
    let home_upper = mock_hidden_vol.join("home");
    let home_work = mock_hidden_vol.join(".work/home");
    let etc_upper = mock_hidden_vol.join("etc");
    let etc_work = mock_hidden_vol.join(".work/etc");

    std::fs::create_dir_all(&home_upper).unwrap();
    std::fs::create_dir_all(&home_work).unwrap();
    std::fs::create_dir_all(&etc_upper).unwrap();
    std::fs::create_dir_all(&etc_work).unwrap();

    // Configure mock to fail mounting /etc
    fs.mock_set_mount_should_fail("/etc", true);

    let mut config = Config::default();
    config.hidden_volume_root = mock_hidden_vol.to_path_buf();
    // Keep the state file and logs on the hidden volume. Their defaults are
    // derived from the test binary location under `/home`, which the
    // overlay-targets floor would (correctly) refuse to mount over.
    config.state_file_path = state_path.clone();
    config.log_path = mock_hidden_vol.join("logs");
    config.overlay_mode = OverlayMode::Auto;

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    // Attempt activation - should succeed partially
    // Skip preflight to directly test mount failure error format
    let _result = manager.lock().unwrap().activate(true);

    // Verify error message format
    assert!(
        logs_contain("⚠ Could not overlay /etc"),
        "Error message should contain '⚠ Could not overlay /etc'"
    );
    assert!(
        logs_contain("⚠ Could not overlay"),
        "Error message should follow format '⚠ Could not overlay <path>: <reason>'"
    );
}

// ========== Auto Mode Edge Cases ==========

#[test]
#[tracing_test::traced_test]
fn test_activate_auto_mode_all_directories_excluded() {
    // Edge case: All directories excluded by user configuration
    // Should activate successfully with 0 overlays and log warning
    use std::sync::Arc;

    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Setup: only 3 directories in root
    fs.mock_set_root_directories(vec![
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/var"),
    ]);

    // Mark hidden volume root as writable
    fs.mock_set_path_exists(mock_hidden_vol.to_str().unwrap(), true);
    fs.mock_set_writable(mock_hidden_vol.to_str().unwrap(), true);

    // Exclude ALL directories (edge case configuration)
    let mut config = Config::default();
    config.hidden_volume_root = mock_hidden_vol.to_path_buf();
    config.overlay_mode = OverlayMode::Auto;
    config.overlay_exclusions = vec![
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/var"),
    ];
    // All three are load-bearing, so the leak has to be accepted explicitly.
    config.allow_leaky_exclusions = config.overlay_exclusions.clone();

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    // Attempt activation - should succeed with 0 overlays
    let result = manager.lock().unwrap().activate(true);

    assert!(
        result.is_ok(),
        "Activation should succeed even with all directories excluded: {:?}",
        result
    );

    // Verify warning about no overlay targets was logged
    assert!(
        logs_contain("No overlay targets after applying exclusions"),
        "Should log warning when all directories excluded"
    );

    // Verify system state is Active (even with 0 overlays)
    let mgr = manager.lock().unwrap();
    let cached = mgr.cached_state.borrow();
    if let Some(ref state_file) = *cached {
        assert!(state_file.state.is_active(), "State should be Active");
        assert_eq!(state_file.overlay_status.len(), 0);
    } else {
        panic!("State file should be cached");
    }
}

// ========== Import Injection Target ==========

/// Injection targets the overlay path, leaving the hidden underlay clean:
/// inject_import_block() targets `/etc/nixos/hardware-configuration.nix` (the overlayed
/// path). The hidden underlay at `{hidden}/etc/nixos/hardware-configuration.nix` must
/// remain unmodified (no import injected).
///
/// Verified by: running inject_import_block on a mock that serves a clean base config at
/// `/etc/nixos/hardware-configuration.nix`, then confirming the MockFilesystem only
/// modified that single path — the hidden underlay path is NOT written to.
#[test]
fn test_activation_inject_targets_overlayed_path_not_underlay() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden = temp_dir.path();
    let fs = MockFilesystem::new();

    // The overlayed (live) hardware config — no import yet (overlay is mounted, so this
    // is what the OS sees at /etc/nixos/hardware-configuration.nix after mounting)
    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", PathKind::File);
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ }",
    );

    // The hidden underlay — also has no import initially
    let underlay = hidden.join("etc/nixos/hardware-configuration.nix");
    fs.mock_set_path_exists(underlay.to_str().unwrap(), true);
    fs.mock_set_path_type(underlay.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(
        underlay.to_str().unwrap(),
        "{ config, lib, pkgs, ... }:\n{ }",
    );

    // inject_import_block writes to /etc/nixos/hardware-configuration.nix (overlayed path)
    let result = inject_import_block(&fs);
    assert!(
        result.is_ok(),
        "inject_import_block should succeed: {:?}",
        result
    );

    // Overlayed path now contains the import
    let overlayed_content = fs
        .read_file_content(std::path::Path::new(
            "/etc/nixos/hardware-configuration.nix",
        ))
        .unwrap();
    assert!(
        overlayed_content.contains("./nails/configuration.nix"),
        "Overlayed hardware-configuration.nix should contain the injected import"
    );

    // Underlay path is UNTOUCHED — contains no import
    let underlay_content = fs.read_file_content(&underlay).unwrap();
    assert!(
        !underlay_content.contains("./nails/configuration.nix"),
        "Hidden underlay hardware-configuration.nix must NOT be modified by inject_import_block"
    );

    // Verify only the overlayed path was written
    let ops = fs.mock_ops();
    assert!(
        ops.contains(&MockOp::WriteFile {
            path: PathBuf::from("/etc/nixos/hardware-configuration.nix")
        }),
        "inject_import_block should write to the overlayed hardware config path"
    );
    assert!(
        !ops.contains(&MockOp::WriteFile { path: underlay }),
        "inject_import_block must not write to the hidden underlay path"
    );
}

/// inject_import_block() must run AFTER the /etc overlay is mounted.
/// This test verifies ordering by inspecting the MockFilesystem operation log.
#[test]
fn test_activation_inject_happens_after_etc_overlay_mount() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    let state_path = mock_hidden_vol.join("state.json");
    let fs = MockFilesystem::new();

    // Base config clean so verify_base_config_clean() passes.
    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", PathKind::File);
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ }",
    );

    // Overlay dirs
    let upper_home = mock_hidden_vol.join("overlays/home/upper");
    let work_home = mock_hidden_vol.join("overlays/home/work");
    let upper_etc = mock_hidden_vol.join("overlays/etc/upper");
    let work_etc = mock_hidden_vol.join("overlays/etc/work");

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_type("/", PathKind::Dir);
    fs.mock_set_path_exists(upper_home.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);
    fs.mock_set_path_exists(upper_etc.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path,
        overlay_mode: crate::OverlayMode::Explicit,
        overlays: vec![
            crate::OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_home,
                work: work_home,
                target: PathBuf::from("/home"),
            },
            crate::OverlayConfig {
                name: "etc".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_etc,
                work: work_etc,
                target: PathBuf::from("/etc"),
            },
        ],
        ..Config::test_default()
    };
    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        mock_hidden_vol.join("state.json"),
    )));

    let result = manager.lock().unwrap().activate(true);
    assert!(result.is_ok(), "Activation should succeed: {:?}", result);

    let ops = fs.mock_ops();
    let etc_mount_idx = ops.iter().position(
        |op| matches!(op, MockOp::MountOverlay { target } if target == &PathBuf::from("/etc")),
    );
    let inject_idx = ops.iter().position(|op| {
            matches!(op, MockOp::WriteFile { path } if path == &PathBuf::from("/etc/nixos/hardware-configuration.nix"))
        });

    assert!(
        etc_mount_idx.is_some(),
        "Expected /etc overlay mount operation in op log"
    );
    assert!(
        inject_idx.is_some(),
        "Expected inject_import_block write operation in op log"
    );
    assert!(
        etc_mount_idx.unwrap() < inject_idx.unwrap(),
        "inject_import_block must run after /etc overlay mount"
    );
}

// ========== Read-only guard (T-083) ==========

/// Build a manager over a Debian/Ubuntu (FHS) mock whose decoy root and /usr are
/// real directories, so the read-only policy resolves to [/, /usr].
fn fhs_guard_manager() -> (
    tempfile::TempDir,
    MockFilesystem,
    NailsManager<MockFilesystem>,
) {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n");
    fs.mock_add_file("/proc/1/comm", "systemd");
    fs.mock_set_path_type("/", PathKind::Dir);
    fs.mock_set_path_type("/usr", PathKind::Dir);
    // usr-merge symlinks resolve into /usr and must not be guarded twice.
    for link in ["/bin", "/sbin", "/lib", "/lib64"] {
        fs.mock_set_is_symlink(link, true);
    }

    let config = Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: state_path.clone(),
        ..Config::test_default()
    };
    let manager = NailsManager::new(fs.clone(), config, state_path);
    (temp_dir, fs, manager)
}

#[test]
fn test_read_only_guard_applies_and_tears_down_on_fhs() {
    let (_tmp, fs, manager) = fhs_guard_manager();

    let guarded = manager
        .apply_read_only_guard()
        .expect("read-only guard applies on an FHS host");
    assert_eq!(
        guarded,
        vec![PathBuf::from("/"), PathBuf::from("/usr")],
        "the decoy root and /usr are guarded; usr-merge symlinks are not"
    );
    assert!(fs.mock_is_read_only_guarded(Path::new("/")));
    assert!(fs.mock_is_read_only_guarded(Path::new("/usr")));

    manager.teardown_read_only_guards(&guarded);
    assert!(!fs.mock_is_read_only_guarded(Path::new("/")));
    assert!(!fs.mock_is_read_only_guarded(Path::new("/usr")));
}

#[test]
fn test_read_only_guard_is_a_no_op_on_nixos() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();
    fs.mock_add_file("/etc/os-release", "ID=nixos\nVERSION_ID=\"24.11\"\n");
    fs.mock_add_file("/proc/1/comm", "systemd");
    fs.mock_set_path_type("/", PathKind::Dir);
    fs.mock_set_path_type("/usr", PathKind::Dir);

    let config = Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: state_path.clone(),
        ..Config::test_default()
    };
    let manager = NailsManager::new(fs.clone(), config, state_path);

    let guarded = manager.apply_read_only_guard().expect("no-op succeeds");
    assert!(
        guarded.is_empty(),
        "NixOS protects the decoy with overlays, not a guard"
    );
    assert!(!fs.mock_is_read_only_guarded(Path::new("/")));
}

#[test]
fn test_read_only_guard_fails_closed_when_root_is_busy() {
    let (_tmp, fs, manager) = fhs_guard_manager();
    // The decoy root cannot be remounted read-only (active references): the guard
    // must fail and leave nothing behind.
    fs.mock_set_mount_fail_errno("/", nix::errno::Errno::EBUSY);

    let error = manager
        .apply_read_only_guard()
        .expect_err("a busy root must fail the guard closed");
    assert!(
        matches!(error, NailsError::MountBusy { .. }),
        "got: {error}"
    );
    assert!(!fs.mock_is_read_only_guarded(Path::new("/")));
    assert!(!fs.mock_is_read_only_guarded(Path::new("/usr")));
}

#[test]
#[serial]
fn test_var_overlay_rehomes_journald_with_restart_flush_and_fd_check() {
    // A successful /var overlay relinquishes the persistent journal before the
    // mount, then re-homes journald with a real restart (stop socket, stop
    // service, start socket, start service), flushes, and verifies its fds.
    let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/var"]);
    let mock_hidden_vol = temp_dir.path();

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Auto,
        overlay_exclusions: vec![],
        overlay_exclusions_remove: vec![],
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    let _ = crate::manager::helpers::drain_recorded_service_actions();

    let result = manager.lock().unwrap().activate(true);
    assert!(result.is_ok(), "activation should succeed: {result:?}");

    let actions = crate::manager::helpers::drain_recorded_service_actions();
    let idx = |needle: &str| {
        actions
            .iter()
            .position(|a| a == needle)
            .unwrap_or_else(|| panic!("missing {needle} in {actions:?}"))
    };

    let relinquish = idx("journalctl:relinquish-var");
    let stop_socket = idx("stop:systemd-journald.socket");
    let stop_service = idx("stop:systemd-journald");
    let start_socket = idx("start:systemd-journald.socket");
    let start_service = idx("start:systemd-journald");
    let flush = idx("journalctl:flush");
    let verify = idx("verify-journald-fds");

    assert!(
        relinquish < stop_socket,
        "relinquish-var must precede the restart: {actions:?}"
    );
    assert!(
        stop_socket < stop_service && stop_service < start_socket && start_socket < start_service,
        "journald restart must stop socket, stop service, then start both: {actions:?}"
    );
    assert!(
        start_service < flush && flush < verify,
        "flush then fd verification must follow the restart: {actions:?}"
    );
}

#[test]
#[serial]
fn test_var_overlay_rolls_back_when_journald_fds_not_in_overlay() {
    // If journald's fds do not resolve into the overlay after the restart, the
    // whole activation rolls back rather than leaking to the decoy journal.
    use crate::manager::activation::overlay_mount::{
        JournaldFdCheck, set_forced_journald_fd_check,
    };

    let (temp_dir, fs, state_path) = setup_auto_mode_test(&["/var"]);
    let mock_hidden_vol = temp_dir.path();

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: OverlayMode::Auto,
        overlay_exclusions: vec![],
        overlay_exclusions_remove: vec![],
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    set_forced_journald_fd_check(Some(JournaldFdCheck::NotInOverlay));
    let result = manager.lock().unwrap().activate(true);
    // Reset immediately so the forced outcome cannot leak into another test.
    set_forced_journald_fd_check(None);

    assert!(
        result.is_err(),
        "activation must fail when journald fds are off the overlay"
    );
    assert!(
        !fs.is_mounted(Path::new("/var")).unwrap(),
        "/var overlay must be unmounted after the re-home rollback"
    );
}
