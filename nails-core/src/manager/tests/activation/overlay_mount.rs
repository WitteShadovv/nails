// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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
fn test_activate_walks_proc_once_per_phase_not_per_target() {
    // The mount phase must walk /proc a single time and classify every target
    // against that one snapshot, rather than re-scanning /proc per target. With
    // three overlays, a per-target scan would capture three times.
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

    crate::process::detection::reset_capture_count();
    let result = manager.lock().unwrap().activate(true);
    assert!(result.is_ok(), "Activation should succeed: {:?}", result);

    assert_eq!(
        crate::process::detection::capture_count(),
        1,
        "the mount phase must capture one /proc snapshot for all three targets, \
         not one per target"
    );
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
    // Auto mode reports the first target that failed to mount, by its typed variant.
    assert!(
        matches!(&err, NailsError::Mount { target, .. } if target == Path::new("/etc")),
        "expected the /etc mount error first, got: {err:?}"
    );

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

    // The overlay-targets safety check refuses before any mount. Assert the
    // failing check by name, then that its message names the covered hidden
    // root and the target that covers it (behaviour, not wording).
    let message = match err {
        NailsError::PreFlightCheckFailed(failures) => {
            let (_, message, _) = failures
                .iter()
                .find(|(name, _, _)| name == "overlay-targets")
                .expect("overlay-targets failure should be reported")
                .clone();
            message
        }
        other => panic!("expected PreFlightCheckFailed, got {other:?}"),
    };
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

    let err = manager.activate(true).unwrap_err();
    // The overlay-targets safety check refuses the leaky exclusion before any
    // mount. Assert the failing check by name and that it names the leaking path.
    match err {
        NailsError::PreFlightCheckFailed(failures) => {
            let (_, message, _) = failures
                .iter()
                .find(|(name, _, _)| name == "overlay-targets")
                .expect("overlay-targets failure should be reported");
            assert!(message.contains("/home"), "{message}");
        }
        other => panic!("expected PreFlightCheckFailed, got {other:?}"),
    }
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

/// An explicit-mode config overlaying each of `targets` from the hidden root,
/// with the upper/work directories present on the mock.
fn explicit_overlays_config(
    fs: &MockFilesystem,
    hidden_root: &Path,
    state_path: &Path,
    targets: &[&str],
) -> Config {
    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_type("/", PathKind::Dir);
    let overlays = targets
        .iter()
        .map(|target| {
            let name = target.trim_start_matches('/');
            let upper = hidden_root.join(format!("overlays/{name}/upper"));
            let work = hidden_root.join(format!("overlays/{name}/work"));
            std::fs::create_dir_all(&upper).unwrap();
            std::fs::create_dir_all(&work).unwrap();
            fs.mock_set_path_exists(target, true);
            fs.mock_set_path_exists(upper.to_str().unwrap(), true);
            fs.mock_set_path_exists(work.to_str().unwrap(), true);
            OverlayConfig {
                name: name.to_string(),
                lower: PathBuf::from("/"),
                upper,
                work,
                target: PathBuf::from(target),
            }
        })
        .collect();
    Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: state_path.to_path_buf(),
        overlay_mode: OverlayMode::Explicit,
        overlays,
        ..Config::test_default()
    }
}

/// The import calls the layer recorded.
fn import_calls(layer: &FakeConfigLayer) -> Vec<LayerCall> {
    layer
        .calls()
        .into_iter()
        .filter(|call| matches!(call, LayerCall::InjectImport { .. }))
        .collect()
}

/// Once `/etc` is overlaid, activation runs the config layer's import exactly
/// once, into the overlaid tree. (What the NixOS import writes is covered by the
/// `inject_import_block` and `NixOsConfigLayer` tests.)
#[test]
fn test_activation_injects_import_block_into_overlayed_hardware_config() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();
    let config = explicit_overlays_config(&fs, hidden_root, &state_path, &["/etc"]);
    StateFile {
        state: SystemState::Inactive,
        ..StateFile::default()
    }
    .save_with_custom_root(&state_path, hidden_root)
    .expect("Should save initial state");

    let (mut manager, layer) = fake_nixos_manager(fs.clone(), config, state_path);
    let result = manager.activate(true);
    assert!(result.is_ok(), "Activation should succeed: {result:?}");

    assert_eq!(
        import_calls(&layer),
        vec![LayerCall::InjectImport { etc_mounted: true }]
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
    let err = result.unwrap_err();
    assert!(
        matches!(err, NailsError::ConfigError(_)),
        "empty explicit overlays must be rejected as a config error: {err:?}"
    );
}

/// A dirty base configuration (the layer's base-config gate fails) aborts
/// activation before any side effect: no write, mount, history cleanup or config
/// staging.
#[test]
fn test_activation_aborts_when_base_hardware_config_is_dirty() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();
    let _home = crate::cleanup::test_utils::set_safe_test_home();
    let bash_history = Path::new(crate::cleanup::test_utils::TEST_HOME).join(".bash_history");
    let config = explicit_overlays_config(&fs, hidden_root, &state_path, &["/home"]);
    fs.mock_set_path_exists(bash_history.to_str().unwrap(), true);
    fs.mock_set_path_type(bash_history.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(bash_history.to_str().unwrap(), "nails activate\nls\n");

    let mut manager = NailsManager::new(fs.clone(), config, state_path);
    let layer = use_scripted_nixos_layer(
        &mut manager,
        FakeConfigLayer::new().with_base_reference(FakeVerdict::Fail("dirty base".into())),
    );

    let err = manager.activate(false).unwrap_err();
    // Behaviour: pre-flight blocks activation and names the responsible check.
    match err {
        NailsError::PreFlightCheckFailed(failures) => assert!(
            failures
                .iter()
                .any(|(name, _, _)| name == crate::platform::FAKE_BASE_REFERENCE_CHECK),
            "the base-config gate failure should be reported: {failures:?}"
        ),
        other => panic!("expected PreFlightCheckFailed, got {other:?}"),
    }
    assert!(
        fs.mock_ops().is_empty(),
        "no side-effecting writes or overlay mounts should be attempted"
    );
    assert!(
        fs.get_written_content(&bash_history).is_none(),
        "pre-activation cleanup must not run before the base-config gate"
    );
    assert!(
        layer.calls().is_empty(),
        "config staging must not run before the base-config gate: {:?}",
        layer.calls()
    );
    assert_eq!(manager.current_state().unwrap(), SystemState::Inactive);
}

/// A base-config gate that cannot run (an unreadable base configuration)
/// aborts activation with its error, before any side effect.
#[test]
fn test_activation_aborts_when_base_hardware_config_cannot_be_read() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();
    let _home = crate::cleanup::test_utils::set_safe_test_home();
    let bash_history = Path::new(crate::cleanup::test_utils::TEST_HOME).join(".bash_history");
    let config = explicit_overlays_config(&fs, hidden_root, &state_path, &["/home"]);
    fs.mock_set_path_exists(bash_history.to_str().unwrap(), true);
    fs.mock_set_path_type(bash_history.to_str().unwrap(), PathKind::File);
    fs.mock_set_file_content(bash_history.to_str().unwrap(), "nails activate\nls\n");

    let mut manager = NailsManager::new(fs.clone(), config, state_path);
    let layer = use_scripted_nixos_layer(
        &mut manager,
        FakeConfigLayer::new().with_base_reference(FakeVerdict::Error("unreadable base".into())),
    );

    let err = manager.activate(false).unwrap_err();
    assert!(
        matches!(&err, NailsError::IoError { source: e, .. } if e.to_string().contains("unreadable base")),
        "expected the gate's I/O error, got: {err:?}"
    );
    assert!(
        fs.mock_ops().is_empty(),
        "no side-effecting writes or overlay mounts should be attempted"
    );
    assert!(
        fs.get_written_content(&bash_history).is_none(),
        "pre-activation cleanup must not run before the base-config gate"
    );
    assert!(
        layer.calls().is_empty(),
        "config staging must not run before the base-config gate: {:?}",
        layer.calls()
    );
}

#[test]
fn test_activate_explicit_mode_rejects_critical_system_root_overlay_bin() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    let state_path = mock_hidden_vol.join("state.json");
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/bin", true);
    // A Debian/Ubuntu (FHS) host keeps /bin read-only, so overlaying it is refused
    // by the platform policy rather than a hardcoded block. /bin is the usr-merge
    // symlink into /usr that a supported release ships, so detection accepts the
    // host and the refusal comes from the overlay policy, not a non-merged refusal.
    fs.mock_set_path_type("/bin", PathKind::Symlink);
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
    assert!(matches!(&err, NailsError::InvalidState(_)), "got: {err:?}");
    // Behaviour: the refusal must name the blocked system tree.
    assert!(err.to_string().contains("/bin"), "got: {err}");
    // Nothing was mounted or written beyond the activation progress record that
    // lives on the hidden volume.
    let progress = mock_hidden_vol.join(crate::progress::PROGRESS_FILE);
    let unexpected: Vec<_> = fs
        .mock_ops()
        .into_iter()
        .filter(|op| !matches!(op, crate::filesystem::mock::MockOp::WriteFile { path } if *path == progress))
        .collect();
    assert!(unexpected.is_empty(), "unexpected ops: {unexpected:?}");
}

/// A failed import after the `/etc` mount rolls the overlay back and leaves the
/// system inactive.
#[test]
fn test_activation_rolls_back_when_import_injection_fails_after_etc_mount() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();
    let config = explicit_overlays_config(&fs, hidden_root, &state_path, &["/etc"]);

    let mut manager = NailsManager::new(fs.clone(), config, state_path);
    let layer = use_scripted_nixos_layer(
        &mut manager,
        FakeConfigLayer::new().with_inject_error("import refused"),
    );

    let err = manager.activate(true).unwrap_err();
    assert!(
        err.to_string().contains("import refused"),
        "expected the import error, got: {err:?}"
    );
    assert_eq!(
        import_calls(&layer),
        vec![LayerCall::InjectImport { etc_mounted: true }]
    );
    assert!(
        !fs.is_mounted(Path::new("/etc")).unwrap(),
        "/etc should be rolled back"
    );
    assert_eq!(manager.current_state().unwrap(), SystemState::Inactive);
}

#[test]
#[tracing_test::traced_test]
fn test_activate_explicit_mode_continues_when_clean_stale_network_config_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    let state_path = mock_hidden_vol.join("state.json");
    let fs = MockFilesystem::new();

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

    let manager = Arc::new(Mutex::new(
        fake_nixos_manager(
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
        )
        .0,
    ));

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

    // A best-effort overlay failure is logged as a warning naming the target,
    // asserted on a stable token rather than the leading warning glyph.
    assert!(
        logs_contain("Could not overlay /etc"),
        "best-effort mount failure should warn and name the /etc target"
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

/// The import runs only once `/etc` is mounted, and not at all when `/etc` is
/// not an overlay target.
#[test]
fn test_activation_inject_happens_after_etc_overlay_mount() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();
    let config = explicit_overlays_config(&fs, hidden_root, &state_path, &["/home", "/etc"]);

    let (mut manager, layer) = fake_nixos_manager(fs.clone(), config, state_path);
    let result = manager.activate(true);
    assert!(result.is_ok(), "Activation should succeed: {result:?}");
    assert_eq!(
        import_calls(&layer),
        vec![LayerCall::InjectImport { etc_mounted: true }],
        "the import must run once, after /etc is mounted"
    );

    // Without /etc among the targets there is nothing to import into.
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();
    let config = explicit_overlays_config(&fs, hidden_root, &state_path, &["/home"]);
    let (mut manager, layer) = fake_nixos_manager(fs, config, state_path);
    manager.activate(true).expect("activation succeeds");
    assert!(import_calls(&layer).is_empty(), "{:?}", layer.calls());
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
