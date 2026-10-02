//! The config fingerprint and the NixOS build fast path.

use super::*;

// ========== Fingerprint persistence ==========

#[test]
fn test_config_fingerprint_field_persistence() {
    // HIGH-2: Validate that config_fingerprint field is properly persisted to state file
    // This test focuses on the state persistence mechanism, which is the integration gap
    // between the manager and the state file. The fingerprint computation itself is
    // well-tested in nixos.rs unit tests.
    use std::sync::Arc;

    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();

    let state_path = mock_hidden_vol.join("state.json");
    let fs = MockFilesystem::new();

    // Setup mock filesystem paths
    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);

    // Create initial state file (INACTIVE, no fingerprint)
    // Write to actual filesystem so manager can load it
    let initial_state = StateFile {
        version: env!("CARGO_PKG_VERSION").to_string(),
        state: SystemState::Inactive,
        nixos_generation: None,
        config_fingerprint: None, // First activation - no fingerprint yet
        overlay_status: HashMap::new(),
        failed_overlays: Vec::new(),
        last_modified: Utc::now(),
        boot_id: None,
        owner_pid: 0,
        integrity_sha256: None,
    };
    let state_json = serde_json::to_string_pretty(&initial_state).unwrap();
    std::fs::write(&state_path, state_json).unwrap();

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    // === TEST 1: Verify fingerprint field loads correctly (None initially) ===
    // Call current_state() to trigger lazy load from disk
    {
        let mgr = manager.lock().unwrap();
        mgr.current_state().expect("State should load successfully");
    }

    {
        let mgr = manager.lock().unwrap();
        let state = mgr.cached_state.borrow();
        assert!(
            state.is_some(),
            "State should be loaded after calling current_state()"
        );
        assert_eq!(
            state.as_ref().unwrap().config_fingerprint,
            None,
            "Initial state should have no fingerprint"
        );
    }

    // === TEST 2: Simulate fingerprint being saved (as happens in activation step 7+9) ===
    let test_fingerprint = "abcd1234efgh5678".to_string();
    {
        let mgr = manager.lock().unwrap();
        let mut cached = mgr.cached_state.borrow_mut();
        if let Some(ref mut state) = *cached {
            state.config_fingerprint = Some(test_fingerprint.clone());
            state.nixos_generation = Some("test-gen-123".to_string());
        }
    }

    // Save state to disk (this is what manager does after successful activation)
    {
        let mgr = manager.lock().unwrap();
        mgr.save_cached_state().expect("State save should succeed");
    }

    // === TEST 3: Verify fingerprint was persisted to actual file ===
    let saved_content =
        std::fs::read_to_string(&state_path).expect("State file should exist on disk");
    let restored_state: StateFile =
        serde_json::from_str(&saved_content).expect("Saved state should deserialize correctly");

    assert_eq!(
        restored_state.config_fingerprint,
        Some(test_fingerprint.clone()),
        "Fingerprint should be persisted to disk (AC4 requirement)"
    );

    // === TEST 4: Verify persisted fingerprint can be loaded back ===
    // Deserialize directly from disk to verify persistence
    let disk_content =
        std::fs::read_to_string(&state_path).expect("State file should exist on disk after save");
    let loaded_state: StateFile =
        serde_json::from_str(&disk_content).expect("State file should be valid JSON");

    assert_eq!(
        loaded_state.config_fingerprint,
        Some(test_fingerprint),
        "Fingerprint should be loaded correctly from disk (AC2 fast path prerequisite)"
    );

    // Test passes: config_fingerprint field is properly saved to disk and loaded back,
    // validating the state persistence integration for Story 15.4
}

#[test]
#[tracing_test::traced_test]
fn test_nixos_build_logs_fast_path_when_fingerprint_matches_and_generation_exists() {
    use crate::NixOSBuilder;
    use crate::nixos::compute_config_fingerprint;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();
    setup_nixos_config_check(&fs, hidden_root);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_mount_should_fail("/home", true);

    let hw_content = fs
        .read_file_content(&hidden_root.join("etc/nixos/hardware-configuration.nix"))
        .unwrap();
    // The wrapper's real hardware content lives in the base file; both feed the
    // fingerprint exactly as the manager combines them.
    let base_content = fs
        .read_file_content(&hidden_root.join("etc/nixos/hardware-configuration.base.nix"))
        .unwrap_or_default();
    let cfg_content = fs
        .read_file_content(&hidden_root.join("config/nixos/configuration.nix"))
        .unwrap();
    let fingerprint =
        compute_config_fingerprint(&format!("{hw_content}\n{base_content}"), &cfg_content);

    let upper_home = hidden_root.join("overlays/home/upper");
    let work_home = hidden_root.join("overlays/home/work");
    std::fs::create_dir_all(&upper_home).unwrap();
    std::fs::create_dir_all(&work_home).unwrap();
    fs.mock_set_path_exists(upper_home.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);
    fs.mock_set_path_exists("/", true);

    let builder = NixOSBuilder::new(
        hidden_root.join("config/nixos"),
        hidden_root.join("profiles/nails-system"),
    );
    let mut manager = NailsManager::with_nixos(
        fs.clone(),
        Config {
            hidden_volume_root: hidden_root.to_path_buf(),
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
        builder,
    );
    manager.set_verbosity(Verbosity::Normal);
    {
        let mut cached = manager.cached_state.borrow_mut();
        *cached = Some(StateFile {
            state: SystemState::Inactive,
            config_fingerprint: Some(fingerprint),
            nixos_generation: Some("123".to_string()),
            ..StateFile::default()
        });
    }

    let result = Arc::new(Mutex::new(manager)).lock().unwrap().activate(true);
    assert!(result.is_err());
    assert!(logs_contain("Computing NixOS config fingerprint"));
    assert!(logs_contain("Fast-path check"));
    assert!(logs_contain("Fast path: fingerprint matches"));
}

#[test]
#[tracing_test::traced_test]
fn test_nixos_build_does_not_take_fast_path_when_generation_missing() {
    use crate::NixOSBuilder;
    use crate::nixos::compute_config_fingerprint;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();
    setup_nixos_config_check(&fs, hidden_root);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_mount_should_fail("/home", true);
    fs.mock_set_path_exists("/", true);

    let hw_content = fs
        .read_file_content(&hidden_root.join("etc/nixos/hardware-configuration.nix"))
        .unwrap();
    // The wrapper's real hardware content lives in the base file; both feed the
    // fingerprint exactly as the manager combines them.
    let base_content = fs
        .read_file_content(&hidden_root.join("etc/nixos/hardware-configuration.base.nix"))
        .unwrap_or_default();
    let cfg_content = fs
        .read_file_content(&hidden_root.join("config/nixos/configuration.nix"))
        .unwrap();
    let fingerprint =
        compute_config_fingerprint(&format!("{hw_content}\n{base_content}"), &cfg_content);

    let upper_home = hidden_root.join("overlays/home/upper");
    let work_home = hidden_root.join("overlays/home/work");
    std::fs::create_dir_all(&upper_home).unwrap();
    std::fs::create_dir_all(&work_home).unwrap();
    fs.mock_set_path_exists(upper_home.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);

    let builder = NixOSBuilder::new(
        hidden_root.join("config/nixos"),
        hidden_root.join("profiles/nails-system"),
    );
    let mut manager = NailsManager::with_nixos(
        fs.clone(),
        Config {
            hidden_volume_root: hidden_root.to_path_buf(),
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
        builder,
    );
    manager.set_verbosity(Verbosity::Normal);
    {
        let mut cached = manager.cached_state.borrow_mut();
        *cached = Some(StateFile {
            state: SystemState::Inactive,
            config_fingerprint: Some(fingerprint),
            nixos_generation: None,
            ..StateFile::default()
        });
    }

    let result = Arc::new(Mutex::new(manager)).lock().unwrap().activate(true);
    assert!(result.is_err());
    assert!(logs_contain("Fast-path check"));
    assert!(!logs_contain("Fast path: fingerprint matches"));
}

#[test]
#[tracing_test::traced_test]
fn test_nixos_build_uses_empty_content_when_both_reads_fail() {
    use crate::NixOSBuilder;
    use crate::nixos::compute_config_fingerprint;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", PathKind::File);
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ }",
    );
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_mount_should_fail("/home", true);
    fs.mock_set_path_exists("/", true);

    // All three hidden config reads fail, so the wrapper and base contents are
    // both empty and the manager fingerprints the "{empty}\n{empty}" material.
    let fingerprint = compute_config_fingerprint("\n", "");
    let upper_home = hidden_root.join("overlays/home/upper");
    let work_home = hidden_root.join("overlays/home/work");
    std::fs::create_dir_all(&upper_home).unwrap();
    std::fs::create_dir_all(&work_home).unwrap();
    fs.mock_set_path_exists(upper_home.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);

    let builder = NixOSBuilder::new(
        hidden_root.join("config/nixos"),
        hidden_root.join("profiles/nails-system"),
    );
    let mut manager = NailsManager::with_nixos(
        fs.clone(),
        Config {
            hidden_volume_root: hidden_root.to_path_buf(),
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
        builder,
    );
    manager.set_verbosity(Verbosity::Normal);
    {
        let mut cached = manager.cached_state.borrow_mut();
        *cached = Some(StateFile {
            state: SystemState::Inactive,
            config_fingerprint: Some(fingerprint),
            nixos_generation: Some("123".to_string()),
            ..StateFile::default()
        });
    }

    let result = Arc::new(Mutex::new(manager)).lock().unwrap().activate(true);
    assert!(result.is_err());
    assert!(logs_contain(
        "Failed to read hardware-configuration.nix for fingerprint"
    ));
    assert!(logs_contain(
        "Failed to read configuration.nix for fingerprint"
    ));
    assert!(logs_contain("Fast path: fingerprint matches"));
}
