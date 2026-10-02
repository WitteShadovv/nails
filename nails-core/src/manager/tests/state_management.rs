//! `current_state`, `update_state`, `verify_overlay_status` and reset-upper.

use super::*;

// ========== current_state() ==========

#[test]
fn test_current_state_lazy_loads_on_first_access() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let state_path = temp_dir.path().join("state.json");

    let fs = MockFilesystem::new();
    let config = Config::default();
    let manager = NailsManager::new(fs, config, state_path);

    // Verify state not loaded yet
    {
        let cached = manager.cached_state.borrow();
        assert!(cached.is_none());
    }

    // First call should load state
    let state = manager.current_state().expect("Should return state");

    // Verify state is now cached
    {
        let cached = manager.cached_state.borrow();
        assert!(cached.is_some());
    }

    // Should be Inactive (default for missing file)
    assert_eq!(state, SystemState::Inactive);
}

#[test]
fn test_current_state_uses_cache_on_subsequent_calls() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let state_path = temp_dir.path().join("state.json");

    let fs = MockFilesystem::new();
    let config = Config::default();
    let manager = NailsManager::new(fs, config, state_path.clone());

    // First call loads and caches
    let state1 = manager.current_state().expect("Should return state");

    // Modify file on disk (to verify cache is used, not re-read)
    let different_state = StateFile {
        state: SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![],
        },
        ..StateFile::default()
    };
    let json = serde_json::to_string_pretty(&different_state).unwrap();
    std::fs::write(&state_path, json).unwrap();

    // Second call should use cache (not re-read file)
    let state2 = manager.current_state().expect("Should return state");

    // Both should be Inactive (from cache, not re-reading modified file)
    assert_eq!(state1, state2);
    assert_eq!(state2, SystemState::Inactive);
}

#[test]
fn test_current_state_missing_file_returns_inactive() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let nonexistent_path = temp_dir.path().join("nonexistent.json");

    let fs = MockFilesystem::new();
    let config = Config::default();
    let manager = NailsManager::new(fs, config, nonexistent_path);

    // Should return Inactive (safe default)
    let state = manager.current_state().expect("Should return state");
    assert_eq!(state, SystemState::Inactive);
}

#[test]
fn test_current_state_malformed_file_returns_inactive() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let malformed_path = temp_dir.path().join("malformed.json");

    // Write invalid JSON
    std::fs::write(&malformed_path, "{ invalid json syntax").unwrap();

    let fs = MockFilesystem::new();
    let config = Config::default();
    let manager = NailsManager::new(fs, config, malformed_path);

    // Should return Inactive (safe default)
    let state = manager.current_state().expect("Should return state");
    assert_eq!(state, SystemState::Inactive);
}

// ========== update_state() ==========

#[test]
fn test_update_state_valid_transition_succeeds() {
    // Use /tmp for testing (bypass hidden volume check for unit tests)
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
    let mut manager = NailsManager::new(fs, config, state_path.clone());

    // Manually create initial state file in temp (simulating hidden volume)
    let initial_state = StateFile::default();
    let json = serde_json::to_string_pretty(&initial_state).unwrap();
    std::fs::write(&state_path, json).unwrap();

    // Valid transition: Inactive -> Activating
    let result = manager.update_state(SystemState::Activating {
        started_at: Utc::now(),
    });
    assert!(result.is_ok());

    // Verify state was updated
    let state = manager.current_state().unwrap();
    assert!(matches!(state, SystemState::Activating { .. }));
}

#[test]
fn test_update_state_invalid_transition_returns_error() {
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
    let mut manager = NailsManager::new(fs, config, state_path.clone());

    // Manually create initial state file
    let initial_state = StateFile::default();
    let json = serde_json::to_string_pretty(&initial_state).unwrap();
    std::fs::write(&state_path, json).unwrap();

    // Invalid transition: Inactive -> Active (must go through Activating)
    let result = manager.update_state(SystemState::Active {
        activated_at: Utc::now(),
        overlays: vec![],
    });
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), NailsError::InvalidState(_)));
}

#[test]
fn test_update_state_saves_to_disk() {
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
    let mut manager = NailsManager::new(fs, config, state_path.clone());

    // Manually create initial state file
    let initial_state = StateFile::default();
    let json = serde_json::to_string_pretty(&initial_state).unwrap();
    std::fs::write(&state_path, json).unwrap();

    // Update state
    manager
        .update_state(SystemState::Activating {
            started_at: Utc::now(),
        })
        .unwrap();

    // Verify file was written (by loading directly)
    let loaded = StateFile::load(&state_path).unwrap();
    assert!(matches!(loaded.state, SystemState::Activating { .. }));
}

#[test]
fn test_update_state_updates_cache() {
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
    let mut manager = NailsManager::new(fs, config, state_path.clone());

    // Manually create initial state file
    let initial_state = StateFile::default();
    let json = serde_json::to_string_pretty(&initial_state).unwrap();
    std::fs::write(&state_path, json).unwrap();

    // Update state
    manager
        .update_state(SystemState::Activating {
            started_at: Utc::now(),
        })
        .unwrap();

    // Verify cache was updated
    let state = manager.current_state().unwrap();
    assert!(matches!(state, SystemState::Activating { .. }));
}

// ========== verify_overlay_status() ==========

#[test]
fn test_verify_overlay_status_active_with_mounted_overlays_ok() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let state_path = temp_dir.path().join("state.json");

    let fs = MockFilesystem::new();

    // Set up mounted overlay
    fs.mock_set_mounted(Path::new("/home"), true);

    let config = Config::default();
    let manager = NailsManager::new(fs, config, state_path.clone());

    // Create Active state file with mounted overlay
    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/home"),
            upper_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
            work_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
            mounted_at: Utc::now(),
        },
    );

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
        },
        overlay_status,
        ..StateFile::default()
    };

    // Save manually
    state_file
        .save_with_custom_root(&state_path, temp_dir.path())
        .unwrap();

    // Verify should succeed
    let result = manager.verify_overlay_status();
    assert!(result.is_ok());
}

#[test]
fn test_verify_overlay_status_active_with_missing_overlay_error() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let state_path = temp_dir.path().join("state.json");

    let fs = MockFilesystem::new();
    // Overlay is NOT mounted

    let config = Config::default();
    let manager = NailsManager::new(fs, config, state_path.clone());

    // Create Active state file claiming overlay is mounted
    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/home"),
            upper_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
            work_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
            mounted_at: Utc::now(),
        },
    );

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
        },
        overlay_status,
        ..StateFile::default()
    };

    // Save manually
    state_file
        .save_with_custom_root(&state_path, temp_dir.path())
        .unwrap();

    // Verify should fail (state claims mounted but it's not)
    let result = manager.verify_overlay_status();
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), NailsError::InvalidState(_)));
}

#[test]
fn test_verify_overlay_status_inactive_with_mounted_overlay_error() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let state_path = temp_dir.path().join("state.json");

    let fs = MockFilesystem::new();

    // Set up overlay as actually mounted
    fs.mock_set_mounted(Path::new("/home"), true);

    let config = Config::default();
    let manager = NailsManager::new(fs, config, state_path.clone());

    // Create Inactive state file but with overlay still tracked
    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/home"),
            upper_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
            work_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
            mounted_at: Utc::now(),
        },
    );

    let state_file = StateFile {
        state: SystemState::Inactive,
        overlay_status,
        ..StateFile::default()
    };

    // Save manually
    state_file
        .save_with_custom_root(&state_path, temp_dir.path())
        .unwrap();

    // Verify should fail (state claims Inactive but overlay is mounted)
    let result = manager.verify_overlay_status();
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), NailsError::InvalidState(_)));
}

#[test]
fn test_verify_overlay_status_transitional_state_skipped() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let state_path = temp_dir.path().join("state.json");

    let fs = MockFilesystem::new();

    // Set up overlay as NOT mounted (potential mismatch if we were strict)
    fs.mock_set_mounted(Path::new("/home"), false);

    let config = Config::default();
    let manager = NailsManager::new(fs, config, state_path.clone());

    // Create Activating state (transitional) - verification should skip
    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/home"),
            upper_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/upper"),
            work_dir: PathBuf::from("/mnt/hidden-volume/overlays/home/work"),
            mounted_at: Utc::now(),
        },
    );

    let state_file = StateFile {
        state: SystemState::Activating {
            started_at: Utc::now(),
        },
        overlay_status,
        ..StateFile::default()
    };

    // Save manually
    state_file
        .save_with_custom_root(&state_path, temp_dir.path())
        .unwrap();

    // Verify should succeed (transitional states are skipped - line 751)
    let result = manager.verify_overlay_status();
    assert!(
        result.is_ok(),
        "Transitional state verification should succeed (skip check)"
    );
}

// ========== reset-upper ==========

/// Build a manager over a MockFilesystem with a real temp hidden root and the
/// given state. Returns the temp dir (kept alive), the hidden root path, a
/// clone of the mock (shared state, for seeding), and the manager.
fn reset_upper_setup(
    state: SystemState,
) -> (
    tempfile::TempDir,
    PathBuf,
    MockFilesystem,
    NailsManager<MockFilesystem>,
) {
    let dir = tempfile::tempdir().expect("temp dir");
    let hidden_root = dir.path().join("hidden");
    std::fs::create_dir_all(&hidden_root).expect("create hidden root");
    let state_path = hidden_root.join("state.json");

    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let fs = MockFilesystem::new();
    let mut manager = NailsManager::new(fs.clone(), config, state_path);
    manager.force_state(state).expect("force state");
    (dir, hidden_root, fs, manager)
}

#[test]
fn test_reset_upper_refuses_when_active() {
    let (_dir, _hidden_root, _fs, manager) = reset_upper_setup(SystemState::Active {
        activated_at: Utc::now(),
        overlays: vec![PathBuf::from("/home")],
    });

    let err = manager
        .plan_reset_upper(Path::new("/home"))
        .expect_err("reset-upper must refuse while Active");
    assert!(matches!(err, NailsError::InvalidState(_)), "got {err:?}");
}

#[test]
fn test_reset_upper_refuses_when_target_mounted() {
    let (_dir, _hidden_root, fs, manager) = reset_upper_setup(SystemState::Inactive);
    fs.mock_set_mounted(Path::new("/home"), true);

    let err = manager
        .plan_reset_upper(Path::new("/home"))
        .expect_err("reset-upper must refuse a mounted target");
    assert!(matches!(err, NailsError::InvalidState(_)), "got {err:?}");
}

#[test]
fn test_reset_upper_plan_alone_removes_nothing() {
    let (_dir, hidden_root, fs, manager) = reset_upper_setup(SystemState::Inactive);
    let upper = hidden_root.join("home");
    let work = hidden_root.join(".work").join("home");
    fs.mock_set_path_exists(upper.to_str().unwrap(), true);
    fs.mock_set_path_exists(work.to_str().unwrap(), true);

    // Planning (the step before a declined prompt) must not delete anything.
    let plan = manager.plan_reset_upper(Path::new("/home")).expect("plan");
    assert!(plan.upper_exists && plan.work_exists);
    assert!(fs.path_exists(&upper).unwrap());
    assert!(fs.path_exists(&work).unwrap());
}

#[test]
fn test_reset_upper_removes_upper_and_work() {
    let (_dir, hidden_root, fs, manager) = reset_upper_setup(SystemState::Inactive);
    let upper = hidden_root.join("home");
    let work = hidden_root.join(".work").join("home");
    fs.mock_set_path_exists(upper.to_str().unwrap(), true);
    fs.mock_set_path_exists(work.to_str().unwrap(), true);

    let plan = manager.plan_reset_upper(Path::new("/home")).expect("plan");
    assert_eq!(plan.upper, upper);
    assert_eq!(plan.work, work);
    assert_eq!(plan.removals(), vec![upper.as_path(), work.as_path()]);
    assert!(!plan.resets_nix_store);

    manager.apply_reset_upper(&plan).expect("apply");
    assert!(!fs.path_exists(&upper).unwrap(), "upper should be removed");
    assert!(!fs.path_exists(&work).unwrap(), "work should be removed");
}

#[test]
fn test_reset_upper_skips_absent_directories() {
    let (_dir, hidden_root, fs, manager) = reset_upper_setup(SystemState::Inactive);
    let upper = hidden_root.join("srv");

    // Neither upper nor work exists: the plan is empty and apply is a no-op.
    let plan = manager.plan_reset_upper(Path::new("/srv")).expect("plan");
    assert!(plan.is_empty());
    assert!(plan.removals().is_empty());
    manager.apply_reset_upper(&plan).expect("apply");
    assert!(!fs.path_exists(&upper).unwrap());
}

#[test]
fn test_reset_upper_flags_nix_store() {
    let (_dir, _hidden_root, _fs, manager) = reset_upper_setup(SystemState::Inactive);
    let plan = manager.plan_reset_upper(Path::new("/nix")).expect("plan");
    assert!(
        plan.resets_nix_store,
        "resetting /nix must flag the Nix store warning"
    );
}
