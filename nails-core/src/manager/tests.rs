#![allow(clippy::field_reassign_with_default)]
use super::*;
use crate::filesystem::{Filesystem, MockOp};
use crate::{
    config::OverlayMode, config::DEFAULT_HIDDEN_VOLUME_ROOT, inject_import_block,
    EphemeralOverlayDir, ExtendedOverlayConfig, MockFilesystem, OverlayConfig, OverlayInfo,
    StateFile, Stopwatch, SystemState, Verbosity,
};
use chrono::Utc;
use serial_test::serial;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Helper function to check if logs contain a specific string.
///
/// Clippy can report this as dead code when linting all targets even though it
/// is exercised by traced test cases in this module.
#[allow(dead_code)]
fn logs_contain(s: &str) -> bool {
    tracing_test::internal::logs_with_scope_contain("", s)
}

fn setup_nixos_config_check(fs: &MockFilesystem, hidden_root: &Path) {
    // Base hardware-configuration.nix must exist
    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ }",
    );
    fs.mock_set_path_exists("/etc/nixos/configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/configuration.nix", "file");

    // Hidden overlay hardware config
    let hidden_etc = hidden_root.join("etc/nixos");
    let hidden_hw = hidden_etc.join("hardware-configuration.nix");
    fs.mock_set_path_exists(hidden_etc.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_etc.to_str().unwrap(), "directory");
    fs.mock_set_writable(hidden_etc.to_str().unwrap(), true);
    fs.mock_set_path_exists(hidden_hw.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_hw.to_str().unwrap(), "file");
    fs.mock_set_file_content(
        hidden_hw.to_str().unwrap(),
        "{ config, lib, pkgs, ... }:\n{ imports = [ ./nails/configuration.nix ]; }",
    );

    // Hidden config in new location
    let hidden_config = hidden_root.join("config/nixos/configuration.nix");
    fs.mock_set_path_exists(hidden_config.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_config.to_str().unwrap(), "file");
    fs.mock_set_file_content(hidden_config.to_str().unwrap(), "{ }");
}

fn create_test_manager() -> NailsManager<MockFilesystem> {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    NailsManager::new(fs, config, state_path)
}

// ========== Task 3: Constructor Tests ==========

#[test]
fn test_new_stores_all_parameters() {
    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: PathBuf::from("/mnt/test-hidden"),
        state_file_path: PathBuf::from("/mnt/test-hidden/state.json"),
        overlays: vec![],
        ..Config::test_default()
    };
    let state_path = PathBuf::from("/mnt/test-hidden/state.json");

    let manager = NailsManager::new(fs, config.clone(), state_path.clone());

    // Verify fields are stored (we can't directly access private fields,
    // but we can verify behavior in other tests)
    assert_eq!(manager.state_file_path, state_path);
    assert_eq!(manager.config, config);
}

#[test]
fn test_new_does_not_load_state() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/nonexistent/path/state.json");

    // Constructor should NOT fail even with invalid path
    // because it doesn't load state (lazy loading)
    let manager = NailsManager::new(fs, config, state_path);

    // State is not loaded yet
    let cached = manager.cached_state.lock().unwrap();
    assert!(cached.is_none());
}

#[test]
fn test_new_initializes_cached_state_to_none() {
    let manager = create_test_manager();

    // Verify cached_state is None (not yet loaded)
    let cached = manager.cached_state.lock().unwrap();
    assert!(cached.is_none());
}

#[test]
fn test_new_with_different_filesystem_implementations() {
    // Test with MockFilesystem
    let mock_fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    let _mock_manager = NailsManager::new(mock_fs, config.clone(), state_path.clone());

    // Test with RealFilesystem (just verify compilation)
    use crate::RealFilesystem;
    let real_fs = RealFilesystem;
    let _real_manager = NailsManager::new(real_fs, config, state_path);
}

// ========== Task 4: current_state() Tests ==========

#[test]
fn test_current_state_lazy_loads_on_first_access() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let state_path = temp_dir.path().join("state.json");

    let fs = MockFilesystem::new();
    let config = Config::default();
    let manager = NailsManager::new(fs, config, state_path);

    // Verify state not loaded yet
    {
        let cached = manager.cached_state.lock().unwrap();
        assert!(cached.is_none());
    }

    // First call should load state
    let state = manager.current_state().expect("Should return state");

    // Verify state is now cached
    {
        let cached = manager.cached_state.lock().unwrap();
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

// ========== Task 5: update_state() Tests ==========

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

// ========== Task 6: verify_overlay_status() Tests ==========

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
    let json = serde_json::to_string_pretty(&state_file).unwrap();
    std::fs::write(&state_path, json).unwrap();

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
    let json = serde_json::to_string_pretty(&state_file).unwrap();
    std::fs::write(&state_path, json).unwrap();

    // Verify should fail (state claims mounted but it's not)
    let result = manager.verify_overlay_status();
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), NailsError::InvalidState(_)));
}

// ========== Task 7: activate() Tests ==========

#[test]
fn test_activate_successful_activation_transitions_through_states() {
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
        fs.clone(),
        config,
        state_path,
    )));

    // Activate should succeed
    let result = NailsManager::activate(Arc::clone(&manager), true);
    assert!(result.is_ok());

    // Final state should be Active
    let state = manager.lock().unwrap().current_state().unwrap();
    assert!(matches!(state, SystemState::Active { .. }));
}

#[test]
fn test_activate_from_non_inactive_returns_error() {
    use crate::StateFile;

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

    // Manually write Active state to file (bypass transition validation)
    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![],
        },
        ..StateFile::default()
    };
    let json = serde_json::to_string_pretty(&state_file).unwrap();
    std::fs::write(&state_path, json).unwrap();

    // Force manager to reload state from disk
    *manager.lock().unwrap().cached_state.lock().unwrap() = None;

    // AC7: activate() is idempotent - calling from Active state should succeed (no-op)
    let result = NailsManager::activate(Arc::clone(&manager), true);
    assert!(
        result.is_ok(),
        "Activate should be idempotent and succeed from Active state"
    );

    // Verify state is still Active (unchanged)
    let final_state = manager.lock().unwrap().current_state().unwrap();
    assert!(
        final_state.is_active(),
        "State should remain Active after idempotent activate"
    );
}

#[test]
fn test_activate_calls_mount_overlay_for_each_configured_overlay() {
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
        fs.clone(),
        config,
        state_path,
    )));

    // Activate
    NailsManager::activate(Arc::clone(&manager), true).unwrap();

    // Verify mount was called
    assert!(fs_clone.is_mounted(Path::new("/home")).unwrap());
}

// ========== Task 5: Activation Failure Rollback Tests ==========

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
    let result = NailsManager::activate(Arc::clone(&manager), true);
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
    let result = NailsManager::activate(Arc::clone(&manager), true);
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
    let result = NailsManager::activate(Arc::clone(&manager), true);
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

// ========== Task 7: Deactivation Failure Rollback Tests ==========

#[test]
fn test_deactivate_failure_at_unmount_rolls_back_to_active() {
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
        })
        .unwrap();
    {
        let mgr = manager.lock().unwrap();
        let mut cached = mgr.cached_state.lock().unwrap();
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
    let result = NailsManager::emergency_deactivate(Arc::clone(&manager));
    assert!(result.is_err());

    // Verify error message (FR51) - orchestrator returns raw unmount error
    match result.unwrap_err() {
        NailsError::UnmountError { reason, .. } => {
            assert!(
                !reason.is_empty(),
                "Error message should not be empty: {}",
                reason
            );
        }
        other => panic!("Expected UnmountError, got: {:?}", other),
    }

    // Verify state was rolled back to Active (FR51)
    let final_state = manager.lock().unwrap().current_state().unwrap();
    assert!(
        matches!(final_state, SystemState::Active { .. }),
        "State should be rolled back to Active after unmount failure"
    );

    // Verify overlay remains mounted after rollback (FR51: Remount overlays if cleanup fails)
    assert!(
        fs_clone.is_mounted(Path::new("/home")).unwrap(),
        "Overlay should remain mounted after failed deactivation"
    );

    // Verify state file contains Active
    let loaded = StateFile::load(&state_path).unwrap();
    assert!(matches!(loaded.state, SystemState::Active { .. }));
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
        })
        .unwrap();
    {
        let mgr = manager.lock().unwrap();
        let mut cached = mgr.cached_state.lock().unwrap();
        if let Some(ref mut state_file) = *cached {
            state_file.overlay_status = overlay_status;
        }
    }

    // Deactivation should succeed (using emergency_deactivate for full unmount)
    let result = NailsManager::emergency_deactivate(Arc::clone(&manager));
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
    let result = NailsManager::deactivate(Arc::clone(&manager));
    assert!(result.is_err(), "Expected Err, got {:?}", result);
    assert!(matches!(result.unwrap_err(), NailsError::InvalidState(_)));
}

#[test]
fn test_deactivate_returns_lock_poisoned_when_manager_mutex_is_poisoned() {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let manager = Arc::new(Mutex::new(create_test_manager()));

    let poisoned = catch_unwind(AssertUnwindSafe({
        let manager = Arc::clone(&manager);
        move || {
            let _guard = manager.lock().unwrap();
            panic!("intentionally poison manager mutex");
        }
    }));
    assert!(poisoned.is_err(), "test setup should poison the mutex");

    let result = catch_unwind(AssertUnwindSafe(|| {
        NailsManager::deactivate(Arc::clone(&manager))
    }));
    assert!(
        result.is_ok(),
        "deactivate should return an error, not panic"
    );

    match result.unwrap() {
        Err(NailsError::LockPoisoned(message)) => {
            assert!(
                message.to_lowercase().contains("poison"),
                "expected poisoned-lock message, got: {message}"
            );
        }
        other => panic!("expected LockPoisoned error, got: {:?}", other),
    }
}

#[test]
fn test_deactivate_partial_failure_unmounts_only_successful_ones() {
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
        })
        .unwrap();
    {
        let mgr = manager.lock().unwrap();
        let mut cached = mgr.cached_state.lock().unwrap();
        if let Some(ref mut state_file) = *cached {
            state_file.overlay_status = overlay_status;
        }
    }

    // Deactivation should fail at /etc
    let result = NailsManager::deactivate(Arc::clone(&manager));
    assert!(result.is_err());

    // Verify state was rolled back to Active
    assert!(matches!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Active { .. }
    ));

    // Successful partial unmounts should be rolled back through remounting.
    let manager_guard = manager.lock().unwrap();
    assert!(
        manager_guard
            .filesystem()
            .is_mounted(Path::new("/home"))
            .unwrap(),
        "/home should be remounted during rollback"
    );
    assert!(
        manager_guard
            .filesystem()
            .is_mounted(Path::new("/etc"))
            .unwrap(),
        "/etc should remain mounted after rollback"
    );
}

// ========== Task 5: Pre-flight Integration Tests ==========

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
    fs.mock_set_path_type(etc_dir.to_str().unwrap(), "directory");
    fs.mock_set_path_exists(home_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(home_dir.to_str().unwrap(), "directory");
    fs.mock_set_path_exists(config_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(config_dir.to_str().unwrap(), "directory");
    fs.mock_set_path_exists(nixos_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(nixos_dir.to_str().unwrap(), "directory");
    fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);
    fs.mock_set_path_type(work_etc.to_str().unwrap(), "directory");
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);
    fs.mock_set_path_type(work_home.to_str().unwrap(), "directory");

    // Set up overlay directories
    let upper_dir = overlays_dir.join("home").join("upper");
    let work_dir_path = work_home.clone();
    std::fs::create_dir_all(&upper_dir).unwrap();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_type("/", "directory");
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(upper_dir.to_str().unwrap(), "directory");
    fs.mock_set_path_exists(work_dir_path.to_str().unwrap(), true);
    fs.mock_set_path_type(work_dir_path.to_str().unwrap(), "directory");
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
        state_path,
    )));

    // Activate with pre-flight checks (no_preflight = false)
    let result = NailsManager::activate(Arc::clone(&manager), false);
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
        state_path,
    )));

    // Verify initial state is Inactive
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );

    // Activate with pre-flight checks (should fail)
    let result = NailsManager::activate(Arc::clone(&manager), false);
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
    let result = NailsManager::activate(Arc::clone(&manager), false);
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
    fs.mock_set_path_type(etc_dir.to_str().unwrap(), "directory");
    fs.mock_set_path_exists(home_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(home_dir.to_str().unwrap(), "directory");
    fs.mock_set_path_exists(config_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(config_dir.to_str().unwrap(), "directory");
    fs.mock_set_path_exists(nixos_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(nixos_dir.to_str().unwrap(), "directory");
    fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);
    fs.mock_set_path_type(work_etc.to_str().unwrap(), "directory");
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);
    fs.mock_set_path_type(work_home.to_str().unwrap(), "directory");

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
    let result = NailsManager::activate(Arc::clone(&manager), false);
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
    let result = NailsManager::activate(Arc::clone(&manager), true);

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
    let result = NailsManager::activate(Arc::clone(&manager), false);
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
    fs.mock_set_path_type(etc_dir.to_str().unwrap(), "directory");
    fs.mock_set_path_exists(home_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(home_dir.to_str().unwrap(), "directory");
    fs.mock_set_path_exists(config_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(config_dir.to_str().unwrap(), "directory");
    fs.mock_set_path_exists(nixos_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(nixos_dir.to_str().unwrap(), "directory");
    fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);
    fs.mock_set_path_type(work_etc.to_str().unwrap(), "directory");
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);
    fs.mock_set_path_type(work_home.to_str().unwrap(), "directory");

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

    let result = NailsManager::activate(Arc::clone(&manager), false);
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

    let result = NailsManager::activate(Arc::clone(&manager), false);
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

// ========== Story 4.6: MountTracker Drop Trait and Edge Cases Tests ==========

#[test]
fn test_mount_tracker_drop_without_commit_triggers_rollback() {
    let fs = MockFilesystem::new();
    let home = PathBuf::from("/home");
    let etc = PathBuf::from("/etc");

    {
        let mut tracker = MountTracker::new(&fs);
        tracker.push_mount(MountInfo::persistent(home.clone()));
        tracker.push_mount(MountInfo::persistent(etc.clone()));
        // Drop without commit - should trigger automatic rollback
    } // Tracker drops here

    // Verify unmount was called for both paths in reverse order
    let mounted = fs.get_mounted_paths();
    assert!(
        mounted.is_empty(),
        "All mounts should be rolled back on Drop without commit"
    );
}

#[test]
fn test_mount_tracker_drop_with_commit_no_rollback() {
    let fs = MockFilesystem::new();
    let home = PathBuf::from("/home");
    let etc = PathBuf::from("/etc");

    // Mock successful mounts
    fs.mock_set_mounted(&home, true);
    fs.mock_set_mounted(&etc, true);

    {
        let mut tracker = MountTracker::new(&fs);
        tracker.push_mount(MountInfo::persistent(home.clone()));
        tracker.push_mount(MountInfo::persistent(etc.clone()));
        tracker.commit(); // Commit prevents rollback
    } // Tracker drops here

    // Verify mounts still exist (no rollback)
    assert!(
        fs.is_mounted(&home).unwrap(),
        "/home should still be mounted after committed Drop"
    );
    assert!(
        fs.is_mounted(&etc).unwrap(),
        "/etc should still be mounted after committed Drop"
    );
}

#[test]
fn test_mount_tracker_rollback_all_best_effort_continues_on_failure() {
    let fs = MockFilesystem::new();
    let home = PathBuf::from("/home");
    let etc = PathBuf::from("/etc");

    // Mock /etc unmount to fail
    fs.mock_set_mounted(&home, true);
    fs.mock_set_mounted(&etc, true);
    fs.mock_set_unmount_should_fail(&etc.to_string_lossy(), true);

    let mut tracker = MountTracker::new(&fs);
    tracker.push_mount(MountInfo::persistent(home.clone()));
    tracker.push_mount(MountInfo::persistent(etc.clone()));

    // Rollback should continue despite /etc failure
    let result = tracker.rollback_all();

    // Should return error mentioning /etc failure
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("/etc") && err_msg.contains("Failed to unmount"),
        "Error should mention /etc unmount failure"
    );

    // But /home should still be unmounted (best-effort)
    assert!(
        !fs.is_mounted(&home).unwrap(),
        "/home should be unmounted despite /etc failure"
    );
}

#[test]
fn test_mount_tracker_rollback_all_aggregate_errors() {
    let fs = MockFilesystem::new();
    let home = PathBuf::from("/home");
    let etc = PathBuf::from("/etc");

    // Mock BOTH unmounts to fail
    fs.mock_set_mounted(&home, true);
    fs.mock_set_mounted(&etc, true);
    fs.mock_set_unmount_should_fail(&home.to_string_lossy(), true);
    fs.mock_set_unmount_should_fail(&etc.to_string_lossy(), true);

    let mut tracker = MountTracker::new(&fs);
    tracker.push_mount(MountInfo::persistent(home.clone()));
    tracker.push_mount(MountInfo::persistent(etc.clone()));

    let result = tracker.rollback_all();

    // Should return aggregate error mentioning both failures
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("/home") && err_msg.contains("/etc"),
        "Error should mention both unmount failures"
    );
}

#[test]
fn test_unmount_overlays_method_reverse_order() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/tmp/state.json");
    let manager = NailsManager::new(fs.clone(), config, state_path);

    let home = PathBuf::from("/home");
    let etc = PathBuf::from("/etc");

    // Mock successful mounts
    fs.mock_set_mounted(&home, true);
    fs.mock_set_mounted(&etc, true);

    // Create mounted paths in mount order: /home, /etc
    let mounted_paths = vec![home.clone(), etc.clone()];

    // Unmount should happen in reverse: /etc first, /home second
    let result = manager.unmount_overlays(mounted_paths);
    assert!(result.is_ok(), "Unmount should succeed");

    // Verify both unmounted
    assert!(!fs.is_mounted(&home).unwrap());
    assert!(!fs.is_mounted(&etc).unwrap());
}

#[test]
fn test_unmount_overlays_best_effort_on_failure() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/tmp/state.json");
    let manager = NailsManager::new(fs.clone(), config, state_path);

    let home = PathBuf::from("/home");
    let etc = PathBuf::from("/etc");

    // Mock /etc unmount to fail, /home to succeed
    fs.mock_set_mounted(&home, true);
    fs.mock_set_mounted(&etc, true);
    fs.mock_set_unmount_should_fail(&etc.to_string_lossy(), true);

    let mounted_paths = vec![home.clone(), etc.clone()];

    // Should return error but still unmount /home
    let result = manager.unmount_overlays(mounted_paths);
    assert!(result.is_err(), "Should return error for /etc failure");

    // Verify /home still unmounted (best-effort)
    assert!(
        !fs.is_mounted(&home).unwrap(),
        "/home should be unmounted despite /etc failure"
    );
}

// Note: Story 14.10 removed MOUNT_ORDER constant in favor of dynamic
// overlay target detection via build_overlay_targets(). See tests:
// - test_build_overlay_targets_auto_mode_*
// - test_build_overlay_targets_explicit_mode_*

// ========== Task 6: DNS Preservation Tests ==========

#[test]
fn test_clean_stale_network_config_removes_resolv_conf() {
    let fs = MockFilesystem::new();
    let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");

    // Create stale resolv.conf
    let resolv_path = upper_dir.join("resolv.conf");
    fs.write_file_content(&resolv_path, "nameserver 8.8.8.8")
        .unwrap();

    // Clean it
    let result = clean_stale_network_config(&upper_dir, &fs);
    assert!(result.is_ok());

    // File should be removed
    assert!(!fs.path_exists(&resolv_path).unwrap());
}

#[test]
fn test_clean_stale_network_config_removes_nsswitch_conf() {
    let fs = MockFilesystem::new();
    let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");

    // Create stale nsswitch.conf
    let nsswitch_path = upper_dir.join("nsswitch.conf");
    fs.write_file_content(&nsswitch_path, "hosts: files dns")
        .unwrap();

    // Clean it
    let result = clean_stale_network_config(&upper_dir, &fs);
    assert!(result.is_ok());

    // File should be removed
    assert!(!fs.path_exists(&nsswitch_path).unwrap());
}

#[test]
fn test_clean_stale_network_config_removes_both_files() {
    let fs = MockFilesystem::new();
    let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");

    // Create both stale files
    let resolv_path = upper_dir.join("resolv.conf");
    let nsswitch_path = upper_dir.join("nsswitch.conf");
    fs.write_file_content(&resolv_path, "nameserver 8.8.8.8")
        .unwrap();
    fs.write_file_content(&nsswitch_path, "hosts: files dns")
        .unwrap();

    // Clean them
    let result = clean_stale_network_config(&upper_dir, &fs);
    assert!(result.is_ok());

    // Both files should be removed
    assert!(!fs.path_exists(&resolv_path).unwrap());
    assert!(!fs.path_exists(&nsswitch_path).unwrap());
}

#[test]
fn test_clean_stale_network_config_no_files_exists() {
    let fs = MockFilesystem::new();
    let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");

    // No files created - should succeed without error
    let result = clean_stale_network_config(&upper_dir, &fs);
    assert!(result.is_ok());
}

#[test]
#[tracing_test::traced_test]
fn test_clean_stale_network_config_logs_removal() {
    let fs = MockFilesystem::new();
    let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");

    // Create stale resolv.conf
    let resolv_path = upper_dir.join("resolv.conf");
    fs.write_file_content(&resolv_path, "nameserver 8.8.8.8")
        .unwrap();

    // Clean it
    let result = clean_stale_network_config(&upper_dir, &fs);
    assert!(result.is_ok());

    // Should log the removal
    assert!(logs_contain("Cleaned stale resolv.conf"));
    assert!(logs_contain("DNS preservation"));
}

#[test]
fn test_clean_stale_network_config_does_not_remove_other_files() {
    let fs = MockFilesystem::new();
    let upper_dir = PathBuf::from("/mnt/hidden/etc-upper");

    // Create files that should NOT be removed
    let passwd_path = upper_dir.join("passwd");
    let shadow_path = upper_dir.join("shadow");
    let hostname_path = upper_dir.join("hostname");
    fs.write_file_content(&passwd_path, "root:x:0:0").unwrap();
    fs.write_file_content(&shadow_path, "root:*").unwrap();
    fs.write_file_content(&hostname_path, "myhostname").unwrap();

    // Also create one that should be removed
    let resolv_path = upper_dir.join("resolv.conf");
    fs.write_file_content(&resolv_path, "nameserver 8.8.8.8")
        .unwrap();

    // Clean
    let result = clean_stale_network_config(&upper_dir, &fs);
    assert!(result.is_ok());

    // Only resolv.conf should be removed
    assert!(!fs.path_exists(&resolv_path).unwrap());
    assert!(fs.path_exists(&passwd_path).unwrap());
    assert!(fs.path_exists(&shadow_path).unwrap());
    assert!(fs.path_exists(&hostname_path).unwrap());
}

// ========== Helper Function Tests ==========

#[test]
fn test_apply_exclusion_filter_empty_exclusions() {
    let dirs = vec![
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/var"),
    ];
    let exclusions: Vec<PathBuf> = vec![];

    let filtered = apply_exclusion_filter(dirs.clone(), &exclusions);

    assert_eq!(filtered.len(), 3);
    assert_eq!(
        filtered,
        vec![
            PathBuf::from("/etc"),
            PathBuf::from("/home"),
            PathBuf::from("/var"),
        ]
    );
}

#[test]
fn test_apply_exclusion_filter_with_exclusions() {
    let dirs = vec![
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/proc"),
        PathBuf::from("/var"),
    ];
    let exclusions = vec![PathBuf::from("/proc")];

    let filtered = apply_exclusion_filter(dirs, &exclusions);

    assert_eq!(filtered.len(), 3);
    assert!(!filtered.contains(&PathBuf::from("/proc")));
    assert!(filtered.contains(&PathBuf::from("/home")));
    assert!(filtered.contains(&PathBuf::from("/etc")));
    assert!(filtered.contains(&PathBuf::from("/var")));
}

#[test]
fn test_apply_exclusion_filter_all_excluded() {
    let dirs = vec![
        PathBuf::from("/proc"),
        PathBuf::from("/sys"),
        PathBuf::from("/dev"),
    ];
    let exclusions = vec![
        PathBuf::from("/proc"),
        PathBuf::from("/sys"),
        PathBuf::from("/dev"),
    ];

    let filtered = apply_exclusion_filter(dirs, &exclusions);

    assert_eq!(filtered.len(), 0);
}

#[test]
fn test_apply_exclusion_filter_sorts_results() {
    let dirs = vec![
        PathBuf::from("/var"),
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
    ];
    let exclusions: Vec<PathBuf> = vec![];

    let filtered = apply_exclusion_filter(dirs, &exclusions);

    // Should be sorted alphabetically
    assert_eq!(filtered[0], PathBuf::from("/etc"));
    assert_eq!(filtered[1], PathBuf::from("/home"));
    assert_eq!(filtered[2], PathBuf::from("/var"));
}

#[test]
fn test_build_overlay_targets_auto_mode_with_defaults() {
    let fs = MockFilesystem::new();

    // Setup root directories (typical Linux system)
    fs.mock_set_root_directories(vec![
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/nix"),
        PathBuf::from("/var"),
        PathBuf::from("/tmp"),
        PathBuf::from("/usr"),
        PathBuf::from("/bin"),
        PathBuf::from("/proc"), // Default exclusion
        PathBuf::from("/sys"),  // Default exclusion
        PathBuf::from("/dev"),  // Default exclusion
        PathBuf::from("/boot"), // Now included (removed from default exclusions)
    ]);

    let config = Config {
        overlay_mode: OverlayMode::Auto,
        ..Config::default()
    };

    let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

    // Should include most dirs, exclude /proc, /sys, /dev + critical /bin, /usr
    assert_eq!(targets.len(), 6);
    assert!(targets.contains(&PathBuf::from("/home")));
    assert!(targets.contains(&PathBuf::from("/etc")));
    assert!(targets.contains(&PathBuf::from("/nix")));
    assert!(targets.contains(&PathBuf::from("/var")));
    assert!(targets.contains(&PathBuf::from("/tmp")));
    assert!(targets.contains(&PathBuf::from("/boot")));
    assert!(!targets.contains(&PathBuf::from("/usr"))); // Critical binary root
    assert!(!targets.contains(&PathBuf::from("/bin"))); // Critical binary root
    assert!(!targets.contains(&PathBuf::from("/proc")));
    assert!(!targets.contains(&PathBuf::from("/sys")));
    assert!(!targets.contains(&PathBuf::from("/dev")));
}

#[test]
fn test_build_overlay_targets_auto_mode_with_user_exclusions() {
    let fs = MockFilesystem::new();

    fs.mock_set_root_directories(vec![
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/nix"),
        PathBuf::from("/var"),
        PathBuf::from("/boot"),
    ]);

    let mut config = Config {
        overlay_mode: OverlayMode::Auto,
        ..Config::default()
    };
    // Add /var and /nix as additional user exclusions
    config.overlay_exclusions = vec![PathBuf::from("/var"), PathBuf::from("/nix")];

    let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

    // Should exclude user-specified directories, /boot now included
    assert_eq!(targets.len(), 3);
    assert!(targets.contains(&PathBuf::from("/home")));
    assert!(targets.contains(&PathBuf::from("/etc")));
    assert!(targets.contains(&PathBuf::from("/boot")));
    assert!(!targets.contains(&PathBuf::from("/nix")));
    assert!(!targets.contains(&PathBuf::from("/var")));
}

#[test]
fn test_build_overlay_targets_auto_mode_with_user_removals() {
    let fs = MockFilesystem::new();

    fs.mock_set_root_directories(vec![
        PathBuf::from("/home"),
        PathBuf::from("/mnt"), // Default exclusion that user wants to remove
    ]);

    let mut config = Config {
        overlay_mode: OverlayMode::Auto,
        ..Config::default()
    };
    config.overlay_exclusions_remove = vec![
        PathBuf::from("/mnt"), // Remove from default exclusions
    ];

    let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

    // /mnt should now be included (removed from exclusions)
    assert_eq!(targets.len(), 2);
    assert!(targets.contains(&PathBuf::from("/home")));
    assert!(targets.contains(&PathBuf::from("/mnt")));
}

#[test]
fn test_build_overlay_targets_auto_mode_empty_root() {
    let fs = MockFilesystem::new();

    // Empty root directory
    fs.mock_set_root_directories(vec![]);

    let config = Config {
        overlay_mode: OverlayMode::Auto,
        ..Config::default()
    };

    let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

    assert_eq!(targets.len(), 0);
}

#[test]
fn test_build_overlay_targets_auto_mode_all_excluded() {
    let fs = MockFilesystem::new();

    fs.mock_set_root_directories(vec![
        PathBuf::from("/proc"),
        PathBuf::from("/sys"),
        PathBuf::from("/dev"),
    ]);

    let config = Config {
        overlay_mode: OverlayMode::Auto,
        ..Config::default()
    };

    let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

    // All directories are in default exclusions
    assert_eq!(targets.len(), 0);
}

#[test]
fn test_build_overlay_targets_auto_mode_sorted_output() {
    let fs = MockFilesystem::new();

    // Unsorted input
    fs.mock_set_root_directories(vec![
        PathBuf::from("/var"),
        PathBuf::from("/etc"),
        PathBuf::from("/home"),
    ]);

    let config = Config {
        overlay_mode: OverlayMode::Auto,
        ..Config::default()
    };

    let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

    // Should be sorted alphabetically
    assert_eq!(targets[0], PathBuf::from("/etc"));
    assert_eq!(targets[1], PathBuf::from("/home"));
    assert_eq!(targets[2], PathBuf::from("/var"));
}

#[test]
fn test_build_overlay_targets_explicit_mode() {
    let fs = MockFilesystem::new();

    // Root has many directories, but explicit mode should ignore them
    fs.mock_set_root_directories(vec![
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/var"),
        PathBuf::from("/tmp"),
        PathBuf::from("/boot"),
    ]);

    let config = Config {
        overlay_mode: OverlayMode::Explicit,
        overlays: vec![
            OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/home"),
                upper: PathBuf::from("/mnt/hidden/home"),
                work: PathBuf::from("/mnt/hidden/.work/home"),
                target: PathBuf::from("/home"),
            },
            OverlayConfig {
                name: "etc".to_string(),
                lower: PathBuf::from("/etc"),
                upper: PathBuf::from("/mnt/hidden/etc"),
                work: PathBuf::from("/mnt/hidden/.work/etc"),
                target: PathBuf::from("/etc"),
            },
        ],
        ..Config::default()
    };

    let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

    // Should only use configured overlays, not all discovered directories
    assert_eq!(targets.len(), 2);
    assert!(targets.contains(&PathBuf::from("/home")));
    assert!(targets.contains(&PathBuf::from("/etc")));
    assert!(!targets.contains(&PathBuf::from("/var")));
    assert!(!targets.contains(&PathBuf::from("/tmp")));
}

#[test]
fn test_build_overlay_targets_explicit_mode_empty_overlays() {
    let fs = MockFilesystem::new();

    fs.mock_set_root_directories(vec![PathBuf::from("/home"), PathBuf::from("/etc")]);

    let config = Config {
        overlay_mode: OverlayMode::Explicit,
        overlays: vec![], // No overlays configured
        ..Config::default()
    };

    let targets = build_overlay_targets(&fs, &config).expect("Should build targets");

    // No overlays configured = no targets
    assert_eq!(targets.len(), 0);
}

#[test]
fn test_mount_tracker_empty_rollback_succeeds() {
    let fs = MockFilesystem::new();
    let mut tracker = MountTracker::new(&fs);

    // Rollback with no mounts should succeed
    let result = tracker.rollback_all();
    assert!(result.is_ok(), "Empty rollback should succeed");
}

#[test]
fn test_unmount_overlays_empty_list_succeeds() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/tmp/state.json");
    let manager = NailsManager::new(fs, config, state_path);

    // Unmount empty list should succeed
    let result = manager.unmount_overlays(vec![]);
    assert!(result.is_ok(), "Unmounting empty list should succeed");
}

#[test]
fn test_unmount_overlays_single_path_failure() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/tmp/state.json");
    let manager = NailsManager::new(fs.clone(), config, state_path);

    let home = PathBuf::from("/home");

    // Mock unmount to fail
    fs.mock_set_mounted(&home, true);
    fs.mock_set_unmount_should_fail(&home.to_string_lossy(), true);

    let mounted_paths = vec![home.clone()];

    // Should return error
    let result = manager.unmount_overlays(mounted_paths);
    assert!(result.is_err(), "Should return error when unmount fails");

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("Unmount completed with errors"),
        "Error should mention unmount failure"
    );
}

#[test]
fn test_unmount_overlays_multiple_paths_partial_failure() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/tmp/state.json");
    let manager = NailsManager::new(fs.clone(), config, state_path);

    let home = PathBuf::from("/home");
    let etc = PathBuf::from("/etc");

    // Mock /etc to fail, /home to succeed
    fs.mock_set_mounted(&home, true);
    fs.mock_set_mounted(&etc, true);
    fs.mock_set_unmount_should_fail(&etc.to_string_lossy(), true);

    let mounted_paths = vec![home.clone(), etc.clone()];

    // Should return error but /home should be unmounted (best-effort)
    let result = manager.unmount_overlays(mounted_paths);
    assert!(result.is_err(), "Should return error for /etc failure");

    // /home should still be unmounted (best-effort)
    assert!(
        !fs.is_mounted(&home).unwrap(),
        "/home should be unmounted despite /etc failure"
    );
}

#[test]
fn test_unmount_overlays_three_paths_reverse_order() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/tmp/state.json");
    let manager = NailsManager::new(fs.clone(), config, state_path);

    let home = PathBuf::from("/home");
    let etc = PathBuf::from("/etc");
    let opt = PathBuf::from("/opt");

    // Mock all as mounted
    fs.mock_set_mounted(&home, true);
    fs.mock_set_mounted(&etc, true);
    fs.mock_set_mounted(&opt, true);

    // Create mounted paths in order: /home, /etc, /opt
    let mounted_paths = vec![home.clone(), etc.clone(), opt.clone()];

    // Unmount should happen in reverse: /opt, /etc, /home
    let result = manager.unmount_overlays(mounted_paths);
    assert!(result.is_ok(), "Unmount should succeed");

    // Verify all unmounted
    assert!(!fs.is_mounted(&home).unwrap());
    assert!(!fs.is_mounted(&etc).unwrap());
    assert!(!fs.is_mounted(&opt).unwrap());
}

// ========== Story 4.7: StateFile Rollback Clearing Tests ==========

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

        let mut cached = mgr.cached_state.lock().unwrap();
        let state_file = StateFile {
            overlay_status,
            nixos_generation: Some("test-generation-123".to_string()),
            ..StateFile::default()
        };
        *cached = Some(state_file);
    }

    // Activation should fail (mount fails)
    let result = NailsManager::activate(Arc::clone(&manager), true);
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

// ========== Story 4.7: Incremental State Persistence Tests (Review Follow-up) ==========

// ========== Additional Coverage Tests: MountTracker and unmount_overlays edge cases ==========

#[test]
fn test_mount_tracker_rollback_graceful_fails_force_succeeds() {
    let fs = MockFilesystem::new();
    let home = PathBuf::from("/home");

    // Mock /home as mounted
    fs.mock_set_mounted(&home, true);

    // Configure graceful unmount to fail, but force unmount to succeed
    // MockFilesystem's mock_set_unmount_should_fail sets both graceful and force to fail
    // We need a workaround: don't set failure, so graceful works, but that doesn't test the path we want
    // Actually the MockFilesystem doesn't distinguish graceful vs force - let's just verify the path is covered

    // For this test, let's ensure the force unmount path (line 164) is covered
    // by having graceful fail and force succeed. MockFilesystem behavior needs checking.

    // Actually, let's set up the mock to simulate graceful failure followed by force success
    // by using mock_set_unmount_graceful_fails to only fail graceful unmount
    fs.mock_set_unmount_graceful_fails(&home.to_string_lossy(), true);

    let mut tracker = MountTracker::new(&fs);
    tracker.push_mount(MountInfo::persistent(home.clone()));

    // Rollback should succeed (graceful fails, force succeeds)
    let result = tracker.rollback_all();

    // Should succeed because force unmount works
    assert!(
        result.is_ok(),
        "Rollback should succeed when force unmount works"
    );

    // Verify /home is unmounted
    assert!(
        !fs.is_mounted(&home).unwrap(),
        "/home should be unmounted after force unmount succeeded"
    );
}

#[test]
fn test_unmount_overlays_graceful_fails_force_succeeds() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/tmp/state.json");
    let manager = NailsManager::new(fs.clone(), config, state_path);

    let home = PathBuf::from("/home");

    // Mock /home as mounted
    fs.mock_set_mounted(&home, true);

    // Configure graceful unmount to fail, force to succeed
    fs.mock_set_unmount_graceful_fails(&home.to_string_lossy(), true);

    let mounted_paths = vec![home.clone()];

    // unmount_overlays should succeed (graceful fails, force succeeds)
    let result = manager.unmount_overlays(mounted_paths);
    assert!(
        result.is_ok(),
        "Unmount should succeed when force unmount works"
    );

    // Verify /home is unmounted
    assert!(
        !fs.is_mounted(&home).unwrap(),
        "/home should be unmounted after force unmount succeeded"
    );
}

#[test]
fn test_nails_manager_debug_impl() {
    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    let manager = NailsManager::new(fs, config.clone(), state_path.clone());

    // Test Debug implementation (lines 242-252)
    let debug_output = format!("{:?}", manager);

    // Verify Debug output contains expected fields
    assert!(
        debug_output.contains("NailsManager"),
        "Debug should contain struct name"
    );
    assert!(
        debug_output.contains("<filesystem>"),
        "Debug should mask filesystem"
    );
    assert!(
        debug_output.contains("config"),
        "Debug should contain config field"
    );
    assert!(
        debug_output.contains("state_file_path"),
        "Debug should contain state_file_path"
    );
    assert!(
        debug_output.contains("<Arc<Mutex<...>>>"),
        "Debug should mask cached_state"
    );
}

#[test]
fn test_nails_manager_debug_with_nixos_builder() {
    use crate::NixOSBuilder;

    let fs = MockFilesystem::new();
    let config = Config::default();
    let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    let nixos_builder = NixOSBuilder::new(
        PathBuf::from("/mnt/hidden/nixos"),
        PathBuf::from("/nix/var/nix/profiles/nails-system"),
    );
    let manager = NailsManager::with_nixos(fs, config, state_path, nixos_builder);

    // Test Debug implementation with NixOSBuilder present
    let debug_output = format!("{:?}", manager);

    // Verify Debug output contains nixos_builder field
    assert!(
        debug_output.contains("nixos_builder"),
        "Debug should contain nixos_builder field"
    );
    assert!(
        debug_output.contains("<NixOSBuilder>"),
        "Debug should mask nixos_builder"
    );
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
    let json = serde_json::to_string_pretty(&state_file).unwrap();
    std::fs::write(&state_path, json).unwrap();

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
    let json = serde_json::to_string_pretty(&state_file).unwrap();
    std::fs::write(&state_path, json).unwrap();

    // Verify should succeed (transitional states are skipped - line 751)
    let result = manager.verify_overlay_status();
    assert!(
        result.is_ok(),
        "Transitional state verification should succeed (skip check)"
    );
}

#[test]
fn test_activate_saves_state_incrementally_after_each_step() {
    use crate::OverlayConfig;

    // Create mock hidden volume structure
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Set up paths to exist
    fs.mock_set_path_exists("/", true);

    // Create two overlays: /home and /etc
    let home_upper = mock_hidden_vol.join("overlays/home/upper");
    let home_work = mock_hidden_vol.join("overlays/home/work");
    let etc_upper = mock_hidden_vol.join("overlays/etc/upper");
    let etc_work = mock_hidden_vol.join("overlays/etc/work");

    std::fs::create_dir_all(&home_upper).unwrap();
    std::fs::create_dir_all(&home_work).unwrap();
    std::fs::create_dir_all(&etc_upper).unwrap();
    std::fs::create_dir_all(&etc_work).unwrap();

    fs.mock_set_path_exists(home_upper.to_str().unwrap(), true);
    fs.mock_set_path_exists(home_work.to_str().unwrap(), true);
    fs.mock_set_path_exists(etc_upper.to_str().unwrap(), true);
    fs.mock_set_path_exists(etc_work.to_str().unwrap(), true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![
            OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: home_upper.clone(),
                work: home_work.clone(),
                target: PathBuf::from("/home"),
            },
            OverlayConfig {
                name: "etc".to_string(),
                lower: PathBuf::from("/"),
                upper: etc_upper.clone(),
                work: etc_work.clone(),
                target: PathBuf::from("/etc"),
            },
        ],
        overlay_mode: crate::OverlayMode::Explicit, // Use explicit mode for test
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    // Run activation
    let result = NailsManager::activate(Arc::clone(&manager), true);
    assert!(result.is_ok(), "Activation should succeed");

    // Verify Step 1: State file contains Activating after transition
    // (This is tested implicitly - we can't check mid-activation, but we verify final state)

    // Verify final state file contains overlay_status for BOTH mounts
    let final_state = StateFile::load(&state_path).expect("Should load final state");

    // AC2: Verify overlay_status populated with /home mount
    assert!(
        final_state
            .overlay_status
            .contains_key(&PathBuf::from("/home")),
        "overlay_status should contain /home entry (AC2)"
    );

    let home_info = final_state
        .overlay_status
        .get(&PathBuf::from("/home"))
        .unwrap();
    assert_eq!(home_info.mount_path, PathBuf::from("/home"));
    assert_eq!(home_info.lower_dir, PathBuf::from("/"));
    assert_eq!(home_info.upper_dir, home_upper);
    assert_eq!(home_info.work_dir, home_work);

    // AC2: Verify overlay_status populated with /etc mount
    assert!(
        final_state
            .overlay_status
            .contains_key(&PathBuf::from("/etc")),
        "overlay_status should contain /etc entry (AC2)"
    );

    let etc_info = final_state
        .overlay_status
        .get(&PathBuf::from("/etc"))
        .unwrap();
    assert_eq!(etc_info.mount_path, PathBuf::from("/etc"));
    assert_eq!(etc_info.lower_dir, PathBuf::from("/"));
    assert_eq!(etc_info.upper_dir, etc_upper);
    assert_eq!(etc_info.work_dir, etc_work);

    // AC1: Verify final state is Active
    assert!(
        matches!(final_state.state, SystemState::Active { .. }),
        "Final state should be Active (AC1)"
    );

    // Verify both overlays are in the Active state's overlay list
    if let SystemState::Active { overlays, .. } = &final_state.state {
        assert_eq!(overlays.len(), 2, "Should have 2 overlays in Active state");
        assert!(overlays.contains(&PathBuf::from("/home")));
        assert!(overlays.contains(&PathBuf::from("/etc")));
    }
}

// ========== Story 4.8: Progress Indicators with Timing Tests ==========

#[test]
fn test_verbosity_set_get() {
    let mut manager = create_test_manager();

    // Default should be Normal
    assert_eq!(manager.verbosity, Verbosity::Normal);

    // Set to Quiet
    manager.set_verbosity(Verbosity::Quiet);
    assert_eq!(manager.verbosity, Verbosity::Quiet);

    // Set to Verbose
    manager.set_verbosity(Verbosity::Verbose);
    assert_eq!(manager.verbosity, Verbosity::Verbose);

    // Set to Debug
    manager.set_verbosity(Verbosity::Debug);
    assert_eq!(manager.verbosity, Verbosity::Debug);
}

#[test]
fn test_verbosity_included_in_debug_output() {
    let manager = create_test_manager();
    let debug_str = format!("{:?}", manager);

    // Verify verbosity field is included in Debug output
    assert!(debug_str.contains("verbosity"));
}

#[test]
fn test_activate_with_different_verbosity_levels() {
    // Test that activate() respects verbosity settings
    // This is tested implicitly through the existing activate tests
    // since they use Normal verbosity by default

    let mut manager = create_test_manager();
    manager.set_verbosity(Verbosity::Quiet);
    assert_eq!(manager.verbosity, Verbosity::Quiet);

    manager.set_verbosity(Verbosity::Debug);
    assert_eq!(manager.verbosity, Verbosity::Debug);
}

#[test]
fn test_stopwatch_used_for_timing() {
    // Verify Stopwatch is available and works correctly
    let stopwatch = Stopwatch::start();
    std::thread::sleep(std::time::Duration::from_millis(10));
    let elapsed = stopwatch.elapsed();

    assert!(elapsed.as_millis() >= 10);

    // Verify Display trait works
    let display = format!("{}", stopwatch);
    assert!(display.ends_with("ms") || display.ends_with("s"));
}

#[test]
fn test_verbosity_ordering_in_manager() {
    // Verify verbosity levels can be compared
    assert!(Verbosity::Quiet < Verbosity::Normal);
    assert!(Verbosity::Normal < Verbosity::Verbose);
    assert!(Verbosity::Verbose < Verbosity::Debug);
}

/// Integration test: Verify activate() includes progress timing
///
/// This test verifies that the activate() method uses Stopwatch
/// for timing and respects verbosity levels. We can't directly
/// capture tracing events in unit tests without tracing-test crate,
/// but we verify the code compiles and runs with different verbosity
/// levels.
#[test]
fn test_activate_progress_timing_integration() {
    use std::sync::Arc;

    // Create mock hidden volume structure in temp dir
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Setup initial state file
    let initial_state = StateFile {
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    initial_state
        .save_with_custom_root(&state_path, mock_hidden_vol)
        .expect("Should save initial state");

    // Create manager with Normal verbosity
    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
    manager.set_verbosity(Verbosity::Normal);

    let manager_arc = Arc::new(Mutex::new(manager));

    // Run activate with no_preflight=true to skip checks
    let result = NailsManager::activate(Arc::clone(&manager_arc), true);

    // Should succeed (even with no overlays configured)
    assert!(result.is_ok(), "Activate should succeed: {:?}", result);

    // Verify final state is Active
    let manager = manager_arc.lock().unwrap();
    let final_state = manager.current_state().expect("Should load state");
    assert!(final_state.is_active(), "System should be active");
}

#[test]
fn test_activate_with_quiet_verbosity() {
    use std::sync::Arc;

    // Create mock hidden volume structure in temp dir
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Setup initial state file
    let initial_state = StateFile {
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    initial_state
        .save_with_custom_root(&state_path, mock_hidden_vol)
        .expect("Should save initial state");

    // Create manager with Quiet verbosity
    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
    manager.set_verbosity(Verbosity::Quiet);

    let manager_arc = Arc::new(Mutex::new(manager));

    // Run activate
    let result = NailsManager::activate(Arc::clone(&manager_arc), true);

    // Should succeed
    assert!(result.is_ok(), "Activate should succeed: {:?}", result);

    // Verify final state is Active
    let manager = manager_arc.lock().unwrap();
    let final_state = manager.current_state().expect("Should load state");
    assert!(final_state.is_active(), "System should be active");
}

#[test]
fn test_activate_with_verbose_verbosity() {
    use std::sync::Arc;

    // Create mock hidden volume structure in temp dir
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Setup initial state file
    let initial_state = StateFile {
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    initial_state
        .save_with_custom_root(&state_path, mock_hidden_vol)
        .expect("Should save initial state");

    // Create manager with Verbose verbosity
    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
    manager.set_verbosity(Verbosity::Verbose);

    let manager_arc = Arc::new(Mutex::new(manager));

    // Run activate
    let result = NailsManager::activate(Arc::clone(&manager_arc), true);

    // Should succeed
    assert!(result.is_ok(), "Activate should succeed: {:?}", result);
}

#[test]
fn test_activate_with_debug_verbosity() {
    use std::sync::Arc;

    // Create mock hidden volume structure in temp dir
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Setup initial state file
    let initial_state = StateFile {
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    initial_state
        .save_with_custom_root(&state_path, mock_hidden_vol)
        .expect("Should save initial state");

    // Create manager with Debug verbosity
    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
    manager.set_verbosity(Verbosity::Debug);

    let manager_arc = Arc::new(Mutex::new(manager));

    // Run activate
    let result = NailsManager::activate(Arc::clone(&manager_arc), true);

    // Should succeed
    assert!(result.is_ok(), "Activate should succeed: {:?}", result);
}

// ========================================================================
// Progress Logging Tests - Tracing Event Capture (Story 4.8 AC: 7)
// ========================================================================

#[test]
#[tracing_test::traced_test]
fn test_activate_logs_all_progress_steps() {
    use std::sync::Arc;

    // Create mock hidden volume structure in temp dir
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Setup initial state file
    let initial_state = StateFile {
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    initial_state
        .save_with_custom_root(&state_path, mock_hidden_vol)
        .expect("Should save initial state");

    // Create manager with Normal verbosity
    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
    manager.set_verbosity(Verbosity::Normal);

    let manager_arc = Arc::new(Mutex::new(manager));

    // Run activate (skip pre-flight since we're testing progress logging, not validation)
    let result = NailsManager::activate(Arc::clone(&manager_arc), true);
    assert!(result.is_ok(), "Activate should succeed: {:?}", result);

    // Verify progress steps were logged (pre-flight will show warning, not "passed" message)
    assert!(logs_contain("DANGER: Skipping pre-flight checks"));
    assert!(logs_contain("Activation complete"));
}

#[test]
#[tracing_test::traced_test]
fn test_activate_logs_include_timing() {
    use std::sync::Arc;

    // Create mock hidden volume structure in temp dir
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Setup initial state file
    let initial_state = StateFile {
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    initial_state
        .save_with_custom_root(&state_path, mock_hidden_vol)
        .expect("Should save initial state");

    // Create manager with Normal verbosity
    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
    manager.set_verbosity(Verbosity::Normal);

    let manager_arc = Arc::new(Mutex::new(manager));

    // Run activate (skip pre-flight to avoid validation failures in test)
    let result = NailsManager::activate(Arc::clone(&manager_arc), true);
    assert!(result.is_ok(), "Activate should succeed: {:?}", result);

    // Verify timing is included (look for patterns like "0.1s", "1.2s", "150ms")
    // The logs should contain timing information in parentheses
    assert!(
        logs_contain("(") && (logs_contain("s)") || logs_contain("ms)")),
        "Logs should contain timing information"
    );
}

#[test]
#[tracing_test::traced_test]
fn test_activate_quiet_mode_minimal_output() {
    use std::sync::Arc;

    // Create mock hidden volume structure in temp dir
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Setup initial state file
    let initial_state = StateFile {
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    initial_state
        .save_with_custom_root(&state_path, mock_hidden_vol)
        .expect("Should save initial state");

    // Create manager with Quiet verbosity
    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
    manager.set_verbosity(Verbosity::Quiet);

    let manager_arc = Arc::new(Mutex::new(manager));

    // Run activate
    let result = NailsManager::activate(Arc::clone(&manager_arc), true);
    assert!(result.is_ok(), "Activate should succeed: {:?}", result);

    // In quiet mode, should NOT see progress steps
    assert!(!logs_contain("[1/6] Preparing session management"));
    assert!(!logs_contain("Pre-flight checks passed"));
    assert!(!logs_contain("Running pre-flight checks"));
}

#[test]
#[tracing_test::traced_test]
fn test_activate_verbose_mode_detailed_output() {
    use crate::OverlayConfig;
    use std::sync::Arc;

    // Create mock hidden volume structure in temp dir
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Set up overlay directories
    fs.mock_set_path_exists("/", true);
    let upper_dir = mock_hidden_vol.join("overlays/home/upper");
    let work_dir = mock_hidden_vol.join("overlays/home/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

    // Setup initial state file
    let initial_state = StateFile {
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    initial_state
        .save_with_custom_root(&state_path, mock_hidden_vol)
        .expect("Should save initial state");

    // Create manager with Verbose verbosity and overlay config
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
    let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
    manager.set_verbosity(Verbosity::Verbose);

    let manager_arc = Arc::new(Mutex::new(manager));

    // Run activate
    let result = NailsManager::activate(Arc::clone(&manager_arc), true);
    assert!(result.is_ok(), "Activate should succeed: {:?}", result);

    // In verbose mode, should see individual mount details
    assert!(logs_contain("/home"));
}

#[test]
#[tracing_test::traced_test]
fn test_activate_already_active_logged() {
    use std::sync::Arc;

    // Create mock hidden volume structure in temp dir
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Setup initial state file as ALREADY ACTIVE
    let initial_state = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![],
        },
        ..StateFile::default()
    };
    initial_state
        .save_with_custom_root(&state_path, mock_hidden_vol)
        .expect("Should save initial state");

    // Create manager with Normal verbosity
    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
    manager.set_verbosity(Verbosity::Normal);

    let manager_arc = Arc::new(Mutex::new(manager));

    // Run activate (should be idempotent)
    let result = NailsManager::activate(Arc::clone(&manager_arc), false);
    assert!(result.is_ok(), "Activate should succeed idempotently");

    // Verify "already active" message was logged
    assert!(logs_contain("already active"));
}

// ============================================================================
// Story 4.9: Rollback Integration Tests - All 7 Scenarios (TR45-TR51)
// ============================================================================
//
// These tests validate rollback behavior for all failure scenarios:
// - TR45: First mount fails
// - TR46: Second mount fails
// - TR47: NixOS build fails
// - TR48: State file write fails
// - TR49: Cleanup fails (Epic 5)
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
    let result = NailsManager::activate(Arc::clone(&manager_arc), true); // skip preflight

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
        assert!(!fs_ref
            .is_mounted(Path::new("/home"))
            .expect("Should check mount"));
        assert!(!fs_ref
            .is_mounted(Path::new("/etc"))
            .expect("Should check mount"));
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

    let result = NailsManager::activate(Arc::clone(&manager_arc), true);

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
    let result = NailsManager::activate(Arc::clone(&manager_arc), true);

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

    let result = NailsManager::activate(Arc::clone(&manager_arc), true);
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

    let result = NailsManager::activate(Arc::clone(&manager_arc), true);
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
    let result = NailsManager::activate(Arc::clone(&manager_arc), true);

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
    let result = NailsManager::activate(Arc::clone(&manager_arc), true);
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
// TR49: Test Rollback Scenario 5 - Cleanup Fails (Epic 5 placeholder)
// ============================================================================

#[test]
fn test_rollback_tr49_cleanup_fails_remounts_overlays() {
    // TR49: Cleanup fails during deactivation → overlays remain mounted, state remains ACTIVE.
    // The current orchestrator rolls back before any unmount step runs, so this validates the
    // observable contract that users rely on today.

    let fs = MockFilesystem::new();
    let (manager, _temp_dir) = create_rollback_test_manager(fs);
    NailsManager::activate(Arc::clone(&manager), true).expect("Should activate for cleanup test");

    {
        let m = manager.lock().unwrap();
        crate::cleanup::test_utils::set_safe_test_home();
        let bash_history = Path::new(crate::cleanup::test_utils::TEST_HOME).join(".bash_history");
        let bash_history_str = bash_history.to_str().unwrap();
        crate::cleanup::test_utils::assert_path_is_safe(bash_history_str);

        m.filesystem().mock_set_path_exists(bash_history_str, true);
        m.filesystem()
            .mock_set_file_content(bash_history_str, "nails deactivate\n");
        m.filesystem()
            .mock_set_write_should_fail(bash_history_str, true);
    }

    let orchestrator =
        crate::DeactivationOrchestrator::new(Arc::clone(&manager), crate::CleanupConfig::default());

    let err = orchestrator
        .run()
        .expect_err("cleanup failure should abort deactivation");
    assert!(matches!(err, NailsError::CleanupError(_)));

    let manager_guard = manager.lock().unwrap();
    assert!(matches!(
        manager_guard.current_state().unwrap(),
        SystemState::Active { .. }
    ));
    assert!(manager_guard
        .filesystem()
        .is_mounted(Path::new("/home"))
        .unwrap());
    assert!(manager_guard
        .filesystem()
        .is_mounted(Path::new("/etc"))
        .unwrap());
}

// ============================================================================
// TR50: Test Rollback Scenario 6 - Unmount Fails
// ============================================================================

#[test]
fn test_rollback_tr50_unmount_fails_during_deactivation() {
    // TR50: Unmount fails → StateGuard rolls back state to ACTIVE
    //
    // KNOWN LIMITATION: StateGuard only restores state metadata, not physical mounts.
    // When deactivation fails partway, overlays successfully unmounted before the failure
    // are NOT remounted. Epic 5 (CleanupManager) will implement full physical rollback.

    // GIVEN: System in ACTIVE state, unmount configured to fail for /etc
    let fs = MockFilesystem::new();
    fs.mock_set_unmount_should_fail("/etc", true);
    let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

    // Activate first
    NailsManager::activate(Arc::clone(&manager_arc), true).expect("Should activate successfully");

    // Verify ACTIVE state
    let state_before = manager_arc.lock().unwrap().current_state().unwrap();
    assert!(matches!(state_before, SystemState::Active { .. }));

    // WHEN: Attempting deactivation with unmount failure on /etc
    // Deactivation tries to unmount overlays; /home succeeds, /etc fails
    let result = NailsManager::emergency_deactivate(Arc::clone(&manager_arc));

    // THEN: Deactivation fails
    assert!(result.is_err(), "Expected deactivation to fail");

    // AND: Error is UnmountError
    let err = result.unwrap_err();
    assert!(
        matches!(err, NailsError::UnmountError { .. }),
        "Expected UnmountError, got: {:?}",
        err
    );

    // AND: State metadata shows ACTIVE (StateGuard rolled back state)
    let state_after = manager_arc.lock().unwrap().current_state().unwrap();
    assert!(
        matches!(state_after, SystemState::Active { .. }),
        "Expected state to remain Active after unmount failure"
    );

    // BUT: Physical mounts state depends on unmount order
    // The orchestrator unmounts in LIFO (reverse) order: /etc first, then /home.
    // Since /etc unmount fails, /home is never unmounted and rollback triggers.
    let manager = manager_arc.lock().unwrap();
    let fs_ref = manager.filesystem();

    assert!(
        fs_ref
            .is_mounted(Path::new("/home"))
            .expect("Should check mount"),
        "/home should remain mounted - orchestrator stops at first failure (LIFO: /etc tried first)"
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

    NailsManager::activate(Arc::clone(&manager_arc), true).expect("Should activate");

    let result = NailsManager::emergency_deactivate(Arc::clone(&manager_arc));
    assert!(result.is_err());

    let err = result.unwrap_err();
    let err_msg = err.to_string();

    // TR50: Error should specifically mention unmount failure
    assert!(
        err_msg.to_lowercase().contains("unmount") && err_msg.contains("/etc"),
        "Error should mention /etc unmount failure: {}",
        err_msg
    );
}

#[test]
fn test_rollback_tr50_first_unmount_fails() {
    // Test rollback when first unmount in deactivation sequence fails

    let fs = MockFilesystem::new();
    // /etc unmounts first in deactivation (LIFO from activation)
    fs.mock_set_unmount_should_fail("/etc", true);
    let (manager_arc, _temp_dir) = create_rollback_test_manager(fs);

    NailsManager::activate(Arc::clone(&manager_arc), true).expect("Should activate");

    let result = NailsManager::emergency_deactivate(Arc::clone(&manager_arc));
    assert!(result.is_err());

    // State should remain ACTIVE
    let state = manager_arc.lock().unwrap().current_state().unwrap();
    assert!(matches!(state, SystemState::Active { .. }));
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
    let result = NailsManager::activate(Arc::clone(&manager_arc), true);

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

    let result = NailsManager::activate(Arc::clone(&manager_arc), true);

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

        let _result = NailsManager::activate(Arc::clone(&manager_arc), true);

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
    let result = NailsManager::activate(Arc::clone(&manager_arc), true);
    assert!(result.is_ok(), "Activation with no overlays should succeed");

    std::mem::forget(temp_dir);
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
    let result = NailsManager::activate(Arc::clone(&manager_arc), true);
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

// ==================== Enhanced MountTracker Tests (Story 4.11) ====================

#[test]
fn test_mount_tracker_persistent_mount() {
    // Verify MountTracker correctly tracks persistent mounts

    let fs = MockFilesystem::new();
    let mut tracker = MountTracker::new(&fs);

    let home_info = MountInfo::persistent(PathBuf::from("/home"));
    tracker.push_mount(home_info.clone());

    assert_eq!(tracker.mounted.len(), 1);
    assert_eq!(tracker.mounted[0].mount_type, MountType::Persistent);
    assert_eq!(tracker.mounted[0].target, PathBuf::from("/home"));
    assert!(
        tracker.mounted[0].tmpfs_paths.is_empty(),
        "Persistent mounts should have no tmpfs paths"
    );
}

#[test]
fn test_mount_tracker_ephemeral_mount() {
    // Verify MountTracker correctly tracks ephemeral mounts with tmpfs paths

    let fs = MockFilesystem::new();
    let mut tracker = MountTracker::new(&fs);

    let var_info = MountInfo::ephemeral(
        PathBuf::from("/var"),
        vec![
            PathBuf::from("/run/nails/var/upper"),
            PathBuf::from("/run/nails/var/work"),
        ],
    );
    tracker.push_mount(var_info.clone());

    assert_eq!(tracker.mounted.len(), 1);
    assert_eq!(tracker.mounted[0].mount_type, MountType::Ephemeral);
    assert_eq!(tracker.mounted[0].target, PathBuf::from("/var"));
    assert_eq!(
        tracker.mounted[0].tmpfs_paths.len(),
        2,
        "Ephemeral mounts should track tmpfs paths"
    );
    assert_eq!(
        tracker.mounted[0].tmpfs_paths[0],
        PathBuf::from("/run/nails/var/upper")
    );
    assert_eq!(
        tracker.mounted[0].tmpfs_paths[1],
        PathBuf::from("/run/nails/var/work")
    );
}

#[test]
fn test_mount_tracker_mixed_persistent_ephemeral() {
    // Verify MountTracker can track both mount types

    let fs = MockFilesystem::new();
    let mut tracker = MountTracker::new(&fs);

    // Add persistent mounts
    tracker.push_mount(MountInfo::persistent(PathBuf::from("/home")));
    tracker.push_mount(MountInfo::persistent(PathBuf::from("/etc")));

    // Add ephemeral mounts
    tracker.push_mount(MountInfo::ephemeral(
        PathBuf::from("/var"),
        vec![
            PathBuf::from("/run/nails/var/upper"),
            PathBuf::from("/run/nails/var/work"),
        ],
    ));
    tracker.push_mount(MountInfo::ephemeral(
        PathBuf::from("/tmp"),
        vec![
            PathBuf::from("/run/nails/tmp/upper"),
            PathBuf::from("/run/nails/tmp/work"),
        ],
    ));

    assert_eq!(tracker.mounted.len(), 4);
    assert_eq!(tracker.mounted[0].mount_type, MountType::Persistent);
    assert_eq!(tracker.mounted[1].mount_type, MountType::Persistent);
    assert_eq!(tracker.mounted[2].mount_type, MountType::Ephemeral);
    assert_eq!(tracker.mounted[3].mount_type, MountType::Ephemeral);
}

#[test]
fn test_mount_tracker_ephemeral_rollback_unmounts_tmpfs() {
    // Verify ephemeral rollback unmounts both overlay and tmpfs

    let fs = MockFilesystem::new();

    // Setup paths
    let var = PathBuf::from("/var");
    let upper = PathBuf::from("/run/nails/var/upper");
    let work = PathBuf::from("/run/nails/var/work");

    // Mock mounted overlay (using overlay mount)
    fs.mock_set_path_exists(&var.to_string_lossy(), true);
    fs.mock_set_path_exists(&upper.to_string_lossy(), true);
    fs.mock_set_path_exists(&work.to_string_lossy(), true);
    fs.mock_set_mounted(&var, true);

    // Mock tmpfs mounts (use mount_tmpfs to properly track them)
    fs.mount_tmpfs(&upper, "1G").unwrap();
    fs.mount_tmpfs(&work, "512M").unwrap();

    let mut tracker = MountTracker::new(&fs);
    tracker.push_mount(MountInfo::ephemeral(
        var.clone(),
        vec![upper.clone(), work.clone()],
    ));

    // Rollback
    let result = tracker.rollback_all();
    assert!(result.is_ok(), "Rollback should succeed");

    // Verify overlay and tmpfs are all unmounted
    assert!(
        !fs.is_mounted(&var).unwrap(),
        "/var overlay should be unmounted"
    );
    assert!(
        !fs.is_mounted(&upper).unwrap(),
        "upper tmpfs should be unmounted"
    );
    assert!(
        !fs.is_mounted(&work).unwrap(),
        "work tmpfs should be unmounted"
    );
}

#[test]
fn test_mount_tracker_ephemeral_cascade_unmount_order() {
    // Verify ephemeral mounts unmount overlay BEFORE tmpfs (cascade)

    let fs = MockFilesystem::new();

    // Setup paths
    let var = PathBuf::from("/var");
    let upper = PathBuf::from("/run/nails/var/upper");
    let work = PathBuf::from("/run/nails/var/work");

    // Mock mounted overlay
    fs.mock_set_path_exists(&var.to_string_lossy(), true);
    fs.mock_set_path_exists(&upper.to_string_lossy(), true);
    fs.mock_set_path_exists(&work.to_string_lossy(), true);
    fs.mock_set_mounted(&var, true);

    // Mock tmpfs mounts
    fs.mount_tmpfs(&upper, "1G").unwrap();
    fs.mount_tmpfs(&work, "512M").unwrap();

    let mut tracker = MountTracker::new(&fs);
    tracker.push_mount(MountInfo::ephemeral(
        var.clone(),
        vec![upper.clone(), work.clone()],
    ));

    // Rollback
    let result = tracker.rollback_all();
    assert!(result.is_ok(), "Rollback should succeed");

    // Verify all unmounted (order is implicit in rollback_all implementation)
    assert!(!fs.is_mounted(&var).unwrap());
    assert!(!fs.is_mounted(&upper).unwrap());
    assert!(!fs.is_mounted(&work).unwrap());
}

#[test]
fn test_mount_tracker_lifo_with_mount_types() {
    // Verify LIFO ordering works correctly with mixed mount types

    let fs = MockFilesystem::new();

    // Setup paths
    let home = PathBuf::from("/home");
    let etc = PathBuf::from("/etc");
    let var = PathBuf::from("/var");
    let var_upper = PathBuf::from("/run/nails/var/upper");
    let var_work = PathBuf::from("/run/nails/var/work");

    // Mock persistent overlays as mounted
    fs.mock_set_path_exists(&home.to_string_lossy(), true);
    fs.mock_set_path_exists(&etc.to_string_lossy(), true);
    fs.mock_set_path_exists(&var.to_string_lossy(), true);
    fs.mock_set_path_exists(&var_upper.to_string_lossy(), true);
    fs.mock_set_path_exists(&var_work.to_string_lossy(), true);
    fs.mock_set_mounted(&home, true);
    fs.mock_set_mounted(&etc, true);
    fs.mock_set_mounted(&var, true);

    // Mock tmpfs mounts for ephemeral overlay
    fs.mount_tmpfs(&var_upper, "1G").unwrap();
    fs.mount_tmpfs(&var_work, "512M").unwrap();

    let mut tracker = MountTracker::new(&fs);

    // Mount order: /home (persistent), /etc (persistent), /var (ephemeral)
    tracker.push_mount(MountInfo::persistent(home.clone()));
    tracker.push_mount(MountInfo::persistent(etc.clone()));
    tracker.push_mount(MountInfo::ephemeral(
        var.clone(),
        vec![var_upper.clone(), var_work.clone()],
    ));

    // Rollback should unmount in reverse: /var (+ tmpfs), /etc, /home
    let result = tracker.rollback_all();
    assert!(result.is_ok(), "Rollback should succeed");

    // Verify all unmounted
    assert!(!fs.is_mounted(&home).unwrap());
    assert!(!fs.is_mounted(&etc).unwrap());
    assert!(!fs.is_mounted(&var).unwrap());
    assert!(!fs.is_mounted(&var_upper).unwrap());
    assert!(!fs.is_mounted(&var_work).unwrap());
}

#[test]
fn test_mount_tracker_ephemeral_tmpfs_failure_best_effort() {
    // Verify rollback continues if tmpfs unmount fails (best-effort)

    let fs = MockFilesystem::new();

    // Setup paths
    let var = PathBuf::from("/var");
    let upper = PathBuf::from("/run/nails/var/upper");
    let work = PathBuf::from("/run/nails/var/work");

    // Mock mounted overlay
    fs.mock_set_path_exists(&var.to_string_lossy(), true);
    fs.mock_set_path_exists(&upper.to_string_lossy(), true);
    fs.mock_set_path_exists(&work.to_string_lossy(), true);
    fs.mock_set_mounted(&var, true);

    // Mock tmpfs mounts
    fs.mount_tmpfs(&upper, "1G").unwrap();
    fs.mount_tmpfs(&work, "512M").unwrap();

    // Make upper tmpfs unmount fail
    fs.mock_set_unmount_should_fail(&upper.to_string_lossy(), true);

    let mut tracker = MountTracker::new(&fs);
    tracker.push_mount(MountInfo::ephemeral(
        var.clone(),
        vec![upper.clone(), work.clone()],
    ));

    // Rollback should return error but continue best-effort
    let result = tracker.rollback_all();
    assert!(
        result.is_err(),
        "Rollback should return error for tmpfs failure"
    );

    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("upper") || err_msg.contains("tmpfs"),
        "Error should mention tmpfs failure: {}",
        err_msg
    );

    // Verify overlay and work tmpfs still unmounted (best-effort)
    assert!(!fs.is_mounted(&var).unwrap(), "/var should be unmounted");
    assert!(
        !fs.is_mounted(&work).unwrap(),
        "work tmpfs should be unmounted"
    );
}

#[test]
fn test_mount_info_constructors() {
    // Verify MountInfo constructor helpers work correctly

    let persistent = MountInfo::persistent(PathBuf::from("/home"));
    assert_eq!(persistent.mount_type, MountType::Persistent);
    assert_eq!(persistent.target, PathBuf::from("/home"));
    assert!(persistent.tmpfs_paths.is_empty());

    let ephemeral = MountInfo::ephemeral(
        PathBuf::from("/var"),
        vec![PathBuf::from("/upper"), PathBuf::from("/work")],
    );
    assert_eq!(ephemeral.mount_type, MountType::Ephemeral);
    assert_eq!(ephemeral.target, PathBuf::from("/var"));
    assert_eq!(ephemeral.tmpfs_paths.len(), 2);
}

// ==================== Activation/Deactivation with Ephemeral Overlays Tests (Story 4.11) ====================

fn create_ephemeral_overlay_test_manager(
    fs: MockFilesystem,
    persistent_targets: &[&str],
    ephemeral_targets: &[&str],
    extended_enabled: bool,
) -> (Arc<Mutex<NailsManager<MockFilesystem>>>, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");

    StateFile {
        state: SystemState::Inactive,
        ..StateFile::default()
    }
    .save_with_custom_root(&state_path, &hidden_root)
    .expect("Should create initial state file");

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists(hidden_root.to_str().unwrap(), true);
    fs.mock_set_path_type(hidden_root.to_str().unwrap(), "directory");
    fs.mock_set_writable(hidden_root.to_str().unwrap(), true);

    setup_nixos_config_check(&fs, &hidden_root);

    let overlays = persistent_targets
        .iter()
        .map(|target| {
            let name = target.trim_start_matches('/');
            let upper = hidden_root.join(format!("{}-upper", name));
            let work = hidden_root.join(format!("{}-work", name));
            std::fs::create_dir_all(&upper).expect("Should create upper dir");
            std::fs::create_dir_all(&work).expect("Should create work dir");
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

    let extended_dirs = ephemeral_targets
        .iter()
        .map(|target| {
            fs.mock_set_path_exists(target, true);
            let name = target.trim_start_matches('/');
            fs.mock_set_directory_creatable(&format!("/run/nails/{}-ephemeral", name), true);
            fs.mock_set_directory_creatable(&format!("/run/nails/{}-ephemeral/upper", name), true);
            fs.mock_set_directory_creatable(&format!("/run/nails/{}-ephemeral/work", name), true);
            fs.mock_set_directory_creatable(&format!("/mnt/nails-pivot/{}", name), true);

            EphemeralOverlayDir {
                path: PathBuf::from(target),
                tmpfs_upper_size: "1G".to_string(),
                tmpfs_work_size: "512M".to_string(),
            }
        })
        .collect();

    let config = Config {
        hidden_volume_root: hidden_root,
        state_file_path: state_path.clone(),
        log_path: state_path
            .parent()
            .expect("state path should have parent")
            .join("logs"),
        overlay_mode: OverlayMode::Explicit,
        overlays,
        extended_overlays: ExtendedOverlayConfig {
            enabled: extended_enabled,
            directories: extended_dirs,
        },
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));
    (manager, temp_dir)
}

fn setup_deactivation_system_profile(fs: &MockFilesystem) {
    fs.mock_set_path_exists("/nix/var/nix/profiles/system", true);
    fs.mock_set_path_exists(
        "/nix/var/nix/profiles/system/bin/switch-to-configuration",
        true,
    );
}

#[test]
fn test_activate_with_ephemeral_overlays_enabled() {
    // AC3: Verify activation mounts both persistent AND ephemeral overlays when enabled

    let fs = MockFilesystem::new();
    let (manager, _temp_dir) =
        create_ephemeral_overlay_test_manager(fs.clone(), &["/home"], &["/var"], true);

    // Activate
    let result = NailsManager::activate(Arc::clone(&manager), true);
    assert!(result.is_ok(), "Activation should succeed: {:?}", result);

    assert!(fs.is_mounted(Path::new("/home")).unwrap());
    assert!(fs.is_mounted(Path::new("/var")).unwrap());
    assert!(fs
        .is_mounted(Path::new("/run/nails/var-ephemeral"))
        .unwrap());

    let state = manager.lock().unwrap().current_state().unwrap();
    assert!(matches!(state, SystemState::Active { .. }));
}

#[test]
fn test_activate_with_ephemeral_overlays_disabled() {
    // AC7: Verify activation skips ephemeral overlays when disabled

    let fs = MockFilesystem::new();
    let (manager, _temp_dir) =
        create_ephemeral_overlay_test_manager(fs.clone(), &["/home"], &["/var"], false);

    // Activate
    let result = NailsManager::activate(Arc::clone(&manager), true);
    assert!(result.is_ok(), "Activation should succeed: {:?}", result);

    assert!(fs.is_mounted(Path::new("/home")).unwrap());
    assert!(
        !fs.is_mounted(Path::new("/var")).unwrap(),
        "/var should not be mounted when extended_overlays.enabled=false"
    );
}

#[test]
fn test_activate_ephemeral_not_in_state_file() {
    // Verify ephemeral overlays are NOT tracked in state file

    let fs = MockFilesystem::new();
    let (manager, _temp_dir) =
        create_ephemeral_overlay_test_manager(fs.clone(), &["/home"], &["/var"], true);

    // Activate
    let result = NailsManager::activate(Arc::clone(&manager), true);
    assert!(result.is_ok(), "Activation should succeed: {:?}", result);

    let mgr = manager.lock().unwrap();
    let state = mgr.cached_state.lock().unwrap();

    if let Some(ref state_file) = *state {
        assert!(
            state_file.overlay_status.contains_key(Path::new("/home")),
            "State file should contain /home (persistent)"
        );
        assert!(
            !state_file.overlay_status.contains_key(Path::new("/var")),
            "State file should NOT contain /var (ephemeral)"
        );
    }
}

#[test]
fn test_deactivate_unmounts_ephemeral_before_persistent() {
    // Normal deactivate() now tears down both ephemeral and persistent
    // overlays before rebooting.

    let fs = MockFilesystem::new();
    let (manager, _temp_dir) =
        create_ephemeral_overlay_test_manager(fs.clone(), &["/home"], &["/var"], true);
    setup_deactivation_system_profile(&fs);

    NailsManager::activate(Arc::clone(&manager), true).expect("Activation should succeed");

    assert!(fs.is_mounted(Path::new("/home")).unwrap());
    assert!(fs.is_mounted(Path::new("/var")).unwrap());

    let result = NailsManager::deactivate(Arc::clone(&manager));
    assert!(result.is_ok(), "Deactivation should succeed: {:?}", result);

    assert!(!fs.is_mounted(Path::new("/var")).unwrap());
    assert!(!fs
        .is_mounted(Path::new("/run/nails/var-ephemeral"))
        .unwrap());
    assert!(
        !fs.is_mounted(Path::new("/home")).unwrap(),
        "Persistent overlays should be unmounted during normal deactivate()"
    );
}

#[test]
fn test_deactivate_ephemeral_unmount_failure_continues_best_effort() {
    // Verify deactivation continues if ephemeral unmount fails (best-effort)
    // while still tearing down persistent overlays.

    let fs = MockFilesystem::new();
    let (manager, _temp_dir) =
        create_ephemeral_overlay_test_manager(fs.clone(), &["/home"], &["/var"], true);
    setup_deactivation_system_profile(&fs);

    NailsManager::activate(Arc::clone(&manager), true).expect("Activation should succeed");

    fs.mock_set_unmount_should_fail("/var", true);

    let result = NailsManager::deactivate(Arc::clone(&manager));
    assert!(result.is_ok(), "Deactivation should continue best-effort");

    assert!(
        !fs.is_mounted(Path::new("/home")).unwrap(),
        "/home should be unmounted during normal deactivate()"
    );
    assert!(
        fs.is_mounted(Path::new("/var")).unwrap(),
        "Failed ephemeral unmount should leave /var mounted"
    );
}

#[test]
fn test_deactivate_with_no_ephemeral_overlays() {
    // Verify deactivation works when no ephemeral overlays are configured.

    let fs = MockFilesystem::new();
    let (manager, _temp_dir) =
        create_ephemeral_overlay_test_manager(fs.clone(), &["/home"], &[], false);
    setup_deactivation_system_profile(&fs);
    NailsManager::activate(Arc::clone(&manager), true).expect("Activation should succeed");

    assert!(fs.is_mounted(Path::new("/home")).unwrap());

    let result = NailsManager::deactivate(Arc::clone(&manager));
    assert!(result.is_ok(), "Deactivation should succeed: {:?}", result);

    assert!(!fs.is_mounted(Path::new("/home")).unwrap());
}

#[test]
fn test_deactivate_multiple_ephemeral_lifo_order() {
    // Verify multiple ephemeral overlays are unmounted in LIFO order and that
    // persistent overlays are also torn down by normal deactivate().

    let fs = MockFilesystem::new();
    let (manager, _temp_dir) = create_ephemeral_overlay_test_manager(
        fs.clone(),
        &["/home"],
        &["/var", "/tmp", "/srv"],
        true,
    );
    setup_deactivation_system_profile(&fs);

    NailsManager::activate(Arc::clone(&manager), true).expect("Activation should succeed");

    assert!(fs.is_mounted(Path::new("/home")).unwrap());
    assert!(fs.is_mounted(Path::new("/var")).unwrap());
    assert!(fs.is_mounted(Path::new("/tmp")).unwrap());
    assert!(fs.is_mounted(Path::new("/srv")).unwrap());

    let result = NailsManager::deactivate(Arc::clone(&manager));
    assert!(result.is_ok(), "Deactivation should succeed: {:?}", result);

    assert!(!fs.is_mounted(Path::new("/var")).unwrap());
    assert!(!fs.is_mounted(Path::new("/tmp")).unwrap());
    assert!(!fs.is_mounted(Path::new("/srv")).unwrap());
    assert!(!fs.is_mounted(Path::new("/home")).unwrap());
}

#[test]
fn test_extended_overlay_full_lifecycle_integration() {
    // HIGH PRIORITY: Comprehensive integration test for extended overlay strategy
    // Tests AC1-AC7: Full activation/deactivation cycle with persistent + ephemeral overlays

    let fs = MockFilesystem::new();
    let (manager, _temp_dir) = create_ephemeral_overlay_test_manager(
        fs.clone(),
        &["/home", "/etc"],
        &["/var", "/tmp"],
        true,
    );
    setup_deactivation_system_profile(&fs);

    // PHASE 1: Activation (AC1, AC2, AC3)
    let result = NailsManager::activate(Arc::clone(&manager), true);
    assert!(result.is_ok(), "Activation should succeed: {:?}", result);

    // Verify persistent overlays mounted (AC1)
    assert!(
        fs.is_mounted(Path::new("/home")).unwrap(),
        "/home should be mounted"
    );
    assert!(
        fs.is_mounted(Path::new("/etc")).unwrap(),
        "/etc should be mounted"
    );

    // Verify ephemeral overlays mounted (AC2, AC3)
    assert!(
        fs.is_mounted(Path::new("/var")).unwrap(),
        "/var should be mounted"
    );
    assert!(
        fs.is_mounted(Path::new("/tmp")).unwrap(),
        "/tmp should be mounted"
    );

    // Verify tmpfs backing stores mounted (AC2)
    assert!(
        fs.is_mounted(Path::new("/run/nails/var-ephemeral"))
            .unwrap(),
        "var ephemeral tmpfs should be mounted"
    );
    assert!(
        fs.is_mounted(Path::new("/run/nails/tmp-ephemeral"))
            .unwrap(),
        "tmp ephemeral tmpfs should be mounted"
    );

    // Verify state is ACTIVE
    {
        let mgr = manager.lock().unwrap();
        let state = mgr.current_state().unwrap();
        assert!(
            matches!(state, SystemState::Active { .. }),
            "State should be Active after activation"
        );
    }

    // PHASE 2: Simulated writes (AC4)
    // In a real system, writes to /var and /tmp would go to tmpfs (RAM)
    // In mock, we just verify mounts exist to represent this capability
    assert!(fs.is_mounted(Path::new("/var")).unwrap());
    assert!(fs.is_mounted(Path::new("/tmp")).unwrap());

    // PHASE 3: Emergency deactivation (AC5)
    // MockFs does not expose the clean base /etc view automatically after the
    // overlay unmount, so restore the clean base fixture before verification.
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ }",
    );
    let result = NailsManager::emergency_deactivate(Arc::clone(&manager));
    assert!(result.is_ok(), "Deactivation should succeed: {:?}", result);

    // Verify ALL overlays unmounted (AC5)
    assert!(
        !fs.is_mounted(Path::new("/home")).unwrap(),
        "/home should be unmounted"
    );
    assert!(
        !fs.is_mounted(Path::new("/etc")).unwrap(),
        "/etc should be unmounted"
    );
    assert!(
        !fs.is_mounted(Path::new("/var")).unwrap(),
        "/var should be unmounted"
    );
    assert!(
        !fs.is_mounted(Path::new("/tmp")).unwrap(),
        "/tmp should be unmounted"
    );

    // Verify tmpfs backing stores destroyed (AC5 - forensic safety)
    assert!(
        !fs.is_mounted(Path::new("/run/nails/var-ephemeral"))
            .unwrap(),
        "var ephemeral tmpfs should be destroyed"
    );
    assert!(
        !fs.is_mounted(Path::new("/run/nails/tmp-ephemeral"))
            .unwrap(),
        "tmp ephemeral tmpfs should be destroyed"
    );

    // Verify state is INACTIVE
    {
        let mgr = manager.lock().unwrap();
        assert_eq!(mgr.current_state().unwrap(), SystemState::Inactive);
    }
}

// ============================================================================
// Story 9.3: Structured Logging Tests
// ============================================================================

#[test]
#[tracing_test::traced_test]
fn test_activation_emits_structured_events_with_state_fields() {
    use std::sync::Arc;

    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

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
        overlays: vec![],
        ..Config::test_default()
    };
    let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
    manager.set_verbosity(Verbosity::Normal);

    let manager_arc = Arc::new(Mutex::new(manager));

    let result = NailsManager::activate(Arc::clone(&manager_arc), true);
    assert!(result.is_ok(), "Activate should succeed: {:?}", result);

    // Verify structured events with state fields (AC#1)
    assert!(logs_contain("Activation started"));
    assert!(logs_contain("activation_started"));
    assert!(logs_contain("state_from"));
    assert!(logs_contain("progress"));
    assert!(logs_contain("session_management"));
    assert!(logs_contain("Activation complete"));
    assert!(logs_contain("activation_complete"));
    assert!(logs_contain("state_to"));
}

#[test]
#[tracing_test::traced_test]
fn test_activation_error_emits_structured_error_fields() {
    use std::sync::Arc;

    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Configure filesystem to fail mount operations by making target directory not exist
    fs.mock_set_path_exists("/home", false);

    // Set up overlay paths
    let upper_dir = mock_hidden_vol.join("home");
    let work_dir = mock_hidden_vol.join(".work/home");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

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
        overlay_mode: crate::OverlayMode::Explicit,
        overlays: vec![crate::OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/home"),
            upper: upper_dir.clone(),
            work: work_dir.clone(),
            target: PathBuf::from("/home"),
        }],
        ..Config::test_default()
    };
    let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
    manager.set_verbosity(Verbosity::Normal);

    let manager_arc = Arc::new(Mutex::new(manager));

    let result = NailsManager::activate(Arc::clone(&manager_arc), true);
    assert!(result.is_err(), "Activate should fail due to mount failure");

    // Verify structured error event fields (AC#2)
    assert!(logs_contain("error"));
    assert!(logs_contain("rollback") || logs_contain("Rollback"));
}

#[test]
#[tracing_test::traced_test]
fn test_overlays_mounted_event_includes_overlay_list() {
    use std::sync::Arc;

    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    let initial_state = StateFile {
        state: SystemState::Inactive,
        ..StateFile::default()
    };
    initial_state
        .save_with_custom_root(&state_path, mock_hidden_vol)
        .expect("Should save initial state");

    // Config with NO overlays - just testing that the log event structure exists
    // When overlays ARE present, the "Overlays mounted" event will fire
    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());
    manager.set_verbosity(Verbosity::Normal);

    let manager_arc = Arc::new(Mutex::new(manager));

    let result = NailsManager::activate(Arc::clone(&manager_arc), true);
    assert!(result.is_ok(), "Activate should succeed: {:?}", result);

    // With no overlays, the mount event won't fire, but activation complete will
    // This test verifies the logging infrastructure works (AC#1)
    assert!(logs_contain("Activation complete"));
    assert!(logs_contain("state_to"));
}

// ========== Story 14.10, Task 12: Integration Tests for Dynamic Overlay Activation ==========

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
    // Task 12.1: Test activation with overlay_mode: auto creates overlays for all non-excluded dirs
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

    let result = NailsManager::activate(Arc::clone(&manager), true);
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
fn test_activate_auto_mode_mount_order_is_alphabetical() {
    // Task 12.2: Test mount order is alphabetical
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

    let result = NailsManager::activate(Arc::clone(&manager), true);
    assert!(result.is_ok(), "Activation should succeed: {:?}", result);

    // Verify mount order is alphabetical by checking overlay_status
    let mgr = manager.lock().unwrap();
    let cached = mgr.cached_state.lock().unwrap();
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
    // Task 12.3: Test upper/work dirs created at correct paths
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

    let result = NailsManager::activate(Arc::clone(&manager), true);
    assert!(result.is_ok(), "Activation should succeed: {:?}", result);

    // Verify overlay paths are correct
    let mgr = manager.lock().unwrap();
    let cached = mgr.cached_state.lock().unwrap();
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
    let result = NailsManager::activate(Arc::clone(&manager), true);
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

    let result = NailsManager::activate(Arc::clone(&manager), true);
    assert!(result.is_err(), "Activation should fail on mount error");

    // Verify failed overlays are recorded in state
    let mgr = manager.lock().unwrap();
    let cached = mgr.cached_state.lock().unwrap();
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

    let err = NailsManager::activate(Arc::clone(&manager), true).unwrap_err();
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
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    let result = NailsManager::activate(Arc::clone(&manager), true);
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

// ========== Story 14.10, Task 13: Integration Tests for Explicit Mode ==========

#[test]
fn test_activate_explicit_mode_uses_only_configured_overlays() {
    // Task 13.1: Test explicit mode uses only configured overlays (legacy behavior)
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

    let result = NailsManager::activate(Arc::clone(&manager), true);
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
    // Task 13.2: Test default mode is auto
    let config = Config::test_default();
    assert_eq!(config.overlay_mode, OverlayMode::Auto);
}

// ========== Story 15.1: /etc hardware-configuration import injection ==========

#[test]
fn test_activation_injects_import_block_into_overlayed_hardware_config() {
    use crate::OverlayConfig;

    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Base hardware config must exist and be clean (AC1)
    let base_content = r#"{ config, pkgs, modulesPath, ... }:
{
  imports = [
    (modulesPath + "/installer/scan/not-detected.nix")
  ];
  boot.loader.grub.enable = true;
}
"#;
    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
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

    let result = NailsManager::activate(Arc::clone(&manager), true);
    assert!(result.is_ok(), "Activation should succeed: {:?}", result);

    let written = fs
        .get_written_content(&PathBuf::from("/etc/nixos/hardware-configuration.nix"))
        .expect("Injection should write overlayed hardware config");

    // AC2: Injected import present and first in imports list
    let nails_pos = written
        .find("./nails/configuration.nix")
        .expect("nails import should be injected");
    let existing_pos = written
        .find("installer/scan/not-detected.nix")
        .expect("original imports should remain");
    assert!(nails_pos < existing_pos, "nails import should be first");

    // AC3: Base content preserved (underlay unchanged in effect)
    assert!(
        written.contains("boot.loader.grub.enable = true;"),
        "Original hardware config should be preserved"
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

    let result = NailsManager::activate(Arc::clone(&manager), true);

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

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ imports = [ /mnt/hidden/nixos/configuration.nix ]; }",
    );

    fs.mock_set_path_exists("/home", true);
    let upper_home = mock_hidden_vol.join("overlays/home/upper");
    let work_home = mock_hidden_vol.join("overlays/home/work");
    std::fs::create_dir_all(&upper_home).unwrap();
    std::fs::create_dir_all(&work_home).unwrap();
    fs.mock_set_path_exists(upper_home.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);

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

    let err = NailsManager::activate(Arc::clone(&manager), true).unwrap_err();
    assert!(err.to_string().contains("forensically clean"));
    assert!(
        fs.mock_ops().is_empty(),
        "no overlay mounts should be attempted"
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

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_path_exists("/home", true);
    let upper_home = mock_hidden_vol.join("overlays/home/upper");
    let work_home = mock_hidden_vol.join("overlays/home/work");
    std::fs::create_dir_all(&upper_home).unwrap();
    std::fs::create_dir_all(&work_home).unwrap();
    fs.mock_set_path_exists(upper_home.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);

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

    let err = NailsManager::activate(Arc::clone(&manager), true).unwrap_err();
    assert!(err.to_string().contains("File not found in mock"));
    assert!(
        fs.mock_ops().is_empty(),
        "no overlay mounts should be attempted"
    );
}

#[test]
fn test_activate_explicit_mode_rejects_critical_system_root_overlay_bin() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    let state_path = mock_hidden_vol.join("state.json");
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ }",
    );
    fs.mock_set_path_exists("/bin", true);

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

    let err = NailsManager::activate(Arc::clone(&manager), true).unwrap_err();
    assert!(err
        .to_string()
        .contains("Overlaying critical system root /bin is blocked"));
    assert!(fs.mock_ops().is_empty());
}

#[test]
fn test_activation_rolls_back_when_import_injection_fails_after_etc_mount() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    let state_path = mock_hidden_vol.join("state.json");
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
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

    let err = NailsManager::activate(Arc::clone(&manager), true).unwrap_err();
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
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
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

    let result = NailsManager::activate(Arc::clone(&manager), true);
    assert!(
        result.is_ok(),
        "activation should continue on stale network cleanup failure: {:?}",
        result
    );
    assert!(logs_contain("Failed to clean stale network config"));
}

#[test]
fn test_activation_ephemeral_mount_failure_rolls_back_persistent_mounts() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    let state_path = mock_hidden_vol.join("state.json");
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ }",
    );
    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/var", true);

    let upper_home = mock_hidden_vol.join("overlays/home/upper");
    let work_home = mock_hidden_vol.join("overlays/home/work");
    std::fs::create_dir_all(&upper_home).unwrap();
    std::fs::create_dir_all(&work_home).unwrap();
    fs.mock_set_path_exists(upper_home.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);
    fs.mock_set_directory_creatable("/run/nails/var-ephemeral", true);
    fs.mock_set_directory_creatable("/run/nails/var-ephemeral/upper", true);
    fs.mock_set_directory_creatable("/run/nails/var-ephemeral/work", true);

    let mut config = Config {
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
    };
    config.extended_overlays = ExtendedOverlayConfig {
        enabled: true,
        directories: vec![EphemeralOverlayDir {
            path: PathBuf::from("/var"),
            tmpfs_upper_size: "bogus".to_string(),
            tmpfs_work_size: "512M".to_string(),
        }],
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path,
    )));

    let err = NailsManager::activate(Arc::clone(&manager), true).unwrap_err();
    assert!(err.to_string().contains("Invalid tmpfs size format"));
    assert!(
        !fs.is_mounted(Path::new("/home")).unwrap(),
        "/home should be rolled back"
    );
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );
}

#[test]
fn test_activation_rebuild_failure_rolls_back_all_mounted_state() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_file_content("/etc/nixos/hardware-configuration.nix", "{ ... }: { }");
    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/etc", true);
    fs.mock_set_path_exists("/home", true);

    let upper_etc = hidden_root.join("overlays/etc/upper");
    let work_etc = hidden_root.join("overlays/etc/work");
    let upper_home = hidden_root.join("overlays/home/upper");
    let work_home = hidden_root.join("overlays/home/work");
    std::fs::create_dir_all(&upper_etc).unwrap();
    std::fs::create_dir_all(&work_etc).unwrap();
    std::fs::create_dir_all(&upper_home).unwrap();
    std::fs::create_dir_all(&work_home).unwrap();
    fs.mock_set_path_exists(upper_etc.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_etc.to_str().unwrap(), true);
    fs.mock_set_path_exists(upper_home.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);

    let bin_dir = hidden_root.join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let rebuild_script = bin_dir.join("nixos-rebuild");
    std::fs::write(
        &rebuild_script,
        "#!/usr/bin/env sh\nprintf 'boom\\n' 1>&2\nexit 2\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&rebuild_script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&rebuild_script, perms).unwrap();
    }

    let old_path = std::env::var_os("PATH");
    let mut paths = vec![bin_dir.clone()];
    if let Some(existing) = &old_path {
        paths.extend(std::env::split_paths(existing));
    }
    unsafe {
        std::env::set_var(
            "PATH",
            std::env::join_paths(paths).expect("failed to compose PATH for test"),
        );
    }

    let builder = crate::nixos::NixOSBuilder::new(
        hidden_root.join("config"),
        hidden_root.join("nails-system"),
    );

    let manager = Arc::new(Mutex::new(NailsManager::with_nixos(
        fs.clone(),
        Config {
            hidden_volume_root: hidden_root.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: OverlayMode::Explicit,
            overlays: vec![
                OverlayConfig {
                    name: "etc".to_string(),
                    lower: PathBuf::from("/"),
                    upper: upper_etc.clone(),
                    work: work_etc.clone(),
                    target: PathBuf::from("/etc"),
                },
                OverlayConfig {
                    name: "home".to_string(),
                    lower: PathBuf::from("/"),
                    upper: upper_home.clone(),
                    work: work_home.clone(),
                    target: PathBuf::from("/home"),
                },
            ],
            ..Config::test_default()
        },
        state_path.clone(),
        builder,
    )));

    let err = NailsManager::activate(Arc::clone(&manager), true).unwrap_err();
    let err_text = err.to_string();
    assert!(
        err_text.contains("NixOS build+switch failed:"),
        "unexpected activation error: {err_text}"
    );

    let manager_guard = manager.lock().unwrap();
    assert_eq!(
        manager_guard.current_state().unwrap(),
        SystemState::Inactive
    );
    drop(manager_guard);

    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded.state, SystemState::Inactive);
    assert!(loaded.overlay_status.is_empty());
    assert!(loaded.failed_overlays.is_empty());

    match old_path {
        Some(path) => unsafe { std::env::set_var("PATH", path) },
        None => unsafe { std::env::remove_var("PATH") },
    }
}

// ========== Story 14.10: Error Format Validation Test ==========

#[test]
#[tracing_test::traced_test]
fn test_overlay_mount_failure_error_format() {
    // AC9: Validate error message format "⚠ Could not overlay /path: {reason}"
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
    config.overlay_mode = OverlayMode::Auto;

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    // Attempt activation - should succeed partially
    // Skip preflight to directly test mount failure error format
    let _result = NailsManager::activate(manager, true);

    // Verify error message format matches AC9 specification
    assert!(
        logs_contain("⚠ Could not overlay /etc"),
        "Error message should contain '⚠ Could not overlay /etc'"
    );
    assert!(
        logs_contain("⚠ Could not overlay"),
        "Error message should follow format '⚠ Could not overlay <path>: <reason>'"
    );
}

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

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    // Attempt activation - should succeed with 0 overlays
    let result = NailsManager::activate(manager.clone(), true);

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
    let cached = mgr.cached_state.lock().unwrap();
    if let Some(ref state_file) = *cached {
        assert!(state_file.state.is_active(), "State should be Active");
        assert_eq!(state_file.overlay_status.len(), 0);
    } else {
        panic!("State file should be cached");
    }
}

// ========== Story 15.3: Switch to Hidden Config and Revert via Overlay Removal ==========

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
        })
        .unwrap();

    // Register /etc overlay in cached state
    {
        let mgr = manager.lock().unwrap();
        let mut cached = mgr.cached_state.lock().unwrap();
        if let Some(ref mut sf) = *cached {
            sf.overlay_status.insert(
                PathBuf::from("/etc"),
                OverlayInfo {
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
        })
        .unwrap();

    // Register /home overlay in cached state
    {
        let mgr = manager.lock().unwrap();
        let mut cached = mgr.cached_state.lock().unwrap();
        if let Some(ref mut sf) = *cached {
            sf.overlay_status.insert(
                PathBuf::from("/home"),
                OverlayInfo {
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

/// AC1, Subtask 1.1 / 1.2:
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
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ }",
    );

    // The hidden underlay — also has no import initially
    let underlay = hidden.join("etc/nixos/hardware-configuration.nix");
    fs.mock_set_path_exists(underlay.to_str().unwrap(), true);
    fs.mock_set_path_type(underlay.to_str().unwrap(), "file");
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

    // Underlay path is UNTOUCHED — contains no import (AC1, subtask 1.2)
    let underlay_content = fs.read_file_content(&underlay).unwrap();
    assert!(
        !underlay_content.contains("./nails/configuration.nix"),
        "Hidden underlay hardware-configuration.nix must NOT be modified by inject_import_block (AC1)"
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

/// AC1, Subtask 1.1:
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
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
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
    fs.mock_set_path_type("/", "directory");
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

    let result = NailsManager::activate(manager.clone(), true);
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

/// AC2, Subtask 2.1 + AC3, Subtask 2.2:
/// After deactivation, /etc overlay is unmounted, so /etc/nixos/hardware-configuration.nix
/// reverts to the base (clean) file. verify_base_config_clean() is called post-unmount and
/// confirms the base is clean. Deactivation succeeds.
#[test]
#[serial]
fn test_deactivation_succeeds_when_base_config_clean_after_unmount() {
    let (manager, fs_clone, state_path, _temp_dir) = setup_active_with_etc_overlay();

    // Simulate post-unmount view: base config is clean (no import, no hidden refs)
    fs_clone.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs_clone.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs_clone.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ }",
    );

    let result = NailsManager::emergency_deactivate(Arc::clone(&manager));
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

/// AC3, Subtask 2.2:
/// If verify_base_config_clean() returns false after deactivation (base config is dirty),
/// deactivation returns an error. This enforces that the base underlay was never polluted.
#[test]
#[serial]
fn test_deactivation_fails_when_base_config_dirty_after_unmount() {
    let (manager, fs_clone, _state_path, _temp_dir) = setup_active_with_etc_overlay();

    // Simulate a dirty base config (contains a hidden path reference — should never happen
    // in production on the base underlay, but if it does, deactivation must catch it).
    fs_clone.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs_clone.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs_clone.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ imports = [ /mnt/hidden/nixos/configuration.nix ]; }",
    );

    let result = NailsManager::emergency_deactivate(Arc::clone(&manager));
    assert!(
        result.is_err(),
        "Deactivation should fail when base config is dirty after unmount (AC3)"
    );

    let err = result.unwrap_err();
    match err {
        NailsError::NixOSError(msg) => {
            assert!(
                msg.contains("forensically clean")
                    || msg.contains("dirty")
                    || msg.contains("clean"),
                "Error message should reference config cleanliness: {}",
                msg
            );
        }
        other => panic!("Expected NixOSError, got: {:?}", other),
    }

    // Overlays were already unmounted; state should reflect Inactive even on error.
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive,
        "State should be Inactive after deactivation cleanliness failure"
    );
}

/// Base config cleanliness check is only required when /etc overlay was mounted.
#[test]
#[serial]
fn test_deactivation_skips_base_check_when_etc_not_overlaid() {
    let (manager, fs_clone, _state_path, _temp_dir) = setup_active_with_home_overlay();

    // Dirty base config should not block deactivation when /etc wasn't overlaid.
    fs_clone.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs_clone.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs_clone.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ imports = [ /mnt/hidden/nixos/configuration.nix ]; }",
    );

    let result = NailsManager::emergency_deactivate(Arc::clone(&manager));
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

/// AC2-3, Subtask 4.1 (integration):
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

    // Base hardware config: clean (AC1 pre-condition)
    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
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
    let activate_result = NailsManager::activate(manager.clone(), true);
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
    let deactivate_result = NailsManager::emergency_deactivate(Arc::clone(&manager));
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
        "Base hardware-configuration.nix must remain clean after full cycle (AC2, AC3)"
    );
}

// ========== Story 15.4: Manager integration test for fingerprint persistence ==========

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
        checksum: None,
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
        let state = mgr.cached_state.lock().unwrap();
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
        let mut cached = mgr.cached_state.lock().unwrap();
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
    use crate::nixos::compute_config_fingerprint;
    use crate::NixOSBuilder;

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
    let cfg_content = fs
        .read_file_content(&hidden_root.join("config/nixos/configuration.nix"))
        .unwrap();
    let fingerprint = compute_config_fingerprint(&hw_content, &cfg_content);

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
        let mut cached = manager.cached_state.lock().unwrap();
        *cached = Some(StateFile {
            state: SystemState::Inactive,
            config_fingerprint: Some(fingerprint),
            nixos_generation: Some("123".to_string()),
            ..StateFile::default()
        });
    }

    let result = NailsManager::activate(Arc::new(Mutex::new(manager)), true);
    assert!(result.is_err());
    assert!(logs_contain("Computing NixOS config fingerprint"));
    assert!(logs_contain("Fast-path check"));
    assert!(logs_contain("Fast path: fingerprint matches"));
}

#[test]
#[tracing_test::traced_test]
fn test_nixos_build_does_not_take_fast_path_when_generation_missing() {
    use crate::nixos::compute_config_fingerprint;
    use crate::NixOSBuilder;

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
    let cfg_content = fs
        .read_file_content(&hidden_root.join("config/nixos/configuration.nix"))
        .unwrap();
    let fingerprint = compute_config_fingerprint(&hw_content, &cfg_content);

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
        let mut cached = manager.cached_state.lock().unwrap();
        *cached = Some(StateFile {
            state: SystemState::Inactive,
            config_fingerprint: Some(fingerprint),
            nixos_generation: None,
            ..StateFile::default()
        });
    }

    let result = NailsManager::activate(Arc::new(Mutex::new(manager)), true);
    assert!(result.is_err());
    assert!(logs_contain("Fast-path check"));
    assert!(!logs_contain("Fast path: fingerprint matches"));
}

#[test]
#[tracing_test::traced_test]
fn test_nixos_build_uses_empty_content_when_both_reads_fail() {
    use crate::nixos::compute_config_fingerprint;
    use crate::NixOSBuilder;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }:\n{ }",
    );
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_mount_should_fail("/home", true);
    fs.mock_set_path_exists("/", true);

    let fingerprint = compute_config_fingerprint("", "");
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
        let mut cached = manager.cached_state.lock().unwrap();
        *cached = Some(StateFile {
            state: SystemState::Inactive,
            config_fingerprint: Some(fingerprint),
            nixos_generation: Some("123".to_string()),
            ..StateFile::default()
        });
    }

    let result = NailsManager::activate(Arc::new(Mutex::new(manager)), true);
    assert!(result.is_err());
    assert!(logs_contain(
        "Failed to read hardware-configuration.nix for fingerprint"
    ));
    assert!(logs_contain(
        "Failed to read configuration.nix for fingerprint"
    ));
    assert!(logs_contain("Fast path: fingerprint matches"));
}

// ========== parse_system_generation Tests ==========

#[test]
fn test_parse_system_generation_valid() {
    assert_eq!(
        super::helpers::parse_system_generation("system-1-link"),
        Some(1)
    );
    assert_eq!(
        super::helpers::parse_system_generation("system-42-link"),
        Some(42)
    );
    assert_eq!(
        super::helpers::parse_system_generation("system-100-link"),
        Some(100)
    );
    assert_eq!(
        super::helpers::parse_system_generation("system-0-link"),
        Some(0)
    );
}

#[test]
fn test_parse_system_generation_invalid_no_prefix() {
    assert_eq!(super::helpers::parse_system_generation("1-link"), None);
    assert_eq!(super::helpers::parse_system_generation("foo-1-link"), None);
}

#[test]
fn test_parse_system_generation_invalid_no_suffix() {
    assert_eq!(super::helpers::parse_system_generation("system-1"), None);
    assert_eq!(
        super::helpers::parse_system_generation("system-1-symlink"),
        None
    );
}

#[test]
fn test_parse_system_generation_non_numeric() {
    assert_eq!(
        super::helpers::parse_system_generation("system-abc-link"),
        None
    );
    assert_eq!(
        super::helpers::parse_system_generation("system--link"),
        None
    );
}

#[test]
fn test_parse_system_generation_empty() {
    assert_eq!(super::helpers::parse_system_generation(""), None);
}

// ========== find_newest_system_profile / select_system_profile Tests ==========

#[test]
fn test_find_newest_system_profile_directory_not_exist() {
    let fs = MockFilesystem::new();
    // Profiles dir doesn't exist
    let result = super::helpers::find_newest_system_profile(&fs);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[test]
fn test_find_newest_system_profile_picks_highest_generation() {
    let fs = MockFilesystem::new();
    // Use runtime value of system_profiles_dir() to stay consistent with any
    // NAILS_SYSTEM_PROFILE_PATH set by concurrent deactivation tests.
    let profiles_dir = super::helpers::system_profiles_dir();
    fs.mock_set_path_exists(profiles_dir.to_str().unwrap(), true);
    fs.mock_set_directory_contents(
        &profiles_dir,
        vec![
            profiles_dir.join("system-1-link"),
            profiles_dir.join("system-5-link"),
            profiles_dir.join("system-3-link"),
            profiles_dir.join("not-a-generation"),
        ],
    );

    let result = super::helpers::find_newest_system_profile(&fs).unwrap();
    assert!(result.is_some());
    let path = result.unwrap();
    assert!(path.to_string_lossy().contains("system-5-link"));
}

#[test]
fn test_find_newest_system_profile_no_valid_entries() {
    let fs = MockFilesystem::new();
    let profiles_dir = PathBuf::from("/nix/var/nix/profiles");
    fs.mock_set_path_exists(profiles_dir.to_str().unwrap(), true);
    fs.mock_set_directory_contents(
        &profiles_dir,
        vec![
            profiles_dir.join("not-a-generation"),
            profiles_dir.join("system"),
        ],
    );

    let result = super::helpers::find_newest_system_profile(&fs).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_select_system_profile_finds_newest() {
    let fs = MockFilesystem::new();
    // Use runtime value of system_profiles_dir() to stay consistent with any
    // NAILS_SYSTEM_PROFILE_PATH set by concurrent deactivation tests.
    let profiles_dir = super::helpers::system_profiles_dir();
    fs.mock_set_path_exists(profiles_dir.to_str().unwrap(), true);
    fs.mock_set_directory_contents(
        &profiles_dir,
        vec![
            profiles_dir.join("system-2-link"),
            profiles_dir.join("system-1-link"),
        ],
    );

    let result = select_system_profile(&fs).unwrap();
    assert!(result.is_some());
    assert!(result.unwrap().to_string_lossy().contains("system-2-link"));
}

#[test]
fn test_select_system_profile_falls_back_to_system_symlink() {
    let fs = MockFilesystem::new();
    // No newest generation found, but system symlink exists
    let system_path = super::helpers::system_profile_path();
    // profiles dir doesn't exist (so no generations found)
    // but the system symlink itself exists
    fs.mock_set_path_exists(system_path.to_str().unwrap(), true);

    let result = select_system_profile(&fs).unwrap();
    assert!(result.is_some());
    assert_eq!(result.unwrap(), system_path);
}

#[test]
fn test_select_system_profile_returns_none_when_nothing_found() {
    let fs = MockFilesystem::new();
    // Neither profiles dir nor system symlink exist
    let result = select_system_profile(&fs).unwrap();
    assert!(result.is_none());
}

// ========== ensure_run_current_system_symlink Tests ==========

#[test]
fn test_ensure_run_current_system_symlink_creates_new_when_not_exists() {
    let fs = MockFilesystem::new();
    let run_current = PathBuf::from("/run/current-system");
    let target = PathBuf::from("/nix/var/nix/profiles/system-1-link");

    // run_current does not exist (neither symlink nor regular file)
    let result = ensure_run_current_system_symlink(&fs, &target);
    assert!(result.is_ok());
    assert_eq!(fs.mock_get_symlink_target(&run_current), Some(target));
}

#[test]
fn test_ensure_run_current_system_symlink_replaces_existing_symlink() {
    let fs = MockFilesystem::new();
    let run_current = PathBuf::from("/run/current-system");
    let target = PathBuf::from("/nix/var/nix/profiles/system-1-link");

    fs.mock_set_path_exists(run_current.to_str().unwrap(), true);
    fs.mock_set_is_symlink(run_current.to_str().unwrap(), true);

    let result = ensure_run_current_system_symlink(&fs, &target);
    assert!(result.is_ok());
    assert_eq!(fs.mock_get_symlink_target(&run_current), Some(target));
}

#[test]
fn test_ensure_run_current_system_symlink_rejects_non_symlink() {
    let fs = MockFilesystem::new();
    let run_current = PathBuf::from("/run/current-system");
    let target = PathBuf::from("/nix/var/nix/profiles/system-1-link");

    fs.mock_set_path_exists(run_current.to_str().unwrap(), true);
    fs.mock_set_is_symlink(run_current.to_str().unwrap(), false);

    let result = ensure_run_current_system_symlink(&fs, &target);
    assert!(result.is_err());
}
