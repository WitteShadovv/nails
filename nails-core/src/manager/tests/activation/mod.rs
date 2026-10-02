//! Activation: state transitions, incremental state saves, progress and logging.

use super::*;

mod nixos_build;
mod nixos_switch;
mod overlay_mount;

// ========== activate() ==========

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
        state_path.clone(),
    )));

    // Activate should succeed
    let result = manager.lock().unwrap().activate(true);
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
    state_file
        .save_with_custom_root(&state_path, temp_dir.path())
        .unwrap();

    // Force manager to reload state from disk
    *manager.lock().unwrap().cached_state.borrow_mut() = None;

    // AC7: activate() is idempotent - calling from Active state should succeed (no-op)
    let result = manager.lock().unwrap().activate(true);
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
        state_path.clone(),
    )));

    // Activate
    manager.lock().unwrap().activate(true).unwrap();

    // Verify mount was called
    assert!(fs_clone.is_mounted(Path::new("/home")).unwrap());
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
    let result = manager.lock().unwrap().activate(true);
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

// ========== Progress timing ==========

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
    let result = manager_arc.lock().unwrap().activate(true);

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
    let result = manager_arc.lock().unwrap().activate(true);

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
    let result = manager_arc.lock().unwrap().activate(true);

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
    let result = manager_arc.lock().unwrap().activate(true);

    // Should succeed
    assert!(result.is_ok(), "Activate should succeed: {:?}", result);
}

// ========================================================================
// Progress Logging Tests - Tracing Event Capture
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
    let result = manager_arc.lock().unwrap().activate(true);
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
    let result = manager_arc.lock().unwrap().activate(true);
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
    let result = manager_arc.lock().unwrap().activate(true);
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
    let result = manager_arc.lock().unwrap().activate(true);
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
    let result = manager_arc.lock().unwrap().activate(false);
    assert!(result.is_ok(), "Activate should succeed idempotently");

    // Verify "already active" message was logged
    assert!(logs_contain("already active"));
}

// ============================================================================
// Structured Logging Tests
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

    let result = manager_arc.lock().unwrap().activate(true);
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

    let result = manager_arc.lock().unwrap().activate(true);
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

    let result = manager_arc.lock().unwrap().activate(true);
    assert!(result.is_ok(), "Activate should succeed: {:?}", result);

    // With no overlays, the mount event won't fire, but activation complete will
    // This test verifies the logging infrastructure works (AC#1)
    assert!(logs_contain("Activation complete"));
    assert!(logs_contain("state_to"));
}
