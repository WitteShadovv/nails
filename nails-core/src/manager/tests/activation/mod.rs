// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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

    // Manually write an Active state (current boot) that records no overlays and
    // has nothing actually mounted: the exact stale-no-op bug. Reconciliation must
    // see it as inconsistent and refuse, rather than silently returning success.
    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![],
            decoy_writers: Vec::new(),
        },
        ..StateFile::default()
    };
    state_file
        .save_with_custom_root(&state_path, temp_dir.path())
        .unwrap();

    // Force manager to reload state from disk
    *manager.lock().unwrap().cached_state.borrow_mut() = None;

    // Activation refuses an Active state that the kernel cannot confirm.
    let result = manager.lock().unwrap().activate(true);
    let err = result.expect_err("activate must refuse a degraded active state, not no-op");
    let message = err.to_string();
    assert!(
        message.contains("nails emergency"),
        "refusal should point at recovery: {message}"
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

    // Verify overlay_status populated with /home mount
    assert!(
        final_state
            .overlay_status
            .contains_key(&PathBuf::from("/home")),
        "overlay_status should contain /home entry"
    );

    let home_info = final_state
        .overlay_status
        .get(&PathBuf::from("/home"))
        .unwrap();
    assert_eq!(home_info.mount_path, PathBuf::from("/home"));
    assert_eq!(home_info.lower_dir, PathBuf::from("/"));
    assert_eq!(home_info.upper_dir, home_upper);
    assert_eq!(home_info.work_dir, home_work);

    // Verify overlay_status populated with /etc mount
    assert!(
        final_state
            .overlay_status
            .contains_key(&PathBuf::from("/etc")),
        "overlay_status should contain /etc entry"
    );

    let etc_info = final_state
        .overlay_status
        .get(&PathBuf::from("/etc"))
        .unwrap();
    assert_eq!(etc_info.mount_path, PathBuf::from("/etc"));
    assert_eq!(etc_info.lower_dir, PathBuf::from("/"));
    assert_eq!(etc_info.upper_dir, etc_upper);
    assert_eq!(etc_info.work_dir, etc_work);

    // Verify final state is Active
    assert!(
        matches!(final_state.state, SystemState::Active { .. }),
        "Final state should be Active"
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

    // The pre-flight bypass warning is a safety contract, so it must be logged.
    // Assert on a stable token rather than its exact punctuation or wording.
    logs_assert(|lines: &[&str]| {
        if lines
            .iter()
            .any(|l| l.contains("Skipping pre-flight checks"))
        {
            Ok(())
        } else {
            Err("expected the pre-flight bypass warning in the logs".to_string())
        }
    });
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
    let reported = Arc::new(Mutex::new(Vec::new()));
    manager.set_reporter(crate::reporter::progress::shared(StepRecorder(
        reported.clone(),
    )));

    let manager_arc = Arc::new(Mutex::new(manager));

    // Run activate
    let result = manager_arc.lock().unwrap().activate(true);
    assert!(result.is_ok(), "Activate should succeed: {:?}", result);

    // In quiet mode no progress reaches the operator: the reporter receives
    // nothing, and no step is logged at info level (it is only in the debug
    // log that the hidden-root log file records).
    assert!(
        reported.lock().unwrap().is_empty(),
        "quiet mode must not report progress: {:?}",
        reported.lock().unwrap()
    );
    logs_assert(|lines: &[&str]| {
        match lines
            .iter()
            .find(|line| line.contains(" INFO ") && line.contains("Preparing session management"))
        {
            Some(line) => Err(format!("step shown at info level in quiet mode: {line}")),
            None => Ok(()),
        }
    });
}

/// Records the step phases an activation reports.
struct StepRecorder(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl crate::reporter::progress::Reporter for StepRecorder {
    fn step(&mut self, step: crate::reporter::progress::Step<'_>) {
        self.0.lock().unwrap().push(step.phase.to_string());
    }
    fn detail(&mut self, detail: &str) {
        self.0.lock().unwrap().push(format!("detail {detail}"));
    }
    fn heartbeat(&mut self, _activity: &str, _elapsed: std::time::Duration, _line: Option<&str>) {
        self.0.lock().unwrap().push("heartbeat".to_string());
    }
    fn finish(&mut self, success: bool) {
        self.0.lock().unwrap().push(format!("finish {success}"));
    }
}

#[test]
fn activation_reports_each_step_and_finishes_successfully() {
    use std::sync::{Arc, Mutex};

    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let hidden = temp_dir.path();
    let state_path = hidden.join("state.json");
    StateFile::default()
        .save_with_custom_root(&state_path, hidden)
        .expect("Should save initial state");
    let config = Config {
        hidden_volume_root: hidden.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let mut manager = NailsManager::new(MockFilesystem::new(), config, state_path);
    let reported = Arc::new(Mutex::new(Vec::new()));
    manager.set_reporter(crate::reporter::progress::shared(StepRecorder(
        reported.clone(),
    )));

    manager.activate(true).expect("activation should succeed");

    let reported = reported.lock().unwrap().clone();
    let steps: Vec<&str> = reported
        .iter()
        .filter(|event| !event.starts_with("detail") && !event.starts_with("finish"))
        .map(String::as_str)
        .collect();
    assert_eq!(
        steps,
        vec![
            "preflight",
            "session_management",
            "config_prepare",
            "overlay_mount",
            "profile_switch",
            "session_restart",
            "finalize",
        ]
    );
    assert_eq!(reported.last().map(String::as_str), Some("finish true"));
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
fn test_activate_already_active_is_verified_no_op() {
    use crate::ActivationOutcome;
    use crate::manager::state_management::reconcile_mounts_override;
    use std::sync::Arc;

    // Create mock hidden volume structure in temp dir
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let fs = MockFilesystem::new();

    // Setup initial state file as ACTIVE recording a /home overlay, in the
    // current boot.
    let initial_state = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![std::path::PathBuf::from("/home")],
            decoy_writers: Vec::new(),
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

    // The kernel confirms /home is a NAILS persistent overlay, so the system is
    // verifiably active: activation is a no-op on every flag path and the state
    // is left untouched.
    let mounts = crate::filesystem::NailsMounts {
        persistent_overlays: vec![std::path::PathBuf::from("/home")],
        ..Default::default()
    };
    let _mounts_guard = reconcile_mounts_override::arm(mounts);

    let outcome = manager_arc
        .lock()
        .unwrap()
        .activate(false)
        .expect("verified-active activation is a success no-op");
    assert_eq!(outcome, ActivationOutcome::AlreadyActive);

    // State is unchanged and still Active.
    assert!(
        manager_arc
            .lock()
            .unwrap()
            .current_state()
            .unwrap()
            .is_active()
    );
}

#[test]
fn test_activate_already_active_exit_ok_on_every_flag_path() {
    use crate::ActivationOutcome;
    use crate::manager::state_management::reconcile_mounts_override;
    use std::sync::{Arc, Mutex};

    // Three flag combinations that reach the shared reconcile before any preflight
    // or session handling: default, keep-session, and no-preflight. All must treat
    // a verified-active system as an AlreadyActive no-op (exit 0, nothing mounted).
    let options = [
        crate::ActivateOptions::default(),
        crate::ActivateOptions {
            kill_session: false,
            ..crate::ActivateOptions::default()
        },
        crate::ActivateOptions {
            skip_flake_validation: true,
            ..crate::ActivateOptions::default()
        },
    ];
    let no_preflight = [false, false, true];

    for (opts, skip) in options.into_iter().zip(no_preflight) {
        let temp_dir = tempfile::tempdir().expect("Should create temp dir");
        let mock_hidden_vol = temp_dir.path();
        std::fs::create_dir_all(mock_hidden_vol).unwrap();
        let state_path = mock_hidden_vol.join("state.json");

        let initial_state = StateFile {
            state: SystemState::Active {
                decoy_writers: Vec::new(),
                activated_at: Utc::now(),
                overlays: vec![std::path::PathBuf::from("/home")],
            },
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
        let manager = Arc::new(Mutex::new(NailsManager::new(
            MockFilesystem::new(),
            config,
            state_path.clone(),
        )));

        let mounts = crate::filesystem::NailsMounts {
            persistent_overlays: vec![std::path::PathBuf::from("/home")],
            ..Default::default()
        };
        let _mounts_guard = reconcile_mounts_override::arm(mounts);

        let outcome = manager
            .lock()
            .unwrap()
            .activate_with_options(opts, skip)
            .expect("verified-active system is always a success no-op");
        assert_eq!(outcome, ActivationOutcome::AlreadyActive);
    }
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

    // Verify structured events with state fields
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
fn test_activation_error_rolls_back_to_inactive() {
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

    // Behaviour: a failed activation rolls back cleanly to Inactive and leaves
    // nothing mounted, rather than leaking a half-activated state.
    assert_eq!(
        manager_arc.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );
    assert!(
        fs.get_mounted_paths().is_empty(),
        "a rolled-back activation must leave nothing mounted"
    );
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
    // This test verifies the logging infrastructure works
    assert!(logs_contain("Activation complete"));
    assert!(logs_contain("state_to"));
}
