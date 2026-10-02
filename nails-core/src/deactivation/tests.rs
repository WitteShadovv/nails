//! Tests for deactivation module
//!
//! # Test Safety Notice
//!
//! Tests in this module MUST use `cleanup::test_utils::TEST_HOME` and
//! `cleanup::test_utils::set_safe_test_home()` instead of reading the real HOME
//! environment variable. This prevents tests from accidentally operating on real
//! user history files.

use super::test_gate::{
    DeactivationGateTestGuard, maybe_block_after_deactivating_state_transition,
};
use super::{DeactivationReport, PostUnmountCleanupReport};
use crate::DeactivationOrchestrator;
use crate::cleanup::test_utils::{TEST_HOME, assert_path_is_safe, set_safe_test_home};
use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
use crate::filesystem::{Filesystem, PathKind};
use crate::test_support::EnvGuard;
use crate::{
    CleanupConfig, CleanupMode, CleanupReport, Config, MockFilesystem, NailsError, NailsManager,
    StateFile, SystemState,
};
use serial_test::serial;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Helper function to check if logs contain a specific string
/// This works with tracing-test's captured output
#[allow(dead_code)]
fn logs_contain(s: &str) -> bool {
    tracing_test::internal::logs_with_scope_contain("", s)
}

/// Takes the environment lock with the deactivation gate variables pointing at
/// the given paths, or removed when `None`; dropping the guard restores them.
fn deactivation_gate_env(gate_path: Option<&Path>, entered_path: Option<&Path>) -> EnvGuard {
    let mut env = EnvGuard::lock();
    for (key, value) in [
        ("NAILS_TEST_DEACTIVATING_GATE_PATH", gate_path),
        ("NAILS_TEST_DEACTIVATING_ENTERED_PATH", entered_path),
    ] {
        match value {
            Some(path) => env.set(key, path),
            None => env.remove(key),
        };
    }
    env
}

fn spawn_deactivation_gate_releaser(
    gate_path: PathBuf,
    entered_path: PathBuf,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        for _ in 0..100 {
            if entered_path.exists() {
                break;
            }

            std::thread::sleep(Duration::from_millis(10));
        }

        if gate_path.exists() {
            std::fs::remove_file(&gate_path).expect("gate file should be removable");
        }
    })
}

/// A configured stub system profile for decoy switching. Holds the backing
/// temp dir and the environment override; both are cleaned up on drop, so the
/// profile lives exactly as long as the test that owns it.
struct SystemProfileStub {
    _dir: tempfile::TempDir,
    _env: EnvGuard,
}

/// Helper function to configure a stub system profile for decoy switching.
fn setup_system_profile_stub(fs: &MockFilesystem) -> SystemProfileStub {
    let profile_root = tempfile::tempdir().expect("tempdir");
    let system_profile_path = profile_root.path().join("system");
    let mut env_guard = EnvGuard::lock();
    env_guard.set("NAILS_SYSTEM_PROFILE_PATH", &system_profile_path);

    let profiles_dir = system_profile_path
        .parent()
        .expect("profile root")
        .to_path_buf();
    let system_link = profiles_dir.join("system-1-link");
    let bin_dir = system_link.join("bin");
    let switch_script = bin_dir.join("switch-to-configuration");

    fs::create_dir_all(&bin_dir).expect("create stub bin dir");
    fs::write(&switch_script, "#!/bin/sh\nexit 0\n").expect("write stub switch script");
    let mut perms = fs::metadata(&switch_script)
        .expect("stat switch script")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&switch_script, perms).expect("chmod switch script");

    fs.mock_set_path_exists(profiles_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(profiles_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_directory_contents(&profiles_dir, vec![system_link]);
    fs.mock_set_path_exists(switch_script.to_str().unwrap(), true);
    fs.mock_set_path_type(switch_script.to_str().unwrap(), PathKind::File);

    SystemProfileStub {
        _dir: profile_root,
        _env: env_guard,
    }
}

/// A manager wired up for a test together with the temporary state directory
/// (and optional system-profile stub) that must outlive it. Dereferences to the
/// `Arc<Mutex<..>>` so call sites use it exactly like the bare manager handle.
struct ManagerFixture {
    manager: Arc<Mutex<NailsManager<MockFilesystem>>>,
    _hidden_root: tempfile::TempDir,
    _profile: Option<SystemProfileStub>,
}

impl std::ops::Deref for ManagerFixture {
    type Target = Arc<Mutex<NailsManager<MockFilesystem>>>;

    fn deref(&self) -> &Self::Target {
        &self.manager
    }
}

/// Helper function to create a test manager in ACTIVE state
fn setup_active_manager() -> ManagerFixture {
    let fs = MockFilesystem::new();
    let profile = setup_system_profile_stub(&fs);

    // Setup mock filesystem for active state
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
    fs.mock_set_path_exists("/mnt/hidden-volume", true);
    fs.mock_set_path_type(DEFAULT_HIDDEN_VOLUME_ROOT, PathKind::Dir);
    fs.mock_set_path_type("/mnt/hidden-volume", PathKind::Dir);

    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path().to_path_buf();
    std::fs::create_dir_all(&mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let config = Config {
        hidden_volume_root: mock_hidden_vol.clone(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let mut manager = NailsManager::new(fs, config, state_path);

    // Set state to ACTIVE
    manager
        .force_state(SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
        })
        .unwrap();

    ManagerFixture {
        manager: Arc::new(Mutex::new(manager)),
        _hidden_root: temp_dir,
        _profile: Some(profile),
    }
}

fn setup_manager_in_state(state: SystemState) -> ManagerFixture {
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);

    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path().to_path_buf();
    std::fs::create_dir_all(&mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let config = Config {
        hidden_volume_root: mock_hidden_vol.clone(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let mut manager = NailsManager::new(fs, config, state_path);
    manager.force_state(state).unwrap();

    ManagerFixture {
        manager: Arc::new(Mutex::new(manager)),
        _hidden_root: temp_dir,
        _profile: None,
    }
}

fn write_state_with_overlay(
    state_path: &Path,
    hidden_root: &Path,
    target: &Path,
    upper_dir: &Path,
    work_dir: &Path,
) {
    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(
        target.to_path_buf(),
        crate::OverlayInfo {
            mount_path: target.to_path_buf(),
            lower_dir: PathBuf::from("/"),
            upper_dir: upper_dir.to_path_buf(),
            work_dir: work_dir.to_path_buf(),
            mounted_at: chrono::Utc::now(),
        },
    );

    StateFile {
        state: SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![target.to_path_buf()],
        },
        overlay_status,
        ..StateFile::default()
    }
    .save_with_custom_root(state_path, hidden_root)
    .unwrap();
}

fn set_state_nixos_generation(state_path: &Path, hidden_root: &Path, generation: &str) {
    let mut loaded = StateFile::load(state_path).unwrap();
    loaded.nixos_generation = Some(generation.to_string());
    loaded
        .save_with_custom_root(state_path, hidden_root)
        .unwrap();
}

#[test]
#[serial]
fn test_deactivation_report_new() {
    let report = DeactivationReport {
        cleanup_report: CleanupReport::default(),
        unmounted_overlays: vec!["/home".to_string(), "/etc".to_string()],
        failed_overlays: Vec::new(),
        remaining_mounts: Vec::new(),
        duration: Duration::from_millis(150),
        final_state: SystemState::Inactive,
        was_already_inactive: false,
        post_unmount_cleanup: PostUnmountCleanupReport::default(),
    };

    assert!(report.is_successful());
    assert_eq!(report.unmounted_overlays.len(), 2);
    assert!(!report.was_already_inactive);
}

#[test]
#[serial]
fn test_deactivation_gate_returns_immediately_when_disabled() {
    let _gate_guard = DeactivationGateTestGuard::enable();
    let _env = deactivation_gate_env(None, None);

    assert!(maybe_block_after_deactivating_state_transition().is_ok());
}

#[test]
#[serial]
fn test_deactivation_gate_writes_default_entered_marker() {
    let _gate_guard = DeactivationGateTestGuard::enable();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let gate_path = temp_dir.path().join("deactivation.gate");
    let entered_path = PathBuf::from(format!("{}.entered", gate_path.display()));
    std::fs::write(&gate_path, []).expect("gate file");
    let _env = deactivation_gate_env(Some(&gate_path), None);

    let releaser = spawn_deactivation_gate_releaser(gate_path.clone(), entered_path.clone());
    maybe_block_after_deactivating_state_transition().expect("gate should be released");
    releaser.join().expect("releaser thread should finish");

    assert!(
        entered_path.exists(),
        "default entered marker should be created"
    );
    assert!(!gate_path.exists(), "gate should be removed by releaser");
}

#[test]
#[serial]
fn test_deactivation_report_display_already_inactive() {
    let report = DeactivationReport {
        cleanup_report: CleanupReport::default(),
        unmounted_overlays: Vec::new(),
        failed_overlays: Vec::new(),
        remaining_mounts: Vec::new(),
        duration: Duration::from_millis(5),
        final_state: SystemState::Inactive,
        was_already_inactive: true,
        post_unmount_cleanup: PostUnmountCleanupReport::default(),
    };

    let output = format!("{}", report);
    assert!(output.contains("Already inactive"));
}

#[test]
#[serial]
fn test_deactivation_report_display_with_items() {
    let mut cleanup_report = CleanupReport::new(CleanupMode::Fast);
    cleanup_report.add_cleaned("Removed 3 history entries");
    cleanup_report.duration = Duration::from_millis(100);

    let report = DeactivationReport {
        cleanup_report,
        unmounted_overlays: vec!["/home".to_string(), "/etc".to_string()],
        failed_overlays: Vec::new(),
        remaining_mounts: Vec::new(),
        duration: Duration::from_millis(150),
        final_state: SystemState::Inactive,
        was_already_inactive: false,
        post_unmount_cleanup: PostUnmountCleanupReport::default(),
    };

    let output = format!("{}", report);
    assert!(output.contains("Deactivation Report"));
    assert!(output.contains("Removed 3 history entries"));
    assert!(output.contains("/home"));
    assert!(output.contains("/etc"));
    assert!(output.contains("Deactivation complete"));
}

#[test]
#[serial]
fn test_deactivation_orchestrator_new() {
    let _manager = setup_active_manager();
    let config = CleanupConfig::default();

    let _orchestrator = DeactivationOrchestrator::new(config.clone());

    // Verify orchestrator is created successfully (no panic)
    // Config is private but we can test it works via run()
}

#[test]
#[serial]
fn test_idempotent_deactivation() {
    // Setup manager in INACTIVE state
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);

    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let mut manager = NailsManager::new(fs, config, state_path);
    manager.force_state(SystemState::Inactive).unwrap();

    let manager = Arc::new(Mutex::new(manager));
    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    // Run deactivation when already inactive
    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_ok());

    let report = result.unwrap();
    assert!(report.was_already_inactive);
    assert_eq!(report.final_state, SystemState::Inactive);
    assert_eq!(report.unmounted_overlays.len(), 0);
}

#[test]
#[serial]
fn test_deactivation_from_non_active_state_fails() {
    // Setup manager in ACTIVATING state (invalid for deactivation)
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);

    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let mut manager = NailsManager::new(fs, config, state_path);
    manager
        .force_state(SystemState::Activating {
            started_at: chrono::Utc::now(),
        })
        .unwrap();

    let manager = Arc::new(Mutex::new(manager));
    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    // Run deactivation from ACTIVATING state (should fail)
    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_err());

    match result {
        Err(NailsError::InvalidState(msg)) => {
            assert!(msg.contains("Cannot deactivate from state"));
            assert!(msg.contains("Must be ACTIVE"));
        }
        _ => panic!("Expected InvalidState error"),
    }
}

#[test]
#[serial]
fn test_successful_deactivation() {
    let manager = setup_active_manager();

    // Setup filesystem mocks for unmount
    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
        m.filesystem().mock_set_mounted(Path::new("/etc"), true);
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_ok());

    let report = result.unwrap();
    assert!(report.is_successful());
    assert_eq!(report.final_state, SystemState::Inactive);
    assert!(!report.was_already_inactive);

    // Verify state is now INACTIVE
    let m = manager.lock().unwrap();
    let state = m.current_state().unwrap();
    assert_eq!(state, SystemState::Inactive);
}

#[test]
#[serial]
fn test_successful_deactivation_unmounts_all_tracked_overlays_in_lifo_order() {
    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");

    let fs = MockFilesystem::new();
    let _profile = setup_system_profile_stub(&fs);

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let overlays = [
        PathBuf::from("/home"),
        PathBuf::from("/etc"),
        PathBuf::from("/tmp"),
    ];
    let mut overlay_status = std::collections::HashMap::new();
    for target in &overlays {
        let name = target
            .strip_prefix("/")
            .expect("overlay target should be absolute");
        let upper_dir = hidden_root.join("overlays").join(name).join("upper");
        let work_dir = hidden_root.join("overlays").join(name).join("work");
        std::fs::create_dir_all(&upper_dir).unwrap();
        std::fs::create_dir_all(&work_dir).unwrap();
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);
        fs.mock_set_mounted(target, true);
        overlay_status.insert(
            target.clone(),
            crate::OverlayInfo {
                mount_path: target.clone(),
                lower_dir: PathBuf::from("/"),
                upper_dir,
                work_dir,
                mounted_at: chrono::Utc::now(),
            },
        );
    }

    StateFile {
        state: SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: overlays.to_vec(),
        },
        overlay_status,
        ..StateFile::default()
    }
    .save_with_custom_root(&state_path, &hidden_root)
    .unwrap();

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));
    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    let report = orchestrator
        .run(&mut manager.lock().unwrap())
        .expect("deactivation should succeed");

    assert_eq!(
        report.unmounted_overlays,
        vec!["/tmp".to_string(), "/etc".to_string(), "/home".to_string()],
        "deactivation should unmount tracked overlays in reverse mount order"
    );

    let guard = manager.lock().unwrap();
    assert_eq!(guard.current_state().unwrap(), SystemState::Inactive);
    for target in &overlays {
        assert!(
            !guard.filesystem().is_mounted(target).unwrap(),
            "expected {} to be unmounted after deactivation",
            target.display()
        );
    }

    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded.state, SystemState::Inactive);
    assert!(loaded.overlay_status.is_empty());
}

#[test]
#[serial]
fn test_deactivation_skips_decoy_restore_when_disabled() {
    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        log_path: hidden_root.join("logs"),
        overlays: vec![],
        ..Config::test_default()
    };

    let upper_dir = hidden_root.join("overlays/home/upper");
    let work_dir = hidden_root.join("overlays/home/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);
    fs.mock_set_mounted(Path::new("/home"), true);

    write_state_with_overlay(
        &state_path,
        &hidden_root,
        Path::new("/home"),
        &upper_dir,
        &work_dir,
    );
    let mut loaded = StateFile::load(&state_path).unwrap();
    loaded.nixos_generation = Some("1".to_string());
    loaded
        .save_with_custom_root(&state_path, &hidden_root)
        .unwrap();

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));
    let orchestrator =
        DeactivationOrchestrator::new(CleanupConfig::default()).with_decoy_profile_restore(false);

    let report = orchestrator
        .run(&mut manager.lock().unwrap())
        .expect("deactivation should succeed without restoring a decoy profile");

    assert_eq!(report.final_state, SystemState::Inactive);
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );

    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded.state, SystemState::Inactive);
    assert!(loaded.overlay_status.is_empty());
}

#[test]
#[serial]
fn test_deactivation_restores_decoy_by_symlink_without_running_switch() {
    // Normal deactivation must restore the decoy by swapping the
    // /run/current-system symlink only. It must never run
    // `switch-to-configuration switch`, which would reinstall the bootloader and
    // write the ESP / EFI NVRAM. A missing switch-to-configuration script is
    // therefore no longer an error.
    let manager = setup_active_manager();

    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
        m.filesystem().mock_set_mounted(Path::new("/etc"), true);
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    let report = orchestrator
        .run(&mut manager.lock().unwrap())
        .expect("deactivation should succeed via the symlink-only decoy restore");

    assert_eq!(report.final_state, SystemState::Inactive);

    let guard = manager.lock().unwrap();
    assert_eq!(guard.current_state().unwrap(), SystemState::Inactive);
    // The decoy was restored by re-pointing /run/current-system, not by a switch.
    assert!(
        guard
            .filesystem()
            .is_symlink(Path::new("/run/current-system"))
            .unwrap()
    );
    drop(guard);
}

#[test]
#[serial]
fn test_deactivation_returns_error_when_no_decoy_profile_is_available() {
    let manager = setup_active_manager();
    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");

    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
        m.filesystem().mock_set_mounted(Path::new("/etc"), true);
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    let err = orchestrator
        .run(&mut manager.lock().unwrap())
        .expect_err("deactivation should report a missing decoy profile");

    assert!(
        err.to_string()
            .contains("No system profile available for decoy restore")
    );
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );
}

#[test]
#[serial]
fn test_deactivation_preserves_generation_and_fingerprint() {
    let fs = MockFilesystem::new();
    let _profile = setup_system_profile_stub(&fs);

    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
    fs.mock_set_path_exists("/mnt/hidden-volume", true);
    fs.mock_set_path_type(DEFAULT_HIDDEN_VOLUME_ROOT, PathKind::Dir);
    fs.mock_set_path_type("/mnt/hidden-volume", PathKind::Dir);

    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let state_file = StateFile {
        version: env!("CARGO_PKG_VERSION").to_string(),
        state: SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
        },
        nixos_generation: Some("6".to_string()),
        config_fingerprint: Some("deadbeefcafebabe".to_string()),
        overlay_status: std::collections::HashMap::new(),
        failed_overlays: Vec::new(),
        last_modified: chrono::Utc::now(),
        boot_id: None,
        owner_pid: 0,
        integrity_sha256: None,
    };
    state_file
        .save_with_custom_root(&state_path, mock_hidden_vol)
        .unwrap();

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));

    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
        m.filesystem().mock_set_mounted(Path::new("/etc"), true);
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());
    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_ok());

    let loaded = StateFile::load(
        &manager
            .lock()
            .unwrap()
            .config()
            .hidden_volume_root
            .join("state.json"),
    )
    .unwrap();
    assert_eq!(loaded.nixos_generation, Some("6".to_string()));
    assert_eq!(
        loaded.config_fingerprint,
        Some("deadbeefcafebabe".to_string())
    );
}

#[test]
#[serial]
fn test_deactivation_clears_failed_overlays_tracker_state() {
    let fs = MockFilesystem::new();
    let _profile = setup_system_profile_stub(&fs);

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![PathBuf::from("/home")],
        },
        failed_overlays: vec![crate::FailedOverlayInfo {
            target: PathBuf::from("/etc"),
            error_message: "previous failure".to_string(),
            failed_at: chrono::Utc::now(),
        }],
        ..StateFile::default()
    };
    state_file
        .save_with_custom_root(&state_path, &hidden_root)
        .unwrap();

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));
    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
    }

    let orchestrator =
        DeactivationOrchestrator::new(CleanupConfig::default()).with_decoy_profile_restore(false);

    let report = orchestrator
        .run(&mut manager.lock().unwrap())
        .expect("deactivation should succeed");
    assert_eq!(report.final_state, SystemState::Inactive);

    let loaded = StateFile::load(&state_path).unwrap();
    assert!(loaded.failed_overlays.is_empty());
    assert!(loaded.overlay_status.is_empty());
}

#[test]
#[serial]
fn test_emergency_cleanup_preserves_explicit_config_path() {
    let fs = MockFilesystem::new();
    let _profile = setup_system_profile_stub(&fs);

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let config_path = PathBuf::from("/tmp/nails-tracker-integrity.yaml");

    fs.mock_set_path_exists("/tmp", true);
    fs.mock_set_files_with_pattern(
        "/tmp",
        "nails",
        &[config_path.as_path(), Path::new("/tmp/nails-status.stdout")],
    );
    fs.mock_set_path_exists(config_path.to_str().unwrap(), true);
    fs.mock_set_path_type(config_path.to_str().unwrap(), PathKind::File);
    fs.mock_set_path_exists("/tmp/nails-status.stdout", true);
    fs.mock_set_path_type("/tmp/nails-status.stdout", PathKind::File);

    let state_file = StateFile {
        state: SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![PathBuf::from("/home")],
        },
        ..StateFile::default()
    };
    state_file
        .save_with_custom_root(&state_path, &hidden_root)
        .unwrap();

    let mut config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    config.loaded_config_path = Some(config_path.clone());

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));
    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
    }

    manager
        .lock()
        .unwrap()
        .emergency_deactivate()
        .expect("emergency deactivation should succeed");

    let m = manager.lock().unwrap();
    assert!(
        m.filesystem()
            .path_exists(&config_path)
            .expect("config path query should succeed"),
        "explicit config path should survive emergency cleanup"
    );
    assert!(
        !m.filesystem()
            .path_exists(Path::new("/tmp/nails-status.stdout"))
            .expect("temp status file query should succeed"),
        "other temp files should still be cleaned"
    );
}

#[test]
#[serial]
fn test_cleanup_failure_rollback() {
    let manager = setup_active_manager();
    // Cleanup resolves the history files from HOME, so it points at the fake
    // home for the whole test.
    let _home = set_safe_test_home();

    // Configure cleanup to FAIL by making the history file write fail
    // This triggers AC4: cleanup failure → rollback to ACTIVE
    {
        let m = manager.lock().unwrap();
        let bash_history = Path::new(TEST_HOME).join(".bash_history");
        let bash_history_str = bash_history.to_str().unwrap();

        // Validate path safety before using
        assert_path_is_safe(bash_history_str);

        // Set up history file that exists with "nails" content
        m.filesystem().mock_set_path_exists(bash_history_str, true);

        // Set up file content that contains "nails" pattern
        m.filesystem()
            .mock_set_file_content(bash_history_str, "nails activate\nsome other command\n");

        // Make write fail so cleanup can't actually clean the file
        // This simulates a permission error or filesystem issue during cleanup
        m.filesystem()
            .mock_set_write_should_fail(bash_history_str, true);
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    let result = orchestrator.run(&mut manager.lock().unwrap());

    // AC4: Cleanup failure should cause deactivation to fail and rollback to ACTIVE
    // This is required for forensic safety - if traces can't be cleaned, we must
    // remain in ACTIVE state with overlays mounted
    assert!(
        result.is_err(),
        "Expected cleanup to fail, got: {:?}",
        result
    );

    // Verify it's a CleanupError
    match &result {
        Err(NailsError::CleanupError(msg)) => {
            assert!(
                msg.contains("Overlays remain mounted") || msg.contains("verification failed"),
                "Expected error message about rollback, got: {}",
                msg
            );
        }
        _ => panic!("Expected CleanupError, got: {:?}", result),
    }

    // Verify state rolled back to ACTIVE via StateGuard RAII
    // AC4: "StateGuard automatically rolls back to ACTIVE"
    let m = manager.lock().unwrap();
    let state = m.current_state().unwrap();
    assert!(
        state.is_active(),
        "AC4 violation: Expected ACTIVE state after cleanup failure, got {:?}",
        state
    );
}

#[test]
#[serial]
fn test_cleanup_failure_keeps_overlays_mounted() {
    // Additional test for AC4: verify overlays remain mounted after cleanup failure
    let manager = setup_active_manager();
    // Cleanup resolves the history files from HOME, so it points at the fake
    // home for the whole test.
    let _home = set_safe_test_home();

    // Setup overlays as mounted
    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
        m.filesystem().mock_set_mounted(Path::new("/etc"), true);

        // Configure cleanup to fail by making write fail
        let bash_history = Path::new(TEST_HOME).join(".bash_history");
        let bash_history_str = bash_history.to_str().unwrap();

        // Validate path safety before using
        assert_path_is_safe(bash_history_str);

        m.filesystem().mock_set_path_exists(bash_history_str, true);
        m.filesystem()
            .mock_set_file_content(bash_history_str, "nails activate\nsome command\n");
        // Make write fail so cleanup can't actually clean the file
        m.filesystem()
            .mock_set_write_should_fail(bash_history_str, true);
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    let _result = orchestrator.run(&mut manager.lock().unwrap());

    // Verify overlays are still mounted (AC4: "overlays are NOT unmounted")
    let m = manager.lock().unwrap();
    let fs = m.filesystem();
    assert!(
        fs.is_mounted(Path::new("/home")).unwrap(),
        "AC4 violation: /home should remain mounted after cleanup failure"
    );
    assert!(
        fs.is_mounted(Path::new("/etc")).unwrap(),
        "AC4 violation: /etc should remain mounted after cleanup failure"
    );
}

#[test]
#[serial]
fn test_emergency_deactivate_from_inactive_state_returns_error() {
    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);

    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");
    let config = Config {
        hidden_volume_root: temp_dir.path().to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));

    let err = manager.lock().unwrap().emergency_deactivate().unwrap_err();
    assert!(matches!(err, NailsError::InvalidState(_)));
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );
}

#[test]
#[serial]
fn test_emergency_deactivate_from_activating_state_returns_error_without_unmounting() {
    let manager = setup_manager_in_state(SystemState::Activating {
        started_at: chrono::Utc::now(),
    });

    {
        let guard = manager.lock().unwrap();
        let fs = guard.filesystem();
        fs.mock_set_mounted(Path::new("/home"), true);
        fs.mock_set_mounted(Path::new("/etc"), true);
    }

    let err = manager.lock().unwrap().emergency_deactivate().unwrap_err();
    assert!(matches!(err, NailsError::InvalidState(_)));
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("Activating"),
        "unexpected error: {err_msg}"
    );
    assert!(
        err_msg.contains("Must be ACTIVE"),
        "unexpected error: {err_msg}"
    );

    let guard = manager.lock().unwrap();
    assert!(matches!(
        guard.current_state().unwrap(),
        SystemState::Activating { .. }
    ));
    assert!(guard.filesystem().is_mounted(Path::new("/home")).unwrap());
    assert!(guard.filesystem().is_mounted(Path::new("/etc")).unwrap());
}

#[test]
#[serial]
fn test_emergency_deactivate_from_deactivating_state_returns_error_without_unmounting() {
    let manager = setup_manager_in_state(SystemState::Deactivating {
        started_at: chrono::Utc::now(),
    });

    {
        let guard = manager.lock().unwrap();
        let fs = guard.filesystem();
        fs.mock_set_mounted(Path::new("/home"), true);
        fs.mock_set_mounted(Path::new("/etc"), true);
    }

    let err = manager.lock().unwrap().emergency_deactivate().unwrap_err();
    assert!(matches!(err, NailsError::InvalidState(_)));
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("Deactivating"),
        "unexpected error: {err_msg}"
    );
    assert!(
        err_msg.contains("Must be ACTIVE"),
        "unexpected error: {err_msg}"
    );

    let guard = manager.lock().unwrap();
    assert!(matches!(
        guard.current_state().unwrap(),
        SystemState::Deactivating { .. }
    ));
    assert!(guard.filesystem().is_mounted(Path::new("/home")).unwrap());
    assert!(guard.filesystem().is_mounted(Path::new("/etc")).unwrap());
}

#[test]
#[serial]
fn test_emergency_deactivate_force_unmount_succeeds_after_graceful_failure() {
    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");

    let fs = MockFilesystem::new();
    let _profile = setup_system_profile_stub(&fs);
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let upper_dir = hidden_root.join("overlays/home/upper");
    let work_dir = hidden_root.join("overlays/home/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    write_state_with_overlay(
        &state_path,
        &hidden_root,
        Path::new("/home"),
        &upper_dir,
        &work_dir,
    );

    let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));

    {
        let manager_guard = manager.lock().unwrap();
        let fs = manager_guard.filesystem();
        fs.mock_set_mounted(Path::new("/home"), true);
        fs.mock_set_unmount_graceful_fails("/home", true);
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);
    }

    manager
        .lock()
        .unwrap()
        .emergency_deactivate()
        .expect("deactivation should work");

    let manager_guard = manager.lock().unwrap();
    assert_eq!(
        manager_guard.current_state().unwrap(),
        SystemState::Inactive
    );
    assert!(
        !manager_guard
            .filesystem()
            .is_mounted(Path::new("/home"))
            .unwrap()
    );
    let loaded =
        StateFile::load(&manager_guard.config().hidden_volume_root.join("state.json")).unwrap();
    assert!(loaded.overlay_status.is_empty());
}

#[test]
#[serial]
fn test_deactivate_returns_error_when_no_system_profile_exists() {
    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);

    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");
    let config = Config {
        hidden_volume_root: temp_dir.path().to_path_buf(),
        state_file_path: state_path.clone(),
        log_path: temp_dir.path().join("logs"),
        overlays: vec![],
        ..Config::test_default()
    };

    let active_state = SystemState::Active {
        activated_at: chrono::Utc::now(),
        overlays: vec![],
    };
    StateFile {
        state: active_state,
        nixos_generation: Some("1".to_string()),
        ..StateFile::default()
    }
    .save_with_custom_root(&state_path, temp_dir.path())
    .unwrap();

    let manager_inner = NailsManager::new(fs, config, state_path);
    let manager = Arc::new(Mutex::new(manager_inner));

    let err = manager.lock().unwrap().deactivate().unwrap_err();
    assert!(
        err.to_string()
            .contains("No system profile found. Cannot restore decoy configuration.")
    );
    assert!(manager.lock().unwrap().current_state().unwrap().is_active());
}

#[test]
#[serial]
fn test_deactivate_overlay_only_session_succeeds_without_system_profile() {
    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        log_path: hidden_root.join("logs"),
        overlays: vec![],
        ..Config::test_default()
    };

    let upper_dir = hidden_root.join("overlays/home/upper");
    let work_dir = hidden_root.join("overlays/home/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    write_state_with_overlay(
        &state_path,
        &hidden_root,
        Path::new("/home"),
        &upper_dir,
        &work_dir,
    );
    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));

    {
        let manager_guard = manager.lock().unwrap();
        let fs = manager_guard.filesystem();
        fs.mock_set_mounted(Path::new("/home"), true);
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);
    }

    manager
        .lock()
        .unwrap()
        .deactivate()
        .expect("overlay-only deactivation should work");

    let manager_guard = manager.lock().unwrap();
    assert_eq!(
        manager_guard.current_state().unwrap(),
        SystemState::Inactive
    );
    assert!(
        !manager_guard
            .filesystem()
            .is_mounted(Path::new("/home"))
            .unwrap()
    );

    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded.state, SystemState::Inactive);
    assert!(loaded.overlay_status.is_empty());
}

#[test]
#[serial]
fn test_deactivate_does_not_reboot_when_decoy_switch_fails() {
    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");

    let fs = MockFilesystem::new();
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let system_profile = hidden_root.join("profiles/system");
    let reboot_script = hidden_root.join("bin/reboot");
    let reboot_marker = hidden_root.join("reboot-called.txt");

    std::fs::create_dir_all(reboot_script.parent().unwrap()).unwrap();
    std::fs::write(
        &reboot_script,
        format!(
            "#!/usr/bin/env bash\n: > '{}'\nexit 0\n",
            reboot_marker.display()
        ),
    )
    .unwrap();
    let mut reboot_perms = std::fs::metadata(&reboot_script).unwrap().permissions();
    reboot_perms.set_mode(0o755);
    std::fs::set_permissions(&reboot_script, reboot_perms).unwrap();

    env.set("NAILS_SYSTEM_PROFILE_PATH", &system_profile)
        .set("NAILS_REBOOT_PATH", &reboot_script);

    fs.mock_set_path_exists(hidden_root.to_str().unwrap(), true);
    fs.mock_set_path_exists(system_profile.parent().unwrap().to_str().unwrap(), true);
    fs.mock_set_path_type(
        system_profile.parent().unwrap().to_str().unwrap(),
        PathKind::Dir,
    );
    fs.mock_set_directory_contents(system_profile.parent().unwrap(), vec![]);

    let upper_dir = hidden_root.join("overlays/home/upper");
    let work_dir = hidden_root.join("overlays/home/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    write_state_with_overlay(
        &state_path,
        &hidden_root,
        Path::new("/home"),
        &upper_dir,
        &work_dir,
    );

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        Config {
            hidden_volume_root: hidden_root.clone(),
            state_file_path: state_path.clone(),
            log_path: hidden_root.join("logs"),
            overlays: vec![],
            ..Config::test_default()
        },
        state_path.clone(),
    )));

    {
        let guard = manager.lock().unwrap();
        guard
            .filesystem()
            .mock_set_mounted(Path::new("/home"), true);
        guard
            .filesystem()
            .mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        guard
            .filesystem()
            .mock_set_path_exists(work_dir.to_str().unwrap(), true);
    }
    set_state_nixos_generation(&state_path, &hidden_root, "1");

    let err = manager
        .lock()
        .unwrap()
        .deactivate()
        .expect_err("normal deactivation should fail when no decoy profile is available");
    let err_text = err.to_string();
    assert!(
        err_text.contains("No system profile available for decoy restore")
            || err_text.contains("No system profile found. Cannot restore decoy configuration."),
        "unexpected error: {err_text}"
    );
    assert!(
        !reboot_marker.exists(),
        "reboot must not be requested on failure"
    );
    assert!(manager.lock().unwrap().current_state().unwrap().is_active());
}

#[test]
#[serial]
fn test_deactivate_prepares_decoy_symlink_when_restore_is_required() {
    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");

    let fs = MockFilesystem::new();
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let profile_root = hidden_root.join("profiles/system-1-link");
    let system_profile = hidden_root.join("profiles/system");
    let switch_script = profile_root.join("bin/switch-to-configuration");

    std::fs::create_dir_all(switch_script.parent().unwrap()).unwrap();
    std::fs::write(&switch_script, "#!/usr/bin/env bash\nexit 0\n").unwrap();
    let mut perms = std::fs::metadata(&switch_script).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&switch_script, perms).unwrap();

    env.set("NAILS_SYSTEM_PROFILE_PATH", &system_profile);

    fs.mock_set_path_exists(hidden_root.to_str().unwrap(), true);
    fs.mock_set_path_exists(system_profile.parent().unwrap().to_str().unwrap(), true);
    fs.mock_set_path_type(
        system_profile.parent().unwrap().to_str().unwrap(),
        PathKind::Dir,
    );
    fs.mock_set_directory_contents(system_profile.parent().unwrap(), vec![profile_root.clone()]);
    fs.mock_set_path_exists(profile_root.to_str().unwrap(), true);
    fs.mock_set_path_type(profile_root.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_path_exists(switch_script.to_str().unwrap(), true);
    fs.mock_set_path_type(switch_script.to_str().unwrap(), PathKind::File);

    let upper_dir = hidden_root.join("overlays/home/upper");
    let work_dir = hidden_root.join("overlays/home/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    write_state_with_overlay(
        &state_path,
        &hidden_root,
        Path::new("/home"),
        &upper_dir,
        &work_dir,
    );
    set_state_nixos_generation(&state_path, &hidden_root, "1");

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        Config {
            hidden_volume_root: hidden_root.clone(),
            state_file_path: state_path.clone(),
            log_path: hidden_root.join("logs"),
            overlays: vec![],
            ..Config::test_default()
        },
        state_path.clone(),
    )));

    {
        let guard = manager.lock().unwrap();
        guard
            .filesystem()
            .mock_set_mounted(Path::new("/home"), true);
        guard
            .filesystem()
            .mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        guard
            .filesystem()
            .mock_set_path_exists(work_dir.to_str().unwrap(), true);
    }

    manager
        .lock()
        .unwrap()
        .deactivate()
        .expect("normal deactivation should succeed");

    assert_eq!(
        manager
            .lock()
            .unwrap()
            .filesystem()
            .mock_get_symlink_target(Path::new("/run/current-system"))
            .as_deref(),
        Some(profile_root.as_path())
    );
}

#[test]
#[serial]
fn test_deactivate_uses_overlay_metadata_when_active_overlay_list_is_incomplete() {
    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");

    let fs = MockFilesystem::new();
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");

    let upper_home = hidden_root.join("overlays/home/upper");
    let work_home = hidden_root.join("overlays/home/work");
    let upper_etc = hidden_root.join("overlays/etc/upper");
    let work_etc = hidden_root.join("overlays/etc/work");
    std::fs::create_dir_all(&upper_home).unwrap();
    std::fs::create_dir_all(&work_home).unwrap();
    std::fs::create_dir_all(&upper_etc).unwrap();
    std::fs::create_dir_all(&work_etc).unwrap();

    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        crate::OverlayInfo {
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/"),
            upper_dir: upper_home.clone(),
            work_dir: work_home.clone(),
            mounted_at: chrono::Utc::now(),
        },
    );
    overlay_status.insert(
        PathBuf::from("/etc"),
        crate::OverlayInfo {
            mount_path: PathBuf::from("/etc"),
            lower_dir: PathBuf::from("/"),
            upper_dir: upper_etc.clone(),
            work_dir: work_etc.clone(),
            mounted_at: chrono::Utc::now() + chrono::TimeDelta::milliseconds(1),
        },
    );

    StateFile {
        state: SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![PathBuf::from("/home")],
        },
        overlay_status,
        ..StateFile::default()
    }
    .save_with_custom_root(&state_path, &hidden_root)
    .unwrap();

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        Config {
            hidden_volume_root: hidden_root.clone(),
            state_file_path: state_path.clone(),
            log_path: hidden_root.join("logs"),
            overlays: vec![],
            ..Config::test_default()
        },
        state_path.clone(),
    )));

    {
        let guard = manager.lock().unwrap();
        guard
            .filesystem()
            .mock_set_mounted(Path::new("/home"), true);
        guard.filesystem().mock_set_mounted(Path::new("/etc"), true);
        guard
            .filesystem()
            .mock_set_path_exists(upper_home.to_str().unwrap(), true);
        guard
            .filesystem()
            .mock_set_path_exists(work_home.to_str().unwrap(), true);
        guard
            .filesystem()
            .mock_set_path_exists(upper_etc.to_str().unwrap(), true);
        guard
            .filesystem()
            .mock_set_path_exists(work_etc.to_str().unwrap(), true);
    }

    let report = DeactivationOrchestrator::new(CleanupConfig::default())
        .with_decoy_profile_restore(false)
        .run(&mut manager.lock().unwrap())
        .expect("deactivation should use tracked overlay metadata");

    assert_eq!(
        report.unmounted_overlays,
        vec!["/etc".to_string(), "/home".to_string()]
    );
    let guard = manager.lock().unwrap();
    assert!(!guard.filesystem().is_mounted(Path::new("/home")).unwrap());
    assert!(!guard.filesystem().is_mounted(Path::new("/etc")).unwrap());
}

#[test]
#[serial]
fn test_emergency_deactivate_restarts_nix_daemon_when_nix_store_unmount_fails() {
    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");

    let fs = MockFilesystem::new();
    let _profile = setup_system_profile_stub(&fs);
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let upper_dir = hidden_root.join("overlays/nix/upper");
    let work_dir = hidden_root.join("overlays/nix/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    write_state_with_overlay(
        &state_path,
        &hidden_root,
        Path::new("/nix"),
        &upper_dir,
        &work_dir,
    );

    let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));

    {
        let manager_guard = manager.lock().unwrap();
        let fs = manager_guard.filesystem();
        fs.mock_set_mounted(Path::new("/nix"), true);
        fs.mock_set_mounted(Path::new("/nix/store"), true);
        // The read-only /nix/store bind refuses to unmount; teardown must treat
        // that as best-effort and still restart nix-daemon, rather than leaving
        // the decoy without a daemon.
        fs.mock_set_unmount_should_fail("/nix/store", true);
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);
    }

    // Clear any recorder residue left on this thread by earlier work.
    let _ = crate::manager::helpers::drain_recorded_service_actions();

    manager
        .lock()
        .unwrap()
        .emergency_deactivate()
        .expect("a best-effort /nix/store unmount failure must not abort deactivation");

    let actions = crate::manager::helpers::drain_recorded_service_actions();
    assert!(
        actions.iter().any(|action| action == "start:nix-daemon"),
        "nix-daemon must be restarted even when the /nix/store bind unmount fails: {actions:?}"
    );
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive,
        "deactivation should complete to Inactive once the /nix overlay is unmounted"
    );
}

#[test]
#[serial]
fn test_emergency_deactivate_missing_switch_script_keeps_inactive_state() {
    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");

    let fs = MockFilesystem::new();
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        log_path: hidden_root.join("logs"),
        overlays: vec![],
        ..Config::test_default()
    };

    let system_profile = hidden_root.join("profiles/system");
    let profiles_dir = system_profile.parent().unwrap().to_path_buf();
    let generation_dir = profiles_dir.join("system-1-link");
    std::fs::create_dir_all(&generation_dir).unwrap();
    env.set("NAILS_SYSTEM_PROFILE_PATH", &system_profile);
    fs.mock_set_path_exists(profiles_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(profiles_dir.to_str().unwrap(), PathKind::Dir);
    fs.mock_set_directory_contents(&profiles_dir, vec![generation_dir.clone()]);

    let upper_dir = hidden_root.join("overlays/home/upper");
    let work_dir = hidden_root.join("overlays/home/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);
    fs.mock_set_mounted(Path::new("/home"), true);

    write_state_with_overlay(
        &state_path,
        &hidden_root,
        Path::new("/home"),
        &upper_dir,
        &work_dir,
    );

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs,
        config,
        state_path.clone(),
    )));

    manager
        .lock()
        .unwrap()
        .emergency_deactivate()
        .expect("overlay-only emergency deactivation should work");
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );

    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded.state, SystemState::Inactive);
    assert!(loaded.overlay_status.is_empty());
}

#[test]
#[serial]
fn test_emergency_deactivate_unmounts_nix_store_when_nix_overlay_present() {
    let mut env = EnvGuard::lock();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");

    let fs = MockFilesystem::new();
    let _profile = setup_system_profile_stub(&fs);
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    let upper_dir = hidden_root.join("overlays/nix/upper");
    let work_dir = hidden_root.join("overlays/nix/work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    write_state_with_overlay(
        &state_path,
        &hidden_root,
        Path::new("/nix"),
        &upper_dir,
        &work_dir,
    );

    let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));

    {
        let manager_guard = manager.lock().unwrap();
        let fs = manager_guard.filesystem();
        fs.mock_set_mounted(Path::new("/nix"), true);
        fs.mock_set_mounted(Path::new("/nix/store"), true);
        fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
        fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);
    }

    manager
        .lock()
        .unwrap()
        .emergency_deactivate()
        .expect("deactivation should work");

    let manager_guard = manager.lock().unwrap();
    assert_eq!(
        manager_guard.current_state().unwrap(),
        SystemState::Inactive
    );
    assert!(
        !manager_guard
            .filesystem()
            .is_mounted(Path::new("/nix"))
            .unwrap()
    );
    assert!(
        !manager_guard
            .filesystem()
            .is_mounted(Path::new("/nix/store"))
            .unwrap()
    );
}

// ============================================================================
// Story 9.3: Structured Logging Tests for Deactivation
// ============================================================================

#[test]
#[serial]
#[tracing_test::traced_test]
fn test_deactivation_emits_structured_events() {
    let manager = setup_active_manager();

    // Setup overlays as mounted
    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
        m.filesystem().mock_set_mounted(Path::new("/etc"), true);
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_ok(), "Deactivation should succeed");

    // Verify structured deactivation events (AC#3)
    assert!(logs_contain("Deactivation started"));
    assert!(logs_contain("phase"));
    assert!(logs_contain("Deactivation complete"));
    assert!(logs_contain("duration_ms"));
}

#[test]
#[serial]
#[tracing_test::traced_test]
fn test_deactivation_cleanup_event_includes_count() {
    let manager = setup_active_manager();
    // Cleanup resolves the history files from HOME, so it points at the fake
    // home for the whole test.
    let _home = set_safe_test_home();

    // Setup overlays as mounted
    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
        m.filesystem().mock_set_mounted(Path::new("/etc"), true);

        // Add some cleanup items
        let bash_history = Path::new(TEST_HOME).join(".bash_history");
        let bash_history_str = bash_history.to_str().unwrap();

        // Validate path safety before using
        assert_path_is_safe(bash_history_str);

        m.filesystem().mock_set_path_exists(bash_history_str, true);
        m.filesystem()
            .mock_set_file_content(bash_history_str, "nails activate\nsome command\n");
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_ok(), "Deactivation should succeed");

    // Verify cleanup event includes count (AC#3)
    assert!(logs_contain("Cleanup complete") || logs_contain("cleaned_items"));
}

#[test]
#[serial]
#[tracing_test::traced_test]
fn test_deactivation_unmount_event_includes_overlay_list() {
    let manager = setup_active_manager();

    // Setup overlays as mounted
    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
        m.filesystem().mock_set_mounted(Path::new("/etc"), true);
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_ok(), "Deactivation should succeed");

    // Verify unmount event includes overlay list (AC#3)
    assert!(logs_contain("Overlays unmounted") || logs_contain("overlays"));
    assert!(logs_contain("count") || logs_contain("unmounted"));
}

#[test]
#[serial]
#[tracing_test::traced_test]
fn test_deactivation_idempotent_log() {
    // Test idempotent deactivation logging
    let manager = setup_active_manager();

    // Set state to Inactive
    {
        let mut m = manager.lock().unwrap();
        m.force_state(SystemState::Inactive)
            .expect("Should set inactive");
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());

    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_ok(), "Idempotent deactivation should succeed");

    // Verify idempotent message with structured fields
    assert!(logs_contain("Already inactive") || logs_contain("already_inactive"));
}

#[test]
fn test_deactivation_report_display_with_post_unmount_cleanup() {
    // Test Display implementation for DeactivationReport with post_unmount_cleanup
    let mut cleanup_report = CleanupReport::new(CleanupMode::Fast);
    cleanup_report.add_cleaned("Removed 3 history entries");
    cleanup_report.duration = Duration::from_millis(100);

    let post_unmount_cleanup = PostUnmountCleanupReport {
        cleaned_items: vec![
            "~/.bash_history (real disk)".to_string(),
            "~/.zsh_history (real disk)".to_string(),
        ],
        warnings: vec!["Failed to clean ~/.fish_history: Permission denied".to_string()],
        was_performed: true,
    };

    let report = DeactivationReport {
        cleanup_report,
        unmounted_overlays: vec!["/home".to_string(), "/etc".to_string()],
        failed_overlays: Vec::new(),
        remaining_mounts: Vec::new(),
        duration: Duration::from_millis(150),
        final_state: SystemState::Inactive,
        was_already_inactive: false,
        post_unmount_cleanup,
    };

    let output = format!("{}", report);
    assert!(output.contains("Deactivation Report"));
    assert!(output.contains("Phase 1 - Overlay Cleanup:"));
    assert!(output.contains("Removed 3 history entries"));
    assert!(output.contains("Unmounted Overlays:"));
    assert!(output.contains("/home"));
    assert!(output.contains("/etc"));
    assert!(output.contains("Phase 2 - Real Disk Cleanup:"));
    assert!(output.contains("~/.bash_history (real disk)"));
    assert!(output.contains("~/.zsh_history (real disk)"));
    assert!(output.contains("⚠ Failed to clean ~/.fish_history: Permission denied"));
    assert!(output.contains("✓ Deactivation complete"));
}

#[test]
fn test_deactivation_report_display_without_post_unmount_cleanup() {
    // Test Display implementation when post_unmount_cleanup.was_performed is false
    let mut cleanup_report = CleanupReport::new(CleanupMode::Fast);
    cleanup_report.add_cleaned("Removed 3 history entries");
    cleanup_report.duration = Duration::from_millis(100);

    let post_unmount_cleanup = PostUnmountCleanupReport {
        cleaned_items: vec![], // Even if items exist, they shouldn't be shown
        warnings: vec![],
        was_performed: false,
    };

    let report = DeactivationReport {
        cleanup_report,
        unmounted_overlays: vec!["/home".to_string()],
        failed_overlays: Vec::new(),
        remaining_mounts: Vec::new(),
        duration: Duration::from_millis(150),
        final_state: SystemState::Inactive,
        was_already_inactive: false,
        post_unmount_cleanup,
    };

    let output = format!("{}", report);
    assert!(output.contains("Deactivation Report"));
    assert!(output.contains("Phase 1 - Overlay Cleanup:"));
    // Phase 2 should NOT appear when was_performed is false
    assert!(!output.contains("Phase 2 - Real Disk Cleanup:"));
}

#[test]
fn test_deactivation_report_is_successful_with_inactive_state() {
    let report = DeactivationReport {
        cleanup_report: CleanupReport::default(),
        unmounted_overlays: vec![],
        failed_overlays: Vec::new(),
        remaining_mounts: Vec::new(),
        duration: Duration::from_millis(100),
        final_state: SystemState::Inactive,
        was_already_inactive: false,
        post_unmount_cleanup: PostUnmountCleanupReport::default(),
    };

    assert!(report.is_successful());
}

#[test]
fn test_deactivation_report_is_not_successful_with_active_state() {
    let report = DeactivationReport {
        cleanup_report: CleanupReport::default(),
        unmounted_overlays: vec![],
        failed_overlays: Vec::new(),
        remaining_mounts: Vec::new(),
        duration: Duration::from_millis(100),
        final_state: SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![],
        },
        was_already_inactive: false,
        post_unmount_cleanup: PostUnmountCleanupReport::default(),
    };

    assert!(!report.is_successful());
}

#[test]
fn test_post_unmount_cleanup_report_default() {
    let report = PostUnmountCleanupReport::default();
    assert_eq!(report.cleaned_items.len(), 0);
    assert_eq!(report.warnings.len(), 0);
    assert!(!report.was_performed);
}

#[test]
fn test_post_unmount_cleanup_report_with_data() {
    let report = PostUnmountCleanupReport {
        cleaned_items: vec!["file1".to_string(), "file2".to_string()],
        warnings: vec!["warning1".to_string()],
        was_performed: true,
    };

    assert_eq!(report.cleaned_items.len(), 2);
    assert_eq!(report.warnings.len(), 1);
    assert!(report.was_performed);
}

#[test]
#[serial]
fn test_emergency_mode_skips_non_essential_steps() {
    use crate::DeactivationMode;

    let manager = setup_active_manager();

    // Setup overlays as mounted
    {
        let m = manager.lock().unwrap();
        m.filesystem().mock_set_mounted(Path::new("/home"), true);
        m.filesystem().mock_set_mounted(Path::new("/etc"), true);
    }

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default())
        .with_mode(DeactivationMode::Emergency);

    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_ok(), "Emergency deactivation should succeed");

    let report = result.unwrap();
    assert!(report.is_successful());
    assert_eq!(report.final_state, SystemState::Inactive);
    assert!(!report.was_already_inactive);

    // Emergency mode should skip post-unmount cleanup
    assert!(
        !report.post_unmount_cleanup.was_performed,
        "Emergency mode should skip post-unmount cleanup"
    );
}

#[test]
#[serial]
fn test_emergency_mode_fails_on_inactive_state() {
    use crate::DeactivationMode;

    // Setup manager in INACTIVE state
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);

    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let mut manager = NailsManager::new(fs, config, state_path);
    manager.force_state(SystemState::Inactive).unwrap();

    let manager = Arc::new(Mutex::new(manager));
    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default())
        .with_mode(DeactivationMode::Emergency);

    // Emergency mode should NOT be idempotent - must fail on Inactive
    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(
        result.is_err(),
        "Emergency mode should fail on Inactive state"
    );

    match result {
        Err(NailsError::InvalidState(msg)) => {
            assert!(msg.contains("Cannot deactivate"));
        }
        _ => panic!("Expected InvalidState error"),
    }
}

#[test]
#[serial]
fn test_normal_mode_is_idempotent_on_inactive() {
    use crate::DeactivationMode;

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);

    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();
    let state_path = mock_hidden_vol.join("state.json");

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    let mut manager = NailsManager::new(fs, config, state_path);
    manager.force_state(SystemState::Inactive).unwrap();

    let manager = Arc::new(Mutex::new(manager));
    let orchestrator =
        DeactivationOrchestrator::new(CleanupConfig::default()).with_mode(DeactivationMode::Normal);

    // Normal mode should be idempotent
    let result = orchestrator.run(&mut manager.lock().unwrap());
    assert!(result.is_ok());
    assert!(result.unwrap().was_already_inactive);
}

// ---------------------------------------------------------------------------
// State-write failures during teardown must return promptly, never hang.
//
// A state write can fail mid-teardown for real reasons: ENOSPC on the hidden
// volume (every overlay upper lives there), EROFS after `errors=remount-ro`, or
// EIO on a failing backend. An earlier design held the manager behind an
// `Arc<Mutex>` and `StateGuard::drop` re-locked it, so any such failure on a `?`
// path dropped the guard while the caller still held it and the process hung
// forever. The manager is now borrowed by `&mut`, which makes that self-deadlock
// unrepresentable; these tests pin the no-hang property at each teardown `?`
// site, in both Normal and Emergency mode, by running the call on a worker thread
// and failing loudly if no result arrives within five seconds.
// ---------------------------------------------------------------------------

/// Run `op` on a worker thread and return its value, panicking if it does not
/// finish within five seconds. A reintroduced `StateGuard::drop` self-deadlock
/// would block the worker here and turn into a loud failure rather than a hung
/// CI run.
fn run_within_timeout<R: Send + 'static>(op: impl FnOnce() -> R + Send + 'static) -> R {
    use std::sync::mpsc::{self, RecvTimeoutError};

    let (tx, rx) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let _ = tx.send(op());
    });

    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(value) => {
            handle.join().expect("deactivation worker thread panicked");
            value
        }
        Err(RecvTimeoutError::Timeout) => panic!(
            "deactivation did not return within 5s - possible self-deadlock in StateGuard::drop"
        ),
        Err(RecvTimeoutError::Disconnected) => match handle.join() {
            Err(payload) => std::panic::resume_unwind(payload),
            Ok(()) => panic!("deactivation worker exited without a result"),
        },
    }
}

/// An ACTIVE manager with no overlays and no decoy profile, so teardown runs the
/// full state-transition sequence without needing a system profile. State writes
/// go to a real temporary hidden volume so the save seam governs their outcome.
fn active_manager_no_profile() -> (
    Arc<Mutex<NailsManager<MockFilesystem>>>,
    tempfile::TempDir,
    EnvGuard,
) {
    let mut env = set_safe_test_home();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");

    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        log_path: hidden_root.join("logs"),
        overlays: vec![],
        clear_history: false,
        ..Config::test_default()
    };

    let mut manager = NailsManager::new(fs, config, state_path);
    manager
        .force_state(SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![],
        })
        .unwrap();

    (Arc::new(Mutex::new(manager)), temp_dir, env)
}

/// An ACTIVE manager (with a recorded decoy generation) whose decoy-profile
/// lookup errors: the profiles directory reports as existing but has no listable
/// contents, so `select_system_profile` returns `Err`. Returns the environment
/// guard so the override is restored when the test ends.
fn active_manager_with_failing_profile_lookup() -> (
    Arc<Mutex<NailsManager<MockFilesystem>>>,
    tempfile::TempDir,
    EnvGuard,
) {
    let mut env = set_safe_test_home();

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");

    let profiles_dir = hidden_root.join("profiles");
    env.set("NAILS_SYSTEM_PROFILE_PATH", profiles_dir.join("system"));

    let fs = MockFilesystem::new();
    // The profiles directory exists but its contents are deliberately left
    // unconfigured, so `list_directory` returns Err and the lookup fails.
    fs.mock_set_path_exists(profiles_dir.to_str().unwrap(), true);
    fs.mock_set_path_type(profiles_dir.to_str().unwrap(), PathKind::Dir);

    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        log_path: hidden_root.join("logs"),
        overlays: vec![],
        clear_history: false,
        ..Config::test_default()
    };

    // A recorded decoy generation makes the teardown attempt a decoy restore,
    // which is what reaches the failing profile lookup. Written to disk before
    // the manager is built so its first state read picks it up.
    StateFile {
        state: SystemState::Active {
            activated_at: chrono::Utc::now(),
            overlays: vec![],
        },
        nixos_generation: Some("1".to_string()),
        ..StateFile::default()
    }
    .save_with_custom_root(&state_path, &hidden_root)
    .unwrap();

    let manager = NailsManager::new(fs, config, state_path);
    (Arc::new(Mutex::new(manager)), temp_dir, env)
}

/// An ACTIVE manager tracking the given overlay targets, each mounted and
/// NAILS-owned on the mock filesystem. No decoy generation is recorded, so the
/// teardown needs no system profile. `mounted_at` is staggered per target so the
/// tracked mount order is exactly `targets`.
fn active_manager_with_overlays(
    targets: &[&str],
) -> (
    Arc<Mutex<NailsManager<MockFilesystem>>>,
    tempfile::TempDir,
    EnvGuard,
) {
    let mut env = set_safe_test_home();
    env.remove("NAILS_SYSTEM_PROFILE_PATH");

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");

    let base = chrono::Utc::now();
    let mut overlay_status = std::collections::HashMap::new();
    let mut overlays = Vec::new();
    for (index, target) in targets.iter().enumerate() {
        let path = PathBuf::from(target);
        overlays.push(path.clone());
        overlay_status.insert(
            path.clone(),
            crate::OverlayInfo {
                mount_path: path.clone(),
                lower_dir: PathBuf::from("/"),
                upper_dir: hidden_root.join(format!("overlays/{index}/upper")),
                work_dir: hidden_root.join(format!("overlays/{index}/work")),
                mounted_at: base + chrono::TimeDelta::milliseconds(index as i64),
            },
        );
    }

    StateFile {
        state: SystemState::Active {
            activated_at: base,
            overlays,
        },
        overlay_status,
        ..StateFile::default()
    }
    .save_with_custom_root(&state_path, &hidden_root)
    .unwrap();

    let fs = MockFilesystem::new();
    for target in targets {
        fs.mock_set_mounted(Path::new(target), true);
    }

    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        log_path: hidden_root.join("logs"),
        overlays: vec![],
        clear_history: false,
        ..Config::test_default()
    };

    let manager = NailsManager::new(fs, config, state_path);
    (Arc::new(Mutex::new(manager)), temp_dir, env)
}

#[test]
#[serial]
fn deactivate_degrades_when_a_target_cannot_unmount() {
    let (manager, _hidden_root, _env) = active_manager_with_overlays(&["/home", "/etc", "/opt"]);
    // Fail the middle target; the teardown must still attempt the other two and
    // must NOT remount what it has already detached.
    manager
        .lock()
        .unwrap()
        .filesystem()
        .mock_set_unmount_should_fail("/etc", true);

    let worker = Arc::clone(&manager);
    let result = run_within_timeout(move || worker.lock().unwrap().deactivate());

    let err = result.expect_err("deactivate must fail when a target stays mounted");
    assert!(
        matches!(err, NailsError::DeactivationIncomplete { .. }),
        "unexpected error: {err:?}"
    );
    assert!(
        err.to_string().contains("/etc"),
        "error must name the live mount: {err}"
    );

    let guard = manager.lock().unwrap();
    // Never ACTIVE once an overlay is detached: the teardown ends DEGRADED.
    match guard.current_state().unwrap() {
        SystemState::Degraded {
            remaining_mounts, ..
        } => assert_eq!(remaining_mounts, vec![PathBuf::from("/etc")]),
        other => panic!("expected Degraded, got {other:?}"),
    }
    // All three targets were attempted: the two that can unmount are gone, and
    // the failing one stays live (no remount).
    assert!(!guard.filesystem().is_mounted(Path::new("/home")).unwrap());
    assert!(!guard.filesystem().is_mounted(Path::new("/opt")).unwrap());
    assert!(guard.filesystem().is_mounted(Path::new("/etc")).unwrap());
}

#[test]
#[serial]
fn emergency_deactivate_degrades_without_remount_when_a_target_cannot_unmount() {
    let (manager, _hidden_root, _env) = active_manager_with_overlays(&["/home", "/etc", "/opt"]);
    manager
        .lock()
        .unwrap()
        .filesystem()
        .mock_set_unmount_should_fail("/etc", true);

    let worker = Arc::clone(&manager);
    let result = run_within_timeout(move || worker.lock().unwrap().emergency_deactivate());

    let err = result.expect_err("emergency deactivate must fail when a target stays mounted");
    assert!(
        matches!(err, NailsError::DeactivationIncomplete { .. }),
        "unexpected error: {err:?}"
    );

    let guard = manager.lock().unwrap();
    assert!(
        guard.current_state().unwrap().is_degraded(),
        "emergency teardown must end DEGRADED, not roll back to ACTIVE"
    );
    // Emergency mode also continues past the failure and never remounts: the two
    // unmountable targets are detached and the failing one is still live.
    assert!(!guard.filesystem().is_mounted(Path::new("/home")).unwrap());
    assert!(!guard.filesystem().is_mounted(Path::new("/opt")).unwrap());
    assert!(guard.filesystem().is_mounted(Path::new("/etc")).unwrap());
}

#[test]
#[serial]
fn deactivate_returns_err_within_timeout_when_deactivating_write_fails() {
    use crate::state::save_probe::{self, FailOn};

    let (manager, _hidden_root, _env) = active_manager_no_profile();
    let worker = Arc::clone(&manager);

    let result = run_within_timeout(move || {
        save_probe::arm(&[FailOn::Deactivating]);
        let outcome = worker.lock().unwrap().deactivate();
        save_probe::disarm();
        outcome
    });

    assert!(
        result.is_err(),
        "deactivate must surface the failed ACTIVE->DEACTIVATING write"
    );
    // The ACTIVE->DEACTIVATING write fails before any overlay is detached, so
    // StateGuard::drop correctly rolls the state back to ACTIVE. (A teardown that
    // fails *after* detaching an overlay ends DEGRADED instead; see the degraded
    // teardown tests below.)
    assert!(manager.lock().unwrap().current_state().unwrap().is_active());
}

#[test]
#[serial]
fn emergency_deactivate_returns_err_within_timeout_when_deactivating_write_fails() {
    use crate::state::save_probe::{self, FailOn};

    let (manager, _hidden_root, _env) = active_manager_no_profile();
    let worker = Arc::clone(&manager);

    let result = run_within_timeout(move || {
        save_probe::arm(&[FailOn::Deactivating]);
        let outcome = worker.lock().unwrap().emergency_deactivate();
        save_probe::disarm();
        outcome
    });

    assert!(
        result.is_err(),
        "emergency deactivate must surface the failed ACTIVE->DEACTIVATING write"
    );
    assert!(manager.lock().unwrap().current_state().unwrap().is_active());
}

#[test]
#[serial]
fn deactivate_returns_err_within_timeout_when_inactive_write_fails() {
    use crate::state::save_probe::{self, FailOn};

    let (manager, _hidden_root, _env) = active_manager_no_profile();
    let worker = Arc::clone(&manager);

    let result = run_within_timeout(move || {
        // The ACTIVE->DEACTIVATING write succeeds; only the final
        // DEACTIVATING->INACTIVE write fails, exercising the late `?` site.
        save_probe::arm(&[FailOn::Inactive]);
        let outcome = worker.lock().unwrap().deactivate();
        save_probe::disarm();
        outcome
    });

    assert!(
        result.is_err(),
        "deactivate must surface the failed DEACTIVATING->INACTIVE write"
    );
    assert!(manager.lock().unwrap().current_state().unwrap().is_active());
}

#[test]
#[serial]
fn emergency_deactivate_returns_err_within_timeout_when_inactive_write_fails() {
    use crate::state::save_probe::{self, FailOn};

    let (manager, _hidden_root, _env) = active_manager_no_profile();
    let worker = Arc::clone(&manager);

    let result = run_within_timeout(move || {
        save_probe::arm(&[FailOn::Inactive]);
        let outcome = worker.lock().unwrap().emergency_deactivate();
        save_probe::disarm();
        outcome
    });

    assert!(
        result.is_err(),
        "emergency deactivate must surface the failed DEACTIVATING->INACTIVE write"
    );
    assert!(manager.lock().unwrap().current_state().unwrap().is_active());
}

#[test]
#[serial]
fn deactivate_returns_err_within_timeout_when_system_profile_lookup_fails() {
    let (manager, _hidden_root, _env) = active_manager_with_failing_profile_lookup();
    let worker = Arc::clone(&manager);

    let result = run_within_timeout(move || worker.lock().unwrap().deactivate());

    assert!(
        result.is_err(),
        "deactivate must surface a failing decoy-profile lookup"
    );
    assert!(manager.lock().unwrap().current_state().unwrap().is_active());
}

#[test]
#[serial]
fn emergency_deactivate_returns_err_within_timeout_when_system_profile_lookup_fails() {
    let (manager, _hidden_root, _env) = active_manager_with_failing_profile_lookup();
    let worker = Arc::clone(&manager);

    // Emergency mode has no up-front profile pre-check, so the failing lookup is
    // reached inside the guarded run, after the state is already INACTIVE; the
    // guard's drop then rolls back without hanging.
    let result = run_within_timeout(move || worker.lock().unwrap().emergency_deactivate());

    assert!(
        result.is_err(),
        "emergency deactivate must surface a failing decoy-profile lookup"
    );
}

#[test]
#[serial]
fn deactivate_returns_err_within_timeout_when_rollback_write_also_fails() {
    use crate::state::save_probe::{self, FailOn};

    let (manager, _hidden_root, _env) = active_manager_no_profile();
    let worker = Arc::clone(&manager);

    // The exact shape of the original deadlock: the initial state write fails
    // AND the rollback write that StateGuard::drop then attempts also fails. The
    // drop must log and return rather than block.
    let result = run_within_timeout(move || {
        save_probe::arm(&[FailOn::Deactivating, FailOn::Active]);
        let outcome = worker.lock().unwrap().deactivate();
        save_probe::disarm();
        outcome
    });

    assert!(
        result.is_err(),
        "deactivate must surface the failed write even when rollback also fails"
    );
}
