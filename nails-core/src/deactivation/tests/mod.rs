// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for deactivation module
//!
//! # Test Safety Notice
//!
//! Tests in this module MUST use `cleanup::test_utils::TEST_HOME` instead of the
//! real HOME. History cleanup in this crate's tests resolves to that fixed home,
//! never to the invoking account's, so no test can touch real history files.

use super::DeactivationReport;
use super::test_gate::maybe_block_after_deactivating_state_transition;
use crate::DeactivationOrchestrator;
use crate::cleanup::test_utils::{TEST_HOME, assert_path_is_safe};
use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
use crate::filesystem::{Filesystem, PathKind};
use crate::{
    CleanupConfig, CleanupMode, CleanupReport, Config, MockFilesystem, NailsError, NailsManager,
    StateFile, SystemState,
};
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

/// A snapshot arming the deactivation gate at the given paths (unarmed for `None`).
fn deactivation_gate_env(
    gate_path: Option<&Path>,
    entered_path: Option<&Path>,
) -> crate::RuntimeEnv {
    crate::RuntimeEnv::empty().with_test_hooks(crate::runtime_env::TestHooks {
        deactivating_gate_path: gate_path.map(Path::to_path_buf),
        deactivating_entered_path: entered_path.map(Path::to_path_buf),
        ..Default::default()
    })
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
/// temp dir (removed on drop) and the snapshot that points the manager at it.
struct SystemProfileStub {
    _dir: tempfile::TempDir,
    /// Attach to the manager under test with `with_runtime_env`.
    env: crate::RuntimeEnv,
}

/// Helper function to configure a stub system profile for decoy switching.
fn setup_system_profile_stub(fs: &MockFilesystem) -> SystemProfileStub {
    let profile_root = tempfile::tempdir().expect("tempdir");
    let system_profile_path = profile_root.path().join("system");
    let env = crate::RuntimeEnv::empty().with_system_profile_path(&system_profile_path);

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
        env,
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

    let mut manager =
        NailsManager::new(fs, config, state_path).with_runtime_env(profile.env.clone());

    // Set state to ACTIVE
    manager
        .force_state(SystemState::Active {
            decoy_writers: Vec::new(),
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
            mount_method: Default::default(),
            mount_path: target.to_path_buf(),
            lower_dir: PathBuf::from("/"),
            upper_dir: upper_dir.to_path_buf(),
            work_dir: work_dir.to_path_buf(),
            mounted_at: chrono::Utc::now(),
        },
    );

    StateFile {
        state: SystemState::Active {
            decoy_writers: Vec::new(),
            activated_at: chrono::Utc::now(),
            overlays: vec![target.to_path_buf()],
        },
        overlay_status,
        ..StateFile::default()
    }
    .save_with_custom_root(state_path, hidden_root)
    .unwrap();
}

fn set_state_hidden_toplevel(state_path: &Path, hidden_root: &Path, generation: &str) {
    let mut loaded = StateFile::load(state_path).unwrap();
    loaded.set_nixos_generation(Some(generation.to_string()));
    loaded
        .save_with_custom_root(state_path, hidden_root)
        .unwrap();
}

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
fn active_manager_no_profile() -> (Arc<Mutex<NailsManager<MockFilesystem>>>, tempfile::TempDir) {
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
            decoy_writers: Vec::new(),
            activated_at: chrono::Utc::now(),
            overlays: vec![],
        })
        .unwrap();

    (Arc::new(Mutex::new(manager)), temp_dir)
}

/// An ACTIVE manager (with a recorded decoy generation) whose decoy-profile
/// lookup errors: the profiles directory reports as existing but has no listable
/// contents, so `select_system_profile` returns `Err`.
fn active_manager_with_failing_profile_lookup()
-> (Arc<Mutex<NailsManager<MockFilesystem>>>, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");

    let profiles_dir = hidden_root.join("profiles");
    let runtime_env =
        crate::RuntimeEnv::empty().with_system_profile_path(profiles_dir.join("system"));

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
            decoy_writers: Vec::new(),
            activated_at: chrono::Utc::now(),
            overlays: vec![],
        },
        platform: Some(crate::state::PlatformState::nixos(Some("1".to_string()))),
        ..StateFile::default()
    }
    .save_with_custom_root(&state_path, &hidden_root)
    .unwrap();

    let manager = NailsManager::new(fs, config, state_path).with_runtime_env(runtime_env);
    (Arc::new(Mutex::new(manager)), temp_dir)
}

/// An ACTIVE manager tracking the given overlay targets, each mounted and
/// NAILS-owned on the mock filesystem. No decoy generation is recorded, so the
/// teardown needs no system profile. `mounted_at` is staggered per target so the
/// tracked mount order is exactly `targets`.
fn active_manager_with_overlays(
    targets: &[&str],
) -> (Arc<Mutex<NailsManager<MockFilesystem>>>, tempfile::TempDir) {
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
                mount_method: Default::default(),
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
            decoy_writers: Vec::new(),
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
    (Arc::new(Mutex::new(manager)), temp_dir)
}

mod cleanup_rollback;
mod decoy;
mod degrade_timeout;
mod emergency;
mod events;
mod gate;
mod normal;
mod reporting;
mod system_profile;
