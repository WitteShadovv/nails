use super::gate::ActivationGateTestGuard;
use super::maybe_block_after_activating_state_transition;
use super::rollback::rollback_overlay_mounts_after_activation_failure;
use crate::{
    Config, EphemeralOverlayDir, ExtendedOverlayConfig, Filesystem, MockFilesystem, NailsManager,
    OverlayConfig, SystemState,
};
use serial_test::serial;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct ActivationGateEnvGuard {
    gate: Option<OsString>,
    entered: Option<OsString>,
}

impl ActivationGateEnvGuard {
    fn capture() -> Self {
        Self {
            gate: std::env::var_os("NAILS_TEST_ACTIVATING_GATE_PATH"),
            entered: std::env::var_os("NAILS_TEST_ACTIVATING_ENTERED_PATH"),
        }
    }

    fn clear() {
        unsafe {
            std::env::remove_var("NAILS_TEST_ACTIVATING_GATE_PATH");
            std::env::remove_var("NAILS_TEST_ACTIVATING_ENTERED_PATH");
        }
    }

    fn set(gate_path: &Path, entered_path: Option<&Path>) {
        unsafe {
            std::env::set_var("NAILS_TEST_ACTIVATING_GATE_PATH", gate_path);
        }

        match entered_path {
            Some(path) => unsafe {
                std::env::set_var("NAILS_TEST_ACTIVATING_ENTERED_PATH", path);
            },
            None => unsafe {
                std::env::remove_var("NAILS_TEST_ACTIVATING_ENTERED_PATH");
            },
        }
    }
}

impl Drop for ActivationGateEnvGuard {
    fn drop(&mut self) {
        match &self.gate {
            Some(value) => unsafe {
                std::env::set_var("NAILS_TEST_ACTIVATING_GATE_PATH", value);
            },
            None => unsafe {
                std::env::remove_var("NAILS_TEST_ACTIVATING_GATE_PATH");
            },
        }

        match &self.entered {
            Some(value) => unsafe {
                std::env::set_var("NAILS_TEST_ACTIVATING_ENTERED_PATH", value);
            },
            None => unsafe {
                std::env::remove_var("NAILS_TEST_ACTIVATING_ENTERED_PATH");
            },
        }
    }
}

fn spawn_gate_releaser(gate_path: PathBuf, entered_path: PathBuf) -> std::thread::JoinHandle<()> {
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

#[test]
#[serial]
fn test_activation_gate_returns_immediately_when_disabled() {
    let _gate_guard = ActivationGateTestGuard::enable();
    let _env_guard = ActivationGateEnvGuard::capture();
    ActivationGateEnvGuard::clear();

    assert!(maybe_block_after_activating_state_transition().is_ok());
}

#[test]
#[serial]
fn test_activation_gate_writes_default_entered_marker() {
    let _gate_guard = ActivationGateTestGuard::enable();
    let _env_guard = ActivationGateEnvGuard::capture();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let gate_path = temp_dir.path().join("activation.gate");
    let entered_path = PathBuf::from(format!("{}.entered", gate_path.display()));
    std::fs::write(&gate_path, []).expect("gate file");
    ActivationGateEnvGuard::set(&gate_path, None);

    let releaser = spawn_gate_releaser(gate_path.clone(), entered_path.clone());
    maybe_block_after_activating_state_transition().expect("gate should be released");
    releaser.join().expect("releaser thread should finish");

    assert!(
        entered_path.exists(),
        "default entered marker should be created"
    );
    assert!(!gate_path.exists(), "gate should be removed by releaser");
}

#[test]
#[serial]
fn test_activation_gate_writes_custom_entered_marker_and_creates_parent_dirs() {
    let _gate_guard = ActivationGateTestGuard::enable();
    let _env_guard = ActivationGateEnvGuard::capture();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let gate_path = temp_dir.path().join("activation.gate");
    let entered_path = temp_dir.path().join("nested/markers/entered.marker");
    std::fs::write(&gate_path, []).expect("gate file");
    ActivationGateEnvGuard::set(&gate_path, Some(&entered_path));

    let releaser = spawn_gate_releaser(gate_path.clone(), entered_path.clone());
    maybe_block_after_activating_state_transition().expect("gate should be released");
    releaser.join().expect("releaser thread should finish");

    assert!(
        entered_path.exists(),
        "custom entered marker should be created"
    );
    assert!(
        entered_path.parent().expect("marker parent").exists(),
        "custom marker parent directory should be created"
    );
}

#[test]
#[serial]
fn test_activation_gate_reports_directory_creation_failures() {
    let _gate_guard = ActivationGateTestGuard::enable();
    let _env_guard = ActivationGateEnvGuard::capture();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let blocker = temp_dir.path().join("not-a-directory");
    let gate_path = temp_dir.path().join("activation.gate");
    let entered_path = blocker.join("entered.marker");
    std::fs::write(&blocker, b"blocker").expect("blocker file");
    ActivationGateEnvGuard::set(&gate_path, Some(&entered_path));

    let err = maybe_block_after_activating_state_transition().expect_err("should fail");
    let msg = err.to_string();

    assert!(msg.contains("Failed to prepare activation test marker directory"));
}

#[test]
#[serial]
fn test_activation_gate_reports_marker_write_failures() {
    let _gate_guard = ActivationGateTestGuard::enable();
    let _env_guard = ActivationGateEnvGuard::capture();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let gate_path = temp_dir.path().join("activation.gate");
    let entered_path = temp_dir.path().join("entered-directory");
    std::fs::create_dir_all(&entered_path).expect("entered dir");
    ActivationGateEnvGuard::set(&gate_path, Some(&entered_path));

    let err = maybe_block_after_activating_state_transition().expect_err("should fail");
    let msg = err.to_string();

    assert!(msg.contains("Failed to write activation test marker"));
}

#[test]
fn test_activation_rollback_reports_ephemeral_cleanup_failures() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state_path = temp_dir.path().join("state.json");
    let fs = MockFilesystem::new();

    fs.mock_set_unmount_should_fail("/mnt/nails-pivot/tmp", true);

    let manager = NailsManager::new(
        fs,
        Config {
            hidden_volume_root: temp_dir.path().to_path_buf(),
            state_file_path: state_path.clone(),
            extended_overlays: ExtendedOverlayConfig {
                enabled: true,
                directories: vec![EphemeralOverlayDir {
                    path: PathBuf::from("/tmp"),
                    tmpfs_upper_size: "256M".to_string(),
                    tmpfs_work_size: "128M".to_string(),
                }],
            },
            ..Config::test_default()
        },
        state_path,
    );

    let err = rollback_overlay_mounts_after_activation_failure(&manager, &[])
        .expect_err("ephemeral cleanup failure should be surfaced");

    assert!(
        err.to_string()
            .contains("Activation rollback ephemeral cleanup failed"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_activation_rollback_unmounts_persistent_overlays_even_when_ephemeral_cleanup_fails() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state_path = temp_dir.path().join("state.json");
    let fs = MockFilesystem::new();

    fs.mock_set_unmount_should_fail("/mnt/nails-pivot/tmp", true);
    fs.mock_set_overlay_mounted(Path::new("/home"), true);

    let manager = NailsManager::new(
        fs.clone(),
        Config {
            hidden_volume_root: temp_dir.path().to_path_buf(),
            state_file_path: state_path.clone(),
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/home"),
                upper: PathBuf::from("/mnt/hidden/home"),
                work: PathBuf::from("/mnt/hidden/.work/home"),
                target: PathBuf::from("/home"),
            }],
            extended_overlays: ExtendedOverlayConfig {
                enabled: true,
                directories: vec![EphemeralOverlayDir {
                    path: PathBuf::from("/tmp"),
                    tmpfs_upper_size: "256M".to_string(),
                    tmpfs_work_size: "128M".to_string(),
                }],
            },
            ..Config::test_default()
        },
        state_path,
    );

    let err = rollback_overlay_mounts_after_activation_failure(&manager, &[PathBuf::from("/home")])
        .expect_err("ephemeral cleanup failure should still be surfaced");

    assert!(
        err.to_string()
            .contains("Activation rollback cleanup failed"),
        "unexpected error: {err}"
    );
    assert!(
        !fs.is_mounted(Path::new("/home"))
            .expect("/home mount query should succeed"),
        "persistent overlays should still be unmounted during rollback"
    );
}

#[test]
fn test_explicit_nix_overlay_restores_nix_store_bind_mount() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let upper_dir = hidden_root.join("nix");
    let work_dir = hidden_root.join(".work/nix");
    std::fs::create_dir_all(&upper_dir).expect("upper dir");
    std::fs::create_dir_all(&work_dir).expect("work dir");

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/nix", true);
    fs.mock_set_path_exists("/nix/store", true);
    fs.mock_set_submount_sources(
        Path::new("/nix"),
        vec![(
            PathBuf::from("/nix/store"),
            PathBuf::from("/persist/nix/store"),
        )],
    );
    fs.mock_set_path_exists("/persist/nix/store", true);
    fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
    fs.mock_set_file_content(
        "/etc/nixos/hardware-configuration.nix",
        "{ config, lib, pkgs, ... }: { imports = [ ./hardware-configuration.nix ]; }",
    );
    fs.mock_set_path_exists(upper_dir.to_str().expect("upper str"), true);
    fs.mock_set_path_exists(work_dir.to_str().expect("work str"), true);

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        Config {
            hidden_volume_root: hidden_root,
            state_file_path: state_path.clone(),
            overlay_mode: crate::OverlayMode::Explicit,
            overlays: vec![OverlayConfig {
                name: "nix".to_string(),
                lower: PathBuf::from("/nix"),
                upper: upper_dir,
                work: work_dir,
                target: PathBuf::from("/nix"),
            }],
            ..Config::test_default()
        },
        state_path,
    )));

    NailsManager::activate(Arc::clone(&manager), true).expect("activation should succeed");

    let state = manager
        .lock()
        .expect("manager lock")
        .current_state()
        .expect("state");
    assert!(matches!(state, SystemState::Active { .. }));
    assert!(fs.is_mounted(Path::new("/nix")).expect("/nix mounted"));
    assert!(
        fs.is_mounted(Path::new("/nix/store"))
            .expect("/nix/store bind mount restored")
    );
}
