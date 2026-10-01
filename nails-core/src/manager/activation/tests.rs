use super::gate::ActivationGateTestGuard;
use super::maybe_block_after_activating_state_transition;
use super::{
    INTEGRITY_VERIFIED_TARGETS, SessionRestartPhase, derive_security_label,
    determine_session_restart_phase,
};
use crate::{Config, Filesystem, MockFilesystem, NailsManager, OverlayConfig, SystemState};
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

    manager
        .lock()
        .unwrap()
        .activate(true)
        .expect("activation should succeed");

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

#[test]
fn session_restart_phase_uses_pre_switch_restart_for_nixos_activation() {
    let plan = crate::process::SessionRestartPlan {
        display_manager: Some("display-manager.service".to_string()),
        target_uid: Some(1000),
    };

    assert_eq!(
        determine_session_restart_phase(&plan, false, true),
        SessionRestartPhase::AfterOverlayMounts
    );
}

#[test]
fn activation_progress_describes_requested_ordering() {
    let source = include_str!("mod.rs");
    let overlay_idx = source
        .find("[4/7] Mounting overlays...")
        .expect("overlay progress marker");
    let restart_idx = source
        .find("[5/7] Restarting session/display manager...")
        .expect("session restart progress marker");
    let switch_idx = source
        .find("[6/7] Running NixOS switch/rebuild...")
        .expect("switch progress marker");

    assert!(
        overlay_idx < restart_idx && restart_idx < switch_idx,
        "activation progress markers should reflect overlays -> restart -> switch ordering"
    );
}

#[test]
fn session_restart_phase_uses_restart_after_overlay_mounts_for_overlay_only_activation() {
    let plan = crate::process::SessionRestartPlan {
        display_manager: Some("display-manager.service".to_string()),
        target_uid: Some(1000),
    };

    assert_eq!(
        determine_session_restart_phase(&plan, true, true),
        SessionRestartPhase::AfterOverlayMounts
    );
}

#[test]
fn session_restart_phase_uses_restart_after_overlay_mounts_when_nixos_switch_unavailable() {
    let plan = crate::process::SessionRestartPlan {
        display_manager: Some("display-manager.service".to_string()),
        target_uid: Some(1000),
    };

    assert_eq!(
        determine_session_restart_phase(&plan, false, false),
        SessionRestartPhase::AfterOverlayMounts
    );
}

#[test]
fn session_restart_phase_is_none_without_restart_plan() {
    assert_eq!(
        determine_session_restart_phase(
            &crate::process::SessionRestartPlan::default(),
            false,
            true
        ),
        SessionRestartPhase::None
    );
}

// Invariant: the security label is a function of surviving writers, never of the
// mount method. `derive_security_label` takes only the leaking targets — it has no
// Direct-vs-Pivot parameter — so the method cannot influence the posture. The
// cases below pin that down: a direct mount that leaks is DEGRADED while a pivot
// mount that does not leak is OPTIMAL. A surviving writer keeps writing to the
// decoy lower tree under either method, so the mount method carries no security
// meaning on its own.

#[test]
fn security_label_degraded_when_a_direct_mount_leaves_surviving_writers() {
    // A direct mount contributes a target to `leaking` only when writers survived
    // Phase 2; such a leak must read DEGRADED despite the mount being "direct".
    let leaking = vec![PathBuf::from("/home")];
    assert_eq!(
        derive_security_label(&leaking, INTEGRITY_VERIFIED_TARGETS),
        "DEGRADED"
    );
}

#[test]
fn security_label_optimal_when_a_pivot_mount_has_no_surviving_writers() {
    // A pivot mount with zero survivors never enters `leaking`, so the posture is
    // OPTIMAL even though the pivot fallback was used.
    let leaking: Vec<PathBuf> = Vec::new();
    assert_eq!(
        derive_security_label(&leaking, INTEGRITY_VERIFIED_TARGETS),
        "OPTIMAL"
    );
}

#[test]
fn security_label_optimal_when_only_integrity_verified_target_leaks() {
    // A surviving writer on an integrity-verified target (/boot) is tolerated
    // because that lower tree is verified at boot, not because of the mount method.
    assert!(INTEGRITY_VERIFIED_TARGETS.contains(&"/boot"));
    let leaking = vec![PathBuf::from("/boot")];
    assert_eq!(
        derive_security_label(&leaking, INTEGRITY_VERIFIED_TARGETS),
        "OPTIMAL"
    );
}

#[test]
fn security_label_degraded_when_unverified_target_leaks_alongside_verified() {
    // One unverified leak is enough to degrade the posture, even mixed with a
    // whitelisted one.
    let leaking = vec![PathBuf::from("/boot"), PathBuf::from("/etc")];
    assert_eq!(
        derive_security_label(&leaking, INTEGRITY_VERIFIED_TARGETS),
        "DEGRADED"
    );
}
