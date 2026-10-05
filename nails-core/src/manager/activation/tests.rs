// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::gate::ActivationGateTestGuard;
use super::maybe_block_after_activating_state_transition;
use super::{
    HiddenConfigOutcome, INTEGRITY_VERIFIED_TARGETS, SessionRestartPhase, StepProgress,
    derive_security_label, determine_session_restart_phase, is_protected_base_unit,
    overlay_status_body, record_surviving_writers,
};
use crate::DecoyWriter;
use crate::Verbosity;
use crate::overlay::SurvivingWriter;
use crate::test_support::EnvGuard;
use crate::{
    Config, Filesystem, MockFilesystem, NailsError, NailsManager, OverlayConfig, SystemState,
};
use serial_test::serial;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Takes the environment lock with the activation gate variables pointing at
/// the given paths, or removed when `None`; dropping the guard restores them.
fn activation_gate_env(gate_path: Option<&Path>, entered_path: Option<&Path>) -> EnvGuard {
    let mut env = EnvGuard::lock();
    for (key, value) in [
        ("NAILS_TEST_ACTIVATING_GATE_PATH", gate_path),
        ("NAILS_TEST_ACTIVATING_ENTERED_PATH", entered_path),
    ] {
        match value {
            Some(path) => env.set(key, path),
            None => env.remove(key),
        };
    }
    env
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
    let _env = activation_gate_env(None, None);

    assert!(maybe_block_after_activating_state_transition().is_ok());
}

#[test]
#[serial]
fn test_activation_gate_writes_default_entered_marker() {
    let _gate_guard = ActivationGateTestGuard::enable();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let gate_path = temp_dir.path().join("activation.gate");
    let entered_path = PathBuf::from(format!("{}.entered", gate_path.display()));
    std::fs::write(&gate_path, []).expect("gate file");
    let _env = activation_gate_env(Some(&gate_path), None);

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
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let gate_path = temp_dir.path().join("activation.gate");
    let entered_path = temp_dir.path().join("nested/markers/entered.marker");
    std::fs::write(&gate_path, []).expect("gate file");
    let _env = activation_gate_env(Some(&gate_path), Some(&entered_path));

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
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let blocker = temp_dir.path().join("not-a-directory");
    let gate_path = temp_dir.path().join("activation.gate");
    let entered_path = blocker.join("entered.marker");
    std::fs::write(&blocker, b"blocker").expect("blocker file");
    let _env = activation_gate_env(Some(&gate_path), Some(&entered_path));

    let err = maybe_block_after_activating_state_transition().expect_err("should fail");
    assert!(matches!(err, NailsError::NixOSError(_)), "{err:?}");
}

#[test]
#[serial]
fn test_activation_gate_reports_marker_write_failures() {
    let _gate_guard = ActivationGateTestGuard::enable();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let gate_path = temp_dir.path().join("activation.gate");
    let entered_path = temp_dir.path().join("entered-directory");
    std::fs::create_dir_all(&entered_path).expect("entered dir");
    let _env = activation_gate_env(Some(&gate_path), Some(&entered_path));

    let err = maybe_block_after_activating_state_transition().expect_err("should fail");
    assert!(matches!(err, NailsError::NixOSError(_)), "{err:?}");
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
    // The /nix/store self-bind restore is NixOS-native behaviour, gated on the
    // platform: declare a NixOS host so the merged loop takes the Native path.
    fs.mock_add_file("/etc/os-release", "ID=nixos\nVERSION_ID=\"24.11\"\n");
    fs.mock_add_file("/proc/1/comm", "systemd");
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
fn session_restart_phase_runs_after_overlay_mounts_for_any_plan() {
    let plan = crate::process::SessionRestartPlan {
        display_manager: Some("display-manager.service".to_string()),
        target_uid: Some(1000),
    };

    // A non-default plan always restarts after the overlay mounts, regardless of
    // overlay-only vs. NixOS activation: the phase is a function of the plan
    // alone.
    assert_eq!(
        determine_session_restart_phase(&plan),
        SessionRestartPhase::AfterOverlayMounts
    );
}

#[test]
fn activation_progress_describes_requested_ordering() {
    let source = include_str!("mod.rs");
    let overlay_idx = source
        .find("\"overlay_mount\", \"Mounting overlays...\"")
        .expect("overlay progress marker");
    let switch_idx = source
        .find("\"profile_switch\", \"Applying hidden configuration...\"")
        .expect("switch progress marker");
    let restart_idx = source
        .find("\"session_restart\", \"Restarting session/display manager...\"")
        .expect("session restart progress marker");

    // The hidden configuration switch runs before the session restart, so the
    // restarted session comes up under the hidden configuration and a failed
    // switch never brings the decoy session up first.
    assert!(
        overlay_idx < switch_idx && switch_idx < restart_idx,
        "activation progress markers should reflect overlays -> switch -> restart ordering"
    );
}

#[test]
fn session_restart_phase_is_none_without_restart_plan() {
    assert_eq!(
        determine_session_restart_phase(&crate::process::SessionRestartPlan::default()),
        SessionRestartPhase::None
    );
}

// Invariant: the security label is a function of surviving writers, never of the
// mount method. `derive_security_label` takes only the writers left on the decoy —
// it has no Direct-vs-Pivot parameter — so the method cannot influence the
// posture. The cases below pin that down: a direct mount that leaks is DEGRADED
// while a pivot mount that does not leak is OPTIMAL. A surviving writer keeps
// writing to the decoy lower tree under either method, so the mount method
// carries no security meaning on its own.

fn survivor(pid: u32, name: &str, service: Option<&str>) -> SurvivingWriter {
    SurvivingWriter {
        pid,
        name: name.to_string(),
        service: service.map(str::to_string),
    }
}

/// Fold per-target survivors the way `mount_overlays` does, one target at a time.
fn collect(per_target: &[(&str, Vec<SurvivingWriter>)]) -> Vec<DecoyWriter> {
    let mut writers = Vec::new();
    for (target, survivors) in per_target {
        record_surviving_writers(&mut writers, Path::new(target), survivors);
    }
    writers
}

#[test]
fn security_label_degraded_when_a_direct_mount_leaves_surviving_writers() {
    // A direct mount contributes writers only when they survived Phase 2; such a
    // leak must read DEGRADED despite the mount being "direct".
    let writers = collect(&[("/home", vec![survivor(700, "firefox", None)])]);
    assert_eq!(derive_security_label(&writers), "DEGRADED");
}

#[test]
fn security_label_optimal_when_a_pivot_mount_has_no_surviving_writers() {
    // A pivot mount with zero survivors records no writer, so the posture is
    // OPTIMAL even though the pivot fallback was used.
    let writers = collect(&[("/home", Vec::new())]);
    assert_eq!(derive_security_label(&writers), "OPTIMAL");
}

#[test]
fn security_label_optimal_when_only_integrity_verified_target_leaks() {
    // A surviving writer on an integrity-verified target (/boot) is tolerated
    // because that lower tree is verified at boot, not because of the mount method.
    assert!(INTEGRITY_VERIFIED_TARGETS.contains(&"/boot"));
    let writers = collect(&[("/boot", vec![survivor(90, "fwupd", Some("fwupd"))])]);
    assert!(writers.is_empty(), "a /boot survivor is not a decoy leak");
    assert_eq!(derive_security_label(&writers), "OPTIMAL");
}

#[test]
fn security_label_degraded_when_unverified_target_leaks_alongside_verified() {
    // One unverified leak is enough to degrade the posture, even mixed with a
    // whitelisted one.
    let writers = collect(&[
        ("/boot", vec![survivor(90, "fwupd", Some("fwupd"))]),
        ("/etc", vec![survivor(500, "dbus-daemon", Some("dbus"))]),
    ]);
    assert_eq!(derive_security_label(&writers), "DEGRADED");
}

#[test]
fn surviving_writers_keep_their_identity_across_targets() {
    // The outcome must name who is still writing, and one process holding two
    // targets is one writer leaking to both, not two writers.
    let writers = collect(&[
        (
            "/etc",
            vec![survivor(600, "NetworkManager", Some("NetworkManager"))],
        ),
        (
            "/var",
            vec![
                survivor(600, "NetworkManager", Some("NetworkManager")),
                survivor(812, "tail", None),
            ],
        ),
    ]);

    assert_eq!(
        writers,
        vec![
            DecoyWriter {
                pid: 600,
                name: "NetworkManager".to_string(),
                service: Some("NetworkManager".to_string()),
                targets: vec![PathBuf::from("/etc"), PathBuf::from("/var")],
            },
            DecoyWriter {
                pid: 812,
                name: "tail".to_string(),
                service: None,
                targets: vec![PathBuf::from("/var")],
            },
        ]
    );
}

#[test]
fn surviving_writers_with_the_same_name_stay_distinct() {
    let writers = collect(&[(
        "/var",
        vec![survivor(10, "tail", None), survivor(11, "tail", None)],
    )]);
    assert_eq!(writers.len(), 2);
}

#[test]
fn overlay_status_notification_names_the_writers_left_on_the_decoy() {
    let writers = collect(&[("/var", vec![survivor(812, "tail", None)])]);
    let body = overlay_status_body("DEGRADED", 2, 0, &writers);
    assert!(body.starts_with("Security: DEGRADED"), "{body}");
    assert!(body.contains("1 writer still on the decoy"), "{body}");
    assert!(body.contains("tail (PID 812) on /var"), "{body}");
}

#[test]
fn overlay_status_notification_summarises_many_writers() {
    let survivors = (1..=5)
        .map(|pid| survivor(pid, &format!("w{pid}"), None))
        .collect();
    let writers = collect(&[("/var", survivors)]);
    let body = overlay_status_body("DEGRADED", 1, 0, &writers);
    assert!(body.contains("5 writers still on the decoy"), "{body}");
    assert!(body.contains("w3 (PID 3)"), "{body}");
    assert!(!body.contains("w4 (PID 4)"), "{body}");
    assert!(body.contains("and 2 more"), "{body}");
}

#[test]
fn overlay_status_notification_without_writers_has_no_leak_clause() {
    let body = overlay_status_body("OPTIMAL", 3, 1, &[]);
    assert!(
        body.starts_with("Security: OPTIMAL — 4 overlay(s) mounted (3 direct, 1 pivot)"),
        "{body}"
    );
    assert!(!body.contains("writer"), "{body}");
}

#[test]
fn overlay_status_notification_records_the_emergency_command() {
    let body = overlay_status_body("OPTIMAL", 1, 0, &[]);
    // The RAM-backed panic button, with the neutral control-copy path and no
    // product name anywhere in the body.
    assert!(
        body.contains("sudo /run/overlay-runtime/control emergency"),
        "{body}"
    );
    assert!(!body.to_lowercase().contains("nails"), "{body}");
}

// ===========================================================================
// Activation mount rollback (T-063)
//
// When activation fails *after* overlays are mounted, the overlays must be
// unmounted before the state is rolled back, so the system never records a
// clean state while NAILS mounts are still live, and the session is restarted
// onto the decoy only after the unmounts.
// ===========================================================================

/// Build a manager with two explicit overlays (`/home`, `/etc`) wired to mount
/// successfully on the mock, with state on a temporary hidden volume. Returns
/// the manager, a filesystem handle sharing its state, and the temp dir guard.
fn rollback_test_manager() -> (
    NailsManager<MockFilesystem>,
    MockFilesystem,
    tempfile::TempDir,
) {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let hv = temp_dir.path().to_path_buf();
    std::fs::create_dir_all(&hv).expect("hidden volume dir");
    let state_path = hv.join("state.json");
    let hv_str = hv.to_string_lossy().to_string();

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_path_exists("/etc", true);
    fs.mock_set_path_exists(&hv_str, true);
    for sub in ["home-upper", "home-work", "etc-upper", "etc-work"] {
        fs.mock_set_path_exists(&format!("{hv_str}/{sub}"), true);
    }
    fs.mock_set_writable(&hv_str, true);
    fs.mock_set_writable("/", true);
    fs.mock_set_readable("/", true);
    fs.mock_set_readable("/home", true);
    fs.mock_set_readable("/etc", true);
    fs.mock_set_path_exists("/nix/var/nix/profiles/system", true);
    fs.mock_set_path_exists(
        "/nix/var/nix/profiles/system/bin/switch-to-configuration",
        true,
    );

    let config = Config {
        hidden_volume_root: hv.clone(),
        state_file_path: state_path.clone(),
        overlays: vec![
            OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: hv.join("home-upper"),
                work: hv.join("home-work"),
                target: PathBuf::from("/home"),
            },
            OverlayConfig {
                name: "etc".to_string(),
                lower: PathBuf::from("/"),
                upper: hv.join("etc-upper"),
                work: hv.join("etc-work"),
                target: PathBuf::from("/etc"),
            },
        ],
        overlay_mode: crate::OverlayMode::Explicit,
        ..Config::test_default()
    };

    let manager = NailsManager::new(fs.clone(), config, state_path);
    (manager, fs, temp_dir)
}

#[test]
fn activation_refuses_an_unsupported_host_before_any_state_write() {
    let (mut manager, fs, _tmp) = rollback_test_manager();

    let state_before = manager.current_state().expect("state");
    manager.set_host_profile(crate::platform::HostProfile {
        kind: crate::platform::PlatformKind::Unsupported,
        id: Some("fedora".to_string()),
        id_like: vec![],
        version_id: None,
        is_systemd: true,
        is_ostree: true,
        has_current_system: false,
        unsupported_reason: Some("ostree / image-based host".to_string()),
    });

    let result = manager.activate(true);
    assert!(
        matches!(result, Err(crate::NailsError::UnsupportedPlatform { .. })),
        "an unsupported host must be refused, got {result:?}"
    );
    // Nothing was staged, mounted or written: state is untouched and no overlays
    // exist.
    assert_eq!(manager.current_state().expect("state"), state_before);
    assert!(
        fs.get_mounted_paths().is_empty(),
        "refusal must happen before any overlay is mounted"
    );
}

#[test]
fn activation_without_a_host_profile_is_not_gated() {
    // A manager whose platform was never detected (the common unit-test path)
    // still activates: the gate is a no-op until a profile is injected.
    let (mut manager, _fs, _tmp) = rollback_test_manager();
    assert!(manager.host_profile().is_none());
    manager.activate(true).expect("activation should succeed");
}

#[test]
fn successful_activation_keeps_overlays_and_does_not_roll_back() {
    let (mut manager, fs, _tmp) = rollback_test_manager();

    manager.activate(true).expect("activation should succeed");

    assert!(matches!(
        manager.current_state().expect("state"),
        SystemState::Active { .. }
    ));
    // The activation-scope guard was disarmed, so the overlays are still mounted.
    assert!(fs.is_mounted(Path::new("/home")).expect("/home mounted"));
    assert!(fs.is_mounted(Path::new("/etc")).expect("/etc mounted"));
}

#[test]
#[serial]
fn failure_at_active_state_write_unmounts_overlays_and_restores_inactive() {
    use crate::state::save_probe::{self, FailOn};

    let (mut manager, fs, _tmp) = rollback_test_manager();

    // Fail only the Activating -> Active write; the overlays mount first.
    save_probe::arm(&[FailOn::Active]);
    let result = manager.activate(true);
    save_probe::disarm();

    assert!(
        result.is_err(),
        "activation must fail when the Active state write fails"
    );
    assert!(
        fs.get_mounted_paths().is_empty(),
        "overlays must be unmounted on rollback, still mounted: {:?}",
        fs.get_mounted_paths()
    );
    assert!(
        matches!(
            manager.current_state().expect("state"),
            SystemState::Inactive
        ),
        "state must roll back to Inactive when every overlay came down"
    );
    // A clean rollback is reported as Completed so the CLI prints the plain
    // "Automatic rollback completed." line.
    assert_eq!(manager.last_rollback(), crate::RollbackOutcome::Completed);
}

#[test]
#[serial]
fn failure_before_any_mount_records_no_rollback() {
    let (mut manager, _fs, _tmp) = rollback_test_manager();

    // Mutually-exclusive options fail at `options.validate()`, before any overlay
    // or guard exists.
    let options = crate::ActivateOptions {
        no_pivot: true,
        accept_pivot_risks: true,
        ..Default::default()
    };
    let result = manager.activate_with_options(options, true);

    assert!(result.is_err(), "invalid options must fail");
    // No overlay was mounted, so no rollback ran: the CLI must print no rollback
    // line at all.
    assert_eq!(manager.last_rollback(), crate::RollbackOutcome::NotNeeded);
}

#[test]
#[serial]
fn failure_during_rollback_unmount_marks_state_degraded() {
    use crate::state::save_probe::{self, FailOn};

    let (mut manager, fs, _tmp) = rollback_test_manager();
    // /etc cannot be unmounted, so rollback leaves it live.
    fs.mock_set_unmount_should_fail("/etc", true);

    save_probe::arm(&[FailOn::Active]);
    let result = manager.activate(true);
    save_probe::disarm();

    assert!(result.is_err(), "activation must fail");
    // /home comes down (best-effort), /etc stays live.
    assert!(!fs.is_mounted(Path::new("/home")).expect("/home status"));
    assert!(fs.is_mounted(Path::new("/etc")).expect("/etc status"));

    match manager.current_state().expect("state") {
        SystemState::Degraded {
            remaining_mounts, ..
        } => assert!(
            remaining_mounts.contains(&PathBuf::from("/etc")),
            "degraded state must list the still-live mount, got {remaining_mounts:?}"
        ),
        other => panic!("expected Degraded with remaining mounts, got {other:?}"),
    }
    // The rollback could not undo everything, so it is reported as Failed, naming
    // the mount left behind; the CLI prints the "rollback FAILED" bullets.
    match manager.last_rollback() {
        crate::RollbackOutcome::Failed(items) => assert!(
            items.iter().any(|i| i.contains("/etc")),
            "failed rollback must name the still-live mount, got {items:?}"
        ),
        other => panic!("expected Failed rollback outcome, got {other:?}"),
    }
}

#[test]
#[serial]
fn failed_session_restart_unmounts_before_restart_and_restores_inactive() {
    use super::guards::test_hooks::{SessionRestartTestGuard, recorded_systemctl};
    use super::rollback::test_events::{ActivationEvent, EventRecorder};
    use crate::process::SessionRestartPlan;

    let (mut manager, fs, _tmp) = rollback_test_manager();

    // Inject a non-default restart plan (so the after-overlay restart step runs)
    // and a recording executor whose every command fails — the post-mount
    // failure under test. The same executor backs both the success-path restart
    // and the guard's error-path restart.
    let _restart = SessionRestartTestGuard::arm(
        SessionRestartPlan {
            display_manager: Some("display-manager.service".to_string()),
            target_uid: Some(1000),
        },
        true,
    );
    let _recorder = EventRecorder::arm();

    let result = manager.activate(true);

    assert!(
        result.is_err(),
        "activation must fail when the session restart fails"
    );
    assert!(
        fs.get_mounted_paths().is_empty(),
        "overlays must be unmounted, still mounted: {:?}",
        fs.get_mounted_paths()
    );
    assert!(matches!(
        manager.current_state().expect("state"),
        SystemState::Inactive
    ));

    // The overlays were torn down before the state was restored to Inactive:
    // rollback recorded at least one unmount, and nothing but unmounts.
    let events = EventRecorder::events();
    assert!(
        !events.is_empty()
            && events
                .iter()
                .all(|e| matches!(e, ActivationEvent::Unmounted(_))),
        "rollback must unmount every overlay, got {events:?}"
    );

    // The production restart code actually ran: the success-path call issued the
    // display-manager start, and the guard's best-effort drop then tried to bring
    // the user and display managers back onto the decoy.
    let systemctl = recorded_systemctl();
    assert_eq!(
        systemctl.first().map(Vec::as_slice),
        Some(["start".to_string(), "display-manager.service".to_string()].as_slice()),
        "the after-overlay restart must start the display manager first, got {systemctl:?}"
    );
    assert!(
        systemctl
            .iter()
            .any(|call| call.as_slice() == ["start", "user@1000.service"]),
        "the error-path restart must try to bring the user manager back, got {systemctl:?}"
    );
    assert!(
        systemctl
            .iter()
            .filter(|call| call.as_slice() == ["start", "display-manager.service"])
            .count()
            >= 2,
        "the display manager restart must be attempted on both paths, got {systemctl:?}"
    );
}

#[test]
fn restart_session_after_success_starts_the_display_manager() {
    use crate::process::SessionRestartPlan;
    use crate::process::session::tests_common::RecordingScriptedSessionCommandExecutor;

    // start + is-active both succeed, so the restart returns without polling.
    let exec = RecordingScriptedSessionCommandExecutor::new(
        vec![
            Ok((true, String::new(), String::new())),
            Ok((true, "active".to_string(), String::new())),
        ],
        Vec::new(),
        false,
    );
    let plan = SessionRestartPlan {
        display_manager: Some("display-manager.service".to_string()),
        target_uid: Some(1000),
    };

    super::restart_session_after_success(&plan, &exec).expect("restart succeeds");

    // A plan with a display manager restarts through it alone; the login stack
    // brings the user manager back, so user@UID is not started explicitly.
    assert_eq!(
        exec.systemctl_calls(),
        vec![
            vec!["start".to_string(), "display-manager.service".to_string()],
            vec![
                "is-active".to_string(),
                "display-manager.service".to_string()
            ],
        ]
    );
}

#[test]
fn restart_session_after_success_starts_the_user_manager_without_a_display_manager() {
    use crate::process::SessionRestartPlan;
    use crate::process::session::tests_common::RecordingScriptedSessionCommandExecutor;

    let exec = RecordingScriptedSessionCommandExecutor::new(
        vec![
            Ok((true, String::new(), String::new())),
            Ok((true, String::new(), String::new())),
        ],
        Vec::new(),
        false,
    );
    let plan = SessionRestartPlan {
        display_manager: None,
        target_uid: Some(1000),
    };

    super::restart_session_after_success(&plan, &exec).expect("restart succeeds");

    assert_eq!(
        exec.systemctl_calls(),
        vec![
            vec![
                "start".to_string(),
                "user-runtime-dir@1000.service".to_string()
            ],
            vec!["start".to_string(), "user@1000.service".to_string()],
        ]
    );
}

#[test]
fn restart_session_after_success_propagates_a_failed_start() {
    use crate::process::SessionRestartPlan;
    use crate::process::session::tests_common::RecordingScriptedSessionCommandExecutor;

    let exec = RecordingScriptedSessionCommandExecutor::new(
        vec![Ok((false, String::new(), "boom".to_string()))],
        Vec::new(),
        false,
    );
    let plan = SessionRestartPlan {
        display_manager: Some("display-manager.service".to_string()),
        target_uid: None,
    };

    assert!(
        super::restart_session_after_success(&plan, &exec).is_err(),
        "a failed display-manager start must surface as an error"
    );
}

#[test]
#[serial]
fn session_restart_guard_restarts_the_session_on_drop() {
    use super::guards::SessionRestartGuard;
    use super::guards::test_hooks::{
        SessionRestartTestGuard, recorded_systemctl, session_executor,
    };
    use crate::process::SessionRestartPlan;

    let plan = SessionRestartPlan {
        display_manager: Some("display-manager.service".to_string()),
        target_uid: Some(1000),
    };
    // Arming installs the recording executor and lets its commands succeed.
    let _arm = SessionRestartTestGuard::arm(plan.clone(), false);

    drop(SessionRestartGuard::new(plan, session_executor()));

    // The error-path drop brings the user manager back first, then the display
    // manager (polling it until active).
    assert_eq!(
        recorded_systemctl(),
        vec![
            vec![
                "start".to_string(),
                "user-runtime-dir@1000.service".to_string()
            ],
            vec!["start".to_string(), "user@1000.service".to_string()],
            vec!["start".to_string(), "display-manager.service".to_string()],
            vec![
                "is-active".to_string(),
                "display-manager.service".to_string()
            ],
        ]
    );
}

#[test]
#[serial]
fn session_restart_guard_issues_nothing_when_disarmed() {
    use super::guards::SessionRestartGuard;
    use super::guards::test_hooks::{
        SessionRestartTestGuard, recorded_systemctl, session_executor,
    };
    use crate::process::SessionRestartPlan;

    let plan = SessionRestartPlan {
        display_manager: Some("display-manager.service".to_string()),
        target_uid: Some(1000),
    };
    let _arm = SessionRestartTestGuard::arm(plan.clone(), false);

    let mut guard = SessionRestartGuard::new(plan, session_executor());
    guard.disarm();
    drop(guard);

    assert!(
        recorded_systemctl().is_empty(),
        "a disarmed guard must not restart the session"
    );
}

#[test]
#[serial]
fn session_restart_guard_issues_nothing_for_an_empty_plan() {
    use super::guards::SessionRestartGuard;
    use super::guards::test_hooks::{
        SessionRestartTestGuard, recorded_systemctl, session_executor,
    };
    use crate::process::SessionRestartPlan;

    let _arm = SessionRestartTestGuard::arm(SessionRestartPlan::default(), false);

    drop(SessionRestartGuard::new(
        SessionRestartPlan::default(),
        session_executor(),
    ));

    assert!(
        recorded_systemctl().is_empty(),
        "an empty plan has no session to restart"
    );
}

// --- Rebuild-floor space re-check (T-096) --------------------------------

/// Build an inactive manager whose hidden volume lives at a known path, with a
/// NixOS builder attached, the given free space, and the given rebuild floor.
fn rebuild_space_manager(
    hidden_root: &str,
    available_bytes: u64,
    rebuild_space_mb: u64,
) -> (NailsManager<MockFilesystem>, tempfile::TempDir) {
    use crate::TestWorld;
    use crate::nixos::NixOSBuilder;

    let fs = MockFilesystem::new();
    fs.mock_set_disk_usage(
        Path::new(hidden_root),
        100 * 1024 * 1024 * 1024,
        available_bytes,
    );

    let config = Config {
        hidden_volume_root: PathBuf::from(hidden_root),
        state_file_path: PathBuf::from(hidden_root).join("state.json"),
        log_path: PathBuf::from(hidden_root).join("logs"),
        overlays: Vec::new(),
        rebuild_space_mb,
        ..Config::test_default()
    };

    let builder = NixOSBuilder::new_with_flake_ref(
        "/etc/nixos#host".to_string(),
        PathBuf::from(hidden_root).join("nails-system"),
    );

    TestWorld::new()
        .with_filesystem(fs)
        .with_config(config)
        .with_nixos(builder)
        .inactive()
        .manager()
}

#[test]
fn rebuild_expected_only_without_a_cached_toplevel() {
    let (manager, _tmp) = rebuild_space_manager("/mnt/hidden-a", 8 * 1024 * 1024 * 1024, 4096);
    // No cached toplevel + a builder + a config layer => a full build will run.
    assert!(manager.rebuild_expected(&None));
    // A carried-forward fast-path toplevel skips the build.
    assert!(!manager.rebuild_expected(&Some("/nix/store/x-nixos-system".to_string())));
}

#[test]
fn rebuild_space_check_fails_below_the_rebuild_floor() {
    // 2 GiB free with a 4 GiB rebuild floor: a rebuild is expected, so the
    // post-mount re-check must fail before any build runs.
    let (manager, _tmp) = rebuild_space_manager("/mnt/hidden-b", 2 * 1024 * 1024 * 1024, 4096);
    assert!(manager.rebuild_expected(&None));
    let err = manager
        .ensure_rebuild_space_before_build(&None)
        .unwrap_err();
    assert!(matches!(err, NailsError::NixOSError(_)), "{err:?}");
}

#[test]
fn rebuild_space_check_passes_above_the_rebuild_floor() {
    // 8 GiB free with a 4 GiB floor: the re-check passes.
    let (manager, _tmp) = rebuild_space_manager("/mnt/hidden-c", 8 * 1024 * 1024 * 1024, 4096);
    assert!(manager.ensure_rebuild_space_before_build(&None).is_ok());
}

#[test]
fn rebuild_space_check_skips_when_no_rebuild_is_expected() {
    // A carried-forward fast-path toplevel means no build, so even a tiny volume
    // passes the rebuild re-check (the base floor still guards overlay-only).
    let (manager, _tmp) = rebuild_space_manager("/mnt/hidden-d", 64 * 1024 * 1024, 4096);
    let fast_path = Some("/nix/store/x-nixos-system".to_string());
    assert!(!manager.rebuild_expected(&fast_path));
    assert!(
        manager
            .ensure_rebuild_space_before_build(&fast_path)
            .is_ok()
    );
}

// ===========================================================================
// Signal cancellation (T-101)
//
// A cancel signal (SIGINT/SIGTERM) sets a process-wide flag that the activation
// path polls between steps via `cancel::checkpoint`. When it is armed before the
// overlay step, activation must return `Cancelled`, the overlays must never be
// mounted, and the state must roll back to `Inactive`.
// ===========================================================================

#[test]
#[serial]
fn cancel_before_overlay_step_returns_cancelled_with_no_mounts_and_inactive_state() {
    use crate::cancel;

    let (mut manager, fs, _tmp) = rollback_test_manager();

    // Arm the cancel flag as a SIGINT/SIGTERM handler would, before activation
    // reaches the overlay step.
    cancel::testing::request();
    let result = manager.activate(true);
    cancel::testing::reset();

    assert!(
        matches!(result, Err(crate::NailsError::Cancelled)),
        "a cancel requested before the overlay step must return Cancelled, got {result:?}"
    );
    assert!(
        fs.get_mounted_paths().is_empty(),
        "no overlay may be mounted when activation is cancelled before the overlay step, \
         still mounted: {:?}",
        fs.get_mounted_paths()
    );
    assert!(
        matches!(
            manager.current_state().expect("state"),
            SystemState::Inactive
        ),
        "a cancelled activation must roll the state back to Inactive"
    );
}

#[test]
#[serial]
fn no_cancel_lets_activation_complete() {
    use crate::cancel;

    // The flag must be clear by default so an ordinary activation is unaffected.
    cancel::testing::reset();
    let (mut manager, fs, _tmp) = rollback_test_manager();
    manager.activate(true).expect("activation should succeed");
    assert!(matches!(
        manager.current_state().expect("state"),
        SystemState::Active { .. }
    ));
    assert!(fs.is_mounted(Path::new("/home")).expect("/home mounted"));
}

#[test]
fn step_progress_numbers_steps_contiguously_up_to_the_total() {
    // The layer path emits seven steps: the counter ends exactly at the total.
    let mut step = StepProgress::new(Verbosity::Normal, 7);
    for _ in 0..7 {
        step.emit("phase", "message");
    }
    assert_eq!(step.current, 7);
    assert_eq!(step.total, 7);
}

#[test]
fn protected_base_units_are_never_treated_as_hidden_added() {
    // Core decoy services that merely cycle while the overlays settle must never
    // be recorded as hidden-added, or emergency would stop them and break the
    // live decoy.
    for unit in [
        "systemd-udevd.service",
        "systemd-journald.service",
        "systemd-logind.service",
        "systemd-user-sessions.service",
        "dbus.service",
        "polkit.service",
        "nix-daemon.service",
        "getty@tty1.service",
        "serial-getty@ttyS0.service",
        "autovt@tty2.service",
    ] {
        assert!(is_protected_base_unit(unit), "{unit} must be protected");
    }

    // A genuine hidden-session service is still recorded for teardown.
    for unit in ["myhidden-agent.service", "ssh-tunnel.service"] {
        assert!(
            !is_protected_base_unit(unit),
            "{unit} must not be protected"
        );
    }
}

#[test]
fn record_hidden_added_units_ignores_units_known_before_the_switch() {
    // The "before" snapshot lists every unit the host knew, active or not. A base
    // service that restarted during the switch (here an arbitrary decoy unit that
    // is not on the protected list) was known before, so it is not recorded; only
    // the unit the hidden generation introduced is.
    let fs = MockFilesystem::new();
    let config = Config::test_default();
    let state_path = PathBuf::from("/mnt/data/state.json");
    let manager = NailsManager::new(fs, config, state_path);
    manager.seed_cached_state(crate::StateFile::default());

    let known_before = vec![
        "cups.service".to_string(),
        "NetworkManager.service".to_string(),
    ];
    let active_after = vec![
        "cups.service".to_string(),
        "NetworkManager.service".to_string(),
        "myhidden-agent.service".to_string(),
    ];
    manager.record_hidden_added_units(
        &HiddenConfigOutcome::Applied {
            toplevel: None,
            fast_path: false,
        },
        &known_before,
        &active_after,
    );

    let recorded = manager
        .cached_state
        .borrow()
        .as_ref()
        .expect("cached state seeded")
        .hidden_added_units
        .clone();
    assert_eq!(recorded, vec!["myhidden-agent.service".to_string()]);
}

#[test]
fn record_hidden_added_units_drops_protected_base_units() {
    // A base service that was inactive in the "before" snapshot and active again
    // in "after" (a mid-switch cycle) must not land in the hidden-added set; a
    // real hidden service in the diff still does.
    let fs = MockFilesystem::new();
    let config = Config::test_default();
    let state_path = PathBuf::from("/mnt/data/state.json");
    let manager = NailsManager::new(fs, config, state_path);
    manager.seed_cached_state(crate::StateFile::default());

    let before = vec!["dbus.service".to_string()];
    let after = vec![
        "dbus.service".to_string(),
        "systemd-udevd.service".to_string(),
        "myhidden-agent.service".to_string(),
    ];
    manager.record_hidden_added_units(
        &HiddenConfigOutcome::Applied {
            toplevel: None,
            fast_path: false,
        },
        &before,
        &after,
    );

    let recorded = manager
        .cached_state
        .borrow()
        .as_ref()
        .expect("cached state seeded")
        .hidden_added_units
        .clone();
    assert_eq!(recorded, vec!["myhidden-agent.service".to_string()]);
}

#[test]
fn record_hidden_added_units_records_nothing_when_the_before_snapshot_is_empty() {
    // An empty "before" snapshot means the host's units could not be enumerated.
    // Trusting the diff then would mark every active unit as hidden-added and have
    // emergency stop the whole running system (the operator's shell and the live
    // decoy with it). Record nothing instead.
    let fs = MockFilesystem::new();
    let config = Config::test_default();
    let state_path = PathBuf::from("/mnt/data/state.json");
    let manager = NailsManager::new(fs, config, state_path);
    manager.seed_cached_state(crate::StateFile::default());

    let before: Vec<String> = Vec::new();
    let after = vec![
        "getty@tty1.service".to_string(),
        "sshd.service".to_string(),
        "dhcpcd.service".to_string(),
    ];
    manager.record_hidden_added_units(
        &HiddenConfigOutcome::Applied {
            toplevel: None,
            fast_path: false,
        },
        &before,
        &after,
    );

    let recorded = manager
        .cached_state
        .borrow()
        .as_ref()
        .expect("cached state seeded")
        .hidden_added_units
        .clone();
    assert!(
        recorded.is_empty(),
        "an empty before-snapshot must record no hidden-added units, got: {recorded:?}"
    );
}

#[test]
fn record_hidden_added_units_records_nothing_without_an_applied_switch() {
    // An overlay-only run (no hidden NixOS switch) reports `NotRequested` and adds
    // no units. Recording the active-unit snapshot there would mark the live decoy
    // units as hidden-added and have emergency stop the running system, so an
    // unapplied outcome must record nothing regardless of the diff.
    let fs = MockFilesystem::new();
    let config = Config::test_default();
    let state_path = PathBuf::from("/mnt/data/state.json");
    let manager = NailsManager::new(fs, config, state_path);
    manager.seed_cached_state(crate::StateFile::default());

    let before = vec!["cups.service".to_string()];
    let after = vec![
        "cups.service".to_string(),
        "myhidden-agent.service".to_string(),
    ];
    for outcome in [
        HiddenConfigOutcome::NotRequested,
        HiddenConfigOutcome::Failed {
            reason: "build failed".to_string(),
        },
    ] {
        manager.record_hidden_added_units(&outcome, &before, &after);
        let recorded = manager
            .cached_state
            .borrow()
            .as_ref()
            .expect("cached state seeded")
            .hidden_added_units
            .clone();
        assert!(
            recorded.is_empty(),
            "{outcome:?} must record no hidden-added units, got: {recorded:?}"
        );
    }
}

#[test]
fn step_progress_total_follows_the_overlay_only_path() {
    // With no declarative layer the two NixOS steps are skipped, so the derived
    // total is five and the five emitted steps number 1..=5 contiguously.
    let mut step = StepProgress::new(Verbosity::Quiet, 5);
    for expected in 1..=5 {
        step.emit("phase", "message");
        assert_eq!(step.current, expected);
    }
    assert_eq!(step.total, 5);
}
