use super::gate::ActivationGateTestGuard;
use super::maybe_block_after_activating_state_transition;
use super::{
    INTEGRITY_VERIFIED_TARGETS, SessionRestartPhase, derive_security_label,
    determine_session_restart_phase, overlay_status_body, record_surviving_writers,
};
use crate::DecoyWriter;
use crate::overlay::SurvivingWriter;
use crate::test_support::EnvGuard;
use crate::{Config, Filesystem, MockFilesystem, NailsManager, OverlayConfig, SystemState};
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
    let msg = err.to_string();

    assert!(msg.contains("Failed to prepare activation test marker directory"));
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
        .find("[4/7] Mounting overlays...")
        .expect("overlay progress marker");
    let switch_idx = source
        .find("[5/7] Running NixOS switch/rebuild...")
        .expect("switch progress marker");
    let restart_idx = source
        .find("[6/7] Restarting session/display manager...")
        .expect("session restart progress marker");

    // The hidden NixOS switch runs before the session restart, so the restarted
    // session comes up under the hidden configuration and a failed switch never
    // brings the decoy session up first.
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
    assert!(body.ends_with("and 2 more"), "{body}");
}

#[test]
fn overlay_status_notification_without_writers_has_no_leak_clause() {
    let body = overlay_status_body("OPTIMAL", 3, 1, &[]);
    assert_eq!(
        body,
        "Security: OPTIMAL — 4 overlay(s) mounted (3 direct, 1 pivot)"
    );
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
}

#[test]
#[serial]
fn failed_session_restart_unmounts_before_restart_and_restores_inactive() {
    use super::guards::test_hooks::SessionRestartTestGuard;
    use super::rollback::test_events::{ActivationEvent, EventRecorder};
    use crate::process::SessionRestartPlan;

    let (mut manager, fs, _tmp) = rollback_test_manager();

    // Inject a non-default restart plan (so the after-overlay restart step runs)
    // and force that restart to fail — the post-mount failure under test.
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

    // Ordering: every overlay unmount is recorded before the error-path session
    // restart, so the display manager comes back onto the decoy.
    let events = EventRecorder::events();
    assert_eq!(
        events.last(),
        Some(&ActivationEvent::SessionRestart),
        "session restart must be the last recorded step, got {events:?}"
    );
    let restart_idx = events
        .iter()
        .position(|e| *e == ActivationEvent::SessionRestart)
        .expect("session restart recorded");
    assert!(restart_idx > 0, "at least one unmount before the restart");
    assert!(
        events[..restart_idx]
            .iter()
            .all(|e| matches!(e, ActivationEvent::Unmounted(_))),
        "all steps before the restart must be unmounts, got {events:?}"
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
    let text = err.to_string();
    assert!(text.contains("rebuild_space_mb"), "{text}");
    assert!(text.contains("rolled back"), "{text}");
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
