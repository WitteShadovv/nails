// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

/// Mount a NAILS-owned overlay at `target` whose upper/work live under the
/// hidden root, so [`Filesystem::discover_nails_mounts`] classifies it as a
/// persistent NAILS overlay the teardown must remove.
fn mount_nails_overlay(fs: &MockFilesystem, hidden_root: &Path, target: &Path) {
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "root".to_string());
    let upper = hidden_root.join(&name);
    let work = hidden_root.join(".work").join(&name);
    fs.mock_mount_nails_overlay(target, &upper, &work);
}

#[test]
fn test_emergency_deactivate_from_inactive_state_with_no_mounts_succeeds() {
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

    // The panic button must never refuse: an Inactive system with nothing to tear
    // down is a clean success, not an error.
    manager.lock().unwrap().emergency_deactivate().unwrap();
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );
}
#[test]
fn test_emergency_deactivate_from_activating_state_tears_down_overlays() {
    let manager = setup_manager_in_state(SystemState::Activating {
        started_at: chrono::Utc::now(),
    });

    let hidden_root = manager.lock().unwrap().config().hidden_volume_root.clone();
    {
        let guard = manager.lock().unwrap();
        let fs = guard.filesystem();
        mount_nails_overlay(fs, &hidden_root, Path::new("/home"));
        mount_nails_overlay(fs, &hidden_root, Path::new("/etc"));
    }

    // Emergency during the switch (state is Activating) must tear the overlays
    // down from the live mount table and end Inactive, not refuse.
    manager.lock().unwrap().emergency_deactivate().unwrap();

    let guard = manager.lock().unwrap();
    assert_eq!(guard.current_state().unwrap(), SystemState::Inactive);
    assert!(!guard.filesystem().is_mounted(Path::new("/home")).unwrap());
    assert!(!guard.filesystem().is_mounted(Path::new("/etc")).unwrap());
}
#[test]
fn test_emergency_deactivate_from_deactivating_state_tears_down_overlays() {
    let manager = setup_manager_in_state(SystemState::Deactivating {
        started_at: chrono::Utc::now(),
    });

    let hidden_root = manager.lock().unwrap().config().hidden_volume_root.clone();
    {
        let guard = manager.lock().unwrap();
        let fs = guard.filesystem();
        mount_nails_overlay(fs, &hidden_root, Path::new("/home"));
        mount_nails_overlay(fs, &hidden_root, Path::new("/etc"));
    }

    // Emergency after an interrupted teardown (state is Deactivating) must finish
    // the job from the live mount table and end Inactive.
    manager.lock().unwrap().emergency_deactivate().unwrap();

    let guard = manager.lock().unwrap();
    assert_eq!(guard.current_state().unwrap(), SystemState::Inactive);
    assert!(!guard.filesystem().is_mounted(Path::new("/home")).unwrap());
    assert!(!guard.filesystem().is_mounted(Path::new("/etc")).unwrap());
}

#[test]
fn test_recover_tears_down_remaining_mounts_from_degraded_state() {
    let manager = setup_manager_in_state(SystemState::Degraded {
        since: chrono::Utc::now(),
        reason: "interrupted teardown".to_string(),
        remaining_mounts: vec![PathBuf::from("/home")],
    });

    let hidden_root = manager.lock().unwrap().config().hidden_volume_root.clone();
    {
        let guard = manager.lock().unwrap();
        mount_nails_overlay(guard.filesystem(), &hidden_root, Path::new("/home"));
    }

    let outcome = manager.lock().unwrap().recover().unwrap();
    assert!(!outcome.was_already_inactive);
    assert!(outcome.state_backed_up.is_none());

    let guard = manager.lock().unwrap();
    assert_eq!(guard.current_state().unwrap(), SystemState::Inactive);
    assert!(!guard.filesystem().is_mounted(Path::new("/home")).unwrap());
}

#[test]
fn test_recover_is_a_no_op_when_already_inactive() {
    let manager = setup_manager_in_state(SystemState::Inactive);

    let outcome = manager.lock().unwrap().recover().unwrap();
    assert!(outcome.was_already_inactive);
    assert!(outcome.state_backed_up.is_none());
    assert_eq!(
        manager.lock().unwrap().current_state().unwrap(),
        SystemState::Inactive
    );
}

#[test]
fn test_recover_backs_up_a_corrupt_state_file() {
    let manager = setup_manager_in_state(SystemState::Activating {
        started_at: chrono::Utc::now(),
    });

    let state_path = manager.lock().unwrap().config().state_file_path.clone();
    // Corrupt the on-disk state file so its load outcome is unknown; recovery must
    // preserve it before the teardown overwrites it.
    std::fs::write(&state_path, b"this is not valid json").unwrap();

    let outcome = manager.lock().unwrap().recover().unwrap();
    assert!(!outcome.was_already_inactive);

    let backup = outcome
        .state_backed_up
        .expect("corrupt state file must be backed up");
    assert_eq!(backup.file_name().unwrap(), "state.json.bad");
    assert!(backup.exists(), "backup file must be on disk");
    assert_eq!(
        std::fs::read(&backup).unwrap(),
        b"this is not valid json".to_vec()
    );
}

#[test]
fn test_emergency_deactivate_force_unmount_succeeds_after_graceful_failure() {
    let fs = MockFilesystem::new();
    let profile = setup_system_profile_stub(&fs);
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

    let manager = Arc::new(Mutex::new(
        NailsManager::new(fs, config, state_path).with_runtime_env(profile.env.clone()),
    ));

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
fn test_emergency_deactivate_restarts_nix_daemon_when_nix_store_unmount_fails() {
    let fs = MockFilesystem::new();
    let profile = setup_system_profile_stub(&fs);
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

    let manager = Arc::new(Mutex::new(
        NailsManager::new(fs, config, state_path).with_runtime_env(profile.env.clone()),
    ));

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
fn test_emergency_deactivate_missing_switch_script_keeps_inactive_state() {
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
    let runtime_env = crate::RuntimeEnv::empty().with_system_profile_path(&system_profile);
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

    let manager = Arc::new(Mutex::new(
        NailsManager::new(fs, config, state_path.clone()).with_runtime_env(runtime_env.clone()),
    ));

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
fn test_emergency_deactivate_unmounts_nix_store_when_nix_overlay_present() {
    let fs = MockFilesystem::new();
    let profile = setup_system_profile_stub(&fs);
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

    let manager = Arc::new(Mutex::new(
        NailsManager::new(fs, config, state_path).with_runtime_env(profile.env.clone()),
    ));

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
#[test]
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
}
#[test]
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
fn test_emergency_deactivate_removes_the_runtime_copy() {
    let manager = setup_manager_in_state(SystemState::Activating {
        started_at: chrono::Utc::now(),
    });

    let hidden_root = manager.lock().unwrap().config().hidden_volume_root.clone();
    {
        let guard = manager.lock().unwrap();
        let fs = guard.filesystem();
        mount_nails_overlay(fs, &hidden_root, Path::new("/home"));

        // A runtime copy left from the live session, as activation would have
        // written it. The removal routes through the manager's (mock) filesystem,
        // so a teardown must clear it.
        fs.mock_set_directory_creatable(crate::runtime_copy::RUNTIME_COPY_DIR, true);
        crate::runtime_copy::write_runtime_copy(
            fs,
            guard.config(),
            Path::new("/bin/control"),
            &[PathBuf::from("/home")],
        )
        .unwrap();
        assert!(
            fs.path_exists(&crate::runtime_copy::runtime_copy_dir())
                .unwrap()
        );
    }

    manager.lock().unwrap().emergency_deactivate().unwrap();

    let guard = manager.lock().unwrap();
    assert_eq!(guard.current_state().unwrap(), SystemState::Inactive);
    assert!(
        !guard
            .filesystem()
            .path_exists(&crate::runtime_copy::runtime_copy_dir())
            .unwrap(),
        "emergency teardown must remove the RAM-backed runtime copy"
    );
}

#[test]
fn test_normal_deactivate_removes_the_runtime_copy() {
    let (manager, _temp) = active_manager_with_overlays(&["/home"]);

    {
        let guard = manager.lock().unwrap();
        let fs = guard.filesystem();
        fs.mock_set_directory_creatable(crate::runtime_copy::RUNTIME_COPY_DIR, true);
        crate::runtime_copy::write_runtime_copy(
            fs,
            guard.config(),
            Path::new("/bin/control"),
            &[PathBuf::from("/home")],
        )
        .unwrap();
    }

    manager.lock().unwrap().deactivate().unwrap();

    let guard = manager.lock().unwrap();
    assert!(
        !guard
            .filesystem()
            .path_exists(&crate::runtime_copy::runtime_copy_dir())
            .unwrap(),
        "deactivate must remove the RAM-backed runtime copy"
    );
}

#[test]
fn test_emergency_stops_recorded_units_but_never_touches_the_session_or_dm() {
    let fs = MockFilesystem::new();
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let config = Config {
        hidden_volume_root: hidden_root.clone(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };

    // State as activation would have recorded it: Active with one overlay, two
    // units the hidden switch added, and the graphical session it took over.
    let upper_dir = hidden_root.join("home");
    let work_dir = hidden_root.join(".work/home");
    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        crate::OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/"),
            upper_dir: upper_dir.clone(),
            work_dir: work_dir.clone(),
            mounted_at: chrono::Utc::now(),
        },
    );
    StateFile {
        state: SystemState::Active {
            decoy_writers: Vec::new(),
            activated_at: chrono::Utc::now(),
            overlays: vec![PathBuf::from("/home")],
        },
        overlay_status,
        hidden_added_units: vec![
            "hidden-app.service".to_string(),
            "hidden-config.service".to_string(),
        ],
        hidden_session: Some(crate::state::HiddenSession {
            target_uid: 1000,
            session_id: Some("c7".to_string()),
            display_manager: Some("display-manager.service".to_string()),
        }),
        ..StateFile::default()
    }
    .save_with_custom_root(&state_path, &hidden_root)
    .unwrap();

    let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));
    {
        let guard = manager.lock().unwrap();
        mount_nails_overlay(guard.filesystem(), &hidden_root, Path::new("/home"));
    }

    // Start from a clean recorder so only this teardown's actions are observed.
    let _ = crate::manager::helpers::drain_recorded_service_actions();

    manager.lock().unwrap().emergency_deactivate().unwrap();

    let actions = crate::manager::helpers::drain_recorded_service_actions();

    // The recorded hidden units are stopped: the service-level stop entries
    // (ignoring the paired `.socket` steps) are precisely the two units the hidden
    // switch added, and nothing else.
    let service_stops: Vec<&str> = actions
        .iter()
        .filter_map(|a| a.strip_prefix("stop:"))
        .filter(|unit| !unit.ends_with(".socket"))
        .collect();
    assert_eq!(
        service_stops,
        vec!["hidden-app.service", "hidden-config.service"],
        "emergency must stop exactly the recorded hidden units: {actions:?}"
    );

    // Emergency must leave the desktop looking unchanged: it never logs the
    // operator out and never touches the display manager. None of the logind
    // terminate or display-manager actions may appear, even though the state
    // recorded a graphical session with a display manager.
    for forbidden in [
        "terminate-session:c7",
        "terminate-user:1000",
        "stop:display-manager.service",
        "start:display-manager.service",
    ] {
        assert!(
            !actions.iter().any(|a| a == forbidden),
            "emergency must not perform {forbidden:?}: {actions:?}"
        );
    }

    let guard = manager.lock().unwrap();
    assert_eq!(guard.current_state().unwrap(), SystemState::Inactive);
    assert!(!guard.filesystem().is_mounted(Path::new("/home")).unwrap());
}

#[test]
fn test_emergency_order_unmount_then_cleanup_then_drop_page_cache() {
    use crate::filesystem::MockOp;

    let fixture = setup_active_manager();
    let hidden_root = fixture.lock().unwrap().config().hidden_volume_root.clone();
    {
        let guard = fixture.lock().unwrap();
        let fs = guard.filesystem();
        // The /proc knob must exist for the in-place write to succeed.
        fs.mock_set_path_exists("/proc/sys/vm/drop_caches", true);
        mount_nails_overlay(fs, &hidden_root, Path::new("/home"));
        mount_nails_overlay(fs, &hidden_root, Path::new("/etc"));
    }

    fixture.lock().unwrap().emergency_deactivate().unwrap();

    let guard = fixture.lock().unwrap();
    let ops = guard.filesystem().mock_ops();

    // The page cache is dropped exactly once, through the kernel-tunable write,
    // writing "3" to drop_caches.
    let drop_idx = ops
        .iter()
        .position(|op| {
            matches!(
                op,
                MockOp::WriteKernelTunable { path, value }
                    if path == Path::new("/proc/sys/vm/drop_caches") && value == "3"
            )
        })
        .expect("emergency must drop the page cache via write_kernel_tunable");

    // Every overlay unmount happens before the page cache is dropped: the one step
    // that matters runs first, the cache drop runs last.
    let last_unmount_idx = ops
        .iter()
        .rposition(|op| matches!(op, MockOp::Unmount { .. }))
        .expect("emergency must detach the overlays");
    assert!(
        last_unmount_idx < drop_idx,
        "page cache must be dropped only after every unmount: {ops:?}"
    );

    // Emergency must not secure-delete the encrypted hidden upper.
    assert!(
        !ops.iter()
            .any(|op| matches!(op, MockOp::SecureDelete { .. })),
        "emergency must not secure-delete hidden-upper files: {ops:?}"
    );
}

#[test]
fn test_emergency_scrubs_the_runtime_journal_even_without_a_var_overlay() {
    use crate::filesystem::PathKind;

    // The decoy keeps a volatile journal, so the hidden session's records land in
    // the RAM-backed /run/log/journal even though /var is not overlaid (the
    // fixture overlays /home and /etc only). Emergency must scrub that runtime
    // journal regardless, or `journalctl` keeps serving the hidden session.

    let fixture = setup_active_manager();
    let hidden_root = fixture.lock().unwrap().config().hidden_volume_root.clone();
    let machine_dir = PathBuf::from("/run/log/journal/0a1b2c3d");
    {
        let guard = fixture.lock().unwrap();
        let fs = guard.filesystem();
        mount_nails_overlay(fs, &hidden_root, Path::new("/home"));
        mount_nails_overlay(fs, &hidden_root, Path::new("/etc"));
        fs.mock_set_path_type("/run/log/journal", PathKind::Dir);
        fs.mock_set_path_type(machine_dir.to_str().unwrap(), PathKind::Dir);
        fs.mock_set_directory_contents(Path::new("/run/log/journal"), vec![machine_dir.clone()]);
    }

    let report = fixture.lock().unwrap().emergency_deactivate().unwrap();

    assert!(
        report.runtime_journal_scrubbed,
        "emergency must scrub the runtime journal even with no /var overlay"
    );
    let guard = fixture.lock().unwrap();
    assert!(
        !guard.filesystem().path_exists(&machine_dir).unwrap(),
        "the hidden session's runtime journal directory must be removed"
    );
}

#[test]
fn test_emergency_detaches_overlays_even_when_the_final_state_write_fails() {
    use crate::state::save_probe::{self, FailOn};

    // A failed or read-only hidden backend cannot persist the final Inactive
    // state, but the overlays must still be detached — the one thing that matters.
    // Arm the save probe to fail the final DEACTIVATING->INACTIVE write and assert
    // emergency still completes and detaches the overlay rather than erroring out
    // (or rolling back to ACTIVE, whose write would also fail).

    let fixture = setup_active_manager();
    let hidden_root = fixture.lock().unwrap().config().hidden_volume_root.clone();
    {
        let guard = fixture.lock().unwrap();
        mount_nails_overlay(guard.filesystem(), &hidden_root, Path::new("/home"));
    }

    save_probe::arm(&[FailOn::Inactive]);
    let report = fixture.lock().unwrap().emergency_deactivate();
    save_probe::disarm();

    let report = report.expect("emergency must complete even when the final state write fails");
    assert_eq!(report.final_state, SystemState::Inactive);
    let guard = fixture.lock().unwrap();
    assert!(
        !guard.filesystem().is_mounted(Path::new("/home")).unwrap(),
        "the overlay must be detached even though the state file could not be written"
    );
}

/// Kill the hidden volume under a live manager: its mount point stops being a
/// directory at all, so every later state read and write fails with a real
/// I/O error (ENOTDIR), as a dead or yanked backend does. Returns a guard that
/// removes the stand-in file so the temp dir can be cleaned up.
fn kill_hidden_volume(hidden_root: &Path) -> impl Drop + use<> {
    struct Restore(PathBuf);
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::create_dir_all(&self.0);
        }
    }
    std::fs::remove_dir_all(hidden_root).unwrap();
    std::fs::write(hidden_root, b"").unwrap();
    Restore(hidden_root.to_path_buf())
}

#[test]
fn test_emergency_tears_down_every_overlay_when_the_hidden_volume_is_dead() {
    // The untrusted path used to abort on its very first state write (the
    // Degraded baseline) when the backend was dead, leaving every overlay
    // mounted. Every state write is best-effort there: the overlays come down
    // regardless, and the failed writes are reported.
    let manager = setup_manager_in_state(SystemState::Activating {
        started_at: chrono::Utc::now(),
    });
    let hidden_root = manager.lock().unwrap().config().hidden_volume_root.clone();
    {
        let guard = manager.lock().unwrap();
        mount_nails_overlay(guard.filesystem(), &hidden_root, Path::new("/home"));
        mount_nails_overlay(guard.filesystem(), &hidden_root, Path::new("/etc"));
    }
    let _restore = kill_hidden_volume(&hidden_root);

    let report = manager
        .lock()
        .unwrap()
        .emergency_deactivate()
        .expect("a dead hidden volume must never stop the emergency teardown");

    let guard = manager.lock().unwrap();
    assert!(!guard.filesystem().is_mounted(Path::new("/home")).unwrap());
    assert!(!guard.filesystem().is_mounted(Path::new("/etc")).unwrap());
    assert_eq!(report.final_state, SystemState::Inactive);
    assert!(
        report.state_write_errors.len() >= 2,
        "both the baseline and the final state write must be reported: {:?}",
        report.state_write_errors
    );
    assert!(
        report
            .state_write_errors
            .iter()
            .any(|e| e.starts_with("untrusted baseline")),
        "{:?}",
        report.state_write_errors
    );
}

#[test]
fn test_emergency_reports_incomplete_not_io_error_when_the_hidden_volume_is_dead() {
    // A mount that cannot be removed still ends DeactivationIncomplete (exit 75)
    // even though the Degraded record cannot be written: the state write never
    // masks the real outcome, and every other overlay still comes down.
    let manager = setup_manager_in_state(SystemState::Activating {
        started_at: chrono::Utc::now(),
    });
    let hidden_root = manager.lock().unwrap().config().hidden_volume_root.clone();
    {
        let guard = manager.lock().unwrap();
        mount_nails_overlay(guard.filesystem(), &hidden_root, Path::new("/home"));
        mount_nails_overlay(guard.filesystem(), &hidden_root, Path::new("/etc"));
        guard
            .filesystem()
            .mock_set_unmount_should_fail("/home", true);
    }
    let _restore = kill_hidden_volume(&hidden_root);

    let result = manager.lock().unwrap().emergency_deactivate();

    match result {
        Err(NailsError::DeactivationIncomplete { remaining_mounts }) => {
            assert_eq!(remaining_mounts, vec![PathBuf::from("/home")]);
        }
        other => panic!("expected DeactivationIncomplete, got {other:?}"),
    }
    let guard = manager.lock().unwrap();
    assert!(!guard.filesystem().is_mounted(Path::new("/etc")).unwrap());
}

#[test]
fn test_emergency_never_touches_decoy_history_or_temp_files_after_unmount() {
    use crate::filesystem::MockOp;

    // With the overlays gone, the history files and /tmp entries a cleanup could
    // reach are the decoy's own. Emergency (and recovery) must leave them exactly
    // as they are: editing them would itself leave fresh timestamps on the decoy.
    let fixture = setup_active_manager();
    let hidden_root = fixture.lock().unwrap().config().hidden_volume_root.clone();
    let history = PathBuf::from(format!("{TEST_HOME}/.bash_history"));
    let temp_entry = PathBuf::from("/tmp/nails-session.sock");
    {
        let guard = fixture.lock().unwrap();
        let fs = guard.filesystem();
        mount_nails_overlay(fs, &hidden_root, Path::new("/home"));
        mount_nails_overlay(fs, &hidden_root, Path::new("/etc"));
        fs.mock_add_file(history.to_str().unwrap(), "nails activate\nls\n");
        fs.mock_add_file(temp_entry.to_str().unwrap(), "x");
        fs.mock_set_files_with_pattern("/tmp", "nails", &[temp_entry.as_path()]);
    }

    fixture.lock().unwrap().emergency_deactivate().unwrap();

    let guard = fixture.lock().unwrap();
    let fs = guard.filesystem();
    assert_eq!(
        fs.read_file_content(&history).unwrap(),
        "nails activate\nls\n",
        "the decoy history file must be left untouched"
    );
    assert!(
        fs.path_exists(&temp_entry).unwrap(),
        "decoy /tmp must be left untouched"
    );
    let decoy_writes: Vec<_> = fs
        .mock_ops()
        .into_iter()
        .filter(|op| match op {
            MockOp::WriteFile { path }
            | MockOp::OverwriteInPlace { path }
            | MockOp::SecureDelete { path, .. } => {
                !path.starts_with("/run") && !path.starts_with(&hidden_root)
            }
            _ => false,
        })
        .collect();
    assert!(decoy_writes.is_empty(), "no decoy write: {decoy_writes:?}");
}

#[test]
fn test_untrusted_emergency_unmounts_persona_binds() {
    // The fresh-home persona bind sits on the /home overlay. The untrusted path
    // discovered overlays and staging mounts but not persona binds, so the bind
    // survived the teardown; it must come off (before the overlay under it).
    let manager = setup_manager_in_state(SystemState::Activating {
        started_at: chrono::Utc::now(),
    });
    let hidden_root = manager.lock().unwrap().config().hidden_volume_root.clone();
    let home = Path::new("/home/testuser");
    {
        let guard = manager.lock().unwrap();
        let fs = guard.filesystem();
        mount_nails_overlay(fs, &hidden_root, Path::new("/home"));
        let persona_home = hidden_root.join("persona/home");
        fs.mock_set_path_exists(persona_home.to_str().unwrap(), true);
        fs.mock_set_path_exists(home.to_str().unwrap(), true);
        fs.bind_mount(&persona_home, home).unwrap();
        assert!(
            fs.discover_nails_mounts(Some(&hidden_root))
                .unwrap()
                .is_owned(home)
        );
    }

    manager.lock().unwrap().emergency_deactivate().unwrap();

    let guard = manager.lock().unwrap();
    assert!(!guard.filesystem().is_mounted(home).unwrap());
    assert!(!guard.filesystem().is_mounted(Path::new("/home")).unwrap());
}

#[test]
fn test_trusted_emergency_unmounts_live_nails_mounts_the_state_missed() {
    // The recorded overlay list covers /home and /etc; a NAILS overlay on /srv
    // that the state never recorded must come down too, not survive a "clean"
    // teardown.
    let fixture = setup_active_manager();
    let hidden_root = fixture.lock().unwrap().config().hidden_volume_root.clone();
    {
        let guard = fixture.lock().unwrap();
        let fs = guard.filesystem();
        mount_nails_overlay(fs, &hidden_root, Path::new("/home"));
        mount_nails_overlay(fs, &hidden_root, Path::new("/etc"));
        mount_nails_overlay(fs, &hidden_root, Path::new("/srv"));
    }

    let report = fixture.lock().unwrap().emergency_deactivate().unwrap();

    assert!(
        report.unmounted_overlays.iter().any(|p| p == "/srv"),
        "{report:?}"
    );
    let guard = fixture.lock().unwrap();
    assert!(!guard.filesystem().is_mounted(Path::new("/srv")).unwrap());
}

#[test]
fn test_a_surviving_discovered_nails_mount_makes_the_teardown_incomplete() {
    // A NAILS mount that cannot be removed is reported even when the recorded
    // list never named it: the remaining-mount check covers every live NAILS
    // mount, not only the attempted targets.
    let fixture = setup_active_manager();
    let hidden_root = fixture.lock().unwrap().config().hidden_volume_root.clone();
    let home = Path::new("/home/testuser");
    {
        let guard = fixture.lock().unwrap();
        let fs = guard.filesystem();
        mount_nails_overlay(fs, &hidden_root, Path::new("/home"));
        mount_nails_overlay(fs, &hidden_root, Path::new("/etc"));
        let persona_home = hidden_root.join("persona/home");
        fs.mock_set_path_exists(persona_home.to_str().unwrap(), true);
        fs.mock_set_path_exists(home.to_str().unwrap(), true);
        fs.bind_mount(&persona_home, home).unwrap();
        fs.mock_set_unmount_should_fail(home.to_str().unwrap(), true);
    }

    match fixture.lock().unwrap().emergency_deactivate() {
        Err(NailsError::DeactivationIncomplete { remaining_mounts }) => {
            assert!(
                remaining_mounts.contains(&home.to_path_buf()),
                "{remaining_mounts:?}"
            );
        }
        other => panic!("expected DeactivationIncomplete, got {other:?}"),
    }
}

#[test]
fn test_untrusted_emergency_repoints_a_hidden_current_system_at_the_booted_decoy() {
    // No reboot follows an emergency, and the untrusted path has no decoy record:
    // a /run/current-system left naming the (now gone) hidden toplevel must be
    // pointed back at the booted decoy generation.
    let manager = setup_manager_in_state(SystemState::Activating {
        started_at: chrono::Utc::now(),
    });
    let hidden_root = manager.lock().unwrap().config().hidden_volume_root.clone();
    {
        let guard = manager.lock().unwrap();
        let fs = guard.filesystem();
        mount_nails_overlay(fs, &hidden_root, Path::new("/home"));
        fs.mock_set_path_exists("/nix/store/booted-decoy", true);
        fs.create_symlink(
            Path::new("/nix/store/booted-decoy"),
            Path::new("/run/booted-system"),
        )
        .unwrap();
        fs.create_symlink(
            Path::new("/nix/store/hidden-system"),
            Path::new("/run/current-system"),
        )
        .unwrap();
    }

    manager.lock().unwrap().emergency_deactivate().unwrap();

    let guard = manager.lock().unwrap();
    assert_eq!(
        guard
            .filesystem()
            .canonicalize(Path::new("/run/current-system"))
            .unwrap(),
        Path::new("/nix/store/booted-decoy")
    );
}

#[test]
fn test_incomplete_emergency_still_scrubs_ram_backed_state() {
    use crate::filesystem::{MockOp, PathKind};

    // A mount that cannot be removed ends the teardown in an error, but the
    // runtime journal and the page cache hold hidden-session data in RAM all the
    // same: both are scrubbed before the error is returned.
    let fixture = setup_active_manager();
    let hidden_root = fixture.lock().unwrap().config().hidden_volume_root.clone();
    let machine_dir = PathBuf::from("/run/log/journal/0a1b2c3d");
    {
        let guard = fixture.lock().unwrap();
        let fs = guard.filesystem();
        mount_nails_overlay(fs, &hidden_root, Path::new("/home"));
        mount_nails_overlay(fs, &hidden_root, Path::new("/etc"));
        fs.mock_set_unmount_should_fail("/home", true);
        fs.mock_set_path_exists("/proc/sys/vm/drop_caches", true);
        fs.mock_set_path_type("/run/log/journal", PathKind::Dir);
        fs.mock_set_path_type(machine_dir.to_str().unwrap(), PathKind::Dir);
        fs.mock_set_directory_contents(Path::new("/run/log/journal"), vec![machine_dir.clone()]);
    }

    let result = fixture.lock().unwrap().emergency_deactivate();
    assert!(
        matches!(result, Err(NailsError::DeactivationIncomplete { .. })),
        "{result:?}"
    );

    let guard = fixture.lock().unwrap();
    let fs = guard.filesystem();
    assert!(
        !fs.path_exists(&machine_dir).unwrap(),
        "runtime journal must be scrubbed"
    );
    assert!(
        fs.mock_ops()
            .iter()
            .any(|op| matches!(op, MockOp::WriteKernelTunable { value, .. } if value == "3")),
        "the page cache must be dropped"
    );
}
