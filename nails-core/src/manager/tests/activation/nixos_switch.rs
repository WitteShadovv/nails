// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The NixOS switch after the overlays are mounted.

use super::*;

#[test]
fn test_activation_rebuild_failure_preserves_mounted_state_and_notifies() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();

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

    // The switch itself is scripted on the fake config layer: it fails with
    // `boom`, as a fatal hidden-config build failure would.
    let builder = crate::nixos::NixOSBuilder::new_legacy(
        hidden_root.join("config/nixos/configuration.nix"),
        hidden_root.join("nails-system"),
    );

    let manager = Arc::new(Mutex::new(fake_nixos_manager_with_builder_scripted(
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
            // switch_required=false keeps the overlays and session on a failed build.
            nixos_switch_required: false,
            ..Config::test_default()
        },
        state_path.clone(),
        builder,
        FakeConfigLayer::new().with_apply_error("boom"),
    )));

    let result = manager.lock().unwrap().activate(true);
    // The outcome is reported truthfully: activation succeeded (overlays up), but
    // the hidden NixOS configuration was not applied, carried as a warning.
    let outcome = result.expect("post-overlay rebuild failure should preserve activation");
    assert!(
        matches!(
            outcome,
            crate::ActivationOutcome::Activated {
                hidden_config: crate::HiddenConfigOutcome::Failed { .. }
            }
        ),
        "a failed switch with switch_required=false reports a Failed hidden config: {outcome:?}"
    );
    assert!(
        !outcome.warnings().is_empty(),
        "a failed hidden switch carries an operator warning"
    );

    let manager_guard = manager.lock().unwrap();
    assert!(matches!(
        manager_guard.current_state().unwrap(),
        SystemState::Active { .. }
    ));
    drop(manager_guard);

    let loaded = StateFile::load(&state_path).unwrap();
    assert!(matches!(loaded.state, SystemState::Active { .. }));
    assert!(loaded.overlay_status.contains_key(&PathBuf::from("/etc")));
    assert!(loaded.overlay_status.contains_key(&PathBuf::from("/home")));
    assert!(loaded.failed_overlays.is_empty());
    // The outcome is persisted so `nails status` can report the hidden
    // configuration as NOT applied after a detached run.
    assert!(
        loaded.last_switch_warning().is_some(),
        "a failed switch must be recorded in state for status to surface it"
    );
    assert!(fs.is_mounted(Path::new("/etc")).unwrap());
    assert!(fs.is_mounted(Path::new("/home")).unwrap());

    let notifications_dir = hidden_root.join("notifications");
    let notifications: Vec<_> = std::fs::read_dir(&notifications_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .collect();
    assert!(
        notifications.iter().any(|entry| {
            std::fs::read_to_string(entry.path())
                .map(|payload| payload.contains("NixOS Rebuild Failed") && payload.contains("boom"))
                .unwrap_or(false)
        }),
        "expected rebuild failure notification in {}",
        notifications_dir.display()
    );
}

#[test]
fn test_activation_non_fatal_switch_failures_do_not_roll_back() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();

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
        "#!/usr/bin/env sh\nprintf 'warning: error(s) occurred while switching to the new configuration\\nThe following units failed: home-manager-amnesia.service\\n' 1>&2\nexit 4\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&rebuild_script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&rebuild_script, perms).unwrap();
    }

    let builder = crate::nixos::NixOSBuilder::new_legacy(
        hidden_root.join("config/nixos/configuration.nix"),
        hidden_root.join("nails-system"),
    )
    .with_executor(Box::new(
        crate::nixos::RealCommandExecutor::with_search_path(&bin_dir),
    ));

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

    let result = manager.lock().unwrap().activate(true);
    assert!(
        result.is_ok(),
        "activation should tolerate non-fatal switch failures: {result:?}"
    );

    let manager_guard = manager.lock().unwrap();
    assert!(matches!(
        manager_guard.current_state().unwrap(),
        SystemState::Active { .. }
    ));
    drop(manager_guard);

    let loaded = StateFile::load(&state_path).unwrap();
    assert!(matches!(loaded.state, SystemState::Active { .. }));
    assert!(!loaded.overlay_status.is_empty());
    let notifications_dir = hidden_root.join("notifications");
    let notifications: Vec<_> = std::fs::read_dir(&notifications_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .collect();
    assert!(
        notifications.iter().all(|entry| {
            std::fs::read_to_string(entry.path())
                .map(|payload| !payload.contains("NixOS Rebuild Failed"))
                .unwrap_or(true)
        }),
        "non-fatal service restart failures should not emit fatal rebuild notifications"
    );
}

#[test]
fn test_switch_required_rolls_overlays_back_on_switch_failure() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/etc", true);
    fs.mock_set_path_exists("/home", true);

    let upper_etc = hidden_root.join("overlays/etc/upper");
    let work_etc = hidden_root.join("overlays/etc/work");
    let upper_home = hidden_root.join("overlays/home/upper");
    let work_home = hidden_root.join("overlays/home/work");
    for dir in [&upper_etc, &work_etc, &upper_home, &work_home] {
        std::fs::create_dir_all(dir).unwrap();
        fs.mock_set_path_exists(dir.to_str().unwrap(), true);
    }

    // The switch itself is scripted on the fake config layer: it fails with
    // `boom`, as a fatal hidden-config build failure would.
    let builder = crate::nixos::NixOSBuilder::new_legacy(
        hidden_root.join("config/nixos/configuration.nix"),
        hidden_root.join("nails-system"),
    );

    let manager = Arc::new(Mutex::new(fake_nixos_manager_with_builder_scripted(
        fs.clone(),
        Config {
            hidden_volume_root: hidden_root.to_path_buf(),
            state_file_path: state_path.clone(),
            overlay_mode: OverlayMode::Explicit,
            // The default, stated explicitly: fail closed.
            nixos_switch_required: true,
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
        FakeConfigLayer::new().with_apply_error("boom"),
    )));

    let result = manager.lock().unwrap().activate(true);
    assert!(
        result.is_err(),
        "a failed switch with switch_required=true must fail activation: {result:?}"
    );

    let manager_guard = manager.lock().unwrap();
    assert!(
        matches!(
            manager_guard.current_state().unwrap(),
            SystemState::Inactive
        ),
        "activation must roll back to Inactive on a fail-closed switch failure"
    );
    drop(manager_guard);

    // The overlays were torn down before any session restart.
    assert!(!fs.is_mounted(Path::new("/etc")).unwrap());
    assert!(!fs.is_mounted(Path::new("/home")).unwrap());

    let loaded = StateFile::load(&state_path).unwrap();
    assert!(matches!(loaded.state, SystemState::Inactive));
    assert!(loaded.overlay_status.is_empty());
}

#[test]
fn test_reapply_clears_stale_switch_warning_on_success() {
    use crate::manager::state_management::reconcile_mounts_override;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");

    // On-disk state: verifiably active on NixOS, but carrying a switch warning
    // left behind by an earlier failed hidden rebuild.
    let mut initial_state = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
            decoy_writers: Vec::new(),
        },
        ..StateFile::default()
    };
    initial_state.set_switch_warning(Some(
        "NixOS operation failed: building the hidden NixOS toplevel: throw".to_string(),
    ));
    initial_state
        .save_with_custom_root(&state_path, hidden_root)
        .unwrap();
    assert!(
        StateFile::load(&state_path)
            .unwrap()
            .last_switch_warning()
            .is_some(),
        "precondition: the persisted state carries a stale switch warning"
    );

    let config = Config {
        hidden_volume_root: hidden_root.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::test_default()
    };
    // No config layer / builder: the reapply switch is NotRequested and therefore
    // clean, so a successful reapply must clear the stale warning. The manager
    // starts with an empty state cache, exactly as the CLI builds it.
    let manager = NailsManager::new(MockFilesystem::new(), config, state_path.clone());

    // The kernel confirms /home is a NAILS persistent overlay, so reconcile
    // reports VerifiedActive and reapply proceeds.
    let mounts = crate::filesystem::NailsMounts {
        persistent_overlays: vec![PathBuf::from("/home")],
        ..Default::default()
    };
    let _mounts_guard = reconcile_mounts_override::arm(mounts);

    manager
        .reapply_hidden_config()
        .expect("reapply on a verifiably active system succeeds");

    let reloaded = StateFile::load(&state_path).unwrap();
    assert_eq!(
        reloaded.last_switch_warning(),
        None,
        "a successful reapply must clear the persisted hidden-config warning"
    );
    assert!(
        matches!(reloaded.state, SystemState::Active { .. }),
        "reapply leaves the system active"
    );
}
