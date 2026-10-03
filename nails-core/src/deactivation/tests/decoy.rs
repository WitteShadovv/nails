use super::*;

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
    loaded.hidden_toplevel = Some("1".to_string());
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
            decoy_writers: Vec::new(),
            activated_at: chrono::Utc::now(),
            overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
        },
        hidden_toplevel: Some("6".to_string()),
        config_fingerprint: Some("deadbeefcafebabe".to_string()),
        last_switch_warning: None,
        overlay_status: std::collections::HashMap::new(),
        failed_overlays: Vec::new(),
        last_modified: chrono::Utc::now(),
        boot_id: None,
        owner_pid: 0,
        nix_store_init_namespace_bound: false,
        read_only_guards: Vec::new(),
        submount_attachments: Vec::new(),
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
    assert_eq!(loaded.hidden_toplevel, Some("6".to_string()));
    assert_eq!(
        loaded.config_fingerprint,
        Some("deadbeefcafebabe".to_string())
    );
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
    set_state_hidden_toplevel(&state_path, &hidden_root, "1");

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
    set_state_hidden_toplevel(&state_path, &hidden_root, "1");

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
