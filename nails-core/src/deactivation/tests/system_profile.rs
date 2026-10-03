use super::*;

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
        decoy_writers: Vec::new(),
        activated_at: chrono::Utc::now(),
        overlays: vec![],
    };
    StateFile {
        state: active_state,
        platform: Some(crate::state::PlatformState::nixos(Some("1".to_string()))),
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
            mount_method: Default::default(),
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
            mount_method: Default::default(),
            mount_path: PathBuf::from("/etc"),
            lower_dir: PathBuf::from("/"),
            upper_dir: upper_etc.clone(),
            work_dir: work_etc.clone(),
            mounted_at: chrono::Utc::now() + chrono::TimeDelta::milliseconds(1),
        },
    );

    StateFile {
        state: SystemState::Active {
            decoy_writers: Vec::new(),
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
