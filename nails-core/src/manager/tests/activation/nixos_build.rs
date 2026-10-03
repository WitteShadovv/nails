//! The config fingerprint and the NixOS build fast path.

use super::*;

// ========== Fingerprint persistence ==========

#[test]
fn test_config_fingerprint_field_persistence() {
    // HIGH-2: Validate that config_fingerprint field is properly persisted to state file
    // This test focuses on the state persistence mechanism, which is the integration gap
    // between the manager and the state file. The fingerprint computation itself is
    // well-tested in nixos.rs unit tests.
    use std::sync::Arc;

    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    std::fs::create_dir_all(mock_hidden_vol).unwrap();

    let state_path = mock_hidden_vol.join("state.json");
    let fs = MockFilesystem::new();

    // Setup mock filesystem paths
    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);

    // Create initial state file (INACTIVE, no fingerprint)
    // Write to actual filesystem so manager can load it
    let initial_state = StateFile {
        version: env!("CARGO_PKG_VERSION").to_string(),
        state: SystemState::Inactive,
        platform: None,
        config_fingerprint: None, // First activation - no fingerprint yet
        hidden_added_units: Vec::new(),
        hidden_session: None,
        overlay_status: HashMap::new(),
        failed_overlays: Vec::new(),
        last_modified: Utc::now(),
        boot_id: None,
        owner_pid: 0,
        nix_store_init_namespace_bound: false,
        read_only_guards: Vec::new(),
        submount_attachments: Vec::new(),
        integrity_sha256: None,
    };
    let state_json = serde_json::to_string_pretty(&initial_state).unwrap();
    std::fs::write(&state_path, state_json).unwrap();

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        ..Config::test_default()
    };

    let manager = Arc::new(Mutex::new(NailsManager::new(
        fs.clone(),
        config,
        state_path.clone(),
    )));

    // === TEST 1: Verify fingerprint field loads correctly (None initially) ===
    // Call current_state() to trigger lazy load from disk
    {
        let mgr = manager.lock().unwrap();
        mgr.current_state().expect("State should load successfully");
    }

    {
        let mgr = manager.lock().unwrap();
        let state = mgr.cached_state.borrow();
        assert!(
            state.is_some(),
            "State should be loaded after calling current_state()"
        );
        assert_eq!(
            state.as_ref().unwrap().config_fingerprint,
            None,
            "Initial state should have no fingerprint"
        );
    }

    // === TEST 2: Simulate fingerprint being saved (as happens in activation step 7+9) ===
    let test_fingerprint = "abcd1234efgh5678".to_string();
    {
        let mgr = manager.lock().unwrap();
        let mut cached = mgr.cached_state.borrow_mut();
        if let Some(ref mut state) = *cached {
            state.config_fingerprint = Some(test_fingerprint.clone());
            state.set_nixos_generation(Some("test-gen-123".to_string()));
        }
    }

    // Save state to disk (this is what manager does after successful activation)
    {
        let mgr = manager.lock().unwrap();
        mgr.save_cached_state().expect("State save should succeed");
    }

    // === TEST 3: Verify fingerprint was persisted to actual file ===
    let saved_content =
        std::fs::read_to_string(&state_path).expect("State file should exist on disk");
    let restored_state: StateFile =
        serde_json::from_str(&saved_content).expect("Saved state should deserialize correctly");

    assert_eq!(
        restored_state.config_fingerprint,
        Some(test_fingerprint.clone()),
        "Fingerprint should be persisted to disk"
    );

    // === TEST 4: Verify persisted fingerprint can be loaded back ===
    // Deserialize directly from disk to verify persistence
    let disk_content =
        std::fs::read_to_string(&state_path).expect("State file should exist on disk after save");
    let loaded_state: StateFile =
        serde_json::from_str(&disk_content).expect("State file should be valid JSON");

    assert_eq!(
        loaded_state.config_fingerprint,
        Some(test_fingerprint),
        "Fingerprint should be loaded correctly from disk (fast-path prerequisite)"
    );

    // Test passes: config_fingerprint field is properly saved to disk and loaded back,
    // validating the state persistence integration
}

// ========== Fast-path plan (fingerprint + cached toplevel) ==========

const CACHED_TOPLEVEL: &str = "/nix/store/0000000000000000000000000000000a-nixos-system-host";

/// Fingerprint the hidden config tree exactly as `plan` does, so a test can arm a
/// matching stored fingerprint and drive the fast path.
fn matching_fingerprint(fs: &MockFilesystem, hidden_root: &Path, config_dir: &Path) -> String {
    use crate::nixos::{collect_config_tree, compute_config_fingerprint};
    let flake_ref = config_dir.to_string_lossy();
    let entries = collect_config_tree(fs, hidden_root, Some(&flake_ref), None);
    compute_config_fingerprint(&entries)
}

/// Build a manager whose hidden config fingerprint matches the stored one, with an
/// optional cached toplevel on disk. Activation fails at the `/home` mount, so only
/// the fingerprint/plan stage runs before the error.
fn plan_manager(
    hidden_root: &Path,
    state_path: &Path,
    fs: &MockFilesystem,
    stored_fingerprint: Option<String>,
    stored_toplevel: Option<String>,
    toplevel_present: bool,
) -> NailsManager<MockFilesystem> {
    use crate::NixOSBuilder;

    setup_nixos_config_check(fs, hidden_root);
    fs.mock_set_path_exists("/home", true);
    fs.mock_set_mount_should_fail("/home", true);
    fs.mock_set_path_exists("/", true);

    if toplevel_present && let Some(ref tp) = stored_toplevel {
        fs.mock_set_path_exists(tp, true);
    }

    let upper_home = hidden_root.join("overlays/home/upper");
    let work_home = hidden_root.join("overlays/home/work");
    std::fs::create_dir_all(&upper_home).unwrap();
    std::fs::create_dir_all(&work_home).unwrap();
    fs.mock_set_path_exists(upper_home.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_home.to_str().unwrap(), true);

    let config_dir = hidden_root.join("config/nixos");
    let builder = NixOSBuilder::new(config_dir, hidden_root.join("profiles/nails-system"));
    let mut manager = NailsManager::with_nixos(
        fs.clone(),
        Config {
            hidden_volume_root: hidden_root.to_path_buf(),
            state_file_path: state_path.to_path_buf(),
            overlay_mode: OverlayMode::Explicit,
            overlays: vec![OverlayConfig {
                name: "home".to_string(),
                lower: PathBuf::from("/"),
                upper: upper_home,
                work: work_home,
                target: PathBuf::from("/home"),
            }],
            ..Config::test_default()
        },
        state_path.to_path_buf(),
        builder,
    );
    manager.set_verbosity(Verbosity::Normal);
    {
        let mut cached = manager.cached_state.borrow_mut();
        *cached = Some(StateFile {
            state: SystemState::Inactive,
            config_fingerprint: stored_fingerprint,
            platform: stored_toplevel.map(|t| crate::state::PlatformState::nixos(Some(t))),
            ..StateFile::default()
        });
    }
    manager
}

#[test]
#[tracing_test::traced_test]
fn test_fast_path_carried_when_fingerprint_matches() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();

    let fp = matching_fingerprint(&fs, hidden_root, &hidden_root.join("config/nixos"));
    let manager = plan_manager(
        hidden_root,
        &state_path,
        &fs,
        Some(fp),
        Some(CACHED_TOPLEVEL.to_string()),
        true,
    );

    let result = Arc::new(Mutex::new(manager)).lock().unwrap().activate(true);
    assert!(result.is_err());
    assert!(logs_contain("Computing NixOS config fingerprint"));
    assert!(logs_contain("Fast-path check"));
    // plan carries the fast path forward on a fingerprint match; the on-disk
    // existence check happens in apply, after the overlays mount.
    assert!(logs_contain("Fast path: fingerprint matches"));
}

#[test]
#[tracing_test::traced_test]
fn test_no_fast_path_when_fingerprint_mismatches() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();

    // A stored fingerprint that cannot match the freshly computed one.
    let manager = plan_manager(
        hidden_root,
        &state_path,
        &fs,
        Some("ffffffffffffffff".to_string()),
        Some(CACHED_TOPLEVEL.to_string()),
        true,
    );

    let result = Arc::new(Mutex::new(manager)).lock().unwrap().activate(true);
    assert!(result.is_err());
    assert!(logs_contain("Fast-path check"));
    assert!(!logs_contain("Fast path: fingerprint matches"));
}
