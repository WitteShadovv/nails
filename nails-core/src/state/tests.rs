//! Tests for state module

use super::*;

// ========== OverlayInfo Tests ==========

#[test]
fn test_overlay_info_creation() {
    let overlay = OverlayInfo {
        mount_method: Default::default(),
        mount_path: PathBuf::from("/home"),
        lower_dir: PathBuf::from("/home"),
        upper_dir: PathBuf::from("/mnt/data/overlays/home/upper"),
        work_dir: PathBuf::from("/mnt/data/overlays/home/work"),
        mounted_at: Utc::now(),
    };

    assert_eq!(overlay.mount_path, PathBuf::from("/home"));
    assert_eq!(
        overlay.upper_dir,
        PathBuf::from("/mnt/data/overlays/home/upper")
    );
}

#[test]
fn test_overlay_info_serialization() {
    let overlay = OverlayInfo {
        mount_method: Default::default(),
        mount_path: PathBuf::from("/home"),
        lower_dir: PathBuf::from("/home"),
        upper_dir: PathBuf::from("/mnt/data/overlays/home/upper"),
        work_dir: PathBuf::from("/mnt/data/overlays/home/work"),
        mounted_at: DateTime::parse_from_rfc3339("2025-01-27T10:30:00Z")
            .unwrap()
            .with_timezone(&Utc),
    };

    // Serialize to JSON
    let json = serde_json::to_string(&overlay).expect("Should serialize");
    assert!(json.contains("\"mount_path\""));
    assert!(json.contains("\"/home\""));

    // Deserialize back
    let deserialized: OverlayInfo = serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(deserialized, overlay);
}

// ========== StateFile Tests ==========

#[test]
fn test_state_file_default() {
    let state_file = StateFile::default();

    assert_eq!(state_file.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(state_file.state, SystemState::Inactive);
    assert_eq!(state_file.nixos_generation, None);
    assert!(state_file.overlay_status.is_empty());
    assert_eq!(state_file.integrity_sha256, None);
    // Just verify last_modified exists (can't test exact time)
    assert!(state_file.last_modified <= Utc::now());
}

#[test]
fn test_state_file_serialization() {
    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/home"),
            upper_dir: PathBuf::from("/mnt/data/overlays/home/upper"),
            work_dir: PathBuf::from("/mnt/data/overlays/home/work"),
            mounted_at: DateTime::parse_from_rfc3339("2025-01-27T10:30:00Z")
                .unwrap()
                .with_timezone(&Utc),
        },
    );

    let state_file = StateFile {
        version: env!("CARGO_PKG_VERSION").to_string(),
        state: SystemState::Active {
            activated_at: DateTime::parse_from_rfc3339("2025-01-27T10:30:00Z")
                .unwrap()
                .with_timezone(&Utc),
            overlays: vec![PathBuf::from("/home")],
        },
        nixos_generation: Some("abc123def456".to_string()),
        overlay_status,
        failed_overlays: Vec::new(),
        last_modified: DateTime::parse_from_rfc3339("2025-01-27T10:30:01Z")
            .unwrap()
            .with_timezone(&Utc),
        boot_id: None,
        owner_pid: 0,
        nix_store_init_namespace_bound: false,
        read_only_guards: Vec::new(),
        integrity_sha256: None,
        config_fingerprint: None,
    };

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&state_file).expect("Should serialize");
    assert!(json.contains("\"version\""));
    assert!(json.contains("\"Active\""));
    assert!(json.contains("\"nixos_generation\""));
    assert!(json.contains("\"overlay_status\""));

    // Deserialize back
    let deserialized: StateFile = serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(deserialized, state_file);
}

// ========== Hidden Volume Validation Tests ==========

#[test]
fn test_save_valid_path_in_hidden_volume() {
    let _state = StateFile::default();

    // Create temporary directory that looks like hidden volume
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let hidden_vol_path = temp_dir.path().join("mnt/hidden-volume");
    std::fs::create_dir_all(&hidden_vol_path).expect("Should create dirs");

    let _state_path = hidden_vol_path.join("state.json");

    // This will fail because temp_dir is not actually /mnt/data
    // For real test, we'd need to mock or use a test-specific constant
    // Let's test the is_on_hidden_volume function directly instead
}

#[test]
fn test_hidden_volume_validation_valid_path() {
    // Test that paths within hidden volume are accepted
    use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
    assert!(is_on_hidden_volume(
        Path::new("/mnt/data/state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));
    assert!(is_on_hidden_volume(
        Path::new("/mnt/data/subdir/state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));
    assert!(is_on_hidden_volume(
        Path::new("/mnt/data/a/b/c/state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));
}

#[test]
fn test_hidden_volume_validation_invalid_paths() {
    // Test that paths outside hidden volume are rejected
    use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
    assert!(!is_on_hidden_volume(
        Path::new("/etc/nails/state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));
    assert!(!is_on_hidden_volume(
        Path::new("/home/user/state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));
    assert!(!is_on_hidden_volume(
        Path::new("/mnt/data-fake/state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));
    assert!(!is_on_hidden_volume(
        Path::new("/tmp/test-hidden-volume/state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));
}

#[test]
fn test_hidden_volume_validation_traversal_attack() {
    // Test that path traversal attacks are rejected
    use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
    assert!(!is_on_hidden_volume(
        Path::new("/mnt/data/../etc/state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));
    assert!(!is_on_hidden_volume(
        Path::new("/mnt/data/../../tmp/state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));
}

#[test]
fn test_save_rejects_path_outside_hidden_volume() {
    use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
    let state = StateFile::default();

    // Try to save to /tmp (should fail)
    let result = state.save(Path::new("/tmp/state.json"), DEFAULT_HIDDEN_VOLUME_ROOT);
    assert!(result.is_err());

    match result {
        Err(NailsError::InvalidState(msg)) => {
            assert!(msg.contains("State file must be on hidden volume"));
            assert!(msg.contains("/tmp/state.json")); // Should include actual path
        }
        _ => panic!("Expected InvalidState error"),
    }

    // Verify no file was written
    assert!(!Path::new("/tmp/state.json").exists());
}

#[test]
fn test_save_rejects_home_directory_path() {
    use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
    let state = StateFile::default();

    // Try to save to home directory (should fail)
    let result = state.save(
        Path::new("/home/user/state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT,
    );
    assert!(result.is_err());

    match result {
        Err(NailsError::InvalidState(msg)) => {
            assert!(msg.contains("State file must be on hidden volume"));
            assert!(msg.contains("/home/user/state.json")); // Should include actual path
        }
        _ => panic!("Expected InvalidState error"),
    }
}

// ========== Load Method Tests ==========

#[test]
fn test_load_missing_file_returns_default() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let nonexistent_path = temp_dir.path().join("nonexistent.json");

    let result = StateFile::load(&nonexistent_path);
    assert!(result.is_ok());

    let state = result.unwrap();
    assert_eq!(state.state, SystemState::Inactive);
    assert_eq!(state.nixos_generation, None);
    assert!(state.overlay_status.is_empty());
}

#[test]
fn test_load_empty_file_returns_default() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let empty_file = temp_dir.path().join("empty.json");

    // Create empty file
    std::fs::write(&empty_file, "").expect("Should write empty file");

    let result = StateFile::load(&empty_file);
    assert!(result.is_ok());

    let state = result.unwrap();
    assert_eq!(state.state, SystemState::Inactive);
}

#[test]
fn test_load_invalid_json_returns_default() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let invalid_file = temp_dir.path().join("invalid.json");

    // Write invalid JSON
    std::fs::write(&invalid_file, "{ invalid json syntax").expect("Should write file");

    let result = StateFile::load(&invalid_file);
    assert!(result.is_ok());

    let state = result.unwrap();
    assert_eq!(state.state, SystemState::Inactive);
}

#[test]
fn test_load_wrong_schema_returns_default() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let wrong_schema = temp_dir.path().join("wrong.json");

    // Write JSON with wrong schema (missing required fields)
    std::fs::write(&wrong_schema, r#"{"wrong": "schema"}"#).expect("Should write file");

    let result = StateFile::load(&wrong_schema);
    assert!(result.is_ok());

    let state = result.unwrap();
    assert_eq!(state.state, SystemState::Inactive);
}

// ========== Round-Trip Integration Tests ==========

#[test]
fn test_save_load_round_trip_with_inactive_state() {
    // Note: We can't actually save to /mnt/data in tests,
    // but we can test the serialization/deserialization logic
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let state_dir = temp_dir.path();
    let state_path = state_dir.join("state.json");

    let original = StateFile {
        version: env!("CARGO_PKG_VERSION").to_string(),
        state: SystemState::Inactive,
        nixos_generation: None,
        overlay_status: std::collections::HashMap::new(),
        failed_overlays: Vec::new(),
        last_modified: DateTime::parse_from_rfc3339("2025-01-27T10:30:00Z")
            .unwrap()
            .with_timezone(&Utc),
        boot_id: None,
        owner_pid: 0,
        nix_store_init_namespace_bound: false,
        read_only_guards: Vec::new(),
        integrity_sha256: None,
        config_fingerprint: None,
    };

    // Save through the real durable path so the file carries a valid digest.
    original
        .save_with_root(&state_path, state_dir.to_str().unwrap())
        .expect("Should save");

    // Load and verify the persisted fields (save also stamps owner_pid/digest).
    let loaded = StateFile::load(&state_path).expect("Should load");
    assert_eq!(loaded.state, original.state);
    assert_eq!(loaded.version, original.version);
    assert_eq!(loaded.nixos_generation, original.nixos_generation);
    assert_eq!(loaded.last_modified, original.last_modified);
}

#[test]
fn test_save_load_round_trip_with_active_state() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let state_dir = temp_dir.path();
    let state_path = state_dir.join("state.json");

    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/home"),
            upper_dir: PathBuf::from("/mnt/data/overlays/home/upper"),
            work_dir: PathBuf::from("/mnt/data/overlays/home/work"),
            mounted_at: DateTime::parse_from_rfc3339("2025-01-27T10:30:00Z")
                .unwrap()
                .with_timezone(&Utc),
        },
    );

    let original = StateFile {
        version: env!("CARGO_PKG_VERSION").to_string(),
        state: SystemState::Active {
            activated_at: DateTime::parse_from_rfc3339("2025-01-27T10:30:00Z")
                .unwrap()
                .with_timezone(&Utc),
            overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
        },
        nixos_generation: Some("abc123def456".to_string()),
        overlay_status,
        failed_overlays: Vec::new(),
        last_modified: DateTime::parse_from_rfc3339("2025-01-27T10:30:01Z")
            .unwrap()
            .with_timezone(&Utc),
        boot_id: None,
        owner_pid: 0,
        nix_store_init_namespace_bound: false,
        read_only_guards: Vec::new(),
        integrity_sha256: None,
        config_fingerprint: None,
    };

    // Save through the real durable path so the file carries a valid digest.
    original
        .save_with_root(&state_path, state_dir.to_str().unwrap())
        .expect("Should save");

    // Load and verify
    let loaded = StateFile::load(&state_path).expect("Should load");
    assert_eq!(loaded.state, original.state);
    assert_eq!(loaded.nixos_generation, original.nixos_generation);
    assert_eq!(loaded.overlay_status, original.overlay_status);
    assert_eq!(loaded.version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn test_save_load_multiple_overlays() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let state_dir = temp_dir.path();
    let state_path = state_dir.join("state.json");

    let mut overlay_status = std::collections::HashMap::new();

    // Add multiple overlays
    for (mount, name) in [("/home", "home"), ("/etc", "etc"), ("/var", "var")] {
        overlay_status.insert(
            PathBuf::from(mount),
            OverlayInfo {
                mount_method: Default::default(),
                mount_path: PathBuf::from(mount),
                lower_dir: PathBuf::from(mount),
                upper_dir: PathBuf::from(format!("/mnt/data/overlays/{}/upper", name)),
                work_dir: PathBuf::from(format!("/mnt/data/overlays/{}/work", name)),
                mounted_at: Utc::now(),
            },
        );
    }

    let original = StateFile {
        version: env!("CARGO_PKG_VERSION").to_string(),
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![
                PathBuf::from("/home"),
                PathBuf::from("/etc"),
                PathBuf::from("/var"),
            ],
        },
        nixos_generation: Some("test123".to_string()),
        overlay_status,
        failed_overlays: Vec::new(),
        last_modified: Utc::now(),
        boot_id: None,
        owner_pid: 0,
        nix_store_init_namespace_bound: false,
        read_only_guards: Vec::new(),
        integrity_sha256: None,
        config_fingerprint: None,
    };

    // Save through the real durable path so the file carries a valid digest.
    original
        .save_with_root(&state_path, state_dir.to_str().unwrap())
        .expect("Should save");

    // Load and verify
    let loaded = StateFile::load(&state_path).expect("Should load");
    assert_eq!(loaded.overlay_status.len(), 3);
    assert!(loaded.overlay_status.contains_key(&PathBuf::from("/home")));
    assert!(loaded.overlay_status.contains_key(&PathBuf::from("/etc")));
    assert!(loaded.overlay_status.contains_key(&PathBuf::from("/var")));
}

// ========== Additional Coverage Tests for Review Items ==========

#[test]
fn test_version_field_serializes() {
    let state = StateFile::default();
    assert_eq!(state.version, env!("CARGO_PKG_VERSION"));

    let json = serde_json::to_string(&state).expect("Should serialize");
    assert!(json.contains(&format!("\"version\":\"{}\"", env!("CARGO_PKG_VERSION"))));
}

#[test]
fn test_checksum_field_optional() {
    let state = StateFile::default();
    assert_eq!(state.integrity_sha256, None);

    let json = serde_json::to_string(&state).expect("Should serialize");
    // Integrity digest should not appear in JSON when None (skip_serializing_if)
    assert!(!json.contains("\"integrity_sha256\""));
}

#[test]
fn test_checksum_field_present_when_set() {
    let state = StateFile {
        boot_id: None,
        owner_pid: 0,
        integrity_sha256: Some("abc123".to_string()),
        ..StateFile::default()
    };

    let json = serde_json::to_string(&state).expect("Should serialize");
    assert!(json.contains("\"integrity_sha256\""));
    assert!(json.contains("\"abc123\""));
}

#[test]
fn test_nix_store_init_namespace_bound_defaults_false() {
    let state = StateFile::default();
    assert!(!state.nix_store_init_namespace_bound);
}

#[test]
fn test_nix_store_init_namespace_bound_round_trips() {
    let state = StateFile {
        nix_store_init_namespace_bound: true,
        read_only_guards: Vec::new(),
        ..StateFile::default()
    };

    let json = serde_json::to_string(&state).expect("Should serialize");
    assert!(json.contains("\"nix_store_init_namespace_bound\":true"));

    let restored: StateFile = serde_json::from_str(&json).expect("Should deserialize");
    assert!(restored.nix_store_init_namespace_bound);
}

#[test]
fn test_nix_store_init_namespace_bound_absent_field_defaults_false() {
    // A state file written before the field existed must still load, defaulting
    // the flag to false so teardown never undoes a bind that was never recorded.
    let legacy = r#"{
        "version": "0.2.0",
        "state": "Inactive",
        "nixos_generation": null,
        "overlay_status": {},
        "last_modified": "2025-01-27T10:30:00Z",
        "owner_pid": 0
    }"#;

    let loaded: StateFile = serde_json::from_str(legacy).expect("Should deserialize legacy state");
    assert!(!loaded.nix_store_init_namespace_bound);
}

#[test]
fn test_path_validation_with_relative_path() {
    // Test that relative paths are rejected (not on hidden volume)
    use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
    assert!(!is_on_hidden_volume(
        Path::new("relative/path/state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));
    assert!(!is_on_hidden_volume(
        Path::new("./state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));
    assert!(!is_on_hidden_volume(
        Path::new("../state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));
}

#[test]
fn test_path_validation_with_non_canonical_paths() {
    // Test paths that need to be cleaned before checking
    // These test the non-canonical path logic (line 70-111)
    use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;
    assert!(!is_on_hidden_volume(
        Path::new("/mnt/data/../etc/state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));
    assert!(!is_on_hidden_volume(
        Path::new("/etc/../home/user/state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));
    assert!(!is_on_hidden_volume(
        Path::new("/mnt/./other/state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));

    // Valid path with redundant components should still work
    assert!(is_on_hidden_volume(
        Path::new("/mnt/data/./subdir/state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));
    assert!(is_on_hidden_volume(
        Path::new("/mnt/data/nested/../other/state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));
    assert!(is_on_hidden_volume(
        Path::new("/mnt/data/subdir/../state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));
}

#[test]
fn test_custom_hidden_volume_root_tmp_validation() {
    // When hidden_volume_root is configured as /tmp,
    // state file at /tmp/state.json passes validation,
    // and /mnt/data/state.json fails
    use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;

    // Test 1: /tmp/state.json should pass with /tmp as root
    assert!(is_on_hidden_volume(Path::new("/tmp/state.json"), "/tmp"));

    // Test 2: /mnt/data/state.json should FAIL with /tmp as root
    assert!(!is_on_hidden_volume(
        Path::new("/mnt/data/state.json"),
        "/tmp"
    ));

    // Test 3: Validate default behavior still works
    assert!(is_on_hidden_volume(
        Path::new("/mnt/data/state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));

    // Test 4: /tmp should fail with default root
    assert!(!is_on_hidden_volume(
        Path::new("/tmp/state.json"),
        DEFAULT_HIDDEN_VOLUME_ROOT
    ));
}

#[test]
fn test_actual_atomic_write_to_temp_hidden_volume() {
    // Create a mock hidden volume in temp for testing
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol_root = temp_dir.path().to_str().unwrap();
    let state_dir = temp_dir.path();
    std::fs::create_dir_all(state_dir).expect("Should create dirs");

    let state_path = state_dir.join("state.json");

    // Now we can actually test save() with a custom hidden volume root!
    let state = StateFile {
        version: env!("CARGO_PKG_VERSION").to_string(),
        state: SystemState::Inactive,
        nixos_generation: Some("test-gen".to_string()),
        overlay_status: std::collections::HashMap::new(),
        failed_overlays: Vec::new(),
        last_modified: Utc::now(),
        boot_id: None,
        owner_pid: 0,
        nix_store_init_namespace_bound: false,
        read_only_guards: Vec::new(),
        integrity_sha256: None,
        config_fingerprint: None,
    };

    // Use save_with_root to test actual atomic write logic
    state
        .save_with_root(&state_path, mock_hidden_vol_root)
        .expect("Should save with custom root");

    // Verify file exists and is readable
    assert!(state_path.exists());
    let loaded_json = std::fs::read_to_string(&state_path).expect("Should read");
    let loaded: StateFile = serde_json::from_str(&loaded_json).expect("Should deserialize");
    assert_eq!(loaded.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(loaded.nixos_generation, Some("test-gen".to_string()));

    // Verify permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&state_path)
            .expect("Should get metadata")
            .permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    // Test that save_with_root rejects paths outside the custom root
    let outside_path = temp_dir.path().parent().unwrap().join("outside.json");
    let result = state.save_with_root(&outside_path, mock_hidden_vol_root);
    assert!(result.is_err());
    match result {
        Err(NailsError::InvalidState(msg)) => {
            assert!(msg.contains("State file must be on hidden volume"));
        }
        _ => panic!("Expected InvalidState error"),
    }
}

#[test]
fn test_load_io_error_returns_default() {
    // Test load() handling of I/O errors beyond just missing file
    // Create a directory with the same name as our target file (causes read error)
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let state_dir = temp_dir.path();
    let dir_as_file = state_dir.join("state.json");
    std::fs::create_dir(&dir_as_file).expect("Should create dir");

    // Try to load directory as file (should fail gracefully)
    let result = StateFile::load(&dir_as_file);
    assert!(result.is_ok());

    let state = result.unwrap();
    assert_eq!(state.state, SystemState::Inactive);
    assert_eq!(state.nixos_generation, None);
}

#[test]
fn test_persist_race_condition_handling() {
    // Test that save_with_root handles race conditions properly
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol_root = temp_dir.path().to_str().unwrap();
    let state_dir = temp_dir.path();
    std::fs::create_dir_all(state_dir).expect("Should create dirs");

    let state_path = state_dir.join("state.json");

    // Pre-create the target file to simulate race condition
    std::fs::write(&state_path, "existing content").expect("Should write existing file");

    let state = StateFile {
        version: env!("CARGO_PKG_VERSION").to_string(),
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![],
        },
        nixos_generation: None,
        overlay_status: std::collections::HashMap::new(),
        failed_overlays: Vec::new(),
        last_modified: Utc::now(),
        boot_id: None,
        owner_pid: 0,
        nix_store_init_namespace_bound: false,
        read_only_guards: Vec::new(),
        integrity_sha256: None,
        config_fingerprint: None,
    };

    // save_with_root should handle the existing file (overwrite it)
    state
        .save_with_root(&state_path, mock_hidden_vol_root)
        .expect("Should overwrite existing file");

    // Verify new content was written
    let loaded_json = std::fs::read_to_string(&state_path).expect("Should read");
    let loaded: StateFile = serde_json::from_str(&loaded_json).expect("Should deserialize");
    assert_eq!(loaded.version, env!("CARGO_PKG_VERSION"));
    assert!(loaded.state.is_active());
    assert_ne!(loaded_json, "existing content");
}

// ========== StateGuard Tests ==========

use crate::Config;
use crate::MockFilesystem;
use crate::NailsManager;

fn create_test_manager_with_state(
    state: SystemState,
) -> (NailsManager<MockFilesystem>, PathBuf, tempfile::TempDir) {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_hidden_vol = temp_dir.path();
    let state_dir = mock_hidden_vol;
    std::fs::create_dir_all(state_dir).expect("Should create dirs");
    let state_path = state_dir.join("state.json");

    // Create initial state file
    let state_file = StateFile {
        version: env!("CARGO_PKG_VERSION").to_string(),
        state,
        nixos_generation: None,
        overlay_status: std::collections::HashMap::new(),
        failed_overlays: Vec::new(),
        last_modified: Utc::now(),
        boot_id: None,
        owner_pid: 0,
        nix_store_init_namespace_bound: false,
        read_only_guards: Vec::new(),
        integrity_sha256: None,
        config_fingerprint: None,
    };
    // Save through the durable path so the file carries a valid integrity digest.
    state_file
        .save_with_custom_root(&state_path, mock_hidden_vol)
        .unwrap();

    let fs = MockFilesystem::new();
    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::default()
    };

    let manager = NailsManager::new(fs, config, state_path.clone());
    (manager, state_path, temp_dir)
}

#[test]
fn test_state_guard_new_creates_uncommitted_guard() {
    let (mut manager, _, _temp_dir) = create_test_manager_with_state(SystemState::Inactive);
    let previous_state = SystemState::Inactive;

    let guard = StateGuard::new(&mut manager, previous_state);
    assert!(!guard.is_committed());
    drop(guard);
}

#[test]
fn test_state_guard_commit_prevents_rollback() {
    let (mut manager, state_path, _temp_dir) =
        create_test_manager_with_state(SystemState::Inactive);

    // Change state to Activating.
    manager
        .force_state(SystemState::Activating {
            started_at: Utc::now(),
        })
        .unwrap();

    // Create guard with Inactive as previous state, then commit (no rollback).
    let guard = StateGuard::new(&mut manager, SystemState::Inactive);
    guard.commit();

    let loaded = StateFile::load(&state_path).unwrap();
    assert!(matches!(loaded.state, SystemState::Activating { .. }));
}

#[test]
fn test_state_guard_drop_rolls_back_if_not_committed() {
    let (mut manager, state_path, _temp_dir) =
        create_test_manager_with_state(SystemState::Inactive);

    let previous_state = manager.current_state().unwrap();

    {
        manager
            .force_state(SystemState::Activating {
                started_at: Utc::now(),
            })
            .unwrap();

        // Guard captures Inactive; it will roll back when dropped.
        let guard = StateGuard::new(&mut manager, previous_state);
        assert!(matches!(
            guard.current_state().unwrap(),
            SystemState::Activating { .. }
        ));
        // Guard goes out of scope here - triggers rollback.
    }

    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded.state, SystemState::Inactive);
}

#[test]
fn test_state_guard_rolls_back_on_panic() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let (mut manager, state_path, _temp_dir) =
        create_test_manager_with_state(SystemState::Inactive);
    assert!(manager.current_state().unwrap().is_inactive());

    let result = catch_unwind(AssertUnwindSafe(|| {
        let previous_state = manager.current_state().unwrap();
        let mut guard = StateGuard::new(&mut manager, previous_state);

        guard
            .force_state(SystemState::Activating {
                started_at: Utc::now(),
            })
            .unwrap();

        // Panic! Guard should still rollback via Drop during unwinding.
        panic!("Simulated failure during activation!");
    }));

    assert!(result.is_err());

    let loaded = StateFile::load(&state_path).unwrap();
    assert!(
        loaded.state.is_inactive(),
        "State should be rolled back to Inactive after panic"
    );
}

#[test]
fn test_state_guard_idempotent_rollback() {
    let (mut manager, state_path, _temp_dir) =
        create_test_manager_with_state(SystemState::Inactive);

    {
        // Create and drop a guard without changing state (idempotent rollback).
        let guard = StateGuard::new(&mut manager, SystemState::Inactive);
        drop(guard);
    }

    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded.state, SystemState::Inactive);
}

#[test]
fn test_state_guard_multiple_guards_sequential() {
    let (mut manager, state_path, _temp_dir) =
        create_test_manager_with_state(SystemState::Inactive);

    {
        let mut guard1 = StateGuard::new(&mut manager, SystemState::Inactive);
        guard1
            .force_state(SystemState::Activating {
                started_at: Utc::now(),
            })
            .unwrap();
        // guard1 drops here, rolls back to Inactive.
    }

    assert!(manager.current_state().unwrap().is_inactive());

    {
        let mut guard2 = StateGuard::new(&mut manager, SystemState::Inactive);
        guard2
            .force_state(SystemState::Activating {
                started_at: Utc::now(),
            })
            .unwrap();
        // guard2 drops here, rolls back to Inactive again.
    }

    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded.state, SystemState::Inactive);
}

#[test]
fn test_state_guard_activation_failure_scenario() {
    let (mut manager, state_path, _temp_dir) =
        create_test_manager_with_state(SystemState::Inactive);

    {
        let previous_state = manager.current_state().unwrap();
        let mut guard = StateGuard::new(&mut manager, previous_state);

        guard
            .force_state(SystemState::Activating {
                started_at: Utc::now(),
            })
            .unwrap();

        // Simulate mount failure - don't commit; guard rolls back automatically.
    }

    let loaded = StateFile::load(&state_path).unwrap();
    assert!(loaded.state.is_inactive());
}

#[test]
fn test_state_guard_deactivation_failure_scenario() {
    let (mut manager, state_path, _temp_dir) =
        create_test_manager_with_state(SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![],
        });

    let previous_state = manager.current_state().unwrap();

    {
        let mut guard = StateGuard::new(&mut manager, previous_state);

        guard
            .force_state(SystemState::Deactivating {
                started_at: Utc::now(),
            })
            .unwrap();

        // Simulate cleanup failure - don't commit; guard rolls back to Active.
    }

    let loaded = StateFile::load(&state_path).unwrap();
    assert!(
        loaded.state.is_active(),
        "State should be Active after rollback, but was {:?}",
        loaded.state
    );
}

#[test]
fn test_state_guard_rollback_after_multiple_state_changes() {
    let (mut manager, state_path, _temp_dir) =
        create_test_manager_with_state(SystemState::Inactive);

    let initial_state = manager.current_state().unwrap();

    {
        let mut guard = StateGuard::new(&mut manager, initial_state);

        guard
            .force_state(SystemState::Activating {
                started_at: Utc::now(),
            })
            .unwrap();
        guard
            .force_state(SystemState::Active {
                activated_at: Utc::now(),
                overlays: vec![],
            })
            .unwrap();
        guard
            .force_state(SystemState::Deactivating {
                started_at: Utc::now(),
            })
            .unwrap();

        // Don't commit - guard should rollback to ORIGINAL state (Inactive).
    }

    let loaded = StateFile::load(&state_path).unwrap();
    assert!(
        loaded.state.is_inactive(),
        "Rollback should restore original captured state (Inactive), not intermediate states"
    );
}

#[test]
fn test_state_guard_commit_is_final() {
    let (mut manager, state_path, _temp_dir) =
        create_test_manager_with_state(SystemState::Inactive);

    {
        let mut guard = StateGuard::new(&mut manager, SystemState::Inactive);

        guard
            .force_state(SystemState::Activating {
                started_at: Utc::now(),
            })
            .unwrap();

        // Commit the transaction (consumes the guard, prevents rollback).
        guard.commit();
    }

    let loaded = StateFile::load(&state_path).unwrap();
    assert!(
        matches!(loaded.state, SystemState::Activating { .. }),
        "State should remain Activating after commit (no rollback)"
    );
}

/// Integration test: a failure during activate() triggers StateGuard rollback.
#[test]
fn test_integration_activate_panic_triggers_stateguard_rollback() {
    use crate::{Config, MockFilesystem, NailsManager, OverlayConfig};

    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    let state_dir = mock_hidden_vol;
    std::fs::create_dir_all(state_dir).unwrap();
    let state_path = state_dir.join("state.json");

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/", true);
    fs.mock_set_path_exists("/nix/var/nix/profiles/system", true);
    fs.mock_set_path_exists(
        "/nix/var/nix/profiles/system/bin/switch-to-configuration",
        true,
    );
    let upper_dir = mock_hidden_vol.join("upper");
    let work_dir = mock_hidden_vol.join("work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlay_mode: crate::config::OverlayMode::Explicit,
        overlays: vec![OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/"),
            upper: upper_dir.clone(),
            work: work_dir.clone(),
            target: PathBuf::from("/home"),
        }],
        ..Config::default()
    };

    let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());

    assert!(manager.current_state().unwrap().is_inactive());

    // Cause a mount failure which triggers StateGuard's automatic rollback.
    fs.mock_set_mount_should_fail("/home", true);

    let result = manager.activate(true);
    assert!(result.is_err(), "Activation should fail due to mount error");

    let state = manager.current_state().unwrap();
    assert!(
        state.is_inactive(),
        "State should be rolled back to Inactive after activation failure, got: {:?}",
        state
    );

    let loaded = StateFile::load(&state_path).unwrap();
    assert!(
        loaded.state.is_inactive(),
        "State file should contain Inactive after StateGuard rollback"
    );
}

/// Integration test: a failure during deactivate() triggers StateGuard rollback.
#[test]
fn test_integration_deactivate_panic_triggers_stateguard_rollback() {
    use crate::{Config, MockFilesystem, NailsManager, OverlayConfig, OverlayInfo};
    use std::collections::HashMap;

    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    let state_dir = mock_hidden_vol;
    std::fs::create_dir_all(state_dir).unwrap();
    let state_path = state_dir.join("state.json");

    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/", true);
    let upper_dir = mock_hidden_vol.join("upper");
    let work_dir = mock_hidden_vol.join("work");
    std::fs::create_dir_all(&upper_dir).unwrap();
    std::fs::create_dir_all(&work_dir).unwrap();
    fs.mock_set_path_exists(upper_dir.to_str().unwrap(), true);
    fs.mock_set_path_exists(work_dir.to_str().unwrap(), true);

    fs.mock_set_mounted(Path::new("/home"), true);

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![OverlayConfig {
            name: "home".to_string(),
            lower: PathBuf::from("/"),
            upper: upper_dir.clone(),
            work: work_dir.clone(),
            target: PathBuf::from("/home"),
        }],
        ..Config::default()
    };

    let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());

    let mut overlay_status = HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/"),
            upper_dir: upper_dir.clone(),
            work_dir: work_dir.clone(),
            mounted_at: Utc::now(),
        },
    );

    let initial_state = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
            overlays: vec![PathBuf::from("/home")],
        },
        overlay_status,
        ..StateFile::default()
    };
    initial_state
        .save_with_custom_root(&state_path, mock_hidden_vol)
        .unwrap();

    // Load the Active state we just wrote.
    assert!(matches!(
        manager.current_state().unwrap(),
        SystemState::Active { .. }
    ));

    // Cause unmount to fail, triggering StateGuard rollback.
    fs.mock_set_unmount_should_fail("/home", true);

    let result = manager.deactivate();
    assert!(
        result.is_err(),
        "Deactivation should fail due to unmount error"
    );

    let state = manager.current_state().unwrap();
    assert!(
        matches!(state, SystemState::Active { .. }),
        "State should be rolled back to Active after deactivation failure, got: {:?}",
        state
    );

    let loaded = StateFile::load(&state_path).unwrap();
    assert!(
        loaded.state.is_active(),
        "State file should contain Active after StateGuard rollback (Remount overlays if cleanup fails)"
    );
}

/// End-to-end test demonstrating the StateGuard pattern in a workflow.
#[test]
fn test_stateguard_end_to_end_workflow() {
    use chrono::Utc;

    let fs = MockFilesystem::new();
    let temp_dir = tempfile::tempdir().unwrap();
    let mock_hidden_vol = temp_dir.path();
    let state_dir = mock_hidden_vol;
    std::fs::create_dir_all(state_dir).unwrap();
    let state_path = state_dir.join("state.json");

    let config = Config {
        hidden_volume_root: mock_hidden_vol.to_path_buf(),
        state_file_path: state_path.clone(),
        overlays: vec![],
        ..Config::default()
    };

    let mut manager = NailsManager::new(fs.clone(), config, state_path.clone());

    // === TEST PART 1: Success Path (commit prevents rollback) ===
    let previous_state = manager.current_state().unwrap();
    assert_eq!(
        previous_state,
        SystemState::Inactive,
        "Should start Inactive"
    );

    {
        let mut guard = StateGuard::new(&mut manager, previous_state);

        // Verify guard internals via getters.
        assert_eq!(*guard.previous_state(), SystemState::Inactive);
        assert!(
            !guard.is_committed(),
            "Guard should be uncommitted initially"
        );

        guard
            .force_state(SystemState::Activating {
                started_at: Utc::now(),
            })
            .unwrap();

        assert!(matches!(
            guard.current_state().unwrap(),
            SystemState::Activating { .. }
        ));

        // All steps succeeded - commit prevents rollback.
        guard.commit();
    }

    assert!(
        matches!(
            manager.current_state().unwrap(),
            SystemState::Activating { .. }
        ),
        "State should remain Activating after commit"
    );

    // === TEST PART 2: Failure Path (auto-rollback on error) ===
    manager.force_state(SystemState::Inactive).unwrap();

    let previous_state = manager.current_state().unwrap();
    assert_eq!(previous_state, SystemState::Inactive);

    {
        let mut guard = StateGuard::new(&mut manager, previous_state);
        guard
            .force_state(SystemState::Activating {
                started_at: Utc::now(),
            })
            .unwrap();
        // Simulate operation failure - DON'T commit, just drop the guard.
    }

    assert_eq!(
        manager.current_state().unwrap(),
        SystemState::Inactive,
        "State should be rolled back to Inactive when guard dropped without commit"
    );

    // === TEST PART 3: Rollback on early return (scope-based) ===
    {
        let previous_state = manager.current_state().unwrap();
        let mut guard = StateGuard::new(&mut manager, previous_state);
        guard
            .force_state(SystemState::Activating {
                started_at: Utc::now(),
            })
            .unwrap();
        // Early return without commit - guard dropped here.
    }

    assert_eq!(
        manager.current_state().unwrap(),
        SystemState::Inactive,
        "State should rollback on early return (scope exit)"
    );

    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded.state, SystemState::Inactive);
}

#[test]
#[cfg(unix)]
fn test_state_file_permissions_are_0600() {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let state_path = temp_dir.path().join("state.json");
    let mock_hidden_vol_root = temp_dir.path().to_str().unwrap();

    let state = StateFile {
        version: env!("CARGO_PKG_VERSION").to_string(),
        state: SystemState::Inactive,
        nixos_generation: None,
        overlay_status: std::collections::HashMap::new(),
        failed_overlays: Vec::new(),
        last_modified: Utc::now(),
        boot_id: None,
        owner_pid: 0,
        nix_store_init_namespace_bound: false,
        read_only_guards: Vec::new(),
        integrity_sha256: None,
        config_fingerprint: None,
    };
    state
        .save_with_root(&state_path, mock_hidden_vol_root)
        .expect("Failed to save state file");

    let perms = std::fs::metadata(&state_path)
        .expect("Should get metadata")
        .permissions();
    assert_eq!(
        perms.mode() & 0o777,
        0o600,
        "State file permissions should be 0o600 (owner read/write only)"
    );
}

// ========== Integrity (corruption-detection) Tests ==========

#[test]
fn test_checksum_round_trip_save_load() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_root = temp_dir.path().to_str().unwrap();
    let state_path = temp_dir.path().join("state.json");

    let state = StateFile {
        version: env!("CARGO_PKG_VERSION").to_string(),
        state: SystemState::Inactive,
        nixos_generation: Some("gen123".to_string()),
        overlay_status: std::collections::HashMap::new(),
        failed_overlays: Vec::new(),
        last_modified: DateTime::parse_from_rfc3339("2025-01-27T10:30:00Z")
            .unwrap()
            .with_timezone(&Utc),
        boot_id: None,
        owner_pid: 0,
        nix_store_init_namespace_bound: false,
        read_only_guards: Vec::new(),
        integrity_sha256: None,
        config_fingerprint: None,
    };

    state
        .save_with_root(&state_path, mock_root)
        .expect("Should save");
    let loaded = StateFile::load(&state_path).expect("Should load");
    assert_eq!(loaded.state, SystemState::Inactive);
    assert_eq!(loaded.nixos_generation, Some("gen123".to_string()));
}

#[test]
fn test_integrity_mismatch_maps_to_unknown() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_root = temp_dir.path().to_str().unwrap();
    let state_path = temp_dir.path().join("state.json");

    let state = StateFile::default();
    state
        .save_with_root(&state_path, mock_root)
        .expect("Should save");

    // Corrupt the file: change a field but keep the stale integrity digest.
    let mut raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    raw["nixos_generation"] = serde_json::Value::String("CORRUPTED".to_string());
    std::fs::write(&state_path, serde_json::to_string_pretty(&raw).unwrap()).unwrap();

    // A digest mismatch is never a hard error: it collapses to the safe default
    // and reports the state as unknown so even emergency can still run.
    let result = StateFile::load_with_outcome(&state_path).expect("Should not hard-error");
    assert_eq!(result.outcome, LoadOutcome::Corrupt);
    assert!(result.outcome.is_unknown());
    assert_eq!(result.state_file.state, SystemState::Inactive);

    // The convenience loader also returns Ok with the safe default.
    let loaded = StateFile::load(&state_path).expect("Should not hard-error");
    assert_eq!(loaded.state, SystemState::Inactive);
}

#[test]
fn test_truncated_file_maps_to_unknown() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_root = temp_dir.path().to_str().unwrap();
    let state_path = temp_dir.path().join("state.json");

    StateFile::default()
        .save_with_root(&state_path, mock_root)
        .expect("Should save");

    // Truncate mid-file so the JSON no longer parses.
    let contents = std::fs::read_to_string(&state_path).unwrap();
    std::fs::write(&state_path, &contents[..contents.len() / 2]).unwrap();

    let result = StateFile::load_with_outcome(&state_path).expect("Should not hard-error");
    assert_eq!(result.outcome, LoadOutcome::Corrupt);
    assert_eq!(result.state_file.state, SystemState::Inactive);
}

#[test]
fn test_missing_integrity_digest_rejected() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let state_path = temp_dir.path().join("state.json");

    // Write a well-formed state file WITHOUT an integrity digest.
    let json = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "state": "Inactive",
        "nixos_generation": null,
        "overlay_status": {},
        "failed_overlays": [],
        "last_modified": "2025-01-27T10:30:00Z"
    });
    std::fs::write(&state_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

    // No digest means the file cannot be trusted: treated as corrupt, not accepted.
    let result = StateFile::load_with_outcome(&state_path).expect("Should not hard-error");
    assert_eq!(result.outcome, LoadOutcome::Corrupt);
    assert_eq!(result.state_file.state, SystemState::Inactive);
}

#[test]
fn test_checksum_populated_after_save() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_root = temp_dir.path().to_str().unwrap();
    let state_path = temp_dir.path().join("state.json");

    let state = StateFile::default();
    state
        .save_with_root(&state_path, mock_root)
        .expect("Should save");

    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    let checksum = raw["integrity_sha256"]
        .as_str()
        .expect("checksum should be present");
    assert_eq!(checksum.len(), 64, "SHA-256 hex should be 64 chars");
    assert!(
        checksum.chars().all(|c| c.is_ascii_hexdigit()),
        "checksum should be hex"
    );
}

// ========== Symlink and Path Escape Regression Tests (P0-03) ==========

#[test]
#[cfg(unix)]
fn test_symlinked_hidden_volume_root_rejected() {
    // A symlink used as the hidden volume root should be rejected
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let real_dir = temp_dir.path().join("real-hv");
    std::fs::create_dir_all(&real_dir).expect("Should create real dir");

    let symlink_root = temp_dir.path().join("symlinked-hv");
    std::os::unix::fs::symlink(&real_dir, &symlink_root).expect("Should create symlink");

    // Create a file inside the real dir
    std::fs::write(real_dir.join("state.json"), "{}").expect("Should write");

    // Path through symlinked root should be rejected
    let test_path = symlink_root.join("state.json");
    let root_str = symlink_root.to_str().unwrap();
    assert!(
        !is_on_hidden_volume(&test_path, root_str),
        "Symlinked hidden volume root should be rejected"
    );
}

#[test]
#[cfg(unix)]
fn test_symlinked_parent_in_path_rejected() {
    // A symlink inside the hidden volume pointing outside should be rejected
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let hv_root = temp_dir.path().join("hv");
    std::fs::create_dir_all(&hv_root).expect("Should create hv dir");

    let outside_dir = temp_dir.path().join("outside");
    std::fs::create_dir_all(&outside_dir).expect("Should create outside dir");
    std::fs::write(outside_dir.join("state.json"), "{}").expect("Should write");

    // Create symlink inside hidden volume pointing outside
    let logs_symlink = hv_root.join("logs");
    std::os::unix::fs::symlink(&outside_dir, &logs_symlink).expect("Should create symlink");

    let test_path = logs_symlink.join("state.json");
    let root_str = hv_root.to_str().unwrap();
    assert!(
        !is_on_hidden_volume(&test_path, root_str),
        "Path through symlink escaping hidden volume should be rejected"
    );
}

#[test]
fn test_traversal_escape_rejected() {
    // Paths using .. to escape the hidden volume must be rejected
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let hv_root = temp_dir.path().join("hv");
    std::fs::create_dir_all(&hv_root).expect("Should create hv dir");
    let root_str = hv_root.to_str().unwrap();

    // ../.. should escape
    let escape_path = hv_root.join("../../etc/shadow");
    assert!(
        !is_on_hidden_volume(&escape_path, root_str),
        "Path traversal escape should be rejected"
    );

    // Single .. should escape
    let escape_path2 = hv_root.join("../outside");
    assert!(
        !is_on_hidden_volume(&escape_path2, root_str),
        "Single .. escape should be rejected"
    );
}

#[test]
fn test_nonexistent_root_rejected() {
    // When root doesn't exist, string-based fallback is used.
    // Paths that don't match the root prefix are rejected.
    let nonexistent_root = "/tmp/nails-test-nonexistent-root-12345";
    assert!(
        !Path::new(nonexistent_root).exists(),
        "Test precondition: root must not exist"
    );

    // An existing path outside the non-existent root should be rejected
    assert!(
        !is_on_hidden_volume(Path::new("/tmp"), nonexistent_root),
        "Existing path should be rejected when it doesn't match root prefix"
    );

    // Traversal escapes are still caught with non-existent roots
    assert!(
        !is_on_hidden_volume(
            Path::new("/tmp/nails-test-nonexistent-root-12345/../../../etc/shadow"),
            nonexistent_root
        ),
        "Traversal escape should be rejected even with non-existent root"
    );

    // Matching string prefix still passes (config validation scenario)
    assert!(
        is_on_hidden_volume(
            Path::new("/tmp/nails-test-nonexistent-root-12345/state.json"),
            nonexistent_root
        ),
        "Matching path should pass string-based check for config validation"
    );
}

// ========== P0-01 Regression Tests: Version Migration + Checksum ==========

/// Helper: given a state file path, change the version string and recompute the checksum
/// using the same method as save_internal (serialize StateFile with checksum=None).
fn rewrite_version_and_recompute_checksum(state_path: &Path, new_version: &str) {
    let raw_json = std::fs::read_to_string(state_path).unwrap();
    let mut state_file: StateFile = serde_json::from_str(&raw_json).unwrap();
    state_file.version = new_version.to_string();
    state_file.integrity_sha256 = None;

    // Compute checksum the same way save_internal does
    let hash_value = serde_json::to_value(&state_file).unwrap();
    let hash_json = hash_value.to_string();
    use sha2::Digest;
    let computed = hex::encode(sha2::Sha256::digest(hash_json.as_bytes()));
    state_file.integrity_sha256 = Some(computed);

    let json = serde_json::to_string_pretty(&state_file).unwrap();
    std::fs::write(state_path, json).unwrap();
}

#[test]
fn test_compatible_version_load_with_checksum() {
    // Regression: previously, loading a state file written by a different minor/patch
    // version would ALWAYS fail checksum verification because the version was updated
    // in memory BEFORE the checksum was verified.
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_root = temp_dir.path().to_str().unwrap();
    let state_path = temp_dir.path().join("state.json");

    let state = StateFile {
        nixos_generation: Some("gen-abc".to_string()),
        last_modified: DateTime::parse_from_rfc3339("2025-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
        ..StateFile::default()
    };

    state
        .save_with_root(&state_path, mock_root)
        .expect("Should save");

    // Simulate a file saved by version "0.99.99" (same major, different minor/patch)
    rewrite_version_and_recompute_checksum(&state_path, "0.99.99");

    let loaded = StateFile::load(&state_path).expect(
        "Should load state file with a different but compatible version without integrity failure",
    );
    assert_eq!(loaded.state, SystemState::Inactive);
    assert_eq!(loaded.nixos_generation, Some("gen-abc".to_string()));
    // With no migration, the stored version is preserved verbatim.
    assert_eq!(loaded.version, "0.99.99");
}

#[test]
fn test_corrupt_compatible_version_maps_to_unknown() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_root = temp_dir.path().to_str().unwrap();
    let state_path = temp_dir.path().join("state.json");

    let state = StateFile::default();
    state
        .save_with_root(&state_path, mock_root)
        .expect("Should save");

    // Change version AND data but keep the OLD integrity digest.
    let mut raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    raw["version"] = serde_json::Value::String("0.99.99".to_string());
    raw["nixos_generation"] = serde_json::Value::String("CORRUPTED".to_string());
    std::fs::write(&state_path, serde_json::to_string_pretty(&raw).unwrap()).unwrap();

    let result = StateFile::load_with_outcome(&state_path).expect("Should not hard-error");
    assert_eq!(result.outcome, LoadOutcome::Corrupt);
    assert_eq!(result.state_file.state, SystemState::Inactive);
}

#[test]
fn test_future_major_version_maps_to_unknown() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_root = temp_dir.path().to_str().unwrap();
    let state_path = temp_dir.path().join("state.json");

    let state = StateFile::default();
    state
        .save_with_root(&state_path, mock_root)
        .expect("Should save");

    // A newer major version is incompatible; re-seal it so the digest is valid.
    rewrite_version_and_recompute_checksum(&state_path, "999.0.0");

    // Incompatible schema is reported as unknown, never a hard error.
    let result = StateFile::load_with_outcome(&state_path).expect("Should not hard-error");
    assert_eq!(result.outcome, LoadOutcome::Corrupt);
    assert_eq!(result.state_file.state, SystemState::Inactive);
}

#[test]
fn test_version_migration_preserves_data() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_root = temp_dir.path().to_str().unwrap();
    let state_path = temp_dir.path().join("state.json");

    let mut overlay_status = std::collections::HashMap::new();
    overlay_status.insert(
        PathBuf::from("/home"),
        OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/home"),
            upper_dir: PathBuf::from("/mnt/data/overlays/home/upper"),
            work_dir: PathBuf::from("/mnt/data/overlays/home/work"),
            mounted_at: DateTime::parse_from_rfc3339("2025-06-01T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        },
    );

    let state = StateFile {
        state: SystemState::Active {
            activated_at: DateTime::parse_from_rfc3339("2025-06-01T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            overlays: vec![PathBuf::from("/home")],
        },
        nixos_generation: Some("gen-xyz".to_string()),
        config_fingerprint: Some("abcdef0123456789".to_string()),
        overlay_status: overlay_status.clone(),
        failed_overlays: vec![FailedOverlayInfo {
            target: PathBuf::from("/var"),
            error_message: "mount failed".to_string(),
            failed_at: DateTime::parse_from_rfc3339("2025-06-01T12:01:00Z")
                .unwrap()
                .with_timezone(&Utc),
        }],
        last_modified: DateTime::parse_from_rfc3339("2025-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
        ..StateFile::default()
    };

    state
        .save_with_root(&state_path, mock_root)
        .expect("Should save");

    // Change version and re-seal the integrity digest.
    rewrite_version_and_recompute_checksum(&state_path, "0.50.0");

    let loaded = StateFile::load(&state_path).expect("Should load a compatible-version file");

    // No migration: the stored version is preserved and the data is intact.
    assert_eq!(loaded.version, "0.50.0");
    assert!(matches!(loaded.state, SystemState::Active { .. }));
    assert_eq!(loaded.nixos_generation, Some("gen-xyz".to_string()));
    assert_eq!(
        loaded.config_fingerprint,
        Some("abcdef0123456789".to_string())
    );
    assert_eq!(loaded.overlay_status.len(), 1);
    assert!(loaded.overlay_status.contains_key(&PathBuf::from("/home")));
    assert_eq!(loaded.failed_overlays.len(), 1);
    assert_eq!(loaded.failed_overlays[0].target, PathBuf::from("/var"));
}

// ========== T-006: durability, provenance, Degraded ==========

#[test]
fn test_save_fsyncs_file_and_directory() {
    use super::file::sync_probe;
    let temp_dir = tempfile::tempdir().unwrap();
    let mock_root = temp_dir.path().to_str().unwrap();
    let state_path = temp_dir.path().join("state.json");

    let files_before = sync_probe::file_syncs();
    let dirs_before = sync_probe::dir_syncs();

    StateFile::default()
        .save_with_root(&state_path, mock_root)
        .unwrap();

    assert!(
        sync_probe::file_syncs() > files_before,
        "temp file must be fsynced before the rename"
    );
    assert!(
        sync_probe::dir_syncs() > dirs_before,
        "parent directory must be fsynced after the rename"
    );
}

#[test]
fn test_stale_temp_files_removed_on_load() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mock_root = temp_dir.path().to_str().unwrap();
    let state_path = temp_dir.path().join("state.json");
    StateFile::default()
        .save_with_root(&state_path, mock_root)
        .unwrap();

    // Simulate interrupted saves that left temp siblings behind, backdated so the
    // age guard treats them as crashed-save leftovers rather than an in-flight save.
    let stale1 = temp_dir.path().join(".tmpABCDEF");
    let stale2 = temp_dir.path().join(".tmp123456");
    std::fs::write(&stale1, b"junk").unwrap();
    std::fs::write(&stale2, b"junk").unwrap();
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
    let times = std::fs::FileTimes::new().set_modified(old);
    for path in [&stale1, &stale2] {
        let handle = std::fs::File::options().write(true).open(path).unwrap();
        handle.set_times(times).unwrap();
    }
    assert!(stale1.exists() && stale2.exists());

    let _ = StateFile::load(&state_path).unwrap();

    assert!(!stale1.exists(), "stale temp file should be swept on load");
    assert!(!stale2.exists(), "stale temp file should be swept on load");
    assert!(
        state_path.exists(),
        "the real state file must survive the sweep"
    );
}

#[test]
fn test_saved_state_carries_boot_id_and_owner_pid() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mock_root = temp_dir.path().to_str().unwrap();
    let state_path = temp_dir.path().join("state.json");
    StateFile::default()
        .save_with_root(&state_path, mock_root)
        .unwrap();

    let raw: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    // Both keys are always present; boot_id may be null in restricted environments.
    assert!(raw.as_object().unwrap().contains_key("boot_id"));
    assert_eq!(
        raw["owner_pid"].as_u64().unwrap() as u32,
        std::process::id()
    );

    let loaded = StateFile::load(&state_path).unwrap();
    assert_eq!(loaded.owner_pid, std::process::id());
}

#[test]
fn test_missing_file_is_missing_not_unknown() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("does-not-exist.json");
    let result = StateFile::load_with_outcome(&state_path).unwrap();
    assert_eq!(result.outcome, LoadOutcome::Missing);
    assert!(!result.outcome.is_unknown());
    assert_eq!(result.state_file.state, SystemState::Inactive);
}

#[test]
fn test_degraded_state_round_trips_through_save_load() {
    let temp_dir = tempfile::tempdir().unwrap();
    let mock_root = temp_dir.path().to_str().unwrap();
    let state_path = temp_dir.path().join("state.json");

    let degraded = SystemState::Degraded {
        since: DateTime::parse_from_rfc3339("2025-06-01T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
        reason: "unmount of /home failed".to_string(),
        remaining_mounts: vec![PathBuf::from("/home"), PathBuf::from("/var")],
    };
    let state = StateFile {
        state: degraded.clone(),
        ..StateFile::default()
    };
    state.save_with_root(&state_path, mock_root).unwrap();

    let result = StateFile::load_with_outcome(&state_path).unwrap();
    assert_eq!(result.outcome, LoadOutcome::Loaded);
    assert_eq!(result.state_file.state, degraded);
}

#[test]
fn test_emergency_transition_targets_inactive_and_degraded_recovers() {
    let after = SystemState::Active {
        activated_at: Utc::now(),
        overlays: vec![],
    }
    .trigger_emergency()
    .unwrap();
    assert!(after.is_inactive());

    let degraded = SystemState::Inactive.enter_degraded("boom".into(), vec![]);
    assert!(degraded.is_degraded());
    assert!(degraded.recover().unwrap().is_inactive());
}
