// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for state module

use super::*;
use crate::NailsError;

#[test]
fn test_state_file_default() {
    let state_file = StateFile::default();

    assert_eq!(state_file.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(state_file.state, SystemState::Inactive);
    assert_eq!(state_file.hidden_toplevel(), None);
    assert_eq!(state_file.integrity_sha256, None);
    // Just verify last_modified exists (can't test exact time)
    assert!(state_file.last_modified <= Utc::now());
}

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

#[test]
fn test_load_missing_file_returns_default() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let nonexistent_path = temp_dir.path().join("nonexistent.json");

    let result = StateFile::load(&nonexistent_path);
    assert!(result.is_ok());

    let state = result.unwrap();
    assert_eq!(state.state, SystemState::Inactive);
    assert_eq!(state.hidden_toplevel(), None);
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
        platform: None,
        last_activation: None,
        last_modified: DateTime::parse_from_rfc3339("2025-01-27T10:30:00Z")
            .unwrap()
            .with_timezone(&Utc),
        boot_id: None,
        owner_pid: 0,
        owner_start_time: None,
        integrity_sha256: None,
        config_fingerprint: None,
        decoy_system: None,
    };

    // Save through the real durable path so the file carries a valid digest.
    original
        .save_with_root(&state_path, state_dir.to_str().unwrap())
        .expect("Should save");

    // Load and verify the persisted fields (save also stamps owner_pid/digest).
    let loaded = StateFile::load(&state_path).expect("Should load");
    assert_eq!(loaded.state, original.state);
    assert_eq!(loaded.version, original.version);
    assert_eq!(loaded.hidden_toplevel(), original.hidden_toplevel());
    assert_eq!(loaded.last_modified, original.last_modified);
}

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
        owner_start_time: None,
        integrity_sha256: Some("abc123".to_string()),
        ..StateFile::default()
    };

    let json = serde_json::to_string(&state).expect("Should serialize");
    assert!(json.contains("\"integrity_sha256\""));
    assert!(json.contains("\"abc123\""));
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
        platform: Some(PlatformState::nixos(Some("test-gen".to_string()))),
        last_activation: None,
        last_modified: Utc::now(),
        boot_id: None,
        owner_pid: 0,
        owner_start_time: None,
        integrity_sha256: None,
        config_fingerprint: None,
        decoy_system: None,
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
    assert_eq!(loaded.hidden_toplevel(), Some("test-gen"));

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
    assert_eq!(state.hidden_toplevel(), None);
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
        platform: None,
        last_activation: None,
        last_modified: Utc::now(),
        boot_id: None,
        owner_pid: 0,
        owner_start_time: None,
        integrity_sha256: None,
        config_fingerprint: None,
        decoy_system: None,
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

#[test]
fn test_checksum_round_trip_save_load() {
    let temp_dir = tempfile::tempdir().expect("Should create temp dir");
    let mock_root = temp_dir.path().to_str().unwrap();
    let state_path = temp_dir.path().join("state.json");

    let state = StateFile {
        version: env!("CARGO_PKG_VERSION").to_string(),
        state: SystemState::Inactive,
        platform: Some(PlatformState::nixos(Some("gen123".to_string()))),
        last_activation: None,
        last_modified: DateTime::parse_from_rfc3339("2025-01-27T10:30:00Z")
            .unwrap()
            .with_timezone(&Utc),
        boot_id: None,
        owner_pid: 0,
        owner_start_time: None,
        integrity_sha256: None,
        config_fingerprint: None,
        decoy_system: None,
    };

    state
        .save_with_root(&state_path, mock_root)
        .expect("Should save");
    let loaded = StateFile::load(&state_path).expect("Should load");
    assert_eq!(loaded.state, SystemState::Inactive);
    assert_eq!(loaded.hidden_toplevel(), Some("gen123"));
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
    raw["config_fingerprint"] = serde_json::Value::String("CORRUPTED".to_string());
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
        platform: Some(PlatformState::nixos(Some("gen-abc".to_string()))),
        last_activation: None,
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
    assert_eq!(loaded.hidden_toplevel(), Some("gen-abc"));
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
    raw["config_fingerprint"] = serde_json::Value::String("CORRUPTED".to_string());
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
fn test_save_refuses_a_symlinked_path_component() {
    // A symlink planted between the hidden root and state.json — even one that
    // stays inside the root — must not be traversed: SafeRoot resolves the write
    // with RESOLVE_NO_SYMLINKS, so a swapped-in link cannot redirect the
    // privileged state write. `is_on_hidden_volume` accepts this path (the link
    // canonicalizes back inside the root); the containment helper is the backstop.
    let temp_dir = tempfile::tempdir().unwrap();
    let root = temp_dir.path().canonicalize().unwrap();
    std::fs::create_dir(root.join("real")).unwrap();
    std::os::unix::fs::symlink("real", root.join("link")).unwrap();

    let state_path = root.join("link/state.json");
    let err = StateFile::default()
        .save_with_root(&state_path, root.to_str().unwrap())
        .unwrap_err();

    assert!(
        err.to_string().contains("symlink") || err.to_string().contains("escapes"),
        "expected a containment refusal, got: {err}"
    );
    // Nothing was written through the link.
    assert!(!root.join("real/state.json").exists());
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
fn platform_state_nixos_round_trips_through_json() {
    let section = PlatformState::NixOs {
        generation: Some("/nix/store/aaaa-nixos-system-host".to_string()),
        last_switch_warning: Some("switch skipped".to_string()),
    };
    let json = serde_json::to_string(&section).unwrap();
    // Internally tagged by `platform`, with the variant in snake_case.
    assert!(json.contains("\"platform\":\"nix_os\""));
    let back: PlatformState = serde_json::from_str(&json).unwrap();
    assert_eq!(section, back);
}

#[test]
fn platform_state_debian_family_round_trips_through_json() {
    let section = PlatformState::DebianFamily { family: None };
    let json = serde_json::to_string(&section).unwrap();
    assert!(json.contains("\"platform\":\"debian_family\""));
    let back: PlatformState = serde_json::from_str(&json).unwrap();
    assert_eq!(section, back);
}

// Pins the serde attributes of the `DebianFamily` section exactly, so a change
// to its tag, its field name, or the `skip_serializing_if` on `family` fails
// here instead of silently changing the wire format and every install's digest.
#[test]
fn debian_family_without_a_family_serialises_to_exactly_the_platform_tag() {
    let section = PlatformState::DebianFamily { family: None };
    assert_eq!(
        serde_json::to_string(&section).unwrap(),
        r#"{"platform":"debian_family"}"#
    );
}

#[test]
fn debian_family_serialises_the_recorded_family_after_the_tag() {
    assert_eq!(
        serde_json::to_string(&PlatformState::DebianFamily {
            family: Some(crate::Family::Fedora),
        })
        .unwrap(),
        r#"{"platform":"debian_family","family":"fedora"}"#
    );
    assert_eq!(
        serde_json::to_string(&PlatformState::DebianFamily {
            family: Some(crate::Family::Arch),
        })
        .unwrap(),
        r#"{"platform":"debian_family","family":"arch"}"#
    );
}

// The heart of the wire-format guarantee: a state file an earlier release wrote
// with a bare `debian_family` section re-serialises byte for byte, so its
// integrity digest is unchanged after the upgrade that added `family`.
#[test]
fn a_family_less_debian_family_section_re_serialises_byte_for_byte() {
    let before = r#"{"platform":"debian_family"}"#;
    let section: PlatformState = serde_json::from_str(before).unwrap();
    assert_eq!(section, PlatformState::DebianFamily { family: None });
    assert_eq!(serde_json::to_string(&section).unwrap(), before);
}

#[test]
fn mark_fhs_family_records_only_fedora_and_arch() {
    // Debian-family and unresolved hosts record no family, so their state file
    // stays `{"platform":"debian_family"}` and byte identical across the upgrade.
    for family in [None, Some(crate::Family::Debian)] {
        let mut state = StateFile::default();
        state.mark_fhs_family(family);
        assert_eq!(
            state.platform,
            Some(PlatformState::DebianFamily { family: None })
        );
        assert_eq!(state.family(), None);
    }

    // Fedora and Arch are kept, ready for when those families are admitted.
    for family in [crate::Family::Fedora, crate::Family::Arch] {
        let mut state = StateFile::default();
        state.mark_fhs_family(Some(family));
        assert_eq!(
            state.platform,
            Some(PlatformState::DebianFamily {
                family: Some(family)
            })
        );
        assert_eq!(state.family(), Some(family));
        assert!(!state.is_nixos());
    }
}

#[test]
fn mark_fhs_family_is_a_no_op_once_nixos_is_recorded() {
    let mut state = StateFile::default();
    state.set_nixos_generation(Some("gen-3".to_string()));
    state.mark_fhs_family(Some(crate::Family::Fedora));
    assert!(state.is_nixos());
    assert_eq!(state.hidden_toplevel(), Some("gen-3"));
    assert_eq!(state.family(), None);
}

#[test]
fn family_accessor_is_none_off_a_debian_family_section() {
    let mut state = StateFile::default();
    assert_eq!(state.family(), None);
    state.set_nixos_generation(Some("gen".to_string()));
    assert_eq!(state.family(), None);
}

#[test]
fn state_file_round_trips_each_platform_section() {
    for section in [
        None,
        Some(PlatformState::nixos(Some("gen-1".to_string()))),
        Some(PlatformState::DebianFamily { family: None }),
    ] {
        let state = StateFile {
            platform: section.clone(),
            ..StateFile::default()
        };
        let json = serde_json::to_string(&state).unwrap();
        let back: StateFile = serde_json::from_str(&json).unwrap();
        assert_eq!(state.platform, section);
        assert_eq!(back.platform, section);
    }
}

#[test]
fn state_file_platform_absent_defaults_to_none() {
    // A state file written without the field must still load (platform None).
    let json = r#"{
        "version": "0.2.0",
        "state": "Inactive",
        "overlay_status": {},
        "last_modified": "2025-01-27T10:30:00Z",
        "owner_pid": 0
    }"#;
    let state: StateFile = serde_json::from_str(json).unwrap();
    assert_eq!(state.platform, None);
    assert!(!state.is_nixos());
    assert_eq!(state.hidden_toplevel(), None);
    assert_eq!(state.last_switch_warning(), None);
}

#[test]
fn state_file_nixos_accessors_read_the_section() {
    let mut state = StateFile::default();
    state.set_nixos_generation(Some("gen-7".to_string()));
    assert!(state.is_nixos());
    assert_eq!(state.hidden_toplevel(), Some("gen-7"));

    // A None generation keeps the stored one and preserves the warning.
    state.set_switch_warning(Some("boom".to_string()));
    state.set_nixos_generation(None);
    assert_eq!(state.hidden_toplevel(), Some("gen-7"));
    assert_eq!(state.last_switch_warning(), Some("boom"));
}

#[test]
fn state_file_mark_debian_family_is_not_nixos_and_has_no_generation() {
    let mut state = StateFile::default();
    state.mark_debian_family();
    assert_eq!(
        state.platform,
        Some(PlatformState::DebianFamily { family: None })
    );
    assert!(!state.is_nixos());
    assert_eq!(state.hidden_toplevel(), None);
    assert_eq!(state.family(), None);

    // Once NixOS is recorded, marking Debian-family is a no-op.
    state.set_nixos_generation(Some("gen".to_string()));
    state.mark_debian_family();
    assert!(state.is_nixos());
}

#[test]
fn state_file_clear_platform_drops_the_section() {
    let mut state = StateFile::default();
    state.set_nixos_generation(Some("gen".to_string()));
    state.clear_platform();
    assert_eq!(state.platform, None);
    assert_eq!(state.hidden_toplevel(), None);
}

#[test]
fn saved_state_is_stamped_with_the_current_boot_id() {
    let _boot = super::file::test_boot_id::arm(Some("boot-a"));
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");
    StateFile::default()
        .save_with_root(&state_path, temp_dir.path().to_str().unwrap())
        .unwrap();
    assert_eq!(
        StateFile::load(&state_path).unwrap().boot_id.as_deref(),
        Some("boot-a")
    );
}

// ---------------------------------------------------------------------------
// Golden state files
//
// `src/state/golden/released/` holds the state files shipped releases write,
// captured verbatim. Each one was written by its release's own code, built
// from its tag: the `StateFile` steps that release's activation takes, up to
// the commit to Active, and the release's own save path, which stamps the
// digest (and, from 0.3.0, the boot id and the writer's pid). They are never
// regenerated, and their SHA-256 is pinned below so they cannot be rewritten
// in passing. The current code must load each one as its release left it,
// digest intact, and write it back byte for byte: a session that is running
// when NAILS is upgraded is then never read as corrupt. A change that fails
// here breaks real installs; change the code, not the file. A new release's
// file is added the same way, from its tag, never from the current code.
//
// The current-format files at the top of `src/state/golden/` record what no
// release has written yet (a Fedora or Arch family). They track the current
// serialiser and are regenerated after a deliberate format change with
// `REGENERATE_STATE_GOLDEN=1 cargo test -p nails-base regenerate_golden`,
// reading every diff.
// ---------------------------------------------------------------------------

/// The directory the committed golden state files live in.
fn golden_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/state/golden")
}

/// The frozen state files of shipped releases, with the SHA-256 of the bytes
/// the release wrote.
const RELEASED: &[(&str, &str)] = &[
    (
        "v0.2.0.json",
        "9744305551f0c55bb0a99c03d12a6df21270681e0a38bc95bf29e196b34c20a2", // pragma: allowlist secret
    ),
    (
        "v0.3.0-rc.2.json",
        "8dca2b4ee748cb46d8458cf28a002d6d234cb7a3538945df1e2e7e4893701d55", // pragma: allowlist secret
    ),
    (
        "v0.3.0-rc.3.json",
        "5fc4f74407a54396b8f9af642d257a9cab0cfa56834a6c47bc2e28b636625629", // pragma: allowlist secret
    ),
    (
        "v0.3.0-rc.3-nixos.json",
        "05b9b01aed5df6ae778123cc82e2cde34248f4e0ec0fbbf5e09e3b2f1775a66d", // pragma: allowlist secret
    ),
];

/// The bytes of a frozen release file.
fn released(name: &str) -> String {
    std::fs::read_to_string(golden_dir().join("released").join(name))
        .unwrap_or_else(|e| panic!("reading released {name}: {e}"))
}

/// Load `bytes` through the real load path, from a state file of their own.
fn load_bytes(bytes: &str) -> LoadResult {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    std::fs::write(&path, bytes).unwrap();
    StateFile::load_with_outcome(&path).unwrap()
}

/// The current-format golden files: `(file name, the state they record)`.
///
/// Only the Fedora and Arch records: no release has written a family yet, so
/// they track the current serialiser. The Debian-family and NixOS records are
/// the frozen release files.
fn current_format_goldens() -> Vec<(&'static str, StateFile)> {
    let activated_at = DateTime::parse_from_rfc3339("2026-05-10T08:15:30Z")
        .unwrap()
        .with_timezone(&Utc);
    let finished_at = DateTime::parse_from_rfc3339("2026-05-10T08:15:33Z")
        .unwrap()
        .with_timezone(&Utc);
    let last_modified = finished_at;
    let with_family = move |family: crate::Family| StateFile {
        version: "0.3.0".to_string(),
        state: SystemState::Active { activated_at },
        platform: Some(PlatformState::DebianFamily {
            family: Some(family),
        }),
        config_fingerprint: None,
        decoy_system: None,
        last_activation: Some(LastActivation {
            duration_ms: 3210,
            finished_at,
        }),
        last_modified,
        boot_id: Some("7c9e6679-7425-40de-944b-e07fc1f90ae7".to_string()),
        owner_pid: 4242,
        owner_start_time: Some(987654),
        integrity_sha256: None,
    };
    vec![
        ("fedora.json", with_family(crate::Family::Fedora)),
        ("arch.json", with_family(crate::Family::Arch)),
    ]
}

/// Serialise `state` exactly as [`StateFile::save`] writes it: body first, then
/// a stamped integrity digest, pretty-printed, with a trailing newline for the
/// repository's end-of-file convention (the binary's own on-disk write omits
/// it, but that whitespace is outside the digest and the parser ignores it).
fn golden_bytes(state: &StateFile) -> String {
    let mut body = state.clone();
    body.integrity_sha256 = None;
    body.integrity_sha256 = Some(super::file::compute_integrity(&body).unwrap());
    format!("{}\n", serde_json::to_string_pretty(&body).unwrap())
}

/// Rewrite the current-format golden files in place. A no-op unless
/// `REGENERATE_STATE_GOLDEN` is set, so the normal test run never touches the
/// working tree. The released files are never written.
#[test]
fn regenerate_golden_state_files() {
    if std::env::var_os("REGENERATE_STATE_GOLDEN").is_none() {
        return;
    }
    for (name, state) in current_format_goldens() {
        std::fs::write(golden_dir().join(name), golden_bytes(&state)).unwrap();
    }
}

/// The committed current-format files are exactly what the current serialiser
/// writes, so a format change that was not regenerated (and reviewed) is caught.
#[test]
fn current_format_golden_files_are_fresh() {
    for (name, state) in current_format_goldens() {
        let committed = std::fs::read_to_string(golden_dir().join(name))
            .unwrap_or_else(|e| panic!("reading golden {name}: {e}"));
        assert_eq!(
            committed,
            golden_bytes(&state),
            "golden {name} is stale; regenerate with REGENERATE_STATE_GOLDEN=1"
        );
    }
}

/// Every current-format golden loads clean (its integrity digest still
/// verifies), re-serialises byte for byte, and keeps its recorded family.
#[test]
fn every_current_format_golden_loads_and_re_serialises_byte_for_byte() {
    for (name, state) in current_format_goldens() {
        let committed = std::fs::read_to_string(golden_dir().join(name)).unwrap();

        let parsed: StateFile = serde_json::from_str(&committed)
            .unwrap_or_else(|e| panic!("parsing golden {name}: {e}"));
        assert_eq!(parsed.platform, state.platform, "{name} platform changed");
        assert_eq!(
            format!("{}\n", serde_json::to_string_pretty(&parsed).unwrap()),
            committed,
            "re-serialising {name} changed its bytes"
        );

        let result = load_bytes(&committed);
        assert_eq!(
            result.outcome,
            LoadOutcome::Loaded,
            "{name} did not load clean"
        );
        assert_eq!(result.state_file.family(), state.family(), "{name} family");
    }
}

/// The released files are the bytes their releases wrote, unchanged: no
/// regeneration, formatter or hand edit has touched them since they were
/// captured.
#[test]
fn the_released_state_files_are_frozen() {
    use sha2::Digest;
    let mut on_disk: Vec<String> = std::fs::read_dir(golden_dir().join("released"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    on_disk.sort();
    let mut pinned: Vec<String> = RELEASED.iter().map(|(name, _)| name.to_string()).collect();
    pinned.sort();
    assert_eq!(
        on_disk, pinned,
        "every released file is pinned, and only those"
    );
    for (name, sha256) in RELEASED {
        let digest = hex::encode(sha2::Sha256::digest(released(name).as_bytes()));
        assert_eq!(
            digest, *sha256,
            "released {name} changed; it is a capture of a shipped release and must stay as \
             written"
        );
    }
}

/// Every 0.3.0 pre-release file loads clean through the real load path, with
/// its integrity digest intact, reads back as the active session its release
/// recorded, and is written back byte for byte: an install upgraded during a
/// session is never read as corrupt or as another session.
#[test]
fn every_released_state_file_loads_and_is_written_back_byte_for_byte() {
    let nixos_generation = "/nix/store/00000000000000000000000000000000-nixos-system-hidden-26.05";
    for (name, version, platform) in [
        (
            "v0.3.0-rc.2.json",
            "0.3.0-rc.2",
            PlatformState::DebianFamily { family: None },
        ),
        (
            "v0.3.0-rc.3.json",
            "0.3.0-rc.3",
            PlatformState::DebianFamily { family: None },
        ),
        (
            "v0.3.0-rc.3-nixos.json",
            "0.3.0-rc.3",
            PlatformState::nixos(Some(nixos_generation.to_string())),
        ),
    ] {
        let committed = released(name);
        let result = load_bytes(&committed);
        assert_eq!(
            result.outcome,
            LoadOutcome::Loaded,
            "{name} did not load clean"
        );
        let state = result.state_file;
        assert_eq!(state.version, version, "{name}");
        assert!(
            matches!(state.state, SystemState::Active { .. }),
            "{name}: {:?}",
            state.state
        );
        assert_eq!(state.platform, Some(platform), "{name} platform");
        assert_eq!(state.family(), None, "{name} family");
        assert!(state.last_activation.is_some(), "{name} last activation");
        assert!(state.boot_id.is_some(), "{name} boot id");

        // Written back by the current serialiser, as `save` writes it: the
        // same bytes, digest included.
        assert_eq!(
            serde_json::to_string_pretty(&state).unwrap(),
            committed,
            "writing {name} back changed its bytes"
        );
    }
}

/// A v0.2.0 state file predates the typed platform section and the integrity
/// digest, so the current reader cannot verify it. Even though it records an
/// active session, it must collapse to the safe inactive default and report the
/// state as unknown — never trust a format it cannot read, never error, never
/// panic. The live session probe is authoritative in that case, so an upgrade
/// from v0.2.0 never mis-reads an active decoy as clean.
#[test]
fn a_v0_2_0_state_file_degrades_safely_to_the_inactive_default() {
    let committed = released("v0.2.0.json");
    assert!(
        committed.contains("\"Active\""),
        "the capture records a session"
    );

    let result = load_bytes(&committed);
    assert!(
        result.outcome.is_unknown(),
        "v0.2.0 should read as unknown, got {:?}",
        result.outcome
    );
    assert_eq!(result.state_file.state, SystemState::Inactive);
    assert_eq!(result.state_file.platform, None);
    assert_eq!(result.state_file.family(), None);
}
