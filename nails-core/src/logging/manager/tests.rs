use super::*;
use crate::MockFilesystem;
use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;

// ========================================================================
// LoggingManager struct tests
// ========================================================================

#[test]
fn test_new_sets_default_max_log_size() {
    let manager = LoggingManager::new(
        PathBuf::from("/mnt/data/logs"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    assert_eq!(manager.max_log_size_mb, 10);
}

#[test]
fn test_new_sets_default_retention_days() {
    let manager = LoggingManager::new(
        PathBuf::from("/mnt/data/logs"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    assert_eq!(manager.retention_days, 7);
}

#[test]
fn test_new_stores_log_path() {
    let log_path = PathBuf::from("/mnt/data/logs");
    let manager = LoggingManager::new(log_path.clone(), PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT));
    assert_eq!(manager.log_path, log_path);
}

#[test]
fn test_new_stores_hidden_volume_root() {
    let hidden = PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT);
    let manager = LoggingManager::new(PathBuf::from("/mnt/data/logs"), hidden.clone());
    assert_eq!(manager.hidden_volume_root, hidden);
}

#[test]
fn test_new_is_cloneable() {
    let manager = LoggingManager::new(
        PathBuf::from("/mnt/data/logs"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    let cloned = manager.clone();
    assert_eq!(cloned.log_path, manager.log_path);
    assert_eq!(cloned.hidden_volume_root, manager.hidden_volume_root);
}

#[test]
fn test_new_is_debuggable() {
    let manager = LoggingManager::new(
        PathBuf::from("/mnt/data/logs"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    let debug_str = format!("{:?}", manager);
    assert!(debug_str.contains("LoggingManager"));
}

// ========================================================================
// Hidden volume path validation tests
// ========================================================================

#[test]
fn test_validate_log_path_valid() {
    let manager = LoggingManager::new(
        PathBuf::from("/mnt/data/logs"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    assert!(manager.validate_log_path().is_ok());
}

#[test]
fn test_validate_log_path_nested_valid() {
    let manager = LoggingManager::new(
        PathBuf::from("/mnt/data/logs"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    assert!(manager.validate_log_path().is_ok());
}

#[test]
fn test_validate_log_path_outside_hidden_volume() {
    let manager = LoggingManager::new(
        PathBuf::from("/var/log"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    let err = manager.validate_log_path().unwrap_err();
    match &err {
        NailsError::InvalidState(msg) => {
            assert!(msg.contains("Log path must be on hidden volume"));
            assert!(msg.contains("/var/log"));
        }
        _ => panic!("Expected InvalidState error, got: {:?}", err),
    }
}

#[test]
fn test_validate_log_path_traversal_attack() {
    let manager = LoggingManager::new(
        PathBuf::from("/mnt/data/../var/log"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    let err = manager.validate_log_path().unwrap_err();
    match &err {
        NailsError::InvalidState(msg) => {
            assert!(msg.contains("Log path must be on hidden volume"));
        }
        _ => panic!("Expected InvalidState error, got: {:?}", err),
    }
}

#[test]
fn test_validate_log_path_similar_prefix() {
    // "/mnt/data-fake" should NOT be treated as within DEFAULT_HIDDEN_VOLUME_ROOT
    let manager = LoggingManager::new(
        PathBuf::from("/mnt/data-fake/logs"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    let err = manager.validate_log_path().unwrap_err();
    match &err {
        NailsError::InvalidState(msg) => {
            assert!(msg.contains("Log path must be on hidden volume"));
        }
        _ => panic!("Expected InvalidState error, got: {:?}", err),
    }
}

#[test]
fn test_validate_log_path_exact_match() {
    // Log path equals hidden volume path - should be valid
    let manager = LoggingManager::new(
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    assert!(manager.validate_log_path().is_ok());
}

#[test]
fn test_validate_log_path_double_traversal() {
    let manager = LoggingManager::new(
        PathBuf::from("/mnt/data/../../etc"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    assert!(manager.validate_log_path().is_err());
}

#[test]
fn test_validate_log_path_empty_path() {
    let manager = LoggingManager::new(PathBuf::from(""), PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT));
    assert!(manager.validate_log_path().is_err());
}

// ========================================================================
// init() method tests
// ========================================================================

#[test]
fn test_init_graceful_degradation_when_hidden_volume_not_mounted() {
    let manager = LoggingManager::new(
        PathBuf::from("/mnt/data/logs"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    let fs = MockFilesystem::new();
    // hidden volume path does not exist in mock

    // Should return Ok(None) for graceful degradation, not an error
    let result = manager.init(&fs).unwrap();
    assert!(
        result.is_none(),
        "Expected None (graceful degradation) when hidden volume not mounted"
    );
}

#[test]
fn test_init_returns_none_when_root_shares_device_with_root_filesystem() {
    // The hidden root directory exists but sits on the same device as `/`, i.e.
    // nothing is mounted there. init() must degrade to stderr-only (Ok(None))
    // rather than writing logs onto the system disk.
    use std::path::Path;

    let manager = LoggingManager::new(
        PathBuf::from("/mnt/data/logs"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
    fs.mock_set_device_id(Path::new("/"), 1);
    fs.mock_set_device_id(Path::new(DEFAULT_HIDDEN_VOLUME_ROOT), 1);

    let result = manager.init(&fs).unwrap();
    assert!(
        result.is_none(),
        "Expected None (stderr-only) when the hidden root shares a device with /"
    );
}

#[test]
fn test_init_fails_when_path_outside_hidden_volume() {
    let manager = LoggingManager::new(
        PathBuf::from("/var/log"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);

    let err = manager.init(&fs).unwrap_err();
    match &err {
        NailsError::InvalidState(msg) => {
            assert!(msg.contains("Log path must be on hidden volume"));
        }
        _ => panic!("Expected InvalidState error, got: {:?}", err),
    }
}

#[test]
fn test_init_creates_log_directory_when_missing() {
    let manager = LoggingManager::new(
        PathBuf::from("/mnt/data/logs"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
    fs.mock_set_path_exists("/mnt/data/logs", false);
    fs.mock_set_writable(DEFAULT_HIDDEN_VOLUME_ROOT, true);

    let result = manager.init(&fs);
    assert!(result.is_ok());
    assert!(fs.path_exists(&PathBuf::from("/mnt/data/logs")).unwrap());
}

#[test]
fn test_init_succeeds_when_log_directory_exists() {
    let manager = LoggingManager::new(
        PathBuf::from("/mnt/data/logs"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
    fs.mock_set_path_exists("/mnt/data/logs", true);

    let result = manager.init(&fs);
    assert!(result.is_ok());
}

#[test]
fn test_init_returns_correct_log_file_path() {
    let manager = LoggingManager::new(
        PathBuf::from("/mnt/data/logs"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
    fs.mock_set_path_exists("/mnt/data/logs", true);

    let config = manager
        .init(&fs)
        .unwrap()
        .expect("Expected Some(LoggingConfig)");
    assert_eq!(
        config.log_file_path,
        PathBuf::from("/mnt/data/logs/nails.log")
    );
}

#[test]
fn test_init_with_traversal_path_fails() {
    let manager = LoggingManager::new(
        PathBuf::from("/mnt/data/../var/log"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);

    let err = manager.init(&fs).unwrap_err();
    match &err {
        NailsError::InvalidState(msg) => {
            assert!(msg.contains("Log path must be on hidden volume"));
        }
        _ => panic!("Expected InvalidState error, got: {:?}", err),
    }
}

// ========================================================================
// Symlink detection tests
// ========================================================================

#[test]
fn test_init_fails_when_log_path_is_symlink() {
    let manager = LoggingManager::new(
        PathBuf::from("/mnt/data/logs"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
    fs.mock_set_path_exists("/mnt/data/logs", true);
    fs.mock_set_is_symlink("/mnt/data/logs", true);

    let err = manager.init(&fs).unwrap_err();
    match &err {
        NailsError::InvalidState(msg) => {
            assert!(
                msg.contains("must not be a symlink"),
                "Expected error about log path, got: {}",
                msg
            );
        }
        _ => panic!("Expected InvalidState error, got: {:?}", err),
    }
}

#[test]
fn test_init_succeeds_when_path_is_not_symlink() {
    let manager = LoggingManager::new(
        PathBuf::from("/mnt/data/logs"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
    fs.mock_set_path_exists("/mnt/data/logs", true);
    fs.mock_set_is_symlink("/mnt/data/logs", false);

    let result = manager.init(&fs);
    assert!(result.is_ok());
}

// ========================================================================
// Configured path / graceful degradation tests
// ========================================================================

#[test]
fn test_init_respects_configured_path_no_false_positive() {
    // AC #1: When hidden volume IS mounted at a non-default path (e.g., /tmp),
    // no false "CRITICAL: Hidden volume not mounted" should occur
    let manager = LoggingManager::new(
        PathBuf::from("/tmp/logs"),
        PathBuf::from("/tmp"), // Non-default hidden volume path
    );
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/tmp", true);
    fs.mock_set_path_exists("/tmp/logs", true);

    let result = manager.init(&fs);
    assert!(result.is_ok(), "Should not fail with configured path /tmp");
    assert!(
        result.unwrap().is_some(),
        "Should return Some(LoggingConfig) when volume is mounted"
    );
}

#[test]
fn test_init_graceful_degradation_returns_ok_none() {
    // AC #3: When hidden volume is genuinely not mounted, graceful degradation
    // returns Ok(None) instead of an error
    let manager = LoggingManager::new(
        PathBuf::from("/mnt/data/logs"),
        PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
    );
    let fs = MockFilesystem::new();
    // hidden volume not mounted - no paths set

    let result = manager.init(&fs);
    assert!(
        result.is_ok(),
        "Graceful degradation should not return an error"
    );
    assert!(
        result.unwrap().is_none(),
        "Should return None (stderr-only mode)"
    );
}

#[test]
fn test_init_with_custom_hidden_volume_root() {
    // AC #4: LoggingConfigBuilder receives hidden_volume_root from config
    let custom_root = PathBuf::from("/mnt/custom-secret");
    let manager = LoggingManager::new(custom_root.join("logs"), custom_root.clone());
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/custom-secret", true);
    fs.mock_set_path_exists("/mnt/custom-secret/logs", true);

    let config = manager
        .init(&fs)
        .unwrap()
        .expect("Expected Some(LoggingConfig)");
    assert_eq!(
        config.log_file_path,
        PathBuf::from("/mnt/custom-secret/logs/nails.log")
    );
}

#[test]
fn test_init_with_realistic_custom_hidden_volume_root() {
    // Realistic scenario: user configures backup hidden volume path
    let custom_root = PathBuf::from("/mnt/backup-nails");
    let manager = LoggingManager::new(custom_root.join("logs"), custom_root.clone());
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/backup-nails", true);
    fs.mock_set_path_exists("/mnt/backup-nails/logs", true);

    let result = manager.init(&fs);
    assert!(result.is_ok(), "Should succeed with realistic custom path");
    assert!(
        result.unwrap().is_some(),
        "Should return Some(LoggingConfig) when volume is mounted"
    );
}

#[test]
fn test_should_rotate_delegates_to_rotation_helper() {
    let manager = LoggingManager {
        log_path: PathBuf::from("/mnt/data/logs"),
        hidden_volume_root: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        max_log_size_mb: 10,
        retention_days: 7,
    };
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/mnt/data/logs/nails.log", true);
    fs.mock_set_file_size("/mnt/data/logs/nails.log", 11_000_000);

    assert!(manager.should_rotate(&fs).unwrap());
}

#[test]
fn test_rotate_logs_delegates_to_rotation_helper() {
    let manager = LoggingManager {
        log_path: PathBuf::from("/mnt/data/logs"),
        hidden_volume_root: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        max_log_size_mb: 10,
        retention_days: 3,
    };
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/mnt/data/logs", true);
    fs.mock_set_path_type("/mnt/data/logs", "directory");
    fs.mock_set_path_exists("/mnt/data/logs/nails.log", true);
    fs.mock_set_file_size("/mnt/data/logs/nails.log", 11_000_000);
    fs.mock_set_file_content("/mnt/data/logs/nails.log", "current");
    fs.mock_set_path_exists("/mnt/data/logs/nails.log.1", true);
    fs.mock_set_file_content("/mnt/data/logs/nails.log.1", "older");
    fs.mock_set_directory_contents(
        &PathBuf::from("/mnt/data/logs"),
        vec![
            PathBuf::from("/mnt/data/logs/nails.log"),
            PathBuf::from("/mnt/data/logs/nails.log.1"),
        ],
    );

    manager.rotate_logs(&fs).unwrap();

    assert_eq!(
        fs.read_file_content(PathBuf::from("/mnt/data/logs/nails.log.1").as_path())
            .unwrap(),
        "current"
    );
    assert_eq!(
        fs.read_file_content(PathBuf::from("/mnt/data/logs/nails.log.2").as_path())
            .unwrap(),
        "older"
    );
    assert_eq!(
        fs.read_file_content(PathBuf::from("/mnt/data/logs/nails.log").as_path())
            .unwrap(),
        ""
    );
}

#[test]
fn test_enforce_retention_delegates_to_rotation_helper() {
    let manager = LoggingManager {
        log_path: PathBuf::from("/mnt/data/logs"),
        hidden_volume_root: PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        max_log_size_mb: 10,
        retention_days: 7,
    };
    let fs = MockFilesystem::new();
    let old_log = PathBuf::from("/mnt/data/logs/nails.log.8");
    let fresh_log = PathBuf::from("/mnt/data/logs/nails.log.1");

    fs.mock_set_path_exists("/mnt/data/logs", true);
    fs.mock_set_path_type("/mnt/data/logs", "directory");
    fs.mock_set_path_exists(old_log.to_str().unwrap(), true);
    fs.mock_set_path_exists(fresh_log.to_str().unwrap(), true);
    fs.mock_set_directory_contents(
        &PathBuf::from("/mnt/data/logs"),
        vec![fresh_log.clone(), old_log.clone()],
    );
    fs.mock_set_modified_time(&old_log, chrono::Utc::now() - chrono::Duration::days(10));

    manager.enforce_retention(&fs).unwrap();

    assert!(fs.path_exists(&fresh_log).unwrap());
    assert!(!fs.path_exists(&old_log).unwrap());
}
