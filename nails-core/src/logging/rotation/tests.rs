use super::*;
use crate::MockFilesystem;
use std::path::PathBuf;

// ========================================================================
// rotate_logs() tests (AC #1, #2)
// ========================================================================

#[test]
fn test_rotate_logs_no_op_when_under_size_limit() {
    let log_path = PathBuf::from("/mnt/hidden/logs");
    let fs = MockFilesystem::new();

    // Set up log file under the limit (10MB)
    fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
    fs.mock_set_file_size("/mnt/hidden/logs/nails.log", 5_000_000); // 5MB

    let result = rotate_logs(
        &log_path,
        DEFAULT_MAX_LOG_SIZE_MB,
        DEFAULT_RETENTION_DAYS,
        &fs,
    );
    assert!(result.is_ok(), "Rotation should succeed (no-op)");

    // File should still exist and not be rotated
    assert!(
        fs.path_exists(Path::new("/mnt/hidden/logs/nails.log"))
            .unwrap()
    );
}

#[test]
fn test_rotate_logs_rotates_when_exceeds_size_limit() {
    let log_path = PathBuf::from("/mnt/hidden/logs");
    let fs = MockFilesystem::new();

    // Set up log file that exceeds the limit (10MB)
    fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
    fs.mock_set_file_size("/mnt/hidden/logs/nails.log", 11_000_000); // 11MB
    fs.mock_set_file_content("/mnt/hidden/logs/nails.log", "log data");

    // Set up log directory for enforce_retention to list
    fs.mock_set_path_exists("/mnt/hidden/logs", true);
    fs.mock_set_path_type("/mnt/hidden/logs", "directory");
    fs.mock_set_directory_contents(
        &PathBuf::from("/mnt/hidden/logs"),
        vec![PathBuf::from("/mnt/hidden/logs/nails.log")],
    );

    let result = rotate_logs(
        &log_path,
        DEFAULT_MAX_LOG_SIZE_MB,
        DEFAULT_RETENTION_DAYS,
        &fs,
    );
    assert!(result.is_ok(), "Rotation should succeed");

    // Original should have been renamed to .1
    assert!(
        fs.path_exists(Path::new("/mnt/hidden/logs/nails.log.1"))
            .unwrap()
    );

    // New empty file should exist at original location
    assert!(
        fs.path_exists(Path::new("/mnt/hidden/logs/nails.log"))
            .unwrap()
    );

    // New file should be empty
    let content = fs
        .read_file_content(Path::new("/mnt/hidden/logs/nails.log"))
        .unwrap();
    assert_eq!(content, "");
}

#[test]
fn test_rotate_logs_shifts_existing_numbered_logs() {
    let log_path = PathBuf::from("/mnt/hidden/logs");
    let fs = MockFilesystem::new();

    // Set up current log exceeding limit
    fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
    fs.mock_set_file_size("/mnt/hidden/logs/nails.log", 11_000_000);
    fs.mock_set_file_content("/mnt/hidden/logs/nails.log", "current");

    // Set up existing numbered logs
    fs.mock_set_path_exists("/mnt/hidden/logs/nails.log.1", true);
    fs.mock_set_file_content("/mnt/hidden/logs/nails.log.1", "old1");

    fs.mock_set_path_exists("/mnt/hidden/logs/nails.log.2", true);
    fs.mock_set_file_content("/mnt/hidden/logs/nails.log.2", "old2");

    // Set up log directory for enforce_retention
    fs.mock_set_path_exists("/mnt/hidden/logs", true);
    fs.mock_set_path_type("/mnt/hidden/logs", "directory");
    fs.mock_set_directory_contents(
        &PathBuf::from("/mnt/hidden/logs"),
        vec![
            PathBuf::from("/mnt/hidden/logs/nails.log"),
            PathBuf::from("/mnt/hidden/logs/nails.log.1"),
            PathBuf::from("/mnt/hidden/logs/nails.log.2"),
        ],
    );

    let result = rotate_logs(
        &log_path,
        DEFAULT_MAX_LOG_SIZE_MB,
        DEFAULT_RETENTION_DAYS,
        &fs,
    );
    assert!(result.is_ok());

    // Check that logs were shifted
    assert_eq!(
        fs.read_file_content(Path::new("/mnt/hidden/logs/nails.log.1"))
            .unwrap(),
        "current"
    );
    assert_eq!(
        fs.read_file_content(Path::new("/mnt/hidden/logs/nails.log.2"))
            .unwrap(),
        "old1"
    );
    assert_eq!(
        fs.read_file_content(Path::new("/mnt/hidden/logs/nails.log.3"))
            .unwrap(),
        "old2"
    );

    // New empty log at original location
    assert_eq!(
        fs.read_file_content(Path::new("/mnt/hidden/logs/nails.log"))
            .unwrap(),
        ""
    );
}

#[test]
fn test_rotate_logs_handles_nonexistent_log_file() {
    let log_path = PathBuf::from("/mnt/hidden/logs");
    let fs = MockFilesystem::new();

    // No log file exists yet (first run scenario)
    fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", false);

    let result = rotate_logs(
        &log_path,
        DEFAULT_MAX_LOG_SIZE_MB,
        DEFAULT_RETENTION_DAYS,
        &fs,
    );
    // Should return error since there's no file to check size of
    assert!(result.is_err());
}

// ========================================================================
// enforce_retention() tests (AC #3)
// ========================================================================

#[test]
fn test_enforce_retention_deletes_old_numbered_logs() {
    let log_path = PathBuf::from("/mnt/hidden/logs");
    let fs = MockFilesystem::new();

    // Set up log directory with files beyond retention (7 days)
    fs.mock_set_path_exists("/mnt/hidden/logs", true);
    fs.mock_set_path_type("/mnt/hidden/logs", "directory");

    let now = chrono::Utc::now();

    // Create logs: .1 through .10
    // Logs 8-10 are 8-10 days old (should be deleted)
    // Logs 1-7 are recent (should be kept)
    let mut dir_contents = vec![];
    for i in 1..=10 {
        let path = format!("/mnt/hidden/logs/nails.log.{}", i);
        fs.mock_set_path_exists(&path, true);
        dir_contents.push(PathBuf::from(&path));

        // Set modification time: logs 8-10 are old
        if i >= 8 {
            let old_time = now - chrono::Duration::days(i as i64);
            fs.mock_set_modified_time(Path::new(&path), old_time);
        }
    }
    fs.mock_set_directory_contents(&PathBuf::from("/mnt/hidden/logs"), dir_contents);

    let result = enforce_retention(&log_path, DEFAULT_RETENTION_DAYS, &fs);
    assert!(result.is_ok());

    // Logs 1-7 should still exist (they're recent)
    for i in 1..=7 {
        assert!(
            fs.path_exists(Path::new(&format!("/mnt/hidden/logs/nails.log.{}", i)))
                .unwrap()
        );
    }

    // Logs 8-10 should be deleted (they're old)
    for i in 8..=10 {
        assert!(
            !fs.path_exists(Path::new(&format!("/mnt/hidden/logs/nails.log.{}", i)))
                .unwrap()
        );
    }
}

#[test]
fn test_enforce_retention_handles_no_old_logs() {
    let log_path = PathBuf::from("/mnt/hidden/logs");
    let fs = MockFilesystem::new();

    // Set up log directory with only recent logs (within retention)
    fs.mock_set_path_exists("/mnt/hidden/logs", true);
    fs.mock_set_path_type("/mnt/hidden/logs", "directory");

    let mut dir_contents = vec![];
    for i in 1..=5 {
        let path = format!("/mnt/hidden/logs/nails.log.{}", i);
        fs.mock_set_path_exists(&path, true);
        dir_contents.push(PathBuf::from(&path));
    }
    fs.mock_set_directory_contents(&PathBuf::from("/mnt/hidden/logs"), dir_contents);

    let result = enforce_retention(&log_path, DEFAULT_RETENTION_DAYS, &fs);
    assert!(result.is_ok());

    // All logs should still exist (none deleted)
    for i in 1..=5 {
        assert!(
            fs.path_exists(Path::new(&format!("/mnt/hidden/logs/nails.log.{}", i)))
                .unwrap()
        );
    }
}

// ========================================================================
// should_rotate() tests (AC #1)
// ========================================================================

#[test]
fn test_should_rotate_returns_true_when_exceeds_limit() {
    let log_path = PathBuf::from("/mnt/hidden/logs");
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
    fs.mock_set_file_size("/mnt/hidden/logs/nails.log", 11_000_000); // 11MB > 10MB

    let result = should_rotate(&log_path, DEFAULT_MAX_LOG_SIZE_MB, &fs);
    assert!(result.is_ok());
    assert!(result.unwrap(), "Should rotate when file exceeds limit");
}

#[test]
fn test_should_rotate_returns_false_when_under_limit() {
    let log_path = PathBuf::from("/mnt/hidden/logs");
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
    fs.mock_set_file_size("/mnt/hidden/logs/nails.log", 5_000_000); // 5MB < 10MB

    let result = should_rotate(&log_path, DEFAULT_MAX_LOG_SIZE_MB, &fs);
    assert!(result.is_ok());
    assert!(
        !result.unwrap(),
        "Should not rotate when file is under limit"
    );
}

#[test]
fn test_should_rotate_handles_exact_limit() {
    let log_path = PathBuf::from("/mnt/hidden/logs");
    let fs = MockFilesystem::new();

    fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
    fs.mock_set_file_size("/mnt/hidden/logs/nails.log", 10_485_760); // Exactly 10MB

    let result = should_rotate(&log_path, DEFAULT_MAX_LOG_SIZE_MB, &fs);
    assert!(result.is_ok());
    assert!(
        !result.unwrap(),
        "Should not rotate when file equals limit (uses > not >=)"
    );
}

#[test]
fn test_should_rotate_handles_missing_file() {
    let log_path = PathBuf::from("/mnt/hidden/logs");
    let fs = MockFilesystem::new();

    // File doesn't exist
    fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", false);

    let result = should_rotate(&log_path, DEFAULT_MAX_LOG_SIZE_MB, &fs);
    assert!(result.is_err(), "Should return error for missing file");
}

// ========================================================================
// Overflow safety tests (AC #6)
// ========================================================================

#[test]
fn test_rotation_uses_checked_mul_for_size_calculation() {
    let log_path = PathBuf::from("/mnt/hidden/logs");
    let fs = MockFilesystem::new();

    // Create a normal sized file
    fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
    fs.mock_set_file_size("/mnt/hidden/logs/nails.log", 1_000_000); // 1MB

    // Use a max_log_size_mb that will overflow when converted to bytes
    let max_size_mb = (u64::MAX / 1024 / 1024) + 1;

    // This should not panic due to overflow
    let result = should_rotate(&log_path, max_size_mb, &fs);
    assert!(result.is_ok());
    // With overflow protection, threshold becomes u64::MAX, so rotation doesn't trigger
    // (effectively treating the limit as "infinite")
    assert!(
        !result.unwrap(),
        "Overflow should result in no rotation (threshold = MAX)"
    );
}

// ========================================================================
// Permission denied tests (AC #4)
// ========================================================================

#[test]
fn test_rotate_logs_handles_permission_denied_on_rename() {
    let log_path = PathBuf::from("/mnt/hidden/logs");
    let fs = MockFilesystem::new();

    // Set up log file exceeding limit
    fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
    fs.mock_set_file_size("/mnt/hidden/logs/nails.log", 11_000_000); // 11MB > 10MB

    // Configure rename to fail with permission denied
    fs.mock_set_rename_should_fail("/mnt/hidden/logs/nails.log", true);

    // Set up log directory
    fs.mock_set_path_exists("/mnt/hidden/logs", true);
    fs.mock_set_path_type("/mnt/hidden/logs", "directory");
    fs.mock_set_directory_contents(
        &PathBuf::from("/mnt/hidden/logs"),
        vec![PathBuf::from("/mnt/hidden/logs/nails.log")],
    );

    let result = rotate_logs(
        &log_path,
        DEFAULT_MAX_LOG_SIZE_MB,
        DEFAULT_RETENTION_DAYS,
        &fs,
    );
    // Should fail due to permission denied
    assert!(result.is_err());

    // Verify warning was logged (we can't easily check tracing logs in unit tests,
    // but we verify the error propagation works correctly)
}
