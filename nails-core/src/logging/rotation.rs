//! Log file rotation and retention management
//!
//! Provides automatic log rotation based on file size limits and
//! enforcement of retention policies based on file age.

use crate::{Filesystem, Result};
use std::path::Path;

use super::path::is_permission_denied;

/// Default maximum log file size in megabytes
pub const DEFAULT_MAX_LOG_SIZE_MB: u64 = 10;

/// Default log retention period in days
pub const DEFAULT_RETENTION_DAYS: u64 = 7;

/// Log file name within the log directory
pub const LOG_FILE_NAME: &str = "nails.log";

/// Check if log rotation should be triggered
///
/// Compares current log file size against `max_log_size_mb` threshold.
/// Uses overflow-safe arithmetic per architecture requirements.
///
/// # Arguments
///
/// * `log_path` - Directory containing log files
/// * `max_log_size_mb` - Maximum log file size in megabytes
/// * `fs` - Filesystem implementation
///
/// # Returns
///
/// `Ok(true)` if file size exceeds threshold (rotation needed),
/// `Ok(false)` if file size is within limit.
///
/// # Errors
///
/// Returns `NailsError::IoError` if log file doesn't exist or cannot be accessed.
///
/// # Overflow Safety
///
/// Uses `checked_mul()` for size calculation. If multiplication overflows,
/// treats threshold as `u64::MAX` (effectively infinite - no rotation).
pub fn should_rotate<F: Filesystem>(log_path: &Path, max_log_size_mb: u64, fs: &F) -> Result<bool> {
    let log_file = log_path.join(LOG_FILE_NAME);
    let file_size = fs.file_size(&log_file)?;

    // Overflow-safe size calculation: MB to bytes
    let threshold = max_log_size_mb
        .checked_mul(1024)
        .and_then(|kb| kb.checked_mul(1024))
        .unwrap_or(u64::MAX);

    Ok(file_size > threshold)
}

/// Rotate log files when size limit is exceeded
///
/// Renames logs in sequence (reverse order to avoid overwriting):
/// - `nails.log.6` → `nails.log.7`
/// - `nails.log.5` → `nails.log.6`
/// - ...
/// - `nails.log.1` → `nails.log.2`
/// - `nails.log` → `nails.log.1`
///
/// Creates a new empty `nails.log` file after rotation.
/// Enforces retention policy after rotation completes.
///
/// # Arguments
///
/// * `log_path` - Directory containing log files
/// * `max_log_size_mb` - Maximum log file size in megabytes
/// * `retention_days` - Number of days to retain log files
/// * `fs` - Filesystem implementation
///
/// # Returns
///
/// `Ok(())` if rotation completed successfully or was not needed.
/// Continues on individual file errors (degraded but functional).
///
/// # Errors
///
/// Returns `NailsError::IoError` only if critical operations fail.
/// Individual rename/remove failures are logged but don't abort rotation.
///
/// # AC Compliance
///
/// - AC #1: No-op if size <= max_log_size_mb
/// - AC #2: Rotates in sequence, logs rotation event
/// - AC #3: Calls `enforce_retention()` after rotation
/// - AC #4: Logs warning on permission denied, continues with degraded functionality
pub fn rotate_logs<F: Filesystem>(
    log_path: &Path,
    max_log_size_mb: u64,
    retention_days: u64,
    fs: &F,
) -> Result<()> {
    // Check if rotation is needed (AC #1)
    match should_rotate(log_path, max_log_size_mb, fs) {
        Ok(false) => return Ok(()), // No-op
        Err(e) => {
            // Log warning but continue - logging still works to current file
            tracing::warn!("Failed to check log file size: {}", e);
            return Err(e);
        }
        Ok(true) => {} // Proceed with rotation
    }

    let log_file = log_path.join(LOG_FILE_NAME);
    #[allow(unused_assignments)]
    let mut rotation_completed = false;
    #[allow(unused_assignments)]
    let mut new_log_created = false;

    // Rotate numbered logs in REVERSE order (highest to lowest)
    // This prevents overwriting: .6 -> .7, .5 -> .6, etc.
    for i in (1..retention_days).rev() {
        let from = log_path.join(format!("{}.{}", LOG_FILE_NAME, i));
        let to = log_path.join(format!("{}.{}", LOG_FILE_NAME, i + 1));

        if fs.path_exists(&from).unwrap_or(false) {
            match fs.rename_file(&from, &to) {
                Ok(_) => {}
                Err(e) => {
                    // Check if this is a permission denied error
                    if is_permission_denied(&e) {
                        tracing::warn!(
                            "Log rotation failed: permission denied renaming {}",
                            from.display()
                        );
                    } else {
                        tracing::warn!(
                            "Failed to rename {} to {}: {}",
                            from.display(),
                            to.display(),
                            e
                        );
                    }
                    // Continue with other files (degraded but functional)
                }
            }
        }
    }

    // Rotate current log to .1
    let log_1 = log_path.join(format!("{}.1", LOG_FILE_NAME));
    match fs.rename_file(&log_file, &log_1) {
        Ok(_) => {
            rotation_completed = true;
        }
        Err(e) => {
            // Log specific permission denied message per AC #4
            if is_permission_denied(&e) {
                tracing::warn!(
                    "Log rotation failed: permission denied renaming {}",
                    log_file.display()
                );
            } else {
                tracing::warn!(
                    "Failed to rename {} to {}: {}",
                    log_file.display(),
                    log_1.display(),
                    e
                );
            }
            // Can't continue without moving current log
            return Err(e);
        }
    }

    // Create new empty log file
    match fs.write_file_content(&log_file, "") {
        Ok(_) => {
            new_log_created = true;
        }
        Err(e) => {
            if is_permission_denied(&e) {
                tracing::warn!("Log rotation failed: permission denied creating new log file",);
            } else {
                tracing::warn!(
                    "Failed to create new log file {}: {}",
                    log_file.display(),
                    e
                );
            }
            // Try to restore rotated log if new file creation failed
            let _ = fs.rename_file(&log_1, &log_file);
            return Err(e);
        }
    }

    // Only log rotation event if it actually completed (AC #2)
    if rotation_completed && new_log_created {
        tracing::info!("Rotated logs: nails.log -> nails.log.1");

        // Enforce retention policy (AC #3)
        let _ = enforce_retention(log_path, retention_days, fs);
    }

    Ok(())
}

/// Enforce log retention policy
///
/// Deletes numbered log files older than the retention period based on
/// file modification timestamps.
///
/// # Arguments
///
/// * `log_path` - Directory containing log files
/// * `retention_days` - Number of days to retain log files
/// * `fs` - Filesystem implementation
///
/// # Returns
///
/// `Ok(())` if retention enforcement succeeded.
///
/// # Errors
///
/// Returns `NailsError::IoError` if file metadata access or deletion fails.
///
/// # AC Compliance
///
/// - AC #3: Checks file modification timestamps
/// - AC #3: Deletes logs older than retention_days (default 7)
/// - AC #3: Logs each deletion with age information
pub fn enforce_retention<F: Filesystem>(
    log_path: &Path,
    retention_days: u64,
    fs: &F,
) -> Result<()> {
    // List all files in log directory
    let entries = fs.list_directory(log_path)?;

    let now = chrono::Utc::now();

    for entry in entries {
        // Check if filename matches pattern: nails.log.N
        if let Some(filename) = entry.file_name().and_then(|n| n.to_str())
            && filename.starts_with(&format!("{}.", LOG_FILE_NAME))
        {
            // Get file modification time
            match fs.modified_time(&entry) {
                Ok(modified) => {
                    // Calculate age in days
                    let duration = now.signed_duration_since(modified);
                    let age_days = duration.num_days();

                    // Delete if older than retention window
                    if age_days > retention_days as i64 {
                        match fs.remove_file(&entry) {
                            Ok(_) => {
                                tracing::info!(
                                    "Deleted old log: {} ({} days old)",
                                    filename,
                                    age_days
                                );
                            }
                            Err(e) => {
                                // Log deletion failure but continue with other files
                                tracing::warn!("Failed to delete old log {}: {}", filename, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    // Log error accessing metadata but continue with other files
                    tracing::warn!("Failed to get modification time for {}: {}", filename, e);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
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
}
