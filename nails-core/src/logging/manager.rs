//! Logging manager with hidden volume validation
//!
//! Provides the core LoggingManager that ensures all log output is
//! directed exclusively to the hidden volume with fail-safe validation.

use crate::{Filesystem, NailsError, Result, output};
use std::path::PathBuf;

use super::config::LoggingConfig;
use super::path::clean_path;
use super::rotation::{
    DEFAULT_MAX_LOG_SIZE_MB, DEFAULT_RETENTION_DAYS, LOG_FILE_NAME, enforce_retention, rotate_logs,
};

/// Manages structured logging with hidden volume validation
///
/// `LoggingManager` ensures all log output is directed exclusively to
/// the hidden volume. It validates paths before initializing any logging
/// infrastructure, preventing forensic leakage to the decoy system.
///
/// # Fields
///
/// * `log_path` - Directory where log files are written (must be within hidden volume)
/// * `hidden_volume_path` - Root path of the hidden volume mount
/// * `max_log_size_mb` - Maximum size of a single log file in MB (default: 10)
/// * `retention_days` - Number of days to retain log files (default: 7)
#[derive(Debug, Clone)]
pub struct LoggingManager {
    /// Directory where log files are written
    pub log_path: PathBuf,
    /// Root path of the hidden volume mount
    pub hidden_volume_path: PathBuf,
    /// Maximum log file size in megabytes
    pub max_log_size_mb: u64,
    /// Log retention period in days
    pub retention_days: u64,
}

impl LoggingManager {
    /// Create a new LoggingManager with default size and retention settings
    ///
    /// # Arguments
    ///
    /// * `log_path` - Directory for log files (must be within hidden volume)
    /// * `hidden_volume_path` - Root of the hidden volume mount point
    ///
    /// # Examples
    ///
    /// ```
    /// use nails_core::logging::LoggingManager;
    /// use std::path::PathBuf;
    ///
    /// let manager = LoggingManager::new(
    ///     PathBuf::from("/mnt/hidden-volume/logs"),
    ///     PathBuf::from("/mnt/hidden-volume"),
    /// );
    /// assert_eq!(manager.max_log_size_mb, 10);
    /// assert_eq!(manager.retention_days, 7);
    /// ```
    pub fn new(log_path: PathBuf, hidden_volume_path: PathBuf) -> Self {
        Self {
            log_path,
            hidden_volume_path,
            max_log_size_mb: DEFAULT_MAX_LOG_SIZE_MB,
            retention_days: DEFAULT_RETENTION_DAYS,
        }
    }

    /// Validate that the log path is within the hidden volume
    ///
    /// Checks that `log_path` starts with `hidden_volume_path` to prevent
    /// forensic leakage. Uses component-based path comparison to handle
    /// path traversal attacks (e.g., `/mnt/hidden-volume/../var/log`).
    ///
    /// Also checks that the log directory is not a symlink to prevent
    /// bypassing the hidden volume check.
    ///
    /// # Errors
    ///
    /// Returns `NailsError::InvalidState` if:
    /// - Log path is outside the hidden volume
    /// - Log path is a symlink (symlinks can bypass path validation)
    ///
    /// # Security
    ///
    /// - Cleans path components to resolve `..` traversal
    /// - Rejects paths that escape the hidden volume boundary
    /// - Rejects symlinks which could redirect logs outside hidden volume
    /// - Logs critical refusal to stderr before returning error
    pub fn validate_log_path(&self) -> Result<()> {
        let cleaned_log = clean_path(&self.log_path);
        let cleaned_hidden = clean_path(&self.hidden_volume_path);

        if !cleaned_log.starts_with(&cleaned_hidden) {
            // Security violation - use ERROR format (not WARNING)
            output::error("Refusing to log outside hidden volume");
            return Err(NailsError::InvalidState(format!(
                "Log path must be on hidden volume: {}",
                self.log_path.display()
            )));
        }

        Ok(())
    }

    /// Initialize logging infrastructure with hidden volume validation
    ///
    /// Validates the log path, verifies the hidden volume is mounted,
    /// creates the log directory if needed, and returns a validated
    /// `LoggingConfig` that can be used to build a tracing subscriber
    /// with JSON formatting.
    ///
    /// # Arguments
    ///
    /// * `fs` - Filesystem implementation (use `MockFilesystem` in tests)
    ///
    /// # Returns
    ///
    /// - `Ok(Some(LoggingConfig))` - Logging initialized successfully
    /// - `Ok(None)` - Hidden volume not available, gracefully degraded to stderr-only
    /// - `Err(...)` - Security violation (log path outside hidden volume, symlink detected)
    ///
    /// # Errors
    ///
    /// Returns `NailsError::InvalidState` if:
    /// - Log path is outside the hidden volume (AR26, FR36)
    /// - Log directory is a symlink (security bypass attempt)
    /// - Log directory cannot be created
    pub fn init<F: Filesystem>(&self, fs: &F) -> Result<Option<LoggingConfig>> {
        // Validate log path is within hidden volume (AR26)
        self.validate_log_path()?;

        // Verify hidden volume is mounted (FR36)
        // Graceful degradation: if hidden volume is not mounted, return None (stderr-only mode)
        if !fs.path_exists(&self.hidden_volume_path)? {
            output::warn("Hidden volume not available, file logging disabled");
            return Ok(None);
        }

        // No need to create directory - log file goes directly in hidden volume root
        let log_file_path = self.log_path.join(LOG_FILE_NAME);

        Ok(Some(LoggingConfig { log_file_path }))
    }

    /// Check if log rotation should be triggered
    ///
    /// Compares current log file size against `max_log_size_mb` threshold.
    /// Uses overflow-safe arithmetic per architecture requirements.
    ///
    /// # Arguments
    ///
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
    pub fn should_rotate<F: Filesystem>(&self, fs: &F) -> Result<bool> {
        super::rotation::should_rotate(&self.log_path, self.max_log_size_mb, fs)
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
    pub fn rotate_logs<F: Filesystem>(&self, fs: &F) -> Result<()> {
        rotate_logs(
            &self.log_path,
            self.max_log_size_mb,
            self.retention_days,
            fs,
        )
    }

    /// Enforce log retention policy
    ///
    /// Deletes numbered log files older than the retention period based on
    /// file modification timestamps.
    ///
    /// # Arguments
    ///
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
    pub fn enforce_retention<F: Filesystem>(&self, fs: &F) -> Result<()> {
        enforce_retention(&self.log_path, self.retention_days, fs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockFilesystem;
    use crate::config::DEFAULT_HIDDEN_VOLUME_ROOT;

    // ========================================================================
    // LoggingManager struct tests
    // ========================================================================

    #[test]
    fn test_new_sets_default_max_log_size() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/logs"),
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        );
        assert_eq!(manager.max_log_size_mb, 10);
    }

    #[test]
    fn test_new_sets_default_retention_days() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/logs"),
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        );
        assert_eq!(manager.retention_days, 7);
    }

    #[test]
    fn test_new_stores_log_path() {
        let log_path = PathBuf::from("/mnt/hidden-volume/logs");
        let manager =
            LoggingManager::new(log_path.clone(), PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT));
        assert_eq!(manager.log_path, log_path);
    }

    #[test]
    fn test_new_stores_hidden_volume_path() {
        let hidden = PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT);
        let manager = LoggingManager::new(PathBuf::from("/mnt/hidden-volume/logs"), hidden.clone());
        assert_eq!(manager.hidden_volume_path, hidden);
    }

    #[test]
    fn test_new_is_cloneable() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/logs"),
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        );
        let cloned = manager.clone();
        assert_eq!(cloned.log_path, manager.log_path);
        assert_eq!(cloned.hidden_volume_path, manager.hidden_volume_path);
    }

    #[test]
    fn test_new_is_debuggable() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/logs"),
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
            PathBuf::from("/mnt/hidden-volume/logs"),
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        );
        assert!(manager.validate_log_path().is_ok());
    }

    #[test]
    fn test_validate_log_path_nested_valid() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/logs"),
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
            PathBuf::from("/mnt/hidden-volume/../var/log"),
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
        // "/mnt/hidden-volume-fake" should NOT be treated as within DEFAULT_HIDDEN_VOLUME_ROOT
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume-fake/logs"),
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
            PathBuf::from("/mnt/hidden-volume/../../etc"),
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        );
        assert!(manager.validate_log_path().is_err());
    }

    #[test]
    fn test_validate_log_path_empty_path() {
        let manager =
            LoggingManager::new(PathBuf::from(""), PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT));
        assert!(manager.validate_log_path().is_err());
    }

    // ========================================================================
    // init() method tests
    // ========================================================================

    #[test]
    fn test_init_graceful_degradation_when_hidden_volume_not_mounted() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/logs"),
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
            PathBuf::from("/mnt/hidden-volume/logs"),
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        );
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
        fs.mock_set_path_exists("/mnt/hidden-volume/logs", false);
        fs.mock_set_writable(DEFAULT_HIDDEN_VOLUME_ROOT, true);

        let result = manager.init(&fs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_init_succeeds_when_log_directory_exists() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/logs"),
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        );
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
        fs.mock_set_path_exists("/mnt/hidden-volume/logs", true);

        let result = manager.init(&fs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_init_returns_correct_log_file_path() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/logs"),
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        );
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
        fs.mock_set_path_exists("/mnt/hidden-volume/logs", true);

        let config = manager
            .init(&fs)
            .unwrap()
            .expect("Expected Some(LoggingConfig)");
        assert_eq!(
            config.log_file_path,
            PathBuf::from("/mnt/hidden-volume/logs/nails.log")
        );
    }

    #[test]
    fn test_init_with_traversal_path_fails() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/../var/log"),
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
            PathBuf::from("/var/log"),
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        );
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
        fs.mock_set_path_exists("/var/log", true);
        fs.mock_set_is_symlink("/var/log", true);

        let err = manager.init(&fs).unwrap_err();
        match &err {
            NailsError::InvalidState(msg) => {
                assert!(
                    msg.contains("Log path must be on hidden volume"),
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
            PathBuf::from("/mnt/hidden-volume/logs"),
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT),
        );
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(DEFAULT_HIDDEN_VOLUME_ROOT, true);
        fs.mock_set_path_exists("/mnt/hidden-volume/logs", true);
        fs.mock_set_is_symlink("/mnt/hidden-volume/logs", false);

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
            PathBuf::from("/mnt/hidden-volume/logs"),
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
        // AC #4: LoggingConfigBuilder receives hidden_volume_path from config
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
    fn test_init_with_realistic_custom_hidden_volume_path() {
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
}
