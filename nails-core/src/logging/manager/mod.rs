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

        if fs.path_exists(&self.log_path)? {
            if fs.is_symlink(&self.log_path)? {
                return Err(NailsError::InvalidState(format!(
                    "Log path must not be a symlink: {}",
                    self.log_path.display()
                )));
            }
        } else {
            fs.create_directory(&self.log_path)?;
        }

        fs.set_permissions(&self.log_path, 0o700)?;

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
mod tests;
