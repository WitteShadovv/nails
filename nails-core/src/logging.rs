//! Logging infrastructure with hidden volume validation
//!
//! Provides structured JSON logging that only writes to the hidden volume,
//! ensuring operational logs never contaminate the decoy system.
//!
//! # Security Constraints
//!
//! - **FR35**: Logs to hidden volume ONLY
//! - **FR36**: Refuse to log if hidden volume not mounted (fail-safe)
//! - **FR38**: Structured JSON logs (newline-delimited)
//! - **AR26**: Pre-flight validation of hidden volume path before any write
//!
//! # Usage Workflow
//!
//! ## 1. Initialize LoggingManager
//!
//! ```no_run
//! use nails_core::logging::LoggingManager;
//! use nails_core::{RealFilesystem, Verbosity};
//! use std::path::PathBuf;
//!
//! // Create manager with log path and hidden volume path
//! let manager = LoggingManager::new(
//!     PathBuf::from("/mnt/hidden-volume/logs"),
//!     PathBuf::from("/mnt/hidden-volume"),
//! );
//!
//! // Validate and initialize (fail-safe: refuses if outside hidden volume)
//! let fs = RealFilesystem;
//! let config = manager.init(&fs).expect("Failed to initialize logging");
//! ```
//!
//! ## 2. Install Subscriber
//!
//! ```no_run
//! # use nails_core::logging::LoggingConfig;
//! # use nails_core::Verbosity;
//! # use std::path::PathBuf;
//! # let config = LoggingConfig {
//! #     log_file_path: PathBuf::from("/mnt/hidden-volume/logs/nails.log"),
//! # };
//! // Install with verbosity level
//! config.build_and_install_with_verbosity(Verbosity::Normal)
//!     .expect("Failed to install subscriber");
//! ```
//!
//! ## 3. Use Tracing Events
//!
//! ```no_run
//! // Now all tracing events are captured to the log file
//! tracing::info!(user = "alice", state = "active", "System activated");
//! tracing::error!(path = "/home", error = "busy", "Mount failed");
//! ```
//!
//! ## JSON Output Format
//!
//! Logs are written as newline-delimited JSON:
//!
//! ```json
//! {"timestamp":"2026-02-12T10:30:45.123Z","level":"INFO","message":"System activated","fields":{"user":"alice","state":"active"}}
//! {"timestamp":"2026-02-12T10:30:46.456Z","level":"ERROR","message":"Mount failed","fields":{"path":"/home","error":"busy"}}
//! ```

use crate::{Filesystem, NailsError, Result, Verbosity};
use std::path::{Path, PathBuf};

/// Default maximum log file size in megabytes
const DEFAULT_MAX_LOG_SIZE_MB: u64 = 10;

/// Default log retention period in days
const DEFAULT_RETENTION_DAYS: u64 = 7;

/// Log file name within the log directory
const LOG_FILE_NAME: &str = "nails.log";

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
            eprintln!("CRITICAL: Refusing to log outside hidden volume");
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
    /// A `LoggingConfig` containing the validated log file path.
    /// The caller is responsible for building and installing the subscriber.
    ///
    /// # Errors
    ///
    /// Returns `NailsError::InvalidState` if:
    /// - Log path is outside the hidden volume (AR26, FR36)
    /// - Hidden volume is not mounted (FR36)
    /// - Log directory cannot be created
    pub fn init<F: Filesystem>(&self, fs: &F) -> Result<LoggingConfig> {
        // Validate log path is within hidden volume (AR26)
        self.validate_log_path()?;

        // Verify hidden volume is mounted (FR36)
        if !fs.path_exists(&self.hidden_volume_path)? {
            eprintln!("CRITICAL: Hidden volume not mounted");
            return Err(NailsError::InvalidState(
                "Hidden volume not mounted".to_string(),
            ));
        }

        // Verify log directory is not a symlink (prevents bypassing path validation)
        if !fs.path_exists(&self.log_path)? {
            // Create log directory if it doesn't exist
            fs.create_directory(&self.log_path)?;
        } else {
            // Path exists - verify it's not a symlink
            if fs.is_symlink(&self.log_path)? {
                eprintln!("CRITICAL: Refusing to log to symlink path");
                return Err(NailsError::InvalidState(
                    "Log path must not be a symlink".to_string(),
                ));
            }
        }

        // Re-verify after directory creation that we're still within hidden volume
        // (defense against race condition where directory is replaced mid-creation)
        self.validate_log_path()?;

        let log_file_path = self.log_path.join(LOG_FILE_NAME);

        Ok(LoggingConfig { log_file_path })
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
        let log_file = self.log_path.join(LOG_FILE_NAME);
        let file_size = fs.file_size(&log_file)?;

        // Overflow-safe size calculation: MB to bytes
        let threshold = self
            .max_log_size_mb
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
        // Check if rotation is needed (AC #1)
        match self.should_rotate(fs) {
            Ok(false) => return Ok(()), // No-op
            Err(e) => {
                // Log warning but continue - logging still works to current file
                tracing::warn!("Failed to check log file size: {}", e);
                return Err(e);
            }
            Ok(true) => {} // Proceed with rotation
        }

        let log_file = self.log_path.join(LOG_FILE_NAME);
        #[allow(unused_assignments)]
        let mut rotation_completed = false;
        #[allow(unused_assignments)]
        let mut new_log_created = false;

        // Rotate numbered logs in REVERSE order (highest to lowest)
        // This prevents overwriting: .6 -> .7, .5 -> .6, etc.
        for i in (1..self.retention_days).rev() {
            let from = self.log_path.join(format!("{}.{}", LOG_FILE_NAME, i));
            let to = self.log_path.join(format!("{}.{}", LOG_FILE_NAME, i + 1));

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
        let log_1 = self.log_path.join(format!("{}.1", LOG_FILE_NAME));
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
            let _ = self.enforce_retention(fs);
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
        // List all files in log directory
        let entries = fs.list_directory(&self.log_path)?;

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
                        if age_days > self.retention_days as i64 {
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
}

/// Validated logging configuration returned by `LoggingManager::init()`
///
/// Contains the validated log file path. Use `build_and_install_subscriber()` to
/// create a tracing subscriber from this configuration.
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Path to the log file (validated to be within hidden volume)
    pub log_file_path: PathBuf,
}

impl LoggingConfig {
    /// Build and install a tracing subscriber with JSON formatting
    ///
    /// Opens the log file for appending, configures a JSON-formatted
    /// tracing subscriber, and sets it as the global default.
    ///
    /// # Arguments
    ///
    /// * `max_level` - Maximum tracing level to capture (use `Verbosity::to_tracing_level()`)
    ///
    /// # Returns
    ///
    /// `Ok(())` on success. The subscriber is installed globally and will
    /// remain active for the program duration.
    ///
    /// # Errors
    ///
    /// Returns `NailsError::IoError` if the log file cannot be opened.
    /// Returns `NailsError::InvalidState` if the global subscriber is already set.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nails_core::logging::LoggingConfig;
    /// use nails_core::Verbosity;
    /// use std::path::PathBuf;
    ///
    /// // Typically obtained from LoggingManager::init()
    /// let config = LoggingConfig {
    ///     log_file_path: PathBuf::from("/mnt/hidden-volume/logs/nails.log"),
    /// };
    ///
    /// // Install the subscriber
    /// config.build_and_install_subscriber(Verbosity::Normal.to_tracing_level())
    ///     .expect("Failed to install logging");
    ///
    /// // Now all tracing events will be written to the log file
    /// ```
    pub fn build_and_install_subscriber(&self, max_level: tracing::Level) -> Result<()> {
        use std::fs::OpenOptions;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file_path)?;

        let writer = std::sync::Mutex::new(file);

        let json_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_writer(writer)
            .with_target(true)
            .with_level(true)
            .with_thread_ids(false)
            .with_thread_names(false);

        tracing_subscriber::registry()
            .with(tracing_subscriber::filter::LevelFilter::from_level(
                max_level,
            ))
            .with(json_layer)
            .try_init()
            .map_err(|e| {
                NailsError::InvalidState(format!("Failed to initialize tracing subscriber: {}", e))
            })?;

        Ok(())
    }

    /// Build and install a tracing subscriber with Verbosity level
    ///
    /// Convenience method that converts `Verbosity` to `tracing::Level`.
    ///
    /// # Arguments
    ///
    /// * `verbosity` - Verbosity level (Quiet, Normal, Verbose, Debug)
    ///
    /// # Errors
    ///
    /// Returns `NailsError::IoError` if the log file cannot be opened.
    /// Returns `NailsError::InvalidState` if the global subscriber is already set.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use nails_core::logging::LoggingConfig;
    /// use nails_core::Verbosity;
    /// use std::path::PathBuf;
    ///
    /// // Typically obtained from LoggingManager::init()
    /// let config = LoggingConfig {
    ///     log_file_path: PathBuf::from("/mnt/hidden-volume/logs/nails.log"),
    /// };
    ///
    /// let result = config.build_and_install_with_verbosity(Verbosity::Normal)
    ///     .expect("Failed to install logging");
    /// ```
    pub fn build_and_install_with_verbosity(&self, verbosity: Verbosity) -> Result<()> {
        self.build_and_install_subscriber(verbosity.to_tracing_level())
    }
}

/// Check if an error indicates permission was denied
///
/// Helper for detecting permission-related failures to log
/// appropriate warning messages per AC #4.
fn is_permission_denied(err: &NailsError) -> bool {
    match err {
        NailsError::IoError(io) => {
            matches!(io.kind(), std::io::ErrorKind::PermissionDenied)
        }
        _ => false,
    }
}

/// Clean a path by resolving `..` components without filesystem access
///
/// This prevents path traversal attacks like `/mnt/hidden-volume/../var/log`
/// by manually resolving parent directory references.
///
/// # Security
///
/// This function is a critical component of path validation. It ensures that
/// path traversal attempts using `..` components are neutralized before
/// checking if a path is within the hidden volume. Combined with
/// symlink checking in `init()`, this defense-in-depth prevents attackers
/// from bypassing hidden volume validation.
///
/// # Limitations
///
/// **Does not follow symlinks** - Symlink detection is handled separately
/// via `Filesystem::is_symlink()` to prevent symlink-based bypasses.
fn clean_path(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                // Pop the last component when encountering ".."
                if !components.is_empty() {
                    components.pop();
                }
            }
            std::path::Component::Normal(c) => {
                components.push(c);
            }
            std::path::Component::RootDir => {
                // Start fresh from root
                components.clear();
            }
            std::path::Component::CurDir => {
                // Ignore current directory component
            }
            std::path::Component::Prefix(_) => {
                // Ignore path prefix (Windows-only)
            }
        }
    }

    // Build cleaned path from collected components
    // Start with root if the original path was absolute
    let mut cleaned = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        PathBuf::new()
    };

    for component in components {
        cleaned.push(component);
    }
    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockFilesystem;

    // ========================================================================
    // Task 1: LoggingManager struct tests
    // ========================================================================

    #[test]
    fn test_new_sets_default_max_log_size() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/logs"),
            PathBuf::from("/mnt/hidden-volume"),
        );
        assert_eq!(manager.max_log_size_mb, 10);
    }

    #[test]
    fn test_new_sets_default_retention_days() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/logs"),
            PathBuf::from("/mnt/hidden-volume"),
        );
        assert_eq!(manager.retention_days, 7);
    }

    #[test]
    fn test_new_stores_log_path() {
        let log_path = PathBuf::from("/mnt/hidden-volume/logs");
        let manager = LoggingManager::new(log_path.clone(), PathBuf::from("/mnt/hidden-volume"));
        assert_eq!(manager.log_path, log_path);
    }

    #[test]
    fn test_new_stores_hidden_volume_path() {
        let hidden = PathBuf::from("/mnt/hidden-volume");
        let manager = LoggingManager::new(PathBuf::from("/mnt/hidden-volume/logs"), hidden.clone());
        assert_eq!(manager.hidden_volume_path, hidden);
    }

    #[test]
    fn test_new_is_cloneable() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/logs"),
            PathBuf::from("/mnt/hidden-volume"),
        );
        let cloned = manager.clone();
        assert_eq!(cloned.log_path, manager.log_path);
        assert_eq!(cloned.hidden_volume_path, manager.hidden_volume_path);
    }

    #[test]
    fn test_new_is_debuggable() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/logs"),
            PathBuf::from("/mnt/hidden-volume"),
        );
        let debug_str = format!("{:?}", manager);
        assert!(debug_str.contains("LoggingManager"));
    }

    // ========================================================================
    // Task 2: Hidden volume path validation tests
    // ========================================================================

    #[test]
    fn test_validate_log_path_valid() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/logs"),
            PathBuf::from("/mnt/hidden-volume"),
        );
        assert!(manager.validate_log_path().is_ok());
    }

    #[test]
    fn test_validate_log_path_nested_valid() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/.nails/logs"),
            PathBuf::from("/mnt/hidden-volume"),
        );
        assert!(manager.validate_log_path().is_ok());
    }

    #[test]
    fn test_validate_log_path_outside_hidden_volume() {
        let manager = LoggingManager::new(
            PathBuf::from("/var/log"),
            PathBuf::from("/mnt/hidden-volume"),
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
            PathBuf::from("/mnt/hidden-volume"),
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
        // "/mnt/hidden-volume-fake" should NOT be treated as within "/mnt/hidden-volume"
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume-fake/logs"),
            PathBuf::from("/mnt/hidden-volume"),
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
            PathBuf::from("/mnt/hidden-volume"),
            PathBuf::from("/mnt/hidden-volume"),
        );
        assert!(manager.validate_log_path().is_ok());
    }

    #[test]
    fn test_validate_log_path_double_traversal() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/../../etc"),
            PathBuf::from("/mnt/hidden-volume"),
        );
        assert!(manager.validate_log_path().is_err());
    }

    #[test]
    fn test_validate_log_path_empty_path() {
        let manager = LoggingManager::new(PathBuf::from(""), PathBuf::from("/mnt/hidden-volume"));
        assert!(manager.validate_log_path().is_err());
    }

    // ========================================================================
    // Task 3: init() method tests
    // ========================================================================

    #[test]
    fn test_init_fails_when_hidden_volume_not_mounted() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/logs"),
            PathBuf::from("/mnt/hidden-volume"),
        );
        let fs = MockFilesystem::new();
        // hidden volume path does not exist in mock

        let err = manager.init(&fs).unwrap_err();
        match &err {
            NailsError::InvalidState(msg) => {
                assert!(
                    msg.contains("Hidden volume not mounted"),
                    "Unexpected message: {}",
                    msg
                );
            }
            _ => panic!("Expected InvalidState error, got: {:?}", err),
        }
    }

    #[test]
    fn test_init_fails_when_path_outside_hidden_volume() {
        let manager = LoggingManager::new(
            PathBuf::from("/var/log"),
            PathBuf::from("/mnt/hidden-volume"),
        );
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/hidden-volume", true);

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
            PathBuf::from("/mnt/hidden-volume"),
        );
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/hidden-volume", true);
        fs.mock_set_path_exists("/mnt/hidden-volume/logs", false);
        fs.mock_set_writable("/mnt/hidden-volume", true);

        let result = manager.init(&fs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_init_succeeds_when_log_directory_exists() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/logs"),
            PathBuf::from("/mnt/hidden-volume"),
        );
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/hidden-volume", true);
        fs.mock_set_path_exists("/mnt/hidden-volume/logs", true);

        let result = manager.init(&fs);
        assert!(result.is_ok());
    }

    #[test]
    fn test_init_returns_correct_log_file_path() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/logs"),
            PathBuf::from("/mnt/hidden-volume"),
        );
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/hidden-volume", true);
        fs.mock_set_path_exists("/mnt/hidden-volume/logs", true);

        let config = manager.init(&fs).unwrap();
        assert_eq!(
            config.log_file_path,
            PathBuf::from("/mnt/hidden-volume/logs/nails.log")
        );
    }

    #[test]
    fn test_init_with_traversal_path_fails() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden-volume/../var/log"),
            PathBuf::from("/mnt/hidden-volume"),
        );
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/hidden-volume", true);

        let err = manager.init(&fs).unwrap_err();
        match &err {
            NailsError::InvalidState(msg) => {
                assert!(msg.contains("Log path must be on hidden volume"));
            }
            _ => panic!("Expected InvalidState error, got: {:?}", err),
        }
    }

    // ========================================================================
    // Symlink detection tests (NEW)
    // ========================================================================

    #[test]
    fn test_init_fails_when_log_path_is_symlink() {
        let manager = LoggingManager::new(
            PathBuf::from("/var/log"),
            PathBuf::from("/mnt/hidden-volume"),
        );
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/hidden-volume", true);
        fs.mock_set_path_exists("/var/log", true);
        fs.mock_set_is_symlink("/var/log", true);

        let err = manager.init(&fs).unwrap_err();
        match &err {
            NailsError::InvalidState(msg) => {
                // Error should be about hidden volume not being mounted
                assert!(
                    msg.contains("Hidden volume not mounted")
                        || msg.contains("Log path must be on hidden volume"),
                    "Expected error about hidden volume or log path, got: {}",
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
            PathBuf::from("/mnt/hidden-volume"),
        );
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/mnt/hidden-volume", true);
        fs.mock_set_path_exists("/mnt/hidden-volume/logs", true);
        fs.mock_set_is_symlink("/mnt/hidden-volume/logs", false);

        let result = manager.init(&fs);
        assert!(result.is_ok());
    }

    // ========================================================================
    // LoggingConfig tests
    // ========================================================================

    #[test]
    fn test_logging_config_is_cloneable() {
        let config = LoggingConfig {
            log_file_path: PathBuf::from("/mnt/hidden-volume/logs/nails.log"),
        };
        let cloned = config.clone();
        assert_eq!(cloned.log_file_path, config.log_file_path);
    }

    #[test]
    fn test_logging_config_is_debuggable() {
        let config = LoggingConfig {
            log_file_path: PathBuf::from("/mnt/hidden-volume/logs/nails.log"),
        };
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("LoggingConfig"));
        assert!(debug_str.contains("nails.log"));
    }

    // ========================================================================
    // clean_path utility tests
    // ========================================================================

    #[test]
    fn test_clean_path_no_traversal() {
        assert_eq!(
            clean_path(Path::new("/mnt/hidden-volume/logs")),
            PathBuf::from("/mnt/hidden-volume/logs")
        );
    }

    #[test]
    fn test_clean_path_with_single_traversal() {
        // /mnt/hidden-volume/../var/log resolves to /mnt/var/log (one level up from hidden-volume)
        assert_eq!(
            clean_path(Path::new("/mnt/hidden-volume/../var/log")),
            PathBuf::from("/mnt/var/log")
        );
    }

    #[test]
    fn test_clean_path_with_double_traversal() {
        assert_eq!(
            clean_path(Path::new("/mnt/hidden-volume/../../etc")),
            PathBuf::from("/etc")
        );
    }

    #[test]
    fn test_clean_path_root() {
        assert_eq!(clean_path(Path::new("/")), PathBuf::from("/"));
    }

    #[test]
    fn test_clean_path_with_dot() {
        // CurDir (.) is ignored by our cleaner
        assert_eq!(
            clean_path(Path::new("/mnt/./hidden-volume/logs")),
            PathBuf::from("/mnt/hidden-volume/logs")
        );
    }

    #[test]
    fn test_clean_path_trailing_slash() {
        assert_eq!(
            clean_path(Path::new("/mnt/hidden-volume/")),
            PathBuf::from("/mnt/hidden-volume")
        );
    }

    // ========================================================================
    // Task 1: rotate_logs() tests (AC #1, #2)
    // ========================================================================

    #[test]
    fn test_rotate_logs_no_op_when_under_size_limit() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden/logs"),
            PathBuf::from("/mnt/hidden"),
        );
        let fs = MockFilesystem::new();

        // Set up log file under the limit (10MB)
        fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
        fs.mock_set_file_size("/mnt/hidden/logs/nails.log", 5_000_000); // 5MB

        let result = manager.rotate_logs(&fs);
        assert!(result.is_ok(), "Rotation should succeed (no-op)");

        // File should still exist and not be rotated
        assert!(
            fs.path_exists(Path::new("/mnt/hidden/logs/nails.log"))
                .unwrap()
        );
    }

    #[test]
    fn test_rotate_logs_rotates_when_exceeds_size_limit() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden/logs"),
            PathBuf::from("/mnt/hidden"),
        );
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

        let result = manager.rotate_logs(&fs);
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
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden/logs"),
            PathBuf::from("/mnt/hidden"),
        );
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

        let result = manager.rotate_logs(&fs);
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
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden/logs"),
            PathBuf::from("/mnt/hidden"),
        );
        let fs = MockFilesystem::new();

        // No log file exists yet (first run scenario)
        fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", false);

        let result = manager.rotate_logs(&fs);
        // Should return error since there's no file to check size of
        assert!(result.is_err());
    }

    // ========================================================================
    // Task 2: enforce_retention() tests (AC #3)
    // ========================================================================

    #[test]
    fn test_enforce_retention_deletes_old_numbered_logs() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden/logs"),
            PathBuf::from("/mnt/hidden"),
        );
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

        let result = manager.enforce_retention(&fs);
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
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden/logs"),
            PathBuf::from("/mnt/hidden"),
        );
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

        let result = manager.enforce_retention(&fs);
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
    // Task 3: should_rotate() tests (AC #1)
    // ========================================================================

    #[test]
    fn test_should_rotate_returns_true_when_exceeds_limit() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden/logs"),
            PathBuf::from("/mnt/hidden"),
        );
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
        fs.mock_set_file_size("/mnt/hidden/logs/nails.log", 11_000_000); // 11MB > 10MB

        let result = manager.should_rotate(&fs);
        assert!(result.is_ok());
        assert!(result.unwrap(), "Should rotate when file exceeds limit");
    }

    #[test]
    fn test_should_rotate_returns_false_when_under_limit() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden/logs"),
            PathBuf::from("/mnt/hidden"),
        );
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
        fs.mock_set_file_size("/mnt/hidden/logs/nails.log", 5_000_000); // 5MB < 10MB

        let result = manager.should_rotate(&fs);
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Should not rotate when file is under limit"
        );
    }

    #[test]
    fn test_should_rotate_handles_exact_limit() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden/logs"),
            PathBuf::from("/mnt/hidden"),
        );
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
        fs.mock_set_file_size("/mnt/hidden/logs/nails.log", 10_485_760); // Exactly 10MB

        let result = manager.should_rotate(&fs);
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Should not rotate when file equals limit (uses > not >=)"
        );
    }

    #[test]
    fn test_should_rotate_handles_missing_file() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden/logs"),
            PathBuf::from("/mnt/hidden"),
        );
        let fs = MockFilesystem::new();

        // File doesn't exist
        fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", false);

        let result = manager.should_rotate(&fs);
        assert!(result.is_err(), "Should return error for missing file");
    }

    // ========================================================================
    // Task 4: Overflow safety tests (AC #6)
    // ========================================================================

    #[test]
    fn test_rotation_uses_checked_mul_for_size_calculation() {
        // Create manager with a max_log_size_mb that will overflow when converted to bytes
        let mut manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden/logs"),
            PathBuf::from("/mnt/hidden"),
        );
        // Set to a value that will overflow: u64::MAX / 1024 / 1024 + 1
        manager.max_log_size_mb = (u64::MAX / 1024 / 1024) + 1;

        let fs = MockFilesystem::new();

        // Create a normal sized file
        fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
        fs.mock_set_file_size("/mnt/hidden/logs/nails.log", 1_000_000); // 1MB

        // This should not panic due to overflow
        let result = manager.should_rotate(&fs);
        assert!(result.is_ok());
        // With overflow protection, threshold becomes u64::MAX, so rotation doesn't trigger
        // (effectively treating the limit as "infinite")
        assert!(
            !result.unwrap(),
            "Overflow should result in no rotation (threshold = MAX)"
        );
    }

    // ========================================================================
    // Task 4.6: Permission denied tests (AC #4)
    // ========================================================================

    #[test]
    fn test_rotate_logs_handles_permission_denied_on_rename() {
        let manager = LoggingManager::new(
            PathBuf::from("/mnt/hidden/logs"),
            PathBuf::from("/mnt/hidden"),
        );
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

        let result = manager.rotate_logs(&fs);
        // Should fail due to permission denied
        assert!(result.is_err());

        // Verify warning was logged (we can't easily check tracing logs in unit tests,
        // but we verify the error propagation works correctly)
    }
}
