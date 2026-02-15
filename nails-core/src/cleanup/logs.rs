//! Log files cleanup for NAILS-generated log files
//!
//! This module provides [`LogCleaner`] which removes nails-generated log files
//! from the hidden volume's log directory with strict hidden volume validation.
//!
//! # Security
//!
//! - **CRITICAL**: REFUSES to clean logs from any path outside the hidden volume
//! - **Hidden Volume Validation**: Validates log_path is within hidden volume BEFORE cleanup
//! - **Pattern Matching**: Only removes files matching `nails.log` or `nails.log.*` patterns
//! - **Fail-Safe**: Returns error if validation fails - no cleanup will occur
//!
//! # Example
//!
//! ```rust,ignore
//! use nails_core::{LogCleaner, MockFilesystem};
//! use std::path::PathBuf;
//!
//! let fs = MockFilesystem::new();
//! let cleaner = LogCleaner::new(fs);
//!
//! // Clean logs from hidden volume (safe)
//! let report = cleaner.clean()?;
//! for item in report {
//!     println!("{}", item);
//! }
//! ```
//!
//! *Note: This example is marked with `ignore` because it uses MockFilesystem
//! which is only available in test configuration. Real usage would use RealFilesystem.*

use crate::{Filesystem, NailsError, Result, config::DEFAULT_HIDDEN_VOLUME_ROOT};
use std::path::PathBuf;

/// Cleans NAILS log files from the hidden volume
///
/// LogCleaner removes nails-generated log files from the hidden volume's
/// log directory. It REFUSES to clean logs from any path outside the
/// hidden volume as a security measure.
///
/// # Security
///
/// - VALIDATES log_path is within hidden_volume BEFORE any cleanup
/// - Will NOT clean /var/log or any decoy system paths
/// - Preserves non-nails log files in the same directory
///
/// # Generic Parameter
///
/// `F: Filesystem` - Abstracted filesystem operations for testability
pub struct LogCleaner<F: Filesystem> {
    filesystem: F,
    log_path: PathBuf,
    hidden_volume_path: PathBuf,
}

impl<F: Filesystem> LogCleaner<F> {
    /// Create a new LogCleaner with default paths
    ///
    /// Default log_path: {DEFAULT_HIDDEN_VOLUME_ROOT}/logs
    /// Default hidden_volume_path: DEFAULT_HIDDEN_VOLUME_ROOT
    pub fn new(filesystem: F) -> Self {
        let hidden_volume = PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT);
        Self {
            filesystem,
            log_path: hidden_volume.join("logs"),
            hidden_volume_path: hidden_volume,
        }
    }

    /// Set custom log path (must still be within hidden volume)
    pub fn with_log_path(mut self, log_path: PathBuf) -> Self {
        self.log_path = log_path;
        self
    }

    /// Set custom hidden volume path (for testing)
    pub fn with_hidden_volume_path(mut self, path: PathBuf) -> Self {
        self.hidden_volume_path = path;
        self
    }

    /// Validate that log_path is within the hidden volume
    ///
    /// # Security
    ///
    /// This is a CRITICAL security check. Failure to validate would allow
    /// accidental cleanup of decoy system logs.
    fn validate_log_path(&self) -> Result<()> {
        let log_path = self.log_path.as_path();
        let hidden_volume = self.hidden_volume_path.as_path();

        // Check if log_path starts with hidden_volume_path
        if !log_path.starts_with(hidden_volume) {
            return Err(NailsError::InvalidState(format!(
                "Log path must be on hidden volume. Log path: {}, Hidden volume: {}",
                log_path.display(),
                hidden_volume.display()
            )));
        }

        Ok(())
    }

    /// Check if a filename matches NAILS log file patterns
    ///
    /// Matches:
    /// - Exact "nails.log"
    /// - Rotated logs: "nails.log.{number}" (e.g., nails.log.1, nails.log.23)
    ///
    /// Does NOT match:
    /// - "nails.log.backup" (non-numeric suffix)
    /// - "nails-debug.log" (different naming pattern)
    /// - "other.log" (not a nails log)
    /// - "nails.log." (empty suffix)
    fn is_nails_log_file(&self, filename: &str) -> bool {
        // Match exact "nails.log"
        if filename == "nails.log" {
            return true;
        }

        // Match "nails.log.{number}" (rotated logs)
        if let Some(suffix) = filename.strip_prefix("nails.log.") {
            // Must have at least one digit and all characters must be digits
            return !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit());
        }

        false
    }

    /// Execute log cleanup
    ///
    /// Removes NAILS log files from the hidden volume's log directory.
    ///
    /// # Security
    ///
    /// REFUSES to clean if log_path is outside hidden volume.
    ///
    /// # Returns
    ///
    /// Vec<String> with descriptions of cleaned items.
    ///
    /// # Errors
    ///
    /// Returns Err if log_path is outside hidden volume (security failure).
    /// Individual file removal errors are logged but don't stop cleanup.
    pub fn clean(&self) -> Result<Vec<String>> {
        // CRITICAL: Validate log path is within hidden volume
        self.validate_log_path()?;

        let mut removed_files = Vec::new();

        // Check if log directory exists
        if !self.filesystem.path_exists(&self.log_path)? {
            // Not an error - just nothing to clean
            return Ok(vec![format!(
                "Log directory not found: {} (no cleanup needed)",
                self.log_path.display()
            )]);
        }

        // List files in log directory
        let files = self.filesystem.list_directory(&self.log_path)?;

        for file_path in files {
            // Get filename
            let filename = match file_path.file_name() {
                Some(name) => name.to_string_lossy().to_string(),
                None => continue,
            };

            // Check if this is a NAILS log file
            if !self.is_nails_log_file(&filename) {
                continue; // Skip non-nails logs
            }

            // Remove the log file
            match self.filesystem.remove_file(&file_path) {
                Ok(()) => {
                    removed_files.push(filename);
                }
                Err(e) => {
                    // Best-effort: log warning but continue
                    eprintln!("Warning: Failed to remove {}: {}", file_path.display(), e);
                }
            }
        }

        if removed_files.is_empty() {
            Ok(vec![format!(
                "No NAILS log files found in {}",
                self.log_path.display()
            )])
        } else {
            // AC3/AC5: Return summary message with count and list
            let count = removed_files.len();
            let files_list = removed_files.join(", ");
            Ok(vec![format!("Removed {} log files: {}", count, files_list)])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockFilesystem;

    #[test]
    fn test_log_cleaner_new() {
        let fs = MockFilesystem::new();
        let cleaner = LogCleaner::new(fs);

        assert_eq!(
            cleaner.log_path,
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT).join("logs")
        );
        assert_eq!(
            cleaner.hidden_volume_path,
            PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT)
        );
    }

    #[test]
    fn test_with_log_path() {
        let fs = MockFilesystem::new();
        let custom_path = PathBuf::from("/mnt/hidden-volume/custom/logs");
        let cleaner = LogCleaner::new(fs).with_log_path(custom_path.clone());

        assert_eq!(cleaner.log_path, custom_path);
    }

    #[test]
    fn test_with_hidden_volume_path() {
        let fs = MockFilesystem::new();
        let custom_hidden = PathBuf::from("/mnt/custom-hidden");
        let cleaner = LogCleaner::new(fs).with_hidden_volume_path(custom_hidden.clone());

        assert_eq!(cleaner.hidden_volume_path, custom_hidden);
    }

    #[test]
    fn test_hidden_volume_validation_passes() {
        let fs = MockFilesystem::new();
        let cleaner = LogCleaner::new(fs)
            .with_hidden_volume_path(PathBuf::from("/mnt/hidden"))
            .with_log_path(PathBuf::from("/mnt/hidden/logs"));

        assert!(cleaner.validate_log_path().is_ok());
    }

    #[test]
    fn test_hidden_volume_validation_passes_for_subdirectory() {
        let fs = MockFilesystem::new();
        let cleaner = LogCleaner::new(fs)
            .with_hidden_volume_path(PathBuf::from("/mnt/hidden"))
            .with_log_path(PathBuf::from("/mnt/hidden/nested/logs"));

        assert!(cleaner.validate_log_path().is_ok());
    }

    #[test]
    fn test_hidden_volume_validation_fails_for_var_log() {
        let fs = MockFilesystem::new();
        let cleaner = LogCleaner::new(fs)
            .with_hidden_volume_path(PathBuf::from("/mnt/hidden"))
            .with_log_path(PathBuf::from("/var/log"));

        let result = cleaner.validate_log_path();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("must be on hidden volume"));
        assert!(err_msg.contains("/var/log"));
        assert!(err_msg.contains("/mnt/hidden"));
    }

    #[test]
    fn test_hidden_volume_validation_fails_for_root() {
        let fs = MockFilesystem::new();
        let cleaner = LogCleaner::new(fs)
            .with_hidden_volume_path(PathBuf::from("/mnt/hidden"))
            .with_log_path(PathBuf::from("/"));

        let result = cleaner.validate_log_path();
        assert!(result.is_err());
    }

    #[test]
    fn test_hidden_volume_validation_fails_for_similar_path() {
        let fs = MockFilesystem::new();
        let cleaner = LogCleaner::new(fs)
            .with_hidden_volume_path(PathBuf::from("/mnt/hidden"))
            .with_log_path(PathBuf::from("/mnt/hidden-fake/logs"));

        let result = cleaner.validate_log_path();
        assert!(result.is_err());
    }

    #[test]
    fn test_log_file_pattern_matching() {
        let fs = MockFilesystem::new();
        let cleaner = LogCleaner::new(fs);

        // Should match
        assert!(cleaner.is_nails_log_file("nails.log"));
        assert!(cleaner.is_nails_log_file("nails.log.1"));
        assert!(cleaner.is_nails_log_file("nails.log.23"));
        assert!(cleaner.is_nails_log_file("nails.log.999"));

        // Should NOT match
        assert!(!cleaner.is_nails_log_file("other.log"));
        assert!(!cleaner.is_nails_log_file("nails.log.backup")); // Not numeric suffix
        assert!(!cleaner.is_nails_log_file("nails-debug.log"));
        assert!(!cleaner.is_nails_log_file("nails.log.")); // Empty suffix
        assert!(!cleaner.is_nails_log_file("nailslog")); // Missing dot
        assert!(!cleaner.is_nails_log_file("nails.log.1a")); // Mixed alphanumeric
    }

    #[test]
    fn test_cleanup_removes_only_nails_logs() {
        let fs = MockFilesystem::new();
        let log_dir = PathBuf::from("/mnt/hidden-volume/logs");

        // Set up mock directory
        fs.mock_set_path_exists(log_dir.to_str().unwrap(), true);
        fs.mock_set_directory_contents(
            &log_dir,
            vec![
                log_dir.join("nails.log"),
                log_dir.join("nails.log.1"),
                log_dir.join("nails.log.2"),
                log_dir.join("other-app.log"),
            ],
        );

        let cleaner = LogCleaner::new(fs.clone());

        let result = cleaner.clean().unwrap();

        // AC3/AC5: Should return summary message
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("Removed 3 log files:"));
        assert!(result[0].contains("nails.log"));
        assert!(result[0].contains("nails.log.1"));
        assert!(result[0].contains("nails.log.2"));
        assert!(!result[0].contains("other-app.log"));
    }

    #[test]
    fn test_cleanup_refuses_outside_hidden_volume() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/var/log", true);

        let cleaner = LogCleaner::new(fs)
            .with_hidden_volume_path(PathBuf::from("/mnt/hidden"))
            .with_log_path(PathBuf::from("/var/log"));

        let result = cleaner.clean();

        // Should fail security validation
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("must be on hidden volume"));
    }

    #[test]
    fn test_missing_log_directory() {
        let fs = MockFilesystem::new();
        // Don't set up log directory to exist
        fs.mock_set_path_exists("/mnt/hidden-volume/logs", false);

        let cleaner = LogCleaner::new(fs);

        let result = cleaner.clean().unwrap();

        // Should succeed with "not found" message
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("not found"));
        assert!(result[0].contains("no cleanup needed"));
    }

    #[test]
    fn test_empty_log_directory() {
        let fs = MockFilesystem::new();
        let log_dir = PathBuf::from("/mnt/hidden-volume/logs");

        fs.mock_set_path_exists(log_dir.to_str().unwrap(), true);
        fs.mock_set_directory_contents(&log_dir, vec![]); // Empty directory

        let cleaner = LogCleaner::new(fs.clone());

        let result = cleaner.clean().unwrap();

        // Should succeed with "no files found" message
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("No NAILS log files found"));
    }

    #[test]
    fn test_cleanup_continues_on_permission_error() {
        let fs = MockFilesystem::new();
        let log_dir = PathBuf::from("/mnt/hidden-volume/logs");

        fs.mock_set_path_exists(log_dir.to_str().unwrap(), true);
        fs.mock_set_directory_contents(
            &log_dir,
            vec![
                log_dir.join("nails.log"),
                log_dir.join("nails.log.1"),
                log_dir.join("nails.log.2"),
            ],
        );

        // Make first file fail to remove
        fs.mock_set_remove_should_fail("/mnt/hidden-volume/logs/nails.log", true);

        let cleaner = LogCleaner::new(fs.clone());

        let result = cleaner.clean();

        // Should succeed overall (best-effort)
        assert!(result.is_ok());
        let cleaned = result.unwrap();

        // AC3/AC5: Should have summary with 2 files that succeeded
        assert_eq!(cleaned.len(), 1);
        assert!(cleaned[0].contains("Removed 2 log files:"));
        assert!(cleaned[0].contains("nails.log.1"));
        assert!(cleaned[0].contains("nails.log.2"));
        assert!(!cleaned[0].contains("nails.log, nails.log.1")); // First file shouldn't be in list
    }

    #[test]
    fn test_cleanup_with_only_exact_nails_log() {
        let fs = MockFilesystem::new();
        let log_dir = PathBuf::from("/mnt/hidden-volume/logs");

        fs.mock_set_path_exists(log_dir.to_str().unwrap(), true);
        fs.mock_set_directory_contents(&log_dir, vec![log_dir.join("nails.log")]);

        let cleaner = LogCleaner::new(fs.clone());

        let result = cleaner.clean().unwrap();

        // AC3/AC5: Should return summary message with count
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("Removed 1 log files:"));
        assert!(result[0].contains("nails.log"));
    }

    #[test]
    fn test_cleanup_preserves_non_nails_logs() {
        let fs = MockFilesystem::new();
        let log_dir = PathBuf::from("/mnt/hidden-volume/logs");

        fs.mock_set_path_exists(log_dir.to_str().unwrap(), true);
        fs.mock_set_directory_contents(
            &log_dir,
            vec![
                log_dir.join("apache.log"),
                log_dir.join("system.log.1"),
                log_dir.join("app-debug.log"),
            ],
        );

        let cleaner = LogCleaner::new(fs.clone());

        let result = cleaner.clean().unwrap();

        // Should find no nails logs to clean
        assert_eq!(result.len(), 1);
        assert!(result[0].contains("No NAILS log files found"));
    }
}
