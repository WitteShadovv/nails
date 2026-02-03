//! Cleanup management for NAILS deactivation
//!
//! This module provides the [`CleanupManager`] which coordinates cleanup operations
//! for shell history, temporary files, and log files during deactivation.
//!
//! The cleanup system supports two execution modes:
//! - **Thorough**: Complete cleanup with optional verification (normal deactivation)
//! - **Fast**: Speed-priority cleanup without verification (emergency deactivation)
//!
//! # Submodules
//!
//! - [`history`] - Shell history cleanup for bash, zsh, fish (Story 5.2)
//! - `temp_files` - Temporary files cleanup (Story 5.3)
//! - `logs` - Log files cleanup (Story 5.4)
//!
//! # Example
//!
//! ```rust,ignore
//! use nails_core::{CleanupManager, CleanupConfig, CleanupMode, MockFilesystem};
//!
//! let fs = MockFilesystem::new();
//! let config = CleanupConfig::default();
//! let mode = CleanupMode::Thorough { verify_cleanup: true };
//!
//! let manager = CleanupManager::new(fs, config, mode);
//! let report = manager.cleanup()?;
//! println!("{}", report);
//! ```

// Submodules
pub mod history;

use crate::{Filesystem, Result};
use history::HistoryCleaner;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Cleanup execution mode
///
/// Determines the thoroughness of cleanup operations:
/// - **Thorough**: Full cleanup with optional verification (deactivation)
/// - **Fast**: Speed-priority cleanup without verification (emergency)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupMode {
    /// Thorough cleanup mode for normal deactivation
    ///
    /// Performs complete cleanup with optional verification step.
    /// Use when time permits and verification is valuable.
    Thorough {
        /// If true, verify artifacts are removed after each cleanup step
        verify_cleanup: bool,
    },

    /// Fast cleanup mode for emergency deactivation
    ///
    /// Prioritizes speed over thoroughness. Skips verification.
    /// Use when under time pressure (emergency scenarios).
    Fast,
}

impl Default for CleanupMode {
    fn default() -> Self {
        CleanupMode::Thorough {
            verify_cleanup: true,
        }
    }
}

/// Configuration for cleanup operations
///
/// Controls which cleanup operations are performed and their parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupConfig {
    /// Whether to clear shell history (default: true)
    pub clear_history: bool,

    /// Whether to clear temporary files (default: true)
    pub clear_temp_files: bool,

    /// Whether to clear log files (default: true)
    pub clear_logs: bool,

    /// Patterns to match in history for removal (case-insensitive)
    /// Default: ["nails", "NAILS"]
    pub history_patterns: Vec<String>,

    /// Directories to scan for temporary files
    /// Default: ["/tmp"]
    pub temp_dirs: Vec<PathBuf>,
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            clear_history: true,
            clear_temp_files: true,
            clear_logs: true,
            history_patterns: vec!["nails".to_string(), "NAILS".to_string()],
            temp_dirs: vec![PathBuf::from("/tmp")],
        }
    }
}

/// Report of cleanup operations
///
/// Provides detailed accounting of what was cleaned, any errors, and timing.
#[derive(Debug, Clone)]
pub struct CleanupReport {
    /// Items that were successfully cleaned
    pub cleaned_items: Vec<String>,

    /// Errors encountered during cleanup (best-effort continues)
    pub errors: Vec<String>,

    /// Total time taken for cleanup
    pub duration: Duration,
}

impl CleanupReport {
    /// Create a new empty report
    pub fn new() -> Self {
        Self {
            cleaned_items: Vec::new(),
            errors: Vec::new(),
            duration: Duration::ZERO,
        }
    }

    /// Check if cleanup was fully successful (no errors)
    pub fn is_successful(&self) -> bool {
        self.errors.is_empty()
    }

    /// Get total number of items cleaned
    pub fn total_cleaned(&self) -> usize {
        self.cleaned_items.len()
    }

    /// Add a cleaned item to the report
    pub fn add_cleaned(&mut self, item: impl Into<String>) {
        self.cleaned_items.push(item.into());
    }

    /// Add an error to the report
    pub fn add_error(&mut self, error: impl Into<String>) {
        self.errors.push(error.into());
    }
}

impl Default for CleanupReport {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CleanupReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Cleanup Report")?;
        writeln!(f, "==============")?;
        writeln!(f, "Duration: {:?}", self.duration)?;
        writeln!(f)?;

        if self.cleaned_items.is_empty() {
            writeln!(f, "No items cleaned.")?;
        } else {
            writeln!(f, "Cleaned ({}):", self.cleaned_items.len())?;
            for item in &self.cleaned_items {
                writeln!(f, "  - {}", item)?;
            }
        }

        if !self.errors.is_empty() {
            writeln!(f)?;
            writeln!(f, "Errors ({}):", self.errors.len())?;
            for error in &self.errors {
                writeln!(f, "  ! {}", error)?;
            }
        }

        Ok(())
    }
}

/// Manages cleanup operations for NAILS deactivation
///
/// CleanupManager coordinates cleanup of shell history, temporary files,
/// and log files. It supports two modes:
/// - **Thorough**: Complete cleanup with verification (for normal deactivation)
/// - **Fast**: Speed-priority cleanup without verification (for emergency)
///
/// # Generic Parameter
///
/// `F: Filesystem` - Abstracted filesystem operations for testability
///
/// # Example
///
/// ```rust,ignore
/// use nails_core::{CleanupManager, CleanupConfig, CleanupMode, MockFilesystem};
///
/// let fs = MockFilesystem::new();
/// let config = CleanupConfig::default();
/// let mode = CleanupMode::Thorough { verify_cleanup: true };
///
/// let manager = CleanupManager::new(fs, config, mode);
/// let report = manager.cleanup()?;
/// println!("{}", report);
/// ```
pub struct CleanupManager<F: Filesystem> {
    filesystem: F,
    config: CleanupConfig,
    mode: CleanupMode,
}

impl<F: Filesystem> CleanupManager<F> {
    /// Create a new CleanupManager
    ///
    /// # Arguments
    ///
    /// * `filesystem` - Filesystem implementation for operations
    /// * `config` - Cleanup configuration
    /// * `mode` - Cleanup execution mode (Thorough or Fast)
    pub fn new(filesystem: F, config: CleanupConfig, mode: CleanupMode) -> Self {
        Self {
            filesystem,
            config,
            mode,
        }
    }

    /// Execute cleanup operations
    ///
    /// Performs cleanup based on configuration and mode:
    /// - Clears shell history (if configured)
    /// - Clears temporary files (if configured)
    /// - Clears log files (if configured)
    ///
    /// In Thorough mode with verify_cleanup=true, verifies each step.
    /// In Fast mode, skips verification for speed.
    ///
    /// # Returns
    ///
    /// `CleanupReport` with details of what was cleaned, any errors, and timing.
    ///
    /// # Errors
    ///
    /// This method uses best-effort cleanup - individual failures are logged
    /// but don't stop the entire cleanup. Check `report.errors` for issues.
    pub fn cleanup(&self) -> Result<CleanupReport> {
        let start = Instant::now();
        let mut report = CleanupReport::new();

        // Step 1: Clear history (Story 5.2)
        if self.config.clear_history {
            self.cleanup_history(&mut report);
        }

        // Step 2: Clear temp files (placeholder for Story 5.3)
        if self.config.clear_temp_files {
            self.cleanup_temp_files(&mut report);
        }

        // Step 3: Clear logs (placeholder for Story 5.4)
        if self.config.clear_logs {
            self.cleanup_logs(&mut report);
        }

        // Verification (Thorough mode only)
        if let CleanupMode::Thorough {
            verify_cleanup: true,
        } = self.mode
        {
            self.verify_cleanup(&mut report);
        }

        report.duration = start.elapsed();
        Ok(report)
    }

    /// Cleanup shell history (Story 5.2 integration)
    ///
    /// Uses HistoryCleaner to remove lines containing patterns from shell history files.
    fn cleanup_history(&self, report: &mut CleanupReport) {
        let history_cleaner = HistoryCleaner::new(self.filesystem.clone())
            .with_patterns(self.config.history_patterns.clone());

        match history_cleaner.clean() {
            Ok(cleaned_items) => {
                for item in cleaned_items {
                    report.add_cleaned(item);
                }
            }
            Err(e) => {
                report.add_error(format!("History cleanup failed: {}", e));
            }
        }
    }

    /// Cleanup temporary files (placeholder for Story 5.3 integration)
    ///
    /// TODO(Story 5.3): Implement temporary files cleanup with pattern matching
    /// - Scan directories in config.temp_dirs for files matching *nails* patterns
    /// - Remove matching temporary files safely
    /// - Use self.filesystem for testable file operations
    fn cleanup_temp_files(&self, report: &mut CleanupReport) {
        // Will be implemented in Story 5.3: TempFilesCleaner
        // For now, just log that we would clean temp files
        report.add_cleaned("Temp files cleanup requested (will be implemented in Story 5.3)");
    }

    /// Cleanup log files (placeholder for Story 5.4 integration)
    ///
    /// TODO(Story 5.4): Implement log files cleanup with hidden volume validation
    /// - Remove log files from hidden volume locations
    /// - Validate hidden volume is mounted before attempting cleanup
    /// - Use self.filesystem for testable file operations
    fn cleanup_logs(&self, report: &mut CleanupReport) {
        // Will be implemented in Story 5.4: LogCleaner
        // For now, just log that we would clean logs
        report.add_cleaned("Log cleanup requested (will be implemented in Story 5.4)");
    }

    /// Verify cleanup was successful (Thorough mode only)
    ///
    /// TODO(Story 5.2-5.4): Expand verification to check:
    /// - Story 5.2: Verify history files no longer contain nails commands
    /// - Story 5.3: Verify temp files matching *nails* patterns are removed
    /// - Story 5.4: Verify log files in hidden volume are removed
    ///
    /// Currently performs basic verification that temp directories exist.
    fn verify_cleanup(&self, report: &mut CleanupReport) {
        // Basic verification: check that temp directories are accessible
        // More comprehensive verification will be added in Stories 5.2-5.4
        let mut verified_items = 0;

        for temp_dir in &self.config.temp_dirs {
            match self.filesystem.path_exists(temp_dir) {
                Ok(true) => {
                    verified_items += 1;
                }
                Ok(false) => {
                    report.add_error(format!(
                        "Verification warning: temp directory does not exist: {}",
                        temp_dir.display()
                    ));
                }
                Err(e) => {
                    report.add_error(format!(
                        "Verification error checking temp directory {}: {}",
                        temp_dir.display(),
                        e
                    ));
                }
            }
        }

        report.add_cleaned(format!(
            "Cleanup verification completed ({} temp directories verified)",
            verified_items
        ));
    }

    /// Get a reference to the config
    pub fn config(&self) -> &CleanupConfig {
        &self.config
    }

    /// Get the current mode
    pub fn mode(&self) -> CleanupMode {
        self.mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockFilesystem;

    #[test]
    fn test_cleanup_mode_default() {
        let mode = CleanupMode::default();
        assert!(matches!(
            mode,
            CleanupMode::Thorough {
                verify_cleanup: true
            }
        ));
    }

    #[test]
    fn test_cleanup_mode_equality() {
        let mode1 = CleanupMode::Thorough {
            verify_cleanup: true,
        };
        let mode2 = CleanupMode::Thorough {
            verify_cleanup: true,
        };
        let mode3 = CleanupMode::Fast;

        assert_eq!(mode1, mode2);
        assert_ne!(mode1, mode3);
    }

    #[test]
    fn test_cleanup_config_default() {
        let config = CleanupConfig::default();
        assert!(config.clear_history);
        assert!(config.clear_temp_files);
        assert!(config.clear_logs);
        assert!(config.history_patterns.contains(&"nails".to_string()));
        assert!(config.history_patterns.contains(&"NAILS".to_string()));
        assert_eq!(config.temp_dirs.len(), 1);
        assert_eq!(config.temp_dirs[0], PathBuf::from("/tmp"));
    }

    #[test]
    fn test_cleanup_config_custom() {
        let config = CleanupConfig {
            clear_history: false,
            clear_temp_files: true,
            clear_logs: false,
            history_patterns: vec!["test".to_string()],
            temp_dirs: vec![PathBuf::from("/custom/tmp")],
        };

        assert!(!config.clear_history);
        assert!(config.clear_temp_files);
        assert!(!config.clear_logs);
        assert_eq!(config.history_patterns, vec!["test".to_string()]);
        assert_eq!(config.temp_dirs, vec![PathBuf::from("/custom/tmp")]);
    }

    #[test]
    fn test_cleanup_config_serialization() {
        let config = CleanupConfig::default();
        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: CleanupConfig = serde_json::from_str(&serialized).unwrap();

        assert_eq!(config.clear_history, deserialized.clear_history);
        assert_eq!(config.clear_temp_files, deserialized.clear_temp_files);
        assert_eq!(config.clear_logs, deserialized.clear_logs);
        assert_eq!(config.history_patterns, deserialized.history_patterns);
        assert_eq!(config.temp_dirs, deserialized.temp_dirs);
    }

    #[test]
    fn test_cleanup_report_new() {
        let report = CleanupReport::new();
        assert!(report.cleaned_items.is_empty());
        assert!(report.errors.is_empty());
        assert_eq!(report.duration, Duration::ZERO);
        assert!(report.is_successful());
        assert_eq!(report.total_cleaned(), 0);
    }

    #[test]
    fn test_cleanup_report_default() {
        let report = CleanupReport::default();
        assert!(report.cleaned_items.is_empty());
        assert!(report.errors.is_empty());
        assert_eq!(report.duration, Duration::ZERO);
        assert!(report.is_successful());
    }

    #[test]
    fn test_cleanup_report_add_cleaned() {
        let mut report = CleanupReport::new();
        report.add_cleaned("Item 1");
        report.add_cleaned("Item 2".to_string());

        assert_eq!(report.cleaned_items.len(), 2);
        assert_eq!(report.total_cleaned(), 2);
        assert!(report.is_successful());
    }

    #[test]
    fn test_cleanup_report_add_error() {
        let mut report = CleanupReport::new();
        report.add_error("Error 1");
        report.add_error("Error 2".to_string());

        assert_eq!(report.errors.len(), 2);
        assert!(!report.is_successful());
    }

    #[test]
    fn test_cleanup_report_display_empty() {
        let report = CleanupReport::new();
        let output = format!("{}", report);

        assert!(output.contains("Cleanup Report"));
        assert!(output.contains("No items cleaned"));
        assert!(!output.contains("Errors"));
    }

    #[test]
    fn test_cleanup_report_display_with_items() {
        let mut report = CleanupReport::new();
        report.add_cleaned("Removed 3 history entries");
        report.add_cleaned("Cleared /tmp/nails-*");
        report.duration = Duration::from_millis(150);

        let output = format!("{}", report);

        assert!(output.contains("Cleanup Report"));
        assert!(output.contains("150ms"));
        assert!(output.contains("Removed 3 history entries"));
        assert!(output.contains("Cleared /tmp/nails-*"));
        assert!(output.contains("Cleaned (2)"));
    }

    #[test]
    fn test_cleanup_report_display_with_errors() {
        let mut report = CleanupReport::new();
        report.add_cleaned("Removed 3 history entries");
        report.add_error("Failed to remove /tmp/nails.lock: permission denied");
        report.duration = Duration::from_millis(150);

        let output = format!("{}", report);

        assert!(output.contains("Cleanup Report"));
        assert!(output.contains("Removed 3 history entries"));
        assert!(output.contains("Failed to remove /tmp/nails.lock"));
        assert!(output.contains("Errors (1)"));
    }

    #[test]
    fn test_cleanup_report_is_successful() {
        let mut report = CleanupReport::new();
        assert!(report.is_successful());

        report.add_cleaned("Item");
        assert!(report.is_successful());

        report.add_error("Error");
        assert!(!report.is_successful());
    }

    #[test]
    fn test_cleanup_manager_new() {
        let fs = MockFilesystem::new();
        let config = CleanupConfig::default();
        let mode = CleanupMode::Thorough {
            verify_cleanup: true,
        };

        let manager = CleanupManager::new(fs, config.clone(), mode);

        assert_eq!(manager.mode(), mode);
        assert_eq!(manager.config().clear_history, config.clear_history);
    }

    #[test]
    fn test_cleanup_manager_thorough_mode_with_verification_includes_verification_entry() {
        let fs = MockFilesystem::new();
        let config = CleanupConfig::default();
        let mode = CleanupMode::Thorough {
            verify_cleanup: true,
        };

        let manager = CleanupManager::new(fs, config, mode);
        let report = manager.cleanup().unwrap();

        // Verify report has content
        assert!(!report.cleaned_items.is_empty());
        // In Thorough mode with verification, should have verification entry
        assert!(
            report
                .cleaned_items
                .iter()
                .any(|s| s.contains("verification"))
        );
    }

    #[test]
    fn test_cleanup_manager_thorough_mode_without_verification_skips_verification_entry() {
        let fs = MockFilesystem::new();
        let config = CleanupConfig::default();
        let mode = CleanupMode::Thorough {
            verify_cleanup: false,
        };

        let manager = CleanupManager::new(fs, config, mode);
        let report = manager.cleanup().unwrap();

        // Verify report has content
        assert!(!report.cleaned_items.is_empty());
        // In Thorough mode WITHOUT verification, should not have verification entry
        assert!(
            !report
                .cleaned_items
                .iter()
                .any(|s| s.contains("verification"))
        );
    }

    #[test]
    fn test_cleanup_manager_fast_mode_skips_verification() {
        let fs = MockFilesystem::new();
        let config = CleanupConfig::default();
        let mode = CleanupMode::Fast;

        let manager = CleanupManager::new(fs, config, mode);
        let report = manager.cleanup().unwrap();

        // Verify report has content
        assert!(!report.cleaned_items.is_empty());
        // In Fast mode, verification should NOT have run
        assert!(
            !report
                .cleaned_items
                .iter()
                .any(|s| s.contains("verification"))
        );
    }

    #[test]
    fn test_cleanup_manager_selective_cleanup() {
        let fs = MockFilesystem::new();
        let config = CleanupConfig {
            clear_history: true,
            clear_temp_files: false,
            clear_logs: false,
            history_patterns: vec!["nails".to_string()],
            temp_dirs: vec![PathBuf::from("/tmp")],
        };
        let mode = CleanupMode::Fast;

        let manager = CleanupManager::new(fs, config, mode);
        let report = manager.cleanup().unwrap();

        // Only history cleanup should be requested (but no history files exist)
        // So we should NOT have temp files or log cleanup
        assert!(
            !report
                .cleaned_items
                .iter()
                .any(|s| s.contains("Temp files cleanup"))
        );
        assert!(
            !report
                .cleaned_items
                .iter()
                .any(|s| s.contains("Log cleanup"))
        );
    }

    #[test]
    fn test_cleanup_manager_timing() {
        let fs = MockFilesystem::new();
        let config = CleanupConfig::default();
        let mode = CleanupMode::Fast;

        let manager = CleanupManager::new(fs, config, mode);
        let report = manager.cleanup().unwrap();

        // Duration should be tracked and non-zero
        assert!(report.duration > Duration::ZERO);
    }

    #[test]
    fn test_cleanup_manager_config_accessor() {
        let fs = MockFilesystem::new();
        let config = CleanupConfig {
            clear_history: false,
            clear_temp_files: true,
            clear_logs: false,
            history_patterns: vec!["test".to_string()],
            temp_dirs: vec![PathBuf::from("/custom")],
        };
        let mode = CleanupMode::Fast;

        let manager = CleanupManager::new(fs, config.clone(), mode);

        assert!(!manager.config().clear_history);
        assert!(manager.config().clear_temp_files);
        assert_eq!(manager.config().history_patterns, vec!["test".to_string()]);
    }

    #[test]
    fn test_cleanup_manager_mode_accessor() {
        let fs = MockFilesystem::new();
        let config = CleanupConfig::default();
        let mode = CleanupMode::Thorough {
            verify_cleanup: true,
        };

        let manager = CleanupManager::new(fs, config, mode);
        assert_eq!(manager.mode(), mode);
    }
}
