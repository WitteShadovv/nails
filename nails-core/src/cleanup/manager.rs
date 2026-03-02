//! Cleanup orchestration and coordination
//!
//! The [`CleanupManager`] coordinates cleanup operations across shell history,
//! temporary files, and log files during deactivation.

use super::ShellType;
use super::history::HistoryCleaner;
use super::logs::LogCleaner;
use super::temp_files::TempFilesCleaner;
use super::types::{CleanupConfig, CleanupMode, CleanupReport};
use crate::{Filesystem, Result, output};
use std::time::Instant;

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
        let mut report = CleanupReport::new(self.mode);

        // Step 1: Clear history (Story 5.2)
        if self.config.clear_history {
            self.cleanup_history(&mut report);
        }

        // Step 2: Clear temp files (Story 5.3)
        if self.config.clear_temp_files {
            self.cleanup_temp_files(&mut report);
        }

        // Step 3: Clear logs (Story 5.4)
        if self.config.clear_logs {
            self.cleanup_logs(&mut report);
        }

        // Step 4: Verification (Thorough mode only)
        if let CleanupMode::Thorough {
            verify_cleanup: true,
        } = self.mode
        {
            let verified = self.verify_cleanup(&mut report);
            report.verification_passed = Some(verified);
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
                let msg = format!("History cleanup failed: {}", e);
                output::warn(&msg);
                report.add_error(msg);
            }
        }
    }

    /// Cleanup temporary files (Story 5.3 integration)
    ///
    /// Uses TempFilesCleaner to remove files matching nails-related patterns
    /// from configured temp directories.
    fn cleanup_temp_files(&self, report: &mut CleanupReport) {
        // Note: TempFilesCleaner uses default patterns ["nails"] which is different
        // from history_patterns. Temp files are always cleaned using "nails" pattern.
        let temp_cleaner = TempFilesCleaner::new(self.filesystem.clone())
            .with_temp_dirs(self.config.temp_dirs.clone());

        match temp_cleaner.clean() {
            Ok(items) => {
                for item in items {
                    report.add_cleaned(item);
                }
            }
            Err(e) => {
                let msg = format!("Temp files cleanup failed: {}", e);
                output::warn(&msg);
                report.add_error(msg);
            }
        }
    }

    /// Cleanup log files (Story 5.4 integration)
    ///
    /// Uses LogCleaner to remove NAILS log files from the hidden volume.
    /// SECURITY: LogCleaner validates that log_path is within hidden_volume before cleanup.
    fn cleanup_logs(&self, report: &mut CleanupReport) {
        let log_cleaner = LogCleaner::new(self.filesystem.clone())
            .with_log_path(self.config.log_path.clone())
            .with_hidden_volume_path(self.config.hidden_volume_path.clone());

        match log_cleaner.clean() {
            Ok(items) => report.extend_cleaned(items),
            Err(e) => {
                let msg = format!("Log cleanup failed: {}", e);
                output::warn(&msg);
                report.add_error(msg);
            }
        }
    }

    /// Verify cleanup was successful (Thorough mode only)
    ///
    /// Verifies all cleanup steps:
    /// - History: No nails commands in shell history files
    /// - Temp files: No nails-related files in temp directories
    /// - Logs: No NAILS log files in hidden volume log directory
    ///
    /// Returns true if all verifications pass, false otherwise.
    fn verify_cleanup(&self, report: &mut CleanupReport) -> bool {
        let mut all_clean = true;

        // Verify history cleanup
        if self.config.clear_history && !self.verify_history_cleanup() {
            report.add_error("Verification: History may still contain 'nails' entries");
            all_clean = false;
        }

        // Verify temp files cleanup
        if self.config.clear_temp_files && !self.verify_temp_cleanup() {
            report.add_error("Verification: Temp files with 'nails' pattern may remain");
            all_clean = false;
        }

        // Verify log cleanup
        if self.config.clear_logs && !self.verify_log_cleanup() {
            report.add_error("Verification: NAILS log files may remain");
            all_clean = false;
        }

        if all_clean {
            report.add_cleaned("Verification completed - no artifacts found");
        }

        all_clean
    }

    /// Verify shell history is clean
    fn verify_history_cleanup(&self) -> bool {
        for shell in ShellType::all() {
            if let Some(path) = shell.history_file_path()
                && let Ok(content) = self.filesystem.read_file_content(&path)
            {
                let content_lower = content.to_lowercase();
                for pattern in &self.config.history_patterns {
                    if content_lower.contains(&pattern.to_lowercase()) {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Verify temp files are clean
    fn verify_temp_cleanup(&self) -> bool {
        for temp_dir in &self.config.temp_dirs {
            for pattern in &self.config.history_patterns {
                if let Ok(files) = self.filesystem.find_files_with_pattern(temp_dir, pattern)
                    && !files.is_empty()
                {
                    return false;
                }
            }
        }
        true
    }

    /// Verify log files are clean
    fn verify_log_cleanup(&self) -> bool {
        if let Ok(files) = self.filesystem.list_directory(&self.config.log_path) {
            for file in files {
                if let Some(name) = file.file_name() {
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with("nails.log") {
                        return false;
                    }
                }
            }
        }
        true
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
