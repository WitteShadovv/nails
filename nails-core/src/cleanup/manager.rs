//! Cleanup orchestration and coordination
//!
//! The [`CleanupManager`] coordinates cleanup operations across shell history,
//! temporary files, and log files during deactivation.

use super::ShellType;
use super::canary::{CanaryConfig, CanaryScanner};
use super::history::HistoryCleaner;
use super::logs::LogCleaner;
use super::temp_files::TempFilesCleaner;
use super::types::{CleanupConfig, CleanupMode, CleanupReport};
use crate::{Filesystem, Result, output};
use std::path::Path;
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
    /// - Performs memory sanitization (if configured)
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

        // Step 4: Memory sanitization (if configured)
        if self.config.sanitize_memory {
            self.sanitize_memory(&mut report);
        }

        // Step 5: Verification (Thorough mode only)
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
            .with_patterns(self.config.history_patterns.clone())
            .with_secure_delete(self.config.secure_delete);

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
            .with_temp_dirs(self.config.temp_dirs.clone())
            .with_preserved_paths(self.config.config_file_path.iter().cloned().collect())
            .with_secure_delete(self.config.secure_delete);

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
            .with_hidden_volume_path(self.config.hidden_volume_path.clone())
            .with_secure_delete(self.config.secure_delete);

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
    /// - History size: History files should be small (< 10KB) or empty after cleanup
    /// - Temp files: No nails-related files in temp directories
    /// - Logs: No NAILS log files in hidden volume log directory
    /// - Canary patterns: No forbidden patterns in scanned files
    ///
    /// Returns true if all verifications pass, false otherwise.
    fn verify_cleanup(&self, report: &mut CleanupReport) -> bool {
        let mut all_clean = true;

        // Verify history cleanup
        if self.config.clear_history && !self.verify_history_cleanup() {
            report.add_error("Verification: History may still contain 'nails' entries");
            all_clean = false;
        }

        // Verify history file sizes (should be small after cleanup)
        if self.config.clear_history && !self.verify_history_file_sizes(report) {
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

        // Canary pattern scanning
        if !self.verify_canary_patterns(report) {
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
        const TEMP_FILE_PATTERN: &str = "nails";

        for temp_dir in &self.config.temp_dirs {
            if let Ok(files) = self
                .filesystem
                .find_files_with_pattern(temp_dir, TEMP_FILE_PATTERN)
                && files.iter().any(|file| !self.is_preserved_temp_path(file))
            {
                return false;
            }
        }
        true
    }

    fn is_preserved_temp_path(&self, path: &Path) -> bool {
        self.config
            .config_file_path
            .as_ref()
            .is_some_and(|preserved| preserved == path)
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

    /// Verify history file sizes are reasonable after cleanup
    ///
    /// After cleaning, history files should either be empty or much smaller
    /// than a typical "dirty" history file. Files larger than 10KB are suspicious.
    fn verify_history_file_sizes(&self, report: &mut CleanupReport) -> bool {
        const MAX_HISTORY_SIZE_BYTES: u64 = 10 * 1024; // 10KB threshold
        let mut all_ok = true;

        for shell in ShellType::all() {
            if let Some(path) = shell.history_file_path() {
                match self.filesystem.file_size(&path) {
                    Ok(size) if size > MAX_HISTORY_SIZE_BYTES => {
                        report.add_error(format!(
                            "Verification: {} history file is large ({} bytes) - may contain artifacts",
                            shell.name(),
                            size
                        ));
                        all_ok = false;
                    }
                    Ok(_) => {
                        // Size is acceptable
                    }
                    Err(_) => {
                        // File doesn't exist or unreadable - that's fine for cleanup
                    }
                }
            }
        }

        all_ok
    }

    /// Verify no canary patterns remain in scanned files
    ///
    /// Runs the canary scanner to detect any forbidden patterns that
    /// should have been removed during cleanup.
    fn verify_canary_patterns(&self, report: &mut CleanupReport) -> bool {
        let canary_config = CanaryConfig::default();
        let scanner = CanaryScanner::new(self.filesystem.clone(), canary_config);

        let scan_result = scanner.scan();

        report.canary_findings_count = scan_result.finding_count();

        if !scan_result.is_clean() {
            for finding in &scan_result.findings {
                let msg = if let Some(line_num) = finding.line_number {
                    format!(
                        "Canary pattern '{}' found in {} at line {}",
                        finding.pattern,
                        finding.path.display(),
                        line_num
                    )
                } else {
                    format!(
                        "Canary pattern '{}' found in {}",
                        finding.pattern,
                        finding.path.display()
                    )
                };
                report.add_error(msg);
            }
            return false;
        }

        true
    }

    /// Sanitize memory by clearing page cache
    ///
    /// Writes "3" to /proc/sys/vm/drop_caches to clear:
    /// - Page cache
    /// - Dentries and inodes
    ///
    /// This helps prevent forensic recovery of cleanup artifacts from RAM.
    /// Requires root privileges.
    fn sanitize_memory(&self, report: &mut CleanupReport) {
        // First, sync to ensure all pending writes are flushed
        if let Err(e) = self.sync_filesystems() {
            let msg = format!("Memory sanitization: sync failed: {}", e);
            output::warn(&msg);
            report.add_error(msg);
            return;
        }

        // Drop caches by writing "3" to /proc/sys/vm/drop_caches
        let drop_caches_path = Path::new("/proc/sys/vm/drop_caches");

        match self.filesystem.write_file_content(drop_caches_path, "3") {
            Ok(()) => {
                report.memory_sanitized = true;
                report.add_cleaned("Memory sanitized (page cache cleared)");
            }
            Err(e) => {
                let msg = format!("Memory sanitization failed (requires root): {}", e);
                output::warn(&msg);
                report.add_error(msg);
            }
        }
    }

    /// Sync all filesystems before memory sanitization
    fn sync_filesystems(&self) -> Result<()> {
        // Use the sync command via std::process::Command
        // This is more portable than using nix::unistd::sync() which requires the 'fs' feature
        let status = std::process::Command::new("sync")
            .status()
            .map_err(crate::NailsError::IoError)?;

        if !status.success() {
            return Err(crate::NailsError::InvalidState(format!(
                "sync command failed with exit code: {:?}",
                status.code()
            )));
        }
        Ok(())
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
