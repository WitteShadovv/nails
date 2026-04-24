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

pub struct CleanupManager<F: Filesystem> {
    filesystem: F,
    config: CleanupConfig,
    mode: CleanupMode,
}

impl<F: Filesystem> CleanupManager<F> {
    pub fn new(filesystem: F, config: CleanupConfig, mode: CleanupMode) -> Self {
        Self {
            filesystem,
            config,
            mode,
        }
    }

    pub fn cleanup(&self) -> Result<CleanupReport> {
        let start = Instant::now();
        let mut report = CleanupReport::new(self.mode);

        if self.config.clear_history {
            self.cleanup_history(&mut report);
        }
        if self.config.clear_temp_files {
            self.cleanup_temp_files(&mut report);
        }
        if self.config.clear_logs {
            self.cleanup_logs(&mut report);
        }
        if self.config.sanitize_memory {
            self.sanitize_memory(&mut report);
        }

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

    fn cleanup_temp_files(&self, report: &mut CleanupReport) {
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

    fn verify_cleanup(&self, report: &mut CleanupReport) -> bool {
        let mut all_clean = true;

        if self.config.clear_history && !self.verify_history_cleanup() {
            report.add_error("Verification: History may still contain 'nails' entries");
            all_clean = false;
        }

        if self.config.clear_history && !self.verify_history_file_sizes(report) {
            all_clean = false;
        }

        if self.config.clear_temp_files && !self.verify_temp_cleanup() {
            report.add_error("Verification: Temp files with 'nails' pattern may remain");
            all_clean = false;
        }

        if self.config.clear_logs && !self.verify_log_cleanup() {
            report.add_error("Verification: NAILS log files may remain");
            all_clean = false;
        }

        if !self.verify_canary_patterns(report) {
            all_clean = false;
        }

        if all_clean {
            report.add_cleaned("Verification completed - no artifacts found");
        }

        all_clean
    }

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

    fn verify_temp_cleanup(&self) -> bool {
        const TEMP_FILE_PATTERN: &str = "nails";

        for temp_dir in &self.config.temp_dirs {
            if let Ok(files) = self
                .filesystem
                .find_files_with_pattern(temp_dir, TEMP_FILE_PATTERN)
                && files.iter().any(|file| {
                    !self.is_preserved_temp_path(file)
                        && !crate::cleanup::temp_files::TempFilesCleaner::<F>::is_preserved_config_file(file)
                })
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

    fn verify_history_file_sizes(&self, report: &mut CleanupReport) -> bool {
        const MAX_HISTORY_SIZE_BYTES: u64 = 10 * 1024;
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
                    Ok(_) => {}
                    Err(_) => {}
                }
            }
        }

        all_ok
    }

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

    fn sanitize_memory(&self, report: &mut CleanupReport) {
        if let Err(e) = self.sync_filesystems() {
            let msg = format!("Memory sanitization: sync failed: {}", e);
            output::warn(&msg);
            report.add_error(msg);
            return;
        }

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

    fn sync_filesystems(&self) -> Result<()> {
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

    pub fn config(&self) -> &CleanupConfig {
        &self.config
    }

    pub fn mode(&self) -> CleanupMode {
        self.mode
    }
}
