// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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
    /// The homes history cleanup covers; resolved from the installed startup
    /// snapshot when none were attached.
    history_homes: Option<Vec<std::path::PathBuf>>,
}

impl<F: Filesystem> CleanupManager<F> {
    pub fn new(filesystem: F, config: CleanupConfig, mode: CleanupMode) -> Self {
        Self {
            filesystem,
            config,
            mode,
            history_homes: None,
        }
    }

    /// Clean and verify the history files under these homes (the operator's
    /// home plus `/root`, as the manager resolves them from its snapshot).
    #[must_use]
    pub fn with_history_homes(mut self, homes: Vec<std::path::PathBuf>) -> Self {
        self.history_homes = Some(homes);
        self
    }

    fn history_homes(&self) -> Vec<std::path::PathBuf> {
        self.history_homes.clone().unwrap_or_else(|| {
            super::history::history_cleanup_homes(&crate::runtime_env::current())
        })
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
        if self.config.drop_page_cache {
            self.drop_page_cache(&mut report);
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
            .with_homes(self.history_homes())
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
            .with_hidden_volume_root(self.config.hidden_volume_root.clone())
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
        for home in self.history_homes() {
            for shell in ShellType::all() {
                let path = shell.history_file_path_for_home(&home);
                if let Ok(content) = self.filesystem.read_file_content(&path) {
                    let content_lower = content.to_lowercase();
                    for pattern in &self.config.history_patterns {
                        if content_lower.contains(&pattern.to_lowercase()) {
                            return false;
                        }
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

        for home in self.history_homes() {
            for shell in ShellType::all() {
                let path = shell.history_file_path_for_home(&home);
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
        let scanner = CanaryScanner::new(self.filesystem.clone(), canary_config)
            .with_history_homes(self.history_homes());

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

    fn drop_page_cache(&self, report: &mut CleanupReport) {
        // No global `sync` here: a blocking, unbounded sync of every filesystem
        // can wedge teardown on a stalled backend, and dropping clean page cache
        // does not require it. drop_caches only frees *clean* cached pages; it
        // does not zero RAM, so this is a modest residue-reduction step, not
        // "memory sanitization".
        //
        // The node is written through `write_kernel_tunable`, which opens procfs
        // directly instead of staging a temp file and renaming it — the atomic
        // write `write_file_content` performs can never succeed on procfs, which
        // is why this step used to fail even as root.
        let drop_caches_path = Path::new("/proc/sys/vm/drop_caches");

        match self.filesystem.write_kernel_tunable(drop_caches_path, "3") {
            Ok(()) => {
                report.page_cache_dropped = true;
                report.add_cleaned("page cache dropped");
            }
            Err(e) => {
                let msg = format!("Dropping the page cache failed (requires root): {}", e);
                output::warn(&msg);
                report.add_error(msg);
            }
        }
    }

    /// Remove the volatile runtime journal under `/run/log/journal`.
    ///
    /// journald's volatile store (`Storage=volatile`, or `auto` with no
    /// persistent `/var/log/journal` — the recommended decoy posture) keeps every
    /// record a hidden session produced in RAM at `/run/log/journal`. `/run` is
    /// never overlaid, so those records survive an emergency teardown, which does
    /// not reboot, and anyone at the machine can then read the hidden session's
    /// service lifecycle, sudo invocations and user-unit stderr with `journalctl`.
    ///
    /// Run at teardown after journald has been restarted onto the decoy `/var` and
    /// the active runtime files rotated, this removes the per-machine journal
    /// directories so the hidden-session runtime records are gone. All runtime
    /// files are removed rather than only those newer than activation: the store
    /// is entirely volatile and journald recreates it, so clearing it wholesale is
    /// both simpler and leaves no hidden-session residue, at the cost of also
    /// dropping pre-activation decoy runtime entries — acceptable for an
    /// anti-forensic teardown.
    ///
    /// This is a decoy-side scrub of the host's own volatile store and is
    /// deliberately *not* bound by the hidden-volume guard that governs
    /// [`LogCleaner`](super::logs::LogCleaner); that guard protects paths under
    /// the hidden volume, which `/run/log/journal` is not. Operates on the
    /// injected [`Filesystem`], so tests exercise it against a mock. Best-effort:
    /// a missing store is a no-op and every removal outcome is recorded on the
    /// report.
    pub fn scrub_runtime_journal(&self, report: &mut CleanupReport) {
        let journal_root = Path::new("/run/log/journal");

        match self.filesystem.path_exists(journal_root) {
            Ok(true) => {}
            Ok(false) => return,
            Err(e) => {
                let msg = format!(
                    "Could not check the runtime journal {}: {}",
                    journal_root.display(),
                    e
                );
                output::warn(&msg);
                report.add_error(msg);
                return;
            }
        }

        if !matches!(self.filesystem.is_directory(journal_root), Ok(true)) {
            return;
        }

        let entries = match self.filesystem.list_directory(journal_root) {
            Ok(entries) => entries,
            Err(e) => {
                let msg = format!(
                    "Could not list the runtime journal {}: {}",
                    journal_root.display(),
                    e
                );
                output::warn(&msg);
                report.add_error(msg);
                return;
            }
        };

        for entry in entries {
            match self.filesystem.remove_dir_all(&entry) {
                Ok(()) => {
                    report.add_cleaned(format!("runtime journal removed: {}", entry.display()));
                }
                Err(e) => {
                    let msg = format!(
                        "Could not remove runtime journal {}: {}",
                        entry.display(),
                        e
                    );
                    output::warn(&msg);
                    report.add_error(msg);
                }
            }
        }
    }

    pub fn config(&self) -> &CleanupConfig {
        &self.config
    }

    pub fn mode(&self) -> CleanupMode {
        self.mode
    }
}
