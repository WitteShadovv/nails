//! Canary pattern scanner for cleanup verification
//!
//! Scans files for forbidden patterns that should not remain after cleanup.
//! Used during verification phase to detect incomplete cleanup operations.
//!
//! # Security
//!
//! Canary patterns help detect:
//! - Incomplete history cleanup (NAILS commands remaining in shell history)
//! - Leaked sensitive patterns (project names, secret identifiers)
//! - Configuration artifacts that could reveal NAILS usage
//!
//! # Example
//!
//! ```rust,ignore
//! use nails_core::cleanup::canary::{CanaryScanner, CanaryConfig};
//! use nails_core::MockFilesystem;
//!
//! let fs = MockFilesystem::new();
//! let config = CanaryConfig::default();
//! let scanner = CanaryScanner::new(fs, config);
//!
//! let result = scanner.scan();
//! if !result.is_clean() {
//!     for finding in result.findings {
//!         eprintln!("Found '{}' in {}", finding.pattern, finding.path.display());
//!     }
//! }
//! ```

#[cfg(test)]
mod tests;

use crate::Filesystem;
use crate::obfuscate;
use std::path::{Path, PathBuf};

/// Configuration for canary pattern scanning
///
/// Defines which patterns to search for and which paths to scan.
#[derive(Debug, Clone)]
pub struct CanaryConfig {
    /// Patterns that should not appear in scanned files
    ///
    /// These are case-insensitive substrings to search for.
    /// Default includes: "nails", "NAILS", "hidden-volume", "secret-project",
    /// "financial-data", "NAILS_CANARY"
    pub forbidden_patterns: Vec<String>,

    /// Paths to scan for forbidden patterns
    ///
    /// Typically includes shell history files and other sensitive locations.
    /// If empty, scanner will use default shell history paths.
    pub scan_paths: Vec<PathBuf>,

    /// Maximum file size to scan (in bytes)
    ///
    /// Files larger than this are skipped to avoid performance issues.
    /// Default: 10MB
    pub max_file_size: u64,
}

impl Default for CanaryConfig {
    fn default() -> Self {
        Self {
            // Use obfuscated patterns for forensic resistance
            forbidden_patterns: obfuscate::default_canary_patterns(),
            scan_paths: Vec::new(), // Empty means use default shell history paths
            max_file_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

impl CanaryConfig {
    /// Create a new config with custom forbidden patterns
    pub fn with_patterns(mut self, patterns: Vec<String>) -> Self {
        self.forbidden_patterns = patterns;
        self
    }

    /// Add additional scan paths
    pub fn with_scan_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.scan_paths = paths;
        self
    }

    /// Set maximum file size to scan
    pub fn with_max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }
}

/// A single finding from the canary scan
#[derive(Debug, Clone)]
pub struct CanaryFinding {
    /// Path where the pattern was found
    pub path: PathBuf,

    /// The forbidden pattern that was detected
    pub pattern: String,

    /// Line number where pattern was found (1-indexed), if available
    pub line_number: Option<usize>,

    /// The line content containing the pattern (truncated if too long)
    pub context: Option<String>,
}

/// Result of a canary scan operation
#[derive(Debug, Clone)]
pub struct CanaryScanResult {
    /// All findings from the scan
    pub findings: Vec<CanaryFinding>,

    /// Paths that were scanned
    pub scanned_paths: Vec<PathBuf>,

    /// Paths that were skipped (not found, too large, or unreadable)
    pub skipped_paths: Vec<(PathBuf, String)>,

    /// Errors encountered during scanning
    pub errors: Vec<String>,
}

impl CanaryScanResult {
    /// Create a new empty result
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            scanned_paths: Vec::new(),
            skipped_paths: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Check if the scan found any forbidden patterns
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Get total number of findings
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// Add a finding to the result
    pub fn add_finding(&mut self, finding: CanaryFinding) {
        self.findings.push(finding);
    }

    /// Add a scanned path
    pub fn add_scanned(&mut self, path: PathBuf) {
        self.scanned_paths.push(path);
    }

    /// Add a skipped path with reason
    pub fn add_skipped(&mut self, path: PathBuf, reason: impl Into<String>) {
        self.skipped_paths.push((path, reason.into()));
    }

    /// Add an error
    pub fn add_error(&mut self, error: impl Into<String>) {
        self.errors.push(error.into());
    }
}

impl Default for CanaryScanResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Scanner for forbidden canary patterns in files
///
/// Scans configured paths for patterns that should not remain after cleanup.
/// Used during verification phase to detect incomplete cleanup operations.
///
/// # Generic Parameter
///
/// `F: Filesystem` - Abstracted filesystem operations for testability
pub struct CanaryScanner<F: Filesystem> {
    filesystem: F,
    config: CanaryConfig,
}

impl<F: Filesystem> CanaryScanner<F> {
    /// Create a new CanaryScanner
    ///
    /// # Arguments
    ///
    /// * `filesystem` - Filesystem implementation for operations
    /// * `config` - Scanner configuration
    pub fn new(filesystem: F, config: CanaryConfig) -> Self {
        Self { filesystem, config }
    }

    /// Scan all configured paths for forbidden patterns
    ///
    /// Returns a `CanaryScanResult` containing all findings, scanned paths,
    /// and any errors encountered during scanning.
    ///
    /// # Returns
    ///
    /// `CanaryScanResult` with findings and scan metadata
    pub fn scan(&self) -> CanaryScanResult {
        let mut result = CanaryScanResult::new();

        // Get paths to scan (use configured paths or default shell history)
        let paths_to_scan = if self.config.scan_paths.is_empty() {
            self.get_default_scan_paths()
        } else {
            self.config.scan_paths.clone()
        };

        for path in paths_to_scan {
            self.scan_file(&path, &mut result);
        }

        result
    }

    /// Scan a single file for forbidden patterns
    fn scan_file(&self, path: &Path, result: &mut CanaryScanResult) {
        // Check if file exists
        match self.filesystem.path_exists(path) {
            Ok(true) => {}
            Ok(false) => {
                result.add_skipped(path.to_path_buf(), "File not found");
                return;
            }
            Err(e) => {
                result.add_error(format!("Error checking path {}: {}", path.display(), e));
                return;
            }
        }

        // Check file size
        match self.filesystem.file_size(path) {
            Ok(size) if size > self.config.max_file_size => {
                result.add_skipped(
                    path.to_path_buf(),
                    format!("File too large ({} bytes)", size),
                );
                return;
            }
            Err(e) => {
                result.add_error(format!("Error getting size of {}: {}", path.display(), e));
                return;
            }
            Ok(_) => {}
        }

        // Read file content
        let content = match self.filesystem.read_file_content(path) {
            Ok(c) => c,
            Err(e) => {
                result.add_skipped(path.to_path_buf(), format!("Cannot read file: {}", e));
                return;
            }
        };

        result.add_scanned(path.to_path_buf());

        // Scan for each forbidden pattern
        for pattern in &self.config.forbidden_patterns {
            self.scan_content_for_pattern(path, &content, pattern, result);
        }
    }

    /// Scan file content for a specific pattern
    fn scan_content_for_pattern(
        &self,
        path: &Path,
        content: &str,
        pattern: &str,
        result: &mut CanaryScanResult,
    ) {
        let pattern_lower = pattern.to_lowercase();

        for (line_num, line) in content.lines().enumerate() {
            if line.to_lowercase().contains(&pattern_lower) {
                // Truncate context if too long
                let context = if line.len() > 100 {
                    format!("{}...", &line[..97])
                } else {
                    line.to_string()
                };

                result.add_finding(CanaryFinding {
                    path: path.to_path_buf(),
                    pattern: pattern.to_string(),
                    line_number: Some(line_num + 1), // 1-indexed
                    context: Some(context),
                });

                // Only report first occurrence per pattern per file
                // to avoid flooding with duplicate findings
                break;
            }
        }
    }

    /// Get default paths to scan (shell history files)
    fn get_default_scan_paths(&self) -> Vec<PathBuf> {
        use super::history::ShellType;

        let mut paths = Vec::new();

        // Add all shell history files
        for shell in ShellType::all() {
            let history_path: Option<PathBuf> = shell.history_file_path();
            if let Some(history_path) = history_path {
                paths.push(history_path);
            }
        }

        paths
    }

    /// Get a reference to the config
    pub fn config(&self) -> &CanaryConfig {
        &self.config
    }
}
