//! Temporary files cleanup for nails-related artifacts
//!
//! This module provides [`TempFilesCleaner`] which removes temporary files
//! and directories matching nails-related patterns from configured directories.
//!
//! # Security
//!
//! - **Safety Checks**: REFUSES to clean system-critical directories (/, /etc, /home, etc.)
//! - **Pattern Matching**: Case-insensitive matching ensures all variations are caught
//! - **Best-Effort**: Continues on individual file failures, logs warnings
//!
//! # Example
//!
//! ```rust,ignore
//! use nails_core::{TempFilesCleaner, MockFilesystem};
//! use std::path::PathBuf;
//!
//! let fs = MockFilesystem::new();
//! let cleaner = TempFilesCleaner::new(fs)
//!     .with_temp_dirs(vec![PathBuf::from("/tmp")])
//!     .with_patterns(vec!["nails".to_string()]);
//!
//! let report = cleaner.clean()?;
//! for item in report {
//!     println!("{}", item);
//! }
//! ```
//!
//! *Note: This example is marked with `ignore` because it uses MockFilesystem
//! which is only available in test configuration. Real usage would use RealFilesystem.*

#[cfg(test)]
mod tests;

use crate::{Filesystem, NailsError, Result, output};
use std::path::{Path, PathBuf};

/// Forbidden paths that must never be cleaned
///
/// These paths are system-critical and cleaning them would be catastrophic.
/// This is a security requirement, not an optional feature.
const FORBIDDEN_PATHS: &[&str] = &[
    "/", "/etc", "/home", "/var", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/root", "/boot",
    "/dev", "/proc", "/sys", "/run", // Exception: /run/nails/* is allowed
];

/// Cleans temporary files matching nails-related patterns
///
/// TempFilesCleaner scans configured directories (default: /tmp) for
/// files and directories matching patterns (default: contains "nails")
/// and removes them.
///
/// # Security
///
/// - REFUSES to clean system-critical directories (/, /etc, /home, etc.)
/// - Case-insensitive pattern matching for thorough cleanup
/// - Best-effort removal - continues on individual failures
/// - Optional secure deletion for forensic resistance
///
/// # Generic Parameter
///
/// `F: Filesystem` - Abstracted filesystem operations for testability
pub struct TempFilesCleaner<F: Filesystem> {
    filesystem: F,
    temp_dirs: Vec<PathBuf>,
    patterns: Vec<String>,
    /// Use secure deletion (overwrite before delete)
    pub(crate) secure_delete: bool,
}

impl<F: Filesystem> TempFilesCleaner<F> {
    /// Create a new TempFilesCleaner with default settings
    ///
    /// Default temp_dirs: ["/tmp"]
    /// Default patterns: ["nails"]
    /// Default secure_delete: false
    pub fn new(filesystem: F) -> Self {
        Self {
            filesystem,
            temp_dirs: vec![PathBuf::from("/tmp")],
            patterns: vec!["nails".to_string()],
            secure_delete: false,
        }
    }

    /// Set custom temp directories to scan (replaces defaults)
    pub fn with_temp_dirs(mut self, dirs: Vec<PathBuf>) -> Self {
        self.temp_dirs = dirs;
        self
    }

    /// Set custom patterns to match (replaces defaults)
    pub fn with_patterns(mut self, patterns: Vec<String>) -> Self {
        self.patterns = patterns;
        self
    }

    /// Enable or disable secure deletion
    ///
    /// When enabled, files are securely deleted (overwritten with zeros,
    /// random data, then zeros again) before being removed.
    pub fn with_secure_delete(mut self, enabled: bool) -> Self {
        self.secure_delete = enabled;
        self
    }

    /// Validate that a temp directory is safe to clean
    ///
    /// # Security
    ///
    /// Returns Err if the directory is in the forbidden list.
    /// Special case: /run is forbidden but /run/nails is allowed.
    fn validate_temp_dir(&self, dir: &Path) -> Result<()> {
        let dir_str = dir.to_string_lossy();

        for forbidden in FORBIDDEN_PATHS {
            // Exact match or if dir equals forbidden path
            if dir_str == *forbidden {
                return Err(NailsError::InvalidArgument(format!(
                    "Refusing to clean system-critical directory: {}",
                    dir.display()
                )));
            }

            // Special case: /run is forbidden but /run/nails and /run/nails/* are allowed
            // Use exact match or path-with-slash to prevent false positives like /run/nails-evil
            if *forbidden == "/run"
                && (dir_str == "/run/nails" || dir_str.starts_with("/run/nails/"))
            {
                continue;
            }

            // Check if dir is under a forbidden path
            // Use path separator to avoid false positives like /tmp matching /
            // The "/" (root) case is special - everything starts with it
            // but we only reject if exact match (handled above)
            if *forbidden == "/" {
                continue; // Skip root for subdirectory check (exact match handled above)
            }

            // Check if path is a subdirectory of forbidden path
            // Add trailing slash to prevent false positives like /etc matching /etcetera
            let forbidden_with_slash = format!("{}/", forbidden);
            if dir_str.starts_with(&forbidden_with_slash) {
                return Err(NailsError::InvalidArgument(format!(
                    "Refusing to clean under system-critical path {}: {}",
                    forbidden,
                    dir.display()
                )));
            }
        }

        Ok(())
    }

    /// Check if a filename matches any configured pattern
    ///
    /// Uses case-insensitive substring matching.
    ///
    /// **Note:** This method is primarily for testing and validation.
    /// The actual pattern matching is performed by `Filesystem::find_files_with_pattern()`,
    /// which is trusted to return only matching files per the trait contract.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let cleaner = TempFilesCleaner::new(fs);
    /// assert!(cleaner.matches_pattern("nails-12345.lock"));
    /// assert!(cleaner.matches_pattern("NAILS-cache"));
    /// assert!(!cleaner.matches_pattern("unrelated.txt"));
    /// ```
    #[cfg(test)]
    pub(crate) fn matches_pattern(&self, filename: &str) -> bool {
        let filename_lower = filename.to_lowercase();
        self.patterns
            .iter()
            .any(|pattern| filename_lower.contains(&pattern.to_lowercase()))
    }

    /// Remove a file or directory
    ///
    /// Uses the filesystem abstraction to remove files or recursively remove directories.
    /// When secure_delete is enabled, uses secure deletion for better forensic resistance.
    fn remove_path(&self, path: &Path) -> Result<()> {
        if self.filesystem.is_directory(path)? {
            if self.secure_delete {
                self.filesystem.secure_delete_dir_all(path)
            } else {
                self.filesystem.remove_dir_all(path)
            }
        } else if self.secure_delete {
            self.filesystem.secure_delete(path)
        } else {
            self.filesystem.remove_file(path)
        }
    }

    /// Execute temp files cleanup
    ///
    /// Scans configured directories and removes files/dirs matching patterns.
    /// Uses best-effort approach - continues on individual failures.
    ///
    /// # Returns
    ///
    /// Vec<String> with descriptions of cleaned items.
    ///
    /// # Errors
    ///
    /// Returns Err if safety validation fails (system-critical directory).
    /// Individual file removal errors are logged but don't stop cleanup.
    pub fn clean(&self) -> Result<Vec<String>> {
        let mut cleaned = Vec::new();
        let mut errors = Vec::new();

        for temp_dir in &self.temp_dirs {
            // Safety check first - CRITICAL security requirement
            self.validate_temp_dir(temp_dir)?;

            // Find matching files for each pattern
            for pattern in &self.patterns {
                match self.filesystem.find_files_with_pattern(temp_dir, pattern) {
                    Ok(files) => {
                        for file in files {
                            // DESIGN DECISION: We trust Filesystem trait implementation
                            // find_files_with_pattern() is guaranteed to return only matching files
                            // No additional pattern verification needed here - that would violate DRY
                            // and suggest the trait contract is unclear.
                            //
                            // The Filesystem trait contract is:
                            // - MockFilesystem: Returns files explicitly set via mock_set_files_with_pattern
                            // - RealFilesystem: Performs actual filesystem search with pattern matching
                            // Both implementations ensure files match the pattern before returning.

                            match self.remove_path(&file) {
                                Ok(()) => {
                                    cleaned.push(format!("Removed {}", file.display()));
                                }
                                Err(e) => {
                                    errors.push(format!(
                                        "Failed to remove {}: {}",
                                        file.display(),
                                        e
                                    ));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        errors.push(format!("Failed to scan {}: {}", temp_dir.display(), e));
                    }
                }
            }
        }

        // Log errors as warnings (best-effort cleanup)
        for error in &errors {
            output::warn(error);
        }

        Ok(cleaned)
    }
}
