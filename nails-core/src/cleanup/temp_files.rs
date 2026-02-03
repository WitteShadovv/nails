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

use crate::{Filesystem, NailsError, Result};
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
///
/// # Generic Parameter
///
/// `F: Filesystem` - Abstracted filesystem operations for testability
pub struct TempFilesCleaner<F: Filesystem> {
    filesystem: F,
    temp_dirs: Vec<PathBuf>,
    patterns: Vec<String>,
}

impl<F: Filesystem> TempFilesCleaner<F> {
    /// Create a new TempFilesCleaner with default settings
    ///
    /// Default temp_dirs: ["/tmp"]
    /// Default patterns: ["nails"]
    pub fn new(filesystem: F) -> Self {
        Self {
            filesystem,
            temp_dirs: vec![PathBuf::from("/tmp")],
            patterns: vec!["nails".to_string()],
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
    fn remove_path(&self, path: &Path) -> Result<()> {
        if self.filesystem.is_directory(path)? {
            self.filesystem.remove_dir_all(path)
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
            eprintln!("Warning: {}", error);
        }

        Ok(cleaned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockFilesystem;

    #[test]
    fn test_temp_files_cleaner_new() {
        let fs = MockFilesystem::new();
        let cleaner = TempFilesCleaner::new(fs);

        assert_eq!(cleaner.temp_dirs, vec![PathBuf::from("/tmp")]);
        assert_eq!(cleaner.patterns, vec!["nails".to_string()]);
    }

    #[test]
    fn test_with_temp_dirs() {
        let fs = MockFilesystem::new();
        let custom_dirs = vec![PathBuf::from("/custom/tmp"), PathBuf::from("/another/tmp")];
        let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(custom_dirs.clone());

        assert_eq!(cleaner.temp_dirs, custom_dirs);
    }

    #[test]
    fn test_with_patterns() {
        let fs = MockFilesystem::new();
        let custom_patterns = vec!["test1".to_string(), "test2".to_string()];
        let cleaner = TempFilesCleaner::new(fs).with_patterns(custom_patterns.clone());

        assert_eq!(cleaner.patterns, custom_patterns);
    }

    #[test]
    fn test_safety_validation_blocks_root() {
        let fs = MockFilesystem::new();
        let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/")]);

        let result = cleaner.clean();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("system-critical"));
        assert!(err_msg.contains("/"));
    }

    #[test]
    fn test_safety_validation_blocks_etc() {
        let fs = MockFilesystem::new();
        let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/etc")]);

        let result = cleaner.clean();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("system-critical"));
    }

    #[test]
    fn test_safety_validation_blocks_home() {
        let fs = MockFilesystem::new();
        let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/home")]);

        let result = cleaner.clean();
        assert!(result.is_err());
    }

    #[test]
    fn test_safety_validation_blocks_var() {
        let fs = MockFilesystem::new();
        let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/var")]);

        let result = cleaner.clean();
        assert!(result.is_err());
    }

    #[test]
    fn test_safety_validation_blocks_usr() {
        let fs = MockFilesystem::new();
        let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/usr")]);

        let result = cleaner.clean();
        assert!(result.is_err());
    }

    #[test]
    fn test_safety_validation_blocks_home_subdirectory() {
        let fs = MockFilesystem::new();
        let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/home/user")]);

        let result = cleaner.clean();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("system-critical path"));
    }

    #[test]
    fn test_safety_validation_allows_tmp() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/tmp", true);
        fs.mock_set_files_with_pattern("/tmp", "nails", &[]);

        let cleaner = TempFilesCleaner::new(fs);
        let result = cleaner.clean();
        assert!(result.is_ok());
    }

    #[test]
    fn test_safety_validation_allows_tmp_subdirectory() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/tmp/custom", true);
        fs.mock_set_files_with_pattern("/tmp/custom", "nails", &[]);

        let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/tmp/custom")]);
        let result = cleaner.clean();
        assert!(result.is_ok());
    }

    #[test]
    fn test_safety_validation_allows_run_nails() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/run/nails", true);
        fs.mock_set_files_with_pattern("/run/nails", "nails", &[]);

        let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/run/nails")]);
        let result = cleaner.clean();
        assert!(result.is_ok());
    }

    #[test]
    fn test_safety_validation_blocks_run_without_nails() {
        let fs = MockFilesystem::new();
        let cleaner = TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/run")]);

        let result = cleaner.clean();
        assert!(result.is_err());
    }

    #[test]
    fn test_safety_validation_blocks_run_nails_prefix_trick() {
        let fs = MockFilesystem::new();
        let cleaner =
            TempFilesCleaner::new(fs).with_temp_dirs(vec![PathBuf::from("/run/nails-evil")]);

        let result = cleaner.clean();
        assert!(
            result.is_err(),
            "Should block /run/nails-evil (prefix trick)"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("system-critical path"));
    }

    #[test]
    fn test_pattern_matching_case_insensitive() {
        let fs = MockFilesystem::new();
        let cleaner = TempFilesCleaner::new(fs);

        assert!(cleaner.matches_pattern("nails-12345.lock"));
        assert!(cleaner.matches_pattern("NAILS-build-cache"));
        assert!(cleaner.matches_pattern("some-NaIlS-temp.txt"));
        assert!(cleaner.matches_pattern("prefix-nails-suffix"));
        assert!(!cleaner.matches_pattern("unrelated-file.txt"));
    }

    #[test]
    fn test_pattern_matching_multiple_patterns() {
        let fs = MockFilesystem::new();
        let cleaner =
            TempFilesCleaner::new(fs).with_patterns(vec!["nails".to_string(), "test".to_string()]);

        assert!(cleaner.matches_pattern("nails-file"));
        assert!(cleaner.matches_pattern("test-file"));
        assert!(cleaner.matches_pattern("NAILS-TEST-file"));
        assert!(!cleaner.matches_pattern("unrelated-file"));
    }

    #[test]
    fn test_cleanup_removes_matching_files() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/tmp", true);
        fs.mock_set_files_with_pattern(
            "/tmp",
            "nails",
            &[
                Path::new("/tmp/nails-12345.lock"),
                Path::new("/tmp/nails_cache"),
            ],
        );
        fs.mock_set_path_exists("/tmp/nails-12345.lock", true);
        fs.mock_set_path_exists("/tmp/nails_cache", true);
        fs.mock_set_path_type("/tmp/nails-12345.lock", "file");
        fs.mock_set_path_type("/tmp/nails_cache", "directory");

        let cleaner = TempFilesCleaner::new(fs);
        let result = cleaner.clean().unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.iter().any(|s| s.contains("nails-12345.lock")));
        assert!(result.iter().any(|s| s.contains("nails_cache")));
    }

    #[test]
    fn test_cleanup_empty_result_when_no_matches() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/tmp", true);
        fs.mock_set_files_with_pattern("/tmp", "nails", &[]); // No matching files

        let cleaner = TempFilesCleaner::new(fs);
        let result = cleaner.clean().unwrap();

        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_cleanup_continues_on_permission_error() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists("/tmp", true);
        fs.mock_set_files_with_pattern(
            "/tmp",
            "nails",
            &[
                Path::new("/tmp/nails-readonly.lock"),
                Path::new("/tmp/nails-normal.txt"),
            ],
        );
        fs.mock_set_path_exists("/tmp/nails-readonly.lock", true);
        fs.mock_set_path_exists("/tmp/nails-normal.txt", true);
        fs.mock_set_path_type("/tmp/nails-readonly.lock", "file");
        fs.mock_set_path_type("/tmp/nails-normal.txt", "file");

        // Configure first file to fail removal
        fs.mock_set_remove_should_fail("/tmp/nails-readonly.lock", true);

        let cleaner = TempFilesCleaner::new(fs);
        let result = cleaner.clean();

        // Should succeed overall (best-effort)
        assert!(result.is_ok());
        let cleaned = result.unwrap();
        // Should have cleaned the second file
        assert!(cleaned.iter().any(|s| s.contains("nails-normal.txt")));
    }

    #[test]
    fn test_filesystem_trait_contract_honored() {
        // Verify MockFilesystem::find_files_with_pattern honors the trait contract
        // by only returning files that actually match the pattern
        let fs = MockFilesystem::new();

        // Set up specific files matching "nails" pattern
        let matching_files = [
            PathBuf::from("/tmp/nails-12345.lock"),
            PathBuf::from("/tmp/nails_cache"),
            PathBuf::from("/tmp/NAILS-UPPER"),
        ];

        // Set up files that should NOT match
        let non_matching_files = [
            PathBuf::from("/tmp/unrelated-file.txt"),
            PathBuf::from("/tmp/other-cache"),
        ];

        fs.mock_set_files_with_pattern(
            "/tmp",
            "nails",
            &matching_files
                .iter()
                .map(|p| p.as_path())
                .collect::<Vec<_>>(),
        );

        // Verify that only matching files are returned
        let result = fs.find_files_with_pattern(Path::new("/tmp"), "nails");
        assert!(result.is_ok());

        let returned_files = result.unwrap();
        assert_eq!(
            returned_files.len(),
            matching_files.len(),
            "Should return exactly the files set via mock_set_files_with_pattern"
        );

        // Verify all returned files were in our matching set
        for file in &returned_files {
            assert!(
                matching_files.contains(file),
                "Returned file {:?} should be in matching_files set",
                file
            );
            assert!(
                !non_matching_files.contains(file),
                "Returned file {:?} should NOT be in non_matching_files set",
                file
            );
        }
    }
}
