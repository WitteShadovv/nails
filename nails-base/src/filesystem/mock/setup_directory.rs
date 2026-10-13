// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::MockFilesystem;
use std::path::{Path, PathBuf};

impl MockFilesystem {
    /// Set whether a write operation should fail for a specific path
    ///
    /// This is useful for testing cleanup failure scenarios where file writes fail.
    ///
    /// # Arguments
    ///
    /// * `path` - File path that should fail to write
    /// * `should_fail` - If true, write_file_content for this path will fail
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_base::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_write_should_fail("/root/.bash_history", true);
    ///
    /// // This will now fail
    /// let result = fs.write_file_content(Path::new("/root/.bash_history"), "content");
    /// assert!(result.is_err());
    /// ```
    pub fn mock_set_write_should_fail(&self, path: &str, should_fail: bool) {
        let mut fail_set = self
            .write_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned");
        if should_fail {
            fail_set.insert(PathBuf::from(path));
        } else {
            fail_set.remove(&PathBuf::from(path));
        }
    }

    /// Set mock results for pattern-based file searches
    ///
    /// # Arguments
    ///
    /// * `dir` - Directory that was searched
    /// * `pattern` - Pattern that was searched for
    /// * `files` - Files to return as search results
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_base::filesystem::MockFilesystem;
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_files_with_pattern("/tmp", "nails", &[
    ///     Path::new("/tmp/nails.log"),
    ///     Path::new("/tmp/nails.toml"),
    /// ]);
    /// ```
    pub fn mock_set_files_with_pattern(&self, dir: &str, pattern: &str, files: &[&Path]) {
        let mut pattern_results = self
            .files_with_pattern
            .lock()
            .expect("MockFilesystem mutex poisoned");
        let key = (PathBuf::from(dir), pattern.to_string());
        pattern_results.insert(key, files.iter().map(|p| p.to_path_buf()).collect());
    }

    /// Set whether a file/directory removal should fail
    ///
    /// This is useful for testing error handling in cleanup operations.
    ///
    /// # Arguments
    ///
    /// * `path` - Path that should fail removal
    /// * `should_fail` - If true, remove_file/remove_dir_all will fail for this path
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_base::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_path_exists("/tmp/readonly.lock", true);
    /// fs.mock_set_remove_should_fail("/tmp/readonly.lock", true);
    ///
    /// // This will now fail
    /// let result = fs.remove_file(Path::new("/tmp/readonly.lock"));
    /// assert!(result.is_err());
    /// ```
    pub fn mock_set_remove_should_fail(&self, path: &str, should_fail: bool) {
        let mut fail_set = self
            .remove_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned");
        if should_fail {
            fail_set.insert(PathBuf::from(path));
        } else {
            fail_set.remove(&PathBuf::from(path));
        }
    }

    /// Set whether a directory can be created: its parent exists and is
    /// writable (`creatable`), or its parent is not writable.
    pub fn mock_set_directory_creatable(&self, path: &str, creatable: bool) {
        let path_buf = PathBuf::from(path);
        if let Some(parent) = path_buf.parent() {
            let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
            let parent_entry = paths.entry(parent.to_path_buf()).or_default();
            parent_entry.exists = true;
            parent_entry.is_directory = true;
            parent_entry.is_writable = creatable;
        }
    }

    /// Set mock directory contents for list_directory tests
    ///
    /// # Arguments
    ///
    /// * `dir` - Directory path
    /// * `contents` - List of paths that should be returned by list_directory
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_base::filesystem::MockFilesystem;
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_directory_contents(
    ///     &PathBuf::from("/mnt/hidden/logs"),
    ///     vec![
    ///         PathBuf::from("/mnt/hidden/logs/nails.log"),
    ///         PathBuf::from("/mnt/hidden/logs/nails.log.1"),
    ///     ]
    /// );
    /// ```
    pub fn mock_set_directory_contents(&self, dir: &Path, contents: Vec<PathBuf>) {
        self.directory_contents
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(dir.to_path_buf(), contents);
    }
}
