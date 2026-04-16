use super::MockFilesystem;
use std::path::{Path, PathBuf};

impl MockFilesystem {
    /// Set whether a write operation should fail for a specific path (Story 5.5)
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
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
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
    /// use nails_core::filesystem::MockFilesystem;
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

    /// Set whether a file/directory removal should fail (Story 5.3)
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
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
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

    /// Set whether a directory can be created (parent exists and is writable)
    ///
    /// Helper for testing directory creation scenarios in verify_mount_preconditions().
    /// This sets up the parent directory to exist and be writable, allowing the test
    /// to verify that a directory can be created when it doesn't exist.
    ///
    /// # Arguments
    ///
    /// * `path` - Directory path that should be creatable
    /// * `creatable` - If true, parent exists and is writable; if false, parent not writable
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{MockFilesystem, verify_mount_preconditions};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_path_exists("/", true);
    ///
    /// // Set parent directory writable, upper doesn't exist but can be created
    /// fs.mock_set_directory_creatable("/mnt/hidden/upper", true);
    /// fs.mock_set_directory_creatable("/mnt/hidden/work", true);
    ///
    /// let result = verify_mount_preconditions(
    ///     &fs,
    ///     Path::new("/"),
    ///     Path::new("/mnt/hidden/upper"),
    ///     Path::new("/mnt/hidden/work"),
    ///     Path::new("/home")
    /// );
    /// assert!(result.is_ok());
    /// ```
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
    /// use nails_core::filesystem::MockFilesystem;
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

    /// Set the list of root directories for enumeration (Story 14.10)
    ///
    /// Configures the list of real directories under `/` that will be returned
    /// by `enumerate_root_directories()`. Symlinks should be set separately
    /// via `mock_set_root_symlinks()`.
    ///
    /// # Arguments
    ///
    /// * `dirs` - List of real directory paths to return
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_root_directories(vec![
    ///     PathBuf::from("/home"),
    ///     PathBuf::from("/etc"),
    ///     PathBuf::from("/var"),
    /// ]);
    ///
    /// let dirs = fs.enumerate_root_directories().unwrap();
    /// assert_eq!(dirs.len(), 3);
    /// ```
    pub fn mock_set_root_directories(&self, dirs: Vec<PathBuf>) {
        *self
            .root_directories
            .lock()
            .expect("MockFilesystem mutex poisoned") = dirs;
    }

    /// Set the list of symlinks under `/` (Story 14.10)
    ///
    /// Configures which paths under `/` are symlinks (not real directories).
    /// These will be excluded from `enumerate_root_directories()` results.
    ///
    /// # Arguments
    ///
    /// * `symlinks` - List of symlink paths to mark
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::PathBuf;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_root_symlinks(vec![
    ///     PathBuf::from("/bin"),  // -> /nix/store/...
    ///     PathBuf::from("/lib"),  // -> /nix/store/...
    /// ]);
    ///
    /// // These won't appear in enumerate_root_directories()
    /// ```
    pub fn mock_set_root_symlinks(&self, symlinks: Vec<PathBuf>) {
        *self
            .root_symlinks
            .lock()
            .expect("MockFilesystem mutex poisoned") = symlinks;
    }
}
