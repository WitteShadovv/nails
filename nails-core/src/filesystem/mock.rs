//! Mock filesystem for testing (no root privileges required)
//!
//! Uses in-memory state tracking to simulate filesystem operations.
//! All operations are thread-safe via Arc<Mutex<_>>.

use super::{Filesystem, MountInfo, verify_mount_preconditions};
use crate::{NailsError, Result};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Path metadata for MockFilesystem
#[derive(Debug, Clone)]
struct PathInfo {
    exists: bool,
    is_directory: bool,
    is_symlink: bool,
    is_readable: bool,
    is_writable: bool,
    free_space: u64,
}

impl Default for PathInfo {
    fn default() -> Self {
        Self {
            exists: false,
            is_directory: false,
            is_symlink: false,
            is_readable: true,
            is_writable: true,
            free_space: u64::MAX,
        }
    }
}

/// Operation log entries for MockFilesystem (test assertions)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockOp {
    MountOverlay { target: PathBuf },
    WriteFile { path: PathBuf },
    CopyTree { src: PathBuf, dst: PathBuf },
}

/// Mock filesystem for testing (no root privileges required)
///
/// Uses in-memory state tracking to simulate filesystem operations.
/// All operations are thread-safe via Arc<Mutex<_>>.
///
/// # Design
///
/// - `mounted`: HashSet of currently mounted paths
/// - `swap_enabled`: Boolean flag for swap status
/// - `paths`: HashMap storing path metadata
/// - `busy`: HashSet of paths marked as busy (open files)
/// - `nixos_profiles`: HashSet of built profile names
/// - `current_profile`: Currently active profile
/// - `tmpfs_mounts`: HashSet of paths with tmpfs mounted (Story 4.11)
/// - `bind_mounts`: HashMap tracking bind mount source→target relationships
///
/// # Thread Safety & Clone Behavior
///
/// All internal state is wrapped in Arc<Mutex<_>> to enable:
/// - Safe sharing across threads
/// - Clone implementation (shares state between clones)
/// - Parallel test execution
///
/// **Note:** Clones share the same underlying state. Modifications via one
/// clone affect all clones. This is intentional for test ergonomics.
#[derive(Debug, Clone)]
pub struct MockFilesystem {
    mounted: Arc<Mutex<HashSet<PathBuf>>>,
    swap_enabled: Arc<Mutex<bool>>,
    paths: Arc<Mutex<HashMap<PathBuf, PathInfo>>>,
    busy: Arc<Mutex<HashSet<PathBuf>>>,
    nixos_profiles: Arc<Mutex<HashSet<String>>>,
    current_profile: Arc<Mutex<Option<String>>>,
    mount_should_fail: Arc<Mutex<HashSet<PathBuf>>>, // Paths that should fail to mount
    unmount_should_fail: Arc<Mutex<HashSet<PathBuf>>>, // Paths that should fail to unmount (both graceful and force)
    unmount_graceful_fails: Arc<Mutex<HashSet<PathBuf>>>, // Paths where graceful unmount fails but force succeeds
    nails_process_running: Arc<Mutex<bool>>,              // Whether nails processes are running
    file_contents: Arc<Mutex<HashMap<PathBuf, String>>>,  // Mock file contents
    #[allow(clippy::type_complexity)]
    files_with_pattern: Arc<Mutex<HashMap<(PathBuf, String), Vec<PathBuf>>>>, // Mock pattern search results
    mounted_overlays: Arc<Mutex<HashMap<PathBuf, MountInfo>>>, // Track overlay mount metadata
    tmpfs_mounts: Arc<Mutex<HashSet<PathBuf>>>,                // Track tmpfs mounts (Story 4.11)
    bind_mounts: Arc<Mutex<HashMap<PathBuf, PathBuf>>>,        // Track bind mounts: target → source
    written_files: Arc<Mutex<HashMap<PathBuf, String>>>,       // Track files written (Story 5.2)
    remove_should_fail: Arc<Mutex<HashSet<PathBuf>>>, // Track paths that should fail removal (Story 5.3)
    directory_contents: Arc<Mutex<HashMap<PathBuf, Vec<PathBuf>>>>, // Track directory contents for list_directory (Story 5.4)
    write_should_fail: Arc<Mutex<HashSet<PathBuf>>>, // Track paths that should fail write (Story 5.5)
    rename_should_fail: Arc<Mutex<HashSet<PathBuf>>>, // Track paths that should fail rename (Story 9.2)
    explicit_file_sizes: Arc<Mutex<HashSet<PathBuf>>>, // Track paths with explicitly set file sizes (Story 9.2)
    modified_times: Arc<Mutex<HashMap<PathBuf, chrono::DateTime<chrono::Utc>>>>, // Track mock modification times (Story 9.2)
    permissions: Arc<Mutex<HashMap<PathBuf, u32>>>, // Track Unix permissions set on paths (Story 14.4)
    root_directories: Arc<Mutex<Vec<PathBuf>>>, // Track root directory list for enumeration (Story 14.10)
    root_symlinks: Arc<Mutex<Vec<PathBuf>>>,    // Track symlinks under / (Story 14.10)
    symlink_targets: Arc<Mutex<HashMap<PathBuf, PathBuf>>>, // Track symlink targets for create_symlink (Story 15.2)
    symlink_support: Arc<Mutex<HashMap<PathBuf, bool>>>,    // Track symlink support per directory
    filesystem_types: Arc<Mutex<HashMap<PathBuf, String>>>, // Track filesystem types at mount points
    op_log: Arc<Mutex<Vec<MockOp>>>,                        // Operation log for test assertions
    copy_tree_should_fail: Arc<Mutex<HashSet<PathBuf>>>, // Track paths where copy_tree should fail
    directory_sizes: Arc<Mutex<HashMap<PathBuf, u64>>>, // Track directory sizes for get_directory_size
    #[allow(clippy::type_complexity)]
    submount_sources: Arc<Mutex<HashMap<PathBuf, Vec<(PathBuf, PathBuf)>>>>, // Track submount sources per target for find_submount_sources
}

impl MockFilesystem {
    /// Create a new MockFilesystem with empty state
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::MockFilesystem;
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// assert!(fs.get_mounted_paths().is_empty());
    ///
    /// // Set up test state
    /// fs.mock_set_mounted(Path::new("/home"), true);
    /// assert_eq!(fs.get_mounted_paths().len(), 1);
    ///
    /// // Reset clears state
    /// fs.reset();
    /// assert!(fs.get_mounted_paths().is_empty());
    /// ```
    pub fn new() -> Self {
        Self {
            mounted: Arc::new(Mutex::new(HashSet::new())),
            swap_enabled: Arc::new(Mutex::new(false)),
            paths: Arc::new(Mutex::new(HashMap::new())),
            busy: Arc::new(Mutex::new(HashSet::new())),
            nixos_profiles: Arc::new(Mutex::new(HashSet::new())),
            current_profile: Arc::new(Mutex::new(None)),
            mount_should_fail: Arc::new(Mutex::new(HashSet::new())),
            unmount_should_fail: Arc::new(Mutex::new(HashSet::new())),
            unmount_graceful_fails: Arc::new(Mutex::new(HashSet::new())),
            nails_process_running: Arc::new(Mutex::new(false)),
            file_contents: Arc::new(Mutex::new(HashMap::new())),
            files_with_pattern: Arc::new(Mutex::new(HashMap::new())),
            mounted_overlays: Arc::new(Mutex::new(HashMap::new())),
            tmpfs_mounts: Arc::new(Mutex::new(HashSet::new())),
            bind_mounts: Arc::new(Mutex::new(HashMap::new())),
            written_files: Arc::new(Mutex::new(HashMap::new())),
            remove_should_fail: Arc::new(Mutex::new(HashSet::new())),
            directory_contents: Arc::new(Mutex::new(HashMap::new())),
            write_should_fail: Arc::new(Mutex::new(HashSet::new())),
            rename_should_fail: Arc::new(Mutex::new(HashSet::new())),
            explicit_file_sizes: Arc::new(Mutex::new(HashSet::new())),
            modified_times: Arc::new(Mutex::new(HashMap::new())),
            permissions: Arc::new(Mutex::new(HashMap::new())),
            root_directories: Arc::new(Mutex::new(Vec::new())),
            root_symlinks: Arc::new(Mutex::new(Vec::new())),
            symlink_targets: Arc::new(Mutex::new(HashMap::new())),
            symlink_support: Arc::new(Mutex::new(HashMap::new())),
            filesystem_types: Arc::new(Mutex::new(HashMap::new())),
            op_log: Arc::new(Mutex::new(Vec::new())),
            copy_tree_should_fail: Arc::new(Mutex::new(HashSet::new())),
            directory_sizes: Arc::new(Mutex::new(HashMap::new())),
            submount_sources: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Reset all internal state to empty
    ///
    /// Useful for test cleanup between test cases.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::MockFilesystem;
    /// use std::path::Path;
    ///
    /// let mut fs = MockFilesystem::new();
    /// fs.mock_set_mounted(Path::new("/home"), true);
    /// fs.reset();
    /// assert!(fs.get_mounted_paths().is_empty());
    /// ```
    pub fn reset(&self) {
        self.mounted.lock().unwrap().clear();
        *self.swap_enabled.lock().unwrap() = false;
        self.paths.lock().unwrap().clear();
        self.busy.lock().unwrap().clear();
        self.nixos_profiles.lock().unwrap().clear();
        self.current_profile.lock().unwrap().take();
        self.mount_should_fail.lock().unwrap().clear();
        self.unmount_should_fail.lock().unwrap().clear();
        self.mounted_overlays.lock().unwrap().clear();
        self.tmpfs_mounts.lock().unwrap().clear();
        self.bind_mounts.lock().unwrap().clear();
        self.written_files.lock().unwrap().clear();
        self.remove_should_fail.lock().unwrap().clear();
        self.directory_contents.lock().unwrap().clear();
        self.write_should_fail.lock().unwrap().clear();
        self.rename_should_fail.lock().unwrap().clear();
        self.explicit_file_sizes.lock().unwrap().clear();
        self.modified_times.lock().unwrap().clear();
        self.permissions.lock().unwrap().clear();
        self.symlink_targets.lock().unwrap().clear();
        self.symlink_support.lock().unwrap().clear();
        self.op_log.lock().unwrap().clear();
        self.copy_tree_should_fail.lock().unwrap().clear();
        self.directory_sizes.lock().unwrap().clear();
        self.submount_sources.lock().unwrap().clear();
    }

    // ========================================================================
    // Test Helper Methods (for setting up mock state)
    // ========================================================================

    /// Set whether a path is mounted
    pub fn mock_set_mounted(&self, path: &Path, mounted: bool) {
        let mut mounts = self.mounted.lock().unwrap();
        if mounted {
            mounts.insert(path.to_path_buf());
        } else {
            mounts.remove(path);
        }
    }

    /// Set whether a path is busy (has open files)
    pub fn mock_set_busy(&self, path: &Path, busy: bool) {
        let mut busy_set = self.busy.lock().unwrap();
        if busy {
            busy_set.insert(path.to_path_buf());
        } else {
            busy_set.remove(path);
        }
    }

    /// Set whether swap is enabled
    pub fn mock_set_swap_enabled(&self, enabled: bool) {
        *self.swap_enabled.lock().unwrap() = enabled;
    }

    /// Set whether a path exists
    pub fn mock_set_path_exists(&self, path: &str, exists: bool) {
        let mut paths = self.paths.lock().unwrap();
        let entry = paths.entry(PathBuf::from(path)).or_default();
        entry.exists = exists;
    }

    /// Set a path's type (directory or file)
    pub fn mock_set_path_type(&self, path: &str, type_str: &str) {
        let mut paths = self.paths.lock().unwrap();
        let entry = paths.entry(PathBuf::from(path)).or_default();
        entry.exists = true;
        entry.is_directory = type_str == "directory";
    }

    /// Set whether a path is writable
    pub fn mock_set_writable(&self, path: &str, writable: bool) {
        let mut paths = self.paths.lock().unwrap();
        let entry = paths.entry(PathBuf::from(path)).or_default();
        entry.is_writable = writable;
    }

    /// Set whether a path is readable
    pub fn mock_set_readable(&self, path: &str, readable: bool) {
        let mut paths = self.paths.lock().unwrap();
        let entry = paths.entry(PathBuf::from(path)).or_default();
        entry.is_readable = readable;
    }

    /// Set whether a path is a symbolic link
    pub fn mock_set_is_symlink(&self, path: &str, is_symlink: bool) {
        let mut paths = self.paths.lock().unwrap();
        let entry = paths.entry(PathBuf::from(path)).or_default();
        entry.exists = true;
        entry.is_symlink = is_symlink;
    }

    /// Set whether a directory's filesystem supports symbolic links
    pub fn mock_set_supports_symlinks(&self, path: &Path, supports: bool) {
        self.symlink_support
            .lock()
            .unwrap()
            .insert(path.to_path_buf(), supports);
    }

    /// Set the filesystem type for a mount point (e.g., "vfat", "ext4", "tmpfs")
    pub fn mock_set_filesystem_type(&self, path: &Path, fstype: &str) {
        self.filesystem_types
            .lock()
            .unwrap()
            .insert(path.to_path_buf(), fstype.to_string());
    }

    /// Set whether copy_tree should fail for a source path
    pub fn mock_set_copy_tree_should_fail(&self, src: &Path) {
        self.copy_tree_should_fail
            .lock()
            .unwrap()
            .insert(src.to_path_buf());
    }

    /// Set the reported size for a directory
    pub fn mock_set_directory_size(&self, path: &Path, size: u64) {
        self.directory_sizes
            .lock()
            .unwrap()
            .insert(path.to_path_buf(), size);
    }

    /// Set mock submount sources for a target directory
    pub fn mock_set_submount_sources(&self, target: &Path, sources: Vec<(PathBuf, PathBuf)>) {
        self.submount_sources
            .lock()
            .unwrap()
            .insert(target.to_path_buf(), sources);
    }

    /// Set free space for a path
    pub fn mock_set_free_space(&self, path: &Path, bytes: u64) {
        let mut paths = self.paths.lock().unwrap();
        let entry = paths.entry(path.to_path_buf()).or_default();
        entry.free_space = bytes;
    }

    /// Set whether a NixOS profile exists
    pub fn mock_set_nixos_profile_exists(&self, profile: &str, exists: bool) {
        let mut profiles = self.nixos_profiles.lock().unwrap();
        if exists {
            profiles.insert(profile.to_string());
        } else {
            profiles.remove(profile);
        }
    }

    /// Set whether a mount operation should fail for a specific path
    ///
    /// This is useful for testing rollback scenarios where mount operations fail.
    ///
    /// # Arguments
    ///
    /// * `path` - Target mount path that should fail
    /// * `should_fail` - If true, mount operations to this path will fail
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_mount_should_fail("/home", true);
    ///
    /// // This will now fail
    /// let result = fs.mount_overlay(
    ///     &[Path::new("/")],
    ///     Path::new("/mnt/hidden/upper"),
    ///     Path::new("/mnt/hidden/work"),
    ///     Path::new("/home")
    /// );
    /// assert!(result.is_err());
    /// ```
    pub fn mock_set_mount_should_fail(&self, path: &str, should_fail: bool) {
        let mut fail_set = self.mount_should_fail.lock().unwrap();
        if should_fail {
            fail_set.insert(PathBuf::from(path));
        } else {
            fail_set.remove(&PathBuf::from(path));
        }
    }

    /// Set whether an unmount operation should fail for a specific path
    ///
    /// This is useful for testing deactivation rollback scenarios where unmount operations fail.
    ///
    /// # Arguments
    ///
    /// * `path` - Target mount path that should fail to unmount
    /// * `should_fail` - If true, unmount operations for this path will fail
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    ///
    /// // Set up a mounted overlay
    /// fs.mock_set_mounted(Path::new("/home"), true);
    ///
    /// // Configure unmount to fail
    /// fs.mock_set_unmount_should_fail("/home", true);
    ///
    /// // This will now fail
    /// let result = fs.unmount(Path::new("/home"), false);
    /// assert!(result.is_err());
    /// ```
    pub fn mock_set_unmount_should_fail(&self, path: &str, should_fail: bool) {
        let mut fail_set = self.unmount_should_fail.lock().unwrap();
        if should_fail {
            fail_set.insert(PathBuf::from(path));
        } else {
            fail_set.remove(&PathBuf::from(path));
        }
    }

    /// Configure graceful unmount to fail for specific paths (force unmount will succeed)
    ///
    /// This is useful for testing the graceful-fail-then-force-succeed path in rollback.
    ///
    /// # Arguments
    ///
    /// * `path` - Path that should fail graceful unmount
    /// * `should_fail` - If true, graceful unmount will fail (force will succeed)
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_mounted(Path::new("/home"), true);
    ///
    /// // Configure graceful to fail, force to succeed
    /// fs.mock_set_unmount_graceful_fails("/home", true);
    ///
    /// // Graceful unmount fails
    /// let graceful_result = fs.unmount(Path::new("/home"), false);
    /// assert!(graceful_result.is_err());
    ///
    /// // Force unmount succeeds
    /// let force_result = fs.unmount(Path::new("/home"), true);
    /// assert!(force_result.is_ok());
    /// ```
    pub fn mock_set_unmount_graceful_fails(&self, path: &str, should_fail: bool) {
        let mut fail_set = self.unmount_graceful_fails.lock().unwrap();
        if should_fail {
            fail_set.insert(PathBuf::from(path));
        } else {
            fail_set.remove(&PathBuf::from(path));
        }
    }

    /// Set whether nails processes are running
    ///
    /// # Arguments
    ///
    /// * `running` - If true, nails_process_running() will return true
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_nails_process_running(true);
    /// assert!(fs.nails_process_running().unwrap());
    /// ```
    pub fn mock_set_nails_process_running(&self, running: bool) {
        let mut is_running = self.nails_process_running.lock().unwrap();
        *is_running = running;
    }

    /// Set mock file contents for reading
    ///
    /// # Arguments
    ///
    /// * `path` - File path
    /// * `content` - Content to return when read_file_content is called
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_file_content("/root/.bash_history", "nails activate\nls\n");
    /// let content = fs.read_file_content(Path::new("/root/.bash_history")).unwrap();
    /// assert!(content.contains("nails"));
    /// ```
    pub fn mock_set_file_content(&self, path: &str, content: &str) {
        let mut contents = self.file_contents.lock().unwrap();
        contents.insert(PathBuf::from(path), content.to_string());
    }

    /// Set mock file size for file_size() tests (Story 9.2)
    ///
    /// Sets the size that will be returned by file_size() for a specific path.
    /// Note: If file content is also set via mock_set_file_content(), the content
    /// length takes precedence over this size value.
    ///
    /// # Arguments
    ///
    /// * `path` - File path
    /// * `size` - Size in bytes to return from file_size()
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
    /// fs.mock_set_file_size("/mnt/hidden/logs/nails.log", 10485760); // 10MB
    ///
    /// let size = fs.file_size(Path::new("/mnt/hidden/logs/nails.log")).unwrap();
    /// assert_eq!(size, 10485760);
    /// ```
    pub fn mock_set_file_size(&self, path: &str, size: u64) {
        let mut paths = self.paths.lock().unwrap();
        let entry = paths.entry(PathBuf::from(path)).or_default();
        entry.exists = true;
        entry.free_space = size; // Reuse free_space field to store file size
        drop(paths);

        // Track that this path's size was explicitly set
        self.explicit_file_sizes
            .lock()
            .unwrap()
            .insert(PathBuf::from(path));
    }

    /// Set whether rename operations should fail for a specific path (Story 9.2)
    ///
    /// This is useful for testing rotation failure scenarios where file renames fail.
    ///
    /// # Arguments
    ///
    /// * `path` - File path that should fail to rename
    /// * `should_fail` - If true, rename_file for this path will fail with PermissionDenied
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_path_exists("/mnt/hidden/logs/nails.log", true);
    /// fs.mock_set_rename_should_fail("/mnt/hidden/logs/nails.log", true);
    ///
    /// // This will now fail with permission denied
    /// let result = fs.rename_file(
    ///     Path::new("/mnt/hidden/logs/nails.log"),
    ///     Path::new("/mnt/hidden/logs/nails.log.1")
    /// );
    /// assert!(result.is_err());
    /// ```
    pub fn mock_set_rename_should_fail(&self, path: &str, should_fail: bool) {
        let mut fails = self.rename_should_fail.lock().unwrap();
        if should_fail {
            fails.insert(PathBuf::from(path));
        } else {
            fails.remove(&PathBuf::from(path));
        }
    }

    /// Set the modification time for a file (Story 9.2)
    ///
    /// Allows tests to control file ages for timestamp-based log retention.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file
    /// * `modified_time` - Modification timestamp to return
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    /// use chrono::{Utc, Duration};
    ///
    /// let fs = MockFilesystem::new();
    /// let old_time = Utc::now() - Duration::days(10);
    /// fs.mock_set_modified_time(Path::new("/mnt/hidden/logs/nails.log.8"), old_time);
    ///
    /// // This file will now be considered 10 days old
    /// let modified = fs.modified_time(Path::new("/mnt/hidden/logs/nails.log.8")).unwrap();
    /// ```
    pub fn mock_set_modified_time(
        &self,
        path: &Path,
        modified_time: chrono::DateTime<chrono::Utc>,
    ) {
        let mut times = self.modified_times.lock().unwrap();
        times.insert(path.to_path_buf(), modified_time);
    }

    /// Get written file content for test verification (Story 5.2)
    ///
    /// Returns the content that was written to a file via write_file_content(),
    /// or None if the file was not written.
    pub fn get_written_content(&self, path: &Path) -> Option<String> {
        let written = self.written_files.lock().unwrap();
        written.get(path).cloned()
    }

    /// Get operation log for verifying call ordering in tests
    pub fn mock_ops(&self) -> Vec<MockOp> {
        self.op_log.lock().unwrap().clone()
    }

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
        let mut fail_set = self.write_should_fail.lock().unwrap();
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
        let mut pattern_results = self.files_with_pattern.lock().unwrap();
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
        let mut fail_set = self.remove_should_fail.lock().unwrap();
        if should_fail {
            fail_set.insert(PathBuf::from(path));
        } else {
            fail_set.remove(&PathBuf::from(path));
        }
    }

    /// Get list of currently mounted paths
    ///
    /// Useful for test assertions.
    pub fn get_mounted_paths(&self) -> Vec<PathBuf> {
        self.mounted.lock().unwrap().iter().cloned().collect()
    }

    /// Get mount info for a specific overlay
    ///
    /// Returns None if the target is not currently mounted as an overlay.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_path_exists("/", true);
    /// fs.mock_set_path_exists("/mnt/hidden/upper", true);
    /// fs.mock_set_path_exists("/mnt/hidden/work", true);
    ///
    /// fs.mount_overlay(
    ///     &[Path::new("/")],
    ///     Path::new("/mnt/hidden/upper"),
    ///     Path::new("/mnt/hidden/work"),
    ///     Path::new("/home")
    /// ).unwrap();
    ///
    /// let info = fs.mock_get_mount_info(Path::new("/home")).unwrap();
    /// assert_eq!(info.lower, Path::new("/"));
    /// assert_eq!(info.upper, Path::new("/mnt/hidden/upper"));
    /// ```
    pub fn mock_get_mount_info(&self, target: &Path) -> Option<MountInfo> {
        self.mounted_overlays.lock().unwrap().get(target).cloned()
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
    /// use nails_core::filesystem::{verify_mount_preconditions, MockFilesystem};
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
            // Set parent to exist and be writable (or not writable)
            let mut paths = self.paths.lock().unwrap();
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
            .unwrap()
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
        *self.root_directories.lock().unwrap() = dirs;
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
        *self.root_symlinks.lock().unwrap() = symlinks;
    }

    /// Get the permissions that were set on a path via `set_permissions`
    ///
    /// Returns `None` if no permissions were explicitly set on this path.
    pub fn mock_get_permissions(&self, path: &Path) -> Option<u32> {
        self.permissions.lock().unwrap().get(path).copied()
    }

    /// Get the symlink target recorded by `create_symlink` (Story 15.2)
    ///
    /// Returns `None` if no symlink was created at this path.
    pub fn mock_get_symlink_target(&self, link: &Path) -> Option<PathBuf> {
        self.symlink_targets.lock().unwrap().get(link).cloned()
    }
}

impl Default for MockFilesystem {
    fn default() -> Self {
        Self::new()
    }
}

impl Filesystem for MockFilesystem {
    fn mount_overlay(
        &self,
        lower: &[&Path],
        upper: &Path,
        work: &Path,
        target: &Path,
    ) -> Result<()> {
        // Check if this mount should fail (for testing rollback)
        let fail_set = self.mount_should_fail.lock().unwrap();
        if fail_set.contains(target) {
            return Err(NailsError::OverlayError(format!(
                "Mock mount failure for testing: {}",
                target.display()
            )));
        }
        drop(fail_set);

        if lower.is_empty() {
            return Err(NailsError::OverlayError(
                "mount_overlay requires at least one lower layer".to_string(),
            ));
        }

        // Verify all preconditions using the helper function (primary lower = lower[0])
        verify_mount_preconditions(self, lower[0], upper, work, target)?;

        // Create mount info with timestamp (store primary lower)
        let mount_info = MountInfo {
            lower: lower[0].to_path_buf(),
            upper: upper.to_path_buf(),
            work: work.to_path_buf(),
            target: target.to_path_buf(),
            mounted_at: chrono::Utc::now(),
        };

        // Add to mounted set and track mount info
        self.mounted.lock().unwrap().insert(target.to_path_buf());
        self.mounted_overlays
            .lock()
            .unwrap()
            .insert(target.to_path_buf(), mount_info);

        self.op_log.lock().unwrap().push(MockOp::MountOverlay {
            target: target.to_path_buf(),
        });

        Ok(())
    }

    fn unmount(&self, target: &Path, force: bool) -> Result<()> {
        // Check if this unmount should always fail (for testing rollback)
        let fail_set = self.unmount_should_fail.lock().unwrap();
        if fail_set.contains(target) {
            return Err(NailsError::UnmountError {
                path: target.to_path_buf(),
                reason: "Mock unmount failure for testing".to_string(),
            });
        }
        drop(fail_set);

        // Check if graceful unmount should fail (but force would succeed)
        let graceful_fail_set = self.unmount_graceful_fails.lock().unwrap();
        if graceful_fail_set.contains(target) && !force {
            return Err(NailsError::UnmountError {
                path: target.to_path_buf(),
                reason: "Mock graceful unmount failure (force would succeed)".to_string(),
            });
        }
        drop(graceful_fail_set);

        let mut mounts = self.mounted.lock().unwrap();

        // Idempotent: succeed if not mounted
        if !mounts.contains(target) {
            return Ok(());
        }

        // Check if busy
        let busy = self.busy.lock().unwrap();
        if busy.contains(target) && !force {
            return Err(NailsError::MountBusy {
                path: target.to_path_buf(),
                suggestion: "Use force=true to override or close open files".to_string(),
            });
        }
        drop(busy);

        // Remove from mounted set and overlays tracking
        mounts.remove(target);
        drop(mounts);
        self.mounted_overlays.lock().unwrap().remove(target);

        Ok(())
    }

    fn is_mounted(&self, target: &Path) -> Result<bool> {
        Ok(self.mounted.lock().unwrap().contains(target))
    }

    fn get_filesystem_type(&self, target: &Path) -> Result<Option<String>> {
        Ok(self.filesystem_types.lock().unwrap().get(target).cloned())
    }

    fn is_overlay_mounted(&self, target: &Path) -> Result<bool> {
        // In mock, all tracked mounts represent overlay mounts
        Ok(self.mounted.lock().unwrap().contains(target))
    }

    fn get_mount_info(&self, target: &Path) -> Option<MountInfo> {
        self.mounted_overlays.lock().unwrap().get(target).cloned()
    }

    fn swap_is_enabled(&self) -> Result<bool> {
        Ok(*self.swap_enabled.lock().unwrap())
    }

    fn swap_disable(&self) -> Result<()> {
        // Idempotent: succeed even if already disabled
        *self.swap_enabled.lock().unwrap() = false;
        Ok(())
    }

    fn path_exists(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().unwrap();
        Ok(paths.get(path).map(|info| info.exists).unwrap_or(false))
    }

    fn is_directory(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().unwrap();
        Ok(paths
            .get(path)
            .map(|info| info.is_directory)
            .unwrap_or(false))
    }

    fn is_symlink(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().unwrap();
        Ok(paths.get(path).map(|info| info.is_symlink).unwrap_or(false))
    }

    fn supports_symlinks(&self, dir: &Path) -> Result<bool> {
        let support = self.symlink_support.lock().unwrap();
        // Default to true (most test filesystems support symlinks)
        Ok(support.get(dir).copied().unwrap_or(true))
    }

    fn create_symlink(&self, target: &Path, link: &Path) -> Result<()> {
        // Idempotent: if symlink already exists pointing to the same target, no-op
        let paths = self.paths.lock().unwrap();
        if let Some(info) = paths.get(link) {
            if info.exists && info.is_symlink {
                // Check stored symlink target
                drop(paths);
                let symlinks = self.symlink_targets.lock().unwrap();
                if symlinks.get(link).map(|t| t == target).unwrap_or(false) {
                    return Ok(());
                }
                return Err(NailsError::IoError(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "Symlink at {} already exists pointing to a different target",
                        link.display()
                    ),
                )));
            } else if info.exists {
                drop(paths);
                return Err(NailsError::IoError(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("Path already exists (not a symlink) at {}", link.display()),
                )));
            }
        }
        drop(paths);

        // Create the symlink entry
        let mut paths = self.paths.lock().unwrap();
        let entry = paths.entry(link.to_path_buf()).or_default();
        entry.exists = true;
        entry.is_symlink = true;
        drop(paths);

        // Record the target
        self.symlink_targets
            .lock()
            .unwrap()
            .insert(link.to_path_buf(), target.to_path_buf());

        Ok(())
    }

    fn get_free_space(&self, path: &Path) -> Result<u64> {
        let paths = self.paths.lock().unwrap();
        Ok(paths
            .get(path)
            .map(|info| info.free_space)
            .unwrap_or(u64::MAX))
    }

    fn create_directory(&self, path: &Path) -> Result<()> {
        // Simulate create_dir_all by creating parent directories recursively
        // This matches RealFilesystem behavior which uses std::fs::create_dir_all
        if let Some(parent) = path.parent() {
            // Check if parent exists
            let parent_exists = {
                let paths = self.paths.lock().unwrap();
                paths.get(parent).map(|info| info.exists).unwrap_or(false)
            };

            // If parent doesn't exist, create it first (recursive)
            if !parent_exists {
                // Check if parent's parent is writable for the parent creation
                if let Some(grandparent) = parent.parent() {
                    let paths = self.paths.lock().unwrap();
                    let grandparent_writable = paths
                        .get(grandparent)
                        .map(|info| info.is_writable)
                        .unwrap_or(false);
                    drop(paths);
                    if !grandparent_writable {
                        return Err(NailsError::PermissionDenied(format!(
                            "Parent directory not writable: {}",
                            grandparent.display()
                        )));
                    }
                }
                // Create parent directory
                self.create_directory(parent)?;
                // Mark newly created parent as writable so children can be created
                let mut paths = self.paths.lock().unwrap();
                if let Some(entry) = paths.get_mut(parent) {
                    entry.is_writable = true;
                }
            } else {
                // Parent exists, check if it's writable
                let paths = self.paths.lock().unwrap();
                let parent_writable = paths
                    .get(parent)
                    .map(|info| info.is_writable)
                    .unwrap_or(false);
                drop(paths);
                if !parent_writable {
                    return Err(NailsError::PermissionDenied(format!(
                        "Parent directory not writable: {}",
                        parent.display()
                    )));
                }
            }
        }

        // Create directory
        let mut paths = self.paths.lock().unwrap();
        let entry = paths.entry(path.to_path_buf()).or_default();
        entry.exists = true;
        entry.is_directory = true;
        Ok(())
    }

    fn set_permissions(&self, path: &Path, mode: u32) -> Result<()> {
        let paths = self.paths.lock().unwrap();
        if !paths.get(path).map(|info| info.exists).unwrap_or(false) {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Path does not exist: {}", path.display()),
            )));
        }
        drop(paths);
        self.permissions
            .lock()
            .unwrap()
            .insert(path.to_path_buf(), mode);
        Ok(())
    }

    fn get_permissions(&self, path: &Path) -> Result<u32> {
        let paths = self.paths.lock().unwrap();
        if let Some(info) = paths.get(path)
            && !info.exists
        {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Path does not exist: {}", path.display()),
            )));
        }
        drop(paths);
        Ok(self
            .permissions
            .lock()
            .unwrap()
            .get(path)
            .copied()
            .unwrap_or(0o755))
    }

    fn is_readable(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().unwrap();
        Ok(paths
            .get(path)
            .map(|info| info.is_readable)
            .unwrap_or(false))
    }

    fn is_writable(&self, path: &Path) -> Result<bool> {
        let paths = self.paths.lock().unwrap();
        Ok(paths
            .get(path)
            .map(|info| info.is_writable)
            .unwrap_or(false))
    }

    fn nixos_profile_exists(&self, profile: &str) -> Result<bool> {
        Ok(self
            .nixos_profiles
            .lock()
            .unwrap()
            .contains(&profile.to_string()))
    }

    fn nixos_build_profile(&self, profile: &str) -> Result<()> {
        // Add profile to set
        self.nixos_profiles
            .lock()
            .unwrap()
            .insert(profile.to_string());
        Ok(())
    }

    fn nixos_switch_profile(&self, profile: &str) -> Result<()> {
        // Check if profile exists
        let exists = self
            .nixos_profiles
            .lock()
            .unwrap()
            .contains(&profile.to_string());
        if !exists {
            return Err(NailsError::NixOSProfileNotFound {
                profile: profile.to_string(),
            });
        }

        // Set current profile
        *self.current_profile.lock().unwrap() = Some(profile.to_string());
        Ok(())
    }

    fn nixos_get_current_profile(&self) -> Result<String> {
        self.current_profile
            .lock()
            .unwrap()
            .as_ref()
            .map(|p| p.clone())
            .ok_or_else(|| NailsError::InvalidState("No NixOS profile is currently active".into()))
    }

    fn nails_process_running(&self) -> Result<bool> {
        Ok(*self.nails_process_running.lock().unwrap())
    }

    fn read_file_content(&self, path: &Path) -> Result<String> {
        self.file_contents
            .lock()
            .unwrap()
            .get(path)
            .cloned()
            .ok_or_else(|| {
                NailsError::IoError(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("File not found in mock: {}", path.display()),
                ))
            })
    }

    fn find_files_with_pattern(&self, dir: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
        let pattern_results = self.files_with_pattern.lock().unwrap();
        let key = (dir.to_path_buf(), pattern.to_string());
        let files = pattern_results.get(&key).cloned().unwrap_or_default();

        // Filter out files that have been explicitly removed
        // Files are removed by setting exists=false in the paths map
        // If a file isn't in the paths map, it was never set up with mock_set_path_exists,
        // so we should still return it (it's implicitly considered to exist)
        let paths = self.paths.lock().unwrap();
        let existing_files: Vec<PathBuf> = files
            .into_iter()
            .filter(|path| {
                // If path is in the map, check exists flag
                // If path is not in the map, assume it exists (wasn't set up, so keep it)
                paths.get(path).map(|info| info.exists).unwrap_or(true)
            })
            .collect();

        Ok(existing_files)
    }

    fn write_file_content(&self, path: &Path, content: &str) -> Result<()> {
        // Check if write should fail for this path (Story 5.5 cleanup failure testing)
        if self.write_should_fail.lock().unwrap().contains(path) {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("Mock write failure for {}", path.display()),
            )));
        }

        // Mark path as existing
        let mut paths = self.paths.lock().unwrap();
        let entry = paths.entry(path.to_path_buf()).or_default();
        entry.exists = true;
        drop(paths);

        // Store the written content for test verification
        let mut written = self.written_files.lock().unwrap();
        written.insert(path.to_path_buf(), content.to_string());

        // Also update file_contents so subsequent reads work
        let mut contents = self.file_contents.lock().unwrap();
        contents.insert(path.to_path_buf(), content.to_string());

        self.op_log.lock().unwrap().push(MockOp::WriteFile {
            path: path.to_path_buf(),
        });

        Ok(())
    }

    fn mount_tmpfs(&self, target: &Path, size: &str) -> Result<()> {
        // Validate size format by parsing it
        let test_dir = crate::config::EphemeralOverlayDir {
            path: target.to_path_buf(),
            tmpfs_upper_size: size.to_string(),
            tmpfs_work_size: size.to_string(),
        };

        if test_dir.parse_upper_size().is_err() {
            return Err(NailsError::OverlayError(format!(
                "Invalid tmpfs size format: {}",
                size
            )));
        }

        // Check if target already has tmpfs mounted
        if self.tmpfs_mounts.lock().unwrap().contains(target) {
            return Err(NailsError::AlreadyMounted {
                path: target.to_path_buf(),
            });
        }

        // Create directory if it doesn't exist
        if !self.path_exists(target)? {
            self.create_directory(target)?;
        }

        // Track tmpfs mount
        self.tmpfs_mounts
            .lock()
            .unwrap()
            .insert(target.to_path_buf());
        self.mounted.lock().unwrap().insert(target.to_path_buf());

        Ok(())
    }

    fn unmount_tmpfs(&self, target: &Path) -> Result<()> {
        // Idempotent: succeed if not mounted
        if !self.tmpfs_mounts.lock().unwrap().contains(target) {
            return Ok(());
        }

        // Check if unmount should fail (mock behavior)
        if self.unmount_should_fail.lock().unwrap().contains(target) {
            return Err(NailsError::UnmountError {
                path: target.to_path_buf(),
                reason: "Mock: unmount_tmpfs configured to fail".to_string(),
            });
        }

        // Remove from tmpfs mounts and mounted sets
        self.tmpfs_mounts.lock().unwrap().remove(target);
        self.mounted.lock().unwrap().remove(target);

        Ok(())
    }

    fn bind_mount(&self, source: &Path, target: &Path) -> Result<()> {
        // Check if this mount should fail (for testing rollback)
        let fail_set = self.mount_should_fail.lock().unwrap();
        if fail_set.contains(target) {
            return Err(NailsError::OverlayError(format!(
                "Mock bind mount failure for testing: {}",
                target.display()
            )));
        }
        drop(fail_set);

        // Verify source exists (must have something to bind from)
        if !self.path_exists(source)? {
            return Err(NailsError::OverlayError(format!(
                "Bind mount source not found: {}",
                source.display()
            )));
        }

        // Check if target already has a bind mount
        if self.bind_mounts.lock().unwrap().contains_key(target) {
            return Err(NailsError::AlreadyMounted {
                path: target.to_path_buf(),
            });
        }

        // Track bind mount: target → source
        self.bind_mounts
            .lock()
            .unwrap()
            .insert(target.to_path_buf(), source.to_path_buf());
        self.mounted.lock().unwrap().insert(target.to_path_buf());

        Ok(())
    }

    fn unmount_bind(&self, target: &Path) -> Result<()> {
        // Idempotent: succeed if not mounted as bind
        if !self.bind_mounts.lock().unwrap().contains_key(target) {
            return Ok(());
        }

        // Check if unmount should fail (mock behavior)
        if self.unmount_should_fail.lock().unwrap().contains(target) {
            return Err(NailsError::UnmountError {
                path: target.to_path_buf(),
                reason: "Mock: unmount_bind configured to fail".to_string(),
            });
        }

        // Remove from bind mounts and mounted sets
        self.bind_mounts.lock().unwrap().remove(target);
        self.mounted.lock().unwrap().remove(target);

        Ok(())
    }

    fn file_size(&self, path: &Path) -> Result<u64> {
        let paths = self.paths.lock().unwrap();
        if let Some(info) = paths.get(path) {
            if !info.exists {
                return Err(NailsError::IoError(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("File not found: {}", path.display()),
                )));
            }

            // Store the size value before dropping paths lock
            let size_value = info.free_space;
            drop(paths);

            // Check if size was explicitly set via mock_set_file_size
            // Use explicit_file_sizes tracking to distinguish "set to 0" from "not set"
            let explicit_sizes = self.explicit_file_sizes.lock().unwrap();
            if explicit_sizes.contains(path) {
                // Return the stored size (even if it's 0)
                return Ok(size_value);
            }
            drop(explicit_sizes);

            // Fall back to file content length if available
            let contents = self.file_contents.lock().unwrap();
            if let Some(content) = contents.get(path) {
                return Ok(content.len() as u64);
            }

            // No size or content available, return 0
            Ok(0)
        } else {
            Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("File not found: {}", path.display()),
            )))
        }
    }

    fn rename_file(&self, from: &Path, to: &Path) -> Result<()> {
        // Check if rename should fail (for testing permission denied scenarios)
        if self.rename_should_fail.lock().unwrap().contains(from) {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Mock: rename_file configured to fail for {}",
                    from.display()
                ),
            )));
        }

        // Check if source exists
        let mut paths = self.paths.lock().unwrap();
        if !paths.get(from).is_some_and(|info| info.exists) {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Source file not found: {}", from.display()),
            )));
        }

        // Move path info from source to destination
        if let Some(mut info) = paths.remove(from) {
            info.exists = true; // Ensure destination is marked as existing
            paths.insert(to.to_path_buf(), info);
        }
        drop(paths);

        // Move file contents if present
        let mut contents = self.file_contents.lock().unwrap();
        if let Some(content) = contents.remove(from) {
            contents.insert(to.to_path_buf(), content);
        }

        Ok(())
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        // Check if removal should fail (mock behavior for testing)
        if self.remove_should_fail.lock().unwrap().contains(path) {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Mock: remove_file configured to fail for {}",
                    path.display()
                ),
            )));
        }

        // Mark file as non-existent instead of removing entry entirely
        // This allows find_files_with_pattern to filter out removed files
        let mut paths = self.paths.lock().unwrap();
        if let Some(info) = paths.get_mut(path) {
            info.exists = false;
        }
        // If path isn't in map, it was never set up, so nothing to do

        // Also remove from file_contents if present
        let mut contents = self.file_contents.lock().unwrap();
        contents.remove(path);

        Ok(())
    }

    fn remove_dir_all(&self, path: &Path) -> Result<()> {
        // Check if removal should fail (mock behavior for testing)
        if self.remove_should_fail.lock().unwrap().contains(path) {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Mock: remove_dir_all configured to fail for {}",
                    path.display()
                ),
            )));
        }

        // Mark directory as non-existent instead of removing entry entirely
        // This allows find_files_with_pattern to filter out removed directories
        let mut paths = self.paths.lock().unwrap();
        if let Some(info) = paths.get_mut(path) {
            info.exists = false;
        }
        // If path isn't in map, it was never set up, so nothing to do

        // In a real implementation, we'd also remove all children
        // For mock purposes, just marking the directory entry is sufficient

        Ok(())
    }

    fn list_directory(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        // Check if directory contents have been mocked
        let contents = self.directory_contents.lock().unwrap();
        if let Some(entries) = contents.get(&dir.to_path_buf()) {
            return Ok(entries.clone());
        }

        // If not mocked, return error (directory not found/not set up for tests)
        Err(NailsError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "Mock: directory contents not configured for {}",
                dir.display()
            ),
        )))
    }

    fn enumerate_root_directories(&self) -> Result<Vec<PathBuf>> {
        // Get configured root directories (real directories, not symlinks)
        let dirs = self.root_directories.lock().unwrap().clone();

        // Get configured symlinks to exclude
        let symlinks = self.root_symlinks.lock().unwrap().clone();

        // Filter out symlinks and /run/nails from the directory list
        let mut result: Vec<PathBuf> = dirs
            .into_iter()
            .filter(|d| !symlinks.contains(d))
            .filter(|d| {
                // Exclude /run/nails directory (Story 14.10, Issue 6)
                if d.starts_with("/run/nails") {
                    tracing::debug!("Skipping NAILS runtime directory: {}", d.display());
                    false
                } else {
                    true
                }
            })
            .collect();

        // Sort alphabetically for consistent order
        result.sort();

        Ok(result)
    }

    fn read_directory(&self, path: &Path) -> Result<Vec<std::fs::DirEntry>> {
        // For mock filesystem, we need to check what entries exist in the path
        let paths = self.paths.lock().unwrap();

        // Collect all paths that start with the given directory
        let entries = Vec::new();
        for (p, info) in paths.iter() {
            // Check if this path is a direct child of the directory
            if let Some(parent) = p.parent()
                && parent == path
                && info.exists
            {
                // Create a mock DirEntry
                // Since std::fs::DirEntry can't be constructed directly,
                // we'll return an error for now - this needs a proper mock implementation
                return Err(NailsError::IoError(std::io::Error::other(
                    "Mock: read_directory not fully implemented for MockFilesystem",
                )));
            }
        }

        Ok(entries)
    }

    fn modified_time(&self, path: &Path) -> Result<chrono::DateTime<chrono::Utc>> {
        // Check if a mock modification time was set for this path
        let times = self.modified_times.lock().unwrap();
        if let Some(modified) = times.get(&path.to_path_buf()) {
            return Ok(*modified);
        }

        // Default to current time if no mock time was set
        Ok(chrono::Utc::now())
    }

    fn copy_tree(&self, src: &Path, dst: &Path) -> Result<()> {
        // Log the operation
        self.op_log.lock().unwrap().push(MockOp::CopyTree {
            src: src.to_path_buf(),
            dst: dst.to_path_buf(),
        });

        // Check if this source should fail
        if self.copy_tree_should_fail.lock().unwrap().contains(src) {
            return Err(NailsError::IoError(std::io::Error::other(format!(
                "Mock copy_tree failure for {}",
                src.display()
            ))));
        }

        Ok(())
    }

    fn get_directory_size(&self, path: &Path) -> Result<u64> {
        let sizes = self.directory_sizes.lock().unwrap();
        Ok(sizes.get(path).copied().unwrap_or(0))
    }

    fn find_submount_sources(&self, target: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
        let sources = self.submount_sources.lock().unwrap();
        Ok(sources.get(target).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_filesystem_new_starts_empty() {
        let fs = MockFilesystem::new();
        assert!(fs.get_mounted_paths().is_empty());
        assert!(!fs.swap_is_enabled().unwrap());
    }

    #[test]
    fn test_mock_filesystem_reset_clears_state() {
        let fs = MockFilesystem::new();
        fs.mock_set_mounted(Path::new("/home"), true);
        fs.mock_set_swap_enabled(true);
        fs.reset();
        assert!(fs.get_mounted_paths().is_empty());
        assert!(!fs.swap_is_enabled().unwrap());
    }

    #[test]
    fn test_mock_filesystem_clone_shares_state() {
        let fs1 = MockFilesystem::new();
        fs1.mock_set_mounted(Path::new("/home"), true);

        let fs2 = fs1.clone();
        assert!(fs2.is_mounted(Path::new("/home")).unwrap());

        // Shared state means modifications from one are visible in the other
        fs2.mock_set_mounted(Path::new("/tmp"), true);
        assert!(fs1.is_mounted(Path::new("/tmp")).unwrap());
    }

    #[test]
    fn test_mock_filesystem_nixos_build_profile_adds_profile() {
        let fs = MockFilesystem::new();

        // Build should add profile to set
        assert!(fs.nixos_build_profile("test-profile").is_ok());
        assert!(fs.nixos_profile_exists("test-profile").unwrap());

        // Building same profile again should work (idempotent)
        assert!(fs.nixos_build_profile("test-profile").is_ok());
    }

    #[test]
    fn test_mock_set_mounted_can_unmount() {
        let fs = MockFilesystem::new();
        let path = Path::new("/test/mount");

        // Mount then unmount
        fs.mock_set_mounted(path, true);
        assert!(fs.is_mounted(path).unwrap());

        fs.mock_set_mounted(path, false);
        assert!(!fs.is_mounted(path).unwrap());
    }

    #[test]
    fn test_mock_filesystem_swap_is_disabled_by_default() {
        let fs = MockFilesystem::new();
        assert!(!fs.swap_is_enabled().unwrap());

        // Enable then disable
        fs.mock_set_swap_enabled(true);
        assert!(fs.swap_is_enabled().unwrap());

        fs.mock_set_swap_enabled(false);
        assert!(!fs.swap_is_enabled().unwrap());
    }

    #[test]
    fn test_mock_filesystem_directory_operations() {
        let fs = MockFilesystem::new();
        let path = Path::new("/test/dir");

        fs.mock_set_path_exists("/test/dir", true);
        fs.mock_set_path_type("/test/dir", "directory");

        assert!(fs.path_exists(path).unwrap());
        assert!(fs.is_directory(path).unwrap());
    }

    #[test]
    fn test_mock_filesystem_file_permissions() {
        let fs = MockFilesystem::new();
        let path = Path::new("/test/file");

        fs.mock_set_path_exists("/test/file", true);
        fs.mock_set_readable("/test/file", true);
        fs.mock_set_writable("/test/file", true);

        assert!(fs.is_readable(path).unwrap());
        assert!(fs.is_writable(path).unwrap());
    }

    // ========================================================================
    // Tests for Story 4.1: Overlay Mount Operations
    // ========================================================================

    #[test]
    fn test_mount_overlay_success_tracks_mount_info() {
        // AC5: MockFilesystem tracks mounted paths with MountInfo
        let fs = MockFilesystem::new();

        // Set up paths to exist
        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        // Mount overlay
        let result = fs.mount_overlay(
            &[Path::new("/")],
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_ok());

        // Verify mount tracking
        assert!(fs.is_mounted(Path::new("/home")).unwrap());

        // Verify MountInfo is tracked
        let mount_info = fs.mock_get_mount_info(Path::new("/home"));
        assert!(mount_info.is_some());

        let info = mount_info.unwrap();
        assert_eq!(info.lower, Path::new("/"));
        assert_eq!(info.upper, Path::new("/mnt/hidden/upper"));
        assert_eq!(info.work, Path::new("/mnt/hidden/work"));
        assert_eq!(info.target, Path::new("/home"));
        // Verify timestamp is recent (within last second)
        let elapsed = chrono::Utc::now() - info.mounted_at;
        assert!(elapsed.num_seconds() < 2);
    }

    #[test]
    fn test_mount_overlay_fails_on_missing_lower() {
        // AC2: Returns error when lower directory missing
        let fs = MockFilesystem::new();

        // Only set upper and work to exist, not lower
        fs.mock_set_path_exists("/mnt/hidden/upper", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        let result = fs.mount_overlay(
            &[Path::new("/nonexistent/lower")],
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::OverlayError(msg) => {
                assert!(msg.contains("Lower directory not found"));
                assert!(msg.contains("/nonexistent/lower"));
            }
            _ => panic!("Expected OverlayError for missing lower directory"),
        }
    }

    #[test]
    fn test_mount_overlay_fails_on_missing_upper() {
        // AC2: Returns error when upper directory missing
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        let result = fs.mount_overlay(
            &[Path::new("/")],
            Path::new("/nonexistent/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::OverlayError(msg) => {
                assert!(msg.contains("Upper directory not found"));
                assert!(msg.contains("/nonexistent/upper"));
            }
            _ => panic!("Expected OverlayError for missing upper directory"),
        }
    }

    #[test]
    fn test_mount_overlay_fails_on_missing_work() {
        // AC2: Returns error when work directory missing
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);

        let result = fs.mount_overlay(
            &[Path::new("/")],
            Path::new("/mnt/hidden/upper"),
            Path::new("/nonexistent/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::OverlayError(msg) => {
                assert!(msg.contains("Work directory not found"));
                assert!(msg.contains("/nonexistent/work"));
            }
            _ => panic!("Expected OverlayError for missing work directory"),
        }
    }

    #[test]
    fn test_mount_overlay_fails_on_already_mounted() {
        // AC4: Returns error when target already mounted
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        // Mount once (should succeed)
        let result = fs.mount_overlay(
            &[Path::new("/")],
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );
        assert!(result.is_ok());

        // Try to mount again (should fail)
        let result = fs.mount_overlay(
            &[Path::new("/")],
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::AlreadyMounted { path } => {
                assert_eq!(path, Path::new("/home"));
            }
            _ => panic!("Expected AlreadyMounted error"),
        }
    }

    #[test]
    fn test_mock_filesystem_can_simulate_mount_failure() {
        // AC5: Mock can simulate mount failures
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        // Configure mock to fail mount for /home
        fs.mock_set_mount_should_fail("/home", true);

        let result = fs.mount_overlay(
            &[Path::new("/")],
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::OverlayError(msg) => {
                // Verify error message format matches AC1 specification
                assert!(msg.contains("Mock mount failure for testing"));
                assert!(msg.contains("/home"), "Error should include target path");
            }
            _ => panic!("Expected OverlayError for simulated failure"),
        }
    }

    #[test]
    fn test_mount_overlay_target_contains_merged_view() {
        // AC4: Verify target contains merged view of lower + upper after mount
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        // Mount overlay
        let result = fs.mount_overlay(
            &[Path::new("/")],
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );
        assert!(result.is_ok());

        // Verify mount info contains merged view metadata
        let mount_info = fs.mock_get_mount_info(Path::new("/home")).unwrap();
        assert_eq!(
            mount_info.lower,
            Path::new("/"),
            "Lower directory should be tracked"
        );
        assert_eq!(
            mount_info.upper,
            Path::new("/mnt/hidden/upper"),
            "Upper directory should be tracked"
        );
        assert_eq!(
            mount_info.work,
            Path::new("/mnt/hidden/work"),
            "Work directory should be tracked"
        );
        assert_eq!(
            mount_info.target,
            Path::new("/home"),
            "Target mount point should be tracked"
        );

        // For MockFilesystem, the merged view is verified through the mount_info tracking
        // For RealFilesystem (integration tests), the actual filesystem would show merged content
    }

    #[test]
    fn test_unmount_removes_mount_info() {
        // Verify unmount removes mount from tracking
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        // Mount
        fs.mount_overlay(
            &[Path::new("/")],
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        )
        .unwrap();

        // Verify mounted
        assert!(fs.is_mounted(Path::new("/home")).unwrap());
        assert!(fs.mock_get_mount_info(Path::new("/home")).is_some());

        // Unmount
        fs.unmount(Path::new("/home"), false).unwrap();

        // Verify unmounted and info removed
        assert!(!fs.is_mounted(Path::new("/home")).unwrap());
        assert!(fs.mock_get_mount_info(Path::new("/home")).is_none());
    }

    #[test]
    fn test_verify_mount_preconditions_succeeds_when_all_valid() {
        // AC6: verify_mount_preconditions checks all conditions
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        let result = verify_mount_preconditions(
            &fs,
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_mount_preconditions_fails_on_missing_lower() {
        // AC6: verify_mount_preconditions detects missing lower
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/mnt/hidden/upper", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        let result = verify_mount_preconditions(
            &fs,
            Path::new("/nonexistent"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::OverlayError(msg) => {
                assert!(msg.contains("Lower directory not found"));
            }
            _ => panic!("Expected OverlayError"),
        }
    }

    #[test]
    fn test_verify_mount_preconditions_fails_on_missing_upper() {
        // AC6: verify_mount_preconditions detects missing upper when parent doesn't exist
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        // Use a path where parent doesn't exist
        let result = verify_mount_preconditions(
            &fs,
            Path::new("/"),
            Path::new("/nonexistent/subdir/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::OverlayError(msg) => {
                assert!(msg.contains("Upper directory not found and parent doesn't exist"));
            }
            _ => panic!("Expected OverlayError"),
        }
    }

    #[test]
    fn test_verify_mount_preconditions_fails_on_missing_work() {
        // AC6: verify_mount_preconditions detects missing work when parent doesn't exist
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);

        // Use a path where parent doesn't exist
        let result = verify_mount_preconditions(
            &fs,
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/nonexistent/subdir/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::OverlayError(msg) => {
                assert!(msg.contains("Work directory not found and parent doesn't exist"));
            }
            _ => panic!("Expected OverlayError"),
        }
    }

    #[test]
    fn test_verify_mount_preconditions_fails_on_already_mounted() {
        // AC6: verify_mount_preconditions detects already mounted
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        // Mount first
        fs.mount_overlay(
            &[Path::new("/")],
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        )
        .unwrap();

        // Try preconditions check (should fail because already mounted)
        let result = verify_mount_preconditions(
            &fs,
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::AlreadyMounted { path } => {
                assert_eq!(path, Path::new("/home"));
            }
            _ => panic!("Expected AlreadyMounted error"),
        }
    }

    #[test]
    fn test_verify_mount_preconditions_succeeds_when_upper_creatable() {
        // AC6: verify_mount_preconditions accepts upper directory if it can be created
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        // Upper doesn't exist but parent is writable
        fs.mock_set_directory_creatable("/mnt/hidden/upper", true);

        let result = verify_mount_preconditions(
            &fs,
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_mount_preconditions_succeeds_when_work_creatable() {
        // AC6: verify_mount_preconditions accepts work directory if it can be created
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);

        // Work doesn't exist but parent is writable
        fs.mock_set_directory_creatable("/mnt/hidden/work", true);

        let result = verify_mount_preconditions(
            &fs,
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_mount_preconditions_fails_when_upper_not_creatable() {
        // AC6: verify_mount_preconditions fails if upper can't be created (parent not writable)
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/work", true);

        // Upper doesn't exist and parent is not writable
        fs.mock_set_directory_creatable("/mnt/hidden/upper", false);

        let result = verify_mount_preconditions(
            &fs,
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::PermissionDenied(msg) => {
                assert!(msg.contains("Upper directory not found and parent not writable"));
            }
            _ => panic!("Expected PermissionDenied error"),
        }
    }

    #[test]
    fn test_verify_mount_preconditions_fails_when_work_not_creatable() {
        // AC6: verify_mount_preconditions fails if work can't be created (parent not writable)
        let fs = MockFilesystem::new();

        fs.mock_set_path_exists("/", true);
        fs.mock_set_path_exists("/mnt/hidden/upper", true);

        // Work doesn't exist and parent is not writable
        fs.mock_set_directory_creatable("/mnt/hidden/work", false);

        let result = verify_mount_preconditions(
            &fs,
            Path::new("/"),
            Path::new("/mnt/hidden/upper"),
            Path::new("/mnt/hidden/work"),
            Path::new("/home"),
        );

        assert!(result.is_err());
        match result.unwrap_err() {
            NailsError::PermissionDenied(msg) => {
                assert!(msg.contains("Work directory not found and parent not writable"));
            }
            _ => panic!("Expected PermissionDenied error"),
        }
    }
}
