use super::super::MountInfo;
use super::MockFilesystem;
use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};

impl MockFilesystem {
    /// Set whether a path is mounted
    pub fn mock_set_mounted(&self, path: &Path, mounted: bool) {
        let mut mounts = self.mounted.lock().expect("MockFilesystem mutex poisoned");
        if mounted {
            mounts.insert(path.to_path_buf());
        } else {
            mounts.remove(path);
            self.mounted_overlays
                .lock()
                .expect("MockFilesystem mutex poisoned")
                .remove(path);
        }
    }

    /// Set whether a path is mounted as an overlay filesystem.
    pub fn mock_set_overlay_mounted(&self, path: &Path, mounted: bool) {
        self.mock_set_mounted(path, mounted);

        let mut overlays = self
            .mounted_overlays
            .lock()
            .expect("MockFilesystem mutex poisoned");
        if mounted {
            overlays.insert(
                path.to_path_buf(),
                MountInfo {
                    lower: path.to_path_buf(),
                    upper: PathBuf::from(format!("/mock-upper{}", path.display())),
                    work: PathBuf::from(format!("/mock-work{}", path.display())),
                    target: path.to_path_buf(),
                    mounted_at: Utc::now(),
                },
            );
        } else {
            overlays.remove(path);
        }
    }

    /// Set whether a path is busy (has open files)
    pub fn mock_set_busy(&self, path: &Path, busy: bool) {
        let mut busy_set = self.busy.lock().expect("MockFilesystem mutex poisoned");
        if busy {
            busy_set.insert(path.to_path_buf());
        } else {
            busy_set.remove(path);
        }
    }

    /// Set whether swap is enabled
    pub fn mock_set_swap_enabled(&self, enabled: bool) {
        *self
            .swap_enabled
            .lock()
            .expect("MockFilesystem mutex poisoned") = enabled;
    }

    /// Set whether a path exists
    pub fn mock_set_path_exists(&self, path: &str, exists: bool) {
        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        let entry = paths.entry(PathBuf::from(path)).or_default();
        entry.exists = exists;
    }

    /// Set a path's type (directory or file)
    pub fn mock_set_path_type(&self, path: &str, type_str: &str) {
        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        let entry = paths.entry(PathBuf::from(path)).or_default();
        entry.exists = true;
        entry.is_directory = type_str == "directory";
    }

    /// Set whether a path is writable
    pub fn mock_set_writable(&self, path: &str, writable: bool) {
        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        let entry = paths.entry(PathBuf::from(path)).or_default();
        entry.is_writable = writable;
    }

    /// Set whether a path is readable
    pub fn mock_set_readable(&self, path: &str, readable: bool) {
        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        let entry = paths.entry(PathBuf::from(path)).or_default();
        entry.is_readable = readable;
    }

    /// Set whether a path is a symbolic link
    pub fn mock_set_is_symlink(&self, path: &str, is_symlink: bool) {
        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        let entry = paths.entry(PathBuf::from(path)).or_default();
        entry.exists = true;
        entry.is_symlink = is_symlink;
    }

    /// Set whether a directory's filesystem supports symbolic links
    pub fn mock_set_supports_symlinks(&self, path: &Path, supports: bool) {
        self.symlink_support
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(path.to_path_buf(), supports);
    }

    /// Set the filesystem type for a mount point (e.g., "vfat", "ext4", "tmpfs")
    pub fn mock_set_filesystem_type(&self, path: &Path, fstype: &str) {
        self.filesystem_types
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(path.to_path_buf(), fstype.to_string());
    }

    /// Set whether copy_tree should fail for a source path
    pub fn mock_set_copy_tree_should_fail(&self, src: &Path) {
        self.copy_tree_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(src.to_path_buf());
    }

    /// Set the reported size for a directory
    pub fn mock_set_directory_size(&self, path: &Path, size: u64) {
        self.directory_sizes
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(path.to_path_buf(), size);
    }

    /// Set mock submount sources for a target directory
    pub fn mock_set_submount_sources(&self, target: &Path, sources: Vec<(PathBuf, PathBuf)>) {
        self.submount_sources
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(target.to_path_buf(), sources);
    }

    /// Set free space for a path
    pub fn mock_set_free_space(&self, path: &Path, bytes: u64) {
        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        let entry = paths.entry(path.to_path_buf()).or_default();
        entry.free_space = bytes;
    }

    /// Set whether a NixOS profile exists
    pub fn mock_set_nixos_profile_exists(&self, profile: &str, exists: bool) {
        let mut profiles = self
            .nixos_profiles
            .lock()
            .expect("MockFilesystem mutex poisoned");
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
        let mut fail_set = self
            .mount_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned");
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
        let mut fail_set = self
            .unmount_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned");
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
        let mut fail_set = self
            .unmount_graceful_fails
            .lock()
            .expect("MockFilesystem mutex poisoned");
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
        let mut is_running = self
            .nails_process_running
            .lock()
            .expect("MockFilesystem mutex poisoned");
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
        let mut contents = self
            .file_contents
            .lock()
            .expect("MockFilesystem mutex poisoned");
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
        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        let entry = paths.entry(PathBuf::from(path)).or_default();
        entry.exists = true;
        entry.free_space = size;
        drop(paths);

        self.explicit_file_sizes
            .lock()
            .expect("MockFilesystem mutex poisoned")
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
        let mut fails = self
            .rename_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned");
        if should_fail {
            fails.insert(PathBuf::from(path));
        } else {
            fails.remove(&PathBuf::from(path));
        }
    }

    /// Set whether set_permissions should fail for a specific path.
    pub fn mock_set_permissions_should_fail(&self, path: &str, should_fail: bool) {
        let mut fails = self
            .permissions_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned");
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
    /// use chrono::{Duration, Utc};
    ///
    /// let fs = MockFilesystem::new();
    /// let old_time = Utc::now() - Duration::days(10);
    /// fs.mock_set_modified_time(Path::new("/mnt/hidden/logs/nails.log.8"), old_time);
    ///
    /// // This file will now be considered 10 days old
    /// let modified = fs.modified_time(Path::new("/mnt/hidden/logs/nails.log.8")).unwrap();
    /// ```
    pub fn mock_set_modified_time(&self, path: &Path, modified_time: DateTime<Utc>) {
        let mut times = self
            .modified_times
            .lock()
            .expect("MockFilesystem mutex poisoned");
        times.insert(path.to_path_buf(), modified_time);
    }
}
