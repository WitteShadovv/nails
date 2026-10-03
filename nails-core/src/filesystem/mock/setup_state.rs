use super::super::{MountInfo, MountSource, ProcessMatch};
use super::MockFilesystem;
use chrono::{DateTime, Utc};
use std::path::{Path, PathBuf};

/// The kind of entry a mock path represents.
///
/// Replaces the former free-form string argument of
/// [`mock_set_path_type`](MockFilesystem::mock_set_path_type) so a test can only
/// ask for a kind the mock actually models, rather than relying on the old
/// "anything that is not `\"directory\"` is a file" convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// A regular file: exists, is not a directory and is not a symlink.
    File,
    /// A directory: exists and reports `is_directory`.
    Dir,
    /// A symbolic link: exists and reports `is_symlink`.
    Symlink,
    /// A path that does not exist.
    Missing,
}

impl MockFilesystem {
    /// Set whether a path is mounted.
    ///
    /// A mount set this way is treated as NAILS-owned, so it can be torn down by
    /// `unmount`. Use [`mock_set_mount_unmanaged`](Self::mock_set_mount_unmanaged)
    /// to simulate a foreign mount that `unmount` must refuse.
    pub fn mock_set_mounted(&self, path: &Path, mounted: bool) {
        let mut mounts = self.mounted.lock().expect("MockFilesystem mutex poisoned");
        let mut owned = self
            .nails_owned_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned");
        if mounted {
            mounts.insert(path.to_path_buf());
            owned.insert(path.to_path_buf());
        } else {
            mounts.remove(path);
            owned.remove(path);
            self.mounted_overlays
                .lock()
                .expect("MockFilesystem mutex poisoned")
                .remove(path);
        }
    }

    /// Mark `path` as mounted but **not** NAILS-owned.
    ///
    /// Simulates a host filesystem (e.g. a real ext4 `/home`) that stale state
    /// might wrongly point NAILS at: `unmount` must refuse it with
    /// [`NailsError::RefusedUnmanagedUnmount`](crate::NailsError::RefusedUnmanagedUnmount).
    pub fn mock_set_mount_unmanaged(&self, path: &Path) {
        self.mounted
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(path.to_path_buf());
        self.nails_owned_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .remove(path);
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

    /// Mount a NAILS overlay at `target` with explicit `upper`/`work` directories.
    ///
    /// Unlike [`mock_set_overlay_mounted`](Self::mock_set_overlay_mounted), which
    /// invents an upperdir outside any hidden root, this records the real upper
    /// and work paths so [`discover_nails_mounts`](crate::Filesystem::discover_nails_mounts)
    /// classifies the overlay as persistent (upper under the hidden root) exactly
    /// as the kernel parser would. Used by status/reconcile tests to stand up a
    /// genuinely NAILS-owned overlay.
    pub fn mock_mount_nails_overlay(&self, target: &Path, upper: &Path, work: &Path) {
        self.mounted
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(target.to_path_buf());
        self.nails_owned_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(target.to_path_buf());
        self.mounted_overlays
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(
                target.to_path_buf(),
                MountInfo {
                    lower: target.to_path_buf(),
                    upper: upper.to_path_buf(),
                    work: work.to_path_buf(),
                    target: target.to_path_buf(),
                    mounted_at: Utc::now(),
                },
            );
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

    /// Set a path's kind (file, directory, symlink or missing).
    pub fn mock_set_path_type(&self, path: &str, kind: PathKind) {
        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        let entry = paths.entry(PathBuf::from(path)).or_default();
        match kind {
            PathKind::File => {
                entry.exists = true;
                entry.is_directory = false;
                entry.is_symlink = false;
            }
            PathKind::Dir => {
                entry.exists = true;
                entry.is_directory = true;
                entry.is_symlink = false;
            }
            PathKind::Symlink => {
                entry.exists = true;
                entry.is_directory = false;
                entry.is_symlink = true;
            }
            PathKind::Missing => {
                entry.exists = false;
            }
        }
    }

    /// Stand up a readable mock file in a single call.
    ///
    /// Combines [`mock_set_path_type`](Self::mock_set_path_type) with
    /// [`mock_set_file_content`](Self::mock_set_file_content) so a test does not
    /// need separate calls to make one file both exist and return contents.
    pub fn mock_add_file(&self, path: &str, content: &str) {
        self.mock_set_path_type(path, PathKind::File);
        self.mock_set_file_content(path, content);
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

    /// Set the device, dm name and label backing a mount point.
    ///
    /// Drives [`Filesystem::mount_source`](crate::Filesystem::mount_source) so a
    /// test can exercise the hidden-volume name check without a real mount table.
    pub fn mock_set_mount_source(&self, path: &Path, source: MountSource) {
        self.mount_sources
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(path.to_path_buf(), source);
    }

    /// Set the device id reported for a path by
    /// [`Filesystem::device_id`](crate::Filesystem::device_id).
    ///
    /// Map a path onto the same id as `/` to make the attach gate treat it as an
    /// unmounted mount point; give it a distinct id to simulate a mounted hidden
    /// volume. Unset paths already report distinct ids, so only the "shares a
    /// device with /" case needs an explicit call.
    pub fn mock_set_device_id(&self, path: &Path, device_id: u64) {
        self.device_ids
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(path.to_path_buf(), device_id);
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

    /// Set the classified submounts returned by
    /// [`Filesystem::find_submounts`](crate::Filesystem::find_submounts) for a
    /// target, so a test can drive the parent-overlay re-attach plan.
    pub fn mock_set_submounts(&self, target: &Path, submounts: Vec<crate::filesystem::Submount>) {
        self.submounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(target.to_path_buf(), submounts);
    }

    /// Set free space for a path
    pub fn mock_set_free_space(&self, path: &Path, bytes: u64) {
        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        let entry = paths.entry(path.to_path_buf()).or_default();
        entry.free_space = bytes;
    }

    /// Set the total and available space reported for a path by
    /// [`disk_usage`](crate::Filesystem::disk_usage).
    ///
    /// Lets tests exercise the status command's hidden-root usage figures
    /// without a real filesystem.
    pub fn mock_set_disk_usage(&self, path: &Path, total: u64, available: u64) {
        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        let entry = paths.entry(path.to_path_buf()).or_default();
        entry.total_space = total;
        entry.free_space = available;
    }

    /// Configure [`is_mounted`](crate::Filesystem::is_mounted) to fail for a path.
    ///
    /// The supplied message is returned as the inner [`std::io::Error`], letting
    /// tests reproduce an unreadable mount table (for example when the status
    /// command must downgrade verification to a mismatch).
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_is_mounted_error(Path::new("/etc"), "mount table unreadable");
    /// assert!(fs.is_mounted(Path::new("/etc")).is_err());
    /// ```
    pub fn mock_set_is_mounted_error(&self, path: &Path, message: &str) {
        self.is_mounted_errors
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(path.to_path_buf(), message.to_string());
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
        let mut fail_map = self
            .mount_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned");
        if should_fail {
            // EIO is a generic, fatal mount failure: it is *not* one of the
            // EINVAL/EBUSY/EOPNOTSUPP errnos the overlay strategy retries with a
            // pivot fallback, so a plain `mount_should_fail` keeps the historical
            // "mount fails outright" behaviour. Tests that need the pivot-fallback
            // branch pick the errno explicitly via `mock_set_mount_fail_errno`.
            fail_map.insert(PathBuf::from(path), nix::errno::Errno::EIO);
        } else {
            fail_map.remove(&PathBuf::from(path));
        }
    }

    /// Configure a mount operation to fail with a specific errno.
    ///
    /// Like [`MockFilesystem::mock_set_mount_should_fail`], but lets tests choose
    /// the errno so strategy code that branches on `EINVAL`/`EBUSY`/`EOPNOTSUPP`
    /// versus a fatal errno can be exercised directly.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nails_core::filesystem::MockFilesystem;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_mount_fail_errno("/data", nix::errno::Errno::ENOSPC);
    /// ```
    pub fn mock_set_mount_fail_errno(&self, path: &str, errno: nix::errno::Errno) {
        self.mount_should_fail
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(PathBuf::from(path), errno);
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

    /// Set the classified process matches returned by
    /// [`Filesystem::nails_process_matches`](crate::Filesystem::nails_process_matches).
    ///
    /// Lets a test drive the honest process check directly — a weak (substring)
    /// match that verify must treat as information, or a strong (binary identity)
    /// match it must treat as critical — instead of only toggling the boolean.
    pub fn mock_set_nails_process_matches(&self, matches: Vec<ProcessMatch>) {
        *self
            .nails_process_matches
            .lock()
            .expect("MockFilesystem mutex poisoned") = Some(matches);
    }

    /// Mark a directory as unreadable, so
    /// [`Filesystem::scan_files_with_pattern`](crate::Filesystem::scan_files_with_pattern)
    /// reports it under [`PatternScan::unreadable`](crate::filesystem::PatternScan::unreadable)
    /// rather than walking it. Models an `EACCES` on `/tmp/systemd-private-*`.
    pub fn mock_set_unreadable_dir(&self, dir: &str) {
        self.unreadable_dirs
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(PathBuf::from(dir));
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

    /// Set mock file size for file_size() tests
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

    /// Set whether rename operations should fail for a specific path
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

    /// Set the modification time for a file
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::Filesystem;

    #[test]
    fn path_kind_dir_reports_directory() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/some/dir", PathKind::Dir);
        assert!(fs.path_exists(Path::new("/some/dir")).unwrap());
        assert!(fs.is_directory(Path::new("/some/dir")).unwrap());
        assert!(!fs.is_symlink(Path::new("/some/dir")).unwrap());
    }

    #[test]
    fn path_kind_file_is_not_a_directory() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/some/file", PathKind::File);
        assert!(fs.path_exists(Path::new("/some/file")).unwrap());
        assert!(!fs.is_directory(Path::new("/some/file")).unwrap());
        assert!(!fs.is_symlink(Path::new("/some/file")).unwrap());
    }

    #[test]
    fn path_kind_symlink_reports_symlink() {
        let fs = MockFilesystem::new();
        fs.mock_set_path_type("/some/link", PathKind::Symlink);
        assert!(fs.path_exists(Path::new("/some/link")).unwrap());
        assert!(fs.is_symlink(Path::new("/some/link")).unwrap());
        assert!(!fs.is_directory(Path::new("/some/link")).unwrap());
    }

    #[test]
    fn path_kind_missing_does_not_exist() {
        let fs = MockFilesystem::new();
        // Mark it present first, then clear it with `Missing`.
        fs.mock_set_path_type("/gone", PathKind::File);
        fs.mock_set_path_type("/gone", PathKind::Missing);
        assert!(!fs.path_exists(Path::new("/gone")).unwrap());
    }

    #[test]
    fn add_file_sets_existence_and_content() {
        let fs = MockFilesystem::new();
        fs.mock_add_file("/etc/example.conf", "key = value\n");
        assert!(fs.path_exists(Path::new("/etc/example.conf")).unwrap());
        assert!(!fs.is_directory(Path::new("/etc/example.conf")).unwrap());
        assert_eq!(
            fs.read_file_content(Path::new("/etc/example.conf"))
                .unwrap(),
            "key = value\n"
        );
    }
}
