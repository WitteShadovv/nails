// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::super::{MountSource, ProcessMatch};
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
    /// Mark the mount at `path` read-only, as the kernel does after an I/O
    /// error on the device behind it.
    pub fn mock_set_mount_read_only(&self, path: &Path) {
        self.read_only_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(path.to_path_buf());
    }

    /// Set whether a path is mounted.
    pub fn mock_set_mounted(&self, path: &Path, mounted: bool) {
        let mut mounts = self.mounted.lock().expect("MockFilesystem mutex poisoned");
        if mounted {
            mounts.insert(path.to_path_buf());
        } else {
            mounts.remove(path);
        }
    }

    /// Seed `/proc/swaps` so [`crate::preflight::classify_swap`] sees swap as
    /// enabled or disabled.
    ///
    /// `true` installs a plain disk partition (classified as a failure); `false`
    /// installs a header-only table (no active swap). Tests that need a specific
    /// device shape (zram, dm-crypt, file) write `/proc/swaps` directly with
    /// [`Self::mock_add_file`].
    pub fn mock_set_swap_enabled(&self, enabled: bool) {
        let content = if enabled {
            "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n\
             /dev/sda2\tpartition\t8388604\t0\t-2\n"
        } else {
            "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
        };
        self.mock_add_file("/proc/swaps", content);
    }

    /// Set whether a path exists
    pub fn mock_set_path_exists(&self, path: &str, exists: bool) {
        let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
        let entry = paths.entry(PathBuf::from(path)).or_default();
        entry.exists = exists;
    }

    /// Record the numeric `(uid, gid)` owner of a path.
    ///
    /// Lets a test stand up a pre-existing, user-owned file so that a later
    /// `write_user_file` into it keeps that owner (an existing file is never
    /// re-chowned), matching the real filesystem.
    pub fn mock_set_owner(&self, path: &Path, uid: u32, gid: u32) {
        self.owners
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .insert(path.to_path_buf(), (uid, gid));
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
    /// use nails_base::filesystem::{Filesystem, MockFilesystem};
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
    /// use nails_base::filesystem::{Filesystem, MockFilesystem};
    /// use std::path::Path;
    ///
    /// let fs = MockFilesystem::new();
    /// fs.mock_set_file_content("/root/.bash_history", "nails activate\nls\n");
    /// let content = fs.read_file_content(Path::new("/root/.bash_history")).unwrap();
    /// assert!(content.contains("nails"));
    /// ```
    pub fn mock_set_file_content(&self, path: &str, content: &str) {
        let path_buf = PathBuf::from(path);

        // Seeding content implies the file exists: without this, `path_exists`,
        // `file_size` and the pattern scanners would disagree with
        // `read_file_content`, which is exactly the kind of mock/real divergence
        // the contract suite exists to catch.
        {
            let mut paths = self.paths.lock().expect("MockFilesystem mutex poisoned");
            let entry = paths.entry(path_buf.clone()).or_default();
            entry.exists = true;
            entry.is_directory = false;
        }

        let mut contents = self
            .file_contents
            .lock()
            .expect("MockFilesystem mutex poisoned");
        contents.insert(path_buf, content.to_string());
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
    /// use nails_base::filesystem::{Filesystem, MockFilesystem};
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
    /// use nails_base::filesystem::{Filesystem, MockFilesystem};
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
    /// use nails_base::filesystem::{Filesystem, MockFilesystem};
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
