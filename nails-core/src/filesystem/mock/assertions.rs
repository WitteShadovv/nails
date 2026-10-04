// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::super::MountInfo;
use super::{MockFilesystem, MockOp};
use std::path::{Path, PathBuf};

impl MockFilesystem {
    /// Get written file content for test verification
    ///
    /// Returns the content that was written to a file via write_file_content(),
    /// or None if the file was not written.
    pub fn get_written_content(&self, path: &Path) -> Option<String> {
        let written = self
            .written_files
            .lock()
            .expect("MockFilesystem mutex poisoned");
        written.get(path).cloned()
    }

    /// Get operation log for verifying call ordering in tests
    pub fn mock_ops(&self) -> Vec<MockOp> {
        self.op_log
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .clone()
    }

    /// Get list of currently mounted paths
    ///
    /// Useful for test assertions.
    pub fn get_mounted_paths(&self) -> Vec<PathBuf> {
        self.mounted
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .iter()
            .cloned()
            .collect()
    }

    /// Get mount info for a specific overlay
    ///
    /// Returns None if the target is not currently mounted as an overlay.
    pub fn mock_get_mount_info(&self, target: &Path) -> Option<MountInfo> {
        self.mounted_overlays
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(target)
            .cloned()
    }

    /// Get the permissions that were set on a path via `set_permissions`
    ///
    /// Returns `None` if no permissions were explicitly set on this path.
    pub fn mock_get_permissions(&self, path: &Path) -> Option<u32> {
        self.permissions
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(path)
            .copied()
    }

    /// Get the symlink target recorded by `create_symlink`
    ///
    /// Returns `None` if no symlink was created at this path.
    pub fn mock_get_symlink_target(&self, link: &Path) -> Option<PathBuf> {
        self.symlink_targets
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(link)
            .cloned()
    }

    /// Get the numeric `(uid, gid)` ownership recorded by `write_user_file`.
    ///
    /// Returns `None` for a path `write_user_file` never created (ordinary
    /// `write_file_content`, `create_directory`, and similar do not record
    /// ownership).
    pub fn mock_get_owner(&self, path: &Path) -> Option<(u32, u32)> {
        self.owners
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(path)
            .copied()
    }

    /// Get the bind-mount source recorded for `target`, if a bind mount is active
    /// there. Lets tests assert what was bind-mounted where.
    pub fn mock_bind_source(&self, target: &Path) -> Option<PathBuf> {
        self.bind_mounts
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(target)
            .cloned()
    }

    /// Whether a read-only self-bind guard is currently applied to `target`.
    ///
    /// Set by [`Filesystem::remount_read_only`](crate::Filesystem::remount_read_only)
    /// and cleared by [`Filesystem::unmount_bind`](crate::Filesystem::unmount_bind),
    /// so tests can assert both that the guard went on and that a rollback took it
    /// back off.
    pub fn mock_is_read_only_guarded(&self, target: &Path) -> bool {
        self.read_only_guards
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .contains(target)
    }
}
