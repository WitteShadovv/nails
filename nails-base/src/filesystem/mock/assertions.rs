// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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

    /// Every path a file write (`write_file_content`, an in-place overwrite,
    /// `write_user_file`) has left content at, sorted: the state a read-only
    /// check must leave empty.
    pub fn mock_written_paths(&self) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = self
            .written_files
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .keys()
            .cloned()
            .collect();
        paths.sort();
        paths
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
}
