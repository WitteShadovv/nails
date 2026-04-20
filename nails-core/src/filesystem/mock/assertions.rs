use super::super::MountInfo;
use super::{MockFilesystem, MockOp};
use std::path::{Path, PathBuf};

impl MockFilesystem {
    /// Get written file content for test verification (Story 5.2)
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

    /// Get the symlink target recorded by `create_symlink` (Story 15.2)
    ///
    /// Returns `None` if no symlink was created at this path.
    pub fn mock_get_symlink_target(&self, link: &Path) -> Option<PathBuf> {
        self.symlink_targets
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(link)
            .cloned()
    }
}
