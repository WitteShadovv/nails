// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::super::{Filesystem, MountEntry, MountSource};
use super::MockFilesystem;
use crate::Result;
use crate::target_user::TargetUser;
use std::path::{Path, PathBuf};

impl Filesystem for MockFilesystem {
    fn mount_table(&self) -> Result<Vec<MountEntry>> {
        self.mount_table_result()
    }

    fn is_mounted(&self, target: &Path) -> Result<bool> {
        self.is_mounted_impl(target)
    }

    fn get_filesystem_type(&self, target: &Path) -> Result<Option<String>> {
        self.get_filesystem_type_impl(target)
    }

    fn is_mount_read_only(&self, target: &Path) -> Result<bool> {
        Ok(self.is_mount_read_only_impl(target))
    }

    fn mount_source(&self, mount_point: &Path) -> Result<Option<MountSource>> {
        self.mount_source_impl(mount_point)
    }

    fn path_exists(&self, path: &Path) -> Result<bool> {
        self.path_exists_impl(path)
    }

    fn is_directory(&self, path: &Path) -> Result<bool> {
        self.is_directory_impl(path)
    }

    fn is_regular_file(&self, path: &Path) -> Result<bool> {
        self.is_regular_file_impl(path)
    }

    fn device_id(&self, path: &Path) -> Result<u64> {
        self.device_id_impl(path)
    }

    fn loop_backing_device(&self, node: &Path) -> Result<u64> {
        self.loop_backing_device_impl(node)
    }

    fn is_symlink(&self, path: &Path) -> Result<bool> {
        self.is_symlink_impl(path)
    }

    fn is_overlay_whiteout(&self, path: &Path) -> Result<bool> {
        self.is_overlay_whiteout_impl(path)
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf> {
        self.canonicalize_impl(path)
    }

    fn create_symlink(&self, target: &Path, link: &Path) -> Result<()> {
        self.create_symlink_impl(target, link)
    }

    fn disk_usage(&self, path: &Path) -> Result<crate::filesystem::DiskUsage> {
        self.disk_usage_impl(path)
    }

    fn create_directory(&self, path: &Path) -> Result<()> {
        self.create_directory_impl(path)
    }

    fn set_permissions(&self, path: &Path, mode: u32) -> Result<()> {
        self.set_permissions_impl(path, mode)
    }

    fn get_permissions(&self, path: &Path) -> Result<u32> {
        self.get_permissions_impl(path)
    }

    fn is_readable(&self, path: &Path) -> Result<bool> {
        self.is_readable_impl(path)
    }

    fn is_writable(&self, path: &Path) -> Result<bool> {
        self.is_writable_impl(path)
    }

    fn nails_process_matches(&self) -> Result<Vec<super::super::ProcessMatch>> {
        self.nails_process_matches_impl()
    }

    fn read_file_content(&self, path: &Path) -> Result<String> {
        self.read_file_content_impl(path)
    }

    fn read_file_bytes(&self, path: &Path) -> Result<Vec<u8>> {
        self.read_file_bytes_impl(path)
    }

    fn mount_root(&self, path: &Path) -> Result<crate::filesystem::MountRoot> {
        if self.is_symlink_impl(path)? {
            return Ok(crate::filesystem::MountRoot::Link);
        }
        match self
            .mount_roots
            .lock()
            .expect("MockFilesystem mutex poisoned")
            .get(path)
        {
            Some(Ok(mount_root)) => Ok(*mount_root),
            Some(Err(kind)) => Err(crate::NailsError::io(
                path,
                std::io::Error::new(*kind, "Mock: statx fails here"),
            )),
            None => Ok(crate::filesystem::MountRoot::Entry(None)),
        }
    }

    fn find_files_with_pattern(&self, dir: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
        self.find_files_with_pattern_impl(dir, pattern)
    }

    fn scan_files_with_pattern(
        &self,
        dir: &Path,
        pattern: &str,
    ) -> Result<super::super::PatternScan> {
        self.scan_files_with_pattern_impl(dir, pattern)
    }

    fn write_file_content(&self, path: &Path, content: &str) -> Result<()> {
        self.write_file_content_impl(path, content)
    }

    fn write_user_file(
        &self,
        path: &Path,
        content: &str,
        user: &TargetUser,
        default_mode: u32,
    ) -> Result<()> {
        self.write_user_file_impl(path, content, user, default_mode)
    }

    fn overwrite_file_in_place(&self, path: &Path, content: &str) -> Result<()> {
        self.overwrite_file_in_place_impl(path, content)
    }

    fn list_directory(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        self.list_directory_impl(dir)
    }

    fn file_size(&self, path: &Path) -> Result<u64> {
        self.file_size_impl(path)
    }

    fn rename_file(&self, from: &Path, to: &Path) -> Result<()> {
        self.rename_file_impl(from, to)
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        self.remove_file_impl(path)
    }

    fn remove_directory(&self, path: &Path) -> Result<()> {
        self.remove_directory_impl(path)
    }

    fn remove_dir_all(&self, path: &Path) -> Result<()> {
        self.remove_dir_all_impl(path)
    }

    fn secure_delete(&self, path: &Path) -> Result<()> {
        self.secure_delete_impl(path)
    }

    fn secure_delete_dir_all(&self, path: &Path) -> Result<()> {
        self.secure_delete_dir_all_impl(path)
    }

    fn supports_symlinks(&self, dir: &Path) -> Result<bool> {
        self.supports_symlinks_impl(dir)
    }

    fn modified_time(&self, path: &Path) -> Result<std::time::SystemTime> {
        self.modified_time_impl(path)
    }

    fn copy_file(&self, src: &Path, dst: &Path) -> Result<()> {
        self.copy_file_impl(src, dst)
    }

    fn copy_tree(&self, src: &Path, dst: &Path) -> Result<()> {
        self.copy_tree_impl(src, dst)
    }
}
