use super::super::{Filesystem, MountInfo};
use super::MockFilesystem;
use crate::Result;
use std::path::{Path, PathBuf};

impl Filesystem for MockFilesystem {
    fn mount_overlay(
        &self,
        lower: &[&Path],
        upper: &Path,
        work: &Path,
        target: &Path,
    ) -> Result<()> {
        self.mount_overlay_impl(lower, upper, work, target)
    }

    fn unmount(&self, target: &Path, force: bool) -> Result<()> {
        self.unmount_impl(target, force)
    }

    fn is_mounted(&self, target: &Path) -> Result<bool> {
        self.is_mounted_impl(target)
    }

    fn get_filesystem_type(&self, target: &Path) -> Result<Option<String>> {
        self.get_filesystem_type_impl(target)
    }

    fn is_overlay_mounted(&self, target: &Path) -> Result<bool> {
        self.is_overlay_mounted_impl(target)
    }

    fn get_mount_info(&self, target: &Path) -> Option<MountInfo> {
        self.get_mount_info_impl(target)
    }

    fn swap_is_enabled(&self) -> Result<bool> {
        self.swap_is_enabled_impl()
    }

    fn swap_disable(&self) -> Result<()> {
        self.swap_disable_impl()
    }

    fn bind_mount(&self, source: &Path, target: &Path) -> Result<()> {
        self.bind_mount_impl(source, target)
    }

    fn unmount_bind(&self, target: &Path) -> Result<()> {
        self.unmount_bind_impl(target)
    }

    fn mount_tmpfs(&self, target: &Path, size: &str) -> Result<()> {
        self.mount_tmpfs_impl(target, size)
    }

    fn unmount_tmpfs(&self, target: &Path) -> Result<()> {
        self.unmount_tmpfs_impl(target)
    }

    fn path_exists(&self, path: &Path) -> Result<bool> {
        self.path_exists_impl(path)
    }

    fn is_directory(&self, path: &Path) -> Result<bool> {
        self.is_directory_impl(path)
    }

    fn is_symlink(&self, path: &Path) -> Result<bool> {
        self.is_symlink_impl(path)
    }

    fn create_symlink(&self, target: &Path, link: &Path) -> Result<()> {
        self.create_symlink_impl(target, link)
    }

    fn get_free_space(&self, path: &Path) -> Result<u64> {
        self.get_free_space_impl(path)
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

    fn nixos_profile_exists(&self, profile: &str) -> Result<bool> {
        self.nixos_profile_exists_impl(profile)
    }

    fn nixos_build_profile(&self, profile: &str) -> Result<()> {
        self.nixos_build_profile_impl(profile)
    }

    fn nixos_switch_profile(&self, profile: &str) -> Result<()> {
        self.nixos_switch_profile_impl(profile)
    }

    fn nixos_get_current_profile(&self) -> Result<String> {
        self.nixos_get_current_profile_impl()
    }

    fn nails_process_running(&self) -> Result<bool> {
        self.nails_process_running_impl()
    }

    fn read_file_content(&self, path: &Path) -> Result<String> {
        self.read_file_content_impl(path)
    }

    fn find_files_with_pattern(&self, dir: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
        self.find_files_with_pattern_impl(dir, pattern)
    }

    fn write_file_content(&self, path: &Path, content: &str) -> Result<()> {
        self.write_file_content_impl(path, content)
    }

    fn list_directory(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        self.list_directory_impl(dir)
    }

    fn enumerate_root_directories(&self) -> Result<Vec<PathBuf>> {
        self.enumerate_root_directories_impl()
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

    fn read_directory(&self, path: &Path) -> Result<Vec<std::fs::DirEntry>> {
        self.read_directory_impl(path)
    }

    fn supports_symlinks(&self, dir: &Path) -> Result<bool> {
        self.supports_symlinks_impl(dir)
    }

    fn modified_time(&self, path: &Path) -> Result<chrono::DateTime<chrono::Utc>> {
        self.modified_time_impl(path)
    }

    fn copy_tree(&self, src: &Path, dst: &Path) -> Result<()> {
        self.copy_tree_impl(src, dst)
    }

    fn get_directory_size(&self, path: &Path) -> Result<u64> {
        self.get_directory_size_impl(path)
    }

    fn find_submount_sources(&self, target: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
        self.find_submount_sources_impl(target)
    }
}
