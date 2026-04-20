//! Real filesystem using system calls
//!
//! Uses actual syscalls for production use. Requires root privileges for mount/unmount operations.
//!
//! # Security
//!
//! - Mount operations require CAP_SYS_ADMIN capability
//! - All operations return proper NailsError types
//! - Force flag enables MNT_FORCE | MNT_DETACH for unmount
//!
//! # Platform
//!
//! Only works on Linux systems with OverlayFS support.

mod dir_ops;
mod file_ops;
mod mount_ops;
mod submount;
mod system_ops;

#[cfg(test)]
pub(crate) use submount::parse_submount_sources;

use super::{Filesystem, MountInfo};
use crate::Result;
use std::path::{Path, PathBuf};

// ============================================================================
// RealFilesystem - Production Implementation
// ============================================================================

/// Real filesystem using system calls
///
/// Uses actual syscalls for production use. Requires root privileges for mount/unmount operations.
///
/// # Security
///
/// - Mount operations require CAP_SYS_ADMIN capability
/// - All operations return proper NailsError types
/// - Force flag enables MNT_FORCE | MNT_DETACH for unmount
///
/// # Platform
///
/// Only works on Linux systems with OverlayFS support.
#[derive(Debug, Clone, Copy)]
pub struct RealFilesystem;

impl Default for RealFilesystem {
    fn default() -> Self {
        Self
    }
}

impl Filesystem for RealFilesystem {
    fn mount_overlay(
        &self,
        lower: &[&Path],
        upper: &Path,
        work: &Path,
        target: &Path,
    ) -> Result<()> {
        mount_ops::mount_overlay(self, lower, upper, work, target)
    }

    fn unmount(&self, target: &Path, force: bool) -> Result<()> {
        mount_ops::unmount(self, target, force)
    }

    fn is_mounted(&self, target: &Path) -> Result<bool> {
        mount_ops::is_mounted(target)
    }

    fn get_filesystem_type(&self, target: &Path) -> Result<Option<String>> {
        mount_ops::get_filesystem_type(target)
    }

    fn is_overlay_mounted(&self, target: &Path) -> Result<bool> {
        mount_ops::is_overlay_mounted(target)
    }

    fn get_mount_info(&self, target: &Path) -> Option<MountInfo> {
        mount_ops::get_mount_info(target)
    }

    fn swap_is_enabled(&self) -> Result<bool> {
        system_ops::swap_is_enabled()
    }

    fn swap_disable(&self) -> Result<()> {
        system_ops::swap_disable(self)
    }

    fn path_exists(&self, path: &Path) -> Result<bool> {
        file_ops::path_exists(path)
    }

    fn is_directory(&self, path: &Path) -> Result<bool> {
        file_ops::is_directory(path)
    }

    fn is_symlink(&self, path: &Path) -> Result<bool> {
        file_ops::is_symlink(path)
    }

    fn supports_symlinks(&self, dir: &Path) -> Result<bool> {
        file_ops::supports_symlinks(dir)
    }

    fn create_symlink(&self, target: &Path, link: &Path) -> Result<()> {
        file_ops::create_symlink(target, link)
    }

    fn get_free_space(&self, path: &Path) -> Result<u64> {
        file_ops::get_free_space(path)
    }

    fn create_directory(&self, path: &Path) -> Result<()> {
        file_ops::create_directory(path)
    }

    fn set_permissions(&self, path: &Path, mode: u32) -> Result<()> {
        file_ops::set_permissions(path, mode)
    }

    fn get_permissions(&self, path: &Path) -> Result<u32> {
        file_ops::get_permissions(path)
    }

    fn is_readable(&self, path: &Path) -> Result<bool> {
        file_ops::is_readable(path)
    }

    fn is_writable(&self, path: &Path) -> Result<bool> {
        file_ops::is_writable(path)
    }

    fn nixos_profile_exists(&self, profile: &str) -> Result<bool> {
        system_ops::nixos_profile_exists(profile)
    }

    fn nixos_build_profile(&self, profile: &str) -> Result<()> {
        system_ops::nixos_build_profile(profile)
    }

    fn nixos_switch_profile(&self, profile: &str) -> Result<()> {
        system_ops::nixos_switch_profile(self, profile)
    }

    fn nixos_get_current_profile(&self) -> Result<String> {
        system_ops::nixos_get_current_profile()
    }

    fn nails_process_running(&self) -> Result<bool> {
        system_ops::nails_process_running()
    }

    fn read_file_content(&self, path: &Path) -> Result<String> {
        file_ops::read_file_content(path)
    }

    fn write_file_content(&self, path: &Path, content: &str) -> Result<()> {
        file_ops::write_file_content(path, content)
    }

    fn find_files_with_pattern(&self, dir: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
        file_ops::find_files_with_pattern(self, dir, pattern)
    }

    fn mount_tmpfs(&self, target: &Path, size: &str) -> Result<()> {
        mount_ops::mount_tmpfs(target, size)
    }

    fn unmount_tmpfs(&self, target: &Path) -> Result<()> {
        mount_ops::unmount_tmpfs(self, target)
    }

    fn bind_mount(&self, source: &Path, target: &Path) -> Result<()> {
        mount_ops::bind_mount(source, target)
    }

    fn unmount_bind(&self, target: &Path) -> Result<()> {
        mount_ops::unmount_bind(self, target)
    }

    fn file_size(&self, path: &Path) -> Result<u64> {
        file_ops::file_size(path)
    }

    fn rename_file(&self, from: &Path, to: &Path) -> Result<()> {
        file_ops::rename_file(from, to)
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        file_ops::remove_file(path)
    }

    fn remove_directory(&self, path: &Path) -> Result<()> {
        file_ops::remove_directory(path)
    }

    fn remove_dir_all(&self, path: &Path) -> Result<()> {
        file_ops::remove_dir_all(path)
    }

    fn secure_delete(&self, path: &Path) -> Result<()> {
        file_ops::secure_delete(self, path)
    }

    fn secure_delete_dir_all(&self, path: &Path) -> Result<()> {
        file_ops::secure_delete_dir_all(self, path)
    }

    fn list_directory(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        dir_ops::list_directory(dir)
    }

    fn enumerate_root_directories(&self) -> Result<Vec<PathBuf>> {
        dir_ops::enumerate_root_directories()
    }

    fn read_directory(&self, path: &Path) -> Result<Vec<std::fs::DirEntry>> {
        dir_ops::read_directory(path)
    }

    fn modified_time(&self, path: &Path) -> Result<chrono::DateTime<chrono::Utc>> {
        dir_ops::modified_time(path)
    }

    fn copy_tree(&self, src: &Path, dst: &Path) -> Result<()> {
        dir_ops::copy_tree(src, dst)
    }

    fn get_directory_size(&self, path: &Path) -> Result<u64> {
        dir_ops::get_directory_size(path)
    }

    fn find_submount_sources(&self, target: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
        dir_ops::find_submount_sources(target)
    }
}

#[cfg(test)]
mod tests;
