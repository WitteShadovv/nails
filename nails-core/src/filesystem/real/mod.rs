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

/// Shared with [`crate::filesystem::safe_path`] so the hidden-root atomic write
/// reuses the same unpredictable, `O_EXCL`-guarded temp-name scheme as the
/// user-home write path.
pub(crate) use file_ops::unique_temp_name;

use super::{Filesystem, MountInfo, MountSource};
use crate::Result;
use crate::target_user::TargetUser;
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

    fn mount_source(&self, mount_point: &Path) -> Result<Option<MountSource>> {
        mount_ops::mount_source(mount_point)
    }

    fn discover_nails_mounts(
        &self,
        hidden_root: Option<&Path>,
    ) -> Result<crate::filesystem::NailsMounts> {
        crate::filesystem::NailsMounts::discover(hidden_root)
    }

    fn swap_is_enabled(&self) -> Result<bool> {
        system_ops::swap_is_enabled()
    }

    fn path_exists(&self, path: &Path) -> Result<bool> {
        file_ops::path_exists(path)
    }

    fn is_directory(&self, path: &Path) -> Result<bool> {
        file_ops::is_directory(path)
    }

    fn device_id(&self, path: &Path) -> Result<u64> {
        file_ops::device_id(path)
    }

    fn is_symlink(&self, path: &Path) -> Result<bool> {
        file_ops::is_symlink(path)
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf> {
        file_ops::canonicalize(path)
    }

    fn supports_symlinks(&self, dir: &Path) -> Result<bool> {
        file_ops::supports_symlinks(dir)
    }

    fn create_symlink(&self, target: &Path, link: &Path) -> Result<()> {
        file_ops::create_symlink(target, link)
    }

    fn disk_usage(&self, path: &Path) -> Result<super::DiskUsage> {
        file_ops::disk_usage(path)
    }

    fn create_directory(&self, path: &Path) -> Result<()> {
        file_ops::create_directory(path)
    }

    fn create_hidden_dir_all(&self, hidden_root: &Path, relative: &Path) -> Result<()> {
        // Resolve every component beneath the hidden-root fd with openat2, so a
        // symlink or `..` planted under the root cannot redirect the creation.
        crate::filesystem::SafeRoot::open(hidden_root)?.create_dir_all(relative)
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

    fn nails_process_running(&self) -> Result<bool> {
        system_ops::nails_process_running()
    }

    fn read_file_content(&self, path: &Path) -> Result<String> {
        file_ops::read_file_content(path)
    }

    fn write_file_content(&self, path: &Path, content: &str) -> Result<()> {
        file_ops::write_file_content(path, content)
    }

    fn write_user_file(
        &self,
        path: &Path,
        content: &str,
        user: &TargetUser,
        default_mode: u32,
    ) -> Result<()> {
        file_ops::write_user_file(path, content, user, default_mode)
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

    fn modified_time(&self, path: &Path) -> Result<std::time::SystemTime> {
        // `dir_ops::modified_time` (owned by another chunk) still yields a
        // `chrono` timestamp; convert at this boundary so the trait never
        // exposes `chrono`.
        Ok(std::time::SystemTime::from(dir_ops::modified_time(path)?))
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
