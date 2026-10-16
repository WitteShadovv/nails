// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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
mod loop_ops;
mod mount_ops;
mod noatime;
mod system_ops;

/// Read-only, access-time-preserving opens and listings, shared with the
/// forensic readers (`nails_forensics::forensic`) so every read of the decoy goes
/// through the same `O_NOATIME` path.
pub use noatime::{EntryType, NoatimeEntry, OpenKind, open_noatime, read_dir_noatime};

/// Shared with [`crate::filesystem::safe_path`] so the hidden-root atomic write
/// reuses the same unpredictable, `O_EXCL`-guarded temp-name scheme as the
/// user-home write path.
pub(crate) use file_ops::unique_temp_name;

use super::{Filesystem, MountEntry, MountSource};
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
    fn mount_table(&self) -> Result<Vec<MountEntry>> {
        mount_ops::mount_table()
    }

    fn is_mounted(&self, target: &Path) -> Result<bool> {
        mount_ops::is_mounted(target)
    }

    fn get_filesystem_type(&self, target: &Path) -> Result<Option<String>> {
        mount_ops::get_filesystem_type(target)
    }

    fn is_mount_read_only(&self, target: &Path) -> Result<bool> {
        mount_ops::is_mount_read_only(target)
    }

    fn mount_source(&self, mount_point: &Path) -> Result<Option<MountSource>> {
        mount_ops::mount_source(mount_point)
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

    fn loop_backing_device(&self, node: &Path) -> Result<u64> {
        loop_ops::loop_backing_device(node)
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

    fn write_hidden_file_atomic(
        &self,
        hidden_root: &Path,
        relative: &Path,
        content: &str,
        mode: u32,
    ) -> Result<()> {
        // Resolve the target beneath the hidden-root fd with openat2 and write
        // through the atomic temp-then-rename path, so a symlink planted at the
        // final component cannot redirect the write off the hidden volume.
        crate::filesystem::SafeRoot::open(hidden_root)?.write_atomic(
            relative,
            content.as_bytes(),
            mode,
        )
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

    fn nails_process_matches(&self) -> Result<Vec<crate::filesystem::ProcessMatch>> {
        system_ops::nails_process_matches()
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

    fn overwrite_file_in_place(&self, path: &Path, content: &str) -> Result<()> {
        file_ops::overwrite_file_in_place(path, content)
    }

    fn find_files_with_pattern(&self, dir: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
        file_ops::find_files_with_pattern(self, dir, pattern)
    }

    fn scan_files_with_pattern(
        &self,
        dir: &Path,
        pattern: &str,
    ) -> Result<crate::filesystem::PatternScan> {
        file_ops::scan_files_with_pattern(dir, pattern)
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

    fn modified_time(&self, path: &Path) -> Result<std::time::SystemTime> {
        // `dir_ops::modified_time` (owned by another chunk) still yields a
        // `chrono` timestamp; convert at this boundary so the trait never
        // exposes `chrono`.
        Ok(std::time::SystemTime::from(dir_ops::modified_time(path)?))
    }

    fn copy_tree(&self, src: &Path, dst: &Path) -> Result<()> {
        dir_ops::copy_tree(src, dst)
    }

    fn copy_file(&self, src: &Path, dst: &Path) -> Result<()> {
        std::fs::copy(src, dst).map_err(|e| {
            crate::NailsError::io(
                src,
                std::io::Error::new(
                    e.kind(),
                    format!("failed to copy {} to {}: {e}", src.display(), dst.display()),
                ),
            )
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
