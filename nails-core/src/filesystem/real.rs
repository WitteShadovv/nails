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

use super::{Filesystem, MountInfo, verify_mount_preconditions};
use crate::{NailsError, Result};
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
    fn mount_overlay(&self, lower: &Path, upper: &Path, work: &Path, target: &Path) -> Result<()> {
        // Verify all preconditions using the helper function
        verify_mount_preconditions(self, lower, upper, work, target)?;

        // Build overlay options
        let options = format!(
            "lowerdir={},upperdir={},workdir={}",
            lower.display(),
            upper.display(),
            work.display()
        );

        // Perform mount using nix crate with security flags
        // MS_NOSUID: Prevent setuid/setgid bits from taking effect
        // MS_NODEV: Prevent access to device files
        // MS_NOEXEC: NOT used - /home and /etc overlays must allow execution
        //            (user scripts, shell configs, system binaries in hidden environment)
        //            Story 4.11 may introduce different strategies for tmpfs-backed layers
        nix::mount::mount(
            Some("overlay"),
            target,
            Some("overlay"),
            nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV,
            Some(options.as_str()),
        )
        .map_err(|e| {
            // Check for specific error conditions
            if e == nix::errno::Errno::EACCES || e == nix::errno::Errno::EPERM {
                NailsError::PermissionDenied("Mount requires root privileges".to_string())
            } else {
                NailsError::OverlayError(format!("Failed to mount {}: {}", target.display(), e))
            }
        })?;

        Ok(())
    }

    fn unmount(&self, target: &Path, force: bool) -> Result<()> {
        // Idempotent: succeed if not mounted
        if !self.is_mounted(target)? {
            return Ok(());
        }

        // Set flags
        let flags = if force {
            nix::mount::MntFlags::MNT_FORCE | nix::mount::MntFlags::MNT_DETACH
        } else {
            nix::mount::MntFlags::empty()
        };

        // Perform unmount
        nix::mount::umount2(target, flags).map_err(|e| {
            if e == nix::errno::Errno::EBUSY {
                NailsError::MountBusy {
                    path: target.to_path_buf(),
                    suggestion: "Use force=true or close open files".to_string(),
                }
            } else {
                NailsError::UnmountError {
                    path: target.to_path_buf(),
                    reason: format!("{}", e),
                }
            }
        })?;

        Ok(())
    }

    fn is_mounted(&self, target: &Path) -> Result<bool> {
        // Parse /proc/mounts to check if path is mounted
        let mounts = std::fs::read_to_string("/proc/mounts")?;
        let canonical_target = target
            .canonicalize()
            .unwrap_or_else(|_| target.to_path_buf());

        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2
                && let Ok(mount_point) = PathBuf::from(parts[1]).canonicalize()
                && mount_point == canonical_target
            {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn get_mount_info(&self, target: &Path) -> Option<MountInfo> {
        // For RealFilesystem, parse /proc/mounts to find mount info
        // Note: Linux /proc/mounts only shows mount point and type, not overlay paths
        // For proper rollback support, mount info should be persisted in state file
        // during activation. This is a best-effort implementation for now.
        let mounts = std::fs::read_to_string("/proc/mounts").ok()?;
        let canonical_target = target.canonicalize().ok()?;

        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let mount_point = PathBuf::from(parts[1]).canonicalize().ok()?;
                let fs_type = parts[2];

                if mount_point == canonical_target && fs_type == "overlay" {
                    // Parse overlay options (lowerdir=...,upperdir=...,workdir=...)
                    let options = parts[3];
                    let mut lower = None;
                    let mut upper = None;
                    let mut work = None;

                    for opt in options.split(',') {
                        if let Some(path) = opt.strip_prefix("lowerdir=") {
                            lower = Some(PathBuf::from(path.split(':').next()?));
                        } else if let Some(path) = opt.strip_prefix("upperdir=") {
                            upper = Some(PathBuf::from(path));
                        } else if let Some(path) = opt.strip_prefix("workdir=") {
                            work = Some(PathBuf::from(path));
                        }
                    }

                    if let (Some(l), Some(u), Some(w)) = (lower, upper, work) {
                        return Some(MountInfo {
                            lower: l,
                            upper: u,
                            work: w,
                            target: canonical_target,
                            mounted_at: chrono::Utc::now(), // Approximation
                        });
                    }
                }
            }
        }

        None
    }

    fn swap_is_enabled(&self) -> Result<bool> {
        // Parse /proc/swaps
        let swaps = std::fs::read_to_string("/proc/swaps")?;
        // Skip header line, check if any swap entries exist
        Ok(swaps.lines().count() > 1)
    }

    fn swap_disable(&self) -> Result<()> {
        // Idempotent: succeed if already disabled
        if !self.swap_is_enabled()? {
            return Ok(());
        }

        // Use swapoff command
        std::process::Command::new("swapoff")
            .arg("-a")
            .output()
            .map_err(|_| NailsError::SwapDisableFailed)?;

        Ok(())
    }

    fn path_exists(&self, path: &Path) -> Result<bool> {
        Ok(path.exists())
    }

    fn is_directory(&self, path: &Path) -> Result<bool> {
        Ok(path.is_dir())
    }

    fn is_symlink(&self, path: &Path) -> Result<bool> {
        Ok(path.is_symlink())
    }

    fn create_symlink(&self, target: &Path, link: &Path) -> Result<()> {
        // Idempotent: if symlink already exists pointing to the same target, no-op
        if link.is_symlink() {
            let existing_target = std::fs::read_link(link).map_err(NailsError::IoError)?;
            if existing_target == target {
                return Ok(());
            }
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "Symlink at {} already exists pointing to a different target",
                    link.display()
                ),
            )));
        }
        if link.exists() {
            return Err(NailsError::IoError(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!("Path already exists (not a symlink) at {}", link.display()),
            )));
        }
        std::os::unix::fs::symlink(target, link).map_err(NailsError::IoError)
    }

    fn get_free_space(&self, path: &Path) -> Result<u64> {
        // Use std::fs metadata (works on any path on filesystem)
        let _metadata = std::fs::metadata(path)?;
        // Note: This is simplified - real implementation would use statvfs
        // For now, return a large number as placeholder
        Ok(u64::MAX)
    }

    fn create_directory(&self, path: &Path) -> Result<()> {
        std::fs::create_dir_all(path)?;
        Ok(())
    }

    fn set_permissions(&self, path: &Path, mode: u32) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(mode);
        std::fs::set_permissions(path, perms)?;
        Ok(())
    }

    fn get_permissions(&self, path: &Path) -> Result<u32> {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        Ok(mode & 0o7777)
    }

    fn is_readable(&self, path: &Path) -> Result<bool> {
        // Try to open file for reading
        Ok(std::fs::File::open(path).is_ok())
    }

    fn is_writable(&self, path: &Path) -> Result<bool> {
        // Try to open file for writing
        if path.is_dir() {
            // For directories, try to create a temp file
            let test_path = path.join(".nails_write_test");
            match std::fs::File::create(&test_path) {
                Ok(_) => {
                    std::fs::remove_file(&test_path)?;
                    Ok(true)
                }
                Err(_) => Ok(false),
            }
        } else {
            // For files, try to open for append
            Ok(std::fs::OpenOptions::new().append(true).open(path).is_ok())
        }
    }

    fn nixos_profile_exists(&self, profile: &str) -> Result<bool> {
        // Check if profile symlink exists in /nix/var/nix/profiles/
        let profile_path = PathBuf::from("/nix/var/nix/profiles").join(profile);
        Ok(profile_path.exists())
    }

    fn nixos_build_profile(&self, profile: &str) -> Result<()> {
        // Use nixos-rebuild build
        let output = std::process::Command::new("nixos-rebuild")
            .arg("build")
            .arg("--profile")
            .arg(profile)
            .output()
            .map_err(|_e| NailsError::NixOSBuildFailed {
                profile: profile.to_string(),
            })?;

        if !output.status.success() {
            return Err(NailsError::NixOSBuildFailed {
                profile: profile.to_string(),
            });
        }

        Ok(())
    }

    fn nixos_switch_profile(&self, profile: &str) -> Result<()> {
        // Check if profile exists
        if !self.nixos_profile_exists(profile)? {
            return Err(NailsError::NixOSProfileNotFound {
                profile: profile.to_string(),
            });
        }

        // Use nixos-rebuild switch
        let output = std::process::Command::new("nixos-rebuild")
            .arg("switch")
            .arg("--profile")
            .arg(profile)
            .output()
            .map_err(|_e| NailsError::NixOSSwitchFailed {
                profile: profile.to_string(),
            })?;

        if !output.status.success() {
            return Err(NailsError::NixOSSwitchFailed {
                profile: profile.to_string(),
            });
        }

        Ok(())
    }

    fn nixos_get_current_profile(&self) -> Result<String> {
        // Read /nix/var/nix/profiles/system to get current profile
        let system_path = PathBuf::from("/nix/var/nix/profiles/system");
        if !system_path.exists() {
            return Err(NailsError::InvalidState(
                "No NixOS profile is currently active".into(),
            ));
        }

        // Try to read symlink target
        system_path
            .read_link()
            .map(|target| target.to_string_lossy().to_string())
            .map_err(|_| NailsError::InvalidState("Could not determine current profile".into()))
    }

    fn nails_process_running(&self) -> Result<bool> {
        // Scan /proc for nails-related processes
        let proc_path = Path::new("/proc");

        if !proc_path.exists() {
            // Not on Linux or /proc not mounted
            return Ok(false);
        }

        // Iterate through /proc/*/cmdline to find nails processes
        if let Ok(entries) = std::fs::read_dir(proc_path) {
            for entry in entries.flatten() {
                let entry_path = entry.path();
                let pid_dir = entry_path.file_name().and_then(|n| n.to_str());

                // Check if it's a numeric PID directory
                if pid_dir.is_some_and(|p| p.chars().all(|c| c.is_ascii_digit())) {
                    let cmdline_path = entry_path.join("cmdline");

                    if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                        // Check if cmdline contains "nails"
                        if cmdline.to_lowercase().contains("nails") {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    fn read_file_content(&self, path: &Path) -> Result<String> {
        std::fs::read_to_string(path).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to read file {}: {}", path.display(), e),
            ))
        })
    }

    fn write_file_content(&self, path: &Path, content: &str) -> Result<()> {
        use std::io::Write;

        // Write to temporary file first, then atomic rename
        let temp_path = path.with_extension("tmp");

        // Write content to temp file
        let mut temp_file = std::fs::File::create(&temp_path).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to create temp file {}: {}", temp_path.display(), e),
            ))
        })?;

        temp_file.write_all(content.as_bytes()).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to write to temp file {}: {}",
                    temp_path.display(),
                    e
                ),
            ))
        })?;

        // Ensure data is flushed to disk
        temp_file.sync_all().map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to sync temp file {}: {}", temp_path.display(), e),
            ))
        })?;

        // Atomic rename
        std::fs::rename(&temp_path, path).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to rename {} to {}: {}",
                    temp_path.display(),
                    path.display(),
                    e
                ),
            ))
        })?;

        Ok(())
    }

    fn find_files_with_pattern(&self, dir: &Path, pattern: &str) -> Result<Vec<PathBuf>> {
        let mut matching_files = Vec::new();

        if !dir.exists() || !dir.is_dir() {
            return Ok(matching_files);
        }

        // Recursively walk the directory tree
        let entries = std::fs::read_dir(dir).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to read directory {}: {}", dir.display(), e),
            ))
        })?;

        for entry in entries.flatten() {
            let path = entry.path();

            if path.is_dir() {
                // Recursively scan subdirectories
                matching_files.extend(self.find_files_with_pattern(&path, pattern)?);
            } else if path.is_file() {
                // Check if filename contains the pattern
                if let Some(filename) = path.file_name()
                    && filename
                        .to_string_lossy()
                        .to_lowercase()
                        .contains(&pattern.to_lowercase())
                {
                    matching_files.push(path);
                }
            }
        }

        Ok(matching_files)
    }

    fn mount_tmpfs(&self, target: &Path, size: &str) -> Result<()> {
        // Validate size string format before attempting mount
        // Valid formats: "512M", "1G", "2048K", etc.
        // Use a temporary EphemeralOverlayDir to leverage existing validation
        let temp_dir = crate::config::EphemeralOverlayDir {
            path: target.to_path_buf(),
            tmpfs_upper_size: size.to_string(),
            tmpfs_work_size: "1M".to_string(), // Dummy value for validation
        };
        temp_dir.parse_upper_size().map_err(|e| {
            NailsError::ConfigError(format!("Invalid tmpfs size '{}': {}", size, e))
        })?;

        // Create mount point if needed
        std::fs::create_dir_all(target)?;

        // Build mount options
        let options = format!("size={}", size);

        // Perform mount using nix crate
        // MS_NOSUID: Prevent setuid/setgid bits from taking effect
        // MS_NODEV: Prevent access to device files
        nix::mount::mount(
            Some("tmpfs"),
            target,
            Some("tmpfs"),
            nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV,
            Some(options.as_str()),
        )
        .map_err(|e| {
            if e == nix::errno::Errno::EACCES || e == nix::errno::Errno::EPERM {
                NailsError::PermissionDenied("Tmpfs mount requires root privileges".to_string())
            } else {
                NailsError::OverlayError(format!(
                    "Failed to mount tmpfs at {}: {}",
                    target.display(),
                    e
                ))
            }
        })?;

        Ok(())
    }

    fn unmount_tmpfs(&self, target: &Path) -> Result<()> {
        // Idempotent: succeed if not mounted
        if !self.is_mounted(target)? {
            return Ok(());
        }

        // Perform unmount (regular unmount, not force)
        nix::mount::umount(target).map_err(|e| NailsError::UnmountError {
            path: target.to_path_buf(),
            reason: format!("{}", e),
        })?;

        Ok(())
    }

    fn bind_mount(&self, source: &Path, target: &Path) -> Result<()> {
        // Verify source exists
        if !source.exists() {
            return Err(NailsError::OverlayError(format!(
                "Bind mount source not found: {}",
                source.display()
            )));
        }

        // Perform bind mount using nix crate
        // MS_BIND: Create a bind mount
        nix::mount::mount(
            Some(source),
            target,
            None::<&str>,
            nix::mount::MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| {
            if e == nix::errno::Errno::EACCES || e == nix::errno::Errno::EPERM {
                NailsError::PermissionDenied("Bind mount requires root privileges".to_string())
            } else if e == nix::errno::Errno::EBUSY {
                NailsError::MountBusy {
                    path: target.to_path_buf(),
                    suggestion: "Target directory has active references".to_string(),
                }
            } else {
                NailsError::OverlayError(format!(
                    "Failed to bind mount {} to {}: {}",
                    source.display(),
                    target.display(),
                    e
                ))
            }
        })?;

        Ok(())
    }

    fn unmount_bind(&self, target: &Path) -> Result<()> {
        // Idempotent: succeed if not mounted
        if !self.is_mounted(target)? {
            return Ok(());
        }

        // Perform unmount (regular unmount for bind mounts)
        nix::mount::umount(target).map_err(|e| NailsError::UnmountError {
            path: target.to_path_buf(),
            reason: format!("{}", e),
        })?;

        Ok(())
    }

    fn file_size(&self, path: &Path) -> Result<u64> {
        let metadata = std::fs::metadata(path).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to get file size for {}: {}", path.display(), e),
            ))
        })?;
        Ok(metadata.len())
    }

    fn rename_file(&self, from: &Path, to: &Path) -> Result<()> {
        std::fs::rename(from, to).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to rename {} to {}: {}",
                    from.display(),
                    to.display(),
                    e
                ),
            ))
        })
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        std::fs::remove_file(path).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to remove file {}: {}", path.display(), e),
            ))
        })
    }

    fn remove_dir_all(&self, path: &Path) -> Result<()> {
        std::fs::remove_dir_all(path).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to remove directory {}: {}", path.display(), e),
            ))
        })
    }

    fn list_directory(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        let entries = std::fs::read_dir(dir).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to read directory {}: {}", dir.display(), e),
            ))
        })?;

        let mut paths = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| {
                NailsError::IoError(std::io::Error::new(
                    e.kind(),
                    format!("Failed to read directory entry in {}: {}", dir.display(), e),
                ))
            })?;
            paths.push(entry.path());
        }

        Ok(paths)
    }

    fn enumerate_root_directories(&self) -> Result<Vec<PathBuf>> {
        let root = Path::new("/");

        // Read all entries under /
        let entries = std::fs::read_dir(root).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to read /: {}", e),
            ))
        })?;

        let mut directories = Vec::new();

        for entry in entries {
            let entry = entry.map_err(|e| {
                NailsError::IoError(std::io::Error::new(
                    e.kind(),
                    format!("Failed to read directory entry: {}", e),
                ))
            })?;
            let path = entry.path();

            // Get metadata without following symlinks (using symlink_metadata)
            let metadata = std::fs::symlink_metadata(&path).map_err(|e| {
                NailsError::IoError(std::io::Error::new(
                    e.kind(),
                    format!("Failed to get metadata for {}: {}", path.display(), e),
                ))
            })?;

            // Skip symlinks (even if they point to directories)
            if metadata.is_symlink() {
                tracing::debug!(
                    "Skipping symlink: {} -> {:?}",
                    path.display(),
                    std::fs::read_link(&path)
                );
                continue;
            }

            // Skip non-directories
            if !metadata.is_dir() {
                continue;
            }

            // Skip /run/nails directory (Story 14.10, Issue 6)
            // This is NAILS' own runtime directory and should never be overlaid
            // to prevent nested overlay filesystem issues
            if path.starts_with("/run/nails") {
                tracing::debug!("Skipping NAILS runtime directory: {}", path.display());
                continue;
            }

            directories.push(path);
        }

        // Sort alphabetically for consistent mount order (Story 14.10)
        // Alphabetical sorting ensures deterministic behavior:
        // - Mount order: /boot, /etc, /home, /var, ...
        // - Unmount order: reverse of mount (LIFO stack)
        // This is different from pre-14.10 hardcoded order (/home, /etc, /var)
        // but provides better scalability for dynamic enumeration
        directories.sort();

        Ok(directories)
    }

    fn read_directory(&self, path: &Path) -> Result<Vec<std::fs::DirEntry>> {
        let entries = std::fs::read_dir(path).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to read directory {}: {}", path.display(), e),
            ))
        })?;

        let mut result = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| {
                NailsError::IoError(std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to read directory entry in {}: {}",
                        path.display(),
                        e
                    ),
                ))
            })?;
            result.push(entry);
        }

        Ok(result)
    }

    fn modified_time(&self, path: &Path) -> Result<chrono::DateTime<chrono::Utc>> {
        let metadata = std::fs::metadata(path).map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!("Failed to get metadata for {}: {}", path.display(), e),
            ))
        })?;

        let modified = metadata.modified().map_err(|e| {
            NailsError::IoError(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to get modification time for {}: {}",
                    path.display(),
                    e
                ),
            ))
        })?;

        // Convert SystemTime to DateTime<Utc>
        let datetime: chrono::DateTime<chrono::Utc> = modified.into();
        Ok(datetime)
    }
}

#[cfg(test)]
#[path = "real_tests.rs"]
mod tests;
