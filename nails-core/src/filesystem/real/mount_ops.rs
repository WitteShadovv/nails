//! Mount, unmount, and mount-query operations for RealFilesystem.

use super::RealFilesystem;
use crate::filesystem::{Filesystem, MountInfo, verify_mount_preconditions};
use crate::{NailsError, Result};
use std::path::{Path, PathBuf};

/// Perform an overlay mount.
pub(super) fn mount_overlay(
    fs: &RealFilesystem,
    lower: &[&Path],
    upper: &Path,
    work: &Path,
    target: &Path,
) -> Result<()> {
    if lower.is_empty() {
        return Err(NailsError::OverlayError(
            "mount_overlay requires at least one lower layer".to_string(),
        ));
    }
    verify_mount_preconditions(fs, lower[0], upper, work, target)?;

    let lowerdir: String = lower
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(":");

    let options = format!(
        "lowerdir={},upperdir={},workdir={}",
        lowerdir,
        upper.display(),
        work.display()
    );

    nix::mount::mount(
        Some("overlay"),
        target,
        Some("overlay"),
        nix::mount::MsFlags::MS_NOSUID | nix::mount::MsFlags::MS_NODEV,
        Some(options.as_str()),
    )
    .map_err(|e| {
        if e == nix::errno::Errno::EACCES || e == nix::errno::Errno::EPERM {
            NailsError::PermissionDenied("Mount requires root privileges".to_string())
        } else {
            NailsError::OverlayError(format!("Failed to mount {}: {}", target.display(), e))
        }
    })?;

    Ok(())
}

/// Unmount a filesystem (idempotent).
pub(super) fn unmount(fs: &RealFilesystem, target: &Path, force: bool) -> Result<()> {
    if !fs.is_mounted(target)? {
        return Ok(());
    }

    let flags = if force {
        nix::mount::MntFlags::MNT_FORCE | nix::mount::MntFlags::MNT_DETACH
    } else {
        nix::mount::MntFlags::empty()
    };

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

/// Check if a path is currently mounted by parsing /proc/mounts.
pub(super) fn is_mounted(target: &Path) -> Result<bool> {
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

/// Get filesystem type at a mount point.
pub(super) fn get_filesystem_type(target: &Path) -> Result<Option<String>> {
    let mounts = std::fs::read_to_string("/proc/mounts")?;
    let canonical_target = target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf());

    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3
            && let Ok(mount_point) = PathBuf::from(parts[1]).canonicalize()
            && mount_point == canonical_target
        {
            return Ok(Some(parts[2].to_string()));
        }
    }

    Ok(None)
}

/// Check if a path has an overlayfs mount.
pub(super) fn is_overlay_mounted(target: &Path) -> Result<bool> {
    let mounts = std::fs::read_to_string("/proc/mounts")?;
    let canonical_target = target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf());

    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3
            && parts[2] == "overlay"
            && let Ok(mount_point) = PathBuf::from(parts[1]).canonicalize()
            && mount_point == canonical_target
        {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Get mount info for a currently mounted overlay.
pub(super) fn get_mount_info(target: &Path) -> Option<MountInfo> {
    let mounts = std::fs::read_to_string("/proc/mounts").ok()?;
    let canonical_target = target.canonicalize().ok()?;

    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 4 {
            let mount_point = PathBuf::from(parts[1]).canonicalize().ok()?;
            let fs_type = parts[2];

            if mount_point == canonical_target && fs_type == "overlay" {
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
                        mounted_at: chrono::Utc::now(),
                    });
                }
            }
        }
    }

    None
}

/// Mount a tmpfs filesystem.
pub(super) fn mount_tmpfs(target: &Path, size: &str) -> Result<()> {
    let temp_dir = crate::config::EphemeralOverlayDir {
        path: target.to_path_buf(),
        tmpfs_upper_size: size.to_string(),
        tmpfs_work_size: "1M".to_string(),
    };
    temp_dir
        .parse_upper_size()
        .map_err(|e| NailsError::ConfigError(format!("Invalid tmpfs size '{}': {}", size, e)))?;

    std::fs::create_dir_all(target)?;

    let options = format!("size={}", size);

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

/// Unmount a tmpfs filesystem (idempotent).
pub(super) fn unmount_tmpfs(fs: &RealFilesystem, target: &Path) -> Result<()> {
    if !fs.is_mounted(target)? {
        return Ok(());
    }

    nix::mount::umount(target).map_err(|e| NailsError::UnmountError {
        path: target.to_path_buf(),
        reason: format!("{}", e),
    })?;

    Ok(())
}

/// Perform a bind mount.
pub(super) fn bind_mount(source: &Path, target: &Path) -> Result<()> {
    if !source.exists() {
        return Err(NailsError::OverlayError(format!(
            "Bind mount source not found: {}",
            source.display()
        )));
    }

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

/// Unmount a bind mount (idempotent).
pub(super) fn unmount_bind(fs: &RealFilesystem, target: &Path) -> Result<()> {
    if !fs.is_mounted(target)? {
        return Ok(());
    }

    nix::mount::umount(target).map_err(|e| NailsError::UnmountError {
        path: target.to_path_buf(),
        reason: format!("{}", e),
    })?;

    Ok(())
}
