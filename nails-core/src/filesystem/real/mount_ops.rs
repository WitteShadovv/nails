//! Mount, unmount, and mount-query operations for RealFilesystem.

use super::RealFilesystem;
use crate::filesystem::mountinfo::{
    NailsMounts, escape_overlay_path, parse_overlay_opts, read_mountinfo,
};
use crate::filesystem::{Filesystem, MountInfo, verify_mount_preconditions};
use crate::{NailsError, Result};
use std::path::{Path, PathBuf};

/// Canonicalize the single queried target, falling back to the literal path.
///
/// Only the target is canonicalized — never a mount-table entry — so a dead
/// NFS/CIFS/FUSE mount elsewhere cannot block the lookup. Mountinfo already
/// records canonical kernel paths, so comparing a canonical target against the
/// raw entries is correct.
fn canonical_target(target: &Path) -> PathBuf {
    target
        .canonicalize()
        .unwrap_or_else(|_| target.to_path_buf())
}

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

    // Escape `,`/`:`/`\` in every path segment and reject newlines so a path
    // with those characters cannot break or inject overlay options.
    let lowerdir = lower
        .iter()
        .map(|p| escape_overlay_path(p))
        .collect::<Result<Vec<_>>>()?
        .join(":");

    let options = format!(
        "lowerdir={},upperdir={},workdir={}",
        lowerdir,
        escape_overlay_path(upper)?,
        escape_overlay_path(work)?
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
            // Preserve the raw errno so the overlay strategy can decide whether
            // to fall back to a pivot mount without parsing the error text.
            NailsError::Mount {
                target: target.to_path_buf(),
                errno: e,
            }
        }
    })?;

    Ok(())
}

/// Unmount a filesystem (idempotent).
///
/// Before touching `umount2`, the mount at `target` is confirmed to be one NAILS
/// created (an overlay, a pivot/staging bind, or the `/nix/store` restore bind).
/// If it is not — for example a real ext4 `/home` that stale state wrongly points
/// at — the call is refused so the `MNT_FORCE | MNT_DETACH` escalation can never
/// lazily detach a host filesystem.
pub(super) fn unmount(fs: &RealFilesystem, target: &Path, force: bool) -> Result<()> {
    if !fs.is_mounted(target)? {
        return Ok(());
    }

    let canonical = canonical_target(target);
    if !NailsMounts::discover(None)?.is_owned(&canonical) {
        return Err(NailsError::RefusedUnmanagedUnmount {
            path: target.to_path_buf(),
        });
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

/// Check if a path is currently mounted.
pub(super) fn is_mounted(target: &Path) -> Result<bool> {
    let canonical = canonical_target(target);
    Ok(read_mountinfo()?.iter().any(|e| e.mount_point == canonical))
}

/// Get filesystem type at a mount point.
pub(super) fn get_filesystem_type(target: &Path) -> Result<Option<String>> {
    let canonical = canonical_target(target);
    Ok(read_mountinfo()?
        .into_iter()
        .find(|e| e.mount_point == canonical)
        .map(|e| e.fstype))
}

/// Check if a path has an overlayfs mount.
pub(super) fn is_overlay_mounted(target: &Path) -> Result<bool> {
    let canonical = canonical_target(target);
    Ok(read_mountinfo()?
        .iter()
        .any(|e| e.mount_point == canonical && e.fstype == "overlay"))
}

/// Get mount info for a currently mounted overlay.
///
/// Returns `None` when the target is not a mounted overlay. A malformed or dead
/// mount-table line no longer aborts the lookup — the parser skips it — so an
/// overlay recorded after such a line is still found.
pub(super) fn get_mount_info(target: &Path) -> Option<MountInfo> {
    let canonical = canonical_target(target);
    for entry in read_mountinfo().ok()? {
        if entry.mount_point == canonical && entry.fstype == "overlay" {
            let opts = parse_overlay_opts(&entry.super_opts);
            if let (Some(lower), Some(upper), Some(work)) = (
                opts.lowerdir.into_iter().next(),
                opts.upperdir,
                opts.workdir,
            ) {
                return Some(MountInfo {
                    lower,
                    upper,
                    work,
                    target: canonical,
                    mounted_at: chrono::Utc::now(),
                });
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
