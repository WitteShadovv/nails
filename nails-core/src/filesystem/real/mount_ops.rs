// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Mount, unmount, and mount-query operations for RealFilesystem.

use super::RealFilesystem;
use crate::filesystem::mountinfo::{
    NailsMounts, escape_overlay_path, parse_overlay_opts, read_mountinfo,
};
use crate::filesystem::{Filesystem, MountInfo, MountSource, verify_mount_preconditions};
use crate::{NailsError, Result};
use std::path::{Path, PathBuf};

/// Where udev records a symlink per filesystem label, named by the label.
const DEV_BY_LABEL: &str = "/dev/disk/by-label";
/// Whole block devices by kernel name; device-mapper devices live here.
const SYS_BLOCK: &str = "/sys/block";

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

/// Build the overlay mount option string.
///
/// `index=off,metacopy=off,redirect_dir=off` is always appended. NAILS depends on
/// plain, predictable copy-up semantics: `metacopy` and `redirect_dir` change
/// where file data and rename state live across the layers (and can leave traces
/// or complicate teardown), and `index` affects hardlink/nlink bookkeeping, so
/// all three are disabled explicitly rather than left to the kernel default,
/// which varies by kernel build and mount-time auto-detection. The segments are
/// already escaped by [`escape_overlay_path`].
fn overlay_mount_options(lowerdir: &str, upper: &str, work: &str) -> String {
    format!(
        "lowerdir={lowerdir},upperdir={upper},workdir={work},index=off,metacopy=off,redirect_dir=off"
    )
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

    let options = overlay_mount_options(
        &lowerdir,
        &escape_overlay_path(upper)?,
        &escape_overlay_path(work)?,
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

/// Check if a path has an overlayfs mount *visible at that path*.
///
/// Only the mount actually reachable at `target` counts. When a later mount on a
/// parent path shadows an overlay still listed at this path — NAILS overlays
/// `/nix`, which hides the `/nix/store` overlay underneath it — `mountinfo` keeps
/// the shadowed entry, but the path now resolves onto the covering mount's
/// device. Matching the entry's device against the device the kernel reports at
/// the path drops the shadowed entry, so a fresh nested overlay is not wrongly
/// refused as a double-mount. A genuine, visible overlay still matches (its
/// device is what `stat` returns), so real double-mount detection is unchanged.
/// When the path cannot be stat'd, fall back to the path+fstype match (fail-safe:
/// treat a present entry as mounted).
pub(super) fn is_overlay_mounted(target: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let canonical = canonical_target(target);
    let visible_dev = std::fs::metadata(&canonical).ok().map(|meta| meta.dev());
    Ok(read_mountinfo()?.iter().any(|e| {
        e.mount_point == canonical
            && e.fstype == "overlay"
            && visible_dev.is_none_or(|dev| mountinfo_dev_matches(&e.dev, dev))
    }))
}

/// Whether a mountinfo `major:minor` device string denotes the same device as a
/// `stat` `st_dev`. A malformed device string never matches.
fn mountinfo_dev_matches(dev_text: &str, st_dev: u64) -> bool {
    let mut parts = dev_text.split(':');
    let (Some(major), Some(minor), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let (Ok(major), Ok(minor)) = (major.parse::<u64>(), minor.parse::<u64>()) else {
        return false;
    };
    nix::sys::stat::makedev(major, minor) == st_dev
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
            if let (false, Some(upper), Some(work)) =
                (opts.lowerdir.is_empty(), opts.upperdir, opts.workdir)
            {
                return Some(MountInfo {
                    lowers: opts.lowerdir,
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

/// Identify the device, device-mapper name and filesystem label behind the
/// mount at `mount_point`.
///
/// Returns `None` when `mount_point` is not itself a mount point. The dm name
/// comes from the source (`/dev/mapper/<name>` directly, `/dev/dm-N` via
/// `/sys/block/dm-N/dm/name`) and the label from the `/dev/disk/by-label`
/// symlink that resolves to the same device. Every attribute is best-effort:
/// an absent dm layer or label is left `None`, never an error.
pub(super) fn mount_source(mount_point: &Path) -> Result<Option<MountSource>> {
    let canonical = canonical_target(mount_point);
    let Some(entry) = read_mountinfo()?
        .into_iter()
        .find(|e| e.mount_point == canonical)
    else {
        return Ok(None);
    };

    let device = entry.source.to_string_lossy().into_owned();
    let dm_name = dm_name_for(&entry.source);
    let label = label_for(&entry.source);

    Ok(Some(MountSource {
        device: Some(device),
        dm_name,
        label,
    }))
}

/// The device-mapper name behind a mount source, if it is a dm device.
///
/// `/dev/mapper/<name>` already carries the name; `/dev/dm-N` is resolved
/// through `/sys/block/dm-N/dm/name`. Anything else is not a dm device.
fn dm_name_for(source: &Path) -> Option<String> {
    let name = source.file_name()?.to_str()?;
    if source.starts_with("/dev/mapper") {
        return Some(name.to_string());
    }
    if name.starts_with("dm-") && name[3..].chars().all(|c| c.is_ascii_digit()) {
        let dm_name =
            std::fs::read_to_string(Path::new(SYS_BLOCK).join(name).join("dm/name")).ok()?;
        let dm_name = dm_name.trim();
        if !dm_name.is_empty() {
            return Some(dm_name.to_string());
        }
    }
    None
}

/// The filesystem label of a mount source, if `/dev/disk/by-label` holds a
/// symlink that resolves to the same device.
///
/// The source is resolved to its canonical device node first, because a label
/// symlink and a `/dev/mapper` source both point at the underlying `/dev/dm-N`.
fn label_for(source: &Path) -> Option<String> {
    let device = source.canonicalize().ok()?;
    for entry in std::fs::read_dir(DEV_BY_LABEL).ok()?.flatten() {
        if entry.path().canonicalize().ok().as_deref() == Some(device.as_path()) {
            return entry.file_name().to_str().map(str::to_string);
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

/// Re-attach a staged submount over its parent overlay.
///
/// `source` is the staging capture (a recursive bind of the submount's live
/// content, taken before the parent overlay shadowed it). It is recursively bound
/// onto `mount_point` — now sitting over the overlay — so the path resolves again,
/// and remounted read-only when asked so a snap squashfs or an ESP cannot be
/// written through the re-attach. The recursive flag carries across any mounts the
/// submount nested inside itself.
pub(super) fn reattach_submount(source: &Path, mount_point: &Path, read_only: bool) -> Result<()> {
    let map_err = |e: nix::errno::Errno, stage: &str| -> NailsError {
        if e == nix::errno::Errno::EACCES || e == nix::errno::Errno::EPERM {
            NailsError::PermissionDenied("Submount re-attach requires root privileges".to_string())
        } else if e == nix::errno::Errno::EBUSY {
            NailsError::MountBusy {
                path: mount_point.to_path_buf(),
                suggestion: "Submount re-attach target has active references".to_string(),
            }
        } else {
            NailsError::OverlayError(format!(
                "Failed to {stage} submount {} -> {}: {e}",
                source.display(),
                mount_point.display(),
            ))
        }
    };

    nix::mount::mount(
        Some(source),
        mount_point,
        None::<&str>,
        nix::mount::MsFlags::MS_BIND | nix::mount::MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| map_err(e, "bind"))?;

    if read_only {
        nix::mount::mount(
            Some(mount_point),
            mount_point,
            None::<&str>,
            nix::mount::MsFlags::MS_BIND
                | nix::mount::MsFlags::MS_REMOUNT
                | nix::mount::MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .map_err(|e| {
            // The bind landed but the read-only remount did not; drop the bind so
            // the submount is not left writable through the re-attach.
            let _ = nix::mount::umount(mount_point);
            map_err(e, "remount read-only")
        })?;
    }

    Ok(())
}

/// Bind-remount a path on itself read-only.
///
/// A plain `MS_REMOUNT|MS_RDONLY` on a mount the kernel considers writable can be
/// refused, so the tree is first self-bound (`MS_BIND`) and the fresh bind is
/// then remounted read-only. The stacked bind is what [`unmount_bind`] later
/// removes to restore write access.
pub(super) fn remount_read_only(target: &Path) -> Result<()> {
    let map_err = |e: nix::errno::Errno, stage: &str| -> NailsError {
        if e == nix::errno::Errno::EACCES || e == nix::errno::Errno::EPERM {
            NailsError::PermissionDenied("Read-only remount requires root privileges".to_string())
        } else if e == nix::errno::Errno::EBUSY {
            NailsError::MountBusy {
                path: target.to_path_buf(),
                suggestion: "Tree has active references and cannot be remounted read-only"
                    .to_string(),
            }
        } else {
            NailsError::OverlayError(format!(
                "Failed to {stage} {} read-only: {e}",
                target.display()
            ))
        }
    };

    nix::mount::mount(
        Some(target),
        target,
        None::<&str>,
        nix::mount::MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|e| map_err(e, "self-bind"))?;

    nix::mount::mount(
        Some(target),
        target,
        None::<&str>,
        nix::mount::MsFlags::MS_BIND
            | nix::mount::MsFlags::MS_REMOUNT
            | nix::mount::MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .map_err(|e| {
        // The self-bind landed but the read-only remount did not; drop the bind so
        // the guard does not leave a redundant writable bind stacked on the tree.
        let _ = nix::mount::umount(target);
        map_err(e, "remount")
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

#[cfg(test)]
mod tests {
    use super::{dm_name_for, mountinfo_dev_matches, overlay_mount_options};
    use std::path::Path;

    #[test]
    fn overlay_options_disable_index_metacopy_and_redirect_dir() {
        let opts = overlay_mount_options("/l", "/u", "/w");
        assert!(opts.contains("index=off"));
        assert!(opts.contains("metacopy=off"));
        assert!(opts.contains("redirect_dir=off"));
    }

    #[test]
    fn overlay_options_keep_lower_upper_and_work_dirs() {
        let opts = overlay_mount_options("/a:/b", "/up", "/work");
        assert_eq!(
            opts,
            "lowerdir=/a:/b,upperdir=/up,workdir=/work,index=off,metacopy=off,redirect_dir=off"
        );
    }

    #[test]
    fn dm_name_reads_straight_off_a_mapper_source() {
        // `/dev/mapper/<name>` carries the name directly — no sysfs read.
        assert_eq!(
            dm_name_for(Path::new("/dev/mapper/veracrypt-hidden")),
            Some("veracrypt-hidden".to_string())
        );
    }

    #[test]
    fn dm_name_is_none_for_a_plain_partition() {
        // A real block device is not a device-mapper device.
        assert_eq!(dm_name_for(Path::new("/dev/sdb1")), None);
    }

    #[test]
    fn mountinfo_dev_matches_the_same_device() {
        let dev = nix::sys::stat::makedev(0, 85);
        assert!(mountinfo_dev_matches("0:85", dev));
        // A shadowed overlay sitting at the same path but on a different device
        // (the covering parent mount) must not match the visible device.
        assert!(!mountinfo_dev_matches("0:41", dev));
        assert!(!mountinfo_dev_matches("253:0", dev));
    }

    #[test]
    fn mountinfo_dev_matches_rejects_malformed_device_strings() {
        let dev = nix::sys::stat::makedev(0, 85);
        assert!(!mountinfo_dev_matches("", dev));
        assert!(!mountinfo_dev_matches("0", dev));
        assert!(!mountinfo_dev_matches("0:85:1", dev));
        assert!(!mountinfo_dev_matches("x:y", dev));
    }
}
