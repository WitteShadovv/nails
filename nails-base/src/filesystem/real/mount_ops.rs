// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Mount-query operations for RealFilesystem.

use crate::Result;
use crate::filesystem::MountSource;
use crate::filesystem::mountinfo::read_mountinfo;
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

/// Whether the mount visible at `target` is mounted read-only.
///
/// Checks the topmost (last listed) mount at the path, reading both the per-mount
/// VFS options (field 6) and the per-superblock options (after the ` - `). An
/// ext4 (or similar) filesystem the kernel remounts read-only after an I/O error
/// flips the *superblock* to `ro` while the per-mount flag can stay `rw`, so both
/// must be consulted or a failed-in-place backend reads as writable. Not a mount
/// point reads as writable (`false`).
pub(super) fn is_mount_read_only(target: &Path) -> Result<bool> {
    let canonical = canonical_target(target);
    Ok(read_mountinfo()?
        .iter()
        .rev()
        .find(|e| e.mount_point == canonical)
        .map(|e| e.read_only() || super_opts_read_only(&e.super_opts))
        .unwrap_or(false))
}

/// Whether a mount's per-superblock option string marks the filesystem read-only
/// (a bare `ro` token), as a kernel emergency remount-ro does.
fn super_opts_read_only(super_opts: &str) -> bool {
    super_opts.split(',').any(|opt| opt == "ro")
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

#[cfg(test)]
mod tests {
    use super::{dm_name_for, super_opts_read_only};
    use std::path::Path;

    #[test]
    fn super_opts_read_only_detects_an_emergency_remount() {
        // A kernel emergency remount-ro flips the superblock options to `ro`.
        assert!(super_opts_read_only("ro,errors=remount-ro,data=ordered"));
        assert!(super_opts_read_only("ro"));
        // A healthy, writable filesystem is not read-only; `relatime` is not `ro`.
        assert!(!super_opts_read_only("rw,errors=remount-ro"));
        assert!(!super_opts_read_only("rw,relatime"));
        assert!(!super_opts_read_only(""));
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
}
