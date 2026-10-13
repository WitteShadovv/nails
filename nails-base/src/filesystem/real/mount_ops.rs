// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Mount-query operations for RealFilesystem.
//!
//! Every query reads the live mount table once and answers for the mount a
//! lookup of the path reaches ([`top_mount_at`]): of several mounts stacked on
//! one point the last, and none where a later mount on a parent directory
//! covers the path, though the covered mount stays in the table.

use crate::Result;
use crate::filesystem::MountSource;
use crate::filesystem::mountinfo::{MountEntry, mount_is_read_only, read_mountinfo, top_mount_at};
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

/// The mount table of this process's mount namespace.
pub(super) fn mount_table() -> Result<Vec<MountEntry>> {
    read_mountinfo()
}

/// The mount visible at `target` in `entries`, or `None`.
fn visible_mount<'a>(entries: &'a [MountEntry], target: &Path) -> Option<&'a MountEntry> {
    top_mount_at(entries, &canonical_target(target))
}

/// Whether a mount is visible at `target`.
pub(super) fn is_mounted(target: &Path) -> Result<bool> {
    Ok(visible_mount(&read_mountinfo()?, target).is_some())
}

/// The filesystem type of the mount visible at `target`.
pub(super) fn get_filesystem_type(target: &Path) -> Result<Option<String>> {
    Ok(visible_mount(&read_mountinfo()?, target).map(|entry| entry.fstype.clone()))
}

/// Whether the mount visible at `target` is mounted read-only.
///
/// Reads both the per-mount VFS options (field 6) and the per-superblock
/// options (after the ` - `), see [`mount_is_read_only`]. Not a mount point
/// reads as writable (`false`).
pub(super) fn is_mount_read_only(target: &Path) -> Result<bool> {
    Ok(visible_mount(&read_mountinfo()?, target).is_some_and(mount_is_read_only))
}

/// Identify the device, device-mapper name and filesystem label behind the
/// mount visible at `mount_point`.
///
/// Returns `None` when `mount_point` is not itself a mount point. The dm name
/// comes from the source (`/dev/mapper/<name>` directly, `/dev/dm-N` via
/// `/sys/block/dm-N/dm/name`) and the label from the `/dev/disk/by-label`
/// symlink that resolves to the same device. Every attribute is best-effort:
/// an absent dm layer or label is left `None`, never an error.
pub(super) fn mount_source(mount_point: &Path) -> Result<Option<MountSource>> {
    let entries = read_mountinfo()?;
    let Some(entry) = visible_mount(&entries, mount_point) else {
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
    use super::{dm_name_for, visible_mount};
    use crate::filesystem::mountinfo::{mount_is_read_only, parse_mountinfo};
    use std::path::Path;

    #[test]
    fn super_opts_read_only_detects_an_emergency_remount() {
        let read_only = |super_opts: &str| {
            let line = format!("36 1 8:1 / /x rw,relatime - ext4 /dev/sda1 {super_opts}");
            mount_is_read_only(&parse_mountinfo(&line)[0])
        };
        // A kernel emergency remount-ro flips the superblock options to `ro`.
        assert!(read_only("ro,errors=remount-ro,data=ordered"));
        assert!(read_only("ro"));
        // A healthy, writable filesystem is not read-only; `relatime` is not `ro`.
        assert!(!read_only("rw,errors=remount-ro"));
        assert!(!read_only("rw,relatime"));
        assert!(!read_only(""));
    }

    /// `/mnt` (1) with `/mnt/data` (2) on it and a second filesystem (3) stacked
    /// on `/mnt/data`, then a mount (4) over `/mnt` that covers both.
    const STACKED: &str = "\
1 0 8:1 / / rw - ext4 /dev/sda1 rw
2 1 8:2 / /mnt rw - ext4 /dev/sda2 rw
3 2 253:0 / /mnt/data rw - ext4 /dev/mapper/first rw
5 3 253:1 / /mnt/data ro - xfs /dev/mapper/second ro
4 2 0:40 / /mnt rw - tmpfs cover rw
";

    #[test]
    fn the_visible_mount_is_the_top_of_a_stack_and_none_under_a_cover() {
        // A scratch root, so the queried paths do not resolve on the host.
        let root = tempfile::tempdir().unwrap();
        let root = root.path().canonicalize().unwrap();
        let table = STACKED.replace(" /mnt", &format!(" {}/mnt", root.display()));
        let entries = parse_mountinfo(&table);
        let without_cover: Vec<_> = entries
            .iter()
            .filter(|e| e.mount_id != 4)
            .cloned()
            .collect();
        let (mnt, data) = (root.join("mnt"), root.join("mnt/data"));

        // Stacked on one point: the last mount answers, for every query.
        let top = visible_mount(&without_cover, &data).unwrap();
        assert_eq!(top.mount_id, 5);
        assert_eq!(top.fstype, "xfs");
        assert_eq!(top.source, Path::new("/dev/mapper/second"));
        assert!(mount_is_read_only(top));

        // A mount on the parent covers both, though they stay in the table.
        assert!(visible_mount(&entries, &data).is_none());
        assert_eq!(visible_mount(&entries, &mnt).map(|e| e.mount_id), Some(4));
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
