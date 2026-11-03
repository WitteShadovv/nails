// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! From the names a configuration file uses to the devices they mean.

use super::SYS_FS_BTRFS;
use super::walk::{dev_node_dir, names, sorted_listing};
use crate::Filesystem;
use std::path::{Path, PathBuf};

/// The sysfs directory of the block device an fstab or crypttab spec names:
/// `/dev/sdb1`, `/dev/mapper/data`, a `/dev/disk/by-*` name, or `UUID=`,
/// `PARTUUID=`, `LABEL=` and `PARTLABEL=`, which udev links under
/// `/dev/disk`. `None` for a file, a pseudo source such as `tmpfs`, or a
/// device that is not present.
pub fn resolve_spec<F: Filesystem>(fs: &F, spec: &str) -> Option<PathBuf> {
    dev_node_dir(fs, &crate::fstab::spec_device(spec)?)
}

/// Every device of the btrfs filesystem that the device `name` (a kernel
/// name) belongs to, sorted: the entries of `/sys/fs/btrfs/<fsid>/devices/`.
/// Empty when no mounted btrfs filesystem uses `name`.
pub fn btrfs_members<F: Filesystem>(fs: &F, name: &str) -> Vec<String> {
    sorted_listing(fs, Path::new(SYS_FS_BTRFS))
        .iter()
        .map(|filesystem| names(&sorted_listing(fs, &filesystem.join("devices"))))
        .find(|members| members.iter().any(|member| member == name))
        .unwrap_or_default()
}

/// The devices of every btrfs filesystem `/sys/fs/btrfs` lists, by kernel
/// name, each sorted: the entries of each `<fsid>/devices/`. None without
/// btrfs. The error is a listing that is there but could not be read
/// (`/sys/fs/btrfs`, or one filesystem's `devices/`): any filesystem could
/// then have devices this does not name.
pub fn btrfs_filesystems<F: Filesystem>(fs: &F) -> Result<Vec<Vec<String>>, PathBuf> {
    let listing = |dir: &Path| match fs.list_directory(dir) {
        Ok(mut entries) => {
            entries.sort();
            Ok(Some(entries))
        }
        Err(error) if error.io_kind() == Some(std::io::ErrorKind::NotFound) => Ok(None),
        Err(_) => Err(dir.to_path_buf()),
    };
    let Some(filesystems) = listing(Path::new(SYS_FS_BTRFS))? else {
        return Ok(Vec::new());
    };
    let mut members = Vec::new();
    for filesystem in filesystems {
        // `features/` lists no devices.
        if let Some(devices) = listing(&filesystem.join("devices"))? {
            members.push(names(&devices));
        }
    }
    Ok(members)
}
