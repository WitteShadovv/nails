// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! From the names a configuration file uses to the devices they mean.

use super::walk::{dev_node_dir_noting, names};
use super::{Attribute, SYS_FS_BTRFS};
use crate::Filesystem;
use std::cell::RefCell;
use std::path::{Path, PathBuf};

/// The sysfs directory of the block device an fstab or crypttab spec names:
/// `/dev/sdb1`, `/dev/mapper/data`, a `/dev/disk/by-*` name, or `UUID=`,
/// `PARTUUID=`, `LABEL=` and `PARTLABEL=`, which udev links under
/// `/dev/disk`. `None` for a file, a pseudo source such as `tmpfs`, or a
/// device that is not present, and also for one NAILS cannot resolve
/// ([`resolve_spec_or_unread`] tells that apart).
pub fn resolve_spec<F: Filesystem>(fs: &F, spec: &str) -> Option<PathBuf> {
    resolve_spec_or_unread(fs, spec).ok().flatten()
}

/// [`resolve_spec`], telling a spec that names no device here from one
/// NAILS cannot resolve: `Err` names the device node, or the `dev` attribute
/// of the device it leads to, that is there but could not be resolved or
/// read, for another reason than that it is not there.
pub fn resolve_spec_or_unread<F: Filesystem>(
    fs: &F,
    spec: &str,
) -> Result<Option<PathBuf>, PathBuf> {
    let Some(device) = crate::fstab::spec_device(spec) else {
        return Ok(None);
    };
    let unread = RefCell::new(Vec::new());
    match dev_node_dir_noting(fs, &device, Attribute::Dev, &unread) {
        Some(dir) => Ok(Some(dir)),
        None => unread
            .into_inner()
            .into_iter()
            .next()
            .map_or(Ok(None), |unread| Err(unread.path)),
    }
}

/// Every device of the btrfs filesystem that the device `name` (a kernel
/// name) belongs to, sorted: the entries of `/sys/fs/btrfs/<fsid>/devices/`.
/// Empty when no mounted btrfs filesystem uses `name`. The error is a
/// listing that is there but could not be read, as for
/// [`btrfs_filesystems`]: the filesystem of `name` could then have devices
/// this does not name.
pub fn btrfs_members<F: Filesystem>(fs: &F, name: &str) -> Result<Vec<String>, PathBuf> {
    Ok(btrfs_filesystems(fs)?
        .into_iter()
        .find(|members| members.iter().any(|member| member == name))
        .unwrap_or_default())
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
