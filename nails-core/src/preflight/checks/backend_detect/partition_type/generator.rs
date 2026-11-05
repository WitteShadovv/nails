// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Which disk systemd-gpt-auto-generator reads the partition table of at
//! boot, found the way systemd 254 to 262 find it (`blockdev_get_root` and
//! `get_block_device_harder` in systemd's `blockdev-util.c`).
//!
//! systemd takes the block device of the root file system: the one its
//! mount reports, or the only device of a btrfs filesystem, but none for a
//! btrfs filesystem of several devices, and then that of `/usr`. From there
//! it follows `slaves/`, one layer down before systemd 259.1, as from a LUKS
//! volume to its partition, and every layer down from 259.1 on, as through
//! LVM on LUKS. Where the devices one layer down are not all on one whole
//! disk (a device-mapper or md device is a whole disk of its own), it keeps
//! the root file system's own device. It reads the partition table of the
//! whole disk it ends on: a partition's disk, or the device itself, which
//! for a device-mapper, md or loop device that holds a filesystem is no
//! table at all.

use super::judge::Discovery;
use crate::Filesystem;
use crate::blockdev::{self, Layer, LoopFollow, MAX_STACK_DEVICES};
use crate::filesystem::mountinfo::{MountEntry, top_mount_at};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The disk the generator reads the table of, as older and newer systemd
/// find it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct GeneratorDisk {
    /// Where systemd 254 to 259.0 end, one layer down.
    older: End,
    /// Where systemd 259.1 and later end, every layer down.
    newer: End,
}

/// Where a way down `slaves/` ends.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
enum End {
    /// At no disk with a partition table: the root file system and `/usr`
    /// show no single block device, or the way ends at a device that is no
    /// partition, such as a device-mapper, md or loop device that holds the
    /// filesystem or a further layer.
    #[default]
    Nowhere,
    /// At this disk, by kernel name.
    Disk(String),
    /// Where sysfs does not show: a `slaves/` that cannot be listed.
    Unknown,
}

impl GeneratorDisk {
    /// The disk as the mount table `mounts` and sysfs show it.
    pub(super) fn read<F: Filesystem>(fs: &F, mounts: &[MountEntry]) -> Self {
        let Some(top) = device(fs, mounts, "/").or_else(|| device(fs, mounts, "/usr")) else {
            return Self::default();
        };
        Self {
            older: way_down(fs, &top, 1),
            newer: way_down(fs, &top, MAX_STACK_DEVICES),
        }
    }

    /// The disks the generator reads in one systemd or another, by kernel
    /// name.
    pub(super) fn disks(&self) -> impl Iterator<Item = &str> {
        [&self.older, &self.newer]
            .into_iter()
            .filter_map(|end| match end {
                End::Disk(disk) => Some(disk.as_str()),
                End::Nowhere | End::Unknown => None,
            })
    }

    /// Whether the generator reads the table of `disk`.
    pub(super) fn discovery(&self, disk: &str) -> Discovery {
        let at = |end: &End| matches!(end, End::Disk(name) if name == disk);
        if at(&self.older) {
            Discovery::Every
        } else if at(&self.newer) {
            Discovery::Recent
        } else if self.older == End::Unknown || self.newer == End::Unknown {
            Discovery::Unknown
        } else {
            Discovery::Elsewhere
        }
    }
}

/// The block device systemd takes the filesystem mounted at `point` to be
/// on, as its sysfs directory: the one the mount reports, `None` for a
/// btrfs filesystem of several devices and for a mount with no block
/// device.
fn device<F: Filesystem>(fs: &F, mounts: &[MountEntry], point: &str) -> Option<PathBuf> {
    let mount = top_mount_at(mounts, Path::new(point))?;
    let dir = blockdev::device_of_mount(fs, mount)?;
    let name = dir.file_name()?.to_string_lossy().into_owned();
    (mount.fstype != "btrfs" || blockdev::btrfs_members(fs, &name).len() < 2).then_some(dir)
}

/// Where the generator ends from the device in the sysfs directory `top`,
/// going at most `layers` layers down `slaves/`.
fn way_down<F: Filesystem>(fs: &F, top: &Path, layers: usize) -> End {
    // A walk reads the device it starts at, even one sysfs does not show.
    let read = |dir: &Path| {
        blockdev::walk(fs, dir, LoopFollow::Never, 1)
            .layers
            .into_iter()
            .next()
            .unwrap_or_default()
    };
    let start = read(top);
    let mut current = start.clone();
    for _ in 0..layers {
        if current.slaves_unread {
            return End::Unknown;
        }
        let below: Vec<Layer> = current
            .slaves
            .iter()
            .map(|slave| read(&current.sysfs.join("slaves").join(slave)))
            .collect();
        if below.iter().map(whole_disk).collect::<BTreeSet<_>>().len() > 1 {
            // systemd gives the way up and keeps the root file system's own
            // device (ENOTUNIQ from block_device_get_originating).
            return end(&start);
        }
        // All on one disk: the first leads there as well as any other.
        let Some(next) = below.into_iter().next() else {
            break;
        };
        current = next;
    }
    end(&current)
}

/// The whole disk of `layer`, as systemd's `block_device_get_whole_disk`
/// takes it: a partition's disk, else the device itself.
fn whole_disk(layer: &Layer) -> String {
    layer
        .partition
        .as_ref()
        .and_then(|partition| partition.disk.clone())
        .unwrap_or_else(|| layer.name.clone())
}

/// Where a way down that stops at `layer` ends: at the disk of a partition.
/// Any other device it stops at holds a filesystem or a further layer of
/// the root's storage, and no partition table.
fn end(layer: &Layer) -> End {
    layer
        .partition
        .as_ref()
        .and_then(|partition| partition.disk.clone())
        .map_or(End::Nowhere, End::Disk)
}
