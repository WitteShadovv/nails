// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The devices under a filesystem, read walk by walk, and where a check goes
//! on below each: the stack the backend checks judge the hidden root by.
//!
//! One walk ([`blockdev::walk()`]) follows `slaves/`, a loop device over a
//! block node, and, as far as the graph's [`LoopFollow`] lets it, a loop
//! device over a file by the file's path. The graph goes further where the
//! walk stops short of where the data lies:
//!
//! - every device of a btrfs or bcachefs filesystem, not only the one the
//!   mount names;
//! - from a partition into its disk, where that disk keeps its data elsewhere
//!   (a loop or device-mapper device, a disk built on others such as an md
//!   array, a disk whose storage sysfs does not show);
//! - with [`LoopFollow::BackingFiles`], from a loop device over a file into
//!   every device of the filesystem the loop driver records for the file. Its
//!   path counts only where the record cannot be read, and a path that leads
//!   to another filesystem than the record ends the way in doubt. With
//!   [`LoopFollow::BlockDevices`] the way ends at a loop device over a file:
//!   the file's filesystem holds the hidden root's data, but none of its own
//!   storage is the hidden root's.

use crate::Filesystem;
use crate::blockdev::{self, Layer, LoopBacking, LoopFollow, MAX_STACK_DEVICES};
use crate::filesystem::mountinfo::MountEntry;
use crate::hidden_root::separation::{
    Claimed, DeviceMap, FileHolder, LoopFile, NodeKind, SYS_CLASS_BLOCK,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The most devices a graph reads in all its walks together.
pub(super) const MAX_DEVICES: usize = 4 * MAX_STACK_DEVICES;

/// The devices read, and where the check goes on from each.
#[derive(Debug, Default)]
pub(super) struct Graph {
    /// How far the walks go below a loop device.
    follow: LoopFollow,
    /// Every device read, by the name of its sysfs directory, as `slaves/`
    /// and the decoy's claims name it.
    pub(super) layers: BTreeMap<String, Layer>,
    /// Where the check goes on from a device past the walk: from a partition
    /// into its disk, from a loop device's file into the devices of its
    /// filesystem.
    below: BTreeMap<String, Vec<String>>,
    /// The devices a way down cannot be followed past, and why.
    pub(super) doubts: BTreeMap<String, String>,
    /// The loop devices whose file the walk could not place on a disk.
    pub(super) unplaced: BTreeSet<String>,
}

impl Graph {
    /// Read the devices below `roots`, the sysfs directories of the devices
    /// of a filesystem, going below a loop device as far as `follow` lets
    /// the walks go. `recorded` holds the loop driver's record of each loop
    /// device's file, as the attach gate read it.
    pub(super) fn read<F: Filesystem>(
        fs: &F,
        mounts: &[MountEntry],
        recorded: &DeviceMap,
        roots: &[PathBuf],
        follow: LoopFollow,
    ) -> Self {
        let mut graph = Self {
            follow,
            ..Self::default()
        };
        let mut pending = roots.to_vec();
        while let Some(dir) = pending.pop() {
            let dir = fs.canonicalize(&dir).unwrap_or(dir);
            if graph.layers.len() >= MAX_DEVICES || graph.layers.contains_key(&dir_name(&dir)) {
                continue;
            }
            let walk = blockdev::walk(fs, &dir, follow, MAX_STACK_DEVICES);
            graph.unplaced.extend(walk.unplaced_loops);
            for layer in walk.layers {
                let name = key(&layer);
                if graph.layers.contains_key(&name) || graph.layers.len() >= MAX_DEVICES {
                    continue;
                }
                pending.extend(graph.beyond(fs, mounts, recorded, &name, &layer));
                graph.layers.insert(name, layer);
            }
        }
        graph
    }

    /// The devices the check goes on into below the device `name`.
    pub(super) fn children<'a>(&'a self, name: &str, layer: &'a Layer) -> &'a [String] {
        self.below.get(name).unwrap_or(&layer.below)
    }

    /// Where the check goes on from `layer` past the walk, as sysfs
    /// directories still to read.
    fn beyond<F: Filesystem>(
        &mut self,
        fs: &F,
        mounts: &[MountEntry],
        recorded: &DeviceMap,
        name: &str,
        layer: &Layer,
    ) -> Vec<PathBuf> {
        if layer.partition.is_some() {
            return self.partition_disk(fs, name, layer);
        }
        match layer.loop_device.as_ref().map(|bound| &bound.backing) {
            Some(LoopBacking::File(file)) if self.follow >= LoopFollow::BackingFiles => {
                self.file_devices(fs, mounts, recorded, name, layer, file)
            }
            _ => Vec::new(),
        }
    }

    /// From the partition `name` into its disk, where the disk keeps its data
    /// elsewhere. A partition of a plain disk ends the way itself.
    fn partition_disk<F: Filesystem>(&mut self, fs: &F, name: &str, layer: &Layer) -> Vec<PathBuf> {
        let Some((dir, disk)) = disk_keeping_data_elsewhere(fs, layer) else {
            return Vec::new();
        };
        self.below.insert(name.to_string(), vec![disk]);
        vec![dir]
    }

    /// From the loop device `name` over `file` into the devices of the
    /// filesystem that holds the file: the one the loop driver records, else,
    /// where only root could read the record, the one the file's path leads
    /// to.
    fn file_devices<F: Filesystem>(
        &mut self,
        fs: &F,
        mounts: &[MountEntry],
        recorded: &DeviceMap,
        name: &str,
        layer: &Layer,
        file: &Path,
    ) -> Vec<PathBuf> {
        let by_path = layer.below.first();
        let holder = match recorded.nodes.get(name).map(|node| &node.kind) {
            Some(NodeKind::Loop {
                file: Some(LoopFile { holder, .. }),
            }) => Some(holder),
            _ => None,
        };
        let mut doubt = |why: &str| {
            self.doubts.insert(
                name.to_string(),
                format!("loop device {} reads {}, {why}", layer.name, file.display()),
            );
            Vec::new()
        };
        let devices = match holder {
            Some(FileHolder::Mount(dev)) => {
                let Some(devices) = mounts
                    .iter()
                    .find(|mount| &mount.dev == dev)
                    .and_then(|mount| filesystem_devices(fs, mount))
                else {
                    return doubt("on a filesystem that shows no block device to follow");
                };
                if by_path
                    .is_some_and(|by_path| !devices.iter().any(|dir| dir_name(dir) == *by_path))
                {
                    return doubt(
                        "which its path now places on another filesystem than the one the loop \
                         driver recorded for it",
                    );
                }
                devices
            }
            Some(FileHolder::Unplaced) => {
                return doubt(
                    "whose filesystem, as the loop driver recorded it, is not mounted here",
                );
            }
            Some(FileHolder::Unreadable(_)) | None => {
                let Some(by_path) = by_path else {
                    return Vec::new();
                };
                let Some(devices) = mounts
                    .iter()
                    .find(|mount| {
                        blockdev::device_of_mount(fs, mount)
                            .is_some_and(|dir| dir_name(&dir) == *by_path)
                    })
                    .and_then(|mount| filesystem_devices(fs, mount))
                else {
                    return Vec::new();
                };
                devices
            }
        };
        self.below.insert(
            name.to_string(),
            devices.iter().map(|dir| dir_name(dir)).collect(),
        );
        devices
    }
}

/// The disk of the partition `layer`, as its sysfs directory and name, when
/// the disk keeps its data elsewhere: a loop or device-mapper device, a disk
/// built on others (an md array), or one whose storage sysfs does not show.
fn disk_keeping_data_elsewhere<F: Filesystem>(fs: &F, layer: &Layer) -> Option<(PathBuf, String)> {
    let dir = layer
        .partition
        .as_ref()
        .and_then(|partition| partition.disk.as_ref())
        .and(layer.sysfs.parent())?;
    let walk = blockdev::walk(fs, dir, LoopFollow::Never, 1);
    let disk = walk.layers.first()?;
    let elsewhere = disk.dm.is_some()
        || disk.loop_device.is_some()
        || !disk.slaves.is_empty()
        || leaf_kind(&key(disk)).is_some();
    elsewhere.then(|| (dir.to_path_buf(), key(disk)))
}

/// `claimed`, the devices the decoy claims, with what the rule for
/// partitions adds: a claimed partition whose disk keeps its data elsewhere
/// claims that disk and every device below it too, as the same piece of the
/// decoy's storage. The decoy's root on a partition of an md array makes the
/// array's devices the decoy's, as its boot opens them.
pub(super) fn widen_claims<F: Filesystem>(
    fs: &F,
    mounts: &[MountEntry],
    recorded: &DeviceMap,
    claimed: BTreeMap<String, Claimed>,
) -> BTreeMap<String, Claimed> {
    let mut widened = claimed.clone();
    for (name, holds) in &claimed {
        let dir = Path::new(SYS_CLASS_BLOCK).join(name);
        let walk = blockdev::walk(fs, &dir, LoopFollow::Never, 1);
        let Some((disk, _)) = walk
            .layers
            .first()
            .and_then(|layer| disk_keeping_data_elsewhere(fs, layer))
        else {
            continue;
        };
        for below in Graph::read(fs, mounts, recorded, &[disk], LoopFollow::BackingFiles)
            .layers
            .into_keys()
        {
            widened.entry(below).or_insert_with(|| holds.clone());
        }
    }
    widened
}

/// The block devices the filesystem mounted as `mount` keeps its data on, as
/// sysfs directories: each device of a btrfs or bcachefs filesystem, the one
/// device of any other. `None` when a device of it cannot be found or none
/// shows at all, as for an overlay, FUSE, a network filesystem or a tmpfs.
pub(super) fn filesystem_devices<F: Filesystem>(
    fs: &F,
    mount: &MountEntry,
) -> Option<Vec<PathBuf>> {
    let source = mount.source.to_string_lossy();
    if mount.fstype == "bcachefs" && source.contains(':') {
        // bcachefs names every device of a filesystem of several in its
        // source, `/dev/sdb:/dev/sdc`; its device number is the first one's.
        return source
            .split(':')
            .map(|device| blockdev::resolve_spec(fs, device))
            .collect();
    }
    let device = blockdev::device_of_mount(fs, mount)?;
    let members = blockdev::btrfs_members(fs, &dir_name(&device));
    if members.len() < 2 {
        return Some(vec![device]);
    }
    members
        .iter()
        .map(|member| blockdev::resolve_spec(fs, &format!("/dev/{member}")))
        .collect()
}

/// What a block device that keeps its data where sysfs does not show is, by
/// its kernel name: a ZFS volume, a network block device, a userspace block
/// device or a compressed RAM disk.
pub(super) fn leaf_kind(name: &str) -> Option<&'static str> {
    const KINDS: &[(&str, &str)] = &[
        ("zd", "a ZFS volume"),
        ("nbd", "a network block device"),
        ("ublkb", "a userspace block device"),
        ("zram", "a compressed RAM disk"),
    ];
    KINDS.iter().find_map(|(prefix, kind)| {
        let number = name.strip_prefix(prefix)?;
        (!number.is_empty() && number.bytes().all(|b| b.is_ascii_digit())).then_some(*kind)
    })
}

/// A device by the name of its sysfs directory.
fn key(layer: &Layer) -> String {
    layer.sysfs.file_name().map_or_else(
        || layer.name.clone(),
        |name| name.to_string_lossy().into_owned(),
    )
}

/// The last component of a sysfs directory.
fn dir_name(dir: &Path) -> String {
    dir.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}
