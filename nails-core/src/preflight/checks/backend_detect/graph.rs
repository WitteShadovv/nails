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
use crate::blockdev::{self, Attribute, Layer, LoopBacking, LoopFollow, MAX_STACK_DEVICES};
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

    /// The names of the attributes and listings among `among` that sysfs
    /// shows of a device of the graph but NAILS could not read, sorted and
    /// each once: what they would say is missing from the graph.
    pub(super) fn unread(&self, among: &[Attribute]) -> Vec<&'static str> {
        unread_names(self.layers.values(), among)
    }

    /// Whether the graph read every device a layer of it goes on into, and
    /// could list the devices below each one.
    pub(super) fn complete(&self) -> bool {
        self.layers.iter().all(|(name, layer)| {
            !layer.slaves_unread
                && self
                    .children(name, layer)
                    .iter()
                    .all(|child| self.layers.contains_key(child))
        })
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
                let found = mounts
                    .iter()
                    .find(|mount| &mount.dev == dev)
                    .map(|mount| filesystem_devices(fs, mount));
                let devices = match found {
                    Some(Ok(Some(devices))) => devices,
                    Some(Err(_)) => {
                        return doubt(
                            "on a filesystem whose devices sysfs shows but NAILS cannot read",
                        );
                    }
                    Some(Ok(None)) | None => {
                        return doubt("on a filesystem that shows no block device to follow");
                    }
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
                let found = mounts
                    .iter()
                    .find(|mount| {
                        blockdev::device_of_mount(fs, mount)
                            .is_some_and(|dir| dir_name(&dir) == *by_path)
                    })
                    .map(|mount| filesystem_devices(fs, mount));
                match found {
                    Some(Ok(Some(devices))) => devices,
                    Some(Err(_)) => {
                        return doubt(
                            "on a filesystem whose devices sysfs shows but NAILS cannot read",
                        );
                    }
                    Some(Ok(None)) | None => return Vec::new(),
                }
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
    // A disk whose kind sysfs shows but NAILS cannot read may keep its data
    // elsewhere: the way goes on into it, where what is unread shows.
    let elsewhere = disk.dm.is_some()
        || disk.loop_device.is_some()
        || !disk.slaves.is_empty()
        || leaf_kind(&key(disk)).is_some()
        || disk.unread_among(KIND).next().is_some();
    elsewhere.then(|| (dir.to_path_buf(), key(disk)))
}

/// The attributes and listings that say what kind of device a disk is: a
/// device-mapper or loop device, or one built on others.
const KIND: &[Attribute] = &[
    Attribute::DmName,
    Attribute::DmUuid,
    Attribute::LoopBackingFile,
    Attribute::Slaves,
];

/// The names of the attributes and listings among `among` that sysfs shows
/// of one of `layers` but NAILS could not read, sorted and each once.
pub(super) fn unread_names<'a>(
    layers: impl IntoIterator<Item = &'a Layer>,
    among: &[Attribute],
) -> Vec<&'static str> {
    let names: BTreeSet<&'static str> = layers
        .into_iter()
        .flat_map(|layer| layer.unread_among(among))
        .map(|unread| unread.attribute.name())
        .collect();
    names.into_iter().collect()
}

/// Why a check cannot tell, where sysfs shows `names` of a device `place`
/// (`below it`), but NAILS cannot read them; the device is not named.
pub(super) fn unread_reason(names: &[&str], place: &str) -> String {
    let listed = match names {
        [] => String::new(),
        [one] => (*one).to_string(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    };
    let them = if names.len() == 1 { "it" } else { "them" };
    format!("sysfs shows {listed} of a device {place}, but NAILS cannot read {them}")
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
/// device of any other. `None` when a device of it is not there or none
/// shows at all, as for an overlay, FUSE, a network filesystem or a tmpfs.
/// The error names the first place that is there but could not be read,
/// for another reason than that it is not there, where it may have shown a
/// device of it: a device node, a `dev` attribute, or a listing of
/// `/sys/block` or `/sys/fs/btrfs`.
pub(super) fn filesystem_devices<F: Filesystem>(
    fs: &F,
    mount: &MountEntry,
) -> Result<Option<Vec<PathBuf>>, PathBuf> {
    let source = mount.source.to_string_lossy();
    let each = |devices: Vec<String>| -> Result<Option<Vec<PathBuf>>, PathBuf> {
        let mut dirs = Vec::new();
        for device in devices {
            match blockdev::resolve_spec_or_unread(fs, &device)? {
                Some(dir) => dirs.push(dir),
                None => return Ok(None),
            }
        }
        Ok(Some(dirs))
    };
    if mount.fstype == "bcachefs" && source.contains(':') {
        // bcachefs names every device of a filesystem of several in its
        // source, `/dev/sdb:/dev/sdc`; its device number is the first one's.
        return each(source.split(':').map(str::to_string).collect());
    }
    let Some(device) = blockdev::device_of_mount_or_unread(fs, mount)? else {
        return Ok(None);
    };
    // Only a btrfs filesystem lies on devices its mount does not name.
    let members = if mount.fstype == "btrfs" {
        blockdev::btrfs_members(fs, &dir_name(&device))?
    } else {
        Vec::new()
    };
    if members.len() < 2 {
        return Ok(Some(vec![device]));
    }
    each(
        members
            .iter()
            .map(|member| format!("/dev/{member}"))
            .collect(),
    )
}

/// Why a check cannot tell, where sysfs shows the devices `what` is on
/// (`its filesystem`, say), but NAILS cannot read a place that shows them;
/// the place is not named, as no device-mapper node is.
pub(super) fn unread_devices(what: &str) -> String {
    format!("sysfs shows the devices {what} is on, but NAILS cannot read them")
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
