// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The judge's inputs, read through the [`Filesystem`] trait.
//!
//! `<etc_root>/etc/fstab` and `<etc_root>/etc/crypttab` (read with
//! `O_NOATIME` by the real filesystem), and from the running system the block
//! devices in `/sys/class/block`, their stacks, the btrfs filesystems in
//! `/sys/fs/btrfs`, the names in `/dev/disk` and the drivers `/proc/devices`
//! lists. `etc_root` is `/` for the running decoy; another root lets an
//! offline scan judge a decoy's files.
//!
//! A file that does not exist is empty: a system without a crypttab opens no
//! encrypted volume at boot. A file that exists but cannot be read is listed as
//! unreadable and never taken as empty: init and check run without root, some
//! distributions keep crypttab readable by root only, and an unread entry
//! could hide the decoy's claim on the hidden root's device.
//! `/sys/class/block` is listed as unreadable when it cannot be listed or is
//! missing (no sysfs, as in some containers): every block device is listed
//! there, so without it no claim can be followed to a device.
//!
//! The filesystem that holds a loop device's backing file is found by the
//! device the loop driver recorded for it (see [`FileHolder`]): a mount with
//! that `major:minor`, or, on btrfs, whose files report a subvolume's own
//! device that no mount line shows, the mount the path leads to when the file
//! there is on that device. A loop whose record cannot be read (its node is
//! readable by root only) is marked so, and only counts when the hidden root
//! is stored on it.
//!
//! A whole disk with nothing below it in sysfs is told apart by the driver
//! `/proc/devices` lists for its major number: `nbd` is a network block
//! device and `zvol` a ZFS volume ([`Served`], [`Untraced`]). A userspace
//! block device takes its number from the range the kernel shares between
//! drivers, so only the name its driver gives it, `ublkb<N>`, tells it; the
//! names `nbd<N>` and `zd<N>` count as well. A disk whose major number no
//! driver is listed for is untraced, and one whose number or list cannot be
//! read is unidentified: like an unread loop record, that only counts when
//! the hidden root's data reaches the disk.

#[cfg(test)]
#[path = "collect_tests.rs"]
mod tests;

use super::{DeviceMap, SYS_CLASS_BLOCK, Served, Untraced};
use super::{FileHolder, Judgement, LoopFile, Node, NodeKind, Scene, judge};
use crate::Filesystem;
use crate::blockdev::{self, DmKind, Layer, LoopBacking, LoopFollow};
use crate::crypttab::{CrypttabEntry, parse_crypttab};
use crate::filesystem::mountinfo::MountEntry;
use crate::fstab::{FstabEntry, parse_fstab};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Everything the judge reads besides the mount table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Collected {
    /// The parsed fstab.
    pub fstab: Vec<FstabEntry>,
    /// The parsed crypttab.
    pub crypttab: Vec<CrypttabEntry>,
    /// The block devices and the names that lead to them.
    pub devices: DeviceMap,
    /// Inputs that exist but could not be read.
    pub unreadable: Vec<PathBuf>,
}

impl Collected {
    /// The judge's view of these inputs and `mounts`.
    pub fn scene<'a>(&'a self, mounts: &'a [MountEntry]) -> Scene<'a> {
        Scene {
            mounts,
            fstab: &self.fstab,
            crypttab: &self.crypttab,
            devices: &self.devices,
            unreadable: &self.unreadable,
        }
    }
}

/// Judge where `hidden`, the mount at the hidden root, lives: collect the
/// inputs (none for a RAM filesystem, which is separate) and [`judge`].
pub fn judge_storage<F: Filesystem>(
    fs: &F,
    mounts: &[MountEntry],
    hidden: &MountEntry,
    etc_root: &Path,
) -> Judgement {
    let collected = if super::judge::is_ram(&hidden.fstype) {
        Collected::default()
    } else {
        collect(fs, mounts, etc_root)
    };
    judge(&collected.scene(mounts), hidden)
}

/// Collect the judge's inputs. See the module docs.
pub fn collect<F: Filesystem>(fs: &F, mounts: &[MountEntry], etc_root: &Path) -> Collected {
    let mut collected = Collected::default();
    let fstab_path = etc_root.join("etc/fstab");
    let crypttab_path = etc_root.join("etc/crypttab");
    if let Some(text) = read_optional(fs, &fstab_path, &mut collected.unreadable) {
        collected.fstab = parse_fstab(&text);
    }
    if let Some(text) = read_optional(fs, &crypttab_path, &mut collected.unreadable) {
        collected.crypttab = parse_crypttab(&text);
    }

    let devices = &mut collected.devices;
    let majors = blockdev::block_majors(fs);
    // Without the list of block devices no claim can be followed to a device,
    // so a missing list is as unreadable as one that cannot be listed.
    let class = Path::new(SYS_CLASS_BLOCK);
    match fs.list_directory(class) {
        Ok(entries) => {
            for entry in entries {
                for layer in blockdev::stack(fs, &entry, LoopFollow::BlockDevices) {
                    add_layer(fs, mounts, majors.as_ref(), devices, &layer);
                }
            }
        }
        Err(_) => collected.unreadable.push(class.to_path_buf()),
    }

    // The names the files and the mount table use for devices.
    let specs = collected
        .fstab
        .iter()
        .map(|entry| entry.spec.clone())
        .chain(
            collected
                .crypttab
                .iter()
                .flat_map(|entry| [entry.source.clone(), format!("/dev/mapper/{}", entry.name)]),
        )
        .chain(
            mounts
                .iter()
                .map(|m| m.source.to_string_lossy().into_owned()),
        );
    for spec in specs {
        if devices.by_spec.contains_key(&spec) {
            continue;
        }
        if let Some(name) = blockdev::resolve_spec(fs, &spec)
            .as_deref()
            .and_then(file_name)
        {
            devices.by_spec.insert(spec, name);
        }
    }

    let names: Vec<String> = devices.nodes.keys().cloned().collect();
    for name in names {
        if devices.btrfs.iter().any(|members| members.contains(&name)) {
            continue;
        }
        let members: BTreeSet<String> = blockdev::btrfs_members(fs, &name).into_iter().collect();
        if !members.is_empty() {
            devices.btrfs.push(members);
        }
    }
    collected
}

/// The contents of `path`; `None` when it does not exist, and also when it
/// cannot be read, which lands in `unreadable`.
fn read_optional<F: Filesystem>(
    fs: &F,
    path: &Path,
    unreadable: &mut Vec<PathBuf>,
) -> Option<String> {
    match fs.path_exists(path) {
        Ok(false) => return None,
        Ok(true) => {}
        Err(_) => {
            unreadable.push(path.to_path_buf());
            return None;
        }
    }
    match fs.read_file_content(path) {
        Ok(text) => Some(text),
        Err(_) => {
            unreadable.push(path.to_path_buf());
            None
        }
    }
}

/// Record one device of a walked stack. `majors` are the drivers
/// `/proc/devices` lists, `None` when it cannot be read.
fn add_layer<F: Filesystem>(
    fs: &F,
    mounts: &[MountEntry],
    majors: Option<&BTreeMap<u32, String>>,
    devices: &mut DeviceMap,
    layer: &Layer,
) {
    let name = file_name(&layer.sysfs).unwrap_or_else(|| layer.name.clone());
    if devices.nodes.contains_key(&name) {
        return;
    }
    let mut below = layer.slaves.clone();
    let kind = if let Some(dm) = &layer.dm {
        devices
            .by_spec
            .insert(format!("/dev/mapper/{}", dm.name), name.clone());
        match dm.kind {
            DmKind::Crypt(_) | DmKind::CryptSubdev | DmKind::VeraCrypt => NodeKind::Crypt {
                name: dm.name.clone(),
            },
            _ => NodeKind::Mapper {
                name: dm.name.clone(),
            },
        }
    } else if let Some(loop_device) = &layer.loop_device {
        match &loop_device.backing {
            LoopBacking::File(file) => NodeKind::Loop {
                file: Some(LoopFile {
                    path: file.clone(),
                    holder: file_holder(fs, mounts, &name, file),
                }),
            },
            LoopBacking::Block { name: backing, .. } => {
                below.push(backing.clone());
                NodeKind::Loop { file: None }
            }
        }
    } else if let Some(partition) = &layer.partition {
        NodeKind::Partition {
            disk: partition.disk.clone().unwrap_or_default(),
        }
    } else if below.is_empty() {
        leaf_kind(&name, layer, majors)
    } else {
        // An md array: its data lies on the devices below it.
        NodeKind::Disk
    };
    if let Some(dev) = &layer.dev {
        devices.by_dev.insert(dev.clone(), name.clone());
    }
    devices.by_spec.insert(format!("/dev/{name}"), name.clone());
    devices.nodes.insert(name, Node { kind, below });
}

/// What the whole disk `name` (read as `layer`) is, with nothing below it in
/// sysfs: by the driver `majors` names for its major number, and by the name
/// that driver gives its disks (see the module docs).
fn leaf_kind(name: &str, layer: &Layer, majors: Option<&BTreeMap<u32, String>>) -> NodeKind {
    let Some(majors) = majors else {
        return NodeKind::Unidentified(PathBuf::from(blockdev::PROC_DEVICES));
    };
    let Some(major) = layer.dev.as_deref().and_then(blockdev::major_of) else {
        return NodeKind::Unidentified(layer.sysfs.join("dev"));
    };
    let Some(driver) = majors.get(&major) else {
        return NodeKind::Untraced(Untraced::UnnamedDriver);
    };
    // A disk is known by its driver's name for it as well, which only ever
    // makes the verdict stricter.
    let named = |prefix: &str| {
        name.strip_prefix(prefix)
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
    };
    if driver == "zvol" || named("zd") {
        NodeKind::Untraced(Untraced::ZfsVolume)
    } else if driver == "nbd" || named("nbd") {
        NodeKind::Served(Served::Network)
    } else if named("ublkb") {
        NodeKind::Served(Served::Userspace)
    } else {
        NodeKind::Disk
    }
}

/// The filesystem that holds `file`, the backing file of the loop device
/// `name`, found by the device the loop driver recorded (see the module docs).
fn file_holder<F: Filesystem>(
    fs: &F,
    mounts: &[MountEntry],
    name: &str,
    file: &Path,
) -> FileHolder {
    let node = Path::new("/dev").join(name);
    let Ok(dev) = fs.loop_backing_device(&node) else {
        return FileHolder::Unreadable(node);
    };
    let number = format!("{}:{}", rustix::fs::major(dev), rustix::fs::minor(dev));
    if mounts.iter().any(|m| m.dev == number) {
        return FileHolder::Mount(number);
    }
    match crate::hidden_root::mount_holding(mounts, file) {
        Some(mount) if fs.device_id(file).ok() == Some(dev) => FileHolder::Mount(mount.dev.clone()),
        _ => FileHolder::Unplaced,
    }
}

fn file_name(path: &Path) -> Option<String> {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
}
