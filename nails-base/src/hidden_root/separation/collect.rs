// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The judge's inputs, read through the [`Filesystem`] trait.
//!
//! `<etc_root>/etc/fstab` and `<etc_root>/etc/crypttab` (read with
//! `O_NOATIME` by the real filesystem), and from the running system the block
//! devices in `/sys/class/block`, their stacks, the btrfs filesystems in
//! `/sys/fs/btrfs` and the names in `/dev/disk`. `etc_root` is `/` for the
//! running decoy; another root lets an offline scan judge a decoy's files.
//!
//! A file that does not exist is empty: a system without a crypttab opens no
//! encrypted volume at boot. A file (or `/sys/class/block`) that exists but
//! cannot be read is listed as unreadable and never taken as empty: init and
//! check run without root, some distributions keep crypttab readable by root
//! only, and an unread entry could hide the decoy's claim on the hidden
//! root's device.

#[cfg(test)]
#[path = "collect_tests.rs"]
mod tests;

use super::DeviceMap;
use super::{Judgement, Node, NodeKind, Scene, judge};
use crate::Filesystem;
use crate::blockdev::{self, DmKind, Layer, LoopBacking, LoopFollow};
use crate::crypttab::{CrypttabEntry, parse_crypttab};
use crate::filesystem::mountinfo::MountEntry;
use crate::fstab::{FstabEntry, parse_fstab};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Where the kernel lists every block device.
const SYS_CLASS_BLOCK: &str = "/sys/class/block";

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
    let collected = if matches!(hidden.fstype.as_str(), "tmpfs" | "ramfs") {
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
    let class = Path::new(SYS_CLASS_BLOCK);
    if fs.path_exists(class).unwrap_or(false) {
        match fs.list_directory(class) {
            Ok(entries) => {
                for entry in entries {
                    for layer in blockdev::stack(fs, &entry, LoopFollow::BlockDevices) {
                        add_layer(devices, &layer);
                    }
                }
            }
            Err(_) => collected.unreadable.push(class.to_path_buf()),
        }
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

/// Record one device of a walked stack.
fn add_layer(devices: &mut DeviceMap, layer: &Layer) {
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
                file: Some(file.clone()),
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
    } else {
        NodeKind::Disk
    };
    if let Some(dev) = &layer.dev {
        devices.by_dev.insert(dev.clone(), name.clone());
    }
    devices.by_spec.insert(format!("/dev/{name}"), name.clone());
    devices.nodes.insert(name, Node { kind, below });
}

fn file_name(path: &Path) -> Option<String> {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
}
