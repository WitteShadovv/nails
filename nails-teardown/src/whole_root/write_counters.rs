// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The kernel's write counters of the decoy disks: what the write tripwire
//! (`[session_mounts] write_tripwire`) watches.
//!
//! Every disk and partition has a counter of the sectors written to it and of
//! the sectors discarded on it (`/sys/dev/block/<major>:<minor>/stat`, fields
//! 7 and 14). The kernel counts a partition's I/O on the partition and again on
//! its whole disk, and a device-mapper device's on it and again on every device
//! below it. So the counters of the decoy's disks tell, without knowing which
//! program wrote, whether anything wrote to them:
//!
//! - every partition of a decoy disk but the hidden volume's own must not grow;
//! - nor may a disk's **residual**, the growth of its own counter less that of
//!   all its partitions: the partition table and the gaps between partitions.
//!
//! The hidden volume's partition (or whole disk) is left out only when it is
//! the hidden volume's alone: every device stacked on it belongs to the hidden
//! volume's stack and no decoy mount uses it. A hidden volume that shares a
//! partition with the decoy (a logical volume beside the decoy's, a folder of a
//! decoy filesystem) or that is a file on a decoy disk, opened through a loop
//! device, cannot be told apart from the decoy by these counters: its own
//! writes pass through the decoy's partition, and a file's write also writes
//! its inode and the journal. [`layout`] refuses those.
//!
//! What the counters do not see: requests that bypass the block layer's
//! accounting (SCSI and NVMe passthrough), what a device writes on its own
//! (its firmware, SMART logs, wear levelling), and other persistent stores
//! (EFI variables, a TPM).
//!
//! [`layout`] runs at activation, on the decoy; the last step before the
//! switch takes the [`Baseline`] after a `sync`, once every decoy unit has
//! stopped; the session watcher [`check`]s the counters against it.

use crate::whole_root::disk_guard::{DevNum, Sysfs, block_device};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The baseline's file name in the runtime directory (neutral).
pub const BASELINE_NAME: &str = "block-counters";

/// A partition, as the layout records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Part {
    /// The kernel name (`vda2`, `nvme0n1p3`).
    pub name: String,
    /// The device number, `major:minor`.
    pub dev: String,
}

/// One decoy disk the tripwire watches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchedDisk {
    /// The kernel name (`vda`, `nvme0n1`).
    pub name: String,
    /// The device number, `major:minor`.
    pub dev: String,
    /// Every partition of the disk at activation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub partitions: Vec<Part>,
    /// The device numbers of the partitions that are the hidden volume's
    /// alone: their writes are allowed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed: Vec<String>,
}

/// What the tripwire watches: every disk that holds a decoy filesystem.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Layout {
    /// The decoy disks.
    pub disks: Vec<WatchedDisk>,
}

/// Why the counters cannot tell the hidden volume's writes from the decoy's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Imprecise {
    /// The hidden root's mount has no block device.
    NoDevice,
    /// The hidden volume lies on a device that a decoy mount, or a device
    /// stacked on it outside the hidden volume, also uses.
    Shared(String),
    /// The hidden volume is a file, opened through a loop device, on a disk.
    File(PathBuf),
    /// A decoy disk's or partition's counters cannot be read.
    Unreadable(String),
}

impl std::fmt::Display for Imprecise {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Imprecise::NoDevice => write!(f, "the hidden root's mount has no block device"),
            Imprecise::Shared(dev) => write!(
                f,
                "the hidden volume lies on {dev}, which the decoy also uses: the kernel's \
                 write counters cannot tell its writes from the decoy's"
            ),
            Imprecise::File(path) => write!(
                f,
                "the hidden volume is the file {} on a disk: writing it also writes the \
                 filesystem it is on",
                path.display()
            ),
            Imprecise::Unreadable(dev) => {
                write!(f, "the kernel's write counters of {dev} cannot be read")
            }
        }
    }
}

/// The devices `seeds` stand on, the seeds included: their slaves, and, with
/// `disks`, the disk below each partition.
fn closure(seeds: &[DevNum], sys: &Sysfs, disks: bool) -> BTreeSet<DevNum> {
    let mut todo = seeds.to_vec();
    let mut done = BTreeSet::new();
    while let Some(dev) = todo.pop() {
        if !done.insert(dev) {
            continue;
        }
        todo.extend(sys.slaves(dev));
        if disks {
            todo.extend(sys.parent(dev));
        }
    }
    done
}

/// The devices stacked directly on `dev`.
fn holders(sys: &Sysfs, dev: DevNum) -> Vec<DevNum> {
    let Some(dir) = sys.dir(dev) else {
        return Vec::new();
    };
    std::fs::read_dir(dir.join("holders"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| Sysfs::dev_in(&e.path()))
        .collect()
}

/// The file a loop device reads, if it is one.
fn loop_file(sys: &Sysfs, dev: DevNum) -> Option<PathBuf> {
    let text = std::fs::read_to_string(sys.dir(dev)?.join("loop/backing_file")).ok()?;
    Some(PathBuf::from(text.trim_end_matches('\n')))
}

/// The device a file lies on, when that is a block device (not a tmpfs).
fn file_device(path: &Path) -> Option<DevNum> {
    let dev = DevNum::from_raw(std::fs::metadata(path).ok()?.dev());
    (dev.major != 0).then_some(dev)
}

/// What the tripwire watches, and what it allows, for a hidden volume whose
/// mount and mappings are the devices `hidden`, on a decoy whose mounts are on
/// the devices `decoy` (the decoy root's, and every other mount outside the
/// hidden root). See the module docs.
pub fn layout(hidden: &[DevNum], decoy: &[DevNum], sys: &Sysfs) -> Result<Layout, Imprecise> {
    layout_with(hidden, decoy, sys, &file_device)
}

/// [`layout`], with `file_device` telling the device a loop device's file
/// lies on.
fn layout_with(
    hidden: &[DevNum],
    decoy: &[DevNum],
    sys: &Sysfs,
    file_device: &dyn Fn(&Path) -> Option<DevNum>,
) -> Result<Layout, Imprecise> {
    if hidden.is_empty() {
        return Err(Imprecise::NoDevice);
    }
    let stack = closure(hidden, sys, false);
    let used = closure(decoy, sys, true);
    let mut owned = BTreeSet::new();
    for &dev in &stack {
        if !sys.slaves(dev).is_empty() {
            continue;
        }
        if let Some(file) = loop_file(sys, dev) {
            if file_device(&file)
                .is_some_and(|d| closure(&[d], sys, true).iter().any(|&d| sys.is_hardware(d)))
            {
                return Err(Imprecise::File(file));
            }
            continue;
        }
        if !sys.is_hardware(dev) {
            continue;
        }
        if used.contains(&dev) || holders(sys, dev).iter().any(|h| !stack.contains(h)) {
            return Err(Imprecise::Shared(dev.text()));
        }
        owned.insert(dev);
    }
    let all = sys.all();
    let mut disks = Vec::new();
    for (dev, name) in &all {
        let whole = sys.parent(*dev).is_none() && sys.is_hardware(*dev);
        if !whole || owned.contains(dev) || !used.contains(dev) {
            continue;
        }
        let mut partitions: Vec<Part> = all
            .iter()
            .filter(|(p, _)| sys.parent(*p) == Some(*dev))
            .map(|(p, n)| Part {
                name: n.clone(),
                dev: p.text(),
            })
            .collect();
        partitions.sort_by(|a, b| a.dev.cmp(&b.dev));
        for d in std::iter::once(dev.text()).chain(partitions.iter().map(|p| p.dev.clone())) {
            if sectors(sys, &d).is_none() {
                return Err(Imprecise::Unreadable(d));
            }
        }
        let allowed = partitions
            .iter()
            .filter(|p| DevNum::parse(&p.dev).is_some_and(|d| owned.contains(&d)))
            .map(|p| p.dev.clone())
            .collect();
        disks.push(WatchedDisk {
            name: name.clone(),
            dev: dev.text(),
            partitions,
            allowed,
        });
    }
    disks.sort_by(|a, b| a.dev.cmp(&b.dev));
    Ok(Layout { disks })
}

/// The devices of the hidden volume for [`layout`]: the device of the mount
/// at the hidden root (`hidden_dev`, `major:minor`, or the block device it
/// shows) and the device-mapper devices of its backend.
pub fn hidden_devices(mount: Option<DevNum>, backend: &[String]) -> Vec<DevNum> {
    mount
        .into_iter()
        .chain(
            backend
                .iter()
                .filter_map(|name| block_device(&Path::new("/dev/mapper").join(name))),
        )
        .collect()
}

/// The sectors written and discarded on `dev` (`major:minor`) since the
/// kernel found it.
pub fn sectors(sys: &Sysfs, dev: &str) -> Option<u64> {
    let text = std::fs::read_to_string(sys.root.join("dev/block").join(dev).join("stat")).ok()?;
    let fields: Vec<u64> = text
        .split_whitespace()
        .map(|f| f.parse().ok())
        .collect::<Option<_>>()?;
    let written = *fields.get(6)?;
    // Kernels before 4.18 list no discard fields; the floor is 6.1.
    let discarded = fields.get(13).copied().unwrap_or(0);
    Some(written + discarded)
}

/// The counters of every watched device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    /// Sectors written and discarded, by `major:minor`.
    pub sectors: BTreeMap<String, u64>,
}

impl Baseline {
    /// The counters of every device of `layout`; `Err` names one that
    /// cannot be read.
    pub fn take(layout: &Layout, sys: &Sysfs) -> Result<Self, String> {
        let mut sectors_by_dev = BTreeMap::new();
        for disk in &layout.disks {
            for dev in std::iter::once(&disk.dev).chain(disk.partitions.iter().map(|p| &p.dev)) {
                let count = sectors(sys, dev).ok_or_else(|| dev.clone())?;
                sectors_by_dev.insert(dev.clone(), count);
            }
        }
        Ok(Self {
            sectors: sectors_by_dev,
        })
    }

    /// Write the baseline to `path`, private.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let text = serde_json::to_vec(self).map_err(io::Error::other)?;
        crate::whole_root::plan::write_private_atomic(path, &text)
    }

    /// The baseline at `path`, if it can be read.
    pub fn load(path: &Path) -> Option<Self> {
        serde_json::from_slice(&std::fs::read(path).ok()?).ok()
    }
}

/// Every write the counters show on `layout`'s disks since `base`, one line
/// each; empty when there is none. A device that is gone or cannot be read, a
/// counter that went down and a partition that appeared or went are lines too:
/// the counters can no longer tell.
///
/// Each disk's own counter is read before its partitions'. The counters only
/// grow, so a write to a partition that lands between the two reads can only
/// make the residual smaller, never show one that is not there.
pub fn check(layout: &Layout, base: &Baseline, sys: &Sysfs) -> Vec<String> {
    let mut found = Vec::new();
    let current: Vec<(DevNum, String)> = sys.all();
    for disk in &layout.disks {
        let growth = |dev: &str, name: &str, found: &mut Vec<String>| -> Option<u64> {
            let Some(&was) = base.sectors.get(dev) else {
                found.push(format!("{name} ({dev}) has no baseline"));
                return None;
            };
            let Some(now) = sectors(sys, dev) else {
                found.push(format!(
                    "the write counters of {name} ({dev}) cannot be read"
                ));
                return None;
            };
            if now < was {
                found.push(format!("the write counters of {name} ({dev}) went down"));
                return None;
            }
            Some(now - was)
        };
        let Some(whole) = growth(&disk.dev, &disk.name, &mut found) else {
            continue;
        };
        let Some(disk_num) = DevNum::parse(&disk.dev) else {
            continue;
        };
        let mut now_parts: Vec<String> = current
            .iter()
            .filter(|(p, _)| sys.parent(*p) == Some(disk_num))
            .map(|(p, _)| p.text())
            .collect();
        now_parts.sort();
        let was_parts: Vec<String> = disk.partitions.iter().map(|p| p.dev.clone()).collect();
        if now_parts != was_parts {
            found.push(format!("the partitions of {} changed", disk.name));
        }
        let mut parts = 0u64;
        for part in &disk.partitions {
            let Some(grew) = growth(&part.dev, &part.name, &mut found) else {
                continue;
            };
            parts += grew;
            if grew > 0 && !disk.allowed.contains(&part.dev) {
                found.push(format!("{grew} sectors written to {}", part.name));
            }
        }
        let residual = whole.saturating_sub(parts);
        if residual > 0 && disk.partitions.is_empty() {
            found.push(format!("{residual} sectors written to {}", disk.name));
        } else if residual > 0 {
            found.push(format!(
                "{residual} sectors written to {} outside its partitions",
                disk.name
            ));
        }
    }
    found
}

#[cfg(test)]
#[path = "write_counters_tests.rs"]
mod tests;
