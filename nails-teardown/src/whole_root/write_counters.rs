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
//! accounting (SCSI and NVMe passthrough), zone resets and finishes, which
//! move no sectors, DAX access to persistent memory, which bypasses the
//! block layer, a second path to the same disk that no multipath device
//! joins (it shows as another disk, unwatched where no decoy mount uses it),
//! what a device writes on its own (its firmware, SMART logs, wear
//! levelling), and other persistent stores (EFI variables, a TPM).
//!
//! A decoy layer that writes on its own after the last write would power off
//! a session that wrote nothing. [`layout`] refuses an md array (its
//! superblock's clean mark and its bitmap follow the last write by seconds)
//! and a device whose writes the counters cannot follow to a disk (nbd,
//! ublk, rbd, or one sysfs does not list). XFS pushes its log's items and
//! covers its log some 20 to 80 seconds after a `sync`; the entry's last step
//! freezes and thaws every XFS filesystem on a watched disk before the
//! baseline, which writes them first. Not refused, and not measured:
//! dm-cache, dm-writecache, bcache and dm-integrity, which write their own
//! metadata, f2fs's garbage collection, ext4's lazy inode-table init on a new
//! filesystem, and btrfs's asynchronous discard.
//!
//! [`layout`] runs at activation, on the decoy; the last step before the
//! switch takes the [`Baseline`] after a `sync`, once every decoy unit has
//! stopped; the session watcher [`check`]s the counters against it. Both
//! read every counter until two reads in a row agree, so a write that lands
//! while they read cannot split a disk from its partitions.

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
    /// The kernel does not count a decoy disk's I/O (`queue/iostats` is 0).
    NotCounted(String),
    /// No decoy filesystem lies on a disk the counters can watch.
    NothingToWatch,
    /// A decoy device writes on its own after the last write (an md array).
    WritesOnItsOwn(String),
    /// A decoy device whose writes the counters cannot follow to a disk.
    Unwatchable(String),
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
            Imprecise::NotCounted(dev) => write!(
                f,
                "the kernel does not count the I/O of {dev} (its queue/iostats is 0)"
            ),
            Imprecise::NothingToWatch => write!(
                f,
                "no decoy filesystem lies on a disk whose write counters can be watched"
            ),
            Imprecise::WritesOnItsOwn(name) => write!(
                f,
                "the decoy uses the md array {name}, which writes its superblock and bitmap \
                 on its own after the last write: the tripwire would power off a session \
                 that wrote nothing"
            ),
            Imprecise::Unwatchable(name) => write!(
                f,
                "the decoy uses {name}, whose writes the counters cannot follow to a disk \
                 (a network or userspace block device, or one sysfs does not list)"
            ),
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

/// Whether the kernel name `name` is a block device in RAM.
fn in_ram(name: &str) -> bool {
    let digits = |rest: &str| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit());
    name.strip_prefix("zram").is_some_and(digits) || name.strip_prefix("ram").is_some_and(digits)
}

/// Refuse a decoy device the counters cannot watch: one that writes on its
/// own after the last write, and one whose writes reach no disk the
/// counters see. `used` are the decoy's devices and everything below them,
/// `stack` the hidden volume's.
fn refuse_restless(
    used: &BTreeSet<DevNum>,
    stack: &BTreeSet<DevNum>,
    names: &BTreeMap<DevNum, String>,
    sys: &Sysfs,
) -> Result<(), Imprecise> {
    for &dev in used.difference(stack) {
        let name = names.get(&dev).cloned().unwrap_or_else(|| dev.text());
        let Some(dir) = sys.dir(dev) else {
            return Err(Imprecise::Unwatchable(name));
        };
        if dir.join("md").is_dir() {
            return Err(Imprecise::WritesOnItsOwn(name));
        }
        let leaf = sys.slaves(dev).is_empty() && sys.parent(dev).is_none();
        if leaf && !sys.is_hardware(dev) && loop_file(sys, dev).is_none() && !in_ram(&name) {
            return Err(Imprecise::Unwatchable(name));
        }
    }
    Ok(())
}

/// Whether the device `dev` lies on a disk of `layout`: the disk, one of
/// its partitions, or a device stacked on them.
pub fn on_watched_disk(layout: &Layout, sys: &Sysfs, dev: DevNum) -> bool {
    closure(&[dev], sys, true)
        .iter()
        .any(|d| layout.disks.iter().any(|disk| disk.dev == d.text()))
}

/// Freeze and thaw the filesystem mounted at `mount_point` (`FIFREEZE`,
/// `FITHAW`). A freeze writes everything the filesystem keeps for later: XFS
/// pushes its log's items to their places and covers its log, which after a
/// plain `sync` it does 20 to 80 seconds on. Measured on Linux 6.8: an XFS
/// filesystem written to and synced wrote 302 more sectors over 110 seconds,
/// and none once frozen and thawed. The thaw is tried again where it fails,
/// as a filesystem left frozen stops every writer.
#[allow(unsafe_code)]
pub fn freeze_and_thaw(mount_point: &Path) -> io::Result<()> {
    use rustix::ioctl::{NoArg, ioctl, opcode};
    const FIFREEZE: rustix::ioctl::Opcode = opcode::read_write::<libc::c_int>(b'X', 119);
    const FITHAW: rustix::ioctl::Opcode = opcode::read_write::<libc::c_int>(b'X', 120);
    let dir = std::fs::File::open(mount_point)?;
    // SAFETY: FIFREEZE takes no argument the kernel reads.
    unsafe { ioctl(&dir, NoArg::<FIFREEZE>::new()) }.map_err(io::Error::from)?;
    let mut thawed = Ok(());
    for _ in 0..3 {
        // SAFETY: FITHAW takes no argument the kernel reads.
        thawed = unsafe { ioctl(&dir, NoArg::<FITHAW>::new()) }.map_err(io::Error::from);
        if thawed.is_ok() {
            break;
        }
    }
    thawed
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
    let names: BTreeMap<DevNum, String> = all.iter().cloned().collect();
    refuse_restless(&used, &stack, &names, sys)?;
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
        match counted(sys, &dev.text()) {
            Some(true) => {}
            Some(false) => return Err(Imprecise::NotCounted(dev.text())),
            None => return Err(Imprecise::Unreadable(dev.text())),
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
    if disks.is_empty() {
        return Err(Imprecise::NothingToWatch);
    }
    Ok(Layout { disks })
}

/// Whether the kernel counts the I/O of the disk `dev` (`major:minor`):
/// `queue/iostats` is 1. A queue whose counting is off shows every counter
/// standing still. `None` where it cannot be read.
pub fn counted(sys: &Sysfs, dev: &str) -> Option<bool> {
    let text =
        std::fs::read_to_string(sys.root.join("dev/block").join(dev).join("queue/iostats")).ok()?;
    match text.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
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

/// How many times a read of every counter is repeated, at most, to find two
/// in a row that agree.
const STABLE_TRIES: usize = 20;

/// The counters of `devs`, read until two reads in a row agree (or the last
/// of [`STABLE_TRIES`] reads, with whether they agreed); `None` for one that
/// cannot be read.
fn stable_read(devs: &[&String], sys: &Sysfs) -> (BTreeMap<String, Option<u64>>, bool) {
    let read = || -> BTreeMap<String, Option<u64>> {
        devs.iter()
            .map(|dev| ((*dev).clone(), sectors(sys, dev)))
            .collect()
    };
    let mut last = read();
    for _ in 0..STABLE_TRIES {
        let now = read();
        if now == last {
            return (now, true);
        }
        last = now;
    }
    (last, false)
}

/// Every device `layout` watches: each disk and its partitions.
fn watched_devices(layout: &Layout) -> Vec<&String> {
    layout
        .disks
        .iter()
        .flat_map(|disk| std::iter::once(&disk.dev).chain(disk.partitions.iter().map(|p| &p.dev)))
        .collect()
}

/// The counters of every watched device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    /// Sectors written and discarded, by `major:minor`.
    pub sectors: BTreeMap<String, u64>,
}

impl Baseline {
    /// The counters of every device of `layout`, read until two reads in a
    /// row agree; `Err` names one that cannot be read, or says that they
    /// did not stop changing.
    pub fn take(layout: &Layout, sys: &Sysfs) -> Result<Self, String> {
        let (read, agreed) = stable_read(&watched_devices(layout), sys);
        let mut sectors_by_dev = BTreeMap::new();
        for (dev, count) in read {
            sectors_by_dev.insert(dev.clone(), count.ok_or(dev)?);
        }
        if !agreed {
            return Err("the write counters did not stop changing".to_string());
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
/// Every counter is read until two reads in a row agree, so a write that
/// lands while they are read cannot split a disk from its partitions; where
/// they never agree, the last read counts.
pub fn check(layout: &Layout, base: &Baseline, sys: &Sysfs) -> Vec<String> {
    let mut found = Vec::new();
    let current: Vec<(DevNum, String)> = sys.all();
    let (now_sectors, _) = stable_read(&watched_devices(layout), sys);
    for disk in &layout.disks {
        let growth = |dev: &str, name: &str, found: &mut Vec<String>| -> Option<u64> {
            let Some(&was) = base.sectors.get(dev) else {
                found.push(format!("{name} ({dev}) has no baseline"));
                return None;
            };
            let Some(now) = now_sectors.get(dev).copied().flatten() else {
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
        if counted(sys, &disk.dev) != Some(true) {
            found.push(format!(
                "the kernel no longer counts the I/O of {} ({})",
                disk.name, disk.dev
            ));
        }
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
