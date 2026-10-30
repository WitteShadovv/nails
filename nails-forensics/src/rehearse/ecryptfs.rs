// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where an eCryptfs mount keeps its encrypted files, for a scan.
//!
//! An eCryptfs mount stores the files under it encrypted in a folder of the
//! filesystem below, so a raw plaintext scan of a device that holds that folder
//! cannot prove the canary absent. The mount table shows the mounts the folder
//! may lie on ([`lowers`]), and sysfs the block devices that hold those mounts'
//! filesystems, which [`blind_spot`] checks a device named for a scan against.

use crate::Filesystem;
use crate::filesystem::MountEntry;
use nails_base::blockdev::{self, Layer, LoopBacking, LoopFollow};
use std::path::{Component, Path, PathBuf};

/// The type of an eCryptfs mount.
const ECRYPTFS: &str = "ecryptfs";

/// The indices of the mounts whose filesystems may hold the folder of the
/// eCryptfs mount at `index` in `mounts`: those the folder may have lain on
/// when it was mounted ([`folder_mounts`]). A folder that lay in the view of
/// another eCryptfs mount is stored, encrypted again, in that mount's folder,
/// so it may be held wherever that folder may lie. `None` when the table cannot
/// place a folder on the way, or places one only in the views of eCryptfs
/// mounts that lie in each other's.
fn holding_mounts(mounts: &[MountEntry], index: usize) -> Option<Vec<usize>> {
    let mut holding = Vec::new();
    let mut seen = vec![index];
    let mut pending = vec![index];
    while let Some(at) = pending.pop() {
        for found in folder_mounts(mounts, at)? {
            if seen.contains(&found) {
                continue;
            }
            seen.push(found);
            if mounts[found].fstype == ECRYPTFS {
                pending.push(found);
            } else {
                holding.push(found);
            }
        }
    }
    (!holding.is_empty()).then_some(holding)
}

/// The index of the one mount of `mounts` that `matches`: `Some(None)` when
/// none does, and `None` when two or more do.
fn only(mounts: &[MountEntry], matches: impl Fn(&MountEntry) -> bool) -> Option<Option<usize>> {
    let mut found = mounts
        .iter()
        .enumerate()
        .filter(|(_, entry)| matches(entry))
        .map(|(at, _)| at);
    match (found.next(), found.next()) {
        (first, None) => Some(first),
        (_, Some(_)) => None,
    }
}

/// The indices of the mounts the folder of the eCryptfs mount at `index` in
/// `mounts` may have lain on when it was mounted.
///
/// The mount point's way down then ran through the mount it was made on (its
/// parent) and that mount's parents, which no later mount changes, and the
/// folder's path took the same way as far as the two paths agree. Below that
/// the path reached the mount there or one stacked on it at a place on the
/// way, and the table does not show which. It lists mounts in the order they
/// were made, but a mount namespace copied from another (one `unshare -m`, a
/// container or a service with mount sandboxing runs in) lists the mounts it
/// copied in the order of their tree, so a mount made before the eCryptfs
/// mount can come after it, and one made after it before it. Each of them
/// counts, and so does the mount below them. `None` for a path that is
/// relative or climbs (`..`), a parent the table does not list or lists twice,
/// a parent chain that runs in a circle, and two mounts on one at a place on
/// the way, or mounts there that run in a circle.
fn folder_mounts(mounts: &[MountEntry], index: usize) -> Option<Vec<usize>> {
    let entry = &mounts[index];
    let folder = entry.source.as_path();
    if !folder.is_absolute() || folder.components().any(|part| part == Component::ParentDir) {
        return None;
    }
    let mut at = only(mounts, |mount| mount.mount_id == entry.parent_id)??;
    // A parent chain is no longer than the table unless it runs in a circle.
    for _ in 0..mounts.len() {
        if folder.starts_with(&mounts[at].mount_point) {
            break;
        }
        let parent = mounts[at].parent_id;
        at = only(mounts, |mount| mount.mount_id == parent)??;
    }
    if !folder.starts_with(&mounts[at].mount_point) {
        return None;
    }
    let shared = folder
        .components()
        .zip(entry.mount_point.components())
        .take_while(|(own, point)| own == point)
        .count();
    let mut point: PathBuf = folder.components().take(shared).collect();
    let mut reached = vec![at];
    for component in folder.components().skip(shared) {
        point.push(component);
        add_stacked(mounts, &point, &mut reached)?;
    }
    Some(reached)
}

/// Add to `reached` the mounts stacked at `point` on those in it, one on
/// another or not: each may have been on top there. `None` when two sit on
/// one mount there, or they run in a circle.
fn add_stacked(mounts: &[MountEntry], point: &Path, reached: &mut Vec<usize>) -> Option<()> {
    let mut next = 0;
    while let Some(&at) = reached.get(next) {
        next += 1;
        let below = mounts[at].mount_id;
        let above = only(mounts, |mount| {
            mount.parent_id == below && mount.mount_point == point && mount.mount_id != below
        })?;
        match above {
            Some(above) if reached.contains(&above) => return None,
            Some(above) => reached.push(above),
            None => {}
        }
    }
    Some(())
}

/// Where the eCryptfs mounts of `mounts` keep their encrypted files: the
/// mounts whose filesystems their folders may lie on ([`holding_mounts`]), and
/// the eCryptfs mounts whose folder the scan cannot place on a mount the table
/// shows.
pub(super) fn lowers(mounts: &[MountEntry]) -> (Vec<&MountEntry>, Vec<&MountEntry>) {
    let mut held: Vec<usize> = Vec::new();
    let mut unplaced = Vec::new();
    for (index, entry) in mounts.iter().enumerate() {
        if entry.fstype != ECRYPTFS {
            continue;
        }
        match holding_mounts(mounts, index) {
            Some(holding) => {
                for at in holding {
                    if !held.contains(&at) {
                        held.push(at);
                    }
                }
            }
            None => unplaced.push(entry),
        }
    }
    (held.into_iter().map(|at| &mounts[at]).collect(), unplaced)
}

/// Why a device named for a scan is not checked when the scan cannot tell
/// whether it holds the folder of an eCryptfs mount, as the storage under the
/// folder or the device itself is out of sysfs's sight.
const ECRYPTFS_UNPLACED: &str = "an eCryptfs mount (an encrypted home or Private folder) stores \
     the files under it encrypted, and the scan cannot tell whether this device holds them: sysfs \
     shows no block device at the bottom of the storage their folder lies on (a tmpfs, an overlay, \
     a FUSE or network filesystem, or an image file stored on one), the mount table shows no \
     mount the scan can place the folder on, or sysfs shows no block device at this path, so \
     this raw plaintext scan cannot prove the canary absent";

/// Why a device named for a scan is not checked when more devices lie below
/// the filesystem an eCryptfs folder lies on, or below the device itself, than
/// the scan follows.
const ECRYPTFS_TOO_MANY: &str = "an eCryptfs mount (an encrypted home or Private folder) stores \
     the files under it encrypted, and the scan cannot tell whether this device holds them: more \
     devices lie below the filesystem their folder lies on, or below this device, than the scan \
     follows, so this raw plaintext scan cannot prove the canary absent";

/// Why a device named for a scan is not checked when it reads, through a loop
/// device, a path that leads to no file the scan can find.
const ECRYPTFS_UNTRACED: &str = "an eCryptfs mount (an encrypted home or Private folder) stores \
     the files under it encrypted, and the scan cannot tell whether this device holds them: it \
     reads through a loop device a path that leads to no file or block device the scan can find \
     (a deleted file, a device node outside /dev, a path only another mount namespace has), so \
     this raw plaintext scan cannot prove the canary absent";

/// The most devices the scan reads below the filesystem an eCryptfs folder
/// lies on, or below a device named for a scan. Real stacks are a few devices
/// deep, and a wide array adds two (a member partition and its disk) per
/// drive, so only a pathological sysfs reaches it.
pub(super) const MAX_HOLDING_DEVICES: usize = 256;

/// Why a clean scan of `device` cannot rule out the eCryptfs mounts whose
/// folders may lie on the filesystems of `lowers`, or that the scan cannot
/// place on a mount the table shows (`unplaced`): it holds one of those
/// folders, read from sysfs through `fs`, or the scan cannot tell whether it
/// does. `None` when there is no eCryptfs mount, or each one's folder lies on
/// other devices.
///
/// A device holds a folder when it is the block device of the filesystem the
/// folder lies on, lies below that device ([`devices_holding`]: a whole disk
/// with it in a partition, the partition below a dm-crypt or LVM mapping, a
/// member of an md array, the file a loop device reads, named as a regular
/// file, or the device of the filesystem that holds that file), or is built on
/// one that does ([`reaches`]: a mapping or a loop device over it, a partition
/// of either). A folder on a filesystem with no block device of its own (a
/// tmpfs, an overlay, a network share), in an image file on one, or on no
/// mount the scan can place it on, a path sysfs lists no block device for that
/// is no regular file (a node outside `/dev`, a system without sysfs), a loop
/// device below `device` bound to a path that leads to no file, and more
/// devices below the folder's filesystem or below `device` than
/// [`MAX_HOLDING_DEVICES`] leave the scan unable to tell, unless the devices
/// it did read hold `device`.
pub(super) fn blind_spot<F: Filesystem>(
    fs: &F,
    device: &Path,
    lowers: &[&MountEntry],
    unplaced: &[&MountEntry],
) -> Option<String> {
    if lowers.is_empty() && unplaced.is_empty() {
        return None;
    }
    let named = named_block_device(fs, device);
    let regular_file = named.is_none() && fs.is_regular_file(device).unwrap_or(false);
    let mut unsure =
        (!unplaced.is_empty() || (named.is_none() && !regular_file)).then_some(ECRYPTFS_UNPLACED);
    for lower in lowers {
        let Some(top) = blockdev::device_of_mount(fs, lower) else {
            unsure.get_or_insert(ECRYPTFS_UNPLACED);
            continue;
        };
        let holding = devices_holding(fs, &top);
        let reach = match &named {
            Some(dir) => reaches(fs, dir, &holding),
            None => Reach {
                holds: holding.reads_file(device),
                gap: None,
            },
        };
        if reach.holds {
            return Some(super::ScanBlindSpot::StackedEncryption.reason().to_string());
        }
        if let Some(gap) = holding.gap.or(reach.gap) {
            unsure.get_or_insert(gap);
        }
    }
    unsure.map(str::to_string)
}

/// The sysfs directory of the block device at `device`, a path under `/dev`;
/// `None` for any other path, and for one sysfs lists no block device for.
fn named_block_device<F: Filesystem>(fs: &F, device: &Path) -> Option<PathBuf> {
    if !device.starts_with("/dev") {
        return None;
    }
    blockdev::resolve_spec(fs, device.to_str()?)
}

/// The block devices below the filesystem an eCryptfs folder lies on, as far
/// as the scan read them ([`devices_holding`]).
#[derive(Debug, Default)]
struct Holding {
    /// The devices read.
    layers: Vec<Layer>,
    /// The sysfs directories of the disks among `layers` that hold the
    /// filesystem only in a partition among them: their other partitions do
    /// not.
    disks: Vec<PathBuf>,
    /// Why devices that hold the filesystem may be missing from `layers`:
    /// [`ECRYPTFS_UNPLACED`] or [`ECRYPTFS_TOO_MANY`].
    gap: Option<&'static str>,
}

impl Holding {
    /// Whether the device whose sysfs directory is `dir` is among them.
    fn has(&self, dir: &Path) -> bool {
        self.layers.iter().any(|layer| layer.sysfs == dir)
    }

    /// Whether a loop device among them reads the file at `path`.
    fn reads_file(&self, path: &Path) -> bool {
        self.layers.iter().any(|layer| {
            layer
                .loop_device
                .as_ref()
                .is_some_and(|bound| bound.backing.path() == path)
        })
    }
}

/// The sysfs directory of the disk `layer` lies on, when it is a partition.
fn disk_of(layer: &Layer) -> Option<&Path> {
    layer
        .partition
        .as_ref()
        .filter(|partition| partition.disk.is_some())
        .and(layer.sysfs.parent())
}

/// The block devices whose raw bytes hold those of the device whose sysfs
/// directory is `top`: the devices below it ([`blockdev::walk()`], through
/// `slaves/` and below a loop device to the device of the filesystem that
/// holds its file), and the disk each partition among them lies on, with the
/// devices below that disk in turn. A disk reached only that way holds them in
/// that partition alone. Some may be missing, which the gap says: a loop
/// device among them reads a file no block device sysfs shows holds, or more
/// than [`MAX_HOLDING_DEVICES`] devices lie below `top`.
fn devices_holding<F: Filesystem>(fs: &F, top: &Path) -> Holding {
    let mut holding = Holding::default();
    // Each device to walk down from, and whether it is the disk of a
    // partition among them, which its walk reads first.
    let mut pending = vec![(top.to_path_buf(), false)];
    while let Some((dir, disk)) = pending.pop() {
        if holding.has(&dir) {
            continue;
        }
        let limit = MAX_HOLDING_DEVICES.saturating_sub(holding.layers.len());
        let walk = blockdev::walk(fs, &dir, LoopFollow::BackingFiles, limit);
        if !walk.unplaced_loops.is_empty() {
            holding.gap.get_or_insert(ECRYPTFS_UNPLACED);
        }
        if walk.cut_short {
            holding.gap.get_or_insert(ECRYPTFS_TOO_MANY);
        }
        for (at, layer) in walk.layers.into_iter().enumerate() {
            let only_disk = disk && at == 0;
            if holding.has(&layer.sysfs) {
                // Reached below a device that holds it, it holds the
                // filesystem in full.
                if !only_disk {
                    holding.disks.retain(|known| *known != layer.sysfs);
                }
                continue;
            }
            if only_disk {
                holding.disks.push(layer.sysfs.clone());
            }
            pending.extend(disk_of(&layer).map(|disk| (disk.to_path_buf(), true)));
            holding.layers.push(layer);
        }
    }
    holding
}

/// What the walk down from a device named for a scan found ([`reaches`]).
#[derive(Debug, Default)]
struct Reach {
    /// Whether the device holds what a [`Holding`] holds.
    holds: bool,
    /// Why devices it is built on may be missing from the walk:
    /// [`ECRYPTFS_UNTRACED`] or [`ECRYPTFS_TOO_MANY`].
    gap: Option<&'static str>,
}

/// Whether the block device whose sysfs directory is `dir` holds what
/// `holding` holds: it is one of those devices, or is built on one. The walk
/// goes down from it through `slaves/` (a mapping, an md array), from a loop
/// device to the block device it is bound to, and from a partition to its
/// disk, as a loop device over a whole disk shows that disk's partitions as
/// its own. A loop device that reads the file a loop device of `holding`
/// reads holds it too, and so does a partition of a disk of `holding`, unless
/// that disk holds it only in another partition. A loop device bound to a
/// path that leads to no regular file here, and more than
/// [`MAX_HOLDING_DEVICES`] devices below `dir`, leave the walk unable to tell.
fn reaches<F: Filesystem>(fs: &F, dir: &Path, holding: &Holding) -> Reach {
    let mut reach = Reach::default();
    let mut read: Vec<PathBuf> = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        if read.contains(&next) {
            continue;
        }
        let limit = MAX_HOLDING_DEVICES.saturating_sub(read.len());
        let walk = blockdev::walk(fs, &next, LoopFollow::BlockDevices, limit);
        if walk.cut_short {
            reach.gap.get_or_insert(ECRYPTFS_TOO_MANY);
        }
        if !walk.unplaced_loops.is_empty() {
            reach.gap.get_or_insert(ECRYPTFS_UNTRACED);
        }
        for layer in walk.layers {
            if read.contains(&layer.sysfs) {
                continue;
            }
            if holding.has(&layer.sysfs) {
                reach.holds = true;
                return reach;
            }
            if let Some(LoopBacking::File(file)) =
                layer.loop_device.as_ref().map(|bound| &bound.backing)
            {
                if holding.reads_file(file) {
                    reach.holds = true;
                    return reach;
                }
                if !fs.is_regular_file(file).unwrap_or(false) {
                    reach.gap.get_or_insert(ECRYPTFS_UNTRACED);
                }
            }
            if let Some(disk) = disk_of(&layer) {
                if !holding.has(disk) {
                    pending.push(disk.to_path_buf());
                } else if !holding.disks.iter().any(|known| known == disk) {
                    reach.holds = true;
                    return reach;
                }
            }
            read.push(layer.sysfs);
        }
    }
    reach
}
