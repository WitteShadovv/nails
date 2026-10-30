// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where an eCryptfs mount keeps its encrypted files, for a scan.
//!
//! An eCryptfs mount stores the files under it encrypted in a folder of the
//! filesystem below, so a raw plaintext scan of a device that holds that folder
//! cannot prove the canary absent. The mount table shows the mount the folder
//! lies on ([`lowers`]), and sysfs the block devices that hold that mount's
//! filesystem, which [`blind_spot`] checks a device named for a scan against.

use crate::Filesystem;
use crate::filesystem::MountEntry;
use nails_base::blockdev::{self, Layer, LoopFollow};
use std::path::{Path, PathBuf};

/// The type of an eCryptfs mount.
const ECRYPTFS: &str = "ecryptfs";

/// The mount whose filesystem holds the folder of the eCryptfs mount at
/// `index` in `mounts`: the one the folder lay on when it was mounted
/// ([`folder_mount`]), which a mount made over the folder's path since does
/// not change. A folder that lay in the view of another eCryptfs mount is
/// stored, encrypted again, in that mount's folder, so it is held where that
/// folder is. `None` when the table cannot place a folder on the way.
fn holding_mount(mounts: &[MountEntry], mut index: usize) -> Option<&MountEntry> {
    // Each round moves on to the eCryptfs mount the last folder lay in, so a
    // table whose eCryptfs mounts lie in each other's views ends unplaced.
    for _ in 0..mounts.len() {
        index = folder_mount(mounts, index)?;
        if mounts[index].fstype != ECRYPTFS {
            return Some(&mounts[index]);
        }
    }
    None
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

/// The index of the mount the folder of the eCryptfs mount at `index` in
/// `mounts` lay on when it was mounted.
///
/// The mount point's way down then ran through the mount it was made on (its
/// parent) and that mount's parents, which no later mount changes, and the
/// folder's path took the same way as far as the two paths agree. Below that,
/// the folder's path reached only mounts made before the eCryptfs mount, which
/// the table lists before it (mountinfo lists mounts in the order they were
/// made), so a filesystem mounted over the folder's path later is passed by.
/// `None` for a relative path, a parent the table does not list or lists
/// twice, a parent chain that runs in a circle, and two mounts the way down
/// could take at one place.
fn folder_mount(mounts: &[MountEntry], index: usize) -> Option<usize> {
    let entry = &mounts[index];
    let folder = entry.source.as_path();
    if !folder.is_absolute() {
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
    for component in folder.components().skip(shared) {
        point.push(component);
        at = top_made_before(mounts, index, at, &point)?;
    }
    Some(at)
}

/// The index of the mount on top at `point` of those stacked there on the
/// mount at `at`, counting only the mounts listed before the one at `index`
/// in `mounts`; `at` itself when none is. `None` when two of them sit on one
/// mount there, or they run in a circle.
fn top_made_before(
    mounts: &[MountEntry],
    index: usize,
    mut at: usize,
    point: &Path,
) -> Option<usize> {
    let made_before = &mounts[..index];
    // Each step up goes to another of them unless they run in a circle, so
    // one more round than there are of them reaches the top.
    for _ in 0..=made_before.len() {
        let below = mounts[at].mount_id;
        let above = only(made_before, |mount| {
            mount.parent_id == below && mount.mount_point == point && mount.mount_id != below
        })?;
        match above {
            Some(above) => at = above,
            None => return Some(at),
        }
    }
    None
}

/// Where the eCryptfs mounts of `mounts` keep their encrypted files: the
/// mounts whose filesystems their folders lie on ([`holding_mount`]), and the
/// eCryptfs mounts whose folder the scan cannot place on a mount the table
/// shows.
pub(super) fn lowers(mounts: &[MountEntry]) -> (Vec<&MountEntry>, Vec<&MountEntry>) {
    let mut lowers = Vec::new();
    let mut unplaced = Vec::new();
    for (index, entry) in mounts.iter().enumerate() {
        if entry.fstype != ECRYPTFS {
            continue;
        }
        match holding_mount(mounts, index) {
            Some(lower) => lowers.push(lower),
            None => unplaced.push(entry),
        }
    }
    (lowers, unplaced)
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

/// Why a device named for a scan is not checked when the devices below the
/// filesystem an eCryptfs folder lies on are more than the scan follows.
const ECRYPTFS_TOO_MANY: &str = "an eCryptfs mount (an encrypted home or Private folder) stores \
     the files under it encrypted, and the scan cannot tell whether this device holds them: more \
     devices lie below the filesystem their folder lies on than the scan follows, so this raw \
     plaintext scan cannot prove the canary absent";

/// The most devices the scan reads below the filesystem an eCryptfs folder
/// lies on. Real stacks are a few devices deep, and a wide array adds two (a
/// member partition and its disk) per drive, so only a pathological sysfs
/// reaches it.
pub(super) const MAX_HOLDING_DEVICES: usize = 256;

/// Why a clean scan of `device` cannot rule out the eCryptfs mounts whose
/// folders lie on the filesystems of `lowers`, or that the scan cannot place
/// on a mount the table shows (`unplaced`): it holds one of those folders,
/// read from sysfs through `fs`, or the scan cannot tell whether it does.
/// `None` when there is no eCryptfs mount, or each one's folder lies on other
/// devices.
///
/// A device holds a folder when it is the block device of the filesystem the
/// folder lies on, or lies below that device: a whole disk with it in a
/// partition, the partition below a dm-crypt or LVM mapping, a member of an md
/// array, the file a loop device reads (named as a regular file) or the device
/// of the filesystem that holds that file. A folder on a filesystem with no
/// block device of its own (a tmpfs, an overlay, a network share), in an
/// image file on one, or on no mount the scan can place it on, a path sysfs
/// lists no block device for that is no regular file (a node outside `/dev`,
/// a system without sysfs), and more devices below the folder's filesystem
/// than [`MAX_HOLDING_DEVICES`] leave the scan unable to tell, unless the
/// devices it did read hold `device`.
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
        let holds = holding.layers.iter().any(|layer| match &named {
            Some(dir) => layer.sysfs == *dir,
            None => layer
                .loop_device
                .as_ref()
                .is_some_and(|bound| bound.backing.path() == device),
        });
        if holds {
            return Some(super::ScanBlindSpot::StackedEncryption.reason().to_string());
        }
        if let Some(gap) = holding.gap {
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
    /// Why devices that hold the filesystem may be missing from `layers`:
    /// [`ECRYPTFS_UNPLACED`] or [`ECRYPTFS_TOO_MANY`].
    gap: Option<&'static str>,
}

/// The block devices whose raw bytes hold those of the device whose sysfs
/// directory is `top`: the devices below it ([`blockdev::walk()`], through
/// `slaves/` and below a loop device to the device of the filesystem that
/// holds its file), and the disk each partition among them lies on, with the
/// devices below that disk in turn. Some may be missing, which the gap says:
/// a loop device among them reads a file no block device sysfs shows holds,
/// or more than [`MAX_HOLDING_DEVICES`] devices lie below `top`.
fn devices_holding<F: Filesystem>(fs: &F, top: &Path) -> Holding {
    let mut holding = Holding::default();
    let mut pending = vec![top.to_path_buf()];
    while let Some(dir) = pending.pop() {
        if holding.layers.iter().any(|known| known.sysfs == dir) {
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
        for layer in walk.layers {
            if holding
                .layers
                .iter()
                .any(|known| known.sysfs == layer.sysfs)
            {
                continue;
            }
            let disk = layer
                .partition
                .as_ref()
                .filter(|partition| partition.disk.is_some())
                .and(layer.sysfs.parent());
            pending.extend(disk.map(Path::to_path_buf));
            holding.layers.push(layer);
        }
    }
    holding
}
