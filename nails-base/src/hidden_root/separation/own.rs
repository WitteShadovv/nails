// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The filesystem a root that `--allow-decoy-storage` accepted lies on,
//! where the root is a folder or a btrfs subvolume of a filesystem the decoy
//! itself mounts at `/` or at a system folder ([`own_filesystem`]).
//!
//! The decoy's own configuration names that filesystem's devices for its own
//! mounts, as NixOS's `hardware-configuration.nix` does for `/` and `/home`.
//! What the judge decided gives the devices by kernel name and device number,
//! so a reader that reads sysfs again lets be only the names of a device it
//! finds with the same name and the same number. It gives the root's own
//! place as well, its folders and its name and id inside the filesystem,
//! which no line of the decoy's needs.

use super::judge::hidden_stack;
use super::lines::mount_option;
use super::{Judgement, Scene, Sharing, Verdict};
use crate::filesystem::mountinfo::MountEntry;
use std::path::{Path, PathBuf};

/// A device the accepted root's filesystem lies on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnDevice {
    /// Its kernel name (`sda2`, `dm-0`).
    pub name: String,
    /// Its `major:minor`, as sysfs gives it.
    pub dev: String,
}

/// The filesystem that a root `--allow-decoy-storage` accepted is a folder
/// or a subvolume of, while the decoy itself mounts another part of it at `/`
/// or at a system folder (see [`own_filesystem`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnFilesystem {
    /// What of that filesystem the root shows: a folder bound there, or a
    /// btrfs subvolume.
    pub how: Sharing,
    /// Where the decoy mounts another part of it ([`Judgement::own_place`]).
    pub at: PathBuf,
    /// The hidden root's mount point, as the mount table shows it.
    pub root: PathBuf,
    /// The devices it lies on: the device the root's mount is on and every
    /// device below it, as the judge walked them, each with its device
    /// number. A device whose number the judge did not read is left out.
    pub devices: Vec<OwnDevice>,
    /// The root's own folder, as each other mount of the filesystem that
    /// shows it or a folder above it names it (`/srv/x` where `/` shows the
    /// filesystem's top and the root is a bind of its folder `srv/x`), and
    /// the mount point of each other mount that shows a folder inside it.
    /// Never `/`.
    pub folders: Vec<PathBuf>,
    /// The path of the root's folder or subvolume inside the filesystem,
    /// from its top, as the mount table shows it (`/@vault`, `/home/alice/vault`).
    /// Never the top itself.
    pub inside: PathBuf,
    /// The filesystem is btrfs.
    pub btrfs: bool,
    /// For a btrfs subvolume, its id, as `subvolid=` names it.
    pub subvolid: Option<u64>,
}

impl OwnFilesystem {
    /// The last part of [`Self::inside`]: the name of the root's folder or
    /// subvolume (`@vault`, `vault`).
    pub fn name(&self) -> String {
        self.inside
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

/// The filesystem `hidden` (the visible mount at the hidden root) lies on,
/// where the judge's answer `judgement` places the root on a filesystem the
/// decoy uses as a folder or a subvolume of it
/// ([`Verdict::OnDecoyFilesystem`] with [`Sharing::Bind`] or
/// [`Sharing::Subvolume`]) and the decoy itself mounts another part of that
/// filesystem at `/` or at a system folder ([`Judgement::own_place`]): the
/// case `--allow-decoy-storage` accepts and the decoy's own lines for that
/// filesystem name its devices. `None` otherwise: for a root that is the
/// whole filesystem, for any other verdict, and where no device of it is
/// known by its number or a subvolume's id is not a number in the mount
/// table.
pub fn own_filesystem(
    scene: &Scene<'_>,
    hidden: &MountEntry,
    judgement: &Judgement,
) -> Option<OwnFilesystem> {
    let Verdict::OnDecoyFilesystem { how, .. } = judgement.verdict else {
        return None;
    };
    if !matches!(how, Sharing::Bind | Sharing::Subvolume) {
        return None;
    }
    let at = judgement.own_place.clone()?;
    let (_, stack) = hidden_stack(scene.devices, hidden);
    let devices: Vec<OwnDevice> = stack
        .iter()
        .filter_map(|name| {
            let dev = scene
                .devices
                .by_dev
                .iter()
                .find_map(|(dev, named)| (named == name).then(|| dev.clone()))?;
            Some(OwnDevice {
                name: name.clone(),
                dev,
            })
        })
        .collect();
    if devices.is_empty() {
        return None;
    }
    // The root's place inside the filesystem: never its top, which a root
    // that is the whole filesystem shows.
    let inside = hidden.root.clone();
    inside.file_name()?;
    let btrfs = hidden.fstype == "btrfs";
    // A subvolume whose id the mount table does not give as a number could
    // be named by it unseen: nothing is then the decoy's own.
    let subvolid = if btrfs && how == Sharing::Subvolume {
        Some(mount_option(hidden, "subvolid")?.parse().ok()?)
    } else {
        None
    };
    Some(OwnFilesystem {
        how,
        at,
        root: hidden.mount_point.clone(),
        devices,
        folders: folders(scene.mounts, hidden),
        inside,
        btrfs,
        subvolid,
    })
}

/// The root's folder as the other mounts of its filesystem in `mounts` name
/// it (see [`OwnFilesystem::folders`]). A mount at or below the root's mount
/// point is the root's own, and names it by that path already.
fn folders(mounts: &[MountEntry], hidden: &MountEntry) -> Vec<PathBuf> {
    let mut folders: Vec<PathBuf> = Vec::new();
    for mount in mounts {
        if mount.dev != hidden.dev || mount.mount_point.starts_with(&hidden.mount_point) {
            continue;
        }
        let folder = if let Ok(rest) = hidden.root.strip_prefix(&mount.root) {
            mount.mount_point.join(rest)
        } else if mount.root.starts_with(&hidden.root) {
            mount.mount_point.clone()
        } else {
            continue;
        };
        if folder != Path::new("/") && !folders.contains(&folder) {
            folders.push(folder);
        }
    }
    folders
}
