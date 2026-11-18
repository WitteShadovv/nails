// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The hidden root's place in a filesystem the decoy uses, where the root is
//! a folder or a btrfs subvolume of it ([`root_place`]): the folders other
//! mounts of that filesystem show it at, its path inside the filesystem and,
//! for a subvolume, its id.

use super::lines::mount_option;
use super::{Judgement, Scene, Sharing, Verdict};
use crate::filesystem::mountinfo::MountEntry;
use std::path::{Path, PathBuf};

/// The hidden root's place in a filesystem the decoy uses, which it is a
/// folder or a subvolume of (see [`root_place`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootPlace {
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
    /// For a btrfs subvolume, its id, as `subvolid=` names it, where the
    /// mount table gives it as a number.
    pub subvolid: Option<u64>,
}

impl RootPlace {
    /// The last part of [`Self::inside`]: the name of the root's folder or
    /// subvolume (`@vault`, `vault`).
    pub fn name(&self) -> String {
        self.inside
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

/// The place of `hidden` (the visible mount at the hidden root) in the
/// filesystem it lies on, where the judge's answer `judgement` places the
/// root on a filesystem the decoy uses as a folder or a subvolume of it
/// ([`Verdict::OnDecoyFilesystem`] with [`Sharing::Bind`] or
/// [`Sharing::Subvolume`]), with `--allow-decoy-storage` or without it.
/// `None` otherwise: for a root that is the whole filesystem and for any
/// other verdict.
pub fn root_place(
    scene: &Scene<'_>,
    hidden: &MountEntry,
    judgement: &Judgement,
) -> Option<RootPlace> {
    let Verdict::OnDecoyFilesystem { how, .. } = judgement.verdict else {
        return None;
    };
    if !matches!(how, Sharing::Bind | Sharing::Subvolume) {
        return None;
    }
    // The root's place inside the filesystem: never its top, which a root
    // that is the whole filesystem shows.
    let inside = hidden.root.clone();
    inside.file_name()?;
    let btrfs = hidden.fstype == "btrfs";
    let subvolid = (btrfs && how == Sharing::Subvolume)
        .then(|| mount_option(hidden, "subvolid")?.parse().ok())
        .flatten();
    Some(RootPlace {
        folders: folders(scene.mounts, hidden),
        inside,
        btrfs,
        subvolid,
    })
}

/// The root's folder as the other mounts of its filesystem in `mounts` name
/// it (see [`RootPlace::folders`]). A mount at or below the root's mount
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
