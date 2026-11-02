// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The offline root itself: a root with nothing to scan is refused.

use super::*;
use crate::NailsError;
use nails_base::error::OfflineRootProblem;
use std::io::ErrorKind;

/// The inode of the root folder of every btrfs subvolume
/// (`BTRFS_FIRST_FREE_OBJECTID`). A subvolume also reports a device of its
/// own, so a folder with both is a subvolume, or a btrfs filesystem mounted
/// there.
const BTRFS_SUBVOLUME_INODE: u64 = 256;

impl<F: Filesystem> Verifier<F> {
    /// Refuse an offline `root` that holds nothing to scan, before any check
    /// reads below it.
    ///
    /// Every check of an offline scan looks for a path of the decoy system
    /// under the root, so a root that does not exist, is not a folder or holds
    /// no `etc` folder finds none of them, and its clean verdict would be read
    /// as the image's. The root of every decoy system holds `etc`, and a
    /// folder without one is something else: an empty mount point, the image
    /// never mounted on it, a fresh filesystem that holds only `lost+found`,
    /// or the top level of a btrfs filesystem mounted whole, whose system lies
    /// in a subvolume, which the refusal then names. Whether a filesystem is
    /// mounted at the root is not asked: a copy of the decoy's files, or the
    /// folder of the subvolume that holds the system, is scanned as a mounted
    /// image is.
    ///
    /// The root may be the decoy's own disk, so the check opens nothing but
    /// the root folder, and that only to list a root without `etc`, with
    /// `O_NOATIME` ([`Filesystem::list_directory`]) like every other read of
    /// an offline scan. Every other path is looked at with `lstat` and `stat`,
    /// and a link inside the root is never followed. Nothing is written, and
    /// the access times of the folder the root names and of what it holds
    /// stay as they were wherever the kernel grants `O_NOATIME`, as it always
    /// does to root. A link on the way to that folder is followed, as by every
    /// lookup, which moves the link's own access time. A lookup or a listing
    /// that fails for any other reason than a missing path is an error, so the
    /// scan does not run then either.
    pub(super) fn refuse_a_root_with_nothing_to_scan(&self, root: &Path) -> Result<()> {
        let problem = match self.filesystem.inode(root) {
            Ok(None) => OfflineRootProblem::Missing,
            // A file on the way to the root: nothing can be at the path.
            Err(error) if error.io_kind() == Some(ErrorKind::NotADirectory) => {
                OfflineRootProblem::Missing
            }
            Err(error) => return Err(error),
            Ok(Some(_)) if !self.filesystem.is_directory(root)? => OfflineRootProblem::NotAFolder,
            Ok(Some(_)) if self.holds_an_etc_folder(root)? => return Ok(()),
            Ok(Some(_)) => {
                let entries = self.filesystem.list_directory(root)?;
                if entries.is_empty() {
                    OfflineRootProblem::Empty
                } else {
                    OfflineRootProblem::NoEtcFolder {
                        subvolumes: self.btrfs_subvolumes(root, &entries),
                    }
                }
            }
        };
        Err(NailsError::RefusedOfflineRoot {
            root: root.to_path_buf(),
            problem,
        })
    }

    /// Whether `root` holds a folder named `etc`, as the root of every decoy
    /// system does. A link there is not followed, and does not count.
    fn holds_an_etc_folder(&self, root: &Path) -> Result<bool> {
        let etc = root.join("etc");
        Ok(!self.filesystem.is_symlink(&etc)? && self.filesystem.is_directory(&etc)?)
    }

    /// The names of the btrfs subvolumes among `entries`, the listing of
    /// `root`, sorted. A link is not followed, and an entry that cannot be
    /// looked at is left out: the names only help the refusal say where the
    /// system is.
    fn btrfs_subvolumes(&self, root: &Path, entries: &[PathBuf]) -> Vec<String> {
        let Ok(device) = self.filesystem.device_id(root) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .iter()
            .filter(|entry| {
                matches!(self.filesystem.is_symlink(entry), Ok(false))
                    && matches!(self.filesystem.is_directory(entry), Ok(true))
                    && matches!(
                        self.filesystem.inode(entry),
                        Ok(Some(BTRFS_SUBVOLUME_INODE))
                    )
                    && self
                        .filesystem
                        .device_id(entry)
                        .is_ok_and(|own| own != device)
            })
            .filter_map(|entry| entry.file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}
