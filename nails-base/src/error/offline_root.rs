// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Why an offline scan refuses its root, in the words the operator reads
//! ([`super::NailsError::RefusedOfflineRoot`]).

use std::fmt;

use crate::next_step::{NextStep, sudo_line};

/// The most subvolume names a message lists; the rest are counted.
const NAMES_SHOWN: usize = 8;

/// Why an offline scan refused its root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfflineRootProblem {
    /// Nothing is at the path, or a folder on the way to it is a file.
    Missing,
    /// The path is a file or some other thing that is not a folder.
    NotAFolder,
    /// The folder holds nothing.
    Empty,
    /// The folder holds no `etc` folder, which the root of every decoy system
    /// holds: a filesystem with no system on it (a fresh one holds only
    /// `lost+found`), a separate `/home`, or the top level of a btrfs
    /// filesystem, whose system lies in one of its subvolumes.
    NoEtcFolder {
        /// The btrfs subvolumes the folder holds, by name and sorted.
        subvolumes: Vec<String>,
    },
}

impl fmt::Display for OfflineRootProblem {
    /// What is wrong with the root, as the rest of a sentence that starts
    /// with it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OfflineRootProblem::Missing => {
                f.write_str("does not exist, so there is nothing to scan")
            }
            OfflineRootProblem::NotAFolder => {
                f.write_str("is not a folder, so there is nothing to scan")
            }
            OfflineRootProblem::Empty => f.write_str("is empty, so there is nothing to scan"),
            OfflineRootProblem::NoEtcFolder { subvolumes } => {
                match subvolumes.as_slice() {
                    [] => f.write_str("holds no etc folder")?,
                    [one] => write!(f, "holds the btrfs subvolume {one} but no etc folder")?,
                    many => write!(
                        f,
                        "holds the btrfs subvolumes {} but no etc folder",
                        listed(many)
                    )?,
                }
                f.write_str(", so it is not the root of a decoy system")
            }
        }
    }
}

impl OfflineRootProblem {
    /// What to do about a root refused for this problem: mount the decoy's
    /// root filesystem so that nothing can write to it, with what its fstab
    /// mounts below, and scan that. A plain read-only mount is not enough:
    /// ext4 replays its journal and cleans up orphans on one, btrfs replays
    /// its tree log, XFS and f2fs recover their logs. In a hidden session the
    /// filesystem is mounted already, so a second mount replays nothing, but
    /// a read-only one is refused there as busy. On btrfs the system is a
    /// subvolume, named at the mount.
    pub fn hint(&self) -> String {
        let scan = sudo_line(NextStep::VerifyOffline);
        let mut hint = format!(
            "Mount the decoy's root filesystem on a folder so that nothing can write to it, and \
             what its /etc/fstab mounts on the folders below it, then run `{scan}`.\n\
             In a hidden session, where the decoy root is mounted already, mount its device again \
             and make that mount read-only: `sudo mount <device> <mount> && sudo mount -o \
             remount,bind,ro <mount>`.\n\
             Elsewhere make the device read-only first (`sudo blockdev --setro <device>`, and \
             `--setrw` after the scan), then mount it with `-o ro,noload` for ext4, \
             `-o ro,rescue=nologreplay` for btrfs or `-o ro,norecovery` for XFS and f2fs: a plain \
             `-o ro` can replay a journal onto the disk."
        );
        if let OfflineRootProblem::NoEtcFolder { .. } = self {
            hint.push_str(
                "\nOn btrfs the system is a subvolume: add `subvol=@` (Fedora: `subvol=root`) to \
                 its mount, and mount each subvolume its /etc/fstab mounts, such as @home, on its \
                 folder.",
            );
        }
        hint
    }
}

/// `names` as a sentence lists them (`a and b`, `a, b and c`), those past
/// [`NAMES_SHOWN`] counted at the end.
fn listed(names: &[String]) -> String {
    let mut shown: Vec<String> = names.iter().take(NAMES_SHOWN).cloned().collect();
    if names.len() > NAMES_SHOWN {
        shown.push(format!("{} more", names.len() - NAMES_SHOWN));
    }
    match shown.split_last() {
        Some((last, [])) => last.clone(),
        Some((last, rest)) => format!("{} and {last}", rest.join(", ")),
        None => String::new(),
    }
}

#[cfg(test)]
#[path = "offline_root_tests.rs"]
mod tests;
