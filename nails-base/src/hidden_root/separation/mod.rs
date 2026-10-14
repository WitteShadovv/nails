// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether the hidden root lives on storage the decoy uses.
//!
//! A volume of its own at the hidden root is not enough: a subvolume of the
//! decoy's btrfs, a bind of a folder of `/home`, a logical volume in the
//! decoy's encrypted volume group or an image file on its disk is a mount
//! point with a filesystem of its own, yet everything written there lands on
//! the decoy's disk, where an examination finds it. This module judges that,
//! as a pure function over what the decoy claims as its own storage:
//!
//! - the mount at `/`;
//! - every `/etc/fstab` entry, swap and `noauto` ones included, except RAM,
//!   kernel, host-share, network and overlay filesystems; a bind (or a swap
//!   file) is claimed through the mount that holds its source;
//! - every `/etc/crypttab` source and its `/dev/mapper/<name>`;
//! - the mounts at `/usr`, `/var`, `/home`, `/srv`, `/boot`, `/efi`,
//!   `/boot/efi`, `/nix` and `/opt` that are not at or under the hidden root.
//!
//! An fstab or crypttab entry that resolves into the hidden mount's own device
//! stack, names one of its mappings or carries `tcrypt-hidden` is an entry for
//! the hidden drive, reported as an [`EntryFinding`]. Such an entry is an
//! enabler stored on the decoy; the attach gate ignores the finding (writing to
//! the root stays safe) and the `backend-entries` check reports it. It is no
//! claim, except an fstab entry the boot mounts or swaps on: that device is the
//! decoy's own storage too.
//!
//! The [`Verdict`], first match wins: the inputs could not all be read; the
//! root is on a claimed filesystem (a bind, a subvolume, the filesystem
//! itself); no block device of the root can be found, so its storage cannot
//! be followed (an overlay, FUSE, a network filesystem); it shares a device
//! with a claim; it is an image file, or an encrypted container file, on a
//! claimed filesystem, or on one whose device cannot be found; else it is
//! separate. A tmpfs or ramfs root is always separate, and so is an overlay
//! whose upper layer lies on one.
//!
//! The inputs are the mount table, the parsed files and a [`DeviceMap`] of
//! the block devices; [`judge`] reads no file. [`collect`] reads them through
//! the [`Filesystem`](crate::Filesystem) trait, and [`judge_storage`] does
//! both for the attach gate.

mod collect;
mod judge;
#[cfg(test)]
mod tests;

pub use collect::{Collected, collect, judge_storage};
pub use judge::{judge, shown_fstype};

use crate::crypttab::CrypttabEntry;
use crate::filesystem::mountinfo::MountEntry;
use crate::fstab::FstabEntry;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// How an encrypted container file on a claimed filesystem is judged (the
/// owner's decision): it only warns. Filesystem journals and copy-on-write
/// snapshots on that filesystem can still keep old copies of the parts of the
/// container that changed.
pub const CONTAINER_VERDICT: Severity = Severity::Warn;

/// The mount points whose filesystems are the decoy's own wherever they are
/// mounted from.
const SYSTEM_MOUNTS: &[&str] = &[
    "/usr",
    "/var",
    "/home",
    "/srv",
    "/boot",
    "/efi",
    "/boot/efi",
    "/nix",
    "/opt",
];

/// The file the fstab entries come from.
pub const FSTAB: &str = "/etc/fstab";
/// The file the crypttab entries come from.
pub const CRYPTTAB: &str = "/etc/crypttab";

/// Upper bound on the devices visited below one device.
const MAX_WALK: usize = 32;

/// What a block device is, as far as the judge needs to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeKind {
    /// A whole disk.
    Disk,
    /// A partition of `disk`.
    Partition {
        /// The kernel name of the disk.
        disk: String,
    },
    /// An encrypting device-mapper mapping (cryptsetup or VeraCrypt).
    Crypt {
        /// The name under `/dev/mapper`.
        name: String,
    },
    /// Another device-mapper mapping (LVM, dm-integrity, …).
    Mapper {
        /// The name under `/dev/mapper`.
        name: String,
    },
    /// A loop device.
    Loop {
        /// The regular file it is bound to; `None` for a loop over a block
        /// device, which appears in `below` instead.
        file: Option<PathBuf>,
    },
}

/// One block device: what it is and the devices directly below it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// What the device is.
    pub kind: NodeKind,
    /// Kernel names of the devices directly below (`slaves/`, or a loop's
    /// backing block device). A partition does not list its disk: two
    /// partitions of one disk share no storage.
    pub below: Vec<String>,
}

impl Node {
    /// The device-mapper name, for a mapping.
    fn dm_name(&self) -> Option<&str> {
        match &self.kind {
            NodeKind::Crypt { name } | NodeKind::Mapper { name } => Some(name),
            _ => None,
        }
    }
}

/// The block devices the judge may meet, and the names that lead to them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceMap {
    /// Every device by kernel name.
    pub nodes: BTreeMap<String, Node>,
    /// Kernel names by `major:minor`, as the mount table and sysfs show them.
    pub by_dev: BTreeMap<String, String>,
    /// Kernel names by the spec or path a file or the mount table uses
    /// (`UUID=…`, `/dev/sda2`, `/dev/mapper/data`).
    pub by_spec: BTreeMap<String, String>,
    /// The devices of each btrfs filesystem, by kernel name.
    pub btrfs: Vec<BTreeSet<String>>,
}

impl DeviceMap {
    /// The device a mount sits on: by its `major:minor`, else by its source
    /// (btrfs reports an anonymous device).
    pub fn node_of_mount(&self, mount: &MountEntry) -> Option<&str> {
        self.by_dev
            .get(&mount.dev)
            .or_else(|| {
                self.by_spec
                    .get(&mount.source.to_string_lossy().into_owned())
            })
            .map(String::as_str)
    }

    /// The device a spec names.
    pub fn node_of_spec(&self, spec: &str) -> Option<&str> {
        self.by_spec.get(spec).map(String::as_str)
    }

    /// `name` and every device below it.
    fn stack(&self, name: &str) -> Vec<String> {
        let mut seen = Vec::new();
        let mut pending = vec![name.to_string()];
        while let Some(next) = pending.pop() {
            if seen.len() >= MAX_WALK || seen.contains(&next) {
                continue;
            }
            if let Some(node) = self.nodes.get(&next) {
                pending.extend(node.below.iter().rev().cloned());
            }
            seen.push(next);
        }
        seen
    }

    /// Whether `a` and `b` are members of one btrfs filesystem.
    fn same_btrfs(&self, a: &str, b: &str) -> bool {
        self.btrfs
            .iter()
            .any(|members| members.contains(a) && members.contains(b))
    }
}

/// Everything the judge reads.
#[derive(Debug, Clone, Copy)]
pub struct Scene<'a> {
    /// The mount table.
    pub mounts: &'a [MountEntry],
    /// The decoy's `/etc/fstab`.
    pub fstab: &'a [FstabEntry],
    /// The decoy's `/etc/crypttab`.
    pub crypttab: &'a [CrypttabEntry],
    /// The block devices.
    pub devices: &'a DeviceMap,
    /// Inputs that exist but could not be read (never taken as empty).
    pub unreadable: &'a [PathBuf],
}

/// How bad a verdict is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Nothing may be written to the root.
    Refuse,
    /// The root may be used; the operator is told why it is risky.
    Warn,
    /// The root is separate from the decoy's storage.
    Pass,
}

/// How a root on a claimed filesystem got there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sharing {
    /// A bind mount of a folder of that filesystem.
    Bind,
    /// A btrfs subvolume of that filesystem.
    Subvolume,
    /// The filesystem itself.
    Filesystem,
}

/// What a claim is, for the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claimed {
    /// The filesystem mounted (or, per fstab, to be mounted) at this path.
    Mount(PathBuf),
    /// A device or file the decoy uses as swap.
    Swap(String),
    /// The encrypted volume the decoy's crypttab opens under this name.
    Encrypted(String),
}

/// Where the hidden root lives, judged against the decoy's storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// An input could not be read, so the judge cannot tell.
    CouldNotJudge {
        /// The inputs that could not be read.
        unreadable: Vec<PathBuf>,
    },
    /// The root is on a filesystem the decoy uses.
    OnDecoyFilesystem {
        /// How.
        how: Sharing,
        /// Where the decoy mounts that filesystem.
        at: PathBuf,
    },
    /// The root shares a device with the decoy's storage.
    InsideDecoyStorage {
        /// The topmost shared device, by kernel name (`dm-0`, `sda3`). A
        /// mapping's own name can name the tool that opened it, so the
        /// operator is shown the kernel name.
        device: String,
        /// What of the decoy's storage also lies on it.
        holds: Claimed,
        /// Whether only entries the decoy never mounts at boot (`noauto`)
        /// share it: a warning, not a refusal.
        noauto_only: bool,
    },
    /// The root is an unencrypted image file on a claimed filesystem.
    ImageFileOnDecoy {
        /// The image file.
        file: PathBuf,
        /// Where the decoy mounts the filesystem holding it.
        at: PathBuf,
    },
    /// The root is an encrypted container file on a claimed filesystem.
    ContainerOnDecoy {
        /// The container file.
        file: PathBuf,
        /// Where the decoy mounts the filesystem holding it.
        at: PathBuf,
    },
    /// Nothing shows on which block device the root's filesystem (or the
    /// filesystem holding its image file) stores its data: an overlay, FUSE,
    /// a network filesystem. Where its writes land cannot be told.
    UntracedStorage {
        /// The type of that filesystem.
        fstype: String,
    },
    /// The root is separate from everything the decoy claims.
    Separate,
}

impl Verdict {
    /// How bad the verdict is, with [`CONTAINER_VERDICT`] for a container.
    pub fn severity(&self) -> Severity {
        self.severity_with(CONTAINER_VERDICT)
    }

    /// How bad the verdict is, with `container` for a container file.
    pub fn severity_with(&self, container: Severity) -> Severity {
        match self {
            Verdict::Separate => Severity::Pass,
            Verdict::ContainerOnDecoy { .. } => container,
            Verdict::InsideDecoyStorage {
                noauto_only: true, ..
            } => Severity::Warn,
            _ => Severity::Refuse,
        }
    }

    /// Why, as a phrase that completes "… is not a volume of its own:".
    pub fn reason(&self) -> String {
        match self {
            Verdict::CouldNotJudge { unreadable } => format!(
                "{} could not be read, so where it lives cannot be told",
                join(unreadable)
            ),
            Verdict::OnDecoyFilesystem { how, at } => match how {
                Sharing::Bind => format!("it is a bind mount of a folder of {}", at.display()),
                Sharing::Subvolume => {
                    format!(
                        "it is a subvolume of the btrfs filesystem at {}",
                        at.display()
                    )
                }
                Sharing::Filesystem => format!(
                    "it is the filesystem this computer mounts at {} per {FSTAB}",
                    at.display()
                ),
            },
            Verdict::InsideDecoyStorage { device, holds, .. } => match holds {
                Claimed::Swap(_) => {
                    format!("it is stored inside /dev/{device}, which this computer uses as swap")
                }
                Claimed::Mount(at) => {
                    format!(
                        "it is stored inside /dev/{device}, which also holds {}",
                        at.display()
                    )
                }
                Claimed::Encrypted(_) => format!(
                    "it is stored inside /dev/{device}, which this computer unlocks through \
                     {CRYPTTAB}"
                ),
            },
            Verdict::ImageFileOnDecoy { file, at } => format!(
                "it is an unencrypted image file ({}) on {}",
                file.display(),
                at.display()
            ),
            Verdict::ContainerOnDecoy { file, at } => format!(
                "it is an encrypted container file ({}) on {}; journals and copy-on-write \
                 snapshots (btrfs, snapper) of that filesystem can keep old copies of the \
                 parts of the container that changed",
                file.display(),
                at.display()
            ),
            Verdict::UntracedStorage { fstype } => {
                format!("it is on a {fstype} filesystem, which shows no disk it stores its data on")
            }
            Verdict::Separate => "it is separate from this computer's own storage".to_string(),
        }
    }
}

fn join(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// How serious an entry for the hidden drive is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// The entry opens or mounts the hidden volume itself.
    Blocking,
    /// The entry opens only another volume on the same drive.
    OuterWarning,
}

/// An fstab or crypttab entry of the decoy for the hidden drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryFinding {
    /// How serious it is.
    pub kind: EntryKind,
    /// The file it is in ([`FSTAB`] or [`CRYPTTAB`]).
    pub file: &'static str,
    /// The entry, as its first fields read.
    pub line: String,
    /// Why it is reported.
    pub why: String,
}

/// The judge's answer: the verdict and the entries for the hidden drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judgement {
    /// Where the hidden root lives.
    pub verdict: Verdict,
    /// The decoy's entries for the hidden drive; they never change the verdict.
    pub entries: Vec<EntryFinding>,
}
