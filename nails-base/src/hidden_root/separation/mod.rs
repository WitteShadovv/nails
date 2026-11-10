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
//! - every `/etc/fstab` entry, swap and `noauto` ones included, except a line
//!   of a RAM, kernel, host-share, network or overlay filesystem that is no
//!   bind line, whose first field names no storage of the decoy's (`_netdev`
//!   lets no line go); a bind line of any type (one with a `bind` or `rbind`
//!   option, `bind=x` too), or a swap or image file, or the file a FUSE line
//!   gives its program, is claimed through the mount that holds its path,
//!   read as written: no link in it is followed (see the `paths` module). A
//!   FUSE line names a device or a path by the source it gives its program,
//!   the part after the `#` of a `fuse` line's first field (see the `plain`
//!   module);
//! - every `/etc/crypttab` source and its `/dev/mapper/<name>`;
//! - the mounts at `/usr`, `/var`, `/home`, `/srv`, `/boot`, `/efi`,
//!   `/boot/efi`, `/nix` and `/opt` that are not at or under the hidden root.
//!
//! An fstab or crypttab entry that resolves into the hidden mount's own device
//! stack, or into another device of its btrfs filesystem and what lies below
//! that, or names one of their mappings, is an entry for the hidden drive,
//! reported as an [`EntryFinding`]; so is a crypttab entry with `tcrypt-hidden`
//! for a device on the hidden drive or one that cannot be found, an fstab bind
//! line whose source, as written, lies in the volume, at the root's folder or
//! inside it as the mount that holds the source shows it, which mounts the
//! volume or a folder of it, and a swap or image file line whose file lies
//! there, which the boot swaps on or mounts. Such an entry is an enabler
//! stored on the decoy; the attach gate ignores the finding (writing to the
//! root stays safe) and the `backend-entries` check reports it. A bind line,
//! or a swap or image file line, whose path cannot be told ([`UntoldPath`])
//! may mount the volume too, and is reported as an entry where that cannot be
//! told ([`EntryKind::Untold`]), wherever its text places it: a path with a
//! symbolic link in any part, which is not followed, one that is not absolute
//! or is a device node, one that crosses the folder of a line, a `noauto` one
//! too, while that line's mount is not there now, one that cannot be looked
//! up, and one whose lookup would mount an automount point. So is every fstab
//! or crypttab line that is not plain ([`read_fstab`], [`read_crypttab`]):
//! NAILS reads only plain lines, and that is the only finding such a line
//! makes, while it claims what NAILS reads in it and makes no mount of the
//! decoy's own ([`decoys_own_mount`]).
//! A finding is no claim, except an fstab entry the
//! boot mounts or swaps on, one for another device of the root's btrfs
//! filesystem, which is the decoy's own storage too, and a line placed by its
//! path: every bind line, a `noauto` one too, claims the filesystem its source
//! lies on, and every swap or image file line the one that holds its file, as
//! their text places them, also where their path cannot be told. A
//! finding the decoy's own boot needs, an fstab entry that mounts another of
//! its filesystems or its swap, or the whole filesystem a root bound from a
//! folder of it or a subvolume of it lies on (the decoy's line for `/` below a
//! bind of a folder of `/`), or one that mounts the root's own filesystem at
//! `/` or at a system folder, whatever it mounts of it, or a crypttab entry
//! that opens a device below one of them or makes one the root's own filesystem
//! lies on while the decoy uses that filesystem (at `/`, at a system folder or
//! by a line its boot needs), is marked so: the hidden root then lies on the
//! decoy's own storage and has to move, since removing the entry would break
//! the decoy. An fstab line the boot mounts at `/` or at a system folder for
//! another part of the filesystem the root is a folder or a subvolume of, its
//! top or a subvolume above or beside the root's, whose mount is there (the
//! mount at its folder is of that filesystem and shows what the line names), is
//! marked as the decoy's own line for it ([`EntryFinding::system_folder`]),
//! which `backend-entries` lets be for a root that `--allow-decoy-storage`
//! accepted on that filesystem; one that mounts the volume itself, whose
//! subvolume cannot be told or whose mount is not there never is. So is a
//! crypttab line the boot opens that makes a device that filesystem lies on,
//! while the decoy mounts another part of it at `/`, by its mount there, or at
//! a system folder, by such an fstab line; a `noauto` one, one with
//! `tcrypt-hidden`, one for any other device and every line for a root that is
//! the whole filesystem never are.
//!
//! The [`Verdict`], first match wins: the inputs could not all be read, or
//! what a claimed filesystem keeps data on besides its device cannot be told;
//! the root's data reaches, wherever it goes, the decoy's own storage
//! included, something that cannot be followed to the disks that hold it: a
//! device that cannot be found, a disk whose kind cannot be read, a ZFS
//! volume, a disk of a driver the kernel does not name, a partition whose
//! disk is not found, a filesystem whose other devices cannot be told, or an
//! image file whose filesystem cannot be told (its loop record cannot be
//! read, no filesystem mounted here holds it, or that filesystem shows no
//! device and is not the decoy's); the root is on a claimed
//! filesystem (a bind, a subvolume, the filesystem itself); no block device
//! of the root can be found, so its storage cannot be followed (an overlay,
//! FUSE, a network filesystem); it shares a device with a claim the decoy's
//! boot uses; its data reaches an unencrypted image file on a claimed
//! filesystem; it reaches a disk that a program serves (a network or
//! userspace block device); it reaches an encrypted container file on a
//! claimed filesystem; it shares a device only with entries the decoy never
//! mounts at boot; else it is separate. The override lifts none of the
//! second verdict, even for a root on the decoy's own filesystem. A served
//! disk comes after every verdict no override lifts and before every one
//! that only warns, so accepting it hides none of the first and none of the
//! second hides it. A tmpfs or ramfs root is always separate. A partition of
//! a loop device lies in the loop device's file and is judged with it, and a
//! root on a partition of an md array, or of a disk that sysfs shows nothing
//! below, is judged with that disk, though a partition of the disk that the
//! decoy uses shares nothing with it. The filesystem that holds an image file
//! is the one on the device the loop driver recorded for the file
//! ([`FileHolder`]), not the one its path leads to today.
//!
//! A filesystem keeps data on the device it is mounted from, and some on
//! others too ([`DeviceMap::extra`]): an XFS log or realtime device, an ext3
//! or ext4 journal on a device of its own, the other devices of a bcachefs
//! filesystem. These belong to the root's stack, and to a claim on a mounted
//! filesystem. Where the root's data reaches is its stack, every other device
//! of a btrfs filesystem in it, and below an image file the devices of the
//! filesystem that holds the file, the decoy's own included, as far down as
//! these go.
//! An image file on a claimed filesystem counts where the data reaches it
//! before the decoy's own storage: below that, the image files are the
//! decoy's. A whole disk that sysfs shows nothing below is known by the
//! driver `/proc/devices` lists for its major number, or, as for a userspace
//! block device, by the name its driver gives it ([`Served`], [`Untraced`]);
//! one whose kind cannot be read is [`NodeKind::Unidentified`], and refused
//! only when the root's data reaches it.
//!
//! The inputs are the mount table, the parsed files, the paths the fstab
//! names as they read ([`NamedPaths`]), and a [`DeviceMap`] of the block
//! devices; [`judge`] reads no file. [`collect`] reads them through the
//! [`Filesystem`](crate::Filesystem) trait, and [`judge_storage`] does both
//! for the attach gate. [`claimed_devices`] lists the devices the claims
//! hold, for a check that weighs the hidden root's own stack against them.
//! [`decoys_own_mount`] tells whether the decoy makes a mount itself, at `/`
//! or by a line of its fstab, for the rule that leaves the decoy's own mounts
//! of an accepted root's filesystem out of its second mounts.

mod collect;
mod extra;
mod judge;
mod lines;
mod paths;
mod plain;
#[cfg(test)]
mod tests;

pub use collect::{Collected, collect, judge_storage};
pub use judge::{claimed_devices, judge, shown_fstype};
pub use lines::{decoys_own_mount, sharing};
pub use paths::{NamedPaths, UntoldPath};
pub use plain::{Unplain, UnplainLine, UnplainLines, read_crypttab, read_fstab};

use crate::crypttab::CrypttabEntry;
use crate::filesystem::mountinfo::MountEntry;
use crate::fstab::FstabEntry;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// How an encrypted container file on a claimed filesystem is judged: it only
/// warns, a deliberate default (`severity_with(Severity::Refuse)` is the
/// stricter setting). Filesystem journals and copy-on-write snapshots on that
/// filesystem can still keep old copies of the parts of the container that
/// changed.
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
/// Where the kernel lists every block device.
pub const SYS_CLASS_BLOCK: &str = "/sys/class/block";

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
        file: Option<LoopFile>,
    },
    /// A whole disk that a program serves: nothing in sysfs shows where the
    /// program keeps the data, which can be a file on the decoy's disk.
    Served(Served),
    /// A whole disk whose data lies on disks sysfs does not show.
    Untraced(Untraced),
    /// A whole disk with nothing below it in sysfs whose kind could not be
    /// read: this input (`/proc/devices`, or the disk's `dev`) could not be.
    Unidentified(PathBuf),
}

/// What serves a disk that a program serves, as its driver shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    /// A network block device (`nbd`, major 43): `qemu-nbd`, `nbd-client` or
    /// `nbdkit` serve it from a file or a disk, of this computer or another.
    Network,
    /// A userspace block device (`ublk`, named `ublkb<N>` by its driver,
    /// which takes its numbers from the shared range): a program on this
    /// computer serves it from wherever it keeps the data.
    Userspace,
}

impl Served {
    /// What it is, for the operator.
    fn what(self) -> &'static str {
        match self {
            Served::Network => "a network block device",
            Served::Userspace => "a userspace block device",
        }
    }
}

/// What a device is whose data lies on disks the gate does not follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Untraced {
    /// A ZFS volume (`zvol`, named `zd<N>`): its data lies in its pool, and
    /// nothing here reads which disks a pool is on.
    ZfsVolume,
    /// A disk whose major number `/proc/devices` names no driver for, or
    /// one on the range the kernel shares between drivers (`blkext`) that
    /// sits below no other device and is no userspace block device, as a
    /// zoned loop device (`zloop<N>`), which keeps its zones in files.
    UnnamedDriver,
    /// A device that cannot be found among those sysfs lists, though the
    /// root's data reaches it: one another device names below it, the device
    /// a loop device's record or a zram device names, or one a filesystem
    /// keeps data on besides the device it is mounted from.
    NotFound,
}

/// The regular file behind a loop device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopFile {
    /// The path the loop driver reports (`loop/backing_file`).
    pub path: PathBuf,
    /// The filesystem that holds it, found by device.
    pub holder: FileHolder,
}

/// Which filesystem holds a loop device's backing file.
///
/// It is found by the device the loop driver recorded for the file, never by
/// the path alone: a filesystem mounted over a folder on that path later
/// leads a lookup to another filesystem, which would make an image on the
/// decoy's disk look like one on that filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileHolder {
    /// The filesystem the mounts with this `major:minor` show.
    Mount(String),
    /// The loop driver's record could not be read (the device node, which
    /// most systems let only root read).
    Unreadable(PathBuf),
    /// No filesystem mounted here is on the recorded device, and the path no
    /// longer leads to it: the file lies under another mount, or on a
    /// filesystem unmounted or out of view.
    Unplaced,
}

/// One block device: what it is and the devices directly below it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// What the device is.
    pub kind: NodeKind,
    /// Kernel names of the devices directly below (`slaves/`, or a loop's
    /// backing block device). A partition does not list its disk: two
    /// partitions of one disk share no storage. The walk of a stack still
    /// goes on from a partition into its disk where that disk is a loop or
    /// device-mapper device, which keeps the partition's data elsewhere, and
    /// for the hidden root where it is an md array or a disk that sysfs
    /// shows nothing below (served, untraced or unidentified).
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

/// What a mounted filesystem keeps data on besides the device it is mounted
/// from (see [`DeviceMap::extra`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extra {
    /// These devices, by kernel name.
    Devices(Vec<String>),
    /// Which they are cannot be told: this input could not be read.
    Unreadable(PathBuf),
    /// It names a device that cannot be found among those sysfs lists.
    NotFound,
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
    /// What a mounted filesystem keeps data on besides the device it is
    /// mounted from, by the `major:minor` of its mounts: an XFS log or
    /// realtime device, an ext3 or ext4 journal on a device of its own, the
    /// other devices of a bcachefs filesystem. One that keeps none has no
    /// entry.
    pub extra: BTreeMap<String, Extra>,
}

impl DeviceMap {
    /// The devices the filesystem mounted as `mount` keeps data on besides
    /// the one it is mounted from, as far as they can be told.
    fn extra_devices(&self, mount: &MountEntry) -> &[String] {
        match self.extra.get(&mount.dev) {
            Some(Extra::Devices(names)) => names,
            _ => &[],
        }
    }

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

    /// `name` and every device below it, as a claim reaches them. Below a
    /// partition of a loop or device-mapper device lies that device: the
    /// partition's data is where the device keeps its own, in an image file
    /// or on the devices below it. A partition of an md array ends the walk,
    /// so a partition of the array that the decoy uses shares nothing with
    /// another one, as two partitions of one disk share nothing.
    fn stack(&self, name: &str) -> Vec<String> {
        self.walk(name, false)
    }

    /// As [`Self::stack`], and below a partition of a disk built on other
    /// devices (an md array) lie that disk and its devices too: everything
    /// that holds the partition's data and has to be opened to use it, and
    /// so does a disk that sysfs shows nothing below (a served, untraced or
    /// unidentified one). The hidden root is judged by this stack.
    fn full_stack(&self, name: &str) -> Vec<String> {
        self.walk(name, true)
    }

    /// `name` and every device below it, each once, into the arrays of
    /// partitions when `into_arrays`. The walk needs no bound: the map holds
    /// the devices sysfs lists, and each is gone into once.
    fn walk(&self, name: &str, into_arrays: bool) -> Vec<String> {
        let mut seen = BTreeSet::new();
        let mut walked = Vec::new();
        let mut pending = vec![name.to_string()];
        while let Some(next) = pending.pop() {
            if !seen.insert(next.clone()) {
                continue;
            }
            if let Some(node) = self.nodes.get(&next) {
                pending.extend(node.below.iter().rev().cloned());
                pending.extend(self.disk_below(node, into_arrays).map(str::to_string));
            }
            walked.push(next);
        }
        walked
    }

    /// The devices right below `name`, as [`Self::walk`] goes on from it.
    fn below(&self, name: &str, into_arrays: bool) -> Vec<String> {
        let Some(node) = self.nodes.get(name) else {
            return Vec::new();
        };
        node.below
            .iter()
            .map(String::as_str)
            .chain(self.disk_below(node, into_arrays))
            .map(str::to_string)
            .collect()
    }

    /// The disk the partition `node` lies on, when that disk keeps its data
    /// elsewhere: a loop or device-mapper device, and with `arrays` a disk
    /// built on other devices, as an md array is, or one that sysfs shows
    /// nothing below.
    fn disk_below<'a>(&self, node: &'a Node, arrays: bool) -> Option<&'a str> {
        let NodeKind::Partition { disk } = &node.kind else {
            return None;
        };
        let on = self.nodes.get(disk)?;
        let elsewhere = match on.kind {
            NodeKind::Loop { .. } | NodeKind::Crypt { .. } | NodeKind::Mapper { .. } => true,
            NodeKind::Disk => arrays && !on.below.is_empty(),
            NodeKind::Served(_) | NodeKind::Untraced(_) | NodeKind::Unidentified(_) => arrays,
            NodeKind::Partition { .. } => false,
        };
        elsewhere.then_some(disk.as_str())
    }

    /// Whether `name` is a partition of a disk the map does not hold, so
    /// nothing shows whether that disk keeps its data elsewhere.
    fn on_an_unknown_disk(&self, name: &str) -> bool {
        self.nodes.get(name).is_some_and(|node| {
            matches!(&node.kind, NodeKind::Partition { disk } if !self.nodes.contains_key(disk))
        })
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
    /// The paths the fstab names, a bind line's source and a swap or image
    /// file, as they read, with no link in them followed.
    pub paths: &'a NamedPaths,
    /// The lines of the fstab that are not plain, by the index of their
    /// entry in [`Scene::fstab`]: NAILS does not read them as `libmount` and
    /// systemd do (see [`read_fstab`]).
    pub unplain: &'a UnplainLines,
    /// The lines of the crypttab that are not plain, by the index of their
    /// entry in [`Scene::crypttab`]: NAILS does not read them as systemd does
    /// (see [`read_crypttab`]).
    pub unplain_crypttab: &'a UnplainLines,
}

impl<'a> Scene<'a> {
    /// The path `spec` of an fstab line names, as [`Scene::paths`] holds it.
    /// One that was not looked up cannot be told.
    fn named_path(&self, spec: &str) -> Result<&'a Path, UntoldPath> {
        match self.paths.get(spec) {
            Some(Ok(path)) => Ok(path),
            Some(Err(why)) => Err(why.clone()),
            None => Err(UntoldPath::NotLookedUp),
        }
    }

    /// The lines of the fstab that are plain, in their order.
    fn plain_lines(&self) -> impl Iterator<Item = &'a FstabEntry> + '_ {
        self.fstab
            .iter()
            .enumerate()
            .filter(|(index, _)| !self.unplain.contains_key(index))
            .map(|(_, entry)| entry)
    }
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
        /// Whether a line of the decoy's fstab mounts that filesystem at
        /// `at`, one for that mount point that names its device. A mount at
        /// `/` or at a system folder that no line names, such as one made by
        /// hand, has none, and neither does a claim through a bind line.
        in_fstab: bool,
    },
    /// The root shares a device with the decoy's storage.
    InsideDecoyStorage {
        /// The topmost shared device, by kernel name (`dm-0`, `sda3`), for
        /// tests and logs. The operator is never shown it: the sentence names
        /// what else the device holds instead.
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
    /// The root is on a partition whose disk sysfs does not show, so nothing
    /// tells whether that disk keeps the partition's data elsewhere (a loop
    /// device over a file, say). Where its writes land cannot be told.
    DiskNotFound,
    /// The root is an image file that no filesystem mounted here holds (see
    /// [`FileHolder::Unplaced`]). Where its writes land cannot be told.
    UnplacedImageFile {
        /// The image file, as the loop driver names it.
        file: PathBuf,
    },
    /// The root's data reaches a disk that a program serves ([`Served`]),
    /// which can keep it in a file on the decoy's disk. Refused, unless the
    /// operator knows the program keeps it elsewhere
    /// ([`Allow::DecoyStorage`](crate::hidden_root::Allow::DecoyStorage)).
    ServedDevice {
        /// What serves the disk.
        kind: Served,
    },
    /// The root's data reaches a device whose data lies on disks the gate
    /// does not follow, or one it cannot find ([`Untraced`]). Where its writes
    /// land cannot be told.
    UntracedDevice {
        /// What the disk is.
        kind: Untraced,
    },
    /// A filesystem the decoy claims keeps data on a device that cannot be
    /// found besides the one it is mounted from, so what the decoy's storage
    /// holds, and whether the root shares it, cannot be told.
    ClaimedDeviceNotFound,
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
            Verdict::OnDecoyFilesystem { how, at, in_fstab } => match how {
                Sharing::Bind => format!("it is a bind mount of a folder of {}", at.display()),
                Sharing::Subvolume => {
                    format!(
                        "it is a subvolume of the btrfs filesystem at {}",
                        at.display()
                    )
                }
                Sharing::Filesystem if *in_fstab => format!(
                    "it is the filesystem this computer mounts at {} per {FSTAB}",
                    at.display()
                ),
                Sharing::Filesystem => format!(
                    "it is the filesystem this computer has mounted at {}",
                    at.display()
                ),
            },
            Verdict::InsideDecoyStorage { holds, .. } => match holds {
                Claimed::Swap(_) => {
                    "it is stored on a device this computer uses as swap".to_string()
                }
                Claimed::Mount(at) => {
                    format!(
                        "it is stored on a device that also holds the filesystem at {}",
                        at.display()
                    )
                }
                Claimed::Encrypted(_) => {
                    format!("it is stored on a device this computer unlocks through {CRYPTTAB}")
                }
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
                format!(
                    "it is on a filesystem of type {fstype}, which shows no disk it stores its data on"
                )
            }
            Verdict::DiskNotFound => {
                "it is on a partition whose disk the kernel does not show".to_string()
            }
            Verdict::UnplacedImageFile { file } => format!(
                "it is an image file ({}) that no filesystem mounted here holds",
                file.display()
            ),
            Verdict::ServedDevice { kind } => format!(
                "it is stored on {}, which a program can serve from a file on this computer's \
                 own disk",
                kind.what()
            ),
            Verdict::UntracedDevice {
                kind: Untraced::ZfsVolume,
            } => "it is stored on a ZFS volume, which shows no disk it stores its data on".into(),
            Verdict::UntracedDevice {
                kind: Untraced::UnnamedDriver,
            } => "it is stored on a device whose driver the kernel does not name".into(),
            Verdict::UntracedDevice {
                kind: Untraced::NotFound,
            } => "it is stored on a device that cannot be found".into(),
            Verdict::ClaimedDeviceNotFound => "it cannot be told apart from this computer's own \
                                               storage, which keeps data on a device that cannot \
                                               be found"
                .into(),
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
    /// Where the entry leads cannot be told, so it may mount the hidden
    /// volume: a bind line, or a swap or image file line, whose path cannot
    /// be told ([`UntoldPath`]), or a line that is not plain
    /// ([`EntryFinding::not_plain`]).
    Untold,
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
    /// Whether the decoy's own boot needs the entry: it mounts the decoy's
    /// root or another of its filesystems or its swap, or it opens a device
    /// below one of them. The hidden root then lies on the decoy's storage.
    pub boot_needs: bool,
    /// For an fstab line that the decoy's boot mounts at `/` or at a system
    /// folder ([`is_system_folder`]) for the filesystem the volume is a folder
    /// or a subvolume of, one that names a device of it and mounts another
    /// part of it than the volume (its top, or a subvolume above or beside
    /// the volume's), while its mount is there (the mount at that folder is of
    /// that filesystem and shows what the line names), that folder. For a
    /// crypttab line the boot opens (no
    /// `noauto`) that makes a device that filesystem lies on (its mapping is
    /// one of them, or one's name, or it opens a device below the one the
    /// filesystem is mounted from) and opens no hidden volume of a container
    /// (no `tcrypt-hidden`), while the decoy mounts another part of
    /// the filesystem at `/` (by its mount there) or at a system folder (by
    /// such an fstab line), the first such folder. Such a line is the
    /// decoy's own, and a root that `--allow-decoy-storage` accepted on that
    /// filesystem lies there anyway. `None` for a line that mounts the volume
    /// itself (a bind line among them), for one whose subvolume cannot be
    /// told or whose mount is not there, for every line of a volume that is
    /// the whole filesystem, and for any other crypttab line.
    pub system_folder: Option<PathBuf>,
    /// Whether the entry is an fstab line that is not plain (see
    /// [`read_fstab`]), an [`EntryKind::Untold`] one: NAILS reads only plain
    /// lines, so its line has to be written plainly before NAILS can tell
    /// what it mounts.
    pub not_plain: bool,
}

/// Whether the decoy mounts its own filesystems at `at`, with the hidden root
/// mounted at `hidden_root`: `/`, or one of the system folders that hold the
/// decoy's own filesystems wherever they are mounted from ([`SYSTEM_MOUNTS`]),
/// unless the hidden root is that folder or lies above it, as the judge counts
/// them.
pub fn is_system_folder(at: &Path, hidden_root: &Path) -> bool {
    at == Path::new("/")
        || (SYSTEM_MOUNTS.iter().any(|point| Path::new(point) == at)
            && !at.starts_with(hidden_root))
}

/// The judge's answer: the verdict and the entries for the hidden drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judgement {
    /// Where the hidden root lives.
    pub verdict: Verdict,
    /// The decoy's entries for the hidden drive; they never change the verdict.
    pub entries: Vec<EntryFinding>,
}
