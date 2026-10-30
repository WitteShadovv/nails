// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The stack of block devices under a filesystem, read from sysfs.
//!
//! A filesystem sits on a stack of block devices: a dm-crypt mapping on a
//! partition, an LVM volume on a LUKS mapping, a loop device over a file. This
//! module reads that stack from sysfs and the names in `/dev/disk`, through
//! the [`Filesystem`](crate::Filesystem) trait, so it runs unchanged against
//! `MockFilesystem` fixtures. It never reads a device-mapper table (a crypt
//! table carries the key), uses no ioctl and opens no device node.
//!
//! - [`stack`] walks down from one device: through `slaves/`, and below a
//!   loop device as far as [`LoopFollow`] allows.
//! - [`walk()`] does the same within a given number of devices, and says where
//!   it stopped short of the bottom.
//! - [`device_of_mount`] finds the device a mount sits on.
//! - [`resolve_spec`] finds the device an fstab or crypttab spec names.
//! - [`btrfs_members`] lists every device of a btrfs filesystem.
//! - [`classify_dm`] says what a device-mapper uuid and name describe.

mod spec;
mod walk;

#[cfg(test)]
mod tests;

pub use spec::{btrfs_members, resolve_spec};
pub use walk::{classify_dm, device_of_mount, stack, walk};

use std::path::{Path, PathBuf};

/// The most devices [`stack`] reads. Real stacks are two to four deep (a
/// filesystem on LVM on dm-crypt on a partition), so the bound is there to stop
/// a pathological sysfs, but a stack wider than it (an md array of more
/// members) is cut short too, which [`walk()`] reports.
pub const MAX_STACK_DEVICES: usize = 16;

/// Block devices by `major:minor`.
const SYS_DEV_BLOCK: &str = "/sys/dev/block";
/// Block devices (disks and partitions) by kernel name.
const SYS_CLASS_BLOCK: &str = "/sys/class/block";
/// Whole block devices by kernel name; device-mapper devices live here.
const SYS_BLOCK: &str = "/sys/block";
/// One directory per mounted btrfs filesystem, named by its fsid.
const SYS_FS_BTRFS: &str = "/sys/fs/btrfs";

/// One block device in a stack, as sysfs reports it. Every attribute is
/// optional: one that is missing or unreadable keeps its default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Layer {
    /// The sysfs directory the device was read from, symlinks resolved.
    pub sysfs: PathBuf,
    /// Kernel name (`dm-3`, `loop0`, `sdb1`).
    pub name: String,
    /// `major:minor`, from `dev`.
    pub dev: Option<String>,
    /// The device-mapper name and uuid, for a device-mapper device.
    pub dm: Option<DeviceMapper>,
    /// Whether the kernel holds the device read-only (`ro`).
    pub read_only: bool,
    /// The size in 512-byte sectors (`size`).
    pub size_sectors: Option<u64>,
    /// `queue/discard_max_bytes`; non-zero means discards reach the device.
    pub discard_max_bytes: u64,
    /// Kernel names of the devices below this one (`slaves/`), sorted.
    pub slaves: Vec<String>,
    /// Kernel names of the devices built on this one (`holders/`), sorted.
    pub holders: Vec<String>,
    /// Partition data, for a partition.
    pub partition: Option<Partition>,
    /// Loop data, for a loop device that is bound to a backing file.
    pub loop_device: Option<LoopDevice>,
}

/// A device-mapper device: its name, its uuid and what they describe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceMapper {
    /// `dm/name`, the name under `/dev/mapper`.
    pub name: String,
    /// `dm/uuid`; empty for a device created without one.
    pub uuid: String,
    /// What kind of mapping the uuid and name describe.
    pub kind: DmKind,
}

/// What a device-mapper uuid (and, without one, the name) says a mapping is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmKind {
    /// A cryptsetup mapping, `CRYPT-<TYPE>-…`, with its type: `LUKS1`,
    /// `LUKS2`, `PLAIN`, `TCRYPT`, `LOOPAES`, `BITLK`, `FVAULT2`, …
    Crypt(String),
    /// An inner layer of a cryptsetup cipher chain (`CRYPT-SUBDEV-…`): a
    /// TrueCrypt or VeraCrypt cascade opened by cryptsetup has one per extra
    /// cipher, below its `TCRYPT` mapping.
    CryptSubdev,
    /// dm-integrity (`CRYPT-INTEGRITY-…`), standalone or under LUKS2's
    /// authenticated encryption. It encrypts nothing.
    Integrity,
    /// dm-verity (`CRYPT-VERITY-…`). It encrypts nothing.
    Verity,
    /// A mapping the VeraCrypt application made with `dmsetup`: no uuid, and
    /// the name `veracrypt<N>`, or `veracrypt<N>_<k>` for an inner cipher of a
    /// cascade.
    VeraCrypt,
    /// An LVM logical volume (`LVM-…`).
    Lvm,
    /// Any other device-mapper device (multipath, a hand-made table, …).
    Other,
}

/// A partition's place in its table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Partition {
    /// The partition number (`partition`).
    pub number: u32,
    /// The first sector on the disk, in 512-byte sectors (`start`).
    pub start: Option<u64>,
    /// The kernel name of the disk the partition is on.
    pub disk: Option<String>,
    /// The partition's name in a GPT table (`PARTNAME=` in `uevent`).
    pub name: Option<String>,
    /// The partition's uuid (`PARTUUID=` in `uevent`).
    pub uuid: Option<String>,
}

/// A bound loop device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopDevice {
    /// What the loop device reads and writes (`loop/backing_file`).
    pub backing: LoopBacking,
    /// Where in the backing file the device starts, in bytes (`loop/offset`).
    pub offset: u64,
    /// The size limit in bytes; 0 for the whole file (`loop/sizelimit`).
    pub size_limit: u64,
    /// Whether the device detaches when its last user closes it
    /// (`loop/autoclear`).
    pub autoclear: bool,
}

/// What a loop device is bound to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopBacking {
    /// A regular file, by the path the loop driver reports.
    File(PathBuf),
    /// A block device node, by the path the loop driver reports and the
    /// device's kernel name.
    Block {
        /// The path the loop driver reports (`/dev/sdb2`, `/dev/dm-4`).
        path: PathBuf,
        /// The kernel name of the device.
        name: String,
    },
}

impl LoopBacking {
    /// The path the loop driver reports for what it is bound to.
    pub fn path(&self) -> &Path {
        match self {
            LoopBacking::File(path) | LoopBacking::Block { path, .. } => path,
        }
    }
}

/// What [`walk()`] read below a device, and where it stopped short of the
/// bottom.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Walk {
    /// The devices read, top first, as [`stack`] returns them.
    pub layers: Vec<Layer>,
    /// Whether the walk reached its limit with a device still to read, so
    /// devices below the top are missing from `layers`.
    pub cut_short: bool,
    /// The kernel names of the loop devices among `layers` that the walk was
    /// to continue below but could not: no block device sysfs shows holds what
    /// one reads (a file on a tmpfs, an overlay, a FUSE or network filesystem).
    pub unplaced_loops: Vec<String>,
}

/// How far below a loop device [`stack`] continues.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum LoopFollow {
    /// Stop at every loop device: only `slaves/` links are followed.
    Never,
    /// Continue into the block device behind a loop over a block node, which
    /// the loop driver does not link as a slave.
    #[default]
    BlockDevices,
    /// Also continue below a loop over a regular file, on the device of the
    /// filesystem that holds the file.
    BackingFiles,
}
