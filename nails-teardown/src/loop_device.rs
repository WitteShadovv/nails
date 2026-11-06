// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The loop driver's record of what a loop device is bound to.
//!
//! The driver keeps the file a loop device is bound to, and
//! `LOOP_GET_STATUS64` reads back the device and inode that file shows. That
//! tells where the file's data lies by device number, not by the path the
//! driver shows, so a mount made over the file's folder later does not make it
//! look like a file of that mount. The record is read here, in the crate that
//! depends on no other NAILS crate, so this crate can read it too, and the
//! base crate's filesystem seam reads its loop records through it.
//!
//! The recorded device is the one the file itself shows (its `st_dev`). For
//! most filesystems that is the number the mount table shows, but btrfs gives
//! each subvolume a number of its own, which no mount line shows. There
//! [`backing_filesystem`] follows the path the driver shows for the file, as
//! the attach gate does, and takes the mount the path leads to only when it
//! leads to the recorded file (its device and inode), so after a mount over
//! the file's folder it names no filesystem.
//!
//! The driver asks the file's filesystem for that device and inode each time
//! the record is read, and a lookup of the path asks each filesystem on the
//! way. A FUSE daemon or a network server that stops answering holds either
//! call, and its caller, until it answers. So [`backing_filesystem`] reads no
//! record and looks up nothing where the path the driver shows runs through
//! an automount point, a FUSE filesystem or a network filesystem, by the
//! mounts the table shows on it, and names no filesystem for it.

use crate::mountinfo::{MountEntry, top_mount_at};
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// The major number of loop devices.
pub const LOOP_MAJOR: u32 = 7;

/// What the loop driver recorded of the file a loop device is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopRecord {
    /// The device the file is on (its `st_dev`, `lo_device`).
    pub device: u64,
    /// The file's inode number on that device (its `st_ino`, `lo_inode`).
    pub inode: u64,
    /// The device the file is, when it is a block device node (its
    /// `st_rdev`, `lo_rdevice`); 0 for a regular file.
    pub rdevice: u64,
}

/// `struct loop_info64` from `<linux/loop.h>`, which `LOOP_GET_STATUS64`
/// fills. Only the two devices and the inode are read; the rest mirrors the
/// kernel's layout.
#[repr(C)]
#[allow(dead_code)]
struct LoopInfo64 {
    lo_device: u64,
    lo_inode: u64,
    lo_rdevice: u64,
    lo_offset: u64,
    lo_sizelimit: u64,
    lo_number: u32,
    lo_encrypt_type: u32,
    lo_encrypt_key_size: u32,
    lo_flags: u32,
    lo_file_name: [u8; 64],
    lo_crypt_name: [u8; 64],
    lo_encrypt_key: [u8; 32],
    lo_init: [u64; 2],
}

/// `LOOP_GET_STATUS64`: a plain number, from before ioctls encoded their
/// argument's size.
const LOOP_GET_STATUS64: rustix::ioctl::Opcode = 0x4C05;

/// The loop driver's record of the backing file of the loop device at
/// `node`. The node is opened read-only and never written; a node that is
/// no loop device, or one bound to nothing, is an error. The driver reads the
/// file's device and inode from the file's filesystem, so this waits for that
/// filesystem to answer.
#[allow(unsafe_code)]
pub fn record(node: &Path) -> io::Result<LoopRecord> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(node)?;
    // SAFETY: LOOP_GET_STATUS64 writes one `struct loop_info64` through the
    // pointer the Getter passes, and LoopInfo64 has that layout.
    let info = unsafe {
        rustix::ioctl::ioctl(
            &file,
            rustix::ioctl::Getter::<LOOP_GET_STATUS64, LoopInfo64>::new(),
        )
    }?;
    Ok(LoopRecord {
        device: info.lo_device,
        inode: info.lo_inode,
        rdevice: info.lo_rdevice,
    })
}

/// The filesystem (`major:minor`, as the mount table writes it) that holds
/// the backing file of the loop device `mount` is a filesystem of, as the
/// loop driver recorded it ([`record`]): the filesystem a mount of the
/// recorded device shows in this process's mount table, or, where none does,
/// as on btrfs, the one the path the driver shows for the file leads to
/// ([`holding_filesystem`]). `None` for a mount whose filesystem is on no
/// loop device (a partition of a loop device is not recognised), for a loop
/// device bound to a device node, which reads that device, when the driver
/// does not answer, as for a caller that may not open the node, when the
/// driver shows no path for the file or one that runs through an automount
/// point, a FUSE filesystem or a network filesystem, which is not asked
/// (the record is not read then), and when no mount the table shows is found
/// to hold the file.
pub fn backing_filesystem(mount: &MountEntry) -> Option<String> {
    let (node, number) = loop_node(mount)?;
    let mounts = crate::mountinfo::read_mountinfo().ok()?;
    holding_filesystem(&mounts, shown_file(number), || record(&node).ok(), reach)
}

/// The number the mount table writes for the device `dev`, `major:minor`.
fn device_number(dev: u64) -> String {
    format!("{}:{}", rustix::fs::major(dev), rustix::fs::minor(dev))
}

/// Where a lookup of a path ended: the mount it reached, by the ID the
/// mount table writes for it, and the file there, by its device and inode
/// number (its `st_dev` and `st_ino`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Reached {
    mount_id: u64,
    device: u64,
    inode: u64,
}

/// The filesystem (`major:minor`, as `mounts` writes it) that holds the file
/// a loop device is bound to, by the loop driver's record of it (`record`)
/// and the path the driver shows for the file (`file`).
///
/// The mounts on the path come first: by the table, a lookup of the path
/// reaches the visible mount at `/` and at each of its folders that is a
/// mount point, and the deepest of them holds the file. Where one of them
/// is an automount point, which a lookup would mount, a FUSE filesystem or a
/// network filesystem ([`served_from_outside`]), no record is read, no
/// lookup is made and no filesystem is named: the driver would ask that
/// filesystem for the record when the file lies there, and a lookup asks
/// each filesystem on the way.
///
/// A mount of the recorded device shows that filesystem. Where none does,
/// as for a file on btrfs, which shows its subvolume's own device while the
/// table writes the filesystem's number, the path is looked up (`lookup`).
/// The mount that holds the path is the filesystem only when the lookup
/// ends on it, at the recorded file (its device and inode). The lookup
/// follows no link. A path that leads elsewhere, such as through a mount
/// made over the file's folder, through a link, or out of view, names no
/// filesystem.
///
/// A loop device bound to a device node reads the device the node is, not
/// the filesystem that holds the node: it names none.
fn holding_filesystem(
    mounts: &[MountEntry],
    file: Option<PathBuf>,
    record: impl FnOnce() -> Option<LoopRecord>,
    lookup: impl FnOnce(&Path) -> Option<Reached>,
) -> Option<String> {
    let file = file?;
    // The deepest first: the mount that holds the file, then those above it.
    let on_the_way: Vec<&MountEntry> = file
        .ancestors()
        .filter_map(|folder| top_mount_at(mounts, folder))
        .collect();
    let holder = *on_the_way.first()?;
    if on_the_way
        .iter()
        .any(|mount| served_from_outside(&mount.fstype))
    {
        return None;
    }
    let record = record()?;
    if record.rdevice != 0 {
        return None;
    }
    let number = device_number(record.device);
    if mounts.iter().any(|m| m.dev == number) {
        return Some(number);
    }
    let reached = lookup(&file)?;
    let on_holder = u64::try_from(holder.mount_id).is_ok_and(|id| id == reached.mount_id);
    let at_file = reached.device == record.device && reached.inode == record.inode;
    (on_holder && at_file).then(|| holder.dev.clone())
}

/// The filesystem types a server outside the kernel answers for: systemd's
/// network filesystems (`fstype_is_network()`) and the shares a virtual
/// machine's host serves.
const SERVED: &[&str] = &[
    "9p",
    "afs",
    "ceph",
    "cifs",
    "davfs",
    "gfs",
    "gfs2",
    "glusterfs",
    "lustre",
    "ncp",
    "ncpfs",
    "nfs",
    "nfs4",
    "ocfs2",
    "orangefs",
    "pvfs2",
    "smb3",
    "smbfs",
    "sshfs",
    "vboxsf",
    "virtiofs",
];

/// Whether the kernel waits for someone outside it to look up a path through
/// a mount of the type `fstype`, as the mount table writes it, or to tell a
/// file's attributes there: the automounter for an automount point, the
/// daemon of a FUSE filesystem (`fuse`, `fuseblk`, and either with the name
/// of its program after a dot, `fuse.sshfs`), and the server of a network
/// filesystem or of a share of a virtual machine's host ([`SERVED`]).
fn served_from_outside(fstype: &str) -> bool {
    let kind = fstype.split_once('.').map_or(fstype, |(kind, _)| kind);
    matches!(kind, "autofs" | "fuse" | "fuseblk") || SERVED.contains(&kind)
}

/// The path the loop driver shows for the file the loop device `number` is
/// bound to (`loop/backing_file` in sysfs), or `None` when it shows none.
fn shown_file(number: u64) -> Option<PathBuf> {
    let attribute = Path::new("/sys/dev/block")
        .join(device_number(number))
        .join("loop/backing_file");
    parse_shown_file(&std::fs::read(attribute).ok()?)
}

/// The path in the text of a `loop/backing_file` attribute: the path the
/// driver shows, as it is, and a newline.
fn parse_shown_file(text: &[u8]) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let path = text.strip_suffix(b"\n").unwrap_or(text);
    (!path.is_empty()).then(|| PathBuf::from(std::ffi::OsStr::from_bytes(path)))
}

/// Where a lookup of `path` that follows no link ends: an `O_PATH` open
/// under `RESOLVE_NO_SYMLINKS`, which reads nothing, then `statx` of it.
/// `None` when the lookup fails, a link anywhere on the path included, and
/// on a kernel without `openat2` or the mount ID in `statx`.
fn reach(path: &Path) -> Option<Reached> {
    use rustix::fs::{AtFlags, CWD, Mode, OFlags, ResolveFlags, StatxFlags};
    let fd = rustix::fs::openat2(
        CWD,
        path,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .ok()?;
    let wanted = StatxFlags::MNT_ID | StatxFlags::INO;
    let stat = rustix::fs::statx(&fd, "", AtFlags::EMPTY_PATH, wanted).ok()?;
    (stat.stx_mask & wanted.bits() == wanted.bits()).then(|| Reached {
        mount_id: stat.stx_mnt_id,
        device: rustix::fs::makedev(stat.stx_dev_major, stat.stx_dev_minor),
        inode: stat.stx_ino,
    })
}

/// The loop device whose filesystem `mount` is, by its node and its device
/// number: by the number the mount table shows, its source when that is the
/// device's node, else `/dev/block/<major>:<minor>`; for a filesystem that
/// shows an anonymous number, as btrfs does, by its source alone. No other
/// mount makes it look at a path.
fn loop_node(mount: &MountEntry) -> Option<(PathBuf, u64)> {
    let (major, minor) = mount.dev.split_once(':')?;
    let (major, minor): (u32, u32) = (major.parse().ok()?, minor.parse().ok()?);
    let source = || {
        mount
            .source
            .starts_with("/dev/")
            .then(|| std::fs::metadata(&mount.source).ok())
            .flatten()
            .filter(|meta| meta.file_type().is_block_device())
            .map(|meta| meta.rdev())
    };
    match major {
        LOOP_MAJOR => {
            let dev = rustix::fs::makedev(major, minor);
            if source() == Some(dev) {
                return Some((mount.source.clone(), dev));
            }
            Some((
                Path::new("/dev/block").join(format!("{major}:{minor}")),
                dev,
            ))
        }
        0 => source()
            .filter(|dev| rustix::fs::major(*dev) == LOOP_MAJOR)
            .map(|dev| (mount.source.clone(), dev)),
        _ => None,
    }
}

#[cfg(test)]
#[path = "loop_device_tests.rs"]
mod tests;
