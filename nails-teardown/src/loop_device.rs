// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The loop driver's record of what a loop device is bound to.
//!
//! The driver keeps the device of the filesystem that holds a loop device's
//! backing file, and `LOOP_GET_STATUS64` reads it back. That tells where the
//! file's data lies by device number, not by the path the driver shows, so a
//! mount made over the file's folder later changes nothing. The record is
//! read here, in the crate that depends on no other NAILS crate, so this
//! crate can read it too, and the base crate's filesystem seam reads its loop
//! records through it.

use crate::mountinfo::MountEntry;
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
    /// The device the file is, when it is a block device node (its
    /// `st_rdev`, `lo_rdevice`); 0 for a regular file.
    pub rdevice: u64,
}

/// `struct loop_info64` from `<linux/loop.h>`, which `LOOP_GET_STATUS64`
/// fills. Only the two devices are read; the rest mirrors the kernel's
/// layout.
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
/// no loop device, or one bound to nothing, is an error.
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
        rdevice: info.lo_rdevice,
    })
}

/// The filesystem (`major:minor`, as the mount table writes it) that holds
/// the backing file of the loop device `mount` is a filesystem of, as the
/// loop driver recorded it ([`record`]). `None` for a mount whose filesystem
/// is on no loop device (a partition of a loop device is not recognised), and
/// when the driver does not answer, as for a caller that may not open the
/// node.
pub fn backing_filesystem(mount: &MountEntry) -> Option<String> {
    let device = record(&loop_node(mount)?).ok()?.device;
    Some(format!(
        "{}:{}",
        rustix::fs::major(device),
        rustix::fs::minor(device)
    ))
}

/// The node of the loop device whose filesystem `mount` is: by the device
/// number the mount table shows, its source when that is the device's node,
/// else `/dev/block/<major>:<minor>`; for a filesystem that shows an
/// anonymous number, as btrfs does, by its source alone. No other mount
/// makes it look at a path.
fn loop_node(mount: &MountEntry) -> Option<PathBuf> {
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
                return Some(mount.source.clone());
            }
            Some(Path::new("/dev/block").join(format!("{major}:{minor}")))
        }
        0 => source()
            .filter(|dev| rustix::fs::major(*dev) == LOOP_MAJOR)
            .map(|_| mount.source.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mountinfo::parse_mountinfo;

    #[test]
    fn a_node_that_is_no_loop_device_has_no_record() {
        // /dev/null opens, but the loop driver does not answer for it.
        assert!(record(Path::new("/dev/null")).is_err());
        assert!(record(Path::new("/dev/nails-no-such-loop")).is_err());
    }

    #[test]
    fn only_a_filesystem_on_a_loop_device_is_looked_up() {
        // A disk's number, a table line with no number, and an anonymous
        // number whose source is no device node: none is on a loop device,
        // whatever the host has at these paths.
        let mounts = parse_mountinfo(
            "1 0 8:2 / / rw - ext4 /dev/loop9 rw\n\
             2 1 x:1 / /odd rw - ext4 /dev/loop9 rw\n\
             3 1 0:44 / /srv rw - btrfs /nonexistent/loop9 rw\n\
             4 1 0:45 / /tmp rw - tmpfs tmpfs rw\n",
        );
        for mount in &mounts {
            assert_eq!(loop_node(mount), None, "{mount:?}");
            assert_eq!(backing_filesystem(mount), None, "{mount:?}");
        }
        // A loop device's number: its node by number when the source is not
        // that node, and no record where no node is.
        let image = parse_mountinfo("5 1 7:1048575 / /mnt/img rw - ext4 /nonexistent/loop rw\n");
        assert_eq!(
            loop_node(&image[0]),
            Some(PathBuf::from("/dev/block/7:1048575"))
        );
        assert_eq!(backing_filesystem(&image[0]), None);
    }
}
