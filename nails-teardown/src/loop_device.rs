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

use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_that_is_no_loop_device_has_no_record() {
        // /dev/null opens, but the loop driver does not answer for it.
        assert!(record(Path::new("/dev/null")).is_err());
        assert!(record(Path::new("/dev/nails-no-such-loop")).is_err());
    }
}
