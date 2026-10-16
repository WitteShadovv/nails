// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The loop driver's record of what a loop device is bound to.

use crate::{IoResultExt, Result};
use std::path::Path;

/// `struct loop_info64` from `<linux/loop.h>`, which `LOOP_GET_STATUS64`
/// fills. Only the device is read; the rest mirrors the kernel's layout.
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

/// The device of the backing file of the loop device at `node`. The node is
/// opened read-only and never written.
#[allow(unsafe_code)]
pub(super) fn loop_backing_device(node: &Path) -> Result<u64> {
    use rustix::fs::{Mode, OFlags};
    let fd = rustix::fs::open(
        node,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .at_path(node)?;
    // SAFETY: LOOP_GET_STATUS64 writes one `struct loop_info64` through the
    // pointer the Getter passes, and LoopInfo64 has that layout.
    let info = unsafe {
        rustix::ioctl::ioctl(
            &fd,
            rustix::ioctl::Getter::<LOOP_GET_STATUS64, LoopInfo64>::new(),
        )
    }
    .map_err(std::io::Error::from)
    .at_path(node)?;
    Ok(info.lo_device)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_that_is_no_loop_device_has_no_backing_device() {
        // /dev/null opens, but the loop driver does not answer for it.
        assert!(loop_backing_device(Path::new("/dev/null")).is_err());
        assert!(loop_backing_device(Path::new("/dev/nails-no-such-loop")).is_err());
    }
}
