// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Opening a file without updating its access time.
//!
//! Under the default `relatime` mount option the kernel still updates an
//! inode's access time on a read when it is older than the inode's last change
//! or more than a day old, so a read of the decoy can stamp it with the time of
//! the read. `O_NOATIME` prevents that, but the kernel grants the flag only to
//! the inode's owner and to a caller with `CAP_FOWNER` (root has it); anyone
//! else gets `EPERM`. Every such read follows one rule, [`with_noatime`]: open
//! with the flag, and without it on `EPERM`, which cannot avoid the update.
//!
//! The flag covers only the inode that is opened. A lookup still updates the
//! access time of each symlink it follows on the way, under the same rules.

use rustix::fs::OFlags;
use rustix::io::{Errno, Result};

/// Call `open` with `O_NOATIME` as the flags to add, and once more with none
/// when the kernel refuses that flag (`EPERM`).
pub fn with_noatime<T>(mut open: impl FnMut(OFlags) -> Result<T>) -> Result<T> {
    match open(OFlags::NOATIME) {
        Err(Errno::PERM) => open(OFlags::empty()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flag_is_dropped_only_when_the_kernel_refuses_it() {
        let mut tried = Vec::new();
        let opened = with_noatime(|flags| {
            tried.push(flags);
            if flags.contains(OFlags::NOATIME) {
                Err(Errno::PERM)
            } else {
                Ok("plain")
            }
        });
        assert_eq!(opened, Ok("plain"));
        assert_eq!(tried, vec![OFlags::NOATIME, OFlags::empty()]);

        let mut calls = 0;
        assert_eq!(
            with_noatime(|_| {
                calls += 1;
                Ok(())
            }),
            Ok(())
        );
        assert_eq!(calls, 1, "a granted flag needs no second open");

        let mut calls = 0;
        assert_eq!(
            with_noatime(|_| -> Result<()> {
                calls += 1;
                Err(Errno::NOENT)
            }),
            Err(Errno::NOENT)
        );
        assert_eq!(calls, 1, "any other error is the answer");
    }
}
