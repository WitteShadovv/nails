// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unmounting in PID 1's mount namespace.
//!
//! When activation ran in a mount namespace other than PID 1's, it had to make
//! the read-only `/nix/store` self-bind there too, and the teardown must undo it
//! there. `setns(CLONE_NEWNS)` changes the caller's whole view and refuses a
//! process that shares its filesystem context with other threads, so the
//! unmount runs in a forked child that enters the namespace and exits.

use std::ffi::CString;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// The mount namespace at `path`, by device and inode.
fn namespace_identity(path: &str) -> io::Result<(u64, u64)> {
    let meta = std::fs::metadata(path)?;
    Ok((meta.dev(), meta.ino()))
}

/// Whether this process runs in a mount namespace other than PID 1's.
pub fn init_namespace_differs() -> io::Result<bool> {
    Ok(namespace_identity("/proc/self/ns/mnt")? != namespace_identity("/proc/1/ns/mnt")?)
}

/// Child exit codes; the child may not allocate, so it reports by number.
const EXIT_UNSHARE: i32 = 11;
const EXIT_SETNS: i32 = 12;
const EXIT_UMOUNT: i32 = 15;

/// Unmount the top mount at `target` in PID 1's mount namespace.
///
/// `Ok(false)` when that namespace is this process's own: an unmount here
/// already reached it, and a second one would strip the decoy's own mount.
pub fn unmount_in_init_namespace(target: &Path) -> io::Result<bool> {
    if !init_namespace_differs()? {
        return Ok(false);
    }
    let namespace = std::fs::File::open("/proc/1/ns/mnt")?;
    let ns_fd = namespace.as_raw_fd();
    let target = CString::new(target.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    #[allow(unsafe_code)]
    // SAFETY: the child branch runs only raw syscalls on data prepared before
    // the fork (an open fd and a NUL-terminated string that outlive it), then
    // `_exit`, so it never touches a lock or allocator another thread held at
    // fork time. The parent branch only waits for the child.
    let code = unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            let code = if libc::unshare(libc::CLONE_FS) != 0 {
                EXIT_UNSHARE
            } else if libc::setns(ns_fd, libc::CLONE_NEWNS) != 0 {
                EXIT_SETNS
            } else if libc::umount2(target.as_ptr(), 0) != 0 {
                EXIT_UMOUNT
            } else {
                0
            };
            libc::_exit(code);
        }
        let mut status = 0;
        if libc::waitpid(pid, &mut status, 0) < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        }
    };
    drop(namespace);
    match code {
        0 => Ok(true),
        EXIT_UNSHARE => Err(io::Error::other("unshare(CLONE_FS) failed in the helper")),
        EXIT_SETNS => Err(io::Error::other("setns into PID 1's namespace failed")),
        EXIT_UMOUNT => Err(io::Error::other("umount in PID 1's namespace failed")),
        _ => Err(io::Error::other("the init-namespace helper died")),
    }
}
