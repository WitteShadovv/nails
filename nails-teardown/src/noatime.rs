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
//!
//! A program NAILS starts reads more than any flag of NAILS' own can cover:
//! its own file, its loader and libraries, its data files and the links on
//! the way to each. [`spawn_without_access_times`] starts it in a mount
//! namespace of its own in which every mount is `noatime`, so none of those
//! reads changes an access time, while everything it does to the system (a
//! request to PID 1, to logind or to the kernel) reaches the system as before.
//!
//! What another process reads because NAILS asked it to is out of reach of
//! both: a reload of the service manager makes PID 1 run every generator and
//! read every unit file again, and a question about a unit it has not loaded
//! makes it read that unit's files. [`QuietMounts`] makes the mounts that keep
//! access times `noatime` for as long as such a request takes, and puts each
//! back as it was.

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

/// `mount_setattr(2)`, by its number, the same on every architecture.
const SYS_MOUNT_SETATTR: libc::c_long = 442;
/// `MOUNT_ATTR_NOATIME`.
const MOUNT_ATTR_NOATIME: u64 = 0x10;
/// `MOUNT_ATTR__ATIME`, the bits of the access-time mode, which a change of
/// the mode must clear.
const MOUNT_ATTR_ATIME_MASK: u64 = 0x70;
/// `AT_RECURSIVE`: the change reaches every mount below the path too.
const AT_RECURSIVE: libc::c_int = 0x8000;

/// `struct mount_attr`.
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// Whether this process may give a child a mount namespace whose mounts it
/// changes: root, in the system's own user namespace, whose mounts carry no
/// lock. In a user namespace of its own (a test's), a copied mount's access
/// time mode is locked, and an unprivileged process may not make a mount
/// namespace at all.
pub fn may_spawn_without_access_times() -> bool {
    rustix::process::geteuid().is_root()
        && std::fs::read_to_string("/proc/self/uid_map")
            .is_ok_and(|map| map.split_whitespace().collect::<Vec<_>>() == ["0", "0", "4294967295"])
}

/// Start the child `command` makes in a mount namespace of its own whose
/// every mount is `noatime`, where this process may
/// ([`may_spawn_without_access_times`]), so that nothing the child reads
/// changes an access time. The namespace's mounts are made private first, so
/// the change reaches no other namespace, and the child sees every mount the
/// system has when it starts. Where the process may and a step fails, the
/// child never runs: the spawn fails with the step's error. Where it may not,
/// as for an unprivileged `nails check`, the child runs as it is and its reads
/// can update access times.
///
/// Add it before a hook that drops the child's privileges.
#[allow(unsafe_code)]
pub fn spawn_without_access_times(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    if !may_spawn_without_access_times() {
        return;
    }
    // SAFETY: the closure runs in the child between fork and exec. It calls
    // only `unshare(2)`, `mount(2)` and `mount_setattr(2)` with constant
    // arguments and a stack value, and reads `errno` on failure: all
    // async-signal-safe, with no allocation and no shared state.
    unsafe {
        command.pre_exec(|| {
            if libc::unshare(libc::CLONE_NEWNS) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let root = c"/";
            if libc::mount(
                std::ptr::null(),
                root.as_ptr(),
                std::ptr::null(),
                libc::MS_REC | libc::MS_PRIVATE,
                std::ptr::null(),
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let attr = MountAttr {
                attr_set: MOUNT_ATTR_NOATIME,
                attr_clr: MOUNT_ATTR_ATIME_MASK,
                propagation: 0,
                userns_fd: 0,
            };
            if libc::syscall(
                SYS_MOUNT_SETATTR,
                libc::AT_FDCWD,
                root.as_ptr(),
                AT_RECURSIVE,
                &raw const attr,
                std::mem::size_of::<MountAttr>(),
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// `MOUNT_ATTR_RELATIME`, the access-time mode of a mount without one of the
/// others.
const MOUNT_ATTR_RELATIME: u64 = 0x00;
/// `MOUNT_ATTR_STRICTATIME`.
const MOUNT_ATTR_STRICTATIME: u64 = 0x20;

/// Filesystem types that keep no access time on a disk, or whose own mount
/// flag does not decide it (an overlay's layers have mounts of their own,
/// which no mount table lists): [`QuietMounts`] leaves their mounts alone.
const NO_DISK_ATIMES: &[&str] = &[
    "autofs",
    "binfmt_misc",
    "bpf",
    "cgroup",
    "cgroup2",
    "configfs",
    "debugfs",
    "devpts",
    "devtmpfs",
    "efivarfs",
    "fusectl",
    "hugetlbfs",
    "iso9660",
    "mqueue",
    "nsfs",
    "overlay",
    "proc",
    "pstore",
    "ramfs",
    "rpc_pipefs",
    "securityfs",
    "selinuxfs",
    "squashfs",
    "sysfs",
    "tmpfs",
    "tracefs",
];

/// The access-time mode of a mount whose per-mount options are `options`, as
/// `mount_setattr(2)` sets it: `None` for `noatime`, which has nothing to keep.
fn atime_mode(options: &str) -> Option<u64> {
    let mut words = options.split(',');
    if words.clone().any(|word| word == "noatime") {
        None
    } else if words.any(|word| word == "relatime") {
        Some(MOUNT_ATTR_RELATIME)
    } else {
        Some(MOUNT_ATTR_STRICTATIME)
    }
}

/// Give the mount `fd` refers to the access-time mode `mode`, leaving every
/// other flag of it as it is.
#[allow(unsafe_code)]
fn set_atime_mode(fd: &rustix::fd::OwnedFd, mode: u64) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let attr = MountAttr {
        attr_set: mode,
        attr_clr: MOUNT_ATTR_ATIME_MASK,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: `mount_setattr(2)` reads `size_of::<MountAttr>()` bytes from
    // `attr`, which lives on this stack frame for the whole call, and the
    // empty path names the mount `fd` refers to (`AT_EMPTY_PATH`).
    let done = unsafe {
        libc::syscall(
            SYS_MOUNT_SETATTR,
            fd.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            &raw const attr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    if done == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Every mount of this process's mount namespace that keeps access times,
/// made `noatime` by [`QuietMounts::open`] for as long as the value lives,
/// and given its own mode back when it is dropped.
#[derive(Debug, Default)]
pub struct QuietMounts {
    /// Each mount changed, by a descriptor of it, with the mode it had.
    changed: Vec<(rustix::fd::OwnedFd, u64)>,
}

impl QuietMounts {
    /// Make `noatime` every mount of this namespace, as `/proc/self/mountinfo`
    /// lists it, that keeps access times (`relatime` or `strictatime`) on a
    /// filesystem that keeps them on a disk ([`NO_DISK_ATIMES`]). Each is
    /// reached by its mount point and taken only when the mount found there is
    /// the one listed: a mount another covers is out of reach of every lookup
    /// and is left. Where this process may not change mounts
    /// ([`may_spawn_without_access_times`]) nothing changes. A change that
    /// fails puts back the ones made before it and is the error: the caller
    /// then knows the request it guards would set access times.
    pub fn open() -> std::io::Result<Self> {
        use rustix::fs::{AtFlags, CWD, StatxFlags, statx};
        use rustix::mount::{OpenTreeFlags, open_tree};
        let mut quiet = QuietMounts::default();
        if !may_spawn_without_access_times() {
            return Ok(quiet);
        }
        for mount in crate::mountinfo::read_mountinfo()? {
            let Some(mode) = atime_mode(&mount.mount_opts) else {
                continue;
            };
            if NO_DISK_ATIMES.contains(&mount.fstype.as_str()) {
                continue;
            }
            let flags = OpenTreeFlags::OPEN_TREE_CLOEXEC
                | OpenTreeFlags::AT_NO_AUTOMOUNT
                | OpenTreeFlags::AT_SYMLINK_NOFOLLOW;
            let Ok(fd) = open_tree(CWD, &mount.mount_point, flags) else {
                continue;
            };
            let reached =
                statx(&fd, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID).is_ok_and(|stat| {
                    i64::try_from(stat.stx_mnt_id).ok() == Some(i64::from(mount.mount_id))
                });
            if !reached {
                continue;
            }
            set_atime_mode(&fd, MOUNT_ATTR_NOATIME)?;
            quiet.changed.push((fd, mode));
        }
        Ok(quiet)
    }

    /// How many mounts it made `noatime`.
    pub fn len(&self) -> usize {
        self.changed.len()
    }

    /// Whether it made no mount `noatime`.
    pub fn is_empty(&self) -> bool {
        self.changed.is_empty()
    }
}

impl Drop for QuietMounts {
    /// Give every mount it changed its own mode back, the last first.
    fn drop(&mut self) {
        for (fd, mode) in self.changed.drain(..).rev() {
            let _ = set_atime_mode(&fd, mode);
        }
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

    #[test]
    fn a_mount_keeps_its_own_access_time_mode() {
        assert_eq!(atime_mode("rw,relatime"), Some(MOUNT_ATTR_RELATIME));
        assert_eq!(
            atime_mode("rw,nosuid,relatime,nodiratime"),
            Some(MOUNT_ATTR_RELATIME)
        );
        assert_eq!(atime_mode("rw"), Some(MOUNT_ATTR_STRICTATIME));
        assert_eq!(atime_mode("ro,nodiratime"), Some(MOUNT_ATTR_STRICTATIME));
        assert_eq!(atime_mode("rw,noatime"), None);
        assert_eq!(atime_mode("rw,noatime,relatime"), None);
    }

    /// Without the right to change mounts (a test runs unprivileged, or as
    /// root of a user namespace of its own) nothing is changed, and a child
    /// starts as it is.
    #[test]
    fn without_the_right_to_change_mounts_nothing_changes() {
        if may_spawn_without_access_times() {
            return;
        }
        let quiet = QuietMounts::open().unwrap();
        assert!(quiet.is_empty());
        assert_eq!(quiet.len(), 0);
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", "exit 0"]);
        spawn_without_access_times(&mut command);
        assert!(command.status().unwrap().success());
    }
}
