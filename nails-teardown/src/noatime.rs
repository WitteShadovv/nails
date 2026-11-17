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
//!
//! A lookup of NAILS' own updates the access time of every symlink it follows,
//! and no open flag prevents that. Through a detached copy of a tree whose
//! every mount is `noatime` ([`quiet_copy`]) no lookup updates one: the way
//! back looks at the decoy root through such a copy.

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
/// changes an access time. The proc and sysfs mounts at `/proc` and `/sys`,
/// which keep no access time on a disk, stay `relatime`, so that the child
/// can still mount its own in a user namespace of its own. The namespace's mounts are made private first, so
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
    // arguments and stack values, and reads `errno` on failure: all
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
            // A child that mounts a proc or a sysfs of its own in a user
            // namespace of its own, as Nix's sandbox does, may do so only
            // where the one it sees has the access-time mode the new one
            // gets, relatime, which its copy keeps locked. Neither keeps an
            // access time on a disk, so both get relatime back. Without them
            // the child still starts: only such a mount fails.
            let relatime = MountAttr {
                attr_set: MOUNT_ATTR_RELATIME,
                attr_clr: MOUNT_ATTR_ATIME_MASK,
                propagation: 0,
                userns_fd: 0,
            };
            for visible in [c"/proc", c"/sys"] {
                libc::syscall(
                    SYS_MOUNT_SETATTR,
                    libc::AT_FDCWD,
                    visible.as_ptr(),
                    AT_RECURSIVE,
                    &raw const relatime,
                    std::mem::size_of::<MountAttr>(),
                );
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
fn set_atime_mode(fd: &rustix::fd::OwnedFd, mode: u64) -> std::io::Result<()> {
    set_attr(fd, libc::AT_EMPTY_PATH, mode, 0)
}

/// `MS_PRIVATE`, as `mount_setattr(2)` takes a propagation.
const MS_PRIVATE: u64 = 1 << 18;

/// Give the mount `fd` refers to, and with `AT_RECURSIVE` in `flags` every
/// mount below it too, the access-time mode `mode` and, unless it is `0`,
/// the propagation `propagation`, leaving every other flag as it is.
#[allow(unsafe_code)]
fn set_attr(
    fd: &rustix::fd::OwnedFd,
    flags: libc::c_int,
    mode: u64,
    propagation: u64,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let attr = MountAttr {
        attr_set: mode,
        attr_clr: MOUNT_ATTR_ATIME_MASK,
        propagation,
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
            flags,
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
/// and given its own mode back when it is closed ([`QuietMounts::close`]) or
/// dropped.
///
/// A bind made while it lives takes `noatime` from the mount it copies. When
/// it is closed, every mount made since that is `noatime` and shows a part
/// of a filesystem it changed gets that mount's own mode too ([`inherited`]),
/// the mode the bind would have had without it.
///
/// A process that dies without unwinding (`SIGKILL`, the OOM killer) closes
/// nothing. [`QuietMounts::open_recorded`] hands what it changes to a record
/// first, so that another process can give those mounts their modes back
/// ([`restore`]).
#[derive(Debug, Default)]
pub struct QuietMounts {
    /// Each mount changed, by a descriptor of it, with the mode it had.
    changed: Vec<(rustix::fd::OwnedFd, u64)>,
    /// Each mount changed, as the mount table listed it, with the mode it had.
    sources: Vec<Source>,
    /// The IDs of the mounts the mount table listed when it was opened.
    before: Vec<i32>,
}

/// A mount [`QuietMounts`] makes `noatime`, as a record that outlives the
/// process: which mount it is and the access-time mode it had.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QuietRecord {
    /// The mount's ID in the mount table.
    pub mount_id: i32,
    /// Where it is mounted.
    pub mount_point: std::path::PathBuf,
    /// Its device, as the mount table writes it (`major:minor`).
    pub dev: String,
    /// The directory of the filesystem at its root.
    pub root: std::path::PathBuf,
    /// Whether it was `relatime`; `strictatime` otherwise.
    pub relatime: bool,
}

impl QuietRecord {
    /// The mode it had, as `mount_setattr(2)` sets it.
    fn mode(&self) -> u64 {
        if self.relatime {
            MOUNT_ATTR_RELATIME
        } else {
            MOUNT_ATTR_STRICTATIME
        }
    }

    /// Whether `mount` is the mount this record names: the same ID, mount
    /// point, device and root, so that a later mount that took a reused ID
    /// is never taken for it.
    fn names(&self, mount: &crate::mountinfo::MountEntry) -> bool {
        mount.mount_id == self.mount_id
            && mount.mount_point == self.mount_point
            && mount.dev == self.dev
            && mount.root == self.root
    }
}

/// Give each mount of `records` that is still mounted and still `noatime` its
/// recorded mode back: what a [`QuietMounts`] whose process died without
/// closing it left. A mount that is gone, or whose mode was changed since, is
/// left as it is. Returns the mount points it could not give their mode back.
pub fn restore(records: &[QuietRecord]) -> Vec<std::path::PathBuf> {
    if records.is_empty() {
        return Vec::new();
    }
    let Ok(mounts) = crate::mountinfo::read_mountinfo() else {
        return records.iter().map(|r| r.mount_point.clone()).collect();
    };
    let mut failed = Vec::new();
    for (record, mount) in to_restore(records, &mounts) {
        let done = reach(mount)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
            .and_then(|fd| set_atime_mode(&fd, record.mode()));
        if done.is_err() {
            failed.push(record.mount_point.clone());
        }
    }
    failed
}

/// The mounts of `mounts` that a record of `records` names and that are
/// still `noatime`, each with its record.
fn to_restore<'a, 'm>(
    records: &'a [QuietRecord],
    mounts: &'m [crate::mountinfo::MountEntry],
) -> Vec<(&'a QuietRecord, &'m crate::mountinfo::MountEntry)> {
    records
        .iter()
        .filter_map(|record| {
            mounts
                .iter()
                .find(|mount| record.names(mount))
                .filter(|mount| atime_mode(&mount.mount_opts).is_none())
                .map(|mount| (record, mount))
        })
        .collect()
}

/// A mount [`QuietMounts`] made `noatime`: the filesystem it shows (its
/// device and the directory of it at its root) and the mode it had.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Source {
    dev: String,
    root: std::path::PathBuf,
    mode: u64,
}

/// The mounts of `mounts` that took `noatime` from a mount [`QuietMounts`]
/// changed, with the mode to give each: one not in `before`, `noatime`, on a
/// filesystem that keeps access times on a disk, that shows a directory at or
/// below the root of a changed mount of its device. Of several such mounts,
/// the one whose root is the deepest is the one a bind copied.
fn inherited<'a>(
    sources: &[Source],
    before: &[i32],
    mounts: &'a [crate::mountinfo::MountEntry],
) -> Vec<(&'a crate::mountinfo::MountEntry, u64)> {
    mounts
        .iter()
        .filter(|mount| !before.contains(&mount.mount_id))
        .filter(|mount| atime_mode(&mount.mount_opts).is_none())
        .filter(|mount| !NO_DISK_ATIMES.contains(&mount.fstype.as_str()))
        .filter_map(|mount| {
            sources
                .iter()
                .filter(|source| source.dev == mount.dev && mount.root.starts_with(&source.root))
                .max_by_key(|source| source.root.components().count())
                .map(|source| (mount, source.mode))
        })
        .collect()
}

/// The mount at `mount`'s mount point, by a descriptor, when it is the one
/// the mount table lists there: `None` for a mount another covers, which no
/// lookup reaches, and when it cannot be reached at all.
fn reach(mount: &crate::mountinfo::MountEntry) -> Option<rustix::fd::OwnedFd> {
    reach_or_covered(mount).ok().flatten()
}

/// The mount at `mount`'s mount point, by a descriptor: `Ok(None)` when no
/// lookup of that path reaches it, because another mount covers it or one of
/// its parents (the path then leads elsewhere or nowhere), and an error when
/// the mount point cannot be opened or asked for its mount for another
/// reason.
fn reach_or_covered(
    mount: &crate::mountinfo::MountEntry,
) -> std::io::Result<Option<rustix::fd::OwnedFd>> {
    use rustix::fs::{AtFlags, CWD, StatxFlags, statx};
    use rustix::mount::{OpenTreeFlags, open_tree};
    let flags = OpenTreeFlags::OPEN_TREE_CLOEXEC
        | OpenTreeFlags::AT_NO_AUTOMOUNT
        | OpenTreeFlags::AT_SYMLINK_NOFOLLOW;
    let fd = match open_tree(CWD, &mount.mount_point, flags) {
        Ok(fd) => fd,
        Err(Errno::NOENT | Errno::NOTDIR) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let stat = statx(&fd, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)?;
    let reached = i64::try_from(stat.stx_mnt_id).ok() == Some(i64::from(mount.mount_id));
    Ok(reached.then_some(fd))
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
        Self::open_recorded(|_| Ok(()))
    }

    /// [`open`](Self::open), handing `record` every mount it will change, with
    /// its mode, before it changes any: where `record` fails, nothing changes
    /// and that is the error. A mount that keeps access times and cannot be
    /// reached for another reason than another mount covering it is an error
    /// too, so that no mount is left out silently.
    pub fn open_recorded(
        record: impl FnOnce(&[QuietRecord]) -> std::io::Result<()>,
    ) -> std::io::Result<Self> {
        let mut quiet = QuietMounts::default();
        if !may_spawn_without_access_times() {
            return Ok(quiet);
        }
        let mounts = crate::mountinfo::read_mountinfo()?;
        quiet.before = mounts.iter().map(|mount| mount.mount_id).collect();
        let mut reached = Vec::new();
        let mut records = Vec::new();
        for mount in mounts {
            let Some(mode) = atime_mode(&mount.mount_opts) else {
                continue;
            };
            if NO_DISK_ATIMES.contains(&mount.fstype.as_str()) {
                continue;
            }
            let Some(fd) = reach_or_covered(&mount)? else {
                continue;
            };
            records.push(QuietRecord {
                mount_id: mount.mount_id,
                mount_point: mount.mount_point.clone(),
                dev: mount.dev.clone(),
                root: mount.root.clone(),
                relatime: mode == MOUNT_ATTR_RELATIME,
            });
            reached.push((fd, mode, mount));
        }
        record(&records)?;
        for (fd, mode, mount) in reached {
            set_atime_mode(&fd, MOUNT_ATTR_NOATIME)?;
            quiet.changed.push((fd, mode));
            quiet.sources.push(Source {
                dev: mount.dev,
                root: mount.root,
                mode,
            });
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

    /// Give every mount it changed its own mode back, the last first, and
    /// every mount made since that took `noatime` from one of them that one's
    /// mode ([`inherited`]). Every mount is tried; the first error is
    /// returned.
    pub fn close(mut self) -> std::io::Result<()> {
        self.give_back()
    }

    /// End it as a process that is killed does: its descriptors closed and
    /// no mount given its mode back. For the tests of [`restore`].
    #[cfg(any(test, feature = "test-support"))]
    pub fn abandon(mut self) {
        self.changed.clear();
        self.sources.clear();
    }

    fn give_back(&mut self) -> std::io::Result<()> {
        let mut result = Ok(());
        let mut keep = |done: std::io::Result<()>| {
            if let Err(e) = done
                && result.is_ok()
            {
                result = Err(e);
            }
        };
        for (fd, mode) in self.changed.drain(..).rev() {
            keep(set_atime_mode(&fd, mode));
        }
        if self.sources.is_empty() {
            return result;
        }
        let sources = std::mem::take(&mut self.sources);
        match crate::mountinfo::read_mountinfo() {
            Ok(mounts) => {
                for (mount, mode) in inherited(&sources, &self.before, &mounts) {
                    if let Some(fd) = reach(mount) {
                        keep(set_atime_mode(&fd, mode));
                    }
                }
            }
            Err(e) => keep(Err(e)),
        }
        result
    }
}

impl Drop for QuietMounts {
    /// What [`close`](QuietMounts::close) does, for a value that was not
    /// closed: an error unwinding, a request that failed. An error here
    /// cannot be reported; a record of it ([`QuietMounts::open_recorded`])
    /// lets a rollback try again ([`restore`]).
    fn drop(&mut self) {
        let _ = self.give_back();
    }
}

/// A detached copy of the mounts at and below `root`, every one `noatime` and
/// private, where this process may change mounts
/// ([`may_spawn_without_access_times`]): no lookup through it changes an
/// access time, a symlink's on the way included, and nothing mounted or
/// unmounted on the system reaches it. The copy is the tree's, not a view of
/// files of its own: what is changed through it is changed on the disk. It
/// goes away with the last descriptor of it. `None` where this process may
/// not, or a step fails.
pub fn quiet_copy(root: &std::path::Path) -> Option<rustix::fd::OwnedFd> {
    use rustix::fs::CWD;
    use rustix::mount::{OpenTreeFlags, open_tree};
    if !may_spawn_without_access_times() {
        return None;
    }
    let flags = OpenTreeFlags::OPEN_TREE_CLONE
        | OpenTreeFlags::OPEN_TREE_CLOEXEC
        | OpenTreeFlags::AT_RECURSIVE
        | OpenTreeFlags::AT_NO_AUTOMOUNT;
    let copy = open_tree(CWD, root, flags).ok()?;
    set_attr(
        &copy,
        libc::AT_EMPTY_PATH | AT_RECURSIVE,
        MOUNT_ATTR_NOATIME,
        MS_PRIVATE,
    )
    .ok()?;
    Some(copy)
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
        assert!(quiet_copy(std::path::Path::new("/")).is_none());
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", "exit 0"]);
        spawn_without_access_times(&mut command);
        assert!(command.status().unwrap().success());
    }

    fn source(dev: &str, root: &str, mode: u64) -> Source {
        Source {
            dev: dev.to_string(),
            root: std::path::PathBuf::from(root),
            mode,
        }
    }

    /// A bind made while the mounts were quiet gets the mode of the mount of
    /// its filesystem whose root holds it, the deepest of several; a mount
    /// listed before, one that keeps access times, one of another device and
    /// one on a filesystem without them on a disk keep theirs.
    #[test]
    fn a_bind_made_while_quiet_gets_the_mode_of_the_mount_it_copies() {
        let table = "\
20 1 8:1 / / rw,noatime - ext4 /dev/sda1 rw
21 1 0:30 /root / rw,noatime - btrfs /dev/vda4 rw
22 1 0:30 /home /home rw,noatime - btrfs /dev/vda4 rw
30 20 8:1 / /run/nextroot/decoy ro,noatime - ext4 /dev/sda1 rw
31 20 0:30 /home/user /run/nextroot/home ro,noatime - btrfs /dev/vda4 rw
32 20 0:30 /root/var /run/nextroot/var rw,noatime - btrfs /dev/vda4 rw
33 20 8:1 /etc /run/nextroot/etc rw,relatime - ext4 /dev/sda1 rw
34 20 8:2 / /run/nextroot/boot rw,noatime - ext4 /dev/sda2 rw
35 20 0:40 / /run/nextroot/run rw,noatime - tmpfs tmpfs rw
";
        let mounts = crate::mountinfo::parse_mountinfo(table);
        let sources = [
            source("8:1", "/", MOUNT_ATTR_RELATIME),
            source("0:30", "/root", MOUNT_ATTR_STRICTATIME),
            source("0:30", "/home", MOUNT_ATTR_RELATIME),
        ];
        let got: Vec<(i32, u64)> = inherited(&sources, &[20, 21, 22], &mounts)
            .into_iter()
            .map(|(mount, mode)| (mount.mount_id, mode))
            .collect();
        assert_eq!(
            got,
            vec![
                (30, MOUNT_ATTR_RELATIME),
                (31, MOUNT_ATTR_RELATIME),
                (32, MOUNT_ATTR_STRICTATIME),
            ]
        );
    }

    fn record(id: i32, point: &str, dev: &str, root: &str, relatime: bool) -> QuietRecord {
        QuietRecord {
            mount_id: id,
            mount_point: std::path::PathBuf::from(point),
            dev: dev.to_string(),
            root: std::path::PathBuf::from(root),
            relatime,
        }
    }

    /// A record gives back its mode only to the mount it names that is still
    /// `noatime`: a mount gone, one whose ID another mount took, and one
    /// whose mode was changed since are left as they are.
    #[test]
    fn a_record_restores_only_the_mount_it_names_while_noatime() {
        let table = "\
20 1 8:1 / / rw,noatime - ext4 /dev/sda1 rw
22 1 0:30 /home /home rw,noatime - btrfs /dev/vda4 rw
24 1 8:2 / /boot rw,relatime - ext4 /dev/sda2 rw
25 1 0:31 / /srv rw,noatime - ext4 /dev/sdb1 rw
";
        let mounts = crate::mountinfo::parse_mountinfo(table);
        let records = [
            record(20, "/", "8:1", "/", true),
            record(22, "/home", "0:30", "/home", false),
            // Its mode was changed back since.
            record(24, "/boot", "8:2", "/", true),
            // Another mount took ID 25.
            record(25, "/srv", "8:3", "/", true),
            // Gone.
            record(26, "/data", "8:4", "/", true),
        ];
        let got: Vec<(i32, u64)> = to_restore(&records, &mounts)
            .into_iter()
            .map(|(record, mount)| (mount.mount_id, record.mode()))
            .collect();
        assert_eq!(
            got,
            vec![(20, MOUNT_ATTR_RELATIME), (22, MOUNT_ATTR_STRICTATIME)]
        );
        assert!(restore(&[]).is_empty());
    }

    /// The record goes into the plan and comes back as it was.
    #[test]
    fn a_record_reads_back_as_it_was_written() {
        let written = record(20, "/", "8:1", "/", true);
        let text = serde_json::to_string(&written).unwrap();
        assert_eq!(serde_json::from_str::<QuietRecord>(&text).unwrap(), written);
    }

    /// Without a mount it changed, no mount takes a mode from it.
    #[test]
    fn without_a_changed_mount_no_mode_is_given() {
        let mounts = crate::mountinfo::parse_mountinfo(
            "30 20 8:1 / /run/x ro,noatime - ext4 /dev/sda1 rw\n",
        );
        assert!(inherited(&[], &[], &mounts).is_empty());
    }
}
