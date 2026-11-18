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
//! back as it was. It changes only mounts of local disk filesystems whose
//! mount points a lookup reaches through local mounts alone, decided from the
//! mount table, and never looks up a FUSE or network mount or anything inside
//! one: those keep their mode, and their access times are kept by their
//! daemon or server.
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

/// The local disk filesystems whose mounts [`QuietMounts`] may change: each
/// keeps its access times on a block device and is run by the kernel itself,
/// with no FUSE daemon or network server behind it. A mount of any other
/// type keeps its mode, a type this list does not name included.
const LOCAL_DISK: &[&str] = &[
    "bcachefs", "btrfs", "exfat", "ext2", "ext3", "ext4", "f2fs", "hfsplus", "jfs", "msdos",
    "nilfs2", "ntfs", "ntfs3", "reiserfs", "udf", "vfat", "xfs", "zfs",
];

/// The filesystems besides [`LOCAL_DISK`] that a lookup of [`QuietMounts`]
/// may go through, which it leaves as they are: each is run by the kernel
/// itself, from its memory or from a read-only image, with no FUSE daemon or
/// network server behind it, and none keeps access times that the window
/// needs to change. A mount inside a mount of any other type, or below the
/// mount point of one, is out of the window ([`in_window`]).
const KERNEL_ONLY: &[&str] = &[
    "binfmt_misc",
    "bpf",
    "cgroup",
    "cgroup2",
    "configfs",
    "debugfs",
    "devpts",
    "devtmpfs",
    "efivarfs",
    "erofs",
    "fusectl",
    "hugetlbfs",
    "iso9660",
    "mqueue",
    "nsfs",
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

/// Whether a lookup may go through `mount`: one of [`LOCAL_DISK`] or
/// [`KERNEL_ONLY`]. FUSE (`fuse`, `fuse.*`, `fuseblk`), every network or
/// cluster filesystem, a stacked one (`overlay`, `ecryptfs`, whose lookups go
/// on to the filesystems below, which can be such), `autofs`, whose lookups
/// can wait for its daemon, and every type neither list names may not.
fn crossable(mount: &crate::mountinfo::MountEntry) -> bool {
    let fstype = mount.fstype.as_str();
    LOCAL_DISK.contains(&fstype) || KERNEL_ONLY.contains(&fstype)
}

/// Whether `mount` is in the window [`QuietMounts`] changes, decided from the
/// mount table `mounts` alone: it is a local disk filesystem
/// ([`LOCAL_DISK`]), every mount it is mounted inside by the table's parent
/// chain is one a lookup may go through ([`crossable`]), and so is every
/// other mount at its mount point or at one on the way to it, which can be
/// stacked on one of those or cover it. Every lookup of its mount point then
/// goes through local mounts alone. Every other mount keeps its mode, and
/// [`QuietMounts`] never looks it up, opens or stats it, nor anything inside
/// it.
fn in_window(
    mount: &crate::mountinfo::MountEntry,
    mounts: &[crate::mountinfo::MountEntry],
) -> bool {
    LOCAL_DISK.contains(&mount.fstype.as_str())
        && ancestors(mount, mounts)
            .iter()
            .all(|id| mounts.iter().filter(|m| m.mount_id == *id).all(crossable))
        && mounts.iter().all(|other| {
            other.mount_id == mount.mount_id
                || crossable(other)
                || !mount.mount_point.starts_with(&other.mount_point)
        })
}

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

/// Every mount of this process's mount namespace in the window
/// ([`in_window`]) that keeps access times, made `noatime` by
/// [`QuietMounts::open`] for as long as the value lives,
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
/// left as it is. A mount that is out of the window now ([`in_window`]), as
/// one a FUSE mount covers since, is never looked up and counts as one it
/// could not give its mode back. Returns the mount points it could not give
/// their mode back.
pub fn restore(records: &[QuietRecord]) -> Vec<std::path::PathBuf> {
    if records.is_empty() {
        return Vec::new();
    }
    let Ok(mounts) = crate::mountinfo::read_mountinfo() else {
        return records.iter().map(|r| r.mount_point.clone()).collect();
    };
    let mut failed = Vec::new();
    for (record, mount) in to_restore(records, &mounts) {
        let done = reach(mount, &mounts)
            .ok()
            .flatten()
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
/// changed, with the mode to give each: one not in `before`, `noatime`, in the
/// window ([`in_window`]), that shows a directory at or
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
        .filter(|mount| in_window(mount, mounts))
        .filter_map(|mount| {
            sources
                .iter()
                .filter(|source| source.dev == mount.dev && mount.root.starts_with(&source.root))
                .max_by_key(|source| source.root.components().count())
                .map(|source| (mount, source.mode))
        })
        .collect()
}

/// The ID of the mount an open file is on, as `/proc/<pid>/fdinfo/<fd>`
/// lists it in `text` (`mnt_id:`): `None` where the line is missing.
fn fdinfo_mount_id(text: &str) -> Option<i32> {
    text.lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))
        .and_then(|id| id.trim().parse().ok())
}

/// The ID of the mount `fd` is on, from the kernel's own record of the
/// descriptor (`/proc/self/fdinfo`), which asks the filesystem nothing.
fn mount_id_of(fd: &rustix::fd::OwnedFd) -> Result<i32> {
    use std::os::fd::AsRawFd;
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd()))
        .map_err(|error| Errno::from_io_error(&error).unwrap_or(Errno::IO))?;
    // The kernel has listed the mount ID there since Linux 3.15.
    fdinfo_mount_id(&text).ok_or(Errno::INVAL)
}

/// The IDs of the mounts `mount` is mounted inside, by the mount table: its
/// parent, the parent's parent, and so on up to a mount the table does not
/// list.
fn ancestors(
    mount: &crate::mountinfo::MountEntry,
    mounts: &[crate::mountinfo::MountEntry],
) -> Vec<i32> {
    let mut chain = Vec::new();
    let mut at = mount;
    while let Some(parent) = mounts
        .iter()
        .find(|parent| parent.mount_id == at.parent_id && parent.mount_id != at.mount_id)
    {
        if chain.contains(&parent.mount_id) || chain.len() > mounts.len() {
            break;
        }
        chain.push(parent.mount_id);
        at = parent;
    }
    chain
}

/// Look `point` up, for a descriptor of the mount there, the last component
/// not followed and no automount triggered.
fn open_walk(point: &std::path::Path) -> Result<rustix::fd::OwnedFd> {
    use rustix::fs::CWD;
    use rustix::mount::{OpenTreeFlags, open_tree};
    let flags = OpenTreeFlags::OPEN_TREE_CLOEXEC
        | OpenTreeFlags::AT_NO_AUTOMOUNT
        | OpenTreeFlags::AT_SYMLINK_NOFOLLOW;
    open_tree(CWD, point, flags)
}

/// The mount `mount` of the mount table `mounts`, by a descriptor of it:
/// `Ok(None)` for a mount out of the window ([`in_window`]), which is never
/// looked up, and for one no lookup of its mount point reaches, because
/// another mount covers it or one of the mounts on the way (the path then
/// leads elsewhere or nowhere); an error where its mount point cannot be
/// looked up or its mount ID read for another reason.
///
/// The lookup goes only through mounts of [`LOCAL_DISK`] and [`KERNEL_ONLY`]
/// filesystems, which [`in_window`] checks from the mount table before it.
/// None of them has a lookup, revalidation or permission check that asks a
/// FUSE daemon or a network server: the kernel answers it from its dentry
/// cache, in which every directory on the way to a mount point stays while
/// the mount does, or from the filesystem's own device. The mount ID comes
/// from the kernel's record of the descriptor ([`mount_id_of`]).
fn reach(
    mount: &crate::mountinfo::MountEntry,
    mounts: &[crate::mountinfo::MountEntry],
) -> Result<Option<rustix::fd::OwnedFd>> {
    if !in_window(mount, mounts) {
        return Ok(None);
    }
    let fd = match open_walk(&mount.mount_point) {
        Ok(fd) => fd,
        Err(Errno::NOENT | Errno::NOTDIR) => return Ok(None),
        Err(e) => return Err(e),
    };
    if mount_id_of(&fd)? != mount.mount_id {
        return Ok(None);
    }
    Ok(Some(fd))
}

/// The oldest Linux NAILS runs on, as its major and minor number: 6.1, a
/// long-term kernel. [`spawn_without_access_times`] and [`QuietMounts`]
/// change mounts with `mount_setattr(2)`, which Linux 5.12 added.
pub const MIN_LINUX: (u32, u32) = (6, 1);

/// The mounts of `mounts` that [`QuietMounts`] makes `noatime`, each with the
/// mode it has: every one in the window ([`in_window`]) that keeps access
/// times (`relatime` or `strictatime`).
fn window(mounts: &[crate::mountinfo::MountEntry]) -> Vec<(&crate::mountinfo::MountEntry, u64)> {
    mounts
        .iter()
        .filter(|mount| in_window(mount, mounts))
        .filter_map(|mount| atime_mode(&mount.mount_opts).map(|mode| (mount, mode)))
        .collect()
}

/// `error`, from reaching or changing `mount`, with the mount's point and
/// type in front of it.
fn naming(mount: &crate::mountinfo::MountEntry, error: std::io::Error) -> std::io::Error {
    std::io::Error::new(
        error.kind(),
        format!(
            "{} ({}): {error}",
            mount.mount_point.display(),
            mount.fstype
        ),
    )
}

impl QuietMounts {
    /// Make `noatime` every mount of this namespace, as `/proc/self/mountinfo`
    /// lists it, that is in the window ([`in_window`]) and keeps access times
    /// (`relatime` or `strictatime`): a mount of a local disk filesystem whose
    /// mount point a lookup reaches through local mounts alone. A FUSE mount,
    /// a network filesystem's, a mount of any other type, and every mount
    /// inside one of them or below its mount point keep their mode, and none
    /// of them is looked up. A mount in the window is reached by its mount
    /// point and taken only when the mount found there is the one listed: a
    /// mount another covers is out of reach of every lookup and is left.
    /// Where this process may not change mounts
    /// ([`may_spawn_without_access_times`]) nothing changes. A change that
    /// fails puts back the ones made before it and is the error: the caller
    /// then knows the request it guards would set access times.
    pub fn open() -> std::io::Result<Self> {
        Self::open_recorded(|_| Ok(()))
    }

    /// [`open`](Self::open), handing `record` every mount it will change, with
    /// its mode, before it changes any: where `record` fails, nothing changes
    /// and that is the error. A mount in the window that keeps access times
    /// and whose mount point cannot be looked up, or that cannot be made
    /// `noatime`, is an error too, which names the mount's point and type.
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
        for (mount, mode) in window(&mounts) {
            let fd = match reach(mount, &mounts) {
                Ok(Some(fd)) => fd,
                Ok(None) => continue,
                Err(error) => return Err(naming(mount, error.into())),
            };
            records.push(QuietRecord {
                mount_id: mount.mount_id,
                mount_point: mount.mount_point.clone(),
                dev: mount.dev.clone(),
                root: mount.root.clone(),
                relatime: mode == MOUNT_ATTR_RELATIME,
            });
            reached.push((fd, mode, mount.clone()));
        }
        record(&records)?;
        for (fd, mode, mount) in reached {
            set_atime_mode(&fd, MOUNT_ATTR_NOATIME).map_err(|error| naming(&mount, error))?;
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
                    if let Ok(Some(fd)) = reach(mount, &mounts) {
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
#[path = "noatime_tests.rs"]
mod tests;
