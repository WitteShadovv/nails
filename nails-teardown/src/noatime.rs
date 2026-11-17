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
fn reach_or_covered(mount: &crate::mountinfo::MountEntry) -> Result<Option<rustix::fd::OwnedFd>> {
    use rustix::fs::{AtFlags, CWD, StatxFlags, statx};
    use rustix::mount::{OpenTreeFlags, open_tree};
    let flags = OpenTreeFlags::OPEN_TREE_CLOEXEC
        | OpenTreeFlags::AT_NO_AUTOMOUNT
        | OpenTreeFlags::AT_SYMLINK_NOFOLLOW;
    let fd = match open_tree(CWD, &mount.mount_point, flags) {
        Ok(fd) => fd,
        Err(Errno::NOENT | Errno::NOTDIR) => return Ok(None),
        Err(e) => return Err(e),
    };
    let stat = statx(&fd, "", AtFlags::EMPTY_PATH, StatxFlags::MNT_ID)?;
    let reached = i64::try_from(stat.stx_mnt_id).ok() == Some(i64::from(mount.mount_id));
    Ok(reached.then_some(fd))
}

/// The FUSE module's parameter that lets a process with `CAP_SYS_ADMIN` in
/// the initial user namespace past the check of a mount's owner. Linux 6.0
/// added it together with that way past the check, which it keeps off by
/// default.
const FUSE_SYS_ADMIN_ACCESS: &str = "/sys/module/fuse/parameters/allow_sys_admin_access";

/// The oldest Linux NAILS runs on, as its major and minor number: 6.1, the
/// oldest long-term kernel with both `mount_setattr(2)` (Linux 5.12), which
/// [`spawn_without_access_times`] and [`QuietMounts`] change mounts with, and
/// FUSE's `allow_sys_admin_access` parameter (Linux 6.0), by which
/// [`QuietMounts`] knows that FUSE lets root no further than its owner check.
pub const MIN_LINUX: (u32, u32) = (6, 1);

/// Whether `mount` is a FUSE mount: of type `fuse`, `fuse.*` or `fuseblk`.
fn is_fuse(mount: &crate::mountinfo::MountEntry) -> bool {
    mount.fstype == "fuse" || mount.fstype == "fuseblk" || mount.fstype.starts_with("fuse.")
}

/// Whether `mount` is a user's FUSE mount: a FUSE mount ([`is_fuse`])
/// mounted without `allow_other` for a user or a group other than root's
/// (`user_id` and `group_id` not both 0). FUSE answers every process whose
/// user and group IDs are not all the mount's own with `EACCES`, root
/// included unless the kernel lets `CAP_SYS_ADMIN` past that check
/// ([`kept_from_root`]). A user's own FUSE mounts are such: a desktop's
/// `gvfsd-fuse` and document portal, an AppImage's `squashfuse`, an `sshfs`.
fn users_fuse(mount: &crate::mountinfo::MountEntry) -> bool {
    let options: Vec<&str> = mount.super_opts.split(',').collect();
    let id = |key: &str| {
        options
            .iter()
            .find_map(|option| option.strip_prefix(key))
            .and_then(|value| value.parse::<u32>().ok())
    };
    let not_roots = match (id("user_id="), id("group_id=")) {
        (Some(user), Some(group)) => user != 0 || group != 0,
        _ => false,
    };
    is_fuse(mount) && !options.contains(&"allow_other") && not_roots
}

/// Whether `mount`, which this process could not reach with `error`, is a
/// FUSE mount the kernel keeps PID 1 out of, so that PID 1 reads nothing on
/// it and [`QuietMounts`] can leave it as it is: a user's FUSE mount
/// ([`users_fuse`]), refused with `EACCES` or `EPERM`, on a kernel whose FUSE
/// lets `CAP_SYS_ADMIN` no further (`sys_admin_access`, the parameter
/// [`FUSE_SYS_ADMIN_ACCESS`] as read, is `N`). PID 1 runs as root and is
/// refused the same way. Every other mount that cannot be reached is an
/// error.
fn kept_from_root(
    mount: &crate::mountinfo::MountEntry,
    error: Errno,
    sys_admin_access: Option<&str>,
) -> bool {
    users_fuse(mount)
        && matches!(error, Errno::ACCESS | Errno::PERM)
        && sys_admin_access.map(str::trim) == Some("N")
}

/// Whether `mount`, which this process could not reach with `error`, lies at
/// or below the mount point of another mount of `mounts` that is a FUSE mount
/// `kept` says the kernel keeps root out of ([`kept_from_root`]): every
/// lookup of root's through that mount fails with `EACCES` or `EPERM`, PID
/// 1's too, so PID 1 reads nothing on `mount` either. An fstab mount inside a
/// home that a user's FUSE mount covers later is such.
fn below_kept_fuse(
    mount: &crate::mountinfo::MountEntry,
    error: Errno,
    mounts: &[crate::mountinfo::MountEntry],
    kept: impl Fn(&crate::mountinfo::MountEntry) -> bool,
) -> bool {
    matches!(error, Errno::ACCESS | Errno::PERM)
        && mounts.iter().any(|fuse| {
            fuse.mount_id != mount.mount_id
                && is_fuse(fuse)
                && mount.mount_point.starts_with(&fuse.mount_point)
                && kept(fuse)
        })
}

/// Judge `mount`, a mount that keeps access times and that this process
/// could not reach with `error`: `Ok` where the kernel keeps PID 1 out of it
/// too, so that [`QuietMounts`] leaves it as it is, a user's FUSE mount
/// ([`kept_from_root`]) or a mount at or below one ([`below_kept_fuse`]),
/// and otherwise the error, naming the mount. `sys_admin_access` is FUSE's
/// [`FUSE_SYS_ADMIN_ACCESS`] as read, and `reach` the error, if any, of
/// reaching another mount of `mounts`. Where the rule would leave the mount
/// out but the parameter cannot be read, the error says so: a kernel without
/// it, one before Linux 6.0, is below [`MIN_LINUX`].
fn judge_unreached(
    mount: &crate::mountinfo::MountEntry,
    error: Errno,
    mounts: &[crate::mountinfo::MountEntry],
    sys_admin_access: &std::io::Result<String>,
    reach: impl Fn(&crate::mountinfo::MountEntry) -> Option<Errno>,
) -> std::io::Result<()> {
    let parameter = sys_admin_access.as_deref().ok();
    let kept = |fuse: &crate::mountinfo::MountEntry| {
        reach(fuse).is_some_and(|error| kept_from_root(fuse, error, parameter))
    };
    if kept_from_root(mount, error, parameter) || below_kept_fuse(mount, error, mounts, kept) {
        return Ok(());
    }
    let users = |fuse: &crate::mountinfo::MountEntry| {
        users_fuse(fuse) && reach(fuse).is_some_and(|e| matches!(e, Errno::ACCESS | Errno::PERM))
    };
    let would_be_kept = matches!(error, Errno::ACCESS | Errno::PERM)
        && (users_fuse(mount) || below_kept_fuse(mount, error, mounts, users));
    match sys_admin_access {
        Err(read) if would_be_kept => {
            let (major, minor) = MIN_LINUX;
            let why = if read.kind() == std::io::ErrorKind::NotFound {
                format!(
                    "this kernel's FUSE has no allow_sys_admin_access parameter \
                     ({FUSE_SYS_ADMIN_ACCESS}), which tells whether root may look into a \
                     user's FUSE mount: Linux 6.0 added it, and NAILS needs Linux \
                     {major}.{minor} or newer"
                )
            } else {
                format!("{FUSE_SYS_ADMIN_ACCESS} cannot be read: {read}")
            };
            Err(naming(
                mount,
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("{}, and {why}", std::io::Error::from(error)),
                ),
            ))
        }
        _ => Err(naming(mount, error.into())),
    }
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
    /// lists it, that keeps access times (`relatime` or `strictatime`) on a
    /// filesystem that keeps them on a disk ([`NO_DISK_ATIMES`]). Each is
    /// reached by its mount point and taken only when the mount found there is
    /// the one listed: a mount another covers is out of reach of every lookup
    /// and is left, and so are a FUSE mount the kernel keeps root, PID 1
    /// included, out of ([`kept_from_root`]) and a mount at or below one
    /// ([`below_kept_fuse`]). Where this process may not change mounts
    /// ([`may_spawn_without_access_times`]) nothing changes. A change that
    /// fails puts back the ones made before it and is the error: the caller
    /// then knows the request it guards would set access times.
    pub fn open() -> std::io::Result<Self> {
        Self::open_recorded(|_| Ok(()))
    }

    /// [`open`](Self::open), handing `record` every mount it will change, with
    /// its mode, before it changes any: where `record` fails, nothing changes
    /// and that is the error. A mount that keeps access times and cannot be
    /// reached for another reason than another mount covering it or the
    /// kernel keeping root out of it or out of a FUSE mount above it
    /// ([`judge_unreached`]) is an error too, so that no mount PID 1 can read
    /// is left out silently. An error names the mount's point and type.
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
        let mut sys_admin_access = None;
        for mount in &mounts {
            let Some(mode) = atime_mode(&mount.mount_opts) else {
                continue;
            };
            if NO_DISK_ATIMES.contains(&mount.fstype.as_str()) {
                continue;
            }
            let fd = match reach_or_covered(mount) {
                Ok(Some(fd)) => fd,
                Ok(None) => continue,
                Err(error) => {
                    let parameter = sys_admin_access
                        .get_or_insert_with(|| std::fs::read_to_string(FUSE_SYS_ADMIN_ACCESS));
                    judge_unreached(mount, error, &mounts, parameter, |other| {
                        reach_or_covered(other).err()
                    })?;
                    continue;
                }
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
#[path = "noatime_tests.rs"]
mod tests;
