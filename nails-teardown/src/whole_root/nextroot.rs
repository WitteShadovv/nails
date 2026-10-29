// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Mount primitives for `/run/nextroot` and the init check before a switch.
//!
//! Everything below `/run/nextroot` is *extrinsic* to systemd: the orderly
//! shutdown of a soft-reboot never unmounts it, and PID 1 switches root into
//! it. These are the few mount operations the transitions need, in both
//! directions:
//!
//! - the root overlay: a non-recursive, read-only bind of the decoy root as the
//!   lower, the upper and work directories on the hidden volume;
//! - plain and read-only binds (`/run`, the hidden volume, the ESP);
//! - an overlay over one other decoy filesystem (a separate `/home`);
//! - the decoy root device mounted again, for the way back;
//! - detaching a whole tree (rollback, a stray `/run/nextroot`).
//!
//! Every mount below the next root is private from the moment it exists. The
//! decoy's `/` is shared (systemd makes it so at boot), so a bind of a decoy
//! filesystem joins that filesystem's peer group, and a mount below such a
//! bind would appear below the decoy's own mount too (a carried `/boot` below
//! the hidden volume's bind would show at `/mnt/data/root/decoy/boot` in the
//! decoy, and keep the decoy from unmounting the hidden volume at the switch).
//! Making the finished tree private comes too late for that;
//! [`make_below_private`] does it again for the finished tree, as a backstop.
//!
//! The next root's own mount (the root overlay at entry, the decoy root on the
//! way back) stays shared until the switch, which makes the whole tree private
//! itself before it moves it. Every mount namespace made before the entry
//! (logind's, and that of every service with a namespace of its own) receives
//! a copy of each mount made directly below it. Two things need those copies
//! to follow the next root:
//!
//! - logind decides whether a plain `reboot` becomes a soft-reboot by looking
//!   for an OS tree at `/run/nextroot` from its own namespace, and on NixOS
//!   the `os-release` it looks for lives in a store mounted below the root;
//! - detaching the tree (a rollback, a disarmed next root, `nails recover`, an
//!   emergency on the decoy) reaches the copies only through a shared root.
//!   Below a private one they would stay, with the hidden volume's bind and
//!   the layers on it, until those services restart: readable by every user
//!   in `/proc/<pid>/mountinfo`, and holding the hidden filesystem busy after
//!   the operator unmounts it.
//!
//! [`precheck`] does what PID 1 (systemd >= 258) does before it switches: the
//! init must resolve *inside* the new root, and the root must be an OS tree. A
//! root that fails either freezes the machine with no way back except a power
//! cycle, so every switch is checked first.

use crate::mountinfo::{MountEntry, escape_overlay_path, read_mountinfo};
use crate::noatime::with_noatime;
use rustix::fs::{Mode, OFlags, ResolveFlags, StatVfsMountFlags};
use rustix::mount::{MountFlags, MountPropagationFlags, UnmountFlags};
use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};

/// Where PID 1 looks for the next root on a soft-reboot.
pub const NEXTROOT: &str = "/run/nextroot";

fn to_io(e: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(e.raw_os_error())
}

fn c_string(text: &str) -> io::Result<CString> {
    CString::new(text).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in mount data"))
}

/// Bind `source` onto `target`, recursively or not, and make the new mount
/// (and with `recursive` everything below it) private. A bind is never the
/// next root's own mount.
pub fn bind(source: &Path, target: &Path, recursive: bool) -> io::Result<()> {
    if recursive {
        rustix::mount::mount_bind_recursive(source, target).map_err(to_io)?;
    } else {
        rustix::mount::mount_bind(source, target).map_err(to_io)?;
    }
    private_or_detach(target, recursive)
}

/// Make the mount at `target`, just made below the next root, private: nothing
/// mounted below it later propagates anywhere (see the module docs).
pub fn make_private(target: &Path) -> io::Result<()> {
    rustix::mount::mount_change(target, MountPropagationFlags::PRIVATE).map_err(to_io)
}

/// Make the mount just made at `target` private, or detach it again: nothing
/// mounted below it later may propagate to the peers of what it was made
/// from (see the module docs).
fn private_or_detach(target: &Path, recursive: bool) -> io::Result<()> {
    let mut flags = MountPropagationFlags::PRIVATE;
    if recursive {
        flags |= MountPropagationFlags::REC;
    }
    if let Err(e) = rustix::mount::mount_change(target, flags) {
        let _ = rustix::mount::unmount(target, UnmountFlags::DETACH);
        return Err(to_io(e));
    }
    Ok(())
}

/// Make the bind mount at `target` read-only, keeping the per-mount flags it
/// already has (a user namespace refuses to clear locked `nosuid`/`nodev`).
pub fn remount_read_only(target: &Path) -> io::Result<()> {
    remount_bind(target, true)
}

/// Make the bind mount at `target` writable again, keeping its other per-mount
/// flags.
pub fn remount_writable(target: &Path) -> io::Result<()> {
    remount_bind(target, false)
}

fn remount_bind(target: &Path, read_only: bool) -> io::Result<()> {
    let current = rustix::fs::statvfs(target).map_err(to_io)?.f_flag;
    let mut flags = MountFlags::BIND;
    if read_only {
        flags |= MountFlags::RDONLY;
    }
    for (have, keep) in [
        (StatVfsMountFlags::NOSUID, MountFlags::NOSUID),
        (StatVfsMountFlags::NODEV, MountFlags::NODEV),
        (StatVfsMountFlags::NOEXEC, MountFlags::NOEXEC),
        (StatVfsMountFlags::NOATIME, MountFlags::NOATIME),
        (StatVfsMountFlags::NODIRATIME, MountFlags::NODIRATIME),
        (StatVfsMountFlags::RELATIME, MountFlags::RELATIME),
    ] {
        if current.contains(have) {
            flags |= keep;
        }
    }
    rustix::mount::mount_remount(target, flags, "").map_err(to_io)
}

/// The per-mount flags a bind remount sets for `options`, the per-mount field
/// of the mount table (`ro,nosuid,nodev,relatime`): with an access-time mode
/// always, so the remount sets exactly these. `None` when a flag in it cannot
/// be set by a remount (an idmapped mount) or is unknown.
pub fn per_mount_flags(options: &str) -> Option<MountFlags> {
    let mut flags = MountFlags::empty();
    let mut atime = MountFlags::STRICTATIME;
    for option in options.split(',') {
        match option {
            "rw" => {}
            "ro" => flags |= MountFlags::RDONLY,
            "nosuid" => flags |= MountFlags::NOSUID,
            "nodev" => flags |= MountFlags::NODEV,
            "noexec" => flags |= MountFlags::NOEXEC,
            "nodiratime" => flags |= MountFlags::NODIRATIME,
            "nosymfollow" => flags |= MountFlags::NOSYMFOLLOW,
            "relatime" => atime = MountFlags::RELATIME,
            "noatime" => atime = MountFlags::NOATIME,
            _ => return None,
        }
    }
    Some(flags | atime)
}

/// Give the mount at `target` exactly the per-mount flags of `options` (see
/// [`per_mount_flags`]), whatever it had.
pub fn set_per_mount_options(target: &Path, options: &str) -> io::Result<()> {
    let flags = per_mount_flags(options).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("the mount options {options} cannot be set again"),
        )
    })?;
    rustix::mount::mount_remount(target, MountFlags::BIND | flags, "").map_err(to_io)
}

/// The ID, as the mount table numbers it, of the mount a lookup of `path`
/// ends on: from `statx`, or from the mount table where `statx` does not tell
/// (Linux before 5.8).
pub fn mount_id_at(path: &Path) -> io::Result<i32> {
    use rustix::fs::{AtFlags, CWD, StatxFlags, statx};
    let stat = statx(CWD, path, AtFlags::NO_AUTOMOUNT, StatxFlags::MNT_ID).map_err(to_io)?;
    if stat.stx_mask & StatxFlags::MNT_ID.bits() != 0 {
        return i32::try_from(stat.stx_mnt_id)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mount ID out of range"));
    }
    crate::mountinfo::top_mount_at(&read_mountinfo()?, path)
        .map(|mount| mount.mount_id)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{} is no mount point", path.display()),
            )
        })
}

/// Whether the mount at `path` is `noexec`.
pub fn is_noexec(path: &Path) -> io::Result<bool> {
    let flags = rustix::fs::statvfs(path).map_err(to_io)?.f_flag;
    Ok(flags.contains(StatVfsMountFlags::NOEXEC))
}

/// Set or clear `noexec` on the mount at `path`, keeping its other per-mount
/// flags. Debian and Ubuntu mount `/run` `noexec`; the transition step and the
/// session's units run the binary copy from it.
pub fn set_noexec(path: &Path, noexec: bool) -> io::Result<()> {
    let current = rustix::fs::statvfs(path).map_err(to_io)?.f_flag;
    let mut flags = MountFlags::BIND;
    for (have, keep) in [
        (StatVfsMountFlags::RDONLY, MountFlags::RDONLY),
        (StatVfsMountFlags::NOSUID, MountFlags::NOSUID),
        (StatVfsMountFlags::NODEV, MountFlags::NODEV),
        (StatVfsMountFlags::NOATIME, MountFlags::NOATIME),
        (StatVfsMountFlags::NODIRATIME, MountFlags::NODIRATIME),
        (StatVfsMountFlags::RELATIME, MountFlags::RELATIME),
    ] {
        if current.contains(have) {
            flags |= keep;
        }
    }
    if noexec {
        flags |= MountFlags::NOEXEC;
    }
    rustix::mount::mount_remount(path, flags, "").map_err(to_io)
}

/// A read-only bind of `source` at `target` (not recursive).
pub fn bind_read_only(source: &Path, target: &Path) -> io::Result<()> {
    bind(source, target, false)?;
    if let Err(e) = remount_read_only(target) {
        let _ = rustix::mount::unmount(target, UnmountFlags::DETACH);
        return Err(e);
    }
    Ok(())
}

/// Make every mount below `target` private, leaving `target`'s own mount as
/// it is (see the module docs: the next root's own mount stays shared until
/// the switch). Every mount below the next root is private from the moment it
/// exists; this is the backstop for the finished tree. A mount that a later
/// mount on top of it or of a parent shadows is left alone: its path leads to
/// the mount on top, and it was made private when it was created.
pub fn make_below_private(target: &Path) -> io::Result<()> {
    for entry in read_mountinfo()
        .unwrap_or_default()
        .into_iter()
        .filter(|entry| entry.mount_point != target && entry.mount_point.starts_with(target))
    {
        if !reaches(&entry.mount_point, entry.mount_id) {
            continue;
        }
        rustix::mount::mount_change(&entry.mount_point, MountPropagationFlags::PRIVATE)
            .map_err(to_io)?;
    }
    Ok(())
}

/// Whether a lookup of `path` ends on the mount `id`, as mountinfo numbers
/// it. A path that no longer exists leads to no mount; without the mount id
/// in `statx` (Linux before 5.8) every path is taken to reach its mount. The
/// lookup never triggers an automount, as the propagation change itself
/// does not: nothing would answer one below the next root.
fn reaches(path: &Path, id: i32) -> bool {
    use rustix::fs::{AtFlags, CWD, StatxFlags, statx};
    match statx(CWD, path, AtFlags::NO_AUTOMOUNT, StatxFlags::MNT_ID) {
        Ok(stat) if stat.stx_mask & StatxFlags::MNT_ID.bits() != 0 => {
            u64::try_from(id).is_ok_and(|id| id == stat.stx_mnt_id)
        }
        Err(rustix::io::Errno::NOENT) => false,
        _ => true,
    }
}

fn overlay_path(path: &Path) -> io::Result<String> {
    escape_overlay_path(path).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} cannot be an overlay layer", path.display()),
        )
    })
}

/// The overlay feature options NAILS pins on every mount (see [`overlay_params`]).
///
/// `index`, `metacopy` and `redirect_dir` default differently across kernels —
/// Arch's turns them on — and each lets the overlay diverge from a plain copy-up:
/// an index survives into the upper, a metadata-only copy leaves the data in the
/// lower, and a followed redirect reads from the lower after a rename. Pinning
/// them off keeps every distribution's overlay behaving as NAILS's forensic
/// promise assumes. `xino` is deliberately left unpinned: it stores nothing in
/// the upper.
pub const OVERLAY_FEATURE_OPTIONS: &str = "index=off,metacopy=off,redirect_dir=nofollow";

/// The options of a one-lower-layer overlay as key and value pairs: the three
/// layer paths, escaped for the overlay option parser, then NAILS's pinned
/// feature options ([`OVERLAY_FEATURE_OPTIONS`]).
///
/// The one place the real mount ([`mount_overlay`], through [`overlay_data`])
/// and the upper-filesystem capability probe, which hands each pair to
/// `fsconfig(2)`, build the options, so the two can never pin a different set.
pub fn overlay_params(
    lower: &Path,
    upper: &Path,
    work: &Path,
) -> io::Result<Vec<(&'static str, String)>> {
    let mut params = vec![
        ("lowerdir", overlay_path(lower)?),
        ("upperdir", overlay_path(upper)?),
        ("workdir", overlay_path(work)?),
    ];
    // Every pinned option is a key and a value, as `fsconfig(2)` takes a
    // string; a bare flag would need a call of its own and is not split out
    // here. A test holds these pairs to the constant word for word, so an
    // option without a value fails it rather than going missing.
    params.extend(
        OVERLAY_FEATURE_OPTIONS
            .split(',')
            .filter_map(|option| option.split_once('='))
            .map(|(key, value)| (key, value.to_string())),
    );
    Ok(params)
}

/// The `mount(2)` data for a one-lower-layer overlay: [`overlay_params`]
/// joined into one option string, NAILS's pinned feature options last.
pub fn overlay_data(lower: &Path, upper: &Path, work: &Path) -> io::Result<String> {
    Ok(overlay_params(lower, upper, work)?
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(","))
}

/// Mount an overlay at `target` with one lower layer.
pub fn mount_overlay(lower: &Path, upper: &Path, work: &Path, target: &Path) -> io::Result<()> {
    let data = c_string(&overlay_data(lower, upper, work)?)?;
    rustix::mount::mount(
        "overlay",
        target,
        "overlay",
        MountFlags::empty(),
        data.as_c_str(),
    )
    .map_err(to_io)
}

/// An overlay at `target` whose lower is the filesystem mounted at `source`
/// alone (none of its submounts), read-only so the overlay can never update an
/// atime on it. `helper` is an empty directory used for the lower bind; the
/// overlay keeps a private clone of its layers, so the helper mount is gone
/// again when this returns.
pub fn overlay_over(
    source: &Path,
    helper: &Path,
    upper: &Path,
    work: &Path,
    target: &Path,
) -> io::Result<()> {
    std::fs::create_dir_all(helper)?;
    bind_read_only(source, helper)?;
    let mounted = mount_overlay(helper, upper, work, target);
    let _ = rustix::mount::unmount(helper, UnmountFlags::DETACH);
    let _ = std::fs::remove_dir(helper);
    mounted
}

/// Mount the block device `source` (`fstype`, with optional `data`) at
/// `target`.
pub fn mount_device(
    source: &Path,
    fstype: &str,
    data: Option<&str>,
    target: &Path,
) -> io::Result<()> {
    let data = data.map(c_string).transpose()?;
    rustix::mount::mount(source, target, fstype, MountFlags::empty(), data.as_deref())
        .map_err(to_io)
}

/// The mount points of the live mount table.
pub fn mount_points() -> Vec<PathBuf> {
    read_mountinfo()
        .unwrap_or_default()
        .into_iter()
        .map(|e| e.mount_point)
        .collect()
}

/// Whether `path` is a mount point in `entries`.
pub fn is_mount_point(entries: &[MountEntry], path: &Path) -> bool {
    entries.iter().any(|e| e.mount_point == path)
}

/// Detach every mount on or below `path` among `mount_points`, deepest first.
/// Returns the mount points detached.
pub fn detach_under(path: &Path, mount_points: &[PathBuf]) -> Vec<PathBuf> {
    let mut under: Vec<&PathBuf> = mount_points
        .iter()
        .filter(|m| m.starts_with(path))
        .collect();
    under.sort_by_key(|m| std::cmp::Reverse(m.components().count()));
    under
        .into_iter()
        .filter(|m| rustix::mount::unmount(m.as_path(), UnmountFlags::DETACH).is_ok())
        .cloned()
        .collect()
}

/// Detach the whole tree at `path` from the live mount table, repeating while
/// mounts remain (stacked mounts come off one per round). Returns what is
/// still mounted on or below `path` afterwards.
pub fn detach_tree(path: &Path) -> Vec<PathBuf> {
    for _ in 0..8 {
        let points = mount_points();
        if !points.iter().any(|m| m.starts_with(path)) {
            return Vec::new();
        }
        if detach_under(path, &points).is_empty() {
            break;
        }
    }
    mount_points()
        .into_iter()
        .filter(|m| m.starts_with(path))
        .collect()
}

/// Remove the runtime directory `dir`, detaching every mount below it first.
/// An activation killed between its lower bind and that bind's read-only
/// remount leaves a writable bind of a decoy filesystem there (the root
/// itself, for the root overlay), and a recursive removal would walk into it.
/// Nothing is removed while anything stays mounted below `dir`.
pub fn remove_runtime_dir(dir: &Path) {
    if detach_tree(dir).is_empty() {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Open `path` as if `root` were `/`: absolute symlinks and `..` stay inside
/// `root`, the way PID 1 resolves the init in the next root.
fn open_in_root(root: &Path, path: &Path) -> io::Result<OwnedFd> {
    open_in_root_with(root, path, OFlags::PATH)
}

/// How often an in-root lookup is tried again after the kernel gave it up.
const LOOKUP_RETRIES: usize = 32;

/// Run the in-root lookup `open` again while the kernel reports `EAGAIN`,
/// [`LOOKUP_RETRIES`] times at most. With `RESOLVE_IN_ROOT` the kernel gives
/// up a lookup through a `..` component when a rename or a mount anywhere on
/// the system races it, and leaves the retry to the caller: a link such as
/// `/etc/os-release -> ../usr/lib/os-release`, or a dotfile link a tool such
/// as GNU stow makes (`~/.config -> ../dotfiles/config`), would otherwise
/// fail now and then on a busy system.
fn retry_lookup<T>(mut open: impl FnMut() -> rustix::io::Result<T>) -> rustix::io::Result<T> {
    let mut tries = 0;
    loop {
        match open() {
            Err(rustix::io::Errno::AGAIN) if tries < LOOKUP_RETRIES => tries += 1,
            result => return result,
        }
    }
}

/// [`open_in_root`] with the open flags `flags`.
fn open_in_root_with(root: &Path, path: &Path, flags: OFlags) -> io::Result<OwnedFd> {
    let dir = rustix::fs::open(
        root,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(to_io)?;
    open_at(&dir, path, flags, ResolveFlags::IN_ROOT)
}

/// Open `path` below the directory `dir` with the open flags `flags` and the
/// lookup restrictions `resolve`: a leading `/` is dropped, and an empty
/// path opens `dir` itself.
fn open_at(
    dir: &OwnedFd,
    path: &Path,
    flags: OFlags,
    resolve: ResolveFlags,
) -> io::Result<OwnedFd> {
    let relative = path.strip_prefix("/").unwrap_or(path);
    let relative = if relative.as_os_str().is_empty() {
        Path::new(".")
    } else {
        relative
    };
    retry_lookup(|| {
        rustix::fs::openat2(
            dir,
            relative.as_os_str().as_bytes(),
            flags | OFlags::CLOEXEC,
            Mode::empty(),
            resolve,
        )
    })
    .map_err(to_io)
}

/// Open (`O_PATH`) the file or directory at `path` below `dir` without
/// leaving the mount `dir` is on and without following a symlink: a lookup
/// that would cross into another mount fails (`EXDEV`), one that would leave
/// `dir` or meet a symlink fails too. An empty `path` opens `dir` itself.
pub fn open_in_mount(dir: &OwnedFd, path: &Path) -> io::Result<OwnedFd> {
    let resolve = ResolveFlags::BENEATH | ResolveFlags::NO_XDEV | ResolveFlags::NO_SYMLINKS;
    open_at(dir, path, OFlags::PATH, resolve)
}

/// Open (`O_PATH`) the file or directory at `path` as if the directory `root`
/// were `/`, through the mounts below it but without following a symlink.
pub fn open_in_tree(root: &OwnedFd, path: &Path) -> io::Result<OwnedFd> {
    let resolve = ResolveFlags::IN_ROOT | ResolveFlags::NO_SYMLINKS;
    open_at(root, path, OFlags::PATH, resolve)
}

/// Open (`O_PATH`) the directory at `path`: the root of the mount a lookup of
/// a mount point ends on.
pub fn open_mount_root(path: &Path) -> io::Result<OwnedFd> {
    rustix::fs::open(
        path,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(to_io)
}

/// The directory at `path` as if `root` were `/`, for the `*at` calls that
/// create, replace or remove an entry in it. The descriptor reads nothing
/// (`O_PATH`).
///
/// A plain path below `/run/nextroot` resolves an absolute symlink on the
/// running system: a decoy whose `/home` or `~/.config` is such a link would
/// take a write meant for the next root onto the decoy disk.
pub fn open_dir_in_root(root: &Path, path: &Path) -> io::Result<OwnedFd> {
    open_in_root_with(root, path, OFlags::PATH | OFlags::DIRECTORY)
}

/// The names in the directory at `path`, resolved as if `root` were `/`.
pub fn list_in_root(root: &Path, path: &Path) -> io::Result<Vec<OsString>> {
    let fd = open_in_root_with(root, path, OFlags::RDONLY | OFlags::DIRECTORY)?;
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::new(fd).map_err(to_io)? {
        let name = entry.map_err(to_io)?.file_name().to_bytes().to_vec();
        if name != b"." && name != b".." {
            names.push(OsString::from_vec(name));
        }
    }
    Ok(names)
}

/// Create the directory `path` and every missing parent as if `root` were
/// `/`, and open it like [`open_dir_in_root`]. `made` is called with the
/// parent and the name of each directory created (mode `0777` less the
/// umask, as `mkdir -p`), to give it an owner. A component that exists but
/// does not resolve to a directory inside `root`, such as a dangling link,
/// fails the call: nothing is created through it.
pub fn create_dir_all_in_root(
    root: &Path,
    path: &Path,
    made: &mut dyn FnMut(BorrowedFd<'_>, &OsStr) -> io::Result<()>,
) -> io::Result<OwnedFd> {
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => names.push(name),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("not a plain path: {}", path.display()),
                ));
            }
        }
    }
    let mut dir = open_dir_in_root(root, Path::new("/"))?;
    let mut current = PathBuf::from("/");
    for name in names {
        current.push(name);
        dir = match open_dir_in_root(root, &current) {
            Ok(fd) => fd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                rustix::fs::mkdirat(&dir, name, Mode::from_raw_mode(0o777)).map_err(to_io)?;
                made(dir.as_fd(), name)?;
                open_dir_in_root(root, &current)?
            }
            Err(e) => return Err(e),
        };
    }
    Ok(dir)
}

/// The path the kernel reports for `fd`: absolute, with no symlink in it, so
/// a later call on it reaches the same directory.
pub fn real_path(fd: &OwnedFd) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
}

/// Whether `path` exists as if `root` were `/`: absolute symlinks resolve
/// inside `root`, so on NixOS `/etc/systemd/system` (a link into `/etc/static`
/// and the store) is looked up in that root's store, not the running one's.
pub fn exists_in_root(root: &Path, path: &Path) -> bool {
    open_in_root(root, path).is_ok()
}

/// Whether `path` is a regular file as if `root` were `/`, its symlinks
/// resolved inside `root` as [`exists_in_root`] resolves them. The lookup
/// opens nothing it reads (`O_PATH`), so a FIFO or a device found there is
/// never opened.
pub fn is_file_in_root(root: &Path, path: &Path) -> bool {
    regular_file_in_root(root, path).unwrap_or(false)
}

/// [`is_file_in_root`], with the error of a lookup that fails: `NotFound`
/// when nothing is there, another kind when something may be there that the
/// lookup cannot reach (a loop of links, a directory it may not search).
pub fn regular_file_in_root(root: &Path, path: &Path) -> io::Result<bool> {
    let stat = rustix::fs::fstat(open_in_root(root, path)?).map_err(to_io)?;
    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFREG)
}

/// How many symlinks [`canonical_in_root`] follows by their text before it
/// gives a path up, as the kernel's own limit for one lookup.
const MAX_LINK_HOPS: usize = 40;

/// `path` as it resolves inside `root`, with every symlink on the way followed
/// inside `root` (absolute links and `..` stay within it): a decoy whose
/// `/home` is a link to `var/home` yields `/var/home`, so the mount, the
/// generated unit name and the fresh home all land where the decoy really keeps
/// the files, never on the symlink. A trailing component that does not exist
/// yet (a mount point or a home not created) is resolved as far as its deepest
/// existing ancestor and then re-appended. A symlink whose target does not
/// exist yet is followed all the same, as systemd's fstab generator follows it,
/// so `/home` linking to a missing `var/home` yields `/var/home` too. The
/// result is absolute, as seen from `root`. A path that resolves to nothing (a
/// loop of links), or any failure, returns `path` unchanged. `path` must be
/// absolute; a relative path is returned as is.
pub fn canonical_in_root(root: &Path, path: &Path) -> PathBuf {
    if !path.is_absolute() {
        return path.to_path_buf();
    }
    let unresolved = || path.to_path_buf();
    let Ok(root_real) = open_mount_root(root).and_then(|fd| real_path(&fd)) else {
        return unresolved();
    };
    // The path of the opened `fd` as seen from `root`.
    let seen = |fd: &OwnedFd| {
        real_path(fd).map(|real| {
            let mut out = PathBuf::from("/");
            out.push(real.strip_prefix(&root_real).unwrap_or(&real));
            out
        })
    };
    let mut current = path.to_path_buf();
    'lookup: for _ in 0..=MAX_LINK_HOPS {
        // Open the longest prefix of `current` that resolves inside `root`,
        // reading its real (symlink-free) path, then re-append the components
        // past it.
        let mut tail: Vec<OsString> = Vec::new();
        let mut prefix = current.clone();
        loop {
            if let Ok(mut out) = open_in_root(root, &prefix).and_then(|fd| seen(&fd)) {
                out.extend(tail.iter().rev());
                return out;
            }
            let (Some(parent), Some(name)) = (prefix.parent(), prefix.file_name()) else {
                return unresolved();
            };
            // A link that leads to nothing yet: go on from its target.
            if let Ok(dir) = open_dir_in_root(root, parent)
                && let Ok(target) = rustix::fs::readlinkat(&dir, name, Vec::new())
                && let Ok(base) = seen(&dir)
            {
                let target = PathBuf::from(OsString::from_vec(target.into_bytes()));
                let mut next = if target.is_absolute() {
                    target
                } else {
                    base.join(target)
                };
                next.extend(tail.iter().rev());
                current = next;
                continue 'lookup;
            }
            tail.push(name.to_os_string());
            prefix = parent.to_path_buf();
        }
    }
    unresolved()
}

/// Read the file at `path` as if `root` were `/` (absolute symlinks resolve
/// inside `root`): the next root's `/etc/fstab`, which on NixOS is a link
/// into the hidden store, or the decoy's own.
///
/// The file is opened with `O_NOATIME` ([`with_noatime`]), so a check or an
/// entry that reads the decoy's fstab does not stamp it with the time of the
/// read on a `relatime` filesystem; a caller that neither owns the file nor
/// holds `CAP_FOWNER` cannot avoid that. The flag covers the file alone: on
/// NixOS the decoy's `/etc/fstab` and `/etc/static` are links on its root,
/// and the lookup that follows them can still update their access times.
pub fn read_in_root(root: &Path, path: &Path) -> io::Result<Vec<u8>> {
    let dir = rustix::fs::open(
        root,
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(to_io)?;
    let relative = path.strip_prefix("/").unwrap_or(path);
    let fd = with_noatime(|noatime| {
        retry_lookup(|| {
            rustix::fs::openat2(
                &dir,
                relative.as_os_str().as_bytes(),
                noatime | OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
                ResolveFlags::IN_ROOT,
            )
        })
    })
    .map_err(to_io)?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::fs::File::from(fd), &mut bytes)?;
    Ok(bytes)
}

/// Why a root failed the pre-switch check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrecheckError {
    /// The init does not resolve inside the root.
    InitMissing(PathBuf, String),
    /// The init resolves but is not an executable regular file.
    InitNotExecutable(PathBuf),
    /// Neither `/etc/os-release` nor `/usr/lib/os-release` resolves inside it.
    NotAnOsTree,
}

impl std::fmt::Display for PrecheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrecheckError::InitMissing(init, why) => {
                write!(
                    f,
                    "the init {} does not resolve in the next root: {why}",
                    init.display()
                )
            }
            PrecheckError::InitNotExecutable(init) => {
                write!(
                    f,
                    "the init {} in the next root is not an executable file",
                    init.display()
                )
            }
            PrecheckError::NotAnOsTree => write!(
                f,
                "the next root has neither /etc/os-release nor /usr/lib/os-release"
            ),
        }
    }
}

impl std::error::Error for PrecheckError {}

/// Check that `root` is a root PID 1 can switch into: `init` resolves inside
/// it to an executable regular file, and it is an OS tree.
pub fn precheck(root: &Path, init: &Path) -> Result<(), PrecheckError> {
    let fd = open_in_root(root, init)
        .map_err(|e| PrecheckError::InitMissing(init.to_path_buf(), e.to_string()))?;
    let stat = rustix::fs::fstat(&fd)
        .map_err(|e| PrecheckError::InitMissing(init.to_path_buf(), e.to_string()))?;
    let mode = stat.st_mode;
    let regular = (mode & libc::S_IFMT) == libc::S_IFREG;
    if !regular || mode & 0o111 == 0 {
        return Err(PrecheckError::InitNotExecutable(init.to_path_buf()));
    }
    let os_tree = ["/etc/os-release", "/usr/lib/os-release"]
        .iter()
        .any(|p| open_in_root(root, Path::new(p)).is_ok());
    if !os_tree {
        return Err(PrecheckError::NotAnOsTree);
    }
    Ok(())
}

#[cfg(test)]
#[path = "nextroot_tests.rs"]
mod tests;
