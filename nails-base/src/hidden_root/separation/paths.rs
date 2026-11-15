// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The paths the decoy's fstab and crypttab name, read as they are written: no
//! link in them is followed. These are a bind line's source, the path of a swap
//! or image file, of what a FUSE program reads and of that program itself where
//! a line names it by an absolute path, and the source of a crypttab line that
//! is no tag and no device's path in `/dev`, such as a container file, which
//! `systemd-cryptsetup` opens through a loop device, and so its key file, its
//! header and what the boot mounts for one of these, and a path an option of a
//! line names, such as an overlay's folders (see the `reads` module). A
//! device's path in `/dev` that no block device answers to, written as that
//! path or as a tag whose udev link it is, is followed through its links only
//! while they stay in `/dev` ([`follow_in_dev`]): a link that leads out of it
//! is not followed.
//!
//! Each part of such a path is looked at on its own through the
//! [`Filesystem`] trait, from `/` down, with one `statx` that follows no link
//! and mounts nothing there ([`Filesystem::mount_root`]), and the path itself
//! is asked whether it is a device node ([`Filesystem::is_device_node`]). No
//! link is read, so no access time changes. Before each part, the mount table
//! is asked whether a lookup there would mount an automount point that
//! nothing is mounted on yet, and such a lookup is not made. `.` is no part,
//! and `..` goes back up one part of the path as written, which is where the
//! kernel's lookup goes too while no part on the way is a link. A part that
//! is not there ends the looking: the rest of the path reads as written,
//! until a `..` leads back to a place that is there.
//!
//! Where such a path lies cannot be told ([`UntoldPath`]) when a part of it
//! is a symbolic link, which the boot's `mount`, `swapon`, `mount.fuse` or
//! `systemd-cryptsetup` would follow, when it is not absolute, when it is a
//! device node, which they would use as the device it is, when it crosses
//! the folder of an fstab line, a
//! `noauto` one too, while that line's mount is not there now
//! ([`unmounted_folders`](super::lines::unmounted_folders)), so what lies
//! there when systemd mounts it cannot be read now, when a part of it cannot
//! be looked up, and when the lookup would mount an automount point.
//!
//! Of each such path that reads and is there, one `stat(2)` gives the file it
//! names, its device and inode ([`identify`]): the path holds no link, so the
//! `stat` follows none, and it changes no access time. A line that names the
//! file a loop device of the hidden root's stack reads, by any spelling of
//! its path, names the volume's own storage (see the `placed` module). A path
//! whose `stat` fails for another reason than that nothing is there cannot be
//! told either.

#[cfg(test)]
#[path = "paths_tests.rs"]
mod tests;

use super::lines::unmounted_folders;
use super::plain::{fuse_program, source};
use super::{DeviceMap, FileId, FileIds};
use crate::Filesystem;
use crate::blockdev::{OutOfDev, follow_in_dev};
use crate::crypttab::CrypttabEntry;
use crate::filesystem::MountRoot;
use crate::filesystem::mountinfo::MountEntry;
use crate::fstab::{FstabEntry, is_network_type, spec_device};
use crate::hidden_root::mount_holding;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// The paths the lines of the decoy's fstab and crypttab name ([`read_all`]),
/// by the path as the line writes it (an fstab line's first field, the
/// source of a FUSE line or its program, a crypttab line's source): each as
/// it reads, with no `.` or `..` in it, or why where it lies cannot be told.
pub type NamedPaths = BTreeMap<String, Result<PathBuf, UntoldPath>>;

/// Why where a path of the decoy's fstab or crypttab lies cannot be told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UntoldPath {
    /// This part of the path is a symbolic link, which is not followed.
    Link(PathBuf),
    /// The path is not absolute.
    Relative,
    /// The path is a device node.
    Device(PathBuf),
    /// The path crosses this folder, which a line of the fstab mounts, at
    /// boot or once a mount below it needs it, while that mount is not there
    /// now.
    Unmounted(PathBuf),
    /// The lookup would mount this automount point, which nothing is
    /// mounted on yet.
    Automount(PathBuf),
    /// This part of the path could not be looked up.
    Unreadable(PathBuf),
    /// This symbolic link, on the way of a device's path in `/dev` that no
    /// block device here answers to, written as that path or as a tag whose
    /// udev link it is, leads out of `/dev`, as one that a `tmpfiles.d` line
    /// makes at boot can: it is not followed, so nothing past `/dev` is
    /// looked up.
    LeavesDev(PathBuf),
    /// The path was not looked up.
    NotLookedUp,
}

impl UntoldPath {
    /// Why, as a phrase that completes "where it lies cannot be told:".
    pub fn reason(&self) -> String {
        match self {
            UntoldPath::Link(link) => format!(
                "{} is a symbolic link, which NAILS does not follow",
                link.display()
            ),
            UntoldPath::Relative => "it is no absolute path".to_string(),
            UntoldPath::Device(node) => format!("{} is a device node", node.display()),
            UntoldPath::Unmounted(folder) => format!(
                "a line of /etc/fstab mounts {}, and that mount is not there now",
                folder.display()
            ),
            UntoldPath::Automount(point) => format!(
                "the lookup would mount the automount point {}, which nothing is mounted on yet",
                point.display()
            ),
            UntoldPath::Unreadable(place) => {
                format!("{} on its way could not be looked up", place.display())
            }
            UntoldPath::LeavesDev(link) => format!(
                "{} is a symbolic link that leads out of /dev, which NAILS does not follow",
                link.display()
            ),
            UntoldPath::NotLookedUp => "it was not looked up".to_string(),
        }
    }
}

/// Whether the claims count the fstab line `entry`, one whose first field can
/// name local storage: every bind line, whatever its type (a `bind` or
/// `rbind` option, with a value too: `bind=x`), and every other line but one
/// of a RAM, kernel, host-share, network or overlay filesystem, which keeps
/// nothing on the decoy's disks. `_netdev` lets no line go: it only has
/// systemd mount the line after the network.
pub(super) fn is_claimed(entry: &FstabEntry) -> bool {
    entry.is_bind()
        || !(entry.is_virtual()
            || entry.is_host_share()
            || is_network_type(&entry.vfstype)
            || entry.vfstype == "overlay")
}

/// Whether `spec`, the first field of an fstab line or the source of a
/// crypttab line, is the path of a device in `/dev`, which no `..` in it
/// leads out of.
fn is_device_path(spec: &str) -> bool {
    spec.starts_with("/dev/")
        && !Path::new(spec)
            .components()
            .any(|part| part == Component::ParentDir)
}

/// The device's path in `/dev` that `spec`, the first field of an fstab
/// line or the source of a crypttab line or what it reads besides, names:
/// the path itself, or for a tag the link udev makes for it
/// ([`spec_device`]), where no `..` in it leads out of `/dev`
/// ([`is_device_path`]).
fn device_path(spec: &str) -> Option<PathBuf> {
    spec_device(spec).filter(|path| path.to_str().is_some_and(is_device_path))
}

/// Whether `spec`, the first field of an fstab line or the source of a
/// crypttab line, is the path of a file: an absolute path that is not the
/// path of a device in `/dev` ([`is_device_path`]), such as `//dev/sdb`, a
/// link to a device or a device node outside `/dev`, which [`read`] tells.
pub(super) fn is_file_path(spec: &str) -> bool {
    spec.starts_with('/') && !is_device_path(spec)
}

/// Whether `spec`, the first field of an fstab line or the source of a
/// crypttab line, leads into `/dev` as it is written ([`as_written`]), while
/// it is no device's path there ([`is_device_path`]): `//dev/sdb` and
/// `/dev/../dev/sdb` name `/dev/sdb`, which `mount` and `systemd-cryptsetup`
/// open, and NAILS reads a device only by its path in `/dev` or a tag.
pub(super) fn names_dev_otherwise(spec: &str) -> bool {
    is_file_path(spec) && as_written(Path::new(spec)).is_some_and(|path| path.starts_with("/dev"))
}

/// Whether the first field of the fstab line `entry`, or the source a FUSE
/// line gives its program ([`source`]), is the path of a file
/// ([`is_file_path`]): a swap file, an image file, or what a FUSE program
/// reads. A first field that is neither absolute nor a tag makes a line that
/// is not plain, unless its type names no local path by it (see the `plain`
/// module).
pub(super) fn names_a_file(entry: &FstabEntry) -> bool {
    source(entry).is_some_and(is_file_path)
}

/// The program `mount.fuse` runs for the fstab line `entry`
/// ([`fuse_program`]), when the line names it by an absolute path, which the
/// claims place the line by as well. A program with no `/` is the one `PATH`
/// finds, which names no path, and one with a `/` that is not absolute makes
/// a line that is not plain.
pub(super) fn program_path(entry: &FstabEntry) -> Option<&str> {
    fuse_program(entry).filter(|program| program.starts_with('/'))
}

/// Whether the crypttab line `entry` opens a file: its source is the path of
/// one ([`is_file_path`]), which `systemd-cryptsetup` opens through the links
/// in it, through a loop device for a regular file. A tag or a device's path
/// in `/dev` names a device instead.
pub(super) fn opens_a_file(entry: &CrypttabEntry) -> bool {
    is_file_path(&entry.source)
}

/// Whether the claims place the fstab line `entry` by the path it names,
/// which [`read`] reads: a bind line's source, or the path of a swap or image
/// file or of what a FUSE program reads.
pub(super) fn names_a_path(entry: &FstabEntry) -> bool {
    is_claimed(entry) && (entry.is_bind() || names_a_file(entry))
}

/// `path` as written, with no `.` or `..` in it, which is where it leads
/// while no part of it is a link: `None` for one that is not absolute.
pub(super) fn as_written(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() {
        return None;
    }
    let mut at = PathBuf::from("/");
    for part in path.components() {
        match part {
            Component::Normal(name) => at.push(name),
            Component::ParentDir => {
                at.pop();
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
    Some(at)
}

/// The paths the lines of `fstab` and `crypttab` name, by the path as it is
/// written, each read with [`read`] below `root`, the folders of the fstab's
/// lines that are not mounted now told by `mounts` and `devices`
/// ([`unmounted_folders`]): the path an fstab line names ([`names_a_path`],
/// [`source`]), the FUSE program it names by its path ([`program_path`]),
/// the file a crypttab line opens ([`opens_a_file`]), and a file it reads
/// besides, its key file, its header or what the boot mounts for one of
/// them ([`reads`](super::reads::reads)). A device's path in `/dev` that an
/// fstab line other than a bind line or a crypttab line names, for what it
/// opens or what it reads, by that path or by a tag ([`device_path`]), and
/// that no block device in `devices` answers to, is held as well, by the
/// spec as it is written, where it leads out of `/dev` or cannot be looked
/// up ([`leaving_dev`]).
pub(super) fn read_all<F: Filesystem>(
    fs: &F,
    mounts: &[MountEntry],
    root: &Path,
    fstab: &[FstabEntry],
    crypttab: &[CrypttabEntry],
    devices: &DeviceMap,
) -> NamedPaths {
    let unmounted = unmounted_folders(mounts, fstab, devices);
    let named = fstab
        .iter()
        .filter(|entry| names_a_path(entry))
        .filter_map(source)
        .chain(
            fstab
                .iter()
                .filter(|entry| is_claimed(entry))
                .filter_map(program_path),
        )
        .chain(
            crypttab
                .iter()
                .filter(|entry| opens_a_file(entry))
                .map(|entry| entry.source.as_str()),
        )
        .chain(crypttab_reads(crypttab).filter(|spec| is_file_path(spec)))
        .chain(fstab_option_reads(fstab).filter(|spec| is_file_path(spec)));
    let mut paths = NamedPaths::new();
    for path in named {
        paths
            .entry(path.to_string())
            .or_insert_with(|| read(fs, mounts, root, &unmounted, Path::new(path)));
    }
    // A device's path in /dev that no block device here answers to, by its
    // path or by a tag, of a line that is no bind line, or of a crypttab
    // line: the device names of the running system, as they are resolved.
    let unresolved = fstab
        .iter()
        .filter(|entry| is_claimed(entry) && !entry.is_bind())
        .filter_map(source)
        .chain(crypttab.iter().map(|entry| entry.source.as_str()))
        .chain(crypttab_reads(crypttab))
        .chain(fstab_option_reads(fstab))
        .filter(|spec| !devices.by_spec.contains_key(*spec))
        .filter_map(|spec| Some((spec, device_path(spec)?)));
    for (spec, path) in unresolved {
        if let Some(why) = leaving_dev(fs, &path) {
            paths.entry(spec.to_string()).or_insert(Err(why));
        }
    }
    paths
}

/// The file each path of `paths` that reads and is there names below `root`,
/// by the path as the line writes it, as one `stat(2)` of the path as it reads
/// gives its device and inode. The path holds no link, so the `stat` follows
/// none. A path whose `stat` fails for another reason than that nothing is
/// there cannot be told: it turns into [`UntoldPath::Unreadable`] in `paths`.
pub(super) fn identify<F: Filesystem>(fs: &F, root: &Path, paths: &mut NamedPaths) -> FileIds {
    let mut files = FileIds::new();
    for (spec, read) in paths.iter_mut() {
        let Ok(path) = read else {
            continue;
        };
        let on_disk = root.join(path.strip_prefix("/").unwrap_or(path));
        match identity(fs, &on_disk) {
            Ok(Some(file)) => {
                files.insert(spec.clone(), file);
            }
            Ok(None) => {}
            Err(_) => *read = Err(UntoldPath::Unreadable(path.clone())),
        }
    }
    files
}

/// The file at `path`, its device and inode as `stat(2)` gives them; `None`
/// where nothing is there.
fn identity<F: Filesystem>(fs: &F, path: &Path) -> crate::Result<Option<FileId>> {
    let Some(inode) = fs.inode(path)? else {
        return Ok(None);
    };
    Ok(Some(FileId {
        device: fs.device_id(path)?,
        inode,
    }))
}

/// The paths and tags the lines of `crypttab` read besides their sources
/// ([`reads`](super::reads::reads)).
pub(super) fn crypttab_reads(crypttab: &[CrypttabEntry]) -> impl Iterator<Item = &str> {
    crypttab
        .iter()
        .flat_map(|entry| super::reads::reads(entry).into_iter().map(|(_, spec)| spec))
}

/// The paths the options of the lines of `fstab` name
/// ([`fstab_reads`](super::reads::fstab_reads)), every line's.
pub(super) fn fstab_option_reads(fstab: &[FstabEntry]) -> impl Iterator<Item = &str> {
    fstab.iter().flat_map(|entry| {
        super::reads::fstab_reads(entry)
            .into_iter()
            .map(|(_, spec)| spec)
    })
}

/// Why where `path`, a device's path in `/dev` that no block device here
/// answers to, leads cannot be told, as [`follow_in_dev`] follows it: a link
/// on its way leads out of `/dev`, to a file, say, which is not followed, so
/// nothing past `/dev` is looked up, or a part of it cannot be looked up for
/// another reason than that it is not there. `None` for one that is not
/// there, as for a drive that is not plugged in, and for one that stays in
/// `/dev`.
fn leaving_dev<F: Filesystem>(fs: &F, path: &Path) -> Option<UntoldPath> {
    match follow_in_dev(fs, path) {
        Ok(_) | Err(OutOfDev::Missing) => None,
        Err(OutOfDev::Leaves(link)) => Some(UntoldPath::LeavesDev(link)),
        Err(OutOfDev::NotInDev) => Some(UntoldPath::LeavesDev(path.into())),
        Err(OutOfDev::Automount(point)) => Some(UntoldPath::Automount(point)),
        Err(OutOfDev::Unreadable(part)) => Some(UntoldPath::Unreadable(part)),
    }
}

/// Whether `spec`, a device's path in `/dev` or a tag that names one
/// ([`device_path`]) that no block device here answers to, cannot be told,
/// as [`read_all`] found ([`leaving_dev`]): the line is then placed by that
/// spec, as by a file's path.
pub(super) fn is_untold_device(paths: &NamedPaths, spec: &str) -> bool {
    device_path(spec).is_some() && matches!(paths.get(spec), Some(Err(_)))
}

/// Whether a lookup that reaches `path` makes the mount that holds it, as
/// `mounts` shows it, mount something: an automount point, unless `path` is
/// the directory of an indirect map, whose names the next part looks up.
fn would_mount(mounts: &[MountEntry], path: &Path) -> bool {
    mount_holding(mounts, path).is_some_and(|mount| {
        mount.fstype == "autofs"
            && (mount.mount_point != path
                || !mount
                    .super_opts
                    .split(',')
                    .any(|option| option == "indirect"))
    })
}

/// `path`, an absolute path of the system whose root is the folder `root`
/// (`/` for the running decoy), as it reads (see the module docs), with no
/// `.` or `..` in it, or why where it lies cannot be told. `mounts` is the
/// mount table of the running system, and `unmounted` holds the folders of
/// the fstab's lines, as they read with no `.` or `..` in them, whose mount
/// is not there now.
pub(super) fn read<F: Filesystem>(
    fs: &F,
    mounts: &[MountEntry],
    root: &Path,
    unmounted: &[PathBuf],
    path: &Path,
) -> Result<PathBuf, UntoldPath> {
    if !path.is_absolute() {
        return Err(UntoldPath::Relative);
    }
    let on_disk = |at: &Path| root.join(at.strip_prefix("/").unwrap_or(at));
    let mut at = PathBuf::from("/");
    // How many parts at the end of `at` are not there.
    let mut missing = 0_usize;
    for part in path.components() {
        match part {
            Component::Normal(name) => at.push(name),
            Component::ParentDir => {
                at.pop();
                missing = missing.saturating_sub(1);
                continue;
            }
            Component::RootDir | Component::CurDir | Component::Prefix(_) => continue,
        }
        if missing > 0 {
            missing += 1;
        } else {
            let place = on_disk(&at);
            if would_mount(mounts, &place) {
                return Err(UntoldPath::Automount(at));
            }
            match fs.mount_root(&place) {
                Ok(MountRoot::Link) => return Err(UntoldPath::Link(at)),
                Ok(MountRoot::Automount) => return Err(UntoldPath::Automount(at)),
                Ok(MountRoot::Entry(_)) => {}
                Err(error) if error.io_kind() == Some(std::io::ErrorKind::NotFound) => missing = 1,
                Err(_) => return Err(UntoldPath::Unreadable(at)),
            }
        }
        if unmounted.contains(&at) {
            return Err(UntoldPath::Unmounted(at));
        }
    }
    if missing == 0 {
        match fs.is_device_node(&on_disk(&at)) {
            Ok(false) => {}
            Ok(true) => return Err(UntoldPath::Device(at)),
            Err(_) => return Err(UntoldPath::Unreadable(at)),
        }
    }
    Ok(at)
}
