// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The paths the decoy's fstab names, a bind line's source and the path of a
//! swap or image file, read as they are written: no link in them is followed.
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
//! is a symbolic link, which the boot's `mount` or `swapon` would follow,
//! when it is not absolute, when it is a device node, which they would use
//! as the device it is, when it crosses the folder of an fstab line that the
//! boot mounts while that line's mount is not there now
//! ([`unmounted_boot_folders`](super::lines::unmounted_boot_folders)), so
//! what lies there at boot cannot be read now, when a part of it cannot be
//! looked up, and when the lookup would mount an automount point.

#[cfg(test)]
#[path = "paths_tests.rs"]
mod tests;

use super::DeviceMap;
use super::lines::unmounted_boot_folders;
use crate::Filesystem;
use crate::filesystem::MountRoot;
use crate::filesystem::mountinfo::MountEntry;
use crate::fstab::FstabEntry;
use crate::hidden_root::mount_holding;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

/// The paths the lines of the decoy's fstab name ([`names_a_path`]), by the
/// line's first field as it is written: each as it reads, with no `.` or
/// `..` in it, or why where it lies cannot be told.
pub type NamedPaths = BTreeMap<String, Result<PathBuf, UntoldPath>>;

/// Why where a path of the decoy's fstab lies cannot be told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UntoldPath {
    /// This part of the path is a symbolic link, which is not followed.
    Link(PathBuf),
    /// The path is not absolute.
    Relative,
    /// The path is a device node.
    Device(PathBuf),
    /// The path crosses this folder, which a line of the fstab mounts at
    /// boot while that mount is not there now.
    Unmounted(PathBuf),
    /// The lookup would mount this automount point, which nothing is
    /// mounted on yet.
    Automount(PathBuf),
    /// This part of the path could not be looked up.
    Unreadable(PathBuf),
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
                "a line of /etc/fstab mounts {} at boot, and that mount is not there now",
                folder.display()
            ),
            UntoldPath::Automount(point) => format!(
                "the lookup would mount the automount point {}, which nothing is mounted on yet",
                point.display()
            ),
            UntoldPath::Unreadable(place) => {
                format!("{} on its way could not be looked up", place.display())
            }
            UntoldPath::NotLookedUp => "it was not looked up".to_string(),
        }
    }
}

/// Whether the claims count the fstab line `entry`: no RAM, kernel,
/// host-share, network or overlay filesystem, which keeps nothing on the
/// decoy's disks.
pub(super) fn is_claimed(entry: &FstabEntry) -> bool {
    !(entry.is_virtual()
        || entry.is_host_share()
        || entry.is_network()
        || entry.vfstype == "overlay")
}

/// Filesystem types that `mount` reads from a block device, or through a
/// loop device from an image file, as a first field that is a path names it.
const BLOCK_TYPES: &[&str] = &[
    "auto", "bcachefs", "btrfs", "erofs", "exfat", "ext2", "ext3", "ext4", "f2fs", "hfs",
    "hfsplus", "iso9660", "jfs", "minix", "msdos", "nilfs2", "ntfs", "ntfs3", "reiserfs",
    "squashfs", "udf", "ufs", "vfat", "xfs",
];

/// Whether `spec`, the first field of an fstab line, is the path of a device
/// in `/dev`, which no `..` in it leads out of.
fn is_device_path(spec: &str) -> bool {
    spec.starts_with("/dev/")
        && !Path::new(spec)
            .components()
            .any(|part| part == Component::ParentDir)
}

/// Whether `spec`, the first field of an fstab line, names a device by a
/// tag: `UUID=`, `LABEL=` and the like.
fn is_tag(spec: &str) -> bool {
    spec.split_once('=')
        .is_some_and(|(key, _)| !key.is_empty() && key.bytes().all(|b| b.is_ascii_uppercase()))
}

/// Whether the first field of the fstab line `entry` is the path of a file:
/// a swap file or an image file. That is an absolute path that is not the
/// path of a device in `/dev` ([`is_device_path`]), and for a swap line, a
/// `loop` line or a line of a filesystem type `mount` reads from a device or
/// an image file, any first field that is neither a device's path nor a tag,
/// which `swapon` and `mount` look up from the folder they run in.
pub(super) fn names_a_file(entry: &FstabEntry) -> bool {
    let spec = entry.spec.as_str();
    if is_device_path(spec) || is_tag(spec) {
        return false;
    }
    spec.starts_with('/')
        || entry.is_swap()
        || entry
            .options
            .iter()
            .any(|option| option == "loop" || option.starts_with("loop="))
        || BLOCK_TYPES.contains(&entry.vfstype.as_str())
}

/// Whether the claims place the fstab line `entry` by the path it names,
/// which [`read`] reads: a bind line's source, or the path of a swap or image
/// file.
pub(super) fn names_a_path(entry: &FstabEntry) -> bool {
    is_claimed(entry) && (entry.is_bind() || names_a_file(entry))
}

/// `spec` as the path it names, as written, with no `.` or `..` in it: `None`
/// for one that is not absolute.
pub(super) fn as_written(spec: &str) -> Option<PathBuf> {
    let path = Path::new(spec);
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

/// The paths the lines of `fstab` name ([`names_a_path`]), each read with
/// [`read`] below `root`, the folders the boot mounts that are not mounted
/// now told by `mounts` and `devices` ([`unmounted_boot_folders`]).
pub(super) fn read_all<F: Filesystem>(
    fs: &F,
    mounts: &[MountEntry],
    root: &Path,
    fstab: &[FstabEntry],
    devices: &DeviceMap,
) -> NamedPaths {
    let unmounted = unmounted_boot_folders(mounts, fstab, devices);
    let mut paths = NamedPaths::new();
    for entry in fstab.iter().filter(|entry| names_a_path(entry)) {
        paths
            .entry(entry.spec.clone())
            .or_insert_with(|| read(fs, mounts, root, &unmounted, Path::new(&entry.spec)));
    }
    paths
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
/// mount table of the running system, and `unmounted` holds the folders,
/// as the fstab writes them, that the boot mounts while their mount is not
/// there now.
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
