// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a line of the decoy's fstab mounts: whether a mount is one the decoy
//! makes itself, at `/` or by a line ([`decoys_own_mount`]), what of a
//! filesystem a device line mounts, as its options name it and as the mount
//! it made shows it, and how a mount shows its filesystem ([`sharing`]).

use super::{Scene, Sharing};
use crate::filesystem::mountinfo::{MountEntry, top_mount_at};
use crate::fstab::FstabEntry;
use crate::hidden_root::mount_holding;
use std::path::{Component, Path, PathBuf};

/// How a mount shows its filesystem: its root inside the filesystem tells a
/// bind of a folder from the filesystem itself, and on btrfs a subvolume
/// (`subvol=` names the mount's root) from a bind.
pub fn sharing(mount: &MountEntry) -> Sharing {
    let root = mount.root.to_string_lossy();
    if root == "/" {
        return Sharing::Filesystem;
    }
    if mount.fstype == "btrfs" && mount_option(mount, "subvol") == Some(root.as_ref()) {
        Sharing::Subvolume
    } else {
        Sharing::Bind
    }
}

/// Whether `mount`, a mount of the filesystem that `hidden` (the visible
/// mount at the hidden root) shows, is one the decoy makes itself: the one at
/// `/`, or one that a line of its fstab makes. Such a line is for `mount`'s
/// mount point and of a kind the claims count (no swap, RAM, kernel,
/// host-share, network or overlay line), and `mount` shows what it mounts:
///
/// - A device line names the device `mount` is on, or another device of its
///   btrfs filesystem, and `mount` shows what the line mounts: the
///   filesystem's top for a line with neither `subvol=` nor `subvolid=`, and
///   otherwise the btrfs subvolume that each of these names, the id as the
///   mount table shows it. Never a folder bound there, no subvolume whose id
///   cannot be read, and nothing of a line whose text does not tell its
///   subvolume (an option given twice, a `..` in its path). A spec that leads
///   to no device here names none, unless `mount` shows no device either, as
///   a ZFS dataset does: then the spec is `mount`'s source and the line's
///   type its type.
/// - A bind line's source lies on another mount of that filesystem than
///   `hidden`, one of the decoy's own itself, and `mount` shows the folder of
///   it that the source names.
///
/// So the fstab makes none of these: a filesystem mounted at a folder that a
/// line names for another device, in place of that device's mount or over
/// it, a folder bound by hand where a line mounts the same filesystem, and
/// the copy that mount propagation makes, at a bind line's mount point, of a
/// mount at or below its source.
pub fn decoys_own_mount(scene: &Scene<'_>, mount: &MountEntry, hidden: &MountEntry) -> bool {
    // A chain of bind lines is no longer than the fstab.
    decoys_own(scene, mount, hidden, scene.fstab.len())
}

/// [`decoys_own_mount`], following bind lines `depth` deep at most.
fn decoys_own(scene: &Scene<'_>, mount: &MountEntry, hidden: &MountEntry, depth: usize) -> bool {
    if mount.mount_point == Path::new("/") {
        return true;
    }
    let devices = scene.devices;
    let node = devices.node_of_mount(mount);
    scene
        .fstab
        .iter()
        .filter(|entry| entry.file == mount.mount_point)
        .filter(|entry| mounts_storage(entry))
        .any(|entry| {
            if entry.is_bind() {
                return depth > 0 && bind_makes(scene, entry, mount, hidden, depth - 1);
            }
            let named = match (devices.node_of_spec(&entry.spec), node) {
                (Some(named), Some(node)) => named == node || devices.same_btrfs(named, node),
                // A filesystem with no device, such as a ZFS dataset, is
                // named by its source.
                (None, None) => {
                    entry.vfstype == mount.fstype
                        && Path::new(&entry.spec) == mount.source.as_path()
                }
                _ => false,
            };
            named && shows_what_it_mounts(entry, mount)
        })
}

/// Whether the bind line `entry` makes `mount`: its source lies on a mount of
/// the same filesystem, neither `hidden` nor `mount` itself, that is one of
/// the decoy's own, and `mount` shows the folder of it the source names.
fn bind_makes(
    scene: &Scene<'_>,
    entry: &FstabEntry,
    mount: &MountEntry,
    hidden: &MountEntry,
    depth: usize,
) -> bool {
    let source = Path::new(&entry.spec);
    let Some(holder) = mount_holding(scene.mounts, source) else {
        return false;
    };
    let Ok(below) = source.strip_prefix(&holder.mount_point) else {
        return false;
    };
    holder.mount_id != hidden.mount_id
        && holder.mount_id != mount.mount_id
        && holder.dev == mount.dev
        && mount.root == holder.root.join(below)
        && decoys_own(scene, holder, hidden, depth)
}

/// Whether the fstab line `entry` mounts a filesystem the claims count: no
/// swap, RAM, kernel, host-share, network or overlay line.
fn mounts_storage(entry: &FstabEntry) -> bool {
    !(entry.is_swap()
        || entry.is_virtual()
        || entry.is_host_share()
        || entry.is_network()
        || entry.vfstype == "overlay")
}

/// Whether `mount` shows what the device line `entry` mounts: the
/// filesystem's top for a line with neither `subvol=` nor `subvolid=`, and
/// otherwise the btrfs subvolume that each of these it gives names. A folder
/// bound there is none of these, and neither is a subvolume whose id cannot
/// be read from the line or from the mount table, which shows it in the
/// mount's options, nor what a line mounts whose subvolume its text does not
/// tell ([`named_subvolume`]).
fn shows_what_it_mounts(entry: &FstabEntry, mount: &MountEntry) -> bool {
    let Some((path, id)) = named_subvolume(entry) else {
        return false;
    };
    if path.is_none() && id.is_none() {
        return mount.root == Path::new("/");
    }
    mount.fstype == "btrfs"
        && sharing(mount) != Sharing::Bind
        && path.is_none_or(|path| mount.root == Path::new("/").join(path.trim_start_matches('/')))
        && id.is_none_or(|id| {
            matches!(
                (subvolume_id(id), mount_option(mount, "subvolid").and_then(subvolume_id)),
                (Some(named), Some(shown)) if named == shown
            )
        })
}

/// The `subvol=` path and the `subvolid=` value the device line `entry`
/// gives, each `None` when it gives none. `None` when its text does not tell
/// which subvolume btrfs mounts for it: when it gives either option twice
/// (btrfs takes the last, so the line can name another subvolume than the
/// one it mounts), or a path with a `..` in it, which btrfs follows.
fn named_subvolume(entry: &FstabEntry) -> Option<(Option<&str>, Option<&str>)> {
    let path = only_value(entry, "subvol")?;
    let id = only_value(entry, "subvolid")?;
    let upward = path.is_some_and(|path| {
        Path::new(path)
            .components()
            .any(|part| part == Component::ParentDir)
    });
    (!upward).then_some((path, id))
}

/// The value of the option `key=` of `entry`: `Some(None)` when it gives
/// none, and `None` when it gives it more than once.
fn only_value<'a>(entry: &'a FstabEntry, key: &str) -> Option<Option<&'a str>> {
    let mut values = entry
        .options
        .iter()
        .filter_map(|option| option.strip_prefix(key)?.strip_prefix('='));
    let first = values.next();
    values.next().is_none().then_some(first)
}

/// The subvolume a `subvolid=` option names, as btrfs reads it: `0` names
/// the top, whose id is 5. None for anything but a plain decimal number,
/// which btrfs could read in another way (a leading `0` as octal, say).
fn subvolume_id(value: &str) -> Option<u64> {
    let plain =
        value.bytes().all(|b| b.is_ascii_digit()) && (value == "0" || !value.starts_with('0'));
    let id: u64 = value.parse().ok().filter(|_| plain)?;
    Some(if id == 0 { 5 } else { id })
}

/// Whether the device line `entry`, one that names a device of the
/// filesystem of `hidden` (the visible mount at the hidden root), mounts the
/// volume or a part of it: any line does for a root that is the whole
/// filesystem, and for a root that is a folder or a btrfs subvolume of it, a
/// line whose subvolume is that one or lies inside it. `Some(false)` for a
/// line that mounts another part of the filesystem the root is part of: its
/// top, or a subvolume above or beside the root's. `None` when what the line
/// mounts cannot be told ([`line_shows`]).
pub(super) fn mounts_the_root(
    scene: &Scene<'_>,
    entry: &FstabEntry,
    hidden: &MountEntry,
) -> Option<bool> {
    if sharing(hidden) == Sharing::Filesystem {
        return Some(true);
    }
    line_shows(scene, entry, hidden).map(|shown| shown.starts_with(&hidden.root))
}

/// The path in the filesystem of `hidden` that the device line `entry`
/// mounts, as the mount table writes a mount's root: `/`, the top, for a
/// line with neither `subvol=` nor `subvolid=`, as [`shows_what_it_mounts`]
/// takes it, and otherwise the btrfs subvolume these name, an id by the path
/// that a mount of that filesystem with that id shows. `None` when that
/// cannot be told: an id that is no plain number or that no such mount
/// shows, options that name two subvolumes, a line whose text does not tell
/// its subvolume ([`named_subvolume`]), or either option on a filesystem that
/// is not btrfs. Only a mount shows how btrfs read a line (a link in its
/// path, a subvolume set as the default), so the decoy's own line for a
/// folder is told by the mount at that folder as well ([`line_is_mounted`]).
fn line_shows(scene: &Scene<'_>, entry: &FstabEntry, hidden: &MountEntry) -> Option<PathBuf> {
    let (path, id) = named_subvolume(entry)?;
    if path.is_none() && id.is_none() {
        return Some(PathBuf::from("/"));
    }
    if hidden.fstype != "btrfs" {
        return None;
    }
    let by_path = path.map(|path| Path::new("/").join(path.trim_start_matches('/')));
    let by_id = match id {
        Some(id) => Some(subvolume_path(scene, hidden, subvolume_id(id)?)?),
        None => None,
    };
    match (by_path, by_id) {
        (Some(path), Some(id)) => (path == id).then_some(path),
        (path, id) => path.or(id),
    }
}

/// The path of the btrfs subvolume with the id `id` in the filesystem of
/// `hidden`, as a mount of that filesystem at that subvolume shows it in the
/// mount table: `/` for the top, whose id is 5.
fn subvolume_path(scene: &Scene<'_>, hidden: &MountEntry, id: u64) -> Option<PathBuf> {
    if id == 5 {
        return Some(PathBuf::from("/"));
    }
    scene
        .mounts
        .iter()
        .filter(|mount| {
            mount.dev == hidden.dev
                && mount.fstype == "btrfs"
                && sharing(mount) == Sharing::Subvolume
        })
        .find(|mount| mount_option(mount, "subvolid").and_then(subvolume_id) == Some(id))
        .map(|mount| mount.root.clone())
}

/// The value of the option `key=` of `mount`, from its filesystem's options
/// or its own.
fn mount_option<'a>(mount: &'a MountEntry, key: &str) -> Option<&'a str> {
    mount
        .super_opts
        .split(',')
        .chain(mount.mount_opts.split(','))
        .find_map(|opt| opt.strip_prefix(key)?.strip_prefix('='))
}

/// Whether a line of the decoy's fstab mounts the filesystem of `hidden`,
/// whose device is `top`, at `at`: a line for that mount point, of a kind
/// the claims count, whose spec names `top` or another device of its btrfs
/// filesystem, or for a filesystem with no device, such as a ZFS dataset, is
/// `hidden`'s source. A claim through a bind line, or through a mount at `/`
/// or at a system folder that no line names, has none.
pub(super) fn in_fstab(
    scene: &Scene<'_>,
    hidden: &MountEntry,
    top: Option<&str>,
    at: &Path,
) -> bool {
    let devices = scene.devices;
    scene
        .fstab
        .iter()
        .filter(|entry| entry.file == at && !entry.is_bind() && mounts_storage(entry))
        .any(|entry| match (devices.node_of_spec(&entry.spec), top) {
            (Some(named), Some(top)) => named == top || devices.same_btrfs(named, top),
            (None, None) => Path::new(&entry.spec) == hidden.source.as_path(),
            _ => false,
        })
}

/// Whether the device line `entry` for the filesystem of `hidden` (the
/// visible mount at the hidden root) is mounted now, as the mount at its
/// folder shows: the visible mount there is of that filesystem and shows what
/// the line names ([`shows_what_it_mounts`]), a btrfs line with neither
/// `subvol=` nor `subvolid=` read as one for the top. So a mount made there
/// by hand that shows the same counts as the line's own. A line whose mount
/// shows something else, as for a `subvol=` path through a link, is not
/// mounted, and neither is a drive mounted only at the root, a line whose
/// automount was never reached, or one unmounted since.
pub(super) fn line_is_mounted(scene: &Scene<'_>, entry: &FstabEntry, hidden: &MountEntry) -> bool {
    top_mount_at(scene.mounts, &entry.file)
        .is_some_and(|mount| mount.dev == hidden.dev && shows_what_it_mounts(entry, mount))
}
