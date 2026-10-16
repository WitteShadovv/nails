// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decoy's mounts that the way back makes again.
//!
//! The way back mounts the decoy root device at `/run/nextroot`, and the
//! hidden session carries the decoy filesystems the fstab policy placed
//! ([`crate::whole_root::carry`]). A booted decoy has more mounts than one per
//! filesystem: binds the boot made of a directory of one of them, and mounts
//! stacked at one place. NixOS binds its store over itself, read-only,
//! `nosuid` and `nodev`, once the initrd has mounted it: a store on the root
//! filesystem is a bind of the root's `/nix/store`, and a store of its own (the
//! test VMs' overlay) gets the bind stacked on top of it. The decoy's own start
//! makes neither again, and neither a fresh boot nor a plain soft-reboot leaves
//! the decoy without them: after a session the store would be writable.
//!
//! [`record`] reads the decoy's tree at entry: every mount below the decoy
//! root, but the API filesystems below `/proc`, `/sys` and `/dev` (PID 1 moves
//! those into the next root itself), `/run` and what is below it (PID 1 and the
//! way back carry `/run` alone, as every soft-reboot into a new root does), and
//! the hidden volume. It keeps each mount whose filesystem the way back has,
//! the decoy root's or a carried one, through a directory that holds the
//! mount's own, on a parent it keeps too: its mount point, that directory, its
//! per-mount options and the ID that libmount's `utab` lines name it by, in the
//! order the decoy mounted them. The others it returns as lost, for the entry
//! to report: among them a bind of a file or directory that was deleted since
//! (the kernel shows its directory as `<path>//deleted`), and a mount on an
//! automount point, which the decoy's start sets up again as after a plain
//! soft-reboot. A mount the way back could not put anywhere is lost too: one
//! on a mount that does not come back, or a carried filesystem whose mount
//! point lies on such a mount.
//!
//! [`restore`] makes them again on the way back, once the decoy root is
//! mounted at `/run/nextroot` and before the decoy's userspace starts. It
//! first opens the directory of every one of them, looked up inside the decoy
//! root or the carried mount alone while nothing is mounted on either yet, so
//! a lookup never meets a mount the way back made a moment before: a store
//! path bound elsewhere lies below NixOS's store bind. It then binds each in
//! that order, with exactly its per-mount options. A lookup that would leave its mount
//! fails, and so does a carried mount that is no longer the one the entry
//! carried: the way back then fails rather than leave a mount out or put
//! another in its place. It records the ID each mount got, by which the
//! transition gives the decoy its `utab` lines back
//! ([`crate::whole_root::utab::restored_lines`]).
//!
//! Propagation needs no record: PID 1 makes every mount private before it
//! switches root, and the decoy's PID 1 marks the whole tree shared again, as
//! at boot. Two mounts that propagated to each other in the decoy (a bind made
//! after the boot and its source) no longer do after the way back.

use crate::mountinfo::{MountEntry, read_mountinfo, top_mount_at};
use crate::whole_root::nextroot;
use crate::whole_root::plan::{CarriedMount, DecoyMount, MountSource};
use std::collections::{HashMap, HashSet};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The trees below these mount points are not the decoy's own (see the
/// module docs).
const NOT_THE_TREE: [&str; 4] = ["/proc", "/sys", "/dev", "/run"];

/// What the kernel appends to the directory a mount shows once that file or
/// directory is deleted. A path it shows has no `//` otherwise.
const DELETED: &[u8] = b"//deleted";

/// Why the way back cannot make a decoy mount again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// Neither the decoy root nor a carried mount shows its directory: its
    /// filesystem is not one the session carries, or the session carries
    /// another mount of it that does not reach the directory.
    NoWayBack,
    /// The mount it sits on does not come back.
    ParentLost,
    /// It has a per-mount flag a remount cannot set (an idmapped mount).
    Options,
    /// The file or directory it shows was deleted.
    Deleted,
    /// It sits on an automount point: the decoy's start sets the automount
    /// up again, and the next access mounts it again.
    Automounted,
}

impl std::fmt::Display for Why {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Why::NoWayBack => "the session carries no mount that reaches its filesystem",
            Why::ParentLost => "the mount it sits on does not come back",
            Why::Options => "its mount options cannot be set again",
            Why::Deleted => "the file or directory it shows was deleted",
            Why::Automounted => {
                "it sits on an automount point, which the decoy's start sets up again"
            }
        })
    }
}

/// A decoy mount the way back cannot make again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lost {
    /// Its mount ID in the decoy at entry.
    pub id: i32,
    /// Its mount point in the decoy root.
    pub target: PathBuf,
    /// Its filesystem type, as the mount table shows it.
    pub fstype: String,
    /// Its source, as the mount table shows it.
    pub source: PathBuf,
    /// Why.
    pub why: Why,
}

impl Lost {
    /// Whether a process of the decoy serves it (FUSE) or PID 1 does (an
    /// automount point, and what an access mounted on one): it ends with the
    /// decoy's userspace anyway, and the decoy's start sets up what it needs
    /// again.
    pub fn ends_with_its_server(&self) -> bool {
        self.why == Why::Automounted
            || self.fstype == "fuse"
            || self.fstype.starts_with("fuse.")
            || self.fstype == "autofs"
    }
}

/// What [`record`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Record {
    /// The mounts the way back makes again, the decoy root first.
    pub mounts: Vec<DecoyMount>,
    /// The decoy's mounts it cannot make again, in the order of the mount
    /// table.
    pub lost: Vec<Lost>,
}

/// Whether the mount point `point`, as the decoy sees it, is in the decoy's
/// tree (see the module docs) given its hidden volume at `hidden_root`.
pub fn in_tree(point: &Path, hidden_root: &Path) -> bool {
    !point.starts_with(hidden_root) && !NOT_THE_TREE.iter().any(|api| point.starts_with(api))
}

/// The mounts below `root`, found by their parents, in the order of the
/// mount table but each after the mount it sits on.
fn below<'a>(mounts: &'a [MountEntry], root: &MountEntry) -> Vec<&'a MountEntry> {
    let mut placed = HashSet::from([root.mount_id]);
    let mut pending: Vec<&MountEntry> = mounts
        .iter()
        .filter(|m| m.mount_id != root.mount_id)
        .collect();
    let mut ordered = Vec::new();
    while let Some(next) = pending.iter().position(|m| placed.contains(&m.parent_id)) {
        let mount = pending.remove(next);
        placed.insert(mount.mount_id);
        ordered.push(mount);
    }
    ordered
}

/// Where the way back takes `mount` from, and its directory relative to the
/// one that source shows: the decoy root, else a carried mount of its
/// filesystem whose directory holds the mount's own.
fn source_of(
    mount: &MountEntry,
    root: &MountEntry,
    carried: &[CarriedMount],
) -> Option<(MountSource, PathBuf)> {
    let within = |dev: &str, shown: &Path| {
        (mount.dev == dev)
            .then(|| mount.root.strip_prefix(shown).ok())
            .flatten()
            .map(Path::to_path_buf)
    };
    if let Some(path) = within(&root.dev, &root.root) {
        return Some((MountSource::Root, path));
    }
    carried.iter().enumerate().find_map(|(index, carried)| {
        let path = within(carried.dev.as_deref()?, carried.root.as_deref()?)?;
        Some((MountSource::Carried(index), path))
    })
}

/// Why the way back cannot make `mount` again, as far as its own line and
/// the mounts kept before it tell, or `None`. `by_id` holds the mount table by
/// mount ID. The top mount at a carried mount point is kept even when the
/// mount below it is lost, as long as the mount the stack there sits on is
/// kept: the way back puts it back on what is there, as it did before
/// anything else was recorded.
fn why_lost(
    mount: &MountEntry,
    by_id: &HashMap<i32, &MountEntry>,
    kept: &HashSet<i32>,
    carried_tops: &[i32],
) -> Option<Why> {
    let on_kept = || {
        carried_tops.contains(&mount.mount_id)
            && stack_base(mount, by_id).is_some_and(|base| kept.contains(&base))
    };
    if mount.root.as_os_str().as_bytes().ends_with(DELETED) {
        Some(Why::Deleted)
    } else if by_id
        .get(&mount.parent_id)
        .is_some_and(|parent| parent.fstype == "autofs")
    {
        Some(Why::Automounted)
    } else if !kept.contains(&mount.parent_id) && !on_kept() {
        Some(Why::ParentLost)
    } else if nextroot::per_mount_flags(&mount.mount_opts).is_none() {
        Some(Why::Options)
    } else {
        None
    }
}

/// The ID of the mount that the stack at `mount`'s mount point sits on: the
/// one its mount point lies on.
fn stack_base(mount: &MountEntry, by_id: &HashMap<i32, &MountEntry>) -> Option<i32> {
    let mut current = mount;
    // No stack is higher than the table is long.
    for _ in 0..by_id.len() {
        let parent = by_id.get(&current.parent_id)?;
        if parent.mount_point != current.mount_point {
            return Some(parent.mount_id);
        }
        current = parent;
    }
    None
}

/// Record the decoy's mounts that the way back makes again, and those it
/// cannot (see the module docs). `mounts` is the decoy's mount table with its
/// mount points as the decoy sees them, `hidden_root` the hidden volume as the
/// decoy sees it, and `carried` what the session carries, each with the
/// filesystem and the directory its mount shows.
pub fn record(mounts: &[MountEntry], hidden_root: &Path, carried: &[CarriedMount]) -> Record {
    let Some(root) = top_mount_at(mounts, Path::new("/")) else {
        return Record::default();
    };
    let by_id: HashMap<i32, &MountEntry> = mounts.iter().map(|m| (m.mount_id, m)).collect();
    let mut record = Record::default();
    record.mounts.push(DecoyMount {
        id: root.mount_id,
        target: PathBuf::from("/"),
        source: MountSource::Root,
        path: PathBuf::new(),
        // Options a remount cannot set stay as the device mount gives them.
        options: nextroot::per_mount_flags(&root.mount_opts)
            .map(|_| root.mount_opts.clone())
            .unwrap_or_default(),
        restored: None,
    });
    let carried_tops: Vec<i32> = carried
        .iter()
        .filter_map(|carried| top_mount_at(mounts, &carried.target))
        .map(|mount| mount.mount_id)
        .collect();
    let mut kept = HashSet::from([root.mount_id]);
    for mount in below(mounts, root) {
        if !in_tree(&mount.mount_point, hidden_root) {
            continue;
        }
        let lost = |why| Lost {
            id: mount.mount_id,
            target: mount.mount_point.clone(),
            fstype: mount.fstype.clone(),
            source: mount.source.clone(),
            why,
        };
        match (
            why_lost(mount, &by_id, &kept, &carried_tops),
            source_of(mount, root, carried),
        ) {
            (Some(why), _) => record.lost.push(lost(why)),
            (None, None) => record.lost.push(lost(Why::NoWayBack)),
            (None, Some((source, path))) => {
                kept.insert(mount.mount_id);
                record.mounts.push(DecoyMount {
                    id: mount.mount_id,
                    target: mount.mount_point.clone(),
                    source,
                    path,
                    options: mount.mount_opts.clone(),
                    restored: None,
                });
            }
        }
    }
    record
}

/// `path`, absolute inside the root mounted at `nextroot`, seen from outside.
fn in_nextroot(nextroot: &Path, path: &Path) -> PathBuf {
    nextroot.join(path.strip_prefix("/").unwrap_or(path))
}

/// An error about the mount at `target`, with `e`'s kind.
fn about(target: &Path, e: impl std::fmt::Display, kind: io::ErrorKind) -> io::Error {
    io::Error::new(kind, format!("{}: {e}", target.display()))
}

/// The root of the carried mount `carried`, while the mount at its place is
/// still the one the entry carried: the top mount there, of the filesystem
/// and the directory recorded.
fn open_carried(carried: &CarriedMount, live: &[MountEntry]) -> io::Result<OwnedFd> {
    let place = std::fs::canonicalize(&carried.at).unwrap_or_else(|_| carried.at.clone());
    let same = top_mount_at(live, &place).is_some_and(|mount| {
        Some(&mount.dev) == carried.dev.as_ref() && Some(&mount.root) == carried.root.as_ref()
    });
    if !same {
        return Err(about(
            &carried.target,
            format!("the session no longer holds it at {}", carried.at.display()),
            io::ErrorKind::NotFound,
        ));
    }
    nextroot::open_mount_root(&place)
}

/// Whether `fd` is a directory.
fn is_dir(fd: &OwnedFd) -> io::Result<bool> {
    let stat = rustix::fs::fstat(fd).map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
    Ok(stat.st_mode & libc::S_IFMT == libc::S_IFDIR)
}

/// The directory `mount` shows, opened inside the decoy root `tree` or the
/// carried mount among `handles` alone ([`nextroot::open_in_mount`]), or
/// `None` for the decoy root itself, which is mounted already.
fn open_source(
    mount: &DecoyMount,
    tree: &OwnedFd,
    handles: &[Option<OwnedFd>],
) -> io::Result<Option<OwnedFd>> {
    if mount.target == Path::new("/") {
        return Ok(None);
    }
    let from = match mount.source {
        MountSource::Root => Some(tree),
        MountSource::Carried(index) => handles.get(index).and_then(Option::as_ref),
    }
    .ok_or_else(|| {
        about(
            &mount.target,
            "its carried filesystem is not in the plan",
            io::ErrorKind::NotFound,
        )
    })?;
    nextroot::open_in_mount(from, &mount.path)
        .map(Some)
        .map_err(|e| about(&mount.target, &e, e.kind()))
}

/// Give the decoy root at `nextroot` the options `mount` records for it, and
/// return its ID.
fn restore_root(mount: &DecoyMount, nextroot: &Path) -> io::Result<i32> {
    let root = |e: io::Error| about(Path::new("/"), &e, e.kind());
    if !mount.options.is_empty() {
        nextroot::set_per_mount_options(nextroot, &mount.options).map_err(root)?;
    }
    nextroot::mount_id_at(nextroot).map_err(root)
}

/// Make `mount` again at its place below `nextroot`, whose root is `tree`: a
/// bind of `source`, the directory it shows, with its options. Returns the
/// new mount's ID.
fn make_again(
    mount: &DecoyMount,
    source: &OwnedFd,
    tree: &OwnedFd,
    nextroot: &Path,
) -> io::Result<i32> {
    let kind = |e: io::Error| about(&mount.target, &e, e.kind());
    // The mount point is the decoy's own and must be there already, reached
    // without a symlink and of the kind the source is: nothing is created in
    // the decoy root, and nothing is mounted outside it.
    let point = nextroot::open_in_tree(tree, &mount.target).map_err(kind)?;
    if is_dir(&point).map_err(kind)? != is_dir(source).map_err(kind)? {
        return Err(about(
            &mount.target,
            "the mount point is not of the kind of what is mounted on it",
            io::ErrorKind::InvalidData,
        ));
    }
    let target = in_nextroot(nextroot, &mount.target);
    let source_path = PathBuf::from(format!("/proc/self/fd/{}", source.as_raw_fd()));
    nextroot::bind(&source_path, &target, false).map_err(kind)?;
    // By its path, which ends on the mount just made.
    nextroot::set_per_mount_options(&target, &mount.options).map_err(kind)?;
    nextroot::mount_id_at(&target).map_err(kind)
}

/// Make the recorded `mounts` again below `nextroot`, where the decoy root
/// is mounted already (the record of `/`, which only gets its options), and
/// record the ID each one got. Every directory is opened before anything is
/// mounted (see the module docs). On an error the mounts made so far stay:
/// the caller detaches the whole tree.
pub fn restore(
    mounts: &mut [DecoyMount],
    carried: &[CarriedMount],
    nextroot: &Path,
) -> io::Result<()> {
    for mount in mounts.iter_mut() {
        mount.restored = None;
    }
    let live = read_mountinfo()?;
    let tree = nextroot::open_mount_root(nextroot)?;
    let mut handles = Vec::with_capacity(carried.len());
    for (index, held) in carried.iter().enumerate() {
        let used = mounts
            .iter()
            .any(|mount| mount.source == MountSource::Carried(index));
        handles.push(if used {
            Some(open_carried(held, &live)?)
        } else {
            None
        });
    }
    let sources = mounts
        .iter()
        .map(|mount| open_source(mount, &tree, &handles))
        .collect::<io::Result<Vec<_>>>()?;
    for (mount, source) in mounts.iter_mut().zip(&sources) {
        let id = match source {
            None => restore_root(mount, nextroot)?,
            Some(source) => make_again(mount, source, &tree, nextroot)?,
        };
        mount.restored = Some(id);
    }
    Ok(())
}

#[cfg(test)]
#[path = "decoy_mounts_tests.rs"]
mod tests;
