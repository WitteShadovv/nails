// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where the paths of the decoy's fstab lead: a bind line's source, and the
//! path of a swap or image file, followed through their links as `mount` and
//! `swapon` follow them.
//!
//! The lookup goes one place at a time through the [`Filesystem`] trait, as
//! the kernel's own does: each place is asked about with one `statx` that
//! follows no link and mounts nothing there ([`Filesystem::mount_root`]), a
//! link is read ([`Filesystem::read_link`]) and its target looked up from the
//! folder the link lies in, or from the root for an absolute one, and `..`
//! goes up from the place reached so far. Reading a link can change its
//! access time, as the boot's own `mount` does. Before each place, the mount
//! table is asked whether a lookup there would mount an automount point that
//! nothing is mounted on yet, and such a lookup is not made.
//!
//! A place that is not there ends the lookup: no link leads on from it, so
//! the rest of the path stays as written. Where a path leads cannot be told
//! ([`Unfollowed`]) when a link on the way leads to nothing, when the links
//! go round (more than the kernel follows in one lookup), when a place on the
//! way cannot be looked up or its link not read, when the lookup would mount
//! an automount point, and for a path that is not absolute.

#[cfg(test)]
#[path = "paths_tests.rs"]
mod tests;

use crate::Filesystem;
use crate::filesystem::MountRoot;
use crate::filesystem::mountinfo::MountEntry;
use crate::fstab::FstabEntry;
use crate::hidden_root::mount_holding;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// The kernel's limit on the links one lookup follows (`MAXSYMLINKS`).
const MAX_LINKS: usize = 40;

/// Where each path of the decoy's fstab that [`names_a_path`] leads, by the
/// line's first field as it is written.
pub type FollowedPaths = BTreeMap<String, Result<PathBuf, Unfollowed>>;

/// Why where a path of the decoy's fstab leads cannot be told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unfollowed {
    /// The link at this path, on the way, leads to nothing.
    Dangling(PathBuf),
    /// The links on the way go round, or are more than the kernel follows
    /// in one lookup.
    Loop,
    /// This place on the way could not be looked up, or its link not read.
    Unreadable(PathBuf),
    /// The lookup would mount this automount point, which nothing is
    /// mounted on yet.
    Automount(PathBuf),
    /// The path is not absolute.
    Relative,
    /// The path was not looked up.
    NotLookedUp,
}

impl Unfollowed {
    /// Why, as a phrase that completes "where it leads cannot be told:".
    pub fn reason(&self) -> String {
        match self {
            Unfollowed::Dangling(link) => format!("the link {} leads to nothing", link.display()),
            Unfollowed::Loop => {
                "the links on its way go round, or are more than the kernel follows".to_string()
            }
            Unfollowed::Unreadable(place) => {
                format!("{} on its way could not be looked up", place.display())
            }
            Unfollowed::Automount(point) => format!(
                "the lookup would mount the automount point {}, which nothing is mounted on yet",
                point.display()
            ),
            Unfollowed::Relative => "it is no absolute path".to_string(),
            Unfollowed::NotLookedUp => "it was not looked up".to_string(),
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

/// Whether the first field of an fstab line is the path of a file, outside
/// `/dev`: a swap file or an image file.
pub(super) fn is_file_spec(spec: &str) -> bool {
    spec.starts_with('/') && !spec.starts_with("/dev/")
}

/// Whether the claims place the fstab line `entry` by the path it names,
/// which [`follow`] looks up: a bind line's source, or the path of a swap or
/// image file.
pub(super) fn names_a_path(entry: &FstabEntry) -> bool {
    is_claimed(entry) && (entry.is_bind() || is_file_spec(&entry.spec))
}

/// Where each path the lines of `fstab` name leads ([`names_a_path`]),
/// looked up with [`follow`].
pub(super) fn follow_all<F: Filesystem>(
    fs: &F,
    mounts: &[MountEntry],
    root: &Path,
    fstab: &[FstabEntry],
) -> FollowedPaths {
    let mut followed = FollowedPaths::new();
    for entry in fstab.iter().filter(|entry| names_a_path(entry)) {
        followed
            .entry(entry.spec.clone())
            .or_insert_with(|| follow(fs, mounts, root, Path::new(&entry.spec)));
    }
    followed
}

/// One step of a lookup.
enum Step {
    /// Into the entry of this name, written by the path or by the target of
    /// the link given.
    Into(OsString, Option<PathBuf>),
    /// Up to the parent, for `..`.
    Up,
}

/// Put the steps of `path` on `steps`, its first step last, so that they are
/// taken from the end in order. `link` is the link whose target `path` is.
fn push_steps(steps: &mut Vec<Step>, path: &Path, link: Option<&Path>) {
    for component in path.components().rev() {
        match component {
            Component::Normal(name) => {
                steps.push(Step::Into(name.to_os_string(), link.map(Path::to_path_buf)));
            }
            Component::ParentDir => steps.push(Step::Up),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
}

/// Whether a lookup that reaches `path` makes the mount that holds it, as
/// `mounts` shows it, mount something: an automount point, unless `path` is
/// the directory of an indirect map, whose names the next step looks up.
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

/// Where `path`, an absolute path of the system whose root is the folder
/// `root` (`/` for the running decoy), leads (see the module docs): the
/// place a lookup that follows its links reaches, as seen from `root`, with
/// no link and no `..` in it. `mounts` is the mount table of the running
/// system.
pub(super) fn follow<F: Filesystem>(
    fs: &F,
    mounts: &[MountEntry],
    root: &Path,
    path: &Path,
) -> Result<PathBuf, Unfollowed> {
    if !path.is_absolute() {
        return Err(Unfollowed::Relative);
    }
    let mut steps = Vec::new();
    push_steps(&mut steps, path, None);
    let mut at = PathBuf::from("/");
    let mut links = 0;
    while let Some(step) = steps.pop() {
        let (name, from_link) = match step {
            Step::Into(name, from_link) => (name, from_link),
            Step::Up => {
                at.pop();
                continue;
            }
        };
        let next = at.join(&name);
        let on_disk = root.join(next.strip_prefix("/").unwrap_or(&next));
        if would_mount(mounts, &on_disk) {
            return Err(Unfollowed::Automount(next));
        }
        match fs.mount_root(&on_disk) {
            Ok(MountRoot::Link) => {
                links += 1;
                if links > MAX_LINKS {
                    return Err(Unfollowed::Loop);
                }
                let target = fs
                    .read_link(&on_disk)
                    .map_err(|_| Unfollowed::Unreadable(next.clone()))?;
                if target.is_absolute() {
                    at = PathBuf::from("/");
                }
                push_steps(&mut steps, &target, Some(&next));
            }
            Ok(MountRoot::Automount) => return Err(Unfollowed::Automount(next)),
            Ok(MountRoot::Entry(_)) => at = next,
            Err(error) if error.io_kind() == Some(std::io::ErrorKind::NotFound) => {
                // A link whose target is not there leads to nothing. Where
                // the path itself names a place that is not there, no link
                // leads on from it: the rest stays as written.
                if let Some(link) = from_link {
                    return Err(Unfollowed::Dangling(link));
                }
                let mut rest = next;
                while let Some(step) = steps.pop() {
                    match step {
                        Step::Into(name, _) => rest.push(name),
                        Step::Up => {
                            rest.pop();
                        }
                    }
                }
                return Ok(rest);
            }
            Err(_) => return Err(Unfollowed::Unreadable(next)),
        }
    }
    Ok(at)
}
