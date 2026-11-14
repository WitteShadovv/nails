// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where a path in `/dev` leads, read without leaving `/dev`.
//!
//! udev's names for a device are symbolic links in `/dev` (`/dev/mapper/data`,
//! `/dev/disk/by-uuid/…`) that lead to the device's own node there. A link in
//! `/dev` may lead out of it as well, as one that a `tmpfiles.d` line makes at
//! boot can, to a file on the decoy's disk, say. [`follow_in_dev`] follows the
//! links of a path in `/dev` one part at a time, only while each leads to a
//! path in `/dev`, and stops at the first one that leads out: it makes no
//! lookup past `/dev`, so it reads no link and changes no access time on a
//! disk, and mounts nothing there.

use crate::Filesystem;
use crate::filesystem::MountRoot;
use std::collections::VecDeque;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// The most links [`follow_in_dev`] follows, the kernel's own limit for one
/// lookup.
const MAX_LINKS: usize = 40;

/// Why a path in `/dev` leads to no path in `/dev`, as [`follow_in_dev`]
/// follows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutOfDev {
    /// The path is not in `/dev` as it is written, or a `..` in it leads out.
    NotInDev,
    /// This symbolic link on its way leads out of `/dev`, and is not followed.
    Leaves(PathBuf),
    /// A part of it is not there, or below a part that is no folder.
    Missing,
    /// The lookup of this part would mount an automount point nothing is
    /// mounted on yet, and is not made.
    Automount(PathBuf),
    /// This part could not be looked up or its link read, or the path has
    /// more links on its way than a lookup follows.
    Unreadable(PathBuf),
}

/// One part of a path still to be followed.
enum Part {
    /// A name to look up below where the walk is.
    Name(OsString),
    /// `..`: back up one part, the parent of where the walk is.
    Up,
}

/// The parts of `path` to follow, `.` and the root left out.
fn parts(path: &Path) -> impl DoubleEndedIterator<Item = Part> + '_ {
    path.components().filter_map(|component| match component {
        Component::Normal(name) => Some(Part::Name(name.to_os_string())),
        Component::ParentDir => Some(Part::Up),
        Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
    })
}

/// Where `path`, a path in `/dev`, leads: the path in `/dev` it names, with no
/// link in it, or why it leads to none. From `/` down, each part is looked at
/// on its own with one `statx` that follows no link and mounts nothing
/// ([`Filesystem::mount_root`]); a link there is read and its target followed
/// from the link's folder, or from `/` when it is absolute, and `..` goes back
/// up one part of where the walk is, as the kernel's lookup goes. A part that
/// would lie outside `/dev` is never looked at: the walk stops there, at the
/// last link it followed, which leads out of `/dev`
/// ([`OutOfDev::Leaves`]).
pub fn follow_in_dev<F: Filesystem>(fs: &F, path: &Path) -> Result<PathBuf, OutOfDev> {
    if !path.starts_with("/dev") {
        return Err(OutOfDev::NotInDev);
    }
    let mut at = PathBuf::from("/");
    let mut rest: VecDeque<Part> = parts(path).collect();
    let mut links = 0_usize;
    let mut last_link: Option<PathBuf> = None;
    let leaves =
        |last_link: Option<PathBuf>| last_link.map_or(OutOfDev::NotInDev, OutOfDev::Leaves);
    while let Some(part) = rest.pop_front() {
        let name = match part {
            Part::Up => {
                at.pop();
                continue;
            }
            Part::Name(name) => name,
        };
        let next = at.join(&name);
        if !next.starts_with("/dev") {
            return Err(leaves(last_link));
        }
        match fs.mount_root(&next) {
            Ok(MountRoot::Link) => {
                links += 1;
                if links > MAX_LINKS {
                    return Err(OutOfDev::Unreadable(path.to_path_buf()));
                }
                let target = fs
                    .read_link(&next)
                    .map_err(|_| OutOfDev::Unreadable(next.clone()))?;
                if target.has_root() {
                    at = PathBuf::from("/");
                }
                for part in parts(&target).rev() {
                    rest.push_front(part);
                }
                last_link = Some(next);
            }
            Ok(MountRoot::Automount) => return Err(OutOfDev::Automount(next)),
            Ok(MountRoot::Entry(_)) => at = next,
            Err(error)
                if matches!(
                    error.io_kind(),
                    Some(std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory)
                ) =>
            {
                return Err(OutOfDev::Missing);
            }
            Err(_) => return Err(OutOfDev::Unreadable(next)),
        }
    }
    if at.starts_with("/dev") {
        Ok(at)
    } else {
        Err(leaves(last_link))
    }
}

#[cfg(test)]
#[path = "dev_path_tests.rs"]
mod tests;
