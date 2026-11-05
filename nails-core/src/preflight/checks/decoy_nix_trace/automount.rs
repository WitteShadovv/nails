// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Where a lookup of the decoy would mount an automount point.
//!
//! A lookup that passes an automount point that nothing is mounted on yet
//! mounts it: a direct one (systemd's for `x-systemd.automount`, or an
//! automounter's direct or offset map) as the lookup goes into it, a name in
//! the directory of an indirect map as the lookup looks that name up. The
//! check asks before each lookup, without making it: it reads the links on
//! the way one by one, never following them, and asks the running system's
//! mount table about each place the lookup would pass.

use crate::Filesystem;
use crate::filesystem::mountinfo::MountEntry;
use crate::hidden_root::mount_holding;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// The filesystem type of an automount point.
const AUTOMOUNT_FS: &str = "autofs";

/// The option of an automount point that is the directory of an indirect
/// map: a lookup of a name in it mounts that name, while the directory
/// itself is no automount point. A direct or offset automount point is one
/// itself.
const INDIRECT_MAP: &str = "indirect";

/// The kernel's limit on the links one lookup follows (`MAXSYMLINKS`).
const MAX_LINKS: usize = 40;

/// One step of a lookup, as [`on_the_way`] takes them.
enum Step {
    /// Into the entry of this name.
    Into(OsString),
    /// Up to the parent, for `..`.
    Up,
}

/// Put the steps of `path` on `steps`, its first step last, so that they are
/// taken from the end in order.
fn push_steps(steps: &mut Vec<Step>, path: &Path) {
    for component in path.components().rev() {
        match component {
            Component::Normal(name) => steps.push(Step::Into(name.to_os_string())),
            Component::ParentDir => steps.push(Step::Up),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => {}
        }
    }
}

/// Whether a lookup that reaches `path` makes `mount`, the mount that holds
/// it, mount something: when it is an automount, unless it is the directory
/// of an indirect map at `path` itself, whose names the next step looks up.
fn mounts(mount: &MountEntry, path: &Path) -> bool {
    mount.fstype == AUTOMOUNT_FS
        && (mount.mount_point != path
            || !mount
                .super_opts
                .split(',')
                .any(|option| option == INDIRECT_MAP))
}

/// The automount point that a lookup of `path`, an absolute path of the
/// running system, would mount, as `table` shows: one that nothing is
/// mounted on yet and that the lookup passes, with each link on the way
/// followed, and the link at its end too when `follow`. Each link is read,
/// never followed, so asking mounts nothing. None where the lookup passes no
/// such point or fails before one.
pub(super) fn on_the_way<F: Filesystem>(
    fs: &F,
    table: &[MountEntry],
    path: &Path,
    follow: bool,
) -> Option<PathBuf> {
    let mut steps = Vec::new();
    push_steps(&mut steps, path);
    let mut at = PathBuf::from("/");
    let mut links = 0;
    while let Some(step) = steps.pop() {
        let name = match step {
            Step::Into(name) => name,
            Step::Up => {
                at.pop();
                continue;
            }
        };
        let next = at.join(name);
        // Each place is asked before the lookup passes it, so the first that
        // would mount is the automount point itself: a direct one, or a name
        // in the directory of an indirect map.
        if mount_holding(table, &next).is_some_and(|mount| mounts(mount, &next)) {
            return Some(next);
        }
        let last = steps.is_empty();
        if (last && !follow) || !fs.is_symlink(&next).unwrap_or(false) {
            at = next;
            continue;
        }
        links += 1;
        if links > MAX_LINKS {
            // The lookup fails here, before it goes on.
            return None;
        }
        // Nor does a lookup go on through a link that cannot be read.
        let target = fs.read_link(&next).ok()?;
        if target.is_absolute() {
            at = PathBuf::from("/");
        }
        push_steps(&mut steps, &target);
    }
    None
}
