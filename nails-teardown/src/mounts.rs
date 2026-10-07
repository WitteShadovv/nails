// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The mount operations a plan's undo needs, and their kernel implementation.
//!
//! The executor in [`crate::undo`] is written against [`MountOps`], so the same
//! ordering, reconcile and fallback logic drives every teardown: the emergency
//! hot path uses [`KernelMountOps`] (raw `umount2` and `mount` calls through
//! rustix), while `nails-core` adapts its own filesystem abstraction so rollback
//! and deactivation run the very same plan through it.

use crate::derive::entry_kind;
use crate::mountinfo::{
    MountEntry, NailsMounts, is_read_only_self_bind, read_mountinfo, top_mount_at,
};
use crate::plan::MountKind;
use std::io;
use std::path::{Path, PathBuf};

/// Whether the mount a step made is still at its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// Nothing is mounted at the target (already undone).
    Absent,
    /// The mount at the target is the step's own (or another NAILS mount).
    Owned,
    /// Something is mounted at the target but NAILS did not make it: a decoy
    /// mount that lay beneath an overlay already taken down. Never touched.
    Foreign,
}

/// What the undo executor needs from the system.
pub trait MountOps {
    /// Whether the mount a step of `kind` made at `target` is still there.
    /// `recorded_id` is the mount id read at activation, when it may be compared.
    fn presence(
        &self,
        target: &Path,
        kind: MountKind,
        recorded_id: Option<i32>,
    ) -> io::Result<Presence>;

    /// Every NAILS-created mount still in the live table.
    fn nails_mounts(&self) -> io::Result<NailsMounts>;

    /// Unmount the top mount at `target`. A `lazy` unmount detaches it from the
    /// mount table at once whatever still holds it (`MNT_DETACH`).
    fn unmount(&self, target: &Path, kind: MountKind, lazy: bool) -> io::Result<()>;

    /// Whether a read-only guard is still on `tree`.
    fn guard_present(&self, tree: &Path) -> io::Result<bool>;

    /// Return write access to `tree`.
    fn remove_guard(&self, tree: &Path) -> io::Result<()>;

    /// Unmount `target` in PID 1's mount namespace. `Ok(false)` when that
    /// namespace is this process's own, so there is nothing separate to undo.
    fn unmount_in_init_namespace(&self, target: &Path) -> io::Result<bool>;

    /// Remove an (empty) directory, after the runtime root's tmpfs is gone.
    fn remove_dir(&self, path: &Path) -> io::Result<()>;
}

/// [`MountOps`] on the running kernel.
#[derive(Debug, Clone)]
pub struct KernelMountOps {
    hidden_root: PathBuf,
    runtime_root: Option<PathBuf>,
    /// Whether recorded mount ids may be compared: only in the mount namespace
    /// the plan was recorded in.
    compare_ids: bool,
}

impl KernelMountOps {
    /// Kernel operations for a plan recorded with `hidden_root` and
    /// `runtime_root` in the mount namespace `recorded_namespace`.
    pub fn new(
        hidden_root: PathBuf,
        runtime_root: Option<PathBuf>,
        recorded_namespace: Option<u64>,
    ) -> Self {
        let compare_ids = recorded_namespace.is_some()
            && recorded_namespace == crate::derive::own_mount_namespace();
        Self {
            hidden_root,
            runtime_root,
            compare_ids,
        }
    }

    fn entries(&self) -> io::Result<Vec<MountEntry>> {
        read_mountinfo()
    }

    /// The runtime root the classifier should use: the recorded one, or the one
    /// it finds structurally.
    fn runtime_root_for(&self, entries: &[MountEntry]) -> Option<PathBuf> {
        self.runtime_root
            .clone()
            .or_else(|| NailsMounts::from_entries(entries, Some(&self.hidden_root)).runtime_tmpfs)
    }
}

/// Whether the top mount `top` at a step's target is the step's own, judged
/// without a usable mount id.
fn structurally_owned(
    entries: &[MountEntry],
    top: &MountEntry,
    kind: MountKind,
    hidden_root: &Path,
    runtime_root: Option<&Path>,
) -> bool {
    if entry_kind(entries, top, Some(hidden_root), runtime_root).is_some() {
        return true;
    }
    match kind {
        // A submount staging bind lives under the hidden root; a re-attach sits
        // directly on a NAILS overlay.
        MountKind::Attachment => {
            top.mount_point.starts_with(hidden_root)
                || entries.iter().any(|parent| {
                    parent.mount_id == top.parent_id
                        && entry_kind(entries, parent, Some(hidden_root), runtime_root).is_some()
                })
        }
        MountKind::RuntimeRoot => {
            top.fstype == "tmpfs" && top.mount_point.parent() == Some(Path::new("/run"))
        }
        _ => false,
    }
}

impl MountOps for KernelMountOps {
    fn presence(
        &self,
        target: &Path,
        kind: MountKind,
        recorded_id: Option<i32>,
    ) -> io::Result<Presence> {
        let entries = self.entries()?;
        let Some(top) = top_mount_at(&entries, target) else {
            return Ok(Presence::Absent);
        };
        let runtime_root = self.runtime_root_for(&entries);
        if self.compare_ids
            && let Some(id) = recorded_id
        {
            if top.mount_id == id {
                return Ok(Presence::Owned);
            }
            // Another mount covers the step's own (or replaced it): leave it to
            // the reconcile sweep, which takes down any NAILS mount it finds.
            return Ok(Presence::Foreign);
        }
        Ok(
            if structurally_owned(
                &entries,
                top,
                kind,
                &self.hidden_root,
                runtime_root.as_deref(),
            ) {
                Presence::Owned
            } else {
                Presence::Foreign
            },
        )
    }

    fn nails_mounts(&self) -> io::Result<NailsMounts> {
        let entries = self.entries()?;
        let mut mounts = NailsMounts::from_entries(&entries, Some(&self.hidden_root));
        // An empty umbrella is not found structurally; the recorded one is ours.
        if mounts.runtime_tmpfs.is_none()
            && let Some(root) = &self.runtime_root
            && top_mount_at(&entries, root).is_some_and(|e| e.fstype == "tmpfs")
        {
            mounts.runtime_tmpfs = Some(root.clone());
        }
        Ok(mounts)
    }

    fn unmount(&self, target: &Path, _kind: MountKind, lazy: bool) -> io::Result<()> {
        use rustix::mount::{UnmountFlags, unmount};
        let mut flags = UnmountFlags::NOFOLLOW;
        if lazy {
            flags |= UnmountFlags::DETACH;
        }
        unmount(target, flags).map_err(io::Error::from)
    }

    fn guard_present(&self, tree: &Path) -> io::Result<bool> {
        let entries = self.entries()?;
        if tree == Path::new("/") {
            return Ok(namespace_root(&entries).is_some_and(root_guarded_in_place));
        }
        Ok(is_read_only_self_bind(&entries, tree))
    }

    fn remove_guard(&self, tree: &Path) -> io::Result<()> {
        let entries = self.entries()?;
        if tree == Path::new("/") {
            return match namespace_root(&entries) {
                Some(root) if root_guarded_in_place(root) => clear_root_read_only(root),
                _ => Ok(()),
            };
        }
        if !is_read_only_self_bind(&entries, tree) {
            return Ok(());
        }
        self.unmount(tree, MountKind::Attachment, false)
            .or_else(|_| self.unmount(tree, MountKind::Attachment, true))
    }

    fn unmount_in_init_namespace(&self, target: &Path) -> io::Result<bool> {
        crate::initns::unmount_in_init_namespace(target)
    }

    fn remove_dir(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_dir(path)
    }
}

/// The namespace root's own mount: the entry at `/` not stacked on another
/// entry at `/`.
fn namespace_root(entries: &[MountEntry]) -> Option<&MountEntry> {
    let root = Path::new("/");
    entries.iter().find(|entry| {
        entry.mount_point == root
            && !entries
                .iter()
                .any(|below| below.mount_id == entry.parent_id && below.mount_point == root)
    })
}

/// Whether the root carries the in-place guard: read-only as a mount on a
/// filesystem that is itself read-write. A root mounted read-only to begin with
/// is never made writable.
fn root_guarded_in_place(root: &MountEntry) -> bool {
    root.read_only() && !root.super_opts.split(',').any(|opt| opt == "ro")
}

/// Clear the root mount's per-mount read-only flag, keeping its security flags.
fn clear_root_read_only(root: &MountEntry) -> io::Result<()> {
    use rustix::mount::{MountFlags, mount_remount};
    let mut flags = MountFlags::BIND;
    for opt in root.mount_opts.split(',') {
        match opt {
            "nosuid" => flags |= MountFlags::NOSUID,
            "nodev" => flags |= MountFlags::NODEV,
            "noexec" => flags |= MountFlags::NOEXEC,
            _ => {}
        }
    }
    mount_remount("/", flags, "").map_err(io::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mountinfo::parse_mountinfo;

    #[test]
    fn a_reattach_on_a_nails_overlay_is_owned_but_the_decoy_submount_is_not() {
        let table = parse_mountinfo(
            "\
1 0 8:1 / / rw - ext4 /dev/sda1 rw
9 1 8:3 / /home/data rw - ext4 /dev/sdb1 rw
30 1 0:50 / /home rw - overlay overlay rw,lowerdir=/home,upperdir=/h/home/upper,workdir=/h/home/work
35 30 8:3 / /home/data ro - ext4 /dev/sdb1 rw
",
        );
        let hidden = Path::new("/h");
        let reattach = table.iter().find(|e| e.mount_id == 35).unwrap();
        let decoy = table.iter().find(|e| e.mount_id == 9).unwrap();
        assert!(structurally_owned(
            &table,
            reattach,
            MountKind::Attachment,
            hidden,
            None
        ));
        assert!(!structurally_owned(
            &table,
            decoy,
            MountKind::Attachment,
            hidden,
            None
        ));
    }

    #[test]
    fn the_root_guard_is_told_apart_from_a_read_only_root() {
        let guarded = parse_mountinfo("1 0 8:1 / / ro,nosuid - ext4 /dev/sda1 rw\n");
        let born_ro = parse_mountinfo("1 0 8:1 / / ro - ext4 /dev/sda1 ro\n");
        assert!(root_guarded_in_place(namespace_root(&guarded).unwrap()));
        assert!(!root_guarded_in_place(namespace_root(&born_ro).unwrap()));
    }
}
