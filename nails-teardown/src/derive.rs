// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Rebuilding a plan from the live mount table when no usable plan exists.
//!
//! A missing, corrupt or foreign-version plan must not leave a NAILS mount
//! behind, so the teardown derives the same kind of plan the activation would
//! have written from what the kernel shows: the runtime root first, then every
//! NAILS-created mount in mount-table order (which is mount order). Undoing it
//! in reverse therefore takes the `/nix/store` bind off before the `/nix`
//! overlay, a persona bind before the `/home` overlay under it, and the runtime
//! root last, exactly like a recorded plan.
//!
//! What the mount table cannot show is left out: read-only guards (a guarded
//! tree looks like any read-only mount), submount re-attaches (plain binds) and
//! the units the hidden configuration added. Those need the recorded plan; the
//! report says the plan was derived so the operator knows.

use crate::mountinfo::{MountEntry, NailsMounts, is_persona_home_root, parse_overlay_opts};
use crate::plan::{MountKind, Plan, Undo};
use std::path::Path;

/// The mount namespace this process runs in, by inode, for
/// [`Plan::mount_namespace`]; `None` when it cannot be read.
pub fn own_mount_namespace() -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self/ns/mnt")
        .ok()
        .map(|meta| meta.ino())
}

/// What a mount-table entry is to NAILS, or `None` when NAILS did not make it.
///
/// Judged per entry, not per mount point, so the decoy's own filesystem at a
/// point an overlay covers (a separate `/home` partition, the boot-time
/// `/nix/store` bind under the `/nix` overlay) is never taken for NAILS's.
pub fn entry_kind(
    entries: &[MountEntry],
    entry: &MountEntry,
    hidden_root: Option<&Path>,
    runtime_root: Option<&Path>,
) -> Option<MountKind> {
    let mount_point = entry.mount_point.as_path();
    if runtime_root == Some(mount_point) {
        return (entry.fstype == "tmpfs").then_some(MountKind::RuntimeRoot);
    }
    if let Some(root) = runtime_root
        && mount_point.starts_with(root)
    {
        return Some(if entry.fstype == "tmpfs" {
            MountKind::Tmpfs
        } else {
            MountKind::Overlay
        });
    }
    if mount_point == Path::new("/nix/store") {
        // Ours only when it sits on the /nix overlay; the boot-time store bind
        // below that overlay is the decoy's.
        let on_nix_overlay = entries.iter().any(|parent| {
            parent.mount_id == entry.parent_id
                && parent.fstype == "overlay"
                && parent.mount_point == Path::new("/nix")
        });
        if on_nix_overlay {
            return Some(MountKind::StoreBind);
        }
    }
    if entry.fstype == "overlay" {
        let opts = parse_overlay_opts(&entry.super_opts);
        let under = |base: &Path| {
            opts.upperdir
                .as_deref()
                .is_some_and(|p| p.starts_with(base))
                || opts.workdir.as_deref().is_some_and(|p| p.starts_with(base))
        };
        let owned = match hidden_root {
            Some(hidden) => under(hidden) || runtime_root.is_some_and(under),
            None => true,
        };
        return owned.then_some(MountKind::Overlay);
    }
    is_persona_home_root(&entry.root).then_some(MountKind::Overlay)
}

/// Derive a plan from the mount table `entries` for an activation that used
/// `hidden_root`.
pub fn derive_plan(entries: &[MountEntry], hidden_root: &Path) -> Plan {
    let mounts = NailsMounts::from_entries(entries, Some(hidden_root));
    let runtime_root = mounts.runtime_tmpfs.clone();
    let mut plan = Plan::new(hidden_root.to_path_buf());
    plan.runtime_root = runtime_root.clone();
    plan.mount_namespace = own_mount_namespace();

    if let Some(root) = &runtime_root
        && let Some(entry) = entries.iter().find(|e| &e.mount_point == root)
    {
        plan.push(Undo::Unmount {
            target: root.clone(),
            kind: MountKind::RuntimeRoot,
            mount_id: Some(entry.mount_id),
        });
    }
    for entry in entries {
        if runtime_root.as_ref() == Some(&entry.mount_point) {
            continue;
        }
        if let Some(kind) = entry_kind(entries, entry, Some(hidden_root), runtime_root.as_deref()) {
            plan.push(Undo::Unmount {
                target: entry.mount_point.clone(),
                kind,
                mount_id: Some(entry.mount_id),
            });
        }
    }
    plan
}

/// Derive a plan from an already classified table, when only the
/// classification is available (no per-entry mount ids): the runtime root
/// first, then the overlays, the persona binds, the staging mounts inside the
/// runtime root and the `/nix/store` bind, so the undo takes them down in the
/// reverse of that order.
pub fn plan_from_nails_mounts(mounts: &NailsMounts, hidden_root: &Path) -> Plan {
    let mut plan = Plan::new(hidden_root.to_path_buf());
    plan.runtime_root = mounts.runtime_tmpfs.clone();
    let mut push = |target: &Path, kind| {
        plan.push(Undo::Unmount {
            target: target.to_path_buf(),
            kind,
            mount_id: None,
        });
    };
    if let Some(root) = &mounts.runtime_tmpfs {
        push(root, MountKind::RuntimeRoot);
    }
    for target in mounts
        .persistent_overlays
        .iter()
        .chain(&mounts.ephemeral_overlays)
        .chain(&mounts.persona_binds)
        .chain(&mounts.pivot_binds)
    {
        push(target, MountKind::Overlay);
    }
    if mounts.nix_overlay_present
        && let Some(bind) = &mounts.nix_store_bind
    {
        push(bind, MountKind::StoreBind);
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mountinfo::parse_mountinfo;
    use std::path::PathBuf;

    const TABLE: &str = "\
1 0 8:1 / / rw - ext4 /dev/sda1 rw
9 1 8:3 / /home rw - ext4 /dev/sdb1 rw
20 1 0:70 / /run/0123456789abcdef rw - tmpfs tmpfs rw,mode=700
21 20 0:71 / /run/0123456789abcdef/var-upper rw - tmpfs tmpfs rw
30 9 0:50 / /home rw - overlay overlay rw,lowerdir=/home,upperdir=/mnt/hidden/home/upper,workdir=/mnt/hidden/home/work
31 1 0:51 / /var rw - overlay overlay rw,lowerdir=/var,upperdir=/run/0123456789abcdef/var-upper/u,workdir=/run/0123456789abcdef/var-upper/w
5 1 8:1 /nix/store /nix/store ro - ext4 /dev/sda1 rw
32 1 0:52 / /nix rw - overlay overlay rw,lowerdir=/nix,upperdir=/mnt/hidden/nix/upper,workdir=/mnt/hidden/nix/work
33 32 0:52 /store /nix/store ro - overlay overlay rw,lowerdir=/nix,upperdir=/mnt/hidden/nix/upper,workdir=/mnt/hidden/nix/work
34 30 8:9 /persona/home /home/op rw - ext4 /dev/mapper/hidden rw
40 1 0:60 / /var/lib/docker/x rw - overlay overlay rw,lowerdir=/a,upperdir=/b,workdir=/c
";

    fn targets(plan: &Plan) -> Vec<(PathBuf, MountKind)> {
        plan.undo_order()
            .filter_map(|undo| match undo {
                Undo::Unmount { target, kind, .. } => Some((target.clone(), *kind)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_derived_plan_undoes_in_the_order_activation_would_have_recorded() {
        let plan = derive_plan(&parse_mountinfo(TABLE), Path::new("/mnt/hidden"));
        assert_eq!(
            targets(&plan),
            vec![
                (PathBuf::from("/home/op"), MountKind::Overlay),
                (PathBuf::from("/nix/store"), MountKind::StoreBind),
                (PathBuf::from("/nix"), MountKind::Overlay),
                (PathBuf::from("/var"), MountKind::Overlay),
                (PathBuf::from("/home"), MountKind::Overlay),
                (
                    PathBuf::from("/run/0123456789abcdef/var-upper"),
                    MountKind::Tmpfs
                ),
                (
                    PathBuf::from("/run/0123456789abcdef"),
                    MountKind::RuntimeRoot
                ),
            ]
        );
    }

    #[test]
    fn the_decoy_mounts_under_an_overlay_are_never_in_a_derived_plan() {
        let plan = derive_plan(&parse_mountinfo(TABLE), Path::new("/mnt/hidden"));
        let ids: Vec<i32> = plan
            .undo_order()
            .filter_map(|undo| match undo {
                Undo::Unmount { mount_id, .. } => *mount_id,
                _ => None,
            })
            .collect();
        // Not the decoy root, the decoy /home partition, the boot-time store
        // bind, or a foreign overlay whose upper is elsewhere.
        for foreign in [1, 9, 5, 40] {
            assert!(!ids.contains(&foreign), "{foreign} in {ids:?}");
        }
    }

    #[test]
    fn an_empty_table_derives_an_empty_plan() {
        let plan = derive_plan(&[], Path::new("/mnt/hidden"));
        assert!(plan.steps.is_empty());
        assert_eq!(plan.runtime_root, None);
    }
}
