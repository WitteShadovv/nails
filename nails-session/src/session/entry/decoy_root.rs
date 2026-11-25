// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The decoy root device the way back mounts again, read from the mount table.

use crate::error::{NailsError, Result};
use nails_teardown::mountinfo::{MountEntry, top_mount_at};
use nails_teardown::whole_root::plan::DecoyRoot;
use std::path::Path;

/// The decoy root device from the mount table, which the plan records. It
/// served the way back, which is gone; the refusals stay until a removal of
/// their own proves the entry on such roots. Refuses a root that cannot be
/// mounted again by device: a
/// RAM root (an impermanent decoy), an overlay, a ZFS dataset, or a bind of a
/// subdirectory other than a btrfs subvolume.
pub fn decoy_root_of(entries: &[MountEntry], root: &Path) -> Result<DecoyRoot> {
    let mount = top_mount_at(entries, root)
        .ok_or_else(|| NailsError::InvalidState("the root is not a mount point".to_string()))?;
    let refuse = |why: String| Err(NailsError::InvalidState(why));
    if !mount.source.starts_with("/dev/") {
        return refuse(format!(
            "the decoy root ({} on {}) is not on a block device, and NAILS supports a decoy root \
             only on one",
            mount.fstype,
            mount.source.display()
        ));
    }
    if matches!(
        mount.fstype.as_str(),
        "zfs" | "overlay" | "tmpfs" | "squashfs" | "erofs"
    ) {
        return refuse(format!(
            "a {} decoy root is not supported by the whole-root session",
            mount.fstype
        ));
    }
    let data = if mount.root == Path::new("/") {
        None
    } else if mount.fstype == "btrfs"
        && mount_subvol(mount).is_some_and(|subvol| Path::new(&subvol) == mount.root)
    {
        // A btrfs mount whose root is exactly its `subvol=` is a subvolume,
        // which the plan records with that `subvol=`. A mount root that is a
        // deeper path (a bind of a plain folder inside the subvolume) has no
        // `subvol=` of its own, so it is refused like any other bind below.
        if mount.root.to_string_lossy().contains(',') {
            // mount(2) splits its options at every comma, so a `subvol=`
            // option could not name this subvolume.
            return refuse(format!(
                "the decoy root's btrfs subvolume {} has a comma in its path, which a subvol= \
                 mount option cannot name",
                mount.root.display()
            ));
        }
        Some(format!("subvol={}", mount.root.display()))
    } else {
        return refuse(format!(
            "the decoy root is a bind of {} on {}",
            mount.root.display(),
            mount.source.display()
        ));
    };
    Ok(DecoyRoot {
        source: mount.source.clone(),
        fstype: mount.fstype.clone(),
        data,
    })
}

/// The `subvol=` a btrfs mount's options name, if any, decoded. btrfs records
/// it in both the per-superblock and the per-mount option fields of the mount
/// table, where the kernel writes a space, tab, newline, comma or backslash in
/// it as an octal escape (`\040`); the mount root it is compared with is
/// decoded already.
fn mount_subvol(mount: &MountEntry) -> Option<String> {
    mount
        .super_opts
        .split(',')
        .chain(mount.mount_opts.split(','))
        .find_map(|opt| opt.strip_prefix("subvol="))
        .map(nails_teardown::mountinfo::unescape_octal)
}
