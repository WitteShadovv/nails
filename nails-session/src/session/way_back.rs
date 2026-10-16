// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the entry keeps for the way back: the decoy filesystems the hidden
//! session carries, and the record of the decoy's mounts.
//!
//! The way back mounts the decoy root device again and takes the decoy's other
//! filesystems from the hidden session ([`nails_teardown::whole_root::carry`]):
//! every one the fstab policy placed in the next root, and the RAM filesystems
//! the decoy's initrd mounted (`x-initrd.mount`; the test VMs' `/nix/.rw-store`
//! holds the upper of their store's overlay). systemd leaves those mounted at a
//! soft-reboot, but the hidden systemd mounts its own, and without them the
//! decoy's start would mount new, empty ones in their place. Each goes to its
//! directory on the hidden volume as the hidden root resolves it, like the
//! policy's own mount points: through a link on the volume's path the bind
//! would land on the decoy's own mount of the volume.
//!
//! From the decoy root and those filesystems, [`keep`] records every mount of
//! the decoy's tree that the way back can make again
//! ([`nails_teardown::whole_root::decoy_mounts`]). The entry warns about the
//! ones it cannot make again at or below a carried filesystem: the way back
//! puts that filesystem back without what the decoy had stacked under it or
//! mounted in it. Another mount it cannot make again (a disk mounted by hand,
//! a FUSE mount, a filesystem on an automount point) is gone after the
//! session, as after a plain soft-reboot, and the decoy's own start mounts
//! again what its fstab and units name.

use super::entry::target_in_nextroot;
use super::fstab::FstabEntry;
use super::layout::{Layout, Paths};
use crate::error::{NailsError, Result};
use nails_teardown::mountinfo::{MountEntry, SELF_MOUNTINFO, read_mountinfo, top_mount_at};
use nails_teardown::whole_root::carry;
use nails_teardown::whole_root::decoy_mounts::{self, Lost};
use nails_teardown::whole_root::plan::{CarriedMount, Plan, PolicyMountKind};
use std::path::{Path, PathBuf};

/// Carry the decoy's filesystems into the next root and record the decoy's
/// mounts in `plan` (see the module docs). `fstab` holds the decoy's fstab
/// entries and `mounts` its mount table, with the mount points as the decoy
/// sees them. Returns the warnings about decoy mounts that do not come back.
pub fn keep(
    paths: &Paths,
    layout: &Layout,
    plan: &mut Plan,
    fstab: &[FstabEntry],
    mounts: &[MountEntry],
) -> Result<Vec<String>> {
    let hidden = hidden_in_decoy(paths, layout.hidden_root());
    let mut targets: Vec<PathBuf> = plan
        .policy_mounts
        .iter()
        .filter(|mount| mount.kind != PolicyMountKind::HiddenVolume)
        .map(|mount| mount.target.clone())
        .collect();
    for target in initrd_ram_filesystems(fstab, mounts, &hidden) {
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    plan.carried = carry_all(paths, layout, &targets, mounts)?;
    let record = decoy_mounts::record(mounts, &hidden, &plan.carried);
    plan.decoy_mounts = record.mounts;
    Ok(warnings(&record.lost, &plan.carried))
}

/// The hidden volume's path as the decoy sees it.
fn hidden_in_decoy(paths: &Paths, hidden_root: &Path) -> PathBuf {
    let hidden = std::fs::canonicalize(hidden_root).unwrap_or_else(|_| hidden_root.to_path_buf());
    match hidden.strip_prefix(&paths.root) {
        Ok(rest) => Path::new("/").join(rest),
        Err(_) => hidden,
    }
}

/// The RAM filesystems of `fstab` that an initrd mounts (`x-initrd.mount`)
/// and that are mounted now in the decoy's tree, outside the hidden volume.
fn initrd_ram_filesystems(
    fstab: &[FstabEntry],
    mounts: &[MountEntry],
    hidden_root: &Path,
) -> Vec<PathBuf> {
    fstab
        .iter()
        .filter(|entry| matches!(entry.vfstype.as_str(), "tmpfs" | "ramfs"))
        .filter(|entry| entry.has_option("x-initrd.mount"))
        .filter(|entry| decoy_mounts::in_tree(&entry.file, hidden_root))
        .filter(|entry| top_mount_at(mounts, &entry.file).is_some())
        .map(|entry| entry.file.clone())
        .collect()
}

/// Carry the decoy filesystem at each of `targets` (see
/// [`nails_teardown::whole_root::carry`]), with the filesystem and the
/// directory the carried mount shows.
fn carry_all(
    paths: &Paths,
    layout: &Layout,
    targets: &[PathBuf],
    mounts: &[MountEntry],
) -> Result<Vec<CarriedMount>> {
    let mut carried = Vec::new();
    for target in targets {
        let at = layout.carried(target);
        let in_nextroot = target_in_nextroot(paths, &at)?;
        carry::carry(&paths.decoy(target), &at, &in_nextroot)
            .map_err(|e| NailsError::io(&in_nextroot, e))?;
        // What the bind took, as the way back checks it is still held.
        let live = read_mountinfo().map_err(|e| NailsError::io(Path::new(SELF_MOUNTINFO), e))?;
        let held = top_mount_at(&live, &in_nextroot);
        carried.push(CarriedMount {
            target: target.clone(),
            read_only: top_mount_at(mounts, target).is_some_and(MountEntry::read_only),
            dev: held.map(|mount| mount.dev.clone()),
            root: held.map(|mount| mount.root.clone()),
            at,
        });
    }
    Ok(carried)
}

/// The entry's warnings about the decoy mounts in `lost` at or below a
/// filesystem the session carries; the others go to the debug log.
fn warnings(lost: &[Lost], carried: &[CarriedMount]) -> Vec<String> {
    let mut warnings = Vec::new();
    for mount in lost {
        let at_carried = carried.iter().any(|c| mount.target.starts_with(&c.target));
        if at_carried && !mount.ends_with_its_server() {
            warnings.push(format!(
                "the way back cannot mount {} ({} {}) again: {}; after the session the decoy is \
                 without it until it is mounted again",
                mount.target.display(),
                mount.fstype,
                mount.source.display(),
                mount.why
            ));
        } else {
            tracing::debug!(
                mount_point = %mount.target.display(),
                fstype = %mount.fstype,
                why = %mount.why,
                "a decoy mount the way back does not make again"
            );
        }
    }
    warnings
}

#[cfg(test)]
#[path = "way_back_tests.rs"]
mod tests;
