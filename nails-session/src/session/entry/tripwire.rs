// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The write tripwire's layout, decided at activation on the decoy
//! (`[session_mounts] write_tripwire`, see
//! [`nails_teardown::whole_root::write_counters`]).
//!
//! The hidden volume is the device of the mount at the hidden root and the
//! device-mapper devices of its backend; the decoy is every other mount with a
//! block device, outside the hidden root, and the decoy root's device. A hidden
//! volume the kernel's write counters cannot tell apart from the decoy refuses
//! the activation before it writes its plan or mounts anything; the rollback
//! removes what it put in `/run` so far.

use crate::error::{NailsError, Result};
use nails_teardown::mountinfo::{MountEntry, top_mount_at};
use nails_teardown::whole_root::disk_guard::{self, DevNum, Sysfs};
use nails_teardown::whole_root::write_counters::{self, Layout};
use std::path::Path;

/// The devices of the decoy's mounts: every mount with a block device that
/// lies outside `hidden_root`, and `decoy_root`, the decoy root's device.
pub(super) fn decoy_devices(
    mounts: &[MountEntry],
    hidden_root: &Path,
    decoy_root: Option<DevNum>,
) -> Vec<DevNum> {
    let mut devices: Vec<DevNum> = mounts
        .iter()
        .filter(|m| !m.mount_point.starts_with(hidden_root))
        .filter_map(disk_guard::mount_device)
        .collect();
    devices.extend(decoy_root);
    devices.sort();
    devices.dedup();
    devices
}

/// The device of the mount a lookup of `hidden_root` reaches.
pub(super) fn hidden_mount_device(mounts: &[MountEntry], hidden_root: &Path) -> Option<DevNum> {
    top_mount_at(mounts, hidden_root).and_then(disk_guard::mount_device)
}

/// The tripwire's layout for an entry with `inputs`, `None` where the
/// tripwire is off, or the entry's refusal.
pub(super) fn for_entry(
    inputs: &super::EntryInputs<'_>,
    mounts: &[MountEntry],
) -> Result<Option<Layout>> {
    if !inputs.write_tripwire {
        return Ok(None);
    }
    layout(
        mounts,
        inputs.hidden_root,
        &inputs.backend,
        &inputs.decoy_root.source,
        &Sysfs::system(),
    )
    .map(Some)
}

/// The tripwire's layout, or the activation's refusal.
pub(super) fn layout(
    mounts: &[MountEntry],
    hidden_root: &Path,
    backend: &[String],
    decoy_root: &Path,
    sys: &Sysfs,
) -> Result<Layout> {
    let root = std::fs::canonicalize(hidden_root).unwrap_or_else(|_| hidden_root.to_path_buf());
    let hidden = write_counters::hidden_devices(hidden_mount_device(mounts, &root), backend);
    let decoy_root = std::fs::metadata(decoy_root)
        .ok()
        .filter(|m| std::os::unix::fs::FileTypeExt::is_block_device(&m.file_type()))
        .map(|m| DevNum::from_raw(std::os::unix::fs::MetadataExt::rdev(&m)));
    let decoy = decoy_devices(mounts, &root, decoy_root);
    write_counters::layout(&hidden, &decoy, sys).map_err(refusal)
}

/// The refusal of a layout the counters cannot watch.
fn refusal(why: write_counters::Imprecise) -> NailsError {
    NailsError::InvalidState(format!(
        "the write tripwire cannot watch this hidden volume: {why}. Keep the hidden volume \
         on a disk or a partition of its own, or set write_tripwire = false in \
         [session_mounts]"
    ))
}

#[cfg(test)]
#[path = "tripwire_tests.rs"]
mod tests;
