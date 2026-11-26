// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The write tripwire's layout, decided at activation on the decoy
//! (`[session_mounts] write_tripwire`, see
//! [`nails_teardown::whole_root::write_counters`]).
//!
//! The hidden volume is the device of the mount at the hidden root and the
//! device-mapper devices of its backend; the decoy is every other mount with a
//! block device, outside the hidden root, and the decoy root's device. Each
//! mount counts with every device its filesystem keeps data on: every device
//! of a btrfs or bcachefs filesystem of several, an XFS log or realtime
//! device, an ext3 or ext4 journal on a device of its own (as the attach gate
//! reads them, [`separation::DeviceMap::extra`]). A decoy ZFS dataset, whose
//! pool the mount table does not name, refuses the activation, and so does a
//! filesystem whose other devices cannot be told. A hidden volume the
//! kernel's write counters cannot tell apart from the decoy refuses the
//! activation before it writes its plan or mounts anything; the rollback
//! removes what it put in `/run` so far.

use crate::error::{NailsError, Result};
use nails_base::RealFilesystem;
use nails_base::blockdev;
use nails_base::hidden_root::separation::{self, Extra};
use nails_teardown::mountinfo::{MountEntry, top_mount_at};
use nails_teardown::whole_root::disk_guard::{DevNum, Sysfs};
use nails_teardown::whole_root::write_counters::{self, Layout};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Why the devices of a filesystem cannot be told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Untold {
    /// This place is there but could not be read.
    Unread(PathBuf),
    /// The filesystem keeps data where the counters cannot follow.
    Unwatchable(String),
}

/// What tells the devices a mounted filesystem keeps its data on: `None`
/// for a mount on no block device.
pub(super) type DevicesOf<'a> =
    dyn Fn(&MountEntry) -> std::result::Result<Option<Vec<DevNum>>, Untold> + 'a;

/// Filesystems on block devices the mount table does not name.
const POOLED: &[&str] = &["zfs"];

/// The devices of `mount`'s filesystem as the pre-flight checks read them
/// ([`blockdev::filesystem_devices`]): every device of a btrfs or bcachefs
/// filesystem of several, the one device of any other.
pub(super) fn devices_of(mount: &MountEntry) -> std::result::Result<Option<Vec<DevNum>>, PathBuf> {
    let Some(dirs) = blockdev::filesystem_devices(&RealFilesystem, mount)? else {
        return Ok(None);
    };
    dirs.iter()
        .map(|dir| {
            std::fs::read_to_string(dir.join("dev"))
                .ok()
                .and_then(|text| DevNum::parse(&text))
                .ok_or_else(|| dir.join("dev"))
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map(Some)
}

/// What the filesystems keep data on besides the device they are mounted
/// from, as the attach gate reads it: by the `major:minor` of their mounts,
/// with the device numbers of the devices it names.
#[derive(Debug, Default)]
pub(super) struct Extras {
    /// By the `major:minor` of a mount.
    pub(super) by_mount: BTreeMap<String, Extra>,
    /// Device numbers by kernel name.
    pub(super) devs: BTreeMap<String, DevNum>,
}

impl Extras {
    /// The running system's, for `mounts`.
    pub(super) fn read(mounts: &[MountEntry]) -> Self {
        let devices = separation::collect(&RealFilesystem, mounts, Path::new("/")).devices;
        Self {
            devs: devices
                .by_dev
                .iter()
                .filter_map(|(dev, name)| Some((name.clone(), DevNum::parse(dev)?)))
                .collect(),
            by_mount: devices.extra,
        }
    }

    /// The other devices of `mount`'s filesystem.
    pub(super) fn of(&self, mount: &MountEntry) -> std::result::Result<Vec<DevNum>, Untold> {
        let at = mount.mount_point.display();
        match self.by_mount.get(&mount.dev) {
            None => Ok(Vec::new()),
            Some(Extra::Devices(names)) => names
                .iter()
                .map(|name| {
                    self.devs.get(name).copied().ok_or_else(|| {
                        Untold::Unwatchable(format!(
                            "the filesystem at {at} keeps data on {name}, which sysfs does not \
                             number"
                        ))
                    })
                })
                .collect(),
            Some(Extra::Unreadable(place)) => Err(Untold::Unread(place.clone())),
            Some(Extra::NotFound) => Err(Untold::Unwatchable(format!(
                "the filesystem at {at} keeps data on a device that cannot be found"
            ))),
        }
    }
}

/// [`devices_of`] and the [`Extras`] of each filesystem, together.
pub(super) fn all_devices_of(
    extras: &Extras,
) -> impl Fn(&MountEntry) -> std::result::Result<Option<Vec<DevNum>>, Untold> + '_ {
    move |mount| {
        let Some(mut devices) = devices_of(mount).map_err(Untold::Unread)? else {
            return Ok(None);
        };
        devices.extend(extras.of(mount)?);
        Ok(Some(devices))
    }
}

/// The devices of the decoy's filesystems: every device of every mount
/// outside `hidden_root`, and `decoy_root`, the decoy root's device.
pub(super) fn decoy_devices(
    mounts: &[MountEntry],
    hidden_root: &Path,
    decoy_root: Option<DevNum>,
    devices_of: &DevicesOf<'_>,
) -> std::result::Result<Vec<DevNum>, Untold> {
    let mut devices = Vec::new();
    for mount in mounts
        .iter()
        .filter(|m| !m.mount_point.starts_with(hidden_root))
    {
        if POOLED.contains(&mount.fstype.as_str()) {
            return Err(Untold::Unwatchable(format!(
                "the decoy mounts the {} dataset {} at {}, whose pool's devices the mount \
                 table does not name",
                mount.fstype,
                mount.source.display(),
                mount.mount_point.display()
            )));
        }
        devices.extend(devices_of(mount)?.unwrap_or_default());
    }
    devices.extend(decoy_root);
    devices.sort();
    devices.dedup();
    Ok(devices)
}

/// The devices of the mount a lookup of `hidden_root` reaches.
pub(super) fn hidden_mount_devices(
    mounts: &[MountEntry],
    hidden_root: &Path,
    devices_of: &DevicesOf<'_>,
) -> std::result::Result<Vec<DevNum>, Untold> {
    match top_mount_at(mounts, hidden_root) {
        Some(mount) => Ok(devices_of(mount)?.unwrap_or_default()),
        None => Ok(Vec::new()),
    }
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
    let extras = Extras::read(mounts);
    layout(
        mounts,
        inputs.hidden_root,
        &inputs.backend,
        &inputs.decoy_root.source,
        &Sysfs::system(),
        &all_devices_of(&extras),
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
    devices_of: &DevicesOf<'_>,
) -> Result<Layout> {
    let root = std::fs::canonicalize(hidden_root).unwrap_or_else(|_| hidden_root.to_path_buf());
    let unread = |untold: Untold| match untold {
        Untold::Unread(path) => NailsError::InvalidState(format!(
            "the write tripwire cannot tell the devices of the decoy's filesystems: {} cannot \
             be read. Set write_tripwire = false in [session_mounts] to activate without it",
            path.display()
        )),
        Untold::Unwatchable(why) => NailsError::InvalidState(format!(
            "the write tripwire cannot watch the decoy's filesystems: {why}. Set \
             write_tripwire = false in [session_mounts] to activate without it"
        )),
    };
    let mut hidden = hidden_mount_devices(mounts, &root, devices_of).map_err(unread)?;
    hidden.extend(write_counters::hidden_devices(None, backend));
    let decoy_root = std::fs::metadata(decoy_root)
        .ok()
        .filter(|m| std::os::unix::fs::FileTypeExt::is_block_device(&m.file_type()))
        .map(|m| DevNum::from_raw(std::os::unix::fs::MetadataExt::rdev(&m)));
    let decoy = decoy_devices(mounts, &root, decoy_root, devices_of).map_err(unread)?;
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
