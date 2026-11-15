// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether the partition the hidden root is stored on has a GPT type that
//! systemd acts on by that type alone.
//!
//! Unless the decoy masks it, systemd-gpt-auto-generator runs at every boot
//! of the decoy and acts on the partitions of one disk by their GPT type
//! alone (see [`discoverable`]): the disk it finds below the root file
//! system, through one layer of devices before systemd 259.1 and through all
//! of them from 259.1 on (module `generator` says which). There it mounts the
//! first `/home`, `/srv`, `/var` or `/var/tmp` partition at that folder, uses
//! the first swap partition as swap, and asks for the passphrase of such a
//! partition that is a LUKS volume. Where it runs, a hidden volume on such a
//! partition can show up at the decoy's next boot, as a failed mount, a
//! failed swap or a passphrase prompt. Nothing of it happens in the hidden
//! session, whose root is an overlay, which the generator skips, but the type
//! stays in the partition table for anyone who reads it. Ubuntu 24.04 and
//! 26.04 mask the generator by default, with a link from
//! `/etc/systemd/system-generators/systemd-gpt-auto-generator` to
//! `/dev/null`. The check reads no mask, so it judges a partition on such a
//! decoy as on any other: the type shows in the table there too.
//!
//! The check walks the devices under the hidden root's filesystem as far as
//! its own storage goes (through `slaves/` and loops over block devices,
//! never into the filesystem that holds a container file) and judges each
//! partition on a disk the decoy boots from: a disk under its root file
//! system or its EFI system partition, and the disk the generator reads. It
//! judges a partition the same on each of them, as the type shows in the
//! table on all, and its texts say whether the generator reads the disk, or
//! that the check cannot tell, where sysfs does not list the devices below
//! the root file system. A partition the decoy claims as its own storage is
//! the decoy's business, and the attach gate's. It reads the disk's
//! partition table read-only and without changing an access time, and
//! matches the entry by its number and its start; where the disk cannot be
//! read, as without root, it takes the entry from udev's record of the
//! partition.
//!
//! [`discoverable`]: crate::forensic::layout::discoverable

use super::graph::{Graph, filesystem_devices, unread_reason, widen_claims};
use crate::blockdev::{Attribute, Layer, LoopFollow, Partition};
use crate::config::get_default_hidden_volume_root;
use crate::filesystem::mountinfo::{MountEntry, top_mount_at};
use crate::filesystem::udev;
use crate::forensic::RawSource;
use crate::forensic::layout::{TableKind, recorded_table};
use crate::hidden_root::separation;
use crate::preflight::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

mod generator;
mod judge;
#[cfg(test)]
mod tests;

use generator::GeneratorDisk;
use judge::{DOC, Damage, Entry, Finding, Place, verdict};

/// Where the device nodes the partition tables are read from live.
const DEV_DIR: &str = "/dev";
/// Where udev keeps its record of each device.
const UDEV_DATA: &str = "/run/udev/data";
/// The names udev gives each disk by its serial and the like.
const BY_ID: &str = "/dev/disk/by-id";
/// The mount points of the decoy's EFI system partition and boot partition.
const BOOT_MOUNTS: &[&str] = &["/boot", "/boot/efi", "/efi"];

/// The attributes and listings of a device of the hidden root's storage the
/// check decides by: whether it is a partition (`partition`), where it
/// starts (`start`) and on which disk (`dev` of the directory above), and
/// what lies below it (what a loop device reads, `slaves/`). Where sysfs
/// shows one but NAILS cannot read it, the check cannot tell.
const HIDDEN: &[Attribute] = &[
    Attribute::Partition,
    Attribute::Start,
    Attribute::DiskDev,
    Attribute::LoopBackingFile,
    Attribute::Slaves,
];

/// Those of a device below the decoy's root file system or its boot
/// partitions: whether it is a partition and of which disk, and what lies
/// below it. Where sysfs shows one but NAILS cannot read it, a disk the decoy
/// boots from may be missing.
const BOOT: &[Attribute] = &[
    Attribute::Partition,
    Attribute::DiskDev,
    Attribute::LoopBackingFile,
    Attribute::Slaves,
];

/// Pre-flight check that refuses a hidden root stored on a partition whose
/// GPT type systemd mounts or uses at boot.
///
/// # Pass, warn and fail
///
/// For each partition of the hidden root's storage on a disk the decoy
/// boots from, its type, read from the disk's GPT, whether or not the decoy
/// masks systemd-gpt-auto-generator and whether or not the generator reads
/// that disk:
///
/// - fails for the `/home`, `/srv`, `/var`, `/var/tmp` and swap types, which
///   systemd mounts or uses at every later boot of the decoy where the
///   generator runs and reads the disk, and for the swap type with the
///   no-auto flag as well, though systemd leaves such a partition alone;
/// - warns for one of the first four with the no-auto flag, which systemd
///   honours, and for the root, EFI system partition and extended boot
///   loader types, which it acts on only under some conditions: the type
///   still names a use the partition does not have;
/// - passes for any other type, and for an MBR;
/// - warns where the table does not list the partition where the kernel has
///   it, where the GPT is damaged (its header or its entries do not match
///   the checksums it keeps, not every entry could be checked against them,
///   or an entry does not fit within its usable blocks), and where neither
///   the disk nor udev's record of the partition can be read;
/// - warns that it could not check where the mount table cannot be read,
///   the hidden root's filesystem shows no block device, its storage or that
///   of the decoy's root file system holds more devices than it reads, or
///   sysfs shows an attribute of one of their devices that it decides by
///   ([`HIDDEN`], [`BOOT`]) but NAILS cannot read it, below the decoy's root
///   where the hidden root's storage has a partition on a disk it does not
///   know the decoy boots from. A partition it could judge and refuses is
///   refused all the same.
///
/// A hidden root on no partition of such a disk passes: a disk of its own,
/// such as an external drive, a container file, or a RAM filesystem. Each
/// failure and warning about a type gives the `sgdisk` command that gives
/// the partition the generic Linux type, to run where setup happens.
#[derive(Debug, Clone)]
pub struct BackendPartitionTypeCheck {
    hidden_volume_root: PathBuf,
    /// Where the disks' device nodes are read from.
    dev_dir: PathBuf,
}

impl BackendPartitionTypeCheck {
    /// A check of the volume mounted at `hidden_volume_root`.
    pub fn new(hidden_volume_root: PathBuf) -> Self {
        Self {
            hidden_volume_root,
            dev_dir: PathBuf::from(DEV_DIR),
        }
    }

    /// The check, reading the disks' device nodes from `dev_dir`: a test's
    /// directory of disk images in place of `/dev`.
    #[cfg(test)]
    fn reading_devices_in(mut self, dev_dir: &Path) -> Self {
        self.dev_dir = dev_dir.to_path_buf();
        self
    }
}

impl Default for BackendPartitionTypeCheck {
    /// Create the check with the default hidden-volume path.
    fn default() -> Self {
        Self::new(PathBuf::from(get_default_hidden_volume_root()))
    }
}

impl<F: Filesystem> PreFlightCheck<F> for BackendPartitionTypeCheck {
    fn name(&self) -> &'static str {
        "backend-partition-type"
    }

    fn description(&self) -> &'static str {
        "Refuses a hidden root on a partition whose type systemd mounts or uses at boot"
    }

    fn requires_hidden_volume(&self) -> bool {
        true
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let root = &self.hidden_volume_root;
        let Ok(table) = fs.mount_table() else {
            return Ok(unchecked(root, "the mount table cannot be read"));
        };
        let canonical = fs.canonicalize(root).unwrap_or_else(|_| root.clone());
        let Some(hidden) = top_mount_at(&table, &canonical) else {
            // The attach gate refuses a root that is no mount point, and the
            // registry skips this check then.
            return Ok(CheckResult::Pass(format!(
                "Partition type check skipped: nothing is mounted at {}",
                root.display()
            )));
        };
        if matches!(hidden.fstype.as_str(), "tmpfs" | "ramfs") {
            return Ok(CheckResult::Pass(format!(
                "The hidden root at {} is a {}, on no partition.",
                root.display(),
                hidden.fstype
            )));
        }
        let Some(roots) = filesystem_devices(fs, hidden) else {
            return Ok(unchecked(
                root,
                &format!(
                    "its {} filesystem shows no block device to follow",
                    separation::shown_fstype(&hidden.fstype)
                ),
            ));
        };

        let collected = separation::collect(fs, &table, Path::new("/"));
        let claimed = widen_claims(
            fs,
            &table,
            &collected.devices,
            separation::claimed_devices(&collected.scene(&table), hidden),
        );
        let graph = Graph::read(
            fs,
            &table,
            &collected.devices,
            &roots,
            LoopFollow::BlockDevices,
        );
        // What keeps the check from telling about all of the hidden root's
        // storage: an attribute it decides by that sysfs shows but NAILS
        // cannot read, or more devices than it reads. A refusal of a
        // partition it could judge stands; otherwise it could not check.
        let unread = graph.unread(HIDDEN);
        let untold = if !unread.is_empty() {
            Some(unread_reason(&unread, "below it"))
        } else if !graph.complete() {
            Some("its storage holds more devices than the check reads".to_string())
        } else {
            None
        };
        let Some(Boot {
            disks: mut boot,
            untold: boot_untold,
        }) = boot_disks(fs, &table, &collected.devices)
        else {
            return Ok(unchecked(
                root,
                "the disk the decoy's root file system is on cannot be found",
            ));
        };
        // The disk the generator reads is one the decoy boots from, also
        // where the root file system lies on several devices and the
        // generator reads the disk below /usr.
        let generator = GeneratorDisk::read(fs, &table);
        boot.extend(generator.disks().map(str::to_string));
        // A disk the decoy boots from that sysfs did not let the check find
        // matters only where a partition of the hidden root's storage is on
        // a disk it does not know the decoy boots from.
        let off_boot = graph.layers.values().any(|layer| {
            layer
                .partition
                .as_ref()
                .and_then(|partition| partition.disk.as_deref())
                .is_some_and(|disk| !boot.contains(disk))
        });
        let untold = untold.or(boot_untold.filter(|_| off_boot));

        let (decoys, on_boot): (Vec<_>, Vec<_>) = graph
            .layers
            .iter()
            .filter_map(|(name, layer)| {
                let partition = layer.partition.as_ref()?;
                let disk = partition.disk.as_deref()?;
                boot.contains(disk)
                    .then_some((claimed.contains_key(name), (layer, partition, disk)))
            })
            .partition(|(decoys, _)| *decoys);
        let result = if on_boot.is_empty() {
            CheckResult::Pass(if decoys.is_empty() {
                format!(
                    "The hidden root at {} is on no partition of a disk the decoy boots from \
                     ({}).",
                    root.display(),
                    boot.iter().cloned().collect::<Vec<_>>().join(", ")
                )
            } else {
                format!(
                    "The hidden root at {} is on no partition of a disk the decoy boots from but \
                     the decoy's own, whose types are the decoy's; the hidden-volume check \
                     reports a root on the decoy's storage.",
                    root.display()
                )
            })
        } else {
            let findings: Vec<Finding> = on_boot
                .into_iter()
                .map(|(_, (layer, partition, disk))| {
                    let place = Place {
                        partition: layer.name.clone(),
                        number: partition.number,
                        disk: disk.to_string(),
                        node: disk_node(fs, disk),
                    };
                    let entry = self.entry(fs, layer, partition, disk);
                    Finding::of(place, entry, generator.discovery(disk))
                })
                .collect();
            verdict(root, &findings)
        };
        Ok(match untold {
            Some(why) if !result.is_fail() => unchecked(root, &why),
            _ => result,
        })
    }
}

impl BackendPartitionTypeCheck {
    /// What the partition table on `disk` says of `partition`, the layer
    /// `layer`: read from the disk, else from udev's record of the partition.
    fn entry<F: Filesystem>(
        &self,
        fs: &F,
        layer: &Layer,
        partition: &Partition,
        disk: &str,
    ) -> Entry {
        let node = self.dev_dir.join(disk);
        let read = RawSource::open(&node).and_then(|source| recorded_table(&source));
        match read {
            Ok(table) => match table.table {
                TableKind::Mbr => Entry::Mbr,
                TableKind::None => Entry::Unlisted,
                TableKind::Gpt => table
                    .partitions
                    .iter()
                    .find(|entry| {
                        entry.number == partition.number
                            && partition.start.and_then(|start| start.checked_mul(512))
                                == Some(entry.start)
                    })
                    .map_or(Entry::Unlisted, |entry| Entry::Gpt {
                        type_id: entry.type_id.clone(),
                        flags: Some(entry.attributes),
                        damage: Damage::of(&table),
                    }),
            },
            Err(error) => udev_entry(fs, layer, partition)
                .unwrap_or_else(|| Entry::Unreadable(format!("{}: {error}", node.display()))),
        }
    }
}

/// The partition's entry as udev's record of it gives it, when that record
/// names the entry the kernel has: the same number and start.
fn udev_entry<F: Filesystem>(fs: &F, layer: &Layer, partition: &Partition) -> Option<Entry> {
    let record = fs
        .read_file_content(&Path::new(UDEV_DATA).join(format!("b{}", layer.dev.as_deref()?)))
        .ok()?;
    let entry = udev::partition_entry(&record)?;
    if entry.number != Some(partition.number) || entry.offset != partition.start {
        return None;
    }
    match entry.scheme.as_str() {
        "dos" => Some(Entry::Mbr),
        "gpt" => Some(Entry::Gpt {
            type_id: entry.type_id,
            flags: entry.flags,
            damage: None,
        }),
        _ => None,
    }
}

/// The disks the decoy boots from, as far as the check can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Boot {
    /// The disks, by kernel name.
    disks: BTreeSet<String>,
    /// Why there may be more, where there may: sysfs shows an attribute the
    /// check decides by of a device below them that NAILS cannot read, or
    /// they hold more devices than the check reads.
    untold: Option<String>,
}

/// The disks the decoy boots from, by kernel name: every disk below its root
/// file system and its EFI system or boot partition, a partition's disk and
/// a whole disk at the bottom. `None` when the root file system's devices
/// cannot be found, and none is found while nothing keeps the check from
/// telling.
fn boot_disks<F: Filesystem>(
    fs: &F,
    mounts: &[MountEntry],
    recorded: &separation::DeviceMap,
) -> Option<Boot> {
    let mut roots = filesystem_devices(fs, top_mount_at(mounts, Path::new("/"))?)?;
    for point in BOOT_MOUNTS {
        // An automount not yet used shows no device, and adds no disk. One
        // that systemd-gpt-auto-generator made mounts a partition of the
        // disk it reads, which the check counts in any case.
        if let Some(devices) =
            top_mount_at(mounts, Path::new(point)).and_then(|mount| filesystem_devices(fs, mount))
        {
            roots.extend(devices);
        }
    }
    let graph = Graph::read(fs, mounts, recorded, &roots, LoopFollow::BlockDevices);
    let unread = graph.unread(BOOT);
    let untold = if !unread.is_empty() {
        Some(unread_reason(&unread, "below the decoy's root file system"))
    } else if !graph.complete() {
        Some(
            "the storage of the decoy's root file system holds more devices than the check reads"
                .to_string(),
        )
    } else {
        None
    };
    let disks: BTreeSet<String> = graph
        .layers
        .values()
        .filter_map(|layer| match &layer.partition {
            Some(partition) => partition.disk.clone(),
            None => (layer.dm.is_none() && layer.loop_device.is_none() && layer.slaves.is_empty())
                .then(|| layer.name.clone()),
        })
        .collect();
    (!disks.is_empty() || untold.is_some()).then_some(Boot { disks, untold })
}

/// The name to give `sgdisk` for the disk `disk`: its first link in
/// `/dev/disk/by-id`, which names it wherever it is attached, else its
/// kernel name.
fn disk_node<F: Filesystem>(fs: &F, disk: &str) -> String {
    let node = Path::new(DEV_DIR).join(disk);
    let mut links = fs.list_directory(Path::new(BY_ID)).unwrap_or_default();
    links.sort();
    links
        .into_iter()
        .filter(|link| {
            link.file_name()
                .is_some_and(|name| !name.to_string_lossy().contains("-part"))
        })
        .find(|link| fs.canonicalize(link).is_ok_and(|target| target == node))
        .unwrap_or(node)
        .display()
        .to_string()
}

/// The warning that the check cannot tell, and `why`.
fn unchecked(root: &Path, why: &str) -> CheckResult {
    CheckResult::warn_with(
        format!(
            "Could not check the partition type of the hidden root at {}: {why}.",
            root.display()
        ),
        format!(
            "Make sure the hidden root is on no partition of the decoy's disk that has a type \
             systemd mounts or uses at boot. See {DOC}."
        ),
    )
}
