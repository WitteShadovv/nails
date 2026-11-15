// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a line of the decoy's crypttab reads besides its source, as systemd's
//! crypttab generator and `systemd-cryptsetup` read it: its key file, the
//! device of its `keyfile:keydev` key field, its `header=` and the device of a
//! `header=<path>:<device>`, the TrueCrypt key files of its `tcrypt-keyfile=`
//! options, and the devices and files of its TPM2 and FIDO2 options; and the
//! paths and devices the options of a line of the fstab name (see the `known`
//! module).
//!
//! `systemd-cryptsetup` opens the `tpm2-device=` of a line and writes TPM
//! commands to it (systemd 260.5 wrote them to the first bytes of a file
//! given so), opens its `fido2-device=`, and reads its `tpm2-signature=` and
//! `tpm2-pcrlock=` files. Of an fstab line, ext4 opens and writes to the
//! journal device that `journal_path=` names, or `journal_dev=` by its number,
//! XFS to the log and realtime devices of `logdev=` and `rtdev=`, and btrfs
//! opens the devices of `device=` as devices of its filesystem; systemd makes
//! the mounts that hold the paths of `x-systemd.requires-mounts-for=` and
//! `x-systemd.wants-mounts-for=` first, `mount.cifs` reads the file of
//! `credentials=`, and an overlay is made of the folders of `lowerdir=`,
//! `upperdir=` and `workdir=` and writes to its upper one. The judge reads
//! each that is an absolute path as it reads a source, below, a device's path
//! in `/dev` through the links that stay in `/dev`, as the collector resolves
//! a source (see the `collect` module), and the device a number names by its
//! `major:minor`. A device of the filesystem the line mounts itself, as
//! `device=` names one, names nothing besides.
//!
//! An option that has the boot open the device it names for writing (see the
//! `known` module), these devices of an fstab line and `tpm2-device=` and
//! `fido2-device=`, fails its line on any device of the hidden drive, not only
//! on one the volume is stored on: on the drive's whole disk, a partition of
//! it, or a device whose data reaches one of these, as a mapping or an image
//! file there does ([`drive_disks`]). `systemd-cryptsetup` would write TPM
//! commands into the first bytes of a whole disk given so, and a filesystem
//! writes its journal or its log onto what lies on the device it names.
//!
//! The generator splits the key field and each `header=` at the last `:`
//! when what follows is an absolute path or a `UUID=`, `LABEL=`, `PARTUUID=`
//! or `PARTLABEL=` tag ([`split_location`]): that is a device it mounts, a
//! key device read-only and a header device read-write, below
//! `/run/systemd/cryptsetup` before it opens the line, and the part before the
//! `:` is the path of the file on that mount (systemd 260.5 mounted
//! `/dev/mapper/data` for `/key:/dev/mapper/data`, and `/dev/sdd` for
//! `none:/dev/sdd`). Otherwise all of it is the path of the file, which
//! `systemd-cryptsetup` reads where it leads, a device's path in `/dev` as
//! that device, and the generator has the line wait for the device a tag or a
//! path in `/dev` names, or for the mounts of any other path. A key field
//! `none` or `-` gives no key file.
//!
//! The judge reads each device and each file so, that is absolute or a tag, as
//! it reads a line's source: a tag or a device's path in `/dev` as a device's
//! name, and any other path as the path of a file, with no link followed (see
//! the `paths` and `placed` modules). A device the volume is stored on, as the
//! root's stack holds it, makes the line a finding, since the boot mounts it or
//! reads it, and so does a file in the volume or in the root's folder, whose
//! holder the line claims, and one whose place cannot be told. A key file that
//! is neither an absolute path nor a tag, which `systemd-cryptsetup` ignores,
//! names nothing here either, and neither does a `header=` that is neither,
//! which it refuses. The path of a file on a device the boot mounts for it lies
//! on that device, which the judge reads instead: a line is not plain where
//! that path holds a `..`, which can lead out of the mount into this computer's
//! folders, where one leads into `/dev` as written but does not start with
//! `/dev/` or holds a `..` (`//dev/sdb`), and where it gives `keyscript=`, a
//! program Debian's initramfs hands the key field to, which reads it in its own
//! way.

use super::judge::reach;
use super::known::{
    Reading, crypttab_option_reads, device_number, fstab_option_reads, opens_for_writing,
};
use super::paths::{is_file_path, is_untold_device};
use super::placed::{Line, Named, place};
use super::plain::{Unplain, is_read};
use super::{EntryFinding, EntryKind, Scene};
use crate::crypttab::{CrypttabEntry, split_location};
use crate::filesystem::mountinfo::MountEntry;
use crate::fstab::{FstabEntry, option_named};
use std::collections::BTreeSet;
use std::path::{Component, Path};

/// The values of the options of `entry` named `name` with a value.
fn values<'a>(entry: &'a CrypttabEntry, name: &'a str) -> impl Iterator<Item = &'a str> {
    entry
        .options
        .iter()
        .filter_map(move |option| option_named(option, name).flatten())
}

/// What a location, the key field or a `header=`, names: the device the boot
/// mounts for the file, as `device`, or the file itself, as `file`.
fn located(location: &str, file: Named, device: Named) -> (Named, &str) {
    match split_location(location) {
        (_, Some(on)) => (device, on),
        (path, None) => (file, path),
    }
}

/// What the crypttab line `entry` reads besides its source (see the module
/// docs), each with the path or tag that names it: its key file or the
/// device the boot mounts for it, each `header=` or the device the boot
/// mounts for it, each `tcrypt-keyfile=`, and the device or file of each
/// option of a TPM2 or FIDO2 token that names one ([`Named::Option`]). Only
/// those that are an absolute path or a tag, which systemd reads; of the
/// token options, only an absolute path, which they take.
pub(super) fn reads(entry: &CrypttabEntry) -> Vec<(Named, &str)> {
    let key = entry
        .key
        .as_deref()
        .map(|key| located(key, Named::KeyFile, Named::KeyDevice));
    let headers =
        values(entry, "header").map(|header| located(header, Named::Header, Named::HeaderDevice));
    let tcrypt = values(entry, "tcrypt-keyfile").map(|key| (Named::KeyFile, key));
    let tokens = crypttab_option_reads(entry)
        .into_iter()
        .filter(|(_, reading, _)| *reading != Reading::KeyLike)
        .map(|(name, _, value)| (Named::Option(name), value))
        .filter(|(_, value)| value.starts_with('/'));
    key.into_iter()
        .chain(headers)
        .chain(tcrypt)
        .filter(|(_, spec)| is_read(spec))
        .chain(tokens)
        .collect()
}

/// The paths and devices the options of the fstab line `entry` name (see the
/// `known` module), each with the option that names it ([`Named::Option`]):
/// each absolute path of a list apart by `:` too. A device given by its
/// number is in [`fstab_numbers`].
pub(super) fn fstab_reads(entry: &FstabEntry) -> Vec<(Named, &str)> {
    let mut reads = Vec::new();
    for (name, reading, value) in fstab_option_reads(entry) {
        match reading {
            Reading::Paths => {
                reads.extend(value.split(':').map(|path| (Named::Option(name), path)))
            }
            Reading::Number => {}
            _ => reads.push((Named::Option(name), value)),
        }
    }
    reads
}

/// The devices the options of the fstab line `entry` name by their number,
/// ext4's `journal_dev=`, each with the option that names it and the device
/// as `major:minor`.
pub(super) fn fstab_numbers(entry: &FstabEntry) -> Vec<(Named, String)> {
    fstab_option_reads(entry)
        .into_iter()
        .filter(|(_, reading, _)| *reading == Reading::Number)
        .filter_map(|(name, _, value)| Some((Named::Option(name), device_number(value)?)))
        .collect()
}

/// Why what the crypttab line `entry` reads besides its source makes a line
/// that is not plain (see the module docs), but for a `//dev` form, which the
/// `plain` module tells with the source's: nothing for a plain line.
pub(super) fn unplain(entry: &CrypttabEntry) -> Vec<Unplain> {
    let mut why = Vec::new();
    let on_device = entry
        .key
        .as_deref()
        .map(|key| ("key file", key))
        .into_iter()
        .chain(values(entry, "header").map(|header| ("header", header)));
    for (what, location) in on_device {
        if let (path, Some(_)) = split_location(location)
            && Path::new(path)
                .components()
                .any(|part| part == Component::ParentDir)
        {
            why.push(Unplain::UpOutOfDevice(what));
        }
    }
    if entry
        .options
        .iter()
        .any(|option| option_named(option, "keyscript").is_some())
    {
        why.push(Unplain::Keyscript);
    }
    why
}

/// The hidden drive, against which what a line reads is judged.
pub(super) struct HiddenDrive<'a> {
    /// The devices an entry for the hidden drive names: the root's stack,
    /// the other devices of its btrfs filesystem and those below them.
    pub devices: &'a [String],
    /// The whole disks the root's data lies on ([`drive_disks`]).
    pub disks: &'a BTreeSet<String>,
}

/// The whole disks the data of the devices `devices` lies on: the disk of
/// each partition and each whole disk among the devices their data reaches
/// ([`reach`]), as far down as it goes, through the files of loop devices
/// too.
pub(super) fn drive_disks(scene: &Scene<'_>, devices: &[String]) -> BTreeSet<String> {
    reach(scene, devices, &BTreeSet::new())
        .iter()
        .filter_map(|node| scene.devices.disk_of(node))
        .map(str::to_string)
        .collect()
}

/// Whether the data of the device `node` reaches one of `disks`: it is one
/// of them, a partition of one, or a device stacked on one, as far down as
/// its data goes ([`drive_disks`]).
fn reaches_a_disk_of(scene: &Scene<'_>, node: &str, disks: &BTreeSet<String>) -> bool {
    drive_disks(scene, &[node.to_string()])
        .iter()
        .any(|disk| disks.contains(disk))
}

/// Why a device that a line opens for writing through its option `option`
/// makes a finding when it lies on the drive of the volume at `root`, its
/// whole disk, a partition of it or a device stacked on it, though not on a
/// device the volume is stored on.
fn drive_why(option: &str, root: &Path) -> String {
    format!(
        "it opens a device of the drive the volume at {} is stored on for writing through its \
         option {option}=",
        root.display()
    )
}

/// Why a device that a line reads `named` lies on the hidden drive, the
/// volume at `root` or a device it is stored on, makes a finding.
fn device_why(named: Named, root: &Path) -> String {
    let root = root.display();
    match named {
        Named::KeyDevice => {
            format!("it mounts the volume at {root} or a device it is stored on for its key file")
        }
        Named::HeaderDevice => {
            format!("it mounts the volume at {root} or a device it is stored on for its header")
        }
        Named::Header => {
            format!("it reads its header from the volume at {root} or a device it is stored on")
        }
        Named::Option(option) => format!(
            "it opens the volume at {root} or a device it is stored on through its option \
             {option}="
        ),
        _ => format!("it reads its key file from the volume at {root} or a device it is stored on"),
    }
}

/// What a line reads besides its source, to judge: the line, the paths and
/// tags it reads ([`reads`], [`fstab_reads`]) and the devices it names by
/// their number ([`fstab_numbers`]).
pub(super) struct Reads<'a, 'b> {
    /// The line, which a finding shows.
    pub line: Line,
    /// The paths and tags, with what each names.
    pub specs: Vec<(Named, &'b str)>,
    /// The devices by `major:minor`, with what each names.
    pub numbers: Vec<(Named, String)>,
    /// A device a read device may be without a finding: one of the
    /// filesystem the line mounts itself, which btrfs's `device=` names.
    pub own: &'a dyn Fn(&str) -> bool,
}

/// The findings of what a line reads besides its source (`reads`), judged
/// against `hidden`, the visible mount at the hidden root, and its drive,
/// `drive`, and the mounts that hold the files it reads, which the line
/// claims. A device the volume is stored on makes a finding, and so does
/// any other device of its drive that an option opens for writing
/// ([`opens_for_writing`]): the drive's whole disk, a partition of it or a
/// device stacked on one of them.
pub(super) fn judge_reads<'a>(
    scene: &Scene<'a>,
    hidden: &MountEntry,
    reads: &Reads<'_, '_>,
    drive: &HiddenDrive<'_>,
) -> (Vec<EntryFinding>, Vec<&'a MountEntry>) {
    let mut findings = Vec::new();
    let mut holders = Vec::new();
    let finding = |why: String| EntryFinding {
        kind: EntryKind::Blocking,
        file: reads.line.file,
        line: reads.line.shown.clone(),
        why,
        boot_needs: reads.line.boot_needs,
        system_folder: None,
        not_plain: false,
        options: Vec::new(),
    };
    // Why the device `node` that `named` names makes a finding, if it does.
    let why = |named: Named, node: &str| {
        if (reads.own)(node) {
            None
        } else if drive.devices.iter().any(|n| n == node) {
            Some(device_why(named, &hidden.mount_point))
        } else {
            match named {
                Named::Option(option)
                    if opens_for_writing(option) && reaches_a_disk_of(scene, node, drive.disks) =>
                {
                    Some(drive_why(option, &hidden.mount_point))
                }
                _ => None,
            }
        }
    };
    for (named, spec) in &reads.specs {
        if is_file_path(spec) || is_untold_device(scene.paths, spec) {
            let line = Line {
                named: *named,
                ..reads.line.clone()
            };
            let (found, holder) = place(scene, hidden, &line, spec);
            findings.extend(found);
            holders.extend(holder);
        } else if let Some(why) = scene
            .devices
            .node_of_spec(spec)
            .and_then(|node| why(*named, node))
        {
            findings.push(finding(why));
        }
    }
    for (named, dev) in &reads.numbers {
        if let Some(why) = scene
            .devices
            .by_dev
            .get(dev)
            .and_then(|node| why(*named, node))
        {
            findings.push(finding(why));
        }
    }
    (findings, holders)
}

/// The findings of what the crypttab line `entry`, shown as `shown`, reads
/// besides its source ([`reads`]), judged against `hidden`, the visible
/// mount at the hidden root, and its drive, `drive` ([`judge_reads`]), and
/// the mounts that hold the files it reads, which the line claims.
/// `boot_needs` tells whether the decoy's own boot needs the line.
pub(super) fn judged<'a>(
    scene: &Scene<'a>,
    hidden: &MountEntry,
    entry: &CrypttabEntry,
    shown: &str,
    drive: &HiddenDrive<'_>,
    boot_needs: bool,
) -> (Vec<EntryFinding>, Vec<&'a MountEntry>) {
    let reads = Reads {
        line: Line {
            file: super::CRYPTTAB,
            shown: shown.to_string(),
            named: Named::KeyFile,
            boot_needs,
        },
        specs: reads(entry),
        numbers: Vec::new(),
        own: &|_| false,
    };
    judge_reads(scene, hidden, &reads, drive)
}

#[cfg(test)]
#[path = "reads_tests.rs"]
mod tests;
