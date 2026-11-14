// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a line of the decoy's crypttab reads besides its source, as systemd's
//! crypttab generator and `systemd-cryptsetup` read it: its key file, the
//! device of its `keyfile:keydev` key field, its `header=` and the device of a
//! `header=<path>:<device>`, and the TrueCrypt key files of its
//! `tcrypt-keyfile=` options.
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
//! The judge reads each device and each file so, that is absolute or a tag,
//! as it reads a line's source: a tag or a device's path in `/dev` as a
//! device's name, and any other path as the path of a file, with no link
//! followed (see the `paths` and `placed` modules). A device of the hidden
//! drive, as the root's stack holds it, makes the line a finding, since the
//! boot mounts it or reads it, and so does a file in the volume or in the
//! root's folder, whose holder the line claims, and one whose place cannot be
//! told. A key file that is no absolute path, which `systemd-cryptsetup`
//! ignores, names nothing here either, and a `header=` that is none it
//! refuses. The path of a file on a device the boot mounts for it lies on
//! that device, which the judge reads instead: a line is not plain where that
//! path holds a `..`, which can lead out of the mount into this computer's
//! folders, where one leads into `/dev` as written but does not start with
//! `/dev/` or holds a `..` (`//dev/sdb`), and where it gives `keyscript=`, a
//! program Debian's initramfs hands the key field to, which reads it in its
//! own way.

use super::paths::{is_file_path, is_untold_device};
use super::placed::{Line, Named, place};
use super::plain::{Unplain, is_read};
use super::{CRYPTTAB, EntryFinding, EntryKind, Scene};
use crate::crypttab::{CrypttabEntry, split_location};
use crate::filesystem::mountinfo::MountEntry;
use crate::fstab::option_named;
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
/// mounts for it, and each `tcrypt-keyfile=`. Only those that are an
/// absolute path or a tag, which systemd reads.
pub(super) fn reads(entry: &CrypttabEntry) -> Vec<(Named, &str)> {
    let key = entry
        .key
        .as_deref()
        .map(|key| located(key, Named::KeyFile, Named::KeyDevice));
    let headers =
        values(entry, "header").map(|header| located(header, Named::Header, Named::HeaderDevice));
    let tcrypt = values(entry, "tcrypt-keyfile").map(|key| (Named::KeyFile, key));
    key.into_iter()
        .chain(headers)
        .chain(tcrypt)
        .filter(|(_, spec)| is_read(spec))
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

/// Why a device that a line of the crypttab reads `named` lies on the hidden
/// drive, the volume at `root` or a device it is stored on, makes a finding.
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
        _ => format!("it reads its key file from the volume at {root} or a device it is stored on"),
    }
}

/// The findings of what the crypttab line `entry`, shown as `shown`, reads
/// besides its source ([`reads`]), judged against `hidden`, the visible
/// mount at the hidden root, whose drive's devices `drive` holds, and the
/// mounts that hold the files it reads, which the line claims. `boot_needs`
/// tells whether the decoy's own boot needs the line.
pub(super) fn judged<'a>(
    scene: &Scene<'a>,
    hidden: &MountEntry,
    entry: &CrypttabEntry,
    shown: &str,
    drive: &[String],
    boot_needs: bool,
) -> (Vec<EntryFinding>, Vec<&'a MountEntry>) {
    let mut findings = Vec::new();
    let mut holders = Vec::new();
    for (named, spec) in reads(entry) {
        if is_file_path(spec) || is_untold_device(scene.paths, spec) {
            let line = Line {
                file: CRYPTTAB,
                shown: shown.to_string(),
                named,
                boot_needs,
            };
            let (finding, holder) = place(scene, hidden, &line, spec);
            findings.extend(finding);
            holders.extend(holder);
        } else if scene
            .devices
            .node_of_spec(spec)
            .is_some_and(|node| drive.iter().any(|n| n == node))
        {
            findings.push(EntryFinding {
                kind: EntryKind::Blocking,
                file: CRYPTTAB,
                line: shown.to_string(),
                why: device_why(named, &hidden.mount_point),
                boot_needs,
                system_folder: None,
                not_plain: false,
            });
        }
    }
    (findings, holders)
}

#[cfg(test)]
#[path = "reads_tests.rs"]
mod tests;
