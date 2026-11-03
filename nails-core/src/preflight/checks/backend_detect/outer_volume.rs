// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether another VeraCrypt or TrueCrypt mapping of the device the hidden
//! root's volume is opened from, its outer volume most of all, is open
//! read-write beside it.
//!
//! A VeraCrypt hidden volume lies in the free space of its outer volume, so
//! a write to the outer volume can land on the hidden one. VeraCrypt guards
//! against that only with its hidden-volume protection, which cryptsetup
//! does not offer, and which the VeraCrypt application gives only through
//! FUSE, outside the kernel. An outer volume that cryptsetup or the
//! VeraCrypt application's kernel path opened read-write, mounted or not,
//! can overwrite the hidden root while a session runs on it: one write of
//! its filesystem's own, a journal replay at a mount, a file someone saves.
//!
//! For each TCRYPT, SUBDEV or VeraCrypt mapping of the hidden root's stack
//! (a SUBDEV mapping that names a volume uuid is the integrity layer of a
//! LUKS2 volume, and none of them), the check takes the device below it and
//! the devices that hold the same data: a loop device over that device,
//! and, where the device is itself a loop device, the device or file below
//! it with every other loop device over that device, or over that file from
//! the same offset. A VeraCrypt or TrueCrypt mapping built on any of these
//! that is no part of the hidden root's stack is another mapping of the
//! volume, and it warns unless the kernel holds it read-only (`ro`). It
//! reads sysfs and the mount table alone, never a mapping's table.

use super::graph::{Graph, filesystem_devices};
use super::luks2::names_a_volume;
use crate::blockdev::{self, DmKind, Layer, LoopBacking, LoopFollow, MAX_STACK_DEVICES};
use crate::config::get_default_hidden_volume_root;
use crate::filesystem::mountinfo::{MountEntry, top_mount_at};
use crate::hidden_root::separation::{self, SYS_CLASS_BLOCK};
use crate::preflight::{CheckResult, PreFlightCheck};
use crate::{Filesystem, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[cfg(test)]
mod tests;

/// Where the outer volume is explained.
const DOC: &str = "docs/backends.md";

/// What the operator does about an outer volume open read-write.
const FIX: &str = "Unmount it and close it before activating (cryptsetup close <name>, or \
     veracrypt --dismount for a volume the VeraCrypt application mounted), or open it read-only \
     with cryptsetup open --readonly when it has to be shown. See docs/backends.md.";

/// Pre-flight check that warns when another VeraCrypt or TrueCrypt mapping
/// of the device the hidden root's volume is opened from is open read-write.
///
/// # Pass and warn
///
/// It warns, naming the other mapping, the device it is opened from and
/// where it is mounted, read-write or read-only, when the kernel holds it
/// writable; a mapping the VeraCrypt application made is writable even for
/// a volume it mounted read-only. It warns as well when it cannot look:
/// when the hidden root's filesystem shows no block device, or sysfs does
/// not let it list the devices below the hidden root or built on its
/// storage. It passes when every such mapping is read-only, when there is
/// none, and when the hidden root's stack holds no VeraCrypt or TrueCrypt
/// mapping. It never fails.
#[derive(Debug, Clone)]
pub struct OuterVolumeCheck {
    hidden_volume_root: PathBuf,
}

impl OuterVolumeCheck {
    /// A check of the volume mounted at `hidden_volume_root`.
    pub fn new(hidden_volume_root: PathBuf) -> Self {
        Self { hidden_volume_root }
    }
}

impl Default for OuterVolumeCheck {
    /// Create the check with the default hidden-volume path.
    fn default() -> Self {
        Self::new(PathBuf::from(get_default_hidden_volume_root()))
    }
}

impl<F: Filesystem> PreFlightCheck<F> for OuterVolumeCheck {
    fn name(&self) -> &'static str {
        "outer-volume"
    }

    fn description(&self) -> &'static str {
        "Warns when another VeraCrypt or TrueCrypt mapping of the hidden volume's device is open read-write"
    }

    fn requires_hidden_volume(&self) -> bool {
        true
    }

    fn run(&self, fs: &F) -> Result<CheckResult> {
        let root = &self.hidden_volume_root;
        let shown = root.display();
        let Ok(table) = fs.mount_table() else {
            return Ok(unchecked(root, "the mount table cannot be read"));
        };
        let canonical = fs.canonicalize(root).unwrap_or_else(|_| root.clone());
        let Some(hidden) = top_mount_at(&table, &canonical) else {
            // The attach gate refuses a root that is no mount point, and the
            // registry skips this check then.
            return Ok(CheckResult::Pass(format!(
                "Outer volume check skipped: nothing is mounted at {shown}"
            )));
        };
        if matches!(hidden.fstype.as_str(), "tmpfs" | "ramfs") {
            return Ok(CheckResult::Pass(format!(
                "The hidden root at {shown} is a {}, in no VeraCrypt or TrueCrypt volume.",
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
        let graph = Graph::read(
            fs,
            &table,
            &separation::DeviceMap::default(),
            &roots,
            LoopFollow::BlockDevices,
        );
        if !graph.complete() {
            return Ok(unchecked(root, "the devices below it cannot all be listed"));
        }
        let below: BTreeSet<String> = graph
            .layers
            .values()
            .filter(|layer| outer_kind(layer).is_some())
            .flat_map(|layer| layer.slaves.iter().cloned())
            .filter(|slave| {
                graph
                    .layers
                    .get(slave)
                    .is_none_or(|layer| outer_kind(layer).is_none())
            })
            .collect();
        if below.is_empty() {
            return Ok(CheckResult::Pass(format!(
                "The hidden root at {shown} is in no VeraCrypt or TrueCrypt volume, so no outer \
                 volume of it can be open."
            )));
        }

        let Some(devices) = Devices::read(fs) else {
            return Ok(unchecked(root, "the block devices cannot be listed"));
        };
        let mut others: BTreeMap<String, Other> = BTreeMap::new();
        for device in &below {
            let Some(holders) = devices.holders_of_data(device, &graph) else {
                return Ok(unchecked(
                    root,
                    "the devices built on its storage cannot all be listed",
                ));
            };
            for (holder, on) in holders {
                if graph.layers.contains_key(&holder) || others.contains_key(&holder) {
                    continue;
                }
                let Some(layer) = devices.layer(&holder) else {
                    continue;
                };
                if let Some(kind) = outer_kind(&layer) {
                    let top = devices.top(&holder);
                    others.insert(
                        holder,
                        Other {
                            kind,
                            device: on,
                            writable: !layer.read_only,
                            mounts: mounts_of(fs, &table, &top),
                            name: top_name(&top),
                        },
                    );
                }
            }
        }
        Ok(verdict(root, &below, &others))
    }
}

/// What kind of mapping of a VeraCrypt or TrueCrypt volume a layer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OuterKind {
    /// A mapping cryptsetup made: `TCRYPT`, or the `SUBDEV` layers below
    /// one for the further ciphers of a cascade.
    Cryptsetup,
    /// A mapping the VeraCrypt application made through the kernel.
    VeraCrypt,
}

/// What kind of VeraCrypt or TrueCrypt mapping `layer` is, if it is one. A
/// `SUBDEV` mapping that names a volume uuid is none: cryptsetup 2.8 and
/// later give that name to the integrity layer of a LUKS2 volume with
/// authenticated encryption too, and a TCRYPT volume has no uuid.
fn outer_kind(layer: &Layer) -> Option<OuterKind> {
    let dm = layer.dm.as_ref()?;
    match &dm.kind {
        DmKind::Crypt(kind) if kind == "TCRYPT" => Some(OuterKind::Cryptsetup),
        DmKind::CryptSubdev if !names_a_volume(&dm.uuid) => Some(OuterKind::Cryptsetup),
        DmKind::VeraCrypt => Some(OuterKind::VeraCrypt),
        _ => None,
    }
}

/// Another mapping of the device the hidden root's volume is opened from.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Other {
    /// Who made it.
    kind: OuterKind,
    /// The device it is opened from, as the hidden volume is.
    device: String,
    /// Whether the kernel lets it be written.
    writable: bool,
    /// Where it, or a device built on it, is mounted, each read-only or not.
    mounts: Vec<(PathBuf, bool)>,
    /// The topmost mapping built on it, as the operator knows it:
    /// `outer (dm-4)`.
    name: String,
}

/// The block devices sysfs shows, read as the check needs them.
struct Devices<'a, F: Filesystem> {
    fs: &'a F,
    /// Every bound loop device.
    loops: Vec<Layer>,
}

impl<'a, F: Filesystem> Devices<'a, F> {
    /// Read the bound loop devices; `None` when the block devices cannot be
    /// listed.
    fn read(fs: &'a F) -> Option<Self> {
        let mut entries = fs.list_directory(Path::new(SYS_CLASS_BLOCK)).ok()?;
        entries.sort();
        let loops = entries
            .iter()
            .filter(|entry| {
                entry
                    .file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.strip_prefix("loop"))
                    .is_some_and(|number| {
                        !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit())
                    })
            })
            .filter_map(|entry| one(fs, entry))
            .filter(|layer| layer.loop_device.is_some())
            .collect();
        Some(Self { fs, loops })
    }

    /// The device `name`, read alone.
    fn layer(&self, name: &str) -> Option<Layer> {
        one(self.fs, &Path::new(SYS_CLASS_BLOCK).join(name))
    }

    /// The devices built on `device`, the one a VeraCrypt or TrueCrypt
    /// mapping of the hidden root reads, or on another device that holds its
    /// data: a loop device over it, and where it is a loop device, the
    /// device below it and the loop devices over that, or the other loop
    /// devices over its file from the same offset. Each with the device it
    /// is built on; `None` when one of these devices cannot be read, or its
    /// `holders/` cannot be listed.
    fn holders_of_data(&self, device: &str, graph: &Graph) -> Option<BTreeSet<(String, String)>> {
        let read = graph
            .layers
            .get(device)
            .cloned()
            .or_else(|| self.layer(device));
        let mut same = BTreeSet::from([device.to_string()]);
        same.extend(self.loops_over_device(device));
        if let Some(bound) = read.as_ref().and_then(|layer| layer.loop_device.as_ref()) {
            match &bound.backing {
                LoopBacking::Block { name, .. } => {
                    same.insert(name.clone());
                    same.extend(self.loops_over_device(name));
                }
                LoopBacking::File(file) => {
                    same.extend(
                        self.loops
                            .iter()
                            .filter(|other| {
                                other.loop_device.as_ref().is_some_and(|loop_device| {
                                    loop_device.backing == LoopBacking::File(file.clone())
                                        && loop_device.offset == bound.offset
                                })
                            })
                            .map(|other| other.name.clone()),
                    );
                }
            }
        }
        let mut holders = BTreeSet::new();
        for name in &same {
            let layer = match graph.layers.get(name) {
                Some(layer) => layer.clone(),
                None => self.layer(name)?,
            };
            if layer.holders_unread {
                return None;
            }
            holders.extend(
                layer
                    .holders
                    .into_iter()
                    .map(|holder| (holder, name.clone())),
            );
        }
        Some(holders)
    }

    /// The loop devices bound to the block device `name`.
    fn loops_over_device(&self, name: &str) -> Vec<String> {
        self.loops
            .iter()
            .filter(|layer| {
                layer.loop_device.as_ref().is_some_and(
                    |bound| matches!(&bound.backing, LoopBacking::Block { name: below, .. } if below == name),
                )
            })
            .map(|layer| layer.name.clone())
            .collect()
    }

    /// `name` and the devices built on it, up to the topmost: the walk up
    /// `holders/`, `name` first, at most [`MAX_STACK_DEVICES`] devices.
    fn top(&self, name: &str) -> Vec<Layer> {
        let mut chain = Vec::new();
        let mut pending = vec![name.to_string()];
        let mut seen = BTreeSet::new();
        while let Some(next) = pending.pop() {
            if chain.len() >= MAX_STACK_DEVICES || !seen.insert(next.clone()) {
                continue;
            }
            if let Some(layer) = self.layer(&next) {
                pending.extend(layer.holders.iter().rev().cloned());
                chain.push(layer);
            }
        }
        chain
    }
}

/// The device whose sysfs directory is `dir`, read alone.
fn one<F: Filesystem>(fs: &F, dir: &Path) -> Option<Layer> {
    blockdev::walk(fs, dir, LoopFollow::Never, 1)
        .layers
        .into_iter()
        .next()
}

/// Where the devices of `chain` are mounted, each mount read-only or not.
fn mounts_of<F: Filesystem>(fs: &F, table: &[MountEntry], chain: &[Layer]) -> Vec<(PathBuf, bool)> {
    let names: BTreeSet<&str> = chain.iter().map(|layer| layer.name.as_str()).collect();
    table
        .iter()
        .filter(|mount| {
            blockdev::device_of_mount(fs, mount)
                .and_then(|dir| {
                    dir.file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                })
                .is_some_and(|name| names.contains(name.as_str()))
        })
        .map(|mount| (mount.mount_point.clone(), mount.read_only()))
        .collect()
}

/// The topmost mapping of `chain`, as the operator knows it: its
/// device-mapper name and its kernel name, `outer (dm-4)`.
fn top_name(chain: &[Layer]) -> String {
    chain
        .iter()
        .rev()
        .find(|layer| layer.holders.is_empty())
        .or_else(|| chain.first())
        .map(|layer| match &layer.dm {
            Some(dm) if !dm.name.is_empty() => format!("{} ({})", dm.name, layer.name),
            _ => layer.name.clone(),
        })
        .unwrap_or_default()
}

/// The result for `others`, the other mappings of the data of `below`, the
/// devices the hidden root's VeraCrypt or TrueCrypt mappings are opened
/// from.
fn verdict(root: &Path, below: &BTreeSet<String>, others: &BTreeMap<String, Other>) -> CheckResult {
    let storage = format!(
        "the storage the hidden root's volume at {} is opened from",
        root.display()
    );
    let writable: Vec<&Other> = others.values().filter(|other| other.writable).collect();
    if !writable.is_empty() {
        let sentences: Vec<String> = writable
            .iter()
            .map(|other| {
                let protection = match other.kind {
                    OuterKind::Cryptsetup => {
                        "cryptsetup offers no hidden-volume protection, so a write to it can \
                         overwrite the hidden root."
                    }
                    OuterKind::VeraCrypt => {
                        "A mapping the VeraCrypt application makes in the kernel has no \
                         hidden-volume protection, and the application leaves it writable even \
                         for a volume it mounts read-only, so a write to it can overwrite the \
                         hidden root."
                    }
                };
                format!(
                    "Another VeraCrypt or TrueCrypt mapping is open read-write on {storage}: {}, \
                     on {}, {}. {protection}",
                    other.name,
                    other.device,
                    mounted(&other.mounts)
                )
            })
            .collect();
        return CheckResult::warn_with(sentences.join(" "), FIX);
    }
    if others.is_empty() {
        return CheckResult::Pass(format!(
            "No other VeraCrypt or TrueCrypt mapping is open on {storage} ({}).",
            below.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    let names: Vec<String> = others
        .values()
        .map(|other| format!("{}, on {}", other.name, other.device))
        .collect();
    CheckResult::Pass(format!(
        "Other VeraCrypt or TrueCrypt mappings are open on {storage}, all of them read-only, so \
         no write through them reaches it: {}.",
        names.join("; ")
    ))
}

/// Where a mapping is mounted, for a sentence.
fn mounted(mounts: &[(PathBuf, bool)]) -> String {
    if mounts.is_empty() {
        return "not mounted".to_string();
    }
    let places: Vec<String> = mounts
        .iter()
        .map(|(at, read_only)| {
            format!(
                "{} at {}",
                if *read_only {
                    "read-only"
                } else {
                    "read-write"
                },
                at.display()
            )
        })
        .collect();
    format!("mounted {}", places.join(" and "))
}

/// The warning that the check cannot look, and `why`.
fn unchecked(root: &Path, why: &str) -> CheckResult {
    CheckResult::warn_with(
        format!(
            "Could not check for an outer volume open beside the hidden root at {}: {why}.",
            root.display()
        ),
        format!(
            "Make sure no outer volume of the hidden volume is open read-write while it is in \
             use. See {DOC}."
        ),
    )
}
