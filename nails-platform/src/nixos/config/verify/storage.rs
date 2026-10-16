// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the hidden volume is stored on, and the names a decoy configuration
//! could give it.
//!
//! The mount table names only the top device (`/dev/mapper/data`). A
//! configuration can name the volume by what lies below it as well, and each
//! device by several names. [`below`] reads them from the system through the
//! [`Filesystem`] trait, for every layer the hidden volume alone uses:
//!
//! - from sysfs, the layers: the LUKS mapping, the partition (`/dev/sdb2`) and
//!   its partition uuid, a mapping below a logical volume, the image file
//!   behind a loop device, and each mapping's `dm-uuid` link and LUKS uuid;
//! - from udev's database (`/run/udev/data/b<major>:<minor>`), every link
//!   udev made for a layer: each `/dev/disk/by-*` name (`by-id`, `by-path`,
//!   `by-partlabel`, `by-partuuid`, `by-diskseq`, the `by-uuid` and
//!   `by-label` of the LUKS header or the filesystem), the LVM path
//!   (`/dev/<vg>/<lv>`) and the mapper links; and the identifiers a
//!   configuration writes as a tag: the uuid (`UUID=`, the filesystem's own
//!   and the LUKS header's), the label (`LABEL=`) and the partition label
//!   (`PARTLABEL=`);
//! - the entries of `/dev/disk/by-*` that resolve to a layer, should udev's
//!   database lack one.

use super::nix_text::Pattern;
use crate::filesystem::Filesystem;
use nails_base::blockdev::{self, DeviceMapper, DmKind, Layer, LoopBacking, LoopFollow};
use nails_base::filesystem::MountEntry;
use std::path::{Path, PathBuf};

/// udev's database: one file per block device, `b<major>:<minor>`.
const UDEV_DATA: &str = "/run/udev/data";
/// The directories of links udev makes for block devices.
const DEV_DISK: &str = "/dev/disk";

/// The storage below the hidden volume's mount, lowercased like the text it
/// is matched against.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Storage {
    /// The device-mapper name of every layer, top first.
    pub(super) names: Vec<String>,
    /// The paths and identifiers of the layers: their links and device
    /// nodes, LUKS, filesystem and partition uuids, labels, image files.
    pub(super) markers: Vec<Pattern>,
}

/// The storage below the top mount at `root` in `mounts`. A device below the
/// top one counts only while everything built on it belongs to the hidden
/// volume: when the hidden root is a logical volume in the decoy's own
/// encrypted volume group, the LUKS mapping and the partition below it are
/// the decoy's, and its configuration names them.
pub(super) fn below<F: Filesystem>(fs: &F, mounts: &[MountEntry], root: &Path) -> Storage {
    let mut storage = Storage::default();
    let Some(mount) = mounts.iter().rev().find(|m| m.mount_point == root) else {
        return storage;
    };
    let Some(top) = blockdev::device_of_mount(fs, mount) else {
        return storage;
    };
    let layers = blockdev::stack(fs, &top, LoopFollow::BlockDevices);
    let mut own: Vec<&str> = Vec::new();
    for (index, layer) in layers.iter().enumerate() {
        let alone = index == 0
            || (!layer.holders.is_empty()
                && layer
                    .holders
                    .iter()
                    .all(|holder| own.contains(&holder.as_str())));
        if alone {
            own.push(&layer.name);
            storage.add(layer);
            storage.add_udev_names(fs, layer);
        }
    }
    storage
}

impl Storage {
    fn push(&mut self, pattern: Pattern) {
        if !self.markers.contains(&pattern) {
            self.markers.push(pattern);
        }
    }

    /// A path, in each spelling a `.nix` file can give it: a link name with
    /// an escape in it (`by-label/My\x20Data`) has its backslash doubled in
    /// a double-quoted string.
    fn path(&mut self, path: &str) {
        let path = path.to_ascii_lowercase();
        if path.contains('\\') {
            self.push(Pattern::Path(path.replace('\\', "\\\\")));
        }
        self.push(Pattern::Path(path));
    }

    /// An identifier written as text (a uuid) or as a tag (a label).
    fn identifier(&mut self, kind: Identifier, value: &str) {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() {
            return;
        }
        self.push(match kind {
            Identifier::Uuid => Pattern::Text(value),
            Identifier::Label => Pattern::Tag {
                tag: "label".into(),
                value,
            },
            Identifier::PartLabel => Pattern::Tag {
                tag: "partlabel".into(),
                value,
            },
        });
    }

    fn add(&mut self, layer: &Layer) {
        if let Some(dm) = &layer.dm {
            let name = dm.name.trim().to_ascii_lowercase();
            if !name.is_empty() && !self.names.contains(&name) {
                self.names.push(name);
            }
            let uuid = dm.uuid.trim();
            if !uuid.is_empty() {
                self.path(&format!("/dev/disk/by-id/dm-uuid-{uuid}"));
            }
            if let Some(uuid) = luks_uuid(dm) {
                self.identifier(Identifier::Uuid, &uuid);
            }
        } else if let Some(device) = &layer.loop_device {
            // A loop over a block device has that device as a layer of its own.
            if let LoopBacking::File(path) = &device.backing {
                self.path(&path.to_string_lossy());
            }
        } else if !layer.name.is_empty() {
            self.path(&format!("/dev/{}", layer.name));
            if let Some(uuid) = layer.partition.as_ref().and_then(|p| p.uuid.as_deref()) {
                self.identifier(Identifier::Uuid, uuid);
            }
        }
    }

    /// The names udev gives `layer`: every link it made below `/dev`, from
    /// its database and from the `/dev/disk/by-*` directories, and the
    /// identifiers its database records.
    fn add_udev_names<F: Filesystem>(&mut self, fs: &F, layer: &Layer) {
        if let Some(dev) = &layer.dev {
            let record = fs
                .read_file_content(&Path::new(UDEV_DATA).join(format!("b{dev}")))
                .unwrap_or_default();
            let property = |key: &str| {
                record.lines().find_map(|line| {
                    line.strip_prefix("E:")?
                        .strip_prefix(key)?
                        .strip_prefix('=')
                })
            };
            for link in record.lines().filter_map(|line| line.strip_prefix("S:")) {
                self.path(&format!("/dev/{}", link.trim()));
            }
            for key in ["ID_FS_UUID", "ID_FS_UUID_SUB", "ID_PART_ENTRY_UUID"] {
                if let Some(uuid) = property(key) {
                    self.identifier(Identifier::Uuid, uuid);
                }
            }
            // The encoded label is the one `by-label` shows; the plain one has
            // its blanks replaced.
            if let Some(label) = property("ID_FS_LABEL_ENC").or_else(|| property("ID_FS_LABEL")) {
                self.identifier(Identifier::Label, &unescape(label));
            }
            if let Some(name) = property("ID_PART_ENTRY_NAME") {
                self.identifier(Identifier::PartLabel, &unescape(name));
            }
        }
        if layer.name.is_empty() {
            return;
        }
        let node = Path::new("/dev").join(&layer.name);
        for dir in listing(fs, Path::new(DEV_DISK)) {
            let kind = match dir.file_name().and_then(|name| name.to_str()) {
                Some("by-uuid" | "by-partuuid") => Some(Identifier::Uuid),
                Some("by-label") => Some(Identifier::Label),
                Some("by-partlabel") => Some(Identifier::PartLabel),
                _ => None,
            };
            for link in listing(fs, &dir) {
                if fs.canonicalize(&link).ok().map(lexical) != Some(node.clone()) {
                    continue;
                }
                self.path(&link.to_string_lossy());
                if let (Some(kind), Some(name)) = (kind, link.file_name().and_then(|n| n.to_str()))
                {
                    self.identifier(kind, &unescape(name));
                }
            }
        }
    }
}

/// How a configuration writes an identifier of a device.
#[derive(Debug, Clone, Copy)]
enum Identifier {
    /// As text: a uuid is unique, wherever it appears.
    Uuid,
    /// As `LABEL=`, or a `fileSystems` or `swapDevices` entry's `label`.
    Label,
    /// As `PARTLABEL=`.
    PartLabel,
}

/// `path` with its `..` components applied, as a resolved path has them.
fn lexical(path: PathBuf) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

/// The entries of `dir`; none when it cannot be listed.
fn listing<F: Filesystem>(fs: &F, dir: &Path) -> Vec<PathBuf> {
    let mut entries = fs.list_directory(dir).unwrap_or_default();
    entries.sort();
    entries
}

/// `text` with udev's `\xNN` escapes decoded (`My\x20Data` is `My Data`).
fn unescape(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = bytes
            .get(i + 2..i + 4)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match hex {
            Some(byte) if bytes[i] == b'\\' && bytes[i + 1] == b'x' => {
                out.push(byte);
                i += 4;
            }
            _ => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The LUKS uuid of a LUKS mapping, as `/dev/disk/by-uuid` and crypttab's
/// `UUID=` write it: cryptsetup names the mapping
/// `CRYPT-LUKS2-<32 hex digits>-<name>`.
fn luks_uuid(dm: &DeviceMapper) -> Option<String> {
    if !matches!(&dm.kind, DmKind::Crypt(kind) if kind.starts_with("LUKS")) {
        return None;
    }
    let hex = dm.uuid.trim().split('-').nth(2)?.to_ascii_lowercase();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

#[cfg(test)]
#[path = "storage_tests.rs"]
mod tests;
