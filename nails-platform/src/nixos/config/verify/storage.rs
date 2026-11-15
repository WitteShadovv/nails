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
//! - from sysfs too, the kernel's name of each layer (`dm-0`, `sdb2`,
//!   `loop0`), which a udev rule writes without `/dev/` (`KERNEL=="sdb2"`),
//!   its device node (`/dev/dm-0`) and the `/dev/block/<major>:<minor>` link
//!   udev makes for it;
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
use nails_base::blockdev::{self, Attribute, DeviceMapper, DmKind, Layer, LoopBacking, LoopFollow};
use nails_base::filesystem::MountEntry;
use std::path::{Path, PathBuf};

/// udev's database: one file per block device, `b<major>:<minor>`.
const UDEV_DATA: &str = "/run/udev/data";
/// The directories of links udev makes for block devices.
const DEV_DISK: &str = "/dev/disk";

/// The attributes and listings of a layer in sysfs that give a name the
/// scan looks for, or the layers it looks at: the kernel name and the
/// partition's uuid (`uevent`), the device number that names the udev
/// record and the `/dev/block` link (`dev`), the device-mapper name and
/// uuid, whether it is a partition, the file a loop device reads, and the
/// devices built on it and below it (`holders/`, `slaves/`). The others give
/// no name.
const NAMES: &[Attribute] = &[
    Attribute::Uevent,
    Attribute::Dev,
    Attribute::DmName,
    Attribute::DmUuid,
    Attribute::Partition,
    Attribute::LoopBackingFile,
    Attribute::Holders,
    Attribute::Slaves,
];

/// The storage below the hidden volume's mount, lowercased like the text it
/// is matched against.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Storage {
    /// The device-mapper name of every layer, top first.
    pub(super) names: Vec<String>,
    /// The paths and identifiers of the layers: their links and device
    /// nodes, LUKS, filesystem and partition uuids, labels, image files.
    pub(super) markers: Vec<Pattern>,
    /// The kernel's name of every layer, top first (`dm-0`, `sdb2`): a udev
    /// rule matches a device by it (`KERNEL=="sdb2"`).
    pub(super) kernel_names: Vec<String>,
    /// The places that are there but could not be read, for another reason
    /// than that they are not there, each of which may give a name above:
    /// the device the volume is mounted from, an attribute or listing of a
    /// layer in sysfs that gives a name ([`NAMES`]), a layer's udev record,
    /// a `/dev/disk` directory or a link in it.
    pub(super) unread: Vec<String>,
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
    let top = match blockdev::device_of_mount_or_unread(fs, mount) {
        Ok(Some(top)) => top,
        Ok(None) => return storage,
        Err(place) => {
            storage.keep_unread(&place);
            return storage;
        }
    };
    let layers = blockdev::walk(
        fs,
        &top,
        LoopFollow::BlockDevices,
        blockdev::MAX_STACK_DEVICES,
    )
    .layers;
    for unread in layers.iter().flat_map(|layer| layer.unread_among(NAMES)) {
        storage.keep_unread(&unread.path);
    }
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
            storage.add_kernel_names(layer);
            storage.add_udev_names(fs, layer);
        }
    }
    storage
}

impl Storage {
    /// The entries of `dir`, sorted; none when it is not there or cannot be
    /// listed, which keeps it in [`Self::unread`].
    fn listing<F: Filesystem>(&mut self, fs: &F, dir: &Path) -> Vec<PathBuf> {
        match fs.list_directory(dir) {
            Ok(mut entries) => {
                entries.sort();
                entries
            }
            Err(error) => {
                if !error.nothing_there() {
                    self.keep_unread(dir);
                }
                Vec::new()
            }
        }
    }

    /// Keep `place`, which could not be read, once.
    fn keep_unread(&mut self, place: &Path) {
        let shown = place.display().to_string();
        if !self.unread.contains(&shown) {
            self.unread.push(shown);
        }
    }

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

    /// The names the kernel gives `layer`: its device node (`/dev/dm-0`),
    /// the `/dev/block/<major>:<minor>` link udev makes for every block
    /// device, and its kernel name alone (`dm-0`), as a udev rule writes it.
    fn add_kernel_names(&mut self, layer: &Layer) {
        let name = layer.name.trim().to_ascii_lowercase();
        if !name.is_empty() {
            self.path(&format!("/dev/{name}"));
            if !name.contains('/') && !self.kernel_names.contains(&name) {
                self.kernel_names.push(name);
            }
        }
        if let Some(dev) = &layer.dev {
            self.path(&format!("/dev/block/{}", dev.trim()));
        }
    }

    /// The names udev gives `layer`: every link it made below `/dev`, from
    /// its database and from the `/dev/disk/by-*` directories, and the
    /// identifiers its database records.
    fn add_udev_names<F: Filesystem>(&mut self, fs: &F, layer: &Layer) {
        if let Some(dev) = &layer.dev {
            let path = Path::new(UDEV_DATA).join(format!("b{dev}"));
            let record = match fs.read_file_content(&path) {
                Ok(record) => record,
                Err(error) if error.nothing_there() => String::new(),
                Err(_) => {
                    self.keep_unread(&path);
                    String::new()
                }
            };
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
        for dir in self.listing(fs, Path::new(DEV_DISK)) {
            let kind = match dir.file_name().and_then(|name| name.to_str()) {
                Some("by-uuid" | "by-partuuid") => Some(Identifier::Uuid),
                Some("by-label") => Some(Identifier::Label),
                Some("by-partlabel") => Some(Identifier::PartLabel),
                _ => None,
            };
            for link in self.listing(fs, &dir) {
                let target = match fs.canonicalize(&link) {
                    Ok(target) => lexical(target),
                    // A link that leads to nothing names no device.
                    Err(error) if error.nothing_there() => continue,
                    Err(_) => {
                        self.keep_unread(&link);
                        continue;
                    }
                };
                if target != node {
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
