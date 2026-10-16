// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Walking a device stack down through sysfs, one device at a time.

use super::{
    DeviceMapper, DmKind, Layer, LoopBacking, LoopDevice, LoopFollow, MAX_STACK_DEVICES, Partition,
    SYS_BLOCK, SYS_CLASS_BLOCK, SYS_DEV_BLOCK,
};
use crate::Filesystem;
use crate::filesystem::mountinfo::{MountEntry, top_mount_at};
use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};

/// Walk the stack down from the device whose sysfs directory is `top`: top
/// first, then breadth-first through `slaves/` and below loop devices as far
/// as `follow` allows. A device reached twice is read once, and at most
/// [`MAX_STACK_DEVICES`] devices are read.
pub fn stack<F: Filesystem>(fs: &F, top: &Path, follow: LoopFollow) -> Vec<Layer> {
    let mut layers = Vec::new();
    let mut seen = HashSet::new();
    let mut mounts = None;
    let mut pending = VecDeque::from([top.to_path_buf()]);
    while let Some(dir) = pending.pop_front() {
        if layers.len() >= MAX_STACK_DEVICES {
            break;
        }
        let dir = canonical(fs, &dir);
        if !seen.insert(dir.clone()) {
            continue;
        }
        let mut layer = read_layer(fs, &dir);
        let slaves = sorted_listing(fs, &dir.join("slaves"));
        layer.slaves = names(&slaves);
        pending.extend(slaves);
        if let Some(below) = below_loop(fs, &layer, follow, &mut mounts) {
            pending.push_back(below);
        }
        layers.push(layer);
    }
    layers
}

/// The sysfs directory of the block device a mount sits on, if any.
pub fn device_of_mount<F: Filesystem>(fs: &F, mount: &MountEntry) -> Option<PathBuf> {
    // ext4, xfs and f2fs report the real block device's number.
    if let Some(dir) = block_dir(fs, &Path::new(SYS_DEV_BLOCK).join(&mount.dev)) {
        return Some(dir);
    }

    // btrfs reports an anonymous `0:N` device, so fall back to the source.
    let source_name = mount.source.file_name()?.to_str()?;
    if mount.source.starts_with("/dev/mapper") {
        return find_dm_by_name(fs, source_name);
    }
    if mount.source.starts_with("/dev") {
        return block_dir(fs, &Path::new(SYS_CLASS_BLOCK).join(source_name));
    }
    None
}

/// What a device-mapper uuid says a mapping is; `name` decides only for a
/// device without a uuid.
///
/// cryptsetup names its mappings `CRYPT-<TYPE>-[<uuid>-]<name>`, e.g.
/// `CRYPT-LUKS2-<hex>-hidden` or `CRYPT-TCRYPT-hidden`, LVM `LVM-<uuids>`.
/// The VeraCrypt application creates its mappings with `dmsetup` and no uuid.
pub fn classify_dm(uuid: &str, name: &str) -> DmKind {
    let uuid = uuid.trim();
    if let Some(rest) = uuid.strip_prefix("CRYPT-") {
        return match rest.split('-').next().unwrap_or_default() {
            "" => DmKind::Other,
            "SUBDEV" => DmKind::CryptSubdev,
            "INTEGRITY" => DmKind::Integrity,
            "VERITY" => DmKind::Verity,
            kind => DmKind::Crypt(kind.to_string()),
        };
    }
    if uuid.starts_with("LVM-") {
        return DmKind::Lvm;
    }
    if uuid.is_empty() && is_veracrypt_name(name.trim()) {
        return DmKind::VeraCrypt;
    }
    DmKind::Other
}

/// `veracrypt<N>`, or `veracrypt<N>_<k>` for an inner cipher of a cascade.
fn is_veracrypt_name(name: &str) -> bool {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    name.strip_prefix("veracrypt")
        .is_some_and(|rest| match rest.split_once('_') {
            Some((slot, layer)) => digits(slot) && digits(layer),
            None => digits(rest),
        })
}

/// The sysfs directory of the block device a `/dev` path names: `/dev/sdb2`,
/// or a link to a device such as `/dev/mapper/data` or a `/dev/disk/by-*`
/// name. Only paths under `/dev` are resolved, so a file on another
/// filesystem is never looked up through its symlinks.
pub(super) fn dev_node_dir<F: Filesystem>(fs: &F, path: &Path) -> Option<PathBuf> {
    if !path.starts_with("/dev") {
        return None;
    }
    let canonical = fs.canonicalize(path).ok()?;
    let name = canonical.strip_prefix("/dev").ok()?;
    if name.components().count() != 1 {
        return None;
    }
    block_dir(fs, &Path::new(SYS_CLASS_BLOCK).join(name))
}

/// `dir` with its symlinks resolved, when it is a block device's sysfs
/// directory (every one carries a `dev` attribute).
pub(super) fn block_dir<F: Filesystem>(fs: &F, dir: &Path) -> Option<PathBuf> {
    let dir = canonical(fs, dir);
    fs.read_file_content(&dir.join("dev"))
        .is_ok()
        .then_some(dir)
}

/// `path` with its symlinks resolved, or as given when that fails.
fn canonical<F: Filesystem>(fs: &F, path: &Path) -> PathBuf {
    fs.canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// The entries of a directory, sorted; none when it cannot be listed.
pub(super) fn sorted_listing<F: Filesystem>(fs: &F, dir: &Path) -> Vec<PathBuf> {
    let mut entries = fs.list_directory(dir).unwrap_or_default();
    entries.sort();
    entries
}

/// The file names of `paths`.
pub(super) fn names(paths: &[PathBuf]) -> Vec<String> {
    paths.iter().filter_map(|path| file_name(path)).collect()
}

/// The last component of `path`.
fn file_name(path: &Path) -> Option<String> {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
}

/// Find the device-mapper device whose `dm/name` is `name`.
fn find_dm_by_name<F: Filesystem>(fs: &F, name: &str) -> Option<PathBuf> {
    sorted_listing(fs, Path::new(SYS_BLOCK))
        .into_iter()
        .map(|dir| canonical(fs, &dir))
        .find(|dir| {
            fs.read_file_content(&dir.join("dm/name"))
                .is_ok_and(|dm_name| dm_name.trim() == name)
        })
}

/// Read the attributes of one block device; every attribute is optional.
fn read_layer<F: Filesystem>(fs: &F, dir: &Path) -> Layer {
    let read = |attribute: &str| fs.read_file_content(&dir.join(attribute)).ok();

    let uevent = read("uevent").unwrap_or_default();
    let dm_name = read("dm/name").map(|name| name.trim().to_string());
    let dm_uuid = read("dm/uuid").map(|uuid| uuid.trim().to_string());
    let dm = (dm_name.is_some() || dm_uuid.is_some()).then(|| {
        let name = dm_name.unwrap_or_default();
        let uuid = dm_uuid.unwrap_or_default();
        DeviceMapper {
            kind: classify_dm(&uuid, &name),
            name,
            uuid,
        }
    });

    Layer {
        sysfs: dir.to_path_buf(),
        name: device_name(&uevent, dir),
        dev: read("dev")
            .map(|dev| dev.trim().to_string())
            .filter(|dev| !dev.is_empty()),
        dm,
        read_only: read("ro").is_some_and(|ro| ro.trim() == "1"),
        size_sectors: read("size").as_deref().and_then(parse_u64),
        discard_max_bytes: read("queue/discard_max_bytes")
            .as_deref()
            .and_then(parse_u64)
            .unwrap_or(0),
        slaves: Vec::new(),
        holders: names(&sorted_listing(fs, &dir.join("holders"))),
        partition: read_partition(fs, dir, &uevent),
        loop_device: read_loop(fs, dir),
    }
}

/// The kernel name, from `DEVNAME=` in `uevent` or else the directory name.
fn device_name(uevent: &str, dir: &Path) -> String {
    uevent_value(uevent, "DEVNAME")
        .or_else(|| file_name(dir))
        .unwrap_or_default()
}

/// A partition's number and start, its disk (the sysfs parent directory) and
/// its name and uuid from `uevent`; `None` for a device that is no partition.
fn read_partition<F: Filesystem>(fs: &F, dir: &Path, uevent: &str) -> Option<Partition> {
    let read = |path: &Path| fs.read_file_content(path).ok();
    let number = read(&dir.join("partition"))?.trim().parse().ok()?;
    let disk = dir
        .parent()
        .filter(|parent| read(&parent.join("dev")).is_some())
        .map(|parent| device_name(&read(&parent.join("uevent")).unwrap_or_default(), parent));
    Some(Partition {
        number,
        start: read(&dir.join("start")).as_deref().and_then(parse_u64),
        disk,
        name: uevent_value(uevent, "PARTNAME"),
        uuid: uevent_value(uevent, "PARTUUID"),
    })
}

/// The binding of a loop device; `None` for any other device and for an
/// unbound loop device, which has no `loop/` directory.
fn read_loop<F: Filesystem>(fs: &F, dir: &Path) -> Option<LoopDevice> {
    let read = |attribute: &str| fs.read_file_content(&dir.join(attribute)).ok();
    let path = read("loop/backing_file")
        .as_deref()
        .and_then(parse_backing_file)?;
    let backing = match dev_node_dir(fs, &path).as_deref().and_then(file_name) {
        Some(name) => LoopBacking::Block { path, name },
        None => LoopBacking::File(path),
    };
    Some(LoopDevice {
        backing,
        offset: read("loop/offset")
            .as_deref()
            .and_then(parse_u64)
            .unwrap_or(0),
        size_limit: read("loop/sizelimit")
            .as_deref()
            .and_then(parse_u64)
            .unwrap_or(0),
        autoclear: read("loop/autoclear").is_some_and(|value| value.trim() == "1"),
    })
}

/// The device below a loop device that `follow` lets the walk continue into.
fn below_loop<F: Filesystem>(
    fs: &F,
    layer: &Layer,
    follow: LoopFollow,
    mounts: &mut Option<Vec<MountEntry>>,
) -> Option<PathBuf> {
    match &layer.loop_device.as_ref()?.backing {
        LoopBacking::Block { name, .. } if follow >= LoopFollow::BlockDevices => {
            block_dir(fs, &Path::new(SYS_CLASS_BLOCK).join(name))
        }
        LoopBacking::File(path) if follow >= LoopFollow::BackingFiles => {
            let mounts = mounts.get_or_insert_with(|| fs.mount_table().unwrap_or_default());
            device_holding(fs, path, mounts)
        }
        _ => None,
    }
}

/// The device of the filesystem that holds `file`: the device number its
/// `stat` reports, or, for a filesystem with an anonymous number (btrfs), the
/// device of the mount it lies on.
fn device_holding<F: Filesystem>(fs: &F, file: &Path, mounts: &[MountEntry]) -> Option<PathBuf> {
    if let Ok(dev) = fs.device_id(file) {
        let number = format!("{}:{}", rustix::fs::major(dev), rustix::fs::minor(dev));
        if let Some(dir) = block_dir(fs, &Path::new(SYS_DEV_BLOCK).join(number)) {
            return Some(dir);
        }
    }
    let mount = file.ancestors().find_map(|dir| top_mount_at(mounts, dir))?;
    device_of_mount(fs, mount)
}

/// The value of `key=` in a sysfs `uevent`, when it is not empty.
pub(super) fn uevent_value(uevent: &str, key: &str) -> Option<String> {
    uevent
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// The file behind a loop device, from `loop/backing_file`: the path plus a
/// newline.
pub(super) fn parse_backing_file(content: &str) -> Option<PathBuf> {
    let path = content.trim_end_matches('\n');
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// A decimal sysfs attribute (`size`, `start`, `queue/discard_max_bytes`).
pub(super) fn parse_u64(content: &str) -> Option<u64> {
    content.trim().parse().ok()
}
