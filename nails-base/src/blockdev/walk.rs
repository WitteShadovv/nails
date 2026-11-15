// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Walking a device stack down through sysfs, one device at a time.

use super::dev_path::{OutOfDev, follow_in_dev};
use super::{
    Attribute, DeviceMapper, DmKind, Layer, LoopBacking, LoopDevice, LoopFollow, MAX_STACK_DEVICES,
    Partition, SYS_BLOCK, SYS_CLASS_BLOCK, SYS_DEV_BLOCK, Unread, Walk,
};
use crate::Filesystem;
use crate::filesystem::mountinfo::{MountEntry, top_mount_at};
use std::cell::RefCell;
use std::collections::{HashSet, VecDeque};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// Where a walk keeps what it could not read.
type Noted = RefCell<Vec<Unread>>;

/// Walk the stack down from the device whose sysfs directory is `top`: top
/// first, then breadth-first through `slaves/` and below loop devices as far
/// as `follow` allows. A device reached twice is read once, and at most
/// [`MAX_STACK_DEVICES`] devices are read.
pub fn stack<F: Filesystem>(fs: &F, top: &Path, follow: LoopFollow) -> Vec<Layer> {
    walk(fs, top, follow, MAX_STACK_DEVICES).layers
}

/// Walk the stack down from `top` as [`stack`] does, reading at most `limit`
/// devices, and say where the walk stopped short of the bottom: at the limit,
/// or at a loop device `follow` lets it continue below when no block device
/// sysfs shows holds what the loop device reads.
pub fn walk<F: Filesystem>(fs: &F, top: &Path, follow: LoopFollow, limit: usize) -> Walk {
    let mut walk = Walk::default();
    let mut seen = HashSet::new();
    let mut mounts = None;
    let mut pending = VecDeque::from([top.to_path_buf()]);
    while let Some(dir) = pending.pop_front() {
        let dir = canonical(fs, &dir);
        if seen.contains(&dir) {
            continue;
        }
        if walk.layers.len() >= limit {
            walk.cut_short = true;
            break;
        }
        seen.insert(dir.clone());
        let mut layer = read_layer(fs, &dir);
        let slaves = match fs.list_directory(&dir.join("slaves")) {
            Ok(mut slaves) => {
                slaves.sort();
                slaves
            }
            Err(error) => {
                layer.slaves_unread = !error.nothing_there();
                if layer.slaves_unread {
                    layer.unread.push(Unread {
                        attribute: Attribute::Slaves,
                        path: dir.join("slaves"),
                    });
                }
                Vec::new()
            }
        };
        layer.slaves = names(&slaves);
        layer.below = layer.slaves.clone();
        pending.extend(slaves);
        match below_loop(fs, &layer, follow, &mut mounts) {
            Below::Device(below) => {
                layer.below.extend(file_name(&below));
                pending.push_back(below);
            }
            Below::Unplaced => walk.unplaced_loops.push(layer.name.clone()),
            Below::Stop => {}
        }
        walk.layers.push(layer);
    }
    walk
}

/// The kernel name of the block device numbered `major:minor`, by its link
/// in `/sys/dev/block`.
pub fn device_numbered<F: Filesystem>(fs: &F, number: &str) -> Option<String> {
    block_dir(fs, &Path::new(SYS_DEV_BLOCK).join(number))
        .as_deref()
        .and_then(file_name)
}

/// The sysfs directory of the block device a mount sits on, if any.
pub fn device_of_mount<F: Filesystem>(fs: &F, mount: &MountEntry) -> Option<PathBuf> {
    device_of_mount_or_unread(fs, mount).ok().flatten()
}

/// [`device_of_mount`], telling a mount on no block device from one whose
/// device NAILS cannot find: `Err` names the first sysfs place that is there
/// but could not be read, for another reason than that it is not there,
/// where no device was found, since it may have shown the device.
pub fn device_of_mount_or_unread<F: Filesystem>(
    fs: &F,
    mount: &MountEntry,
) -> Result<Option<PathBuf>, PathBuf> {
    let unread = RefCell::new(Vec::new());
    match device_of_mount_noting(fs, mount, &unread) {
        Some(dir) => Ok(Some(dir)),
        None => unread
            .into_inner()
            .into_iter()
            .next()
            .map_or(Ok(None), |unread| Err(unread.path)),
    }
}

/// [`device_of_mount`], keeping in `unread` each place that could not be
/// read.
fn device_of_mount_noting<F: Filesystem>(
    fs: &F,
    mount: &MountEntry,
    unread: &Noted,
) -> Option<PathBuf> {
    // ext4, xfs and f2fs report the real block device's number.
    let by_number = Path::new(SYS_DEV_BLOCK).join(&mount.dev);
    if let Some(dir) = block_dir_noting(fs, &by_number, Attribute::Dev, unread) {
        return Some(dir);
    }

    // btrfs reports an anonymous `0:N` device, so fall back to the source.
    let source_name = mount.source.file_name()?.to_str()?;
    if mount.source.starts_with("/dev/mapper") {
        return find_dm_by_name(fs, source_name, unread);
    }
    if mount.source.starts_with("/dev") {
        let by_name = Path::new(SYS_CLASS_BLOCK).join(source_name);
        return block_dir_noting(fs, &by_name, Attribute::Dev, unread);
    }
    None
}

/// What a device-mapper uuid says a mapping is; `name` decides only for a
/// device without a uuid or with one the VeraCrypt application gave it.
///
/// cryptsetup names its mappings `CRYPT-<TYPE>-[<uuid>-]<name>`, e.g.
/// `CRYPT-LUKS2-<hex>-hidden` or `CRYPT-TCRYPT-hidden`, LVM `LVM-<uuids>`.
/// The VeraCrypt application creates its mappings with `dmsetup`: up to
/// 1.26.29 with no uuid, from 1.26.30 on with the uuid
/// `VERACRYPT-<serial>-<name>`, the serial being the number it gives the
/// mount.
pub fn classify_dm(uuid: &str, name: &str) -> DmKind {
    let uuid = uuid.trim();
    let name = name.trim();
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
    if is_veracrypt_name(name) && (uuid.is_empty() || is_veracrypt_uuid(uuid, name)) {
        return DmKind::VeraCrypt;
    }
    DmKind::Other
}

/// `veracrypt<N>`, or `veracrypt<N>_<k>` for an inner cipher of a cascade.
fn is_veracrypt_name(name: &str) -> bool {
    name.strip_prefix("veracrypt")
        .is_some_and(|rest| match rest.split_once('_') {
            Some((slot, layer)) => digits(slot) && digits(layer),
            None => digits(rest),
        })
}

/// `VERACRYPT-<serial>-<name>`, the uuid VeraCrypt 1.26.30 and later give
/// their mapping `name`, the serial a decimal number.
fn is_veracrypt_uuid(uuid: &str, name: &str) -> bool {
    uuid.strip_prefix("VERACRYPT-")
        .and_then(|rest| rest.strip_suffix(name))
        .and_then(|rest| rest.strip_suffix('-'))
        .is_some_and(digits)
}

/// Whether `s` is a decimal number, no sign and at least one digit.
fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// The sysfs directory of the block device a `/dev` path names: `/dev/sdb2`,
/// or a link to a device such as `/dev/mapper/data` or a `/dev/disk/by-*`
/// name. Only paths under `/dev` are resolved, and only through links that
/// lead to a path in `/dev` ([`follow_in_dev`]), so a file on another
/// filesystem is never looked up through its symlinks, and neither is a path
/// that a link in `/dev` leads to outside it.
pub(super) fn dev_node_dir<F: Filesystem>(fs: &F, path: &Path) -> Option<PathBuf> {
    dev_node_dir_noting(fs, path, Attribute::Dev, &RefCell::new(Vec::new()))
}

/// [`dev_node_dir`], keeping in `unread`, as `attribute`, the device node
/// whose way NAILS could not follow, where a part of it could not be looked
/// up or would mount an automount point ([`OutOfDev::Unreadable`],
/// [`OutOfDev::Automount`]), or the `dev` attribute on the way that is there
/// but could not be read for another reason than that it is not there. A
/// node that is not there, or a link that leads out of `/dev`, names no
/// device.
fn dev_node_dir_noting<F: Filesystem>(
    fs: &F,
    path: &Path,
    attribute: Attribute,
    unread: &Noted,
) -> Option<PathBuf> {
    let node = match follow_in_dev(fs, path) {
        Ok(node) => node,
        Err(OutOfDev::Unreadable(_) | OutOfDev::Automount(_)) => {
            unread.borrow_mut().push(Unread {
                attribute,
                path: path.to_path_buf(),
            });
            return None;
        }
        Err(OutOfDev::NotInDev | OutOfDev::Leaves(_) | OutOfDev::Missing) => return None,
    };
    let name = node.strip_prefix("/dev").ok()?;
    if name.components().count() != 1 {
        return None;
    }
    block_dir_noting(
        fs,
        &Path::new(SYS_CLASS_BLOCK).join(name),
        attribute,
        unread,
    )
}

/// `dir` with its symlinks resolved, when it is a block device's sysfs
/// directory (every one carries a `dev` attribute).
pub(super) fn block_dir<F: Filesystem>(fs: &F, dir: &Path) -> Option<PathBuf> {
    block_dir_noting(fs, dir, Attribute::Dev, &RefCell::new(Vec::new()))
}

/// [`block_dir`], keeping in `unread`, as `attribute`, a `dev` attribute
/// that could not be read for another reason than that it is not there.
fn block_dir_noting<F: Filesystem>(
    fs: &F,
    dir: &Path,
    attribute: Attribute,
    unread: &Noted,
) -> Option<PathBuf> {
    let dir = canonical(fs, dir);
    bytes(fs, &dir.join("dev"), attribute, unread).map(|_| dir)
}

/// The bytes of the sysfs attribute at `path`, which need not be text (a
/// loop device's file may have any name), or `None` when it is not there or
/// cannot be read; one that is there but cannot be read for another reason
/// than that it is not there is kept in `unread` as `attribute`.
fn bytes<F: Filesystem>(
    fs: &F,
    path: &Path,
    attribute: Attribute,
    unread: &Noted,
) -> Option<Vec<u8>> {
    match fs.read_file_bytes(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.nothing_there() => None,
        Err(_) => {
            unread.borrow_mut().push(Unread {
                attribute,
                path: path.to_path_buf(),
            });
            None
        }
    }
}

/// [`bytes`] as text, a byte that is no UTF-8 replaced: sysfs gives names
/// and numbers as text.
fn text<F: Filesystem>(
    fs: &F,
    path: &Path,
    attribute: Attribute,
    unread: &Noted,
) -> Option<String> {
    bytes(fs, path, attribute, unread).map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
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

/// Find the device-mapper device whose `dm/name` is `name`; a listing or a
/// name that could not be read is kept in `unread`.
fn find_dm_by_name<F: Filesystem>(fs: &F, name: &str, unread: &Noted) -> Option<PathBuf> {
    let mut entries = match fs.list_directory(Path::new(SYS_BLOCK)) {
        Ok(entries) => entries,
        Err(error) => {
            if !error.nothing_there() {
                unread.borrow_mut().push(Unread {
                    attribute: Attribute::DmName,
                    path: PathBuf::from(SYS_BLOCK),
                });
            }
            return None;
        }
    };
    entries.sort();
    entries
        .into_iter()
        .map(|dir| canonical(fs, &dir))
        .find(|dir| {
            text(fs, &dir.join("dm/name"), Attribute::DmName, unread)
                .is_some_and(|dm_name| dm_name.trim() == name)
        })
}

/// Read the attributes of one block device; every attribute is optional,
/// and one that is there but cannot be read is kept in [`Layer::unread`].
fn read_layer<F: Filesystem>(fs: &F, dir: &Path) -> Layer {
    let unread = RefCell::new(Vec::new());
    let read = |attribute: Attribute| text(fs, &dir.join(attribute.name()), attribute, &unread);

    let uevent = read(Attribute::Uevent).unwrap_or_default();
    let (holders, holders_unread) = match fs.list_directory(&dir.join("holders")) {
        Ok(mut holders) => {
            holders.sort();
            (names(&holders), false)
        }
        Err(error) => {
            let unlisted = !error.nothing_there();
            if unlisted {
                unread.borrow_mut().push(Unread {
                    attribute: Attribute::Holders,
                    path: dir.join("holders"),
                });
            }
            (Vec::new(), unlisted)
        }
    };
    let dm_name = read(Attribute::DmName).map(|name| name.trim().to_string());
    let dm_uuid = read(Attribute::DmUuid).map(|uuid| uuid.trim().to_string());
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
        dev: read(Attribute::Dev)
            .map(|dev| dev.trim().to_string())
            .filter(|dev| !dev.is_empty()),
        dm,
        read_only: read(Attribute::ReadOnly).is_some_and(|ro| ro.trim() == "1"),
        size_sectors: read(Attribute::Size).as_deref().and_then(parse_u64),
        discard_max_bytes: read(Attribute::DiscardMaxBytes)
            .as_deref()
            .and_then(parse_u64)
            .unwrap_or(0),
        slaves: Vec::new(),
        slaves_unread: false,
        below: Vec::new(),
        holders,
        holders_unread,
        partition: read_partition(fs, dir, &uevent, &unread),
        loop_device: read_loop(fs, dir, &unread),
        unread: unread.take(),
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
fn read_partition<F: Filesystem>(
    fs: &F,
    dir: &Path,
    uevent: &str,
    unread: &Noted,
) -> Option<Partition> {
    let read = |path: &Path, attribute| text(fs, path, attribute, unread);
    let number = read(&dir.join("partition"), Attribute::Partition)?
        .trim()
        .parse()
        .ok()?;
    let disk = dir
        .parent()
        .filter(|parent| read(&parent.join("dev"), Attribute::DiskDev).is_some())
        .map(|parent| {
            let uevent = read(&parent.join("uevent"), Attribute::DiskUevent);
            device_name(&uevent.unwrap_or_default(), parent)
        });
    Some(Partition {
        number,
        start: read(&dir.join("start"), Attribute::Start)
            .as_deref()
            .and_then(parse_u64),
        disk,
        name: uevent_value(uevent, "PARTNAME"),
        uuid: uevent_value(uevent, "PARTUUID"),
    })
}

/// The binding of a loop device; `None` for any other device and for an
/// unbound loop device, which has no `loop/` directory.
fn read_loop<F: Filesystem>(fs: &F, dir: &Path, unread: &Noted) -> Option<LoopDevice> {
    let read = |attribute: Attribute| text(fs, &dir.join(attribute.name()), attribute, unread);
    let backing_file = Attribute::LoopBackingFile;
    let path = bytes(fs, &dir.join(backing_file.name()), backing_file, unread)
        .as_deref()
        .and_then(parse_backing_file)?;
    // A device node it cannot resolve, or whose device's number it cannot
    // read, may be a block device: kept as unread with the file.
    let backing = match dev_node_dir_noting(fs, &path, backing_file, unread)
        .as_deref()
        .and_then(file_name)
    {
        Some(name) => LoopBacking::Block { path, name },
        None => LoopBacking::File(path),
    };
    Some(LoopDevice {
        backing,
        offset: read(Attribute::LoopOffset)
            .as_deref()
            .and_then(parse_u64)
            .unwrap_or(0),
        size_limit: read(Attribute::LoopSizeLimit)
            .as_deref()
            .and_then(parse_u64)
            .unwrap_or(0),
        autoclear: read(Attribute::LoopAutoclear).is_some_and(|value| value.trim() == "1"),
    })
}

/// Where a walk goes on below a device that may be a loop device.
enum Below {
    /// Into the device whose sysfs directory this is.
    Device(PathBuf),
    /// Nowhere: the device is no bound loop device, or `follow` stops at it.
    Stop,
    /// Nowhere it can name: `follow` lets the walk continue below the loop
    /// device, but no block device sysfs shows holds what it reads.
    Unplaced,
}

/// Where the walk goes on below `layer`, as far as `follow` lets it.
fn below_loop<F: Filesystem>(
    fs: &F,
    layer: &Layer,
    follow: LoopFollow,
    mounts: &mut Option<Vec<MountEntry>>,
) -> Below {
    let Some(bound) = &layer.loop_device else {
        return Below::Stop;
    };
    let below = match &bound.backing {
        LoopBacking::Block { name, .. } if follow >= LoopFollow::BlockDevices => {
            block_dir(fs, &Path::new(SYS_CLASS_BLOCK).join(name))
        }
        LoopBacking::File(path) if follow >= LoopFollow::BackingFiles => {
            let mounts = mounts.get_or_insert_with(|| fs.mount_table().unwrap_or_default());
            device_holding(fs, path, mounts)
        }
        _ => return Below::Stop,
    };
    below.map_or(Below::Unplaced, Below::Device)
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

/// The file behind a loop device, from `loop/backing_file`: the path, in
/// whatever bytes it has, plus a newline.
pub(super) fn parse_backing_file(content: &[u8]) -> Option<PathBuf> {
    let end = content
        .iter()
        .rposition(|&byte| byte != b'\n')
        .map_or(0, |last| last + 1);
    let path = &content[..end];
    (!path.is_empty()).then(|| PathBuf::from(OsStr::from_bytes(path)))
}

/// A decimal sysfs attribute (`size`, `start`, `queue/discard_max_bytes`).
pub(super) fn parse_u64(content: &str) -> Option<u64> {
    content.trim().parse().ok()
}
