// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Step three of a rehearsal: search the raw decoy devices for the canary.

use crate::filesystem::MountEntry;
use crate::forensic::{Hit, RawSource, TokenScan};
use crate::{Filesystem, NailsError, Result};
use nails_base::blockdev::{self, Layer, LoopFollow};
use serde::Serialize;
use std::io;
use std::path::{Path, PathBuf};

/// What a raw scan of the decrypted decoy cannot see. Printed with every
/// result, so a clean scan is never read as more than it is.
pub const NOT_VISIBLE: &[&str] = &[
    "flash cells an SSD has remapped or keeps in reserve (wear levelling, over-provisioning): no host read reaches them, only a chip-off read does",
    "blocks discarded with TRIM: they read back as zeros here even where the flash still holds them",
    "disks and partitions not mounted while the scan runs (a second disk, an unused swap partition) unless named with --device",
    "a canary stored compressed or copy-on-write (btrfs, bcachefs, zfs, an f2fs made with compression): this raw plaintext scan cannot match it, so such storage is reported not checked. A mounted device is judged by its mount, an image or an unmounted --device by its superblock (a whole disk partition by partition), and an encrypted container, or storage on which the scan identifies no filesystem, is reported not checked too",
    "a canary stored encrypted or compressed file by file (in an eCryptfs folder, an encrypted directory of an ext4 or f2fs, a compressed NTFS folder, or a vault a FUSE tool such as gocryptfs, CryFS or EncFS encrypts): this raw plaintext scan cannot match it either. A device that holds the folder of an eCryptfs mount (a whole disk too), an ext4 or f2fs with the encrypt feature, and an NTFS (or any fuseblk mount) are reported not checked, but three escape it: an eCryptfs folder not mounted during the scan, every eCryptfs folder in an --offline scan, which reads no mount table, and a FUSE tool's vault",
    "anything outside the decrypted mapping: the encryption header area and other partitions of the same disk",
    "firmware storage (EFI variables, pstore) and RAM",
];

/// Filesystem types that are read-only formats: nothing a session does can
/// write to them, so they are not scanned by default.
const READ_ONLY_FORMATS: &[&str] = &["erofs", "squashfs", "iso9660", "udf"];

/// The result for one device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceScan {
    /// The device or image scanned.
    pub device: PathBuf,
    /// Its size in bytes.
    pub size: u64,
    /// Bytes read.
    pub bytes_scanned: u64,
    /// Bytes skipped as holes of a sparse image.
    pub bytes_skipped: u64,
    /// Where the canary was found.
    pub hits: Vec<Hit>,
    /// Whether more hits exist than were recorded.
    pub hits_capped: bool,
    /// Whether the byte limit stopped the scan early.
    pub limit_reached: bool,
    /// Why the device could not be scanned, if it could not: it failed to
    /// open or read, it is empty, or it is a mount with no block device of
    /// its own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Why a clean scan of this device is not a clean result: its filesystem
    /// compresses contents or is copy-on-write, is NTFS, or encrypts files
    /// (the encrypt feature, an eCryptfs folder on it), it is an encrypted
    /// container or holds no filesystem the scan identifies, or it ends before
    /// its filesystem, a partition its table lists or the disk its GPT was
    /// written for does, so a leaked canary can hide from a raw plaintext
    /// scan. `None` when a clean scan of it is conclusive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blind_spot: Option<String>,
}

/// The result of a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanReport {
    /// One entry per device.
    pub devices: Vec<DeviceScan>,
    /// What the scan could not see.
    pub not_visible: Vec<&'static str>,
}

impl ScanReport {
    /// Hits over every device.
    pub fn total_hits(&self) -> usize {
        self.devices.iter().map(|device| device.hits.len()).sum()
    }

    /// Whether any device could not be scanned (or was cut short).
    pub fn incomplete(&self) -> bool {
        self.devices
            .iter()
            .any(|device| device.error.is_some() || device.limit_reached)
    }

    /// Whether any device's storage hides data from a raw plaintext scan, so a
    /// clean result over it cannot be trusted. A device with a hit still counts
    /// as found; this reports only that a clean scan was not conclusive.
    pub fn inconclusive(&self) -> bool {
        self.devices
            .iter()
            .any(|device| device.blind_spot.is_some())
    }
}

/// One device a scan reads, with why a clean scan of it would not be a clean
/// result (its filesystem compresses contents, is copy-on-write or NTFS, or
/// it holds the folder of an eCryptfs mount) when that is the case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanTarget {
    /// The device or image to read.
    pub device: PathBuf,
    /// Why a clean scan of it is inconclusive, or `None` when it is conclusive.
    pub blind_spot: Option<String>,
    /// Whether the scan identifies its storage from the raw superblock and
    /// partition table when it reads it: true for a target nothing names (an
    /// image, an unmounted device), false for one the mount table or the swap
    /// list already classifies.
    pub probe: bool,
    /// The filesystem type the mount table shows on it, for a target it
    /// names. No mount option shows whether an ext4 or f2fs has the encrypt
    /// feature, so the scan reads that from the superblock of such a target
    /// when it reads it.
    pub fstype: Option<String>,
    /// Why it is listed but never read: a mount with no block device of its
    /// own (a zfs dataset), which still carries its blind spot.
    pub unread: Option<String>,
}

impl ScanTarget {
    /// A target nothing names (an image, an unmounted device): the scan
    /// identifies its storage from the raw superblock and partition table.
    pub fn new(device: PathBuf) -> Self {
        Self {
            device,
            blind_spot: None,
            probe: true,
            fstype: None,
            unread: None,
        }
    }

    /// A target for `device`, classified from the filesystem the mount table
    /// shows on it: compressed, copy-on-write or NTFS storage, or an eCryptfs
    /// mount stacked on the filesystem, marks it a blind spot. A device the
    /// mount table does not show (an unmounted partition or disk) is
    /// identified from its raw superblock and partition table instead. Mounted
    /// or not, a device that holds the folder of an eCryptfs mount some other
    /// way (a whole disk with that filesystem in a partition, a device below
    /// it), which `fs` reads from sysfs, is a blind spot too, and so is one of
    /// which the scan cannot tell whether it does.
    pub fn classified<F: Filesystem>(fs: &F, device: PathBuf, mounts: &[MountEntry]) -> Self {
        let canonical = device
            .canonicalize()
            .unwrap_or_else(|_| device.to_path_buf());
        let entry = mounts.iter().find(|entry| {
            entry.source == device || entry.source.canonicalize().unwrap_or_default() == canonical
        });
        let (lowers, unplaced) = ecryptfs_lowers(mounts);
        Self {
            blind_spot: entry
                .and_then(|entry| mount_blind_spot(entry, &lowers))
                .or_else(|| ecryptfs_blind_spot(fs, &canonical, &lowers, &unplaced)),
            device: canonical,
            probe: entry.is_none(),
            fstype: entry.map(|entry| entry.fstype.clone()),
            unread: None,
        }
    }
}

/// The type of an eCryptfs mount.
const ECRYPTFS: &str = "ecryptfs";

/// The mount whose filesystem holds `path`: of the mounts on the longest
/// mount point `path` lies under, the last, an eCryptfs mount aside. `None`
/// when no mount point holds it (a relative path).
fn holding_mount<'a>(mounts: &'a [MountEntry], path: &Path) -> Option<&'a MountEntry> {
    mounts
        .iter()
        .filter(|entry| entry.fstype != ECRYPTFS && path.starts_with(&entry.mount_point))
        .max_by_key(|entry| entry.mount_point.components().count())
}

/// Where the eCryptfs mounts of `mounts` keep their encrypted files: the
/// mounts whose filesystems their folders lie on, and the eCryptfs mounts
/// whose folder lies on no mount the table shows.
fn ecryptfs_lowers(mounts: &[MountEntry]) -> (Vec<&MountEntry>, Vec<&MountEntry>) {
    let mut lowers = Vec::new();
    let mut unplaced = Vec::new();
    for entry in mounts.iter().filter(|entry| entry.fstype == ECRYPTFS) {
        match holding_mount(mounts, &entry.source) {
            Some(lower) => lowers.push(lower),
            None => unplaced.push(entry),
        }
    }
    (lowers, unplaced)
}

/// The blind spot a raw plaintext scan has on the filesystem of `entry`:
/// the one its type and options show, else an eCryptfs mount stacked on it
/// when it has the device number of one of `lowers`.
fn mount_blind_spot(entry: &MountEntry, lowers: &[&MountEntry]) -> Option<String> {
    super::scan_blind_spot(&entry.fstype, &entry.super_opts)
        .or_else(|| {
            lowers
                .iter()
                .any(|lower| lower.dev == entry.dev)
                .then_some(super::ScanBlindSpot::StackedEncryption)
        })
        .map(|blind| blind.reason().to_string())
}

/// Why a device named for a scan is not checked when the scan cannot tell
/// whether it holds the folder of an eCryptfs mount.
const ECRYPTFS_UNPLACED: &str = "an eCryptfs mount (an encrypted home or Private folder) stores \
     the files under it encrypted, and the scan cannot tell whether this device holds them: sysfs \
     shows no block device under their folder (it lies on a tmpfs, an overlay or a network share, \
     or on no mount the table shows) or none at this path, so this raw plaintext scan cannot \
     prove the canary absent";

/// Why a clean scan of `device` cannot rule out the eCryptfs mounts whose
/// folders lie on the filesystems of `lowers` or on no mount (`unplaced`): it
/// holds one of those folders, read from sysfs through `fs`, or the scan
/// cannot tell whether it does. `None` when there is no eCryptfs mount, or
/// each one's folder lies on other devices.
///
/// A device holds a folder when it is the block device of the filesystem the
/// folder lies on, or lies below that device: a whole disk with it in a
/// partition, the partition below a dm-crypt or LVM mapping, a member of an md
/// array, the file a loop device reads (named as a regular file) or the device
/// of the filesystem that holds that file. A folder on a filesystem with no
/// block device of its own (a tmpfs, an overlay, a network share) or on no
/// mount at all, and a path sysfs lists no block device for that is no
/// regular file (a node outside `/dev`, a system without sysfs), leave the
/// scan unable to tell.
fn ecryptfs_blind_spot<F: Filesystem>(
    fs: &F,
    device: &Path,
    lowers: &[&MountEntry],
    unplaced: &[&MountEntry],
) -> Option<String> {
    if lowers.is_empty() && unplaced.is_empty() {
        return None;
    }
    let named = named_block_device(fs, device);
    let regular_file = named.is_none() && fs.is_regular_file(device).unwrap_or(false);
    let mut unsure = !unplaced.is_empty() || (named.is_none() && !regular_file);
    for lower in lowers {
        let Some(layers) =
            blockdev::device_of_mount(fs, lower).and_then(|top| devices_holding(fs, &top))
        else {
            unsure = true;
            continue;
        };
        let holds = layers.iter().any(|layer| match &named {
            Some(dir) => layer.sysfs == *dir,
            None => layer
                .loop_device
                .as_ref()
                .is_some_and(|bound| bound.backing.path() == device),
        });
        if holds {
            return Some(super::ScanBlindSpot::StackedEncryption.reason().to_string());
        }
    }
    unsure.then(|| ECRYPTFS_UNPLACED.to_string())
}

/// The sysfs directory of the block device at `device`, a path under `/dev`;
/// `None` for any other path, and for one sysfs lists no block device for.
fn named_block_device<F: Filesystem>(fs: &F, device: &Path) -> Option<PathBuf> {
    if !device.starts_with("/dev") {
        return None;
    }
    blockdev::resolve_spec(fs, device.to_str()?)
}

/// The block devices whose raw bytes hold those of the device whose sysfs
/// directory is `top`: the devices below it ([`blockdev::stack`], through
/// `slaves/` and below a loop device to the device of the filesystem that
/// holds its file), and the disk each partition among them lies on, with the
/// devices below that disk in turn. `None` when they reach
/// [`blockdev::MAX_STACK_DEVICES`], more than any real stack has, as some may
/// then be missing.
fn devices_holding<F: Filesystem>(fs: &F, top: &Path) -> Option<Vec<Layer>> {
    let mut layers: Vec<Layer> = Vec::new();
    let mut pending = vec![top.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for layer in blockdev::stack(fs, &dir, LoopFollow::BackingFiles) {
            if layers.iter().any(|known| known.sysfs == layer.sysfs) {
                continue;
            }
            let disk = layer
                .partition
                .as_ref()
                .filter(|partition| partition.disk.is_some())
                .and(layer.sysfs.parent());
            pending.extend(disk.map(Path::to_path_buf));
            layers.push(layer);
        }
    }
    (layers.len() < blockdev::MAX_STACK_DEVICES).then_some(layers)
}

/// Add a target under `device`, deduplicated by canonical path, keeping the
/// first blind-spot reason seen for it. The mount table (which shows it as
/// `fstype`) or the swap list names its storage, so the scan does not identify
/// it again.
fn push_target(
    targets: &mut Vec<ScanTarget>,
    device: &Path,
    blind_spot: Option<String>,
    fstype: Option<&str>,
) {
    let canonical = device
        .canonicalize()
        .unwrap_or_else(|_| device.to_path_buf());
    if targets.iter().any(|target| target.device == canonical) {
        return;
    }
    targets.push(ScanTarget {
        device: canonical,
        blind_spot,
        probe: false,
        fstype: fstype.map(str::to_string),
        unread: None,
    });
}

/// The devices a scan reads by default: every block device mounted read-write
/// with a writable filesystem, plus active swap partitions, minus the hidden
/// volume and anything mounted under it. Duplicates (by canonical path) are
/// listed once. Each filesystem-backed device carries the blind spot its
/// storage gives a raw plaintext scan, so a scan of a compressed,
/// copy-on-write or NTFS decoy reports "not checked" rather than clean, and so
/// does one of a filesystem an eCryptfs mount keeps its encrypted files on. A
/// mount with no block device of its own (a zfs dataset, named by its pool)
/// cannot be read raw: one whose filesystem is such a blind spot is listed
/// unread with it, so a zfs decoy reports "not checked" too, and so is an
/// eCryptfs mount whose folder lies on no mount the table shows.
pub fn default_scan_targets(
    mounts: &[MountEntry],
    swaps: &str,
    hidden_root: &Path,
) -> Vec<ScanTarget> {
    let hidden_dev = mounts
        .iter()
        .rev()
        .find(|entry| entry.mount_point == hidden_root)
        .map(|entry| entry.dev.clone());
    let (lowers, unplaced) = ecryptfs_lowers(mounts);
    let mut targets: Vec<ScanTarget> = Vec::new();
    for entry in mounts {
        if READ_ONLY_FORMATS.contains(&entry.fstype.as_str())
            || entry.mount_point.starts_with(hidden_root)
            || hidden_dev.as_deref() == Some(entry.dev.as_str())
        {
            continue;
        }
        let blind_spot = mount_blind_spot(entry, &lowers);
        if entry.source.starts_with("/dev/") {
            push_target(&mut targets, &entry.source, blind_spot, Some(&entry.fstype));
        } else if let Some(blind_spot) = blind_spot
            && !targets.iter().any(|target| target.device == entry.source)
        {
            targets.push(ScanTarget {
                device: entry.source.clone(),
                blind_spot: Some(blind_spot),
                probe: false,
                fstype: Some(entry.fstype.clone()),
                unread: Some(format!(
                    "a {} mount, which has no block device of its own for a raw scan to read",
                    entry.fstype
                )),
            });
        }
    }
    for entry in unplaced {
        if !targets.iter().any(|target| target.device == entry.source) {
            targets.push(ScanTarget {
                device: entry.source.clone(),
                blind_spot: Some(super::ScanBlindSpot::StackedEncryption.reason().to_string()),
                probe: false,
                fstype: Some(entry.fstype.clone()),
                unread: Some(
                    "an ecryptfs mount whose folder lies on no mount the table shows, so no \
                     device the scan reads is known to hold it"
                        .to_string(),
                ),
            });
        }
    }
    for line in swaps.lines().skip(1) {
        let mut fields = line.split_whitespace();
        if let (Some(device), Some("partition")) = (fields.next(), fields.next()) {
            push_target(&mut targets, Path::new(device), None, None);
        }
    }
    targets
}

/// Why `source` is not scanned at all: it holds no byte to read (an image
/// whose copy failed, a loop device with no file behind it).
fn empty(source: &RawSource) -> Option<io::Error> {
    (source.size() == 0).then(|| {
        io::Error::other(
            "it is empty: 0 bytes to read (an image whose copy failed, or a loop device with no \
             file behind it)",
        )
    })
}

/// Scan `targets` for `token`.
///
/// Before reading any device the matcher proves on a buffer that it finds the
/// token in both encodings, so a clean result cannot come from a broken
/// matcher. A device that cannot be opened or read, or holds no byte at all, is
/// reported with its error; the others are still scanned. A target's blind
/// spot (compressed, copy-on-write or NTFS storage, an eCryptfs folder on it)
/// travels onto its result, so a clean scan of such a device reads as "not
/// checked" rather than clean. A target nothing names is identified from its
/// raw superblock and partition table first, so an encrypted container,
/// storage the scan does not identify, or a whole disk with such a partition
/// reads that way too, and the superblock of a target the mount table shows as
/// an ext4 or f2fs is read for the encrypt feature.
///
/// # Errors
///
/// Fails when the token is malformed or the matcher self-check fails.
pub fn scan(token: &str, targets: &[ScanTarget], limit: Option<u64>) -> Result<ScanReport> {
    if !super::valid_token(token) {
        return Err(NailsError::InvalidState(
            "the canary token is malformed".to_string(),
        ));
    }
    let matcher = TokenScan::new(token).limit(limit);
    let mut probe = b"\x00padding ".to_vec();
    probe.extend(token.as_bytes());
    probe.extend(b" \x00");
    probe.extend(crate::forensic::scan::utf16le(token));
    if matcher.scan_bytes(&probe).len() != 2 {
        return Err(NailsError::InvalidState(
            "the canary matcher failed its self-check; no scan was run".to_string(),
        ));
    }

    let mut report = ScanReport {
        devices: Vec::new(),
        not_visible: NOT_VISIBLE.to_vec(),
    };
    for target in targets {
        let device = &target.device;
        let mut blind_spot = target.blind_spot.clone();
        let result = match &target.unread {
            Some(why) => Err(io::Error::other(why.clone())),
            None => RawSource::open(device).and_then(|source| {
                if let Some(err) = empty(&source) {
                    return Err(err);
                }
                // The mount table classifies a live device; an offline image or
                // an unmounted --device it cannot, so identify its storage from
                // the raw superblock and partition table here, lest a
                // compressing, encrypted or unidentified decoy read this way be
                // reported clean rather than "not checked". Nor does any mount
                // option show the encrypt feature of a mounted ext4 or f2fs:
                // its superblock does.
                if blind_spot.is_none() {
                    blind_spot = if target.probe {
                        super::identify::blind_spot(&source)
                    } else {
                        target
                            .fstype
                            .as_deref()
                            .and_then(|fstype| super::identify::mounted_blind_spot(&source, fstype))
                    };
                }
                let size = source.size();
                matcher.scan(&source).map(|outcome| (size, outcome))
            }),
        };
        report.devices.push(match result {
            Ok((size, outcome)) => DeviceScan {
                device: device.clone(),
                size,
                bytes_scanned: outcome.bytes_scanned,
                bytes_skipped: outcome.bytes_skipped,
                hits: outcome.hits,
                hits_capped: outcome.hits_capped,
                limit_reached: outcome.limit_reached,
                error: None,
                blind_spot,
            },
            Err(err) => DeviceScan {
                device: device.clone(),
                size: 0,
                bytes_scanned: 0,
                bytes_skipped: 0,
                hits: Vec::new(),
                hits_capped: false,
                limit_reached: false,
                error: Some(err.to_string()),
                blind_spot,
            },
        });
    }
    Ok(report)
}
