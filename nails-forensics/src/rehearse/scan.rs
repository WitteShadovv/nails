// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Step three of a rehearsal: search the raw decoy devices for the canary.

use crate::filesystem::MountEntry;
use crate::forensic::{Hit, RawSource, TokenScan};
use crate::{NailsError, Result};
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
    "a canary stored encrypted or compressed file by file (in an eCryptfs folder, an encrypted directory of an ext4 or f2fs, a compressed NTFS folder, or a vault a FUSE tool such as gocryptfs, CryFS or EncFS encrypts): this raw plaintext scan cannot match it either. A device with an eCryptfs mount on it, an ext4 or f2fs with the encrypt feature, and an NTFS (or any fuseblk mount) are reported not checked, but an eCryptfs folder not mounted during the scan, and a FUSE tool's vault, are not seen",
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
    /// (the encrypt feature, an eCryptfs mount on it), it is an encrypted
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
/// has an eCryptfs mount on it) when that is the case.
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
    /// identified from its raw superblock and partition table instead.
    pub fn classified(device: PathBuf, mounts: &[MountEntry]) -> Self {
        let canonical = device
            .canonicalize()
            .unwrap_or_else(|_| device.to_path_buf());
        let entry = mounts.iter().find(|entry| {
            entry.source == device || entry.source.canonicalize().unwrap_or_default() == canonical
        });
        let stacked = ecryptfs_lowers(mounts).0;
        Self {
            device: canonical,
            blind_spot: entry.and_then(|entry| mount_blind_spot(entry, &stacked)),
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
/// device numbers (`major:minor`) of the filesystems their folders lie on, and
/// the eCryptfs mounts whose folder lies on no mount the table shows.
fn ecryptfs_lowers(mounts: &[MountEntry]) -> (Vec<&str>, Vec<&MountEntry>) {
    let mut lowers = Vec::new();
    let mut unplaced = Vec::new();
    for entry in mounts.iter().filter(|entry| entry.fstype == ECRYPTFS) {
        match holding_mount(mounts, &entry.source) {
            Some(lower) => lowers.push(lower.dev.as_str()),
            None => unplaced.push(entry),
        }
    }
    (lowers, unplaced)
}

/// The blind spot a raw plaintext scan has on the filesystem of `entry`:
/// the one its type and options show, else an eCryptfs mount stacked on it
/// when its device number is among `stacked`.
fn mount_blind_spot(entry: &MountEntry, stacked: &[&str]) -> Option<String> {
    super::scan_blind_spot(&entry.fstype, &entry.super_opts)
        .or_else(|| {
            stacked
                .contains(&entry.dev.as_str())
                .then_some(super::ScanBlindSpot::StackedEncryption)
        })
        .map(|blind| blind.reason().to_string())
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
    let (stacked, unplaced) = ecryptfs_lowers(mounts);
    let mut targets: Vec<ScanTarget> = Vec::new();
    for entry in mounts {
        if READ_ONLY_FORMATS.contains(&entry.fstype.as_str())
            || entry.mount_point.starts_with(hidden_root)
            || hidden_dev.as_deref() == Some(entry.dev.as_str())
        {
            continue;
        }
        let blind_spot = mount_blind_spot(entry, &stacked);
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
/// spot (compressed, copy-on-write or NTFS storage, an eCryptfs mount on it)
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
