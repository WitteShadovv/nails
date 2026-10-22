// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Step three of a rehearsal: search the raw decoy devices for the canary.

use crate::filesystem::MountEntry;
use crate::forensic::layout::{self, Signature};
use crate::forensic::{Hit, RawSource, TokenScan};
use crate::{NailsError, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

/// What a raw scan of the decrypted decoy cannot see. Printed with every
/// result, so a clean scan is never read as more than it is.
pub const NOT_VISIBLE: &[&str] = &[
    "flash cells an SSD has remapped or keeps in reserve (wear levelling, over-provisioning): no host read reaches them, only a chip-off read does",
    "blocks discarded with TRIM: they read back as zeros here even where the flash still holds them",
    "disks and partitions not mounted while the scan runs (a second disk, an unused swap partition) unless named with --device",
    "a canary stored compressed or copy-on-write (btrfs, bcachefs, zfs, f2fs): this raw plaintext scan cannot match it. An image or a --device is classified from its on-disk superblock, so a btrfs or f2fs one is reported not-checked; a whole-disk image, or a bcachefs or zfs one, whose format the superblock check does not identify, is read as plain storage",
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
    /// Why the device could not be scanned, if it could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Why a clean scan of this device is not a clean result: its filesystem
    /// compresses contents or is copy-on-write, so a leaked canary can hide from
    /// a raw plaintext scan. `None` when a clean scan of it is conclusive.
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
/// result (its filesystem compresses contents or is copy-on-write) when that is
/// the case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanTarget {
    /// The device or image to read.
    pub device: PathBuf,
    /// Why a clean scan of it is inconclusive, or `None` when it is conclusive.
    pub blind_spot: Option<String>,
}

impl ScanTarget {
    /// A target whose storage does not hide data from a raw scan (an image, or
    /// a device whose filesystem is not inspected).
    pub fn new(device: PathBuf) -> Self {
        Self {
            device,
            blind_spot: None,
        }
    }

    /// A target for `device`, classified from the filesystem the mount table
    /// shows on it: compressed or copy-on-write storage marks it a blind spot.
    pub fn classified(device: PathBuf, mounts: &[MountEntry]) -> Self {
        let canonical = device
            .canonicalize()
            .unwrap_or_else(|_| device.to_path_buf());
        let blind_spot = mounts
            .iter()
            .find(|entry| {
                entry.source == device
                    || entry.source.canonicalize().unwrap_or_default() == canonical
            })
            .and_then(|entry| super::scan_blind_spot(&entry.fstype, &entry.super_opts))
            .map(|blind| blind.reason().to_string());
        Self {
            device: canonical,
            blind_spot,
        }
    }
}

/// Add a target under `device`, deduplicated by canonical path, keeping the
/// first blind-spot reason seen for it.
fn push_target(targets: &mut Vec<ScanTarget>, device: &Path, blind_spot: Option<String>) {
    let canonical = device
        .canonicalize()
        .unwrap_or_else(|_| device.to_path_buf());
    if targets.iter().any(|target| target.device == canonical) {
        return;
    }
    targets.push(ScanTarget {
        device: canonical,
        blind_spot,
    });
}

/// The devices a scan reads by default: every block device mounted read-write
/// with a writable filesystem, plus active swap partitions, minus the hidden
/// volume and anything mounted under it. Duplicates (by canonical path) are
/// listed once. Each filesystem-backed device carries the blind spot its
/// storage gives a raw plaintext scan, so a scan of a compressed or
/// copy-on-write decoy reports "not checked" rather than clean.
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
    let mut targets: Vec<ScanTarget> = Vec::new();
    for entry in mounts {
        if !entry.source.starts_with("/dev/")
            || READ_ONLY_FORMATS.contains(&entry.fstype.as_str())
            || entry.mount_point.starts_with(hidden_root)
            || hidden_dev.as_deref() == Some(entry.dev.as_str())
        {
            continue;
        }
        let blind_spot = super::scan_blind_spot(&entry.fstype, &entry.super_opts)
            .map(|blind| blind.reason().to_string());
        push_target(&mut targets, &entry.source, blind_spot);
    }
    for line in swaps.lines().skip(1) {
        let mut fields = line.split_whitespace();
        if let (Some(device), Some("partition")) = (fields.next(), fields.next()) {
            push_target(&mut targets, Path::new(device), None);
        }
    }
    targets
}

/// Identify the filesystem on a device from its raw superblock and, for a
/// copy-on-write or compression-capable format (btrfs, f2fs), give the reason a
/// clean scan of it is not conclusive. This classifies an offline image or an
/// unmounted `--device`, which the mount table cannot. A verbatim format (ext4,
/// xfs, vfat), a format whose superblock this does not identify (a whole-disk
/// image, bcachefs, zfs), or a read error all return `None`: a raw plaintext
/// scan of verbatim or unidentified bytes is conclusive, and an unreadable
/// device is reported by the scan itself.
fn detect_blind_spot(source: &RawSource) -> Option<String> {
    match layout::signature_at(source, 0) {
        Ok(Signature::Format(fstype)) => {
            super::scan_blind_spot(fstype, "").map(|blind| blind.reason().to_string())
        }
        _ => None,
    }
}

/// Scan `targets` for `token`.
///
/// Before reading any device the matcher proves on a buffer that it finds the
/// token in both encodings, so a clean result cannot come from a broken
/// matcher. A device that cannot be opened or read is reported with its error;
/// the others are still scanned. A target's blind spot (compressed or
/// copy-on-write storage) travels onto its result, so a clean scan of such a
/// device reads as "not checked" rather than clean.
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
        let result = RawSource::open(device).and_then(|source| {
            // The mount table classifies a live device; an offline image or an
            // unmounted --device it cannot, so identify the filesystem from the
            // raw superblock here, lest a copy-on-write or compressing decoy
            // read this way be reported clean rather than "not checked".
            if blind_spot.is_none() {
                blind_spot = detect_blind_spot(&source);
            }
            let size = source.size();
            matcher.scan(&source).map(|outcome| (size, outcome))
        });
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
