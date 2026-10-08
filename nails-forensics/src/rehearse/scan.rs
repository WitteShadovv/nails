// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Step three of a rehearsal: search the raw decoy devices for the canary.

use crate::filesystem::MountEntry;
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
}

/// The devices a scan reads by default: every block device mounted read-write
/// with a writable filesystem, plus active swap partitions, minus the hidden
/// volume and anything mounted under it. Duplicates (by canonical path) are
/// listed once.
pub fn default_scan_targets(
    mounts: &[MountEntry],
    swaps: &str,
    hidden_root: &Path,
) -> Vec<PathBuf> {
    let hidden_dev = mounts
        .iter()
        .rev()
        .find(|entry| entry.mount_point == hidden_root)
        .map(|entry| entry.dev.clone());
    let mut targets: Vec<PathBuf> = Vec::new();
    let mut push = |path: &Path| {
        let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if !targets.contains(&canonical) {
            targets.push(canonical);
        }
    };
    for entry in mounts {
        if !entry.source.starts_with("/dev/")
            || READ_ONLY_FORMATS.contains(&entry.fstype.as_str())
            || entry.mount_point.starts_with(hidden_root)
            || hidden_dev.as_deref() == Some(entry.dev.as_str())
        {
            continue;
        }
        push(&entry.source);
    }
    for line in swaps.lines().skip(1) {
        let mut fields = line.split_whitespace();
        if let (Some(device), Some("partition")) = (fields.next(), fields.next()) {
            push(Path::new(device));
        }
    }
    targets
}

/// Scan `devices` for `token`.
///
/// Before reading any device the matcher proves on a buffer that it finds the
/// token in both encodings, so a clean result cannot come from a broken
/// matcher. A device that cannot be opened or read is reported with its error;
/// the others are still scanned.
///
/// # Errors
///
/// Fails when the token is malformed or the matcher self-check fails.
pub fn scan(token: &str, devices: &[PathBuf], limit: Option<u64>) -> Result<ScanReport> {
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
    for device in devices {
        let result = RawSource::open(device).and_then(|source| {
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
            },
        });
    }
    Ok(report)
}
