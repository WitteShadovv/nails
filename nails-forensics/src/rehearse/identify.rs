// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Identify the storage of a scan target that nothing names, from its raw
//! bytes.
//!
//! The mount table classifies a live decoy device. An offline image, or a
//! `--device` that is not mounted, has no entry there, so step three reads its
//! superblock and partition table instead. A clean scan of such a source is a
//! clean result only when every filesystem on it is one the scan reads
//! verbatim; anything else is a blind spot, reported "not checked":
//!
//! - a filesystem that can compress file contents (btrfs, f2fs, bcachefs),
//!   found by its own magic, so a stale signature of another format beside it
//!   cannot hide it;
//! - an encrypted container (LUKS, BitLocker), of which a raw scan reads only
//!   ciphertext: its unlocked mapping is what to scan;
//! - an LVM physical volume, whose logical volumes the scan does not identify;
//! - storage on which no filesystem is identified at all (zfs, an encrypted
//!   volume without a header, raw data);
//! - a filesystem that spans more bytes than the source holds, as an image
//!   whose copy stopped early does;
//! - first blocks that cannot be read.
//!
//! A source with a partition table (a whole disk) is classified partition by
//! partition, and a blind spot on any partition, named by its number, makes
//! the whole source one.

use crate::forensic::layout::{self, Signature, TableKind};
use crate::forensic::raw::RawSource;
use std::io;

/// What a raw plaintext scan can make of one region of a source.
enum Region {
    /// A filesystem or format the scan reads verbatim (ext4, xfs, vfat, swap).
    Verbatim,
    /// Storage that can hide the canary from the scan, and why.
    Hidden(String),
    /// Nothing the scan identifies.
    Unidentified,
}

/// Why the scan cannot vouch for storage on which it identifies no
/// filesystem.
const UNIDENTIFIED: &str = "the scan identifies no filesystem here, so it cannot tell whether \
     the storage keeps file contents verbatim (zfs compresses them, an encrypted volume shows \
     only ciphertext): scan the decoy's unlocked filesystem itself";

/// Why an LVM physical volume is not checked.
const VOLUME_GROUP: &str = "this is an LVM physical volume, whose logical volumes the scan does \
     not identify: activate the volume group and scan each logical volume \
     (/dev/mapper/<vg>-<lv>) instead";

/// Why an encrypted container of `kind` is not checked.
fn encrypted(kind: &str) -> String {
    format!(
        "this is an encrypted container ({kind}), of which a raw scan reads only ciphertext, \
         where no canary can show: unlock it and scan the unlocked mapping \
         (/dev/mapper/<name>) instead"
    )
}

/// Why a source whose first blocks fail to read is not checked.
fn unreadable(err: &io::Error) -> String {
    format!("its first blocks could not be read ({err}), so its storage was not identified")
}

/// Why the scan of a cut-short filesystem is not checked.
fn truncated(fstype: &str, recorded: u64, available: u64) -> String {
    format!(
        "the {fstype} filesystem here spans {recorded} bytes, but the source holds only \
         {available} of them, so the rest was never read"
    )
}

/// What the region of `source` from `start` to `end` holds, for a raw
/// plaintext scan.
fn region(source: &RawSource, start: u64, end: u64) -> io::Result<Region> {
    // A filesystem that can compress wins over whatever else the region's
    // first blocks show: a stale signature of another format must never make
    // it read as verbatim.
    if let Some(blind) = layout::compressing_format_at(source, start)?
        .and_then(|fstype| super::scan_blind_spot(fstype, ""))
    {
        return Ok(Region::Hidden(blind.reason().to_string()));
    }
    Ok(match layout::signature_at(source, start)? {
        Signature::Luks(_) | Signature::Luks2Secondary(_) => Region::Hidden(encrypted("LUKS")),
        Signature::Format("bitlocker") => Region::Hidden(encrypted("BitLocker")),
        Signature::Format("lvm2-pv") => Region::Hidden(VOLUME_GROUP.to_string()),
        Signature::Format(fstype) => match super::scan_blind_spot(fstype, "") {
            Some(blind) => Region::Hidden(blind.reason().to_string()),
            None => match layout::recorded_size(source, start, fstype)? {
                Some(recorded) if recorded > end - start => {
                    Region::Hidden(truncated(fstype, recorded, end - start))
                }
                _ => Region::Verbatim,
            },
        },
        Signature::Unknown => Region::Unidentified,
    })
}

/// Why a clean scan of `source` is not a clean result, or `None` when every
/// filesystem on it is one a raw plaintext scan reads verbatim.
///
/// A blind spot at offset 0 decides at once. Otherwise a source without a
/// partition table is conclusive only when offset 0 holds a filesystem read
/// verbatim; with a table, each partition is classified, whatever offset 0
/// shows, and a blind spot on any of them, named by its number, decides.
pub(super) fn blind_spot(source: &RawSource) -> Option<String> {
    let whole = match region(source, 0, source.size()) {
        Ok(Region::Hidden(reason)) => return Some(reason),
        Ok(whole) => whole,
        Err(err) => return Some(unreadable(&err)),
    };
    let table = match layout::read_table(source) {
        Ok(table) => table,
        Err(err) => return Some(unreadable(&err)),
    };
    if table.table == TableKind::None {
        return match whole {
            Region::Verbatim => None,
            _ => Some(UNIDENTIFIED.to_string()),
        };
    }
    if table.partitions.is_empty() {
        return Some(UNIDENTIFIED.to_string());
    }
    let reasons: Vec<String> = table
        .partitions
        .iter()
        .filter_map(|partition| {
            let reason = match region(source, partition.start, partition.end()) {
                Ok(Region::Verbatim) => return None,
                Ok(Region::Hidden(reason)) => reason,
                Ok(Region::Unidentified) => UNIDENTIFIED.to_string(),
                Err(err) => unreadable(&err),
            };
            Some(format!("partition {}: {reason}", partition.number))
        })
        .collect();
    (!reasons.is_empty()).then(|| reasons.join("; "))
}
