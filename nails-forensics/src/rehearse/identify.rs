// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Identify the storage of a scan target that nothing names, from its raw
//! bytes.
//!
//! The mount table classifies a live decoy device. An offline image, or a
//! `--device` that is not mounted, has no entry there, so step three reads its
//! superblock and partition table instead. A clean scan of such a source is a
//! clean result only when every filesystem on it is one the scan reads
//! verbatim and the source holds all of it; anything else is a blind spot,
//! reported "not checked":
//!
//! - a filesystem that can compress file contents (btrfs, bcachefs, an f2fs
//!   whose superblock carries the compression feature), found by its own
//!   magic, so a stale signature of another format beside it cannot hide it;
//! - an encrypted container (LUKS, BitLocker), of which a raw scan reads only
//!   ciphertext: its unlocked mapping is what to scan;
//! - an LVM physical volume, whose logical volumes the scan does not identify;
//! - storage on which no filesystem is identified at all (zfs, an encrypted
//!   volume without a header, raw data), even where an ext4 or xfs magic
//!   shows over a block size no such filesystem uses;
//! - a filesystem, a partition, or the disk a GPT was written for, that runs
//!   past the end of the source, as on an image whose copy stopped early;
//! - first blocks that cannot be read.
//!
//! A source with a partition table (a whole disk) is classified partition by
//! partition, and a blind spot on any partition, named by its number, makes
//! the whole source one.

use crate::forensic::layout::{self, Partition, RecordedSize, Signature, TableKind};
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

/// Why a source that ends before the disk its GPT was written for is not
/// checked.
fn disk_cut_short(recorded: u64, available: u64) -> String {
    format!(
        "the partition table was written for a disk of {recorded} bytes, but the source holds \
         only {available} of them, so the rest was never read"
    )
}

/// Why a partition the source does not hold in full is not checked.
fn partition_cut_short(partition: &Partition, available: u64) -> String {
    let unread = if partition.start >= available {
        "none of it was read"
    } else {
        "the rest of it was never read"
    };
    format!(
        "it runs from byte {} to byte {}, but the source holds only {available} bytes, so \
         {unread}",
        partition.start,
        partition.end()
    )
}

/// What the region of `source` from `start` to `end` holds, for a raw
/// plaintext scan.
fn region(source: &RawSource, start: u64, end: u64) -> io::Result<Region> {
    // A filesystem that can compress wins over whatever else the region's
    // first blocks show: a stale signature of another format must never make
    // it read as verbatim, nor stand in for it when it is verbatim. An f2fs
    // compresses only when made with the compression feature, so its
    // superblock decides.
    if let Some(fstype) = layout::compressing_format_at(source, start)? {
        let blind = if fstype == "f2fs" {
            super::f2fs_image_blind_spot(layout::f2fs_compression(source, start)?)
        } else {
            super::scan_blind_spot(fstype, "")
        };
        return match blind {
            Some(blind) => Ok(Region::Hidden(blind.reason().to_string())),
            None => sized(source, start, end, fstype),
        };
    }
    Ok(match layout::signature_at(source, start)? {
        Signature::Luks(_) | Signature::Luks2Secondary(_) => Region::Hidden(encrypted("LUKS")),
        Signature::Format("bitlocker") => Region::Hidden(encrypted("BitLocker")),
        Signature::Format("lvm2-pv") => Region::Hidden(VOLUME_GROUP.to_string()),
        Signature::Format(fstype) => match super::scan_blind_spot(fstype, "") {
            Some(blind) => Region::Hidden(blind.reason().to_string()),
            None => sized(source, start, end, fstype)?,
        },
        Signature::Unknown => Region::Unidentified,
    })
}

/// A filesystem of `fstype` at `start` that a raw plaintext scan reads
/// verbatim: verbatim when the region to `end` holds all of it.
fn sized(source: &RawSource, start: u64, end: u64, fstype: &str) -> io::Result<Region> {
    Ok(match layout::recorded_size(source, start, fstype)? {
        RecordedSize::Bytes(recorded) if recorded > end - start => {
            Region::Hidden(truncated(fstype, recorded, end - start))
        }
        // An ext4, xfs or f2fs magic over a superblock with a block size no
        // such filesystem uses matched other bytes by chance, the ciphertext
        // of a volume without a header among them.
        RecordedSize::Implausible => Region::Unidentified,
        RecordedSize::Bytes(_) | RecordedSize::Unrecorded => Region::Verbatim,
    })
}

/// Why a clean scan of `partition` of `source` is not a clean result, or
/// `None` when the source holds all of it and it holds a filesystem a raw
/// plaintext scan reads verbatim.
fn partition_blind_spot(source: &RawSource, partition: &Partition) -> Option<String> {
    if partition.end() > source.size() {
        return Some(partition_cut_short(partition, source.size()));
    }
    match region(source, partition.start, partition.end()) {
        Ok(Region::Verbatim) => None,
        Ok(Region::Hidden(reason)) => Some(reason),
        Ok(Region::Unidentified) => Some(UNIDENTIFIED.to_string()),
        Err(err) => Some(unreadable(&err)),
    }
}

/// Why a clean scan of `source` is not a clean result, or `None` when every
/// filesystem on it is one a raw plaintext scan reads verbatim and the source
/// holds all of it.
///
/// A blind spot at offset 0 decides at once. Otherwise a source without a
/// partition table is conclusive only when offset 0 holds a filesystem read
/// verbatim. With a table, each partition is classified, whatever offset 0
/// shows, and a blind spot on any of them, named by its number, decides: a
/// partition the source does not hold in full is one. So is a source shorter
/// than the disk its GPT was written for. Only a GPT that breaks its own
/// rules in front of a filesystem read verbatim is set aside: it is what an
/// older table left when that filesystem was made on the whole disk, its
/// entries written over.
pub(super) fn blind_spot(source: &RawSource) -> Option<String> {
    let size = source.size();
    let whole = match region(source, 0, size) {
        Ok(Region::Hidden(reason)) => return Some(reason),
        Ok(whole) => whole,
        Err(err) => return Some(unreadable(&err)),
    };
    let table = match layout::recorded_table(source) {
        Ok(table) => table,
        Err(err) => return Some(unreadable(&err)),
    };
    let verbatim = matches!(whole, Region::Verbatim);
    if table.table == TableKind::None || (verbatim && !table.consistent) {
        return (!verbatim).then(|| UNIDENTIFIED.to_string());
    }
    let mut reasons: Vec<String> = table
        .disk_end
        .filter(|&recorded| recorded > size)
        .map(|recorded| disk_cut_short(recorded, size))
        .into_iter()
        .collect();
    if table.partitions.is_empty() {
        reasons.push(UNIDENTIFIED.to_string());
    }
    reasons.extend(table.partitions.iter().filter_map(|partition| {
        partition_blind_spot(source, partition)
            .map(|reason| format!("partition {}: {reason}", partition.number))
    }));
    (!reasons.is_empty()).then(|| reasons.join("; "))
}
