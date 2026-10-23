// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Disk layout as an examiner sees it: the partition table, the space it does
//! not cover, and what each region starts with.
//!
//! Parses an MBR or a GPT read-only from a [`RawSource`], lists the gaps
//! between and after partitions, and identifies the common on-disk signatures
//! (LUKS, the usual filesystems, LVM, swap, BitLocker). Nothing here mounts or
//! writes; every read is a bounded positioned read.

use super::raw::RawSource;
use serde::Serialize;
use std::io;

/// Logical sector size assumed for MBR addressing and GPT on 512e disks.
pub const SECTOR: u64 = 512;

/// One partition from the table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Partition {
    /// 1-based position in the table.
    pub number: u32,
    /// First byte.
    pub start: u64,
    /// Length in bytes.
    pub size: u64,
    /// The type, as an MBR type byte (`0x83`) or a GPT type GUID.
    pub type_id: String,
}

impl Partition {
    /// One past the last byte.
    pub fn end(&self) -> u64 {
        self.start + self.size
    }
}

/// Which partition table, if any, the source carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TableKind {
    /// No recognisable table: the source is one filesystem or raw data.
    None,
    /// A DOS/MBR table (primary partitions only).
    Mbr,
    /// A GUID partition table.
    Gpt,
}

/// The parsed layout of a source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Layout {
    /// The table found.
    pub table: TableKind,
    /// Partitions in start order.
    pub partitions: Vec<Partition>,
    /// Ranges no partition covers, after the table's own metadata, in order.
    pub gaps: Vec<(u64, u64)>,
}

/// What a region starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Signature {
    /// A LUKS header (version 1 or 2).
    Luks(u16),
    /// A LUKS2 secondary header at the given offset into the region.
    Luks2Secondary(u64),
    /// A filesystem or volume format, by name.
    Format(&'static str),
    /// Nothing recognised.
    Unknown,
}

/// LUKS primary-header magic.
const LUKS_MAGIC: &[u8] = b"LUKS\xba\xbe";
/// LUKS2 secondary-header magic.
const LUKS2_SECONDARY_MAGIC: &[u8] = b"SKUL\xba\xbe";
/// Offsets a LUKS2 secondary header can sit at (the binary area sizes).
const LUKS2_SECONDARY_OFFSETS: &[u64] = &[
    0x4000, 0x8000, 0x1_0000, 0x2_0000, 0x4_0000, 0x8_0000, 0x10_0000, 0x20_0000, 0x40_0000,
];
/// How much of a region is read to identify it (covers btrfs at 64 KiB + 64).
const PROBE_LEN: usize = 0x1_1000;

/// A format identified by a fixed magic: `(offset, magic, name)`.
type Magic = (usize, &'static [u8], &'static str);

/// The btrfs superblock magic, 64 KiB + 64 bytes in.
const BTRFS: Magic = (0x1_0040, b"_BHRfS_M", "btrfs");
/// The f2fs superblock magic, 1 KiB in.
const F2FS: Magic = (0x400, &[0x10, 0x20, 0xF5, 0xF2], "f2fs");
/// The bcachefs superblock magic (a UUID), 0x18 bytes into the superblock at
/// 4 KiB.
const BCACHEFS: Magic = (
    0x1018,
    &[
        0xC6, 0x85, 0x73, 0xF6, 0x66, 0xCE, 0x90, 0xA9, 0xD9, 0x6A, 0x60, 0xCF, 0x80, 0x3D, 0xF7,
        0xEF,
    ],
    "bcachefs",
);

/// The formats identified by a fixed magic, in the order [`signature_at`]
/// tries them.
const FORMATS: &[Magic] = &[
    (0, b"XFSB", "xfs"),
    (0, b"hsqs", "squashfs"),
    (3, b"NTFS    ", "ntfs"),
    (3, b"EXFAT   ", "exfat"),
    (3, b"-FVE-FS-", "bitlocker"),
    (0x52, b"FAT32   ", "vfat"),
    (0x36, b"FAT16   ", "vfat"),
    (0x36, b"FAT12   ", "vfat"),
    (0x218, b"LVM2 001", "lvm2-pv"),
    (0xff6, b"SWAPSPACE2", "swap"),
    (0xff6, b"SWAP-SPACE", "swap"),
    (0x8001, b"CD001", "iso9660"),
    BTRFS,
    (0x438, &[0x53, 0xEF], "ext2/3/4"),
    (0x400, &[0xE2, 0xE1, 0xF5, 0xE0], "erofs"),
    F2FS,
];

/// The filesystems that can store file contents compressed, so a raw read
/// does not see them verbatim. [`compressing_format_at`] looks for these on
/// their own, outside the first-match order of [`FORMATS`].
const COMPRESSING_FORMATS: &[Magic] = &[BTRFS, F2FS, BCACHEFS];

/// The first format in `formats` whose magic `head` carries.
fn first_match(head: &[u8], formats: &[Magic]) -> Option<&'static str> {
    formats
        .iter()
        .find(|(offset, magic, _)| head.get(*offset..offset + magic.len()) == Some(*magic))
        .map(|(_, _, name)| *name)
}

/// Identify what the region starting at `start` holds.
///
/// # Errors
///
/// Propagates a read error.
pub fn signature_at(source: &RawSource, start: u64) -> io::Result<Signature> {
    let mut head = vec![0u8; PROBE_LEN];
    let read = source.read_at(&mut head, start)?;
    head.truncate(read);
    if head.starts_with(LUKS_MAGIC) && head.len() >= 8 {
        return Ok(Signature::Luks(u16::from_be_bytes([head[6], head[7]])));
    }
    if let Some(name) = first_match(&head, FORMATS) {
        return Ok(Signature::Format(name));
    }
    let mut magic = [0u8; 6];
    for offset in LUKS2_SECONDARY_OFFSETS {
        if source.read_at(&mut magic, start + offset)? == magic.len()
            && magic == LUKS2_SECONDARY_MAGIC
        {
            return Ok(Signature::Luks2Secondary(*offset));
        }
    }
    Ok(Signature::Unknown)
}

/// The filesystem that can store file contents compressed (btrfs, f2fs,
/// bcachefs) whose magic the region starting at `start` carries, if any.
///
/// Unlike [`signature_at`], which takes the first format that matches, this
/// finds such a filesystem whatever other signature sits beside it. mkfs.f2fs,
/// for one, rewrites only its first blocks and leaves the rest of the first
/// 2 MiB to discard, so on a device without discard an older ISO9660 volume
/// descriptor at 32 KiB survives it, and that descriptor comes first in
/// [`FORMATS`].
///
/// # Errors
///
/// Propagates a read error.
pub fn compressing_format_at(source: &RawSource, start: u64) -> io::Result<Option<&'static str>> {
    let mut head = vec![0u8; PROBE_LEN];
    let read = source.read_at(&mut head, start)?;
    head.truncate(read);
    Ok(first_match(&head, COMPRESSING_FORMATS))
}

/// How many bytes the filesystem of `format` at `start` says it spans: an
/// ext2/3/4 superblock's block count times its block size, an xfs
/// superblock's data blocks times its block size. `None` for any other
/// format, and for a block size neither filesystem uses.
///
/// # Errors
///
/// Propagates a read error.
pub fn recorded_size(source: &RawSource, start: u64, format: &str) -> io::Result<Option<u64>> {
    match format {
        "ext2/3/4" => {
            // The superblock at 1 KiB, through s_blocks_count_hi; past the
            // end of the source its fields read as zero.
            let mut sb = [0u8; 0x154];
            source.read_at(&mut sb, start.saturating_add(0x400))?;
            let log_block = le_u32(&sb, 0x18);
            let mut blocks = le_u32(&sb, 0x04);
            // The 64bit feature adds the high half of the block count.
            if le_u32(&sb, 0x60) & 0x80 != 0 {
                blocks += le_u32(&sb, 0x150) << 32;
            }
            // ext2/3/4 blocks are 1 KiB to 64 KiB.
            Ok((log_block <= 6).then(|| blocks.saturating_mul(1024 << log_block)))
        }
        "xfs" => {
            let mut sb = [0u8; 16];
            source.read_at(&mut sb, start)?;
            let block = u64::from(u32::from_be_bytes([sb[4], sb[5], sb[6], sb[7]]));
            let blocks = u64::from_be_bytes(sb[8..16].try_into().unwrap_or_default());
            // xfs blocks are a power of two from 512 bytes to 64 KiB.
            Ok(
                (block.is_power_of_two() && (512..=1 << 16).contains(&block))
                    .then(|| blocks.saturating_mul(block)),
            )
        }
        _ => Ok(None),
    }
}

fn le_u32(bytes: &[u8], at: usize) -> u64 {
    u64::from(u32::from_le_bytes(
        bytes[at..at + 4].try_into().unwrap_or_default(),
    ))
}

fn le_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or_default())
}

/// Format a GPT GUID (mixed-endian on disk) in its usual text form.
fn guid(bytes: &[u8]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[3],
        bytes[2],
        bytes[1],
        bytes[0],
        bytes[5],
        bytes[4],
        bytes[7],
        bytes[6],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

/// Parse the GPT whose header is at `header_at`, if there is one.
fn parse_gpt(source: &RawSource, header_at: u64, block: u64) -> io::Result<Option<Layout>> {
    let mut header = [0u8; 92];
    if source.read_at(&mut header, header_at)? < header.len() || &header[..8] != b"EFI PART" {
        return Ok(None);
    }
    // A block number is whatever the disk says. One whose byte offset does
    // not fit 64 bits lies past the end of any disk, so the offset saturates
    // there rather than wrapping round to a small one.
    let offset = |lba: u64| lba.saturating_mul(block);
    let first_usable = offset(le_u64(&header, 40));
    let last_usable = offset(le_u64(&header, 48).saturating_add(1));
    let entries_at = offset(le_u64(&header, 72));
    let count = le_u32(&header, 80).min(256);
    let entry_size = le_u32(&header, 84).clamp(128, 1024);
    let mut table = vec![0u8; (count * entry_size) as usize];
    // Past the end of the source there is nothing to read, and a read at an
    // offset beyond 2^63 bytes fails rather than reading nothing.
    let read = if entries_at < source.size() {
        source.read_at(&mut table, entries_at)?
    } else {
        0
    };
    table.truncate(read);

    let mut partitions = Vec::new();
    for index in 0..count {
        let at = (index * entry_size) as usize;
        if at + 48 > table.len() {
            break;
        }
        let entry = &table[at..at + 48];
        if entry[..16].iter().all(|&b| b == 0) {
            continue;
        }
        let first = offset(le_u64(entry, 32));
        let last = offset(le_u64(entry, 40).saturating_add(1));
        if last <= first || first >= source.size() {
            continue;
        }
        partitions.push(Partition {
            number: index as u32 + 1,
            start: first,
            size: last.min(source.size()) - first,
            type_id: guid(&entry[..16]),
        });
    }
    let end = last_usable.min(source.size());
    Ok(Some(finish(TableKind::Gpt, partitions, first_usable, end)))
}

/// Parse a DOS/MBR table from the first sector, if there is one.
fn parse_mbr(source: &RawSource, sector0: &[u8]) -> Option<Layout> {
    if sector0.len() < 512 || sector0[510..512] != [0x55, 0xAA] {
        return None;
    }
    let mut partitions = Vec::new();
    for index in 0..4u32 {
        let at = 446 + 16 * index as usize;
        let entry = &sector0[at..at + 16];
        let type_byte = entry[4];
        let start = le_u32(entry, 8) * SECTOR;
        let size = le_u32(entry, 12) * SECTOR;
        if type_byte == 0 || size == 0 || start >= source.size() {
            continue;
        }
        partitions.push(Partition {
            number: index + 1,
            start,
            size: size.min(source.size() - start),
            type_id: format!("0x{type_byte:02x}"),
        });
    }
    if partitions.is_empty() {
        // A boot-sector signature with no entries is a filesystem's boot
        // sector (FAT, NTFS), not a partition table.
        return None;
    }
    Some(finish(TableKind::Mbr, partitions, SECTOR, source.size()))
}

/// Sort the partitions and compute the gaps between `from` and `to`.
fn finish(table: TableKind, mut partitions: Vec<Partition>, from: u64, to: u64) -> Layout {
    partitions.sort_by_key(|p| p.start);
    let mut gaps = Vec::new();
    let mut cursor = from;
    for partition in &partitions {
        if partition.start > cursor {
            gaps.push((cursor, partition.start));
        }
        cursor = cursor.max(partition.end());
    }
    if to > cursor {
        gaps.push((cursor, to));
    }
    Layout {
        table,
        partitions,
        gaps,
    }
}

/// The layout of a source with no partition table.
fn no_table() -> Layout {
    Layout {
        table: TableKind::None,
        partitions: Vec::new(),
        gaps: Vec::new(),
    }
}

/// Read the layout of `source`: GPT first (512- and 4096-byte blocks), then
/// MBR, else no table.
///
/// # Errors
///
/// Propagates a read error.
pub fn read_layout(source: &RawSource) -> io::Result<Layout> {
    // A filesystem at offset 0 (a FAT or NTFS boot sector carries the same
    // 0x55AA signature as an MBR) means there is no partition table.
    if let Signature::Format(_) = signature_at(source, 0)? {
        return Ok(no_table());
    }
    read_table(source)
}

/// Read the partition table of `source` as [`read_layout`] does, but whatever
/// signature lies beyond the first sector. Partitioning rewrites only the
/// table, so an older filesystem's signature in the space before the first
/// partition (an ISO9660 descriptor at 32 KiB, an ext4 superblock at 1 KiB
/// behind an MBR) can outlive it, and [`read_layout`] would then see that
/// filesystem and no table. Only a first sector that is itself a filesystem's
/// boot sector or superblock (FAT, NTFS, exFAT, BitLocker, xfs, squashfs) or a
/// LUKS header rules an MBR out.
///
/// # Errors
///
/// Propagates a read error.
pub fn read_table(source: &RawSource) -> io::Result<Layout> {
    let mut sector0 = [0u8; 512];
    let read = source.read_at(&mut sector0, 0)?;
    let sector0 = &sector0[..read];
    let protective = read == 512 && sector0[510..512] == [0x55, 0xAA] && sector0[450] == 0xEE;
    for block in [SECTOR, 4096] {
        if let Some(layout) = parse_gpt(source, block, block)? {
            return Ok(layout);
        }
    }
    // Only the formats whose magic lies in the first sector can match here.
    let boot_sector = sector0.starts_with(LUKS_MAGIC) || first_match(sector0, FORMATS).is_some();
    if !protective
        && !boot_sector
        && let Some(layout) = parse_mbr(source, sector0)
    {
        return Ok(layout);
    }
    Ok(no_table())
}

#[cfg(test)]
pub(crate) mod tests;
