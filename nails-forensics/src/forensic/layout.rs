// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Disk layout as an examiner sees it: the partition table, the space it does
//! not cover, and what each region starts with.
//!
//! Parses an MBR or a GPT read-only from a [`RawSource`], lists the gaps
//! between and after partitions, and identifies the common on-disk signatures
//! (LUKS, the usual filesystems, LVM, swap, BitLocker). The layout is fitted
//! to the source; [`recorded_table`] keeps the table as the disk records it,
//! for a source that ends before the disk did. Nothing here mounts or writes;
//! every read is a bounded positioned read.

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

/// A partition table as the disk records it, before [`read_table`] fits it
/// to the source. An image whose copy stopped early still holds the whole
/// table but not all of the disk it describes, so a partition here can start
/// or end past the end of the source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedTable {
    /// The table found.
    pub table: TableKind,
    /// Every partition the table lists, in start order, as far as the table
    /// says it runs.
    pub partitions: Vec<Partition>,
    /// For a GPT, one past the last byte of the disk it was written for: the
    /// end of its last usable block or of its backup header, whichever lies
    /// further. `None` for an MBR, which records no disk size.
    pub disk_end: Option<u64>,
    /// Whether a GPT keeps its own rules: every entry runs forwards within the
    /// usable blocks, and when the header's own checksum holds, the entries
    /// match the checksum it keeps of them. The header of an older GPT in
    /// front of a filesystem made on the whole disk since breaks them, its
    /// entries written over. An MBR has no such rules and always keeps them.
    pub consistent: bool,
    /// The bytes the partitions may use: from the first usable block to one
    /// past the last.
    usable: (u64, u64),
}

impl RecordedTable {
    /// No table.
    fn none() -> Self {
        Self {
            table: TableKind::None,
            partitions: Vec::new(),
            disk_end: None,
            consistent: true,
            usable: (0, 0),
        }
    }

    /// The layout on a source of `size` bytes: a partition that starts past
    /// its end is left out, one that runs past it is cut there, and so are
    /// the gaps.
    fn fitted(&self, size: u64) -> Layout {
        let partitions: Vec<Partition> = self
            .partitions
            .iter()
            .filter(|partition| partition.start < size)
            .map(|partition| Partition {
                size: partition.end().min(size) - partition.start,
                ..partition.clone()
            })
            .collect();
        // An MBR none of whose partitions starts on the source reads as no
        // table, as one that lists none does.
        if self.table == TableKind::None || (self.table == TableKind::Mbr && partitions.is_empty())
        {
            return no_table();
        }
        finish(
            self.table,
            partitions,
            self.usable.0,
            self.usable.1.min(size),
        )
    }
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

/// Where an f2fs superblock keeps its feature flags: `feature`, 0x884 bytes
/// into the superblock at 1 KiB (`struct f2fs_super_block`).
const F2FS_FEATURES: u64 = 0x400 + 0x884;

/// The f2fs feature flag of a filesystem made with compression
/// (`F2FS_FEATURE_COMPRESSION`).
const F2FS_FEATURE_COMPRESSION: u32 = 0x2000;

/// The f2fs feature flag of a filesystem that can encrypt
/// (`F2FS_FEATURE_ENCRYPT`).
const F2FS_FEATURE_ENCRYPT: u32 = 0x0001;

/// Where an ext2/3/4 superblock keeps its incompatible feature flags:
/// `s_feature_incompat`, 0x60 bytes into the superblock at 1 KiB.
const EXT4_INCOMPAT: u64 = 0x400 + 0x60;

/// The ext4 feature flag of a filesystem that can encrypt
/// (`EXT4_FEATURE_INCOMPAT_ENCRYPT`).
const EXT4_FEATURE_ENCRYPT: u32 = 0x1_0000;

/// Whether the 32-bit feature flags `at` bytes into the region at `start`
/// carry `flag`; `None` when the source ends before the flags, so they say
/// nothing either way.
fn feature(source: &RawSource, start: u64, at: u64, flag: u32) -> io::Result<Option<bool>> {
    let mut features = [0u8; 4];
    let read = source.read_at(&mut features, start.saturating_add(at))?;
    Ok((read == features.len()).then(|| u32::from_le_bytes(features) & flag != 0))
}

/// Whether the f2fs at `start` was made with the compression feature
/// (`mkfs.f2fs -O compression`), from its superblock's feature flags; `None`
/// when the source ends inside the superblock, before its flags.
///
/// # Errors
///
/// Propagates a read error.
pub fn f2fs_compression(source: &RawSource, start: u64) -> io::Result<Option<bool>> {
    feature(source, start, F2FS_FEATURES, F2FS_FEATURE_COMPRESSION)
}

/// Whether the filesystem of `format` at `start` has the encrypt feature
/// (fscrypt, which `mkfs.ext4 -O encrypt` or `mkfs.f2fs -O encrypt` sets),
/// from its superblock's feature flags. An ext2/3/4 or f2fs with it stores the
/// files of an encrypted directory encrypted; no other format has it. `None`
/// when the source ends inside the superblock of an ext2/3/4 or f2fs, before
/// its flags.
///
/// # Errors
///
/// Propagates a read error.
pub fn encryption_feature(
    source: &RawSource,
    start: u64,
    format: &str,
) -> io::Result<Option<bool>> {
    match format {
        "ext2/3/4" => feature(source, start, EXT4_INCOMPAT, EXT4_FEATURE_ENCRYPT),
        "f2fs" => feature(source, start, F2FS_FEATURES, F2FS_FEATURE_ENCRYPT),
        _ => Ok(Some(false)),
    }
}

/// What a filesystem's superblock says about the bytes the filesystem spans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordedSize {
    /// It spans this many bytes.
    Bytes(u64),
    /// The format keeps no size [`recorded_size`] reads.
    Unrecorded,
    /// The superblock records what no filesystem of the format has, such as
    /// a block size it never uses: its magic matched other bytes by chance,
    /// and no such filesystem is there.
    Implausible,
}

/// The size of a page of a swap area whose magic is at 0xff6: the magic ends
/// the first page, so it is 4 KiB.
const SWAP_PAGE: u64 = 0xff6 + 10;

/// How many bytes the filesystem of `format` at `start` says it spans: an
/// ext2/3/4 superblock's block count times its block size, an xfs
/// superblock's data blocks times its block size, an f2fs superblock's block
/// count times its block size, a FAT, NTFS or exFAT boot sector's sector
/// count times its sector size, and a swap header's last page plus one times
/// the page. A boot sector whose sector is no power of two from 512 bytes to
/// 4 KiB, or that counts no sector, is implausible, and so is a swap header
/// of a version the kernel does not read or with no page past itself.
///
/// # Errors
///
/// Propagates a read error.
pub fn recorded_size(source: &RawSource, start: u64, format: &str) -> io::Result<RecordedSize> {
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
            Ok(if log_block <= 6 {
                RecordedSize::Bytes(blocks.saturating_mul(1024 << log_block))
            } else {
                RecordedSize::Implausible
            })
        }
        "xfs" => {
            let mut sb = [0u8; 16];
            source.read_at(&mut sb, start)?;
            let block = u64::from(u32::from_be_bytes([sb[4], sb[5], sb[6], sb[7]]));
            let blocks = u64::from_be_bytes(sb[8..16].try_into().unwrap_or_default());
            // xfs blocks are a power of two from 512 bytes to 64 KiB.
            Ok(
                if block.is_power_of_two() && (512..=1 << 16).contains(&block) {
                    RecordedSize::Bytes(blocks.saturating_mul(block))
                } else {
                    RecordedSize::Implausible
                },
            )
        }
        "f2fs" => {
            // The superblock at 1 KiB, through block_count: log2 of the block
            // size at 0x10 and the block count at 0x24; past the end of the
            // source its fields read as zero.
            let mut sb = [0u8; 0x2C];
            source.read_at(&mut sb, start.saturating_add(0x400))?;
            let log_block = le_u32(&sb, 0x10);
            let blocks = le_u64(&sb, 0x24);
            // An f2fs block is the page size: 4 KiB, up to 64 KiB.
            Ok(if (12..=16).contains(&log_block) {
                RecordedSize::Bytes(blocks.saturating_mul(1 << log_block))
            } else {
                RecordedSize::Implausible
            })
        }
        "vfat" => {
            // The BIOS parameter block: the bytes per sector at 0x0B and the
            // sector count at 0x13, or at 0x20 where that one is zero (on a
            // FAT32, and on any FAT of 65536 sectors or more).
            let mut bpb = [0u8; 0x24];
            source.read_at(&mut bpb, start)?;
            let sectors = match le_u16(&bpb, 0x13) {
                0 => le_u32(&bpb, 0x20),
                sectors => sectors,
            };
            Ok(in_sectors(le_u16(&bpb, 0x0B), sectors))
        }
        "ntfs" => {
            // The bytes per sector at 0x0B and the sector count at 0x28.
            let mut bpb = [0u8; 0x30];
            source.read_at(&mut bpb, start)?;
            Ok(in_sectors(le_u16(&bpb, 0x0B), le_u64(&bpb, 0x28)))
        }
        "exfat" => {
            // The sector count at 0x48 and log2 of the bytes per sector at
            // 0x6C.
            let mut boot = [0u8; 0x6D];
            source.read_at(&mut boot, start)?;
            let sector = 1u64.checked_shl(u32::from(boot[0x6C])).unwrap_or(0);
            Ok(in_sectors(sector, le_u64(&boot, 0x48)))
        }
        "swap" => {
            // The header's version at 1 KiB, then the number of its last
            // page; past the end of the source both read as zero.
            let mut info = [0u8; 8];
            source.read_at(&mut info, start.saturating_add(0x400))?;
            let last_page = match info {
                [1, 0, 0, 0, page @ ..] => u32::from_le_bytes(page),
                // Made on a big-endian machine: the kernel swaps its bytes.
                [0, 0, 0, 1, page @ ..] => u32::from_be_bytes(page),
                // The first version kept a map of its pages here, which no
                // kernel since 2.5 reads.
                _ => return Ok(RecordedSize::Implausible),
            };
            // The kernel refuses a swap area with no page past its header.
            Ok(if last_page == 0 {
                RecordedSize::Implausible
            } else {
                RecordedSize::Bytes((u64::from(last_page) + 1) * SWAP_PAGE)
            })
        }
        _ => Ok(RecordedSize::Unrecorded),
    }
}

/// The bytes `sectors` sectors of `sector` bytes span, as a FAT, NTFS or
/// exFAT boot sector records them: implausible unless a sector is a power of
/// two from 512 bytes to 4 KiB and there is one at least.
fn in_sectors(sector: u64, sectors: u64) -> RecordedSize {
    if sector.is_power_of_two() && (512..=4096).contains(&sector) && sectors > 0 {
        RecordedSize::Bytes(sectors.saturating_mul(sector))
    } else {
        RecordedSize::Implausible
    }
}

fn le_u16(bytes: &[u8], at: usize) -> u64 {
    u64::from(u16::from_le_bytes(
        bytes[at..at + 2].try_into().unwrap_or_default(),
    ))
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

/// The CRC-32 a GPT keeps of its header and of its entries (the IEEE
/// polynomial, as zlib computes it).
fn crc32(bytes: &[u8]) -> u32 {
    !bytes.iter().fold(u32::MAX, |crc, &byte| {
        (0..8).fold(crc ^ u32::from(byte), |crc, _| {
            (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg())
        })
    })
}

/// Whether a GPT header matches the checksum it keeps of itself: over its own
/// length, with the checksum field read as zero.
fn header_checksum_holds(header: &[u8]) -> bool {
    let length = le_u32(header, 12);
    if !(92..=header.len() as u64).contains(&length) {
        return false;
    }
    let mut own = header[..length as usize].to_vec();
    own[16..20].fill(0);
    u64::from(crc32(&own)) == le_u32(header, 16)
}

/// Parse the GPT whose header is at `header_at`, if there is one.
fn parse_gpt(source: &RawSource, header_at: u64, block: u64) -> io::Result<Option<RecordedTable>> {
    let mut header = vec![0u8; block as usize];
    let read = source.read_at(&mut header, header_at)?;
    if read < 92 || &header[..8] != b"EFI PART" {
        return Ok(None);
    }
    header.truncate(read);
    // A block number is whatever the disk says. One whose byte offset does
    // not fit 64 bits lies past the end of any disk, so the offset saturates
    // there rather than wrapping round to a small one.
    let offset = |lba: u64| lba.saturating_mul(block);
    let first_usable = offset(le_u64(&header, 40));
    let last_usable = offset(le_u64(&header, 48).saturating_add(1));
    let backup_end = offset(le_u64(&header, 32).saturating_add(1));
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
    // The entries' checksum vouches for them only when the header's own
    // holds and every entry it lists was read.
    let checked = read == table.len()
        && (le_u32(&header, 80), le_u32(&header, 84)) == (count, entry_size)
        && header_checksum_holds(&header);
    let mut consistent = !checked || u64::from(crc32(&table)) == le_u32(&header, 88);
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
        consistent &= first_usable <= first && first < last && last <= last_usable;
        if last <= first {
            continue;
        }
        partitions.push(Partition {
            number: index as u32 + 1,
            start: first,
            size: last - first,
            type_id: guid(&entry[..16]),
        });
    }
    partitions.sort_by_key(|partition| partition.start);
    Ok(Some(RecordedTable {
        table: TableKind::Gpt,
        partitions,
        disk_end: Some(last_usable.max(backup_end)),
        consistent,
        usable: (first_usable, last_usable),
    }))
}

/// Parse a DOS/MBR table from the first sector, if there is one.
fn parse_mbr(sector0: &[u8]) -> Option<RecordedTable> {
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
        if type_byte == 0 || size == 0 {
            continue;
        }
        partitions.push(Partition {
            number: index + 1,
            start,
            size,
            type_id: format!("0x{type_byte:02x}"),
        });
    }
    if partitions.is_empty() {
        // A boot-sector signature with no entries is a filesystem's boot
        // sector (FAT, NTFS), not a partition table.
        return None;
    }
    partitions.sort_by_key(|partition| partition.start);
    Some(RecordedTable {
        table: TableKind::Mbr,
        partitions,
        disk_end: None,
        consistent: true,
        usable: (SECTOR, u64::MAX),
    })
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
    Ok(recorded_table(source)?.fitted(source.size()))
}

/// The partition table of `source` as [`read_table`] finds it, before it is
/// fitted to the source: a partition that runs past the end of the source,
/// as on an image whose copy stopped early, is listed as the table records
/// it, and a GPT says how large a disk it was written for.
///
/// # Errors
///
/// Propagates a read error.
pub fn recorded_table(source: &RawSource) -> io::Result<RecordedTable> {
    let mut sector0 = [0u8; 512];
    let read = source.read_at(&mut sector0, 0)?;
    let sector0 = &sector0[..read];
    let protective = read == 512 && sector0[510..512] == [0x55, 0xAA] && sector0[450] == 0xEE;
    for block in [SECTOR, 4096] {
        if let Some(table) = parse_gpt(source, block, block)? {
            return Ok(table);
        }
    }
    // Only the formats whose magic lies in the first sector can match here.
    let boot_sector = sector0.starts_with(LUKS_MAGIC) || first_match(sector0, FORMATS).is_some();
    if !protective
        && !boot_sector
        && let Some(table) = parse_mbr(sector0)
    {
        return Ok(table);
    }
    Ok(RecordedTable::none())
}

#[cfg(test)]
pub(crate) mod tests;
