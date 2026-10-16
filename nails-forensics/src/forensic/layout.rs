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

/// `(offset, magic, name)` for the formats identified by a fixed magic.
const FORMATS: &[(usize, &[u8], &str)] = &[
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
    (0x1_0040, b"_BHRfS_M", "btrfs"),
    (0x438, &[0x53, 0xEF], "ext2/3/4"),
    (0x400, &[0xE2, 0xE1, 0xF5, 0xE0], "erofs"),
    (0x400, &[0x10, 0x20, 0xF5, 0xF2], "f2fs"),
];

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
    for (offset, magic, name) in FORMATS {
        if head.len() >= offset + magic.len() && &head[*offset..offset + magic.len()] == *magic {
            return Ok(Signature::Format(name));
        }
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

/// Read the layout of `source`: GPT first (512- and 4096-byte blocks), then
/// MBR, else no table.
///
/// # Errors
///
/// Propagates a read error.
pub fn read_layout(source: &RawSource) -> io::Result<Layout> {
    let none = Layout {
        table: TableKind::None,
        partitions: Vec::new(),
        gaps: Vec::new(),
    };
    // A filesystem at offset 0 (a FAT or NTFS boot sector carries the same
    // 0x55AA signature as an MBR) means there is no partition table.
    if let Signature::Format(_) = signature_at(source, 0)? {
        return Ok(none);
    }
    let mut sector0 = [0u8; 512];
    let read = source.read_at(&mut sector0, 0)?;
    let protective = read == 512 && sector0[510..512] == [0x55, 0xAA] && sector0[450] == 0xEE;
    for block in [SECTOR, 4096] {
        if let Some(layout) = parse_gpt(source, block, block)? {
            return Ok(layout);
        }
    }
    if !protective && let Some(layout) = parse_mbr(source, &sector0[..read]) {
        return Ok(layout);
    }
    Ok(none)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    /// Write `bytes` at `offset` into an image file.
    pub(crate) fn put(file: &mut std::fs::File, offset: u64, bytes: &[u8]) {
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(bytes).unwrap();
    }

    /// A sparse image of `size` bytes with an MBR listing `parts` as
    /// `(type, start_sector, sectors)`.
    pub(crate) fn mbr_image(
        dir: &tempfile::TempDir,
        size: u64,
        parts: &[(u8, u32, u32)],
    ) -> (std::path::PathBuf, std::fs::File) {
        let path = dir.path().join("mbr.img");
        let mut file = std::fs::File::create(&path).unwrap();
        file.set_len(size).unwrap();
        let mut sector = [0u8; 512];
        for (index, (kind, start, sectors)) in parts.iter().enumerate() {
            let at = 446 + 16 * index;
            sector[at + 4] = *kind;
            sector[at + 8..at + 12].copy_from_slice(&start.to_le_bytes());
            sector[at + 12..at + 16].copy_from_slice(&sectors.to_le_bytes());
        }
        sector[510] = 0x55;
        sector[511] = 0xAA;
        put(&mut file, 0, &sector);
        (path, file)
    }

    #[test]
    fn an_mbr_layout_lists_partitions_and_gaps() {
        let dir = tempfile::tempdir().unwrap();
        // 64 MiB disk: p1 at 1 MiB for 16 MiB, p2 at 32 MiB for 8 MiB.
        let (path, file) = mbr_image(&dir, 64 << 20, &[(0x83, 2048, 32768), (0x83, 65536, 16384)]);
        file.sync_all().unwrap();

        let layout = read_layout(&RawSource::open(&path).unwrap()).unwrap();

        assert_eq!(layout.table, TableKind::Mbr);
        assert_eq!(layout.partitions.len(), 2);
        assert_eq!(layout.partitions[0].start, 1 << 20);
        assert_eq!(layout.partitions[1].end(), 40 << 20);
        assert_eq!(
            layout.gaps,
            vec![(512, 1 << 20), (17 << 20, 32 << 20), (40 << 20, 64 << 20)]
        );
    }

    #[test]
    fn a_gpt_layout_is_parsed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gpt.img");
        let mut file = std::fs::File::create(&path).unwrap();
        file.set_len(16 << 20).unwrap();
        // Protective MBR.
        let mut mbr = [0u8; 512];
        mbr[450] = 0xEE;
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        put(&mut file, 0, &mbr);
        let mut header = [0u8; 92];
        header[..8].copy_from_slice(b"EFI PART");
        header[40..48].copy_from_slice(&34u64.to_le_bytes()); // first usable LBA
        header[48..56].copy_from_slice(&(32_734u64).to_le_bytes()); // last usable LBA
        header[72..80].copy_from_slice(&2u64.to_le_bytes()); // entries LBA
        header[80..84].copy_from_slice(&128u32.to_le_bytes());
        header[84..88].copy_from_slice(&128u32.to_le_bytes());
        put(&mut file, 512, &header);
        let mut entry = [0u8; 128];
        entry[..16].copy_from_slice(&[0xAF; 16]);
        entry[32..40].copy_from_slice(&2048u64.to_le_bytes());
        entry[40..48].copy_from_slice(&10_239u64.to_le_bytes());
        put(&mut file, 1024, &entry);
        file.sync_all().unwrap();

        let layout = read_layout(&RawSource::open(&path).unwrap()).unwrap();

        assert_eq!(layout.table, TableKind::Gpt);
        assert_eq!(layout.partitions.len(), 1);
        assert_eq!(layout.partitions[0].start, 1 << 20);
        assert_eq!(layout.partitions[0].size, 4 << 20);
        assert_eq!(layout.gaps.len(), 2);
        assert_eq!(layout.gaps[1], (5 << 20, 32_735 * 512));
    }

    /// Block numbers whose byte offsets do not fit 64 bits, found by the
    /// `disk_layout` fuzz target: the multiplication overflowed, and in a
    /// release build wrapped round to a small offset on the disk.
    #[test]
    fn block_numbers_past_any_disk_do_not_wrap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("gpt.img");
        let mut file = std::fs::File::create(&path).unwrap();
        file.set_len(16 << 20).unwrap();
        let mut header = [0u8; 92];
        header[..8].copy_from_slice(b"EFI PART");
        header[40..48].copy_from_slice(&u64::MAX.to_le_bytes()); // first usable LBA
        header[48..56].copy_from_slice(&u64::MAX.to_le_bytes()); // last usable LBA
        header[72..80].copy_from_slice(&2u64.to_le_bytes()); // entries LBA
        header[80..84].copy_from_slice(&128u32.to_le_bytes());
        header[84..88].copy_from_slice(&128u32.to_le_bytes());
        put(&mut file, 512, &header);
        let entry = |first: u64, last: u64| {
            let mut entry = [0u8; 128];
            entry[..16].copy_from_slice(&[0xAF; 16]);
            entry[32..40].copy_from_slice(&first.to_le_bytes());
            entry[40..48].copy_from_slice(&last.to_le_bytes());
            entry
        };
        // 2^55 + 2 blocks are 2^64 + 1 KiB bytes, which wrapped to 1 KiB.
        put(&mut file, 1024, &entry((1 << 55) + 2, (1 << 55) + 10));
        // The last block there is: the partition runs to the end of the disk.
        put(&mut file, 1024 + 128, &entry(2048, u64::MAX));
        file.sync_all().unwrap();

        let layout = read_layout(&RawSource::open(&path).unwrap()).unwrap();
        assert_eq!(layout.table, TableKind::Gpt);
        assert_eq!(layout.partitions.len(), 1, "{layout:?}");
        assert_eq!(layout.partitions[0].number, 2);
        assert_eq!(layout.partitions[0].start, 1 << 20);
        assert_eq!(layout.partitions[0].end(), 16 << 20);
        // The first usable block lies past the disk, so nothing is free.
        assert!(layout.gaps.is_empty(), "{layout:?}");

        // An entry array past the end of the disk holds no entry: beyond
        // 2^63 bytes the read itself failed, and beyond 2^64 it wrapped.
        for lba in [1u64 << 54, 1 << 60] {
            header[72..80].copy_from_slice(&lba.to_le_bytes());
            put(&mut file, 512, &header);
            file.sync_all().unwrap();
            let layout = read_layout(&RawSource::open(&path).unwrap()).unwrap();
            assert_eq!(layout.table, TableKind::Gpt);
            assert!(layout.partitions.is_empty(), "{layout:?}");
        }
    }

    #[test]
    fn signatures_are_identified() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sig.img");
        let mut file = std::fs::File::create(&path).unwrap();
        file.set_len(32 << 20).unwrap();
        // LUKS2 at 0, ext4 at 4 MiB, LUKS2 secondary only at 8 MiB + 16 KiB.
        put(&mut file, 0, b"LUKS\xba\xbe\x00\x02");
        put(&mut file, (4 << 20) + 0x438, &[0x53, 0xEF]);
        put(&mut file, (8 << 20) + 0x4000, b"SKUL\xba\xbe\x00\x02");
        file.sync_all().unwrap();
        let source = RawSource::open(&path).unwrap();

        assert_eq!(signature_at(&source, 0).unwrap(), Signature::Luks(2));
        assert_eq!(
            signature_at(&source, 4 << 20).unwrap(),
            Signature::Format("ext2/3/4")
        );
        assert_eq!(
            signature_at(&source, 8 << 20).unwrap(),
            Signature::Luks2Secondary(0x4000)
        );
        assert_eq!(signature_at(&source, 16 << 20).unwrap(), Signature::Unknown);
    }

    #[test]
    fn a_bare_filesystem_has_no_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fs.img");
        let mut file = std::fs::File::create(&path).unwrap();
        file.set_len(4 << 20).unwrap();
        put(&mut file, 0x438, &[0x53, 0xEF]);
        file.sync_all().unwrap();

        let layout = read_layout(&RawSource::open(&path).unwrap()).unwrap();
        assert_eq!(layout.table, TableKind::None);
        assert!(layout.partitions.is_empty());
    }
}
