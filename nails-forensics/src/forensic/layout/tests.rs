// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The disk layout readers on image files: partition tables, signatures,
//! and the image builders the examiner tests share.

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

#[test]
fn a_compressing_filesystem_is_found_beside_a_stale_signature() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f2fs.img");
    let mut file = std::fs::File::create(&path).unwrap();
    file.set_len(4 << 20).unwrap();
    // An f2fs over an older ISO9660 image, a bcachefs at 2 MiB and a
    // btrfs at 3 MiB.
    put(&mut file, 0x400, F2FS.1);
    put(&mut file, 0x8001, b"CD001");
    put(&mut file, (2 << 20) + 0x1018, BCACHEFS.1);
    put(&mut file, (3 << 20) + 0x1_0040, b"_BHRfS_M");
    file.sync_all().unwrap();
    let source = RawSource::open(&path).unwrap();

    // The first match is the ISO9660 descriptor; the f2fs is still found.
    assert_eq!(
        signature_at(&source, 0).unwrap(),
        Signature::Format("iso9660")
    );
    assert_eq!(compressing_format_at(&source, 0).unwrap(), Some("f2fs"));
    assert_eq!(
        compressing_format_at(&source, 2 << 20).unwrap(),
        Some("bcachefs")
    );
    assert_eq!(
        compressing_format_at(&source, 3 << 20).unwrap(),
        Some("btrfs")
    );
    assert_eq!(compressing_format_at(&source, 1 << 20).unwrap(), None);
}

#[test]
fn the_recorded_size_of_ext4_and_xfs_comes_from_the_superblock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sizes.img");
    let mut file = std::fs::File::create(&path).unwrap();
    file.set_len(1 << 20).unwrap();
    let ext4 = |blocks: u32, log_block: u32, incompat: u32, blocks_hi: u32| {
        let mut sb = [0u8; 0x154];
        sb[0x04..0x08].copy_from_slice(&blocks.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&log_block.to_le_bytes());
        sb[0x60..0x64].copy_from_slice(&incompat.to_le_bytes());
        sb[0x150..0x154].copy_from_slice(&blocks_hi.to_le_bytes());
        sb
    };
    let xfs = |block: u32, blocks: u64| {
        let mut sb = [0u8; 16];
        sb[..4].copy_from_slice(b"XFSB");
        sb[4..8].copy_from_slice(&block.to_be_bytes());
        sb[8..].copy_from_slice(&blocks.to_be_bytes());
        sb
    };
    // 4 KiB blocks; the high half of the count only with the 64bit feature.
    put(&mut file, 0x400, &ext4(16384, 2, 0, 1));
    put(&mut file, (64 << 10) + 0x400, &ext4(16384, 2, 0x80, 1));
    // 64 KiB blocks are the largest ext4 has.
    put(&mut file, (128 << 10) + 0x400, &ext4(10, 6, 0, 0));
    put(&mut file, (192 << 10) + 0x400, &ext4(10, 7, 0, 0));
    // xfs blocks are a power of two from 512 bytes to 64 KiB.
    put(&mut file, 256 << 10, &xfs(4096, 100));
    put(&mut file, 320 << 10, &xfs(512, 3));
    put(&mut file, 384 << 10, &xfs(1 << 16, 2));
    put(&mut file, 448 << 10, &xfs(1000, 100));
    put(&mut file, 512 << 10, &xfs(256, 100));
    put(&mut file, 576 << 10, &xfs(1 << 17, 100));
    file.sync_all().unwrap();
    let source = RawSource::open(&path).unwrap();
    let size = |start, format| recorded_size(&source, start, format).unwrap();

    assert_eq!(size(0, "ext2/3/4"), Some(16384 * 4096));
    assert_eq!(size(64 << 10, "ext2/3/4"), Some(((1 << 32) + 16384) * 4096));
    assert_eq!(size(128 << 10, "ext2/3/4"), Some(10 << 16));
    assert_eq!(size(192 << 10, "ext2/3/4"), None);
    assert_eq!(size(256 << 10, "xfs"), Some(409_600));
    assert_eq!(size(320 << 10, "xfs"), Some(1536));
    assert_eq!(size(384 << 10, "xfs"), Some(2 << 16));
    for start in [448 << 10, 512 << 10, 576 << 10] {
        assert_eq!(size(start, "xfs"), None, "{start}");
    }
    assert_eq!(size(0, "vfat"), None);
}

#[test]
fn a_table_behind_a_stale_superblock_is_found_by_read_table() {
    let dir = tempfile::tempdir().unwrap();
    // An MBR over what an ext4 that once spanned the disk left behind it.
    let (path, mut file) = mbr_image(&dir, 64 << 20, &[(0x83, 2048, 32768)]);
    put(&mut file, 0x438, &[0x53, 0xEF]);
    file.sync_all().unwrap();
    let source = RawSource::open(&path).unwrap();

    assert_eq!(read_layout(&source).unwrap().table, TableKind::None);
    let table = read_table(&source).unwrap();
    assert_eq!(table.table, TableKind::Mbr);
    assert_eq!(table.partitions.len(), 1);
    assert_eq!(table.partitions[0].start, 1 << 20);
}

#[test]
fn a_boot_sector_or_a_luks_header_is_never_read_as_an_mbr() {
    // A FAT32 boot sector and a LUKS header, each with the 0x55AA
    // signature and an entry where an MBR keeps its first partition.
    for (offset, magic) in [(0x52, &b"FAT32   "[..]), (0, &b"LUKS\xba\xbe\x00\x01"[..])] {
        let dir = tempfile::tempdir().unwrap();
        let (path, mut file) = mbr_image(&dir, 64 << 20, &[(0x83, 2048, 32768)]);
        put(&mut file, offset, magic);
        file.sync_all().unwrap();
        let source = RawSource::open(&path).unwrap();

        assert_eq!(read_table(&source).unwrap(), no_table(), "{magic:?}");
        assert_eq!(read_layout(&source).unwrap(), no_table(), "{magic:?}");
    }
}
