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

/// A GPT entry for a partition from block `first` to block `last`.
pub(crate) fn gpt_entry(first: u64, last: u64) -> [u8; 128] {
    let mut entry = [0u8; 128];
    entry[..16].copy_from_slice(&[0xAF; 16]);
    entry[32..40].copy_from_slice(&first.to_le_bytes());
    entry[40..48].copy_from_slice(&last.to_le_bytes());
    entry
}

/// A GPT header for block 1 of a 512-byte-block disk, keeping both
/// checksums: its entry array is `entries` from block 2, its usable blocks
/// run from `first_usable` to `last_usable`, and its backup header lies at
/// block `backup`.
pub(crate) fn gpt_header(
    first_usable: u64,
    last_usable: u64,
    backup: u64,
    entries: &[u8],
) -> [u8; 92] {
    let count = u32::try_from(entries.len() / 128).unwrap();
    let mut header = [0u8; 92];
    header[..8].copy_from_slice(b"EFI PART");
    header[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // revision 1.0
    header[12..16].copy_from_slice(&92u32.to_le_bytes()); // header size
    header[24..32].copy_from_slice(&1u64.to_le_bytes()); // this header's block
    header[32..40].copy_from_slice(&backup.to_le_bytes());
    header[40..48].copy_from_slice(&first_usable.to_le_bytes());
    header[48..56].copy_from_slice(&last_usable.to_le_bytes());
    header[72..80].copy_from_slice(&2u64.to_le_bytes()); // entries block
    header[80..84].copy_from_slice(&count.to_le_bytes());
    header[84..88].copy_from_slice(&128u32.to_le_bytes());
    header[88..92].copy_from_slice(&crc32(entries).to_le_bytes());
    let own = crc32(&header);
    header[16..20].copy_from_slice(&own.to_le_bytes());
    header
}

#[test]
fn the_gpt_checksum_is_the_one_zlib_computes() {
    // The check value of the CRC-32 over the IEEE polynomial.
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b""), 0);
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
    use RecordedSize::{Bytes, Implausible, Unrecorded};
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

    assert_eq!(size(0, "ext2/3/4"), Bytes(16384 * 4096));
    assert_eq!(
        size(64 << 10, "ext2/3/4"),
        Bytes(((1 << 32) + 16384) * 4096)
    );
    assert_eq!(size(128 << 10, "ext2/3/4"), Bytes(10 << 16));
    assert_eq!(size(192 << 10, "ext2/3/4"), Implausible);
    assert_eq!(size(256 << 10, "xfs"), Bytes(409_600));
    assert_eq!(size(320 << 10, "xfs"), Bytes(1536));
    assert_eq!(size(384 << 10, "xfs"), Bytes(2 << 16));
    for start in [448 << 10, 512 << 10, 576 << 10] {
        assert_eq!(size(start, "xfs"), Implausible, "{start}");
    }
    // A read-only format keeps no size the scan reads.
    assert_eq!(size(0, "erofs"), Unrecorded);
}

/// A FAT boot sector (`mkfs.fat`) of `sector` bytes per sector with the
/// 16-bit sector count `sectors16` and the 32-bit one `sectors32`, its type
/// named at 0x52 as on a FAT32.
pub(crate) fn fat_boot_sector(sector: u16, sectors16: u16, sectors32: u32) -> [u8; 512] {
    let mut boot = [0u8; 512];
    boot[3..11].copy_from_slice(b"mkfs.fat");
    boot[0x0B..0x0D].copy_from_slice(&sector.to_le_bytes());
    boot[0x13..0x15].copy_from_slice(&sectors16.to_le_bytes());
    boot[0x20..0x24].copy_from_slice(&sectors32.to_le_bytes());
    boot[0x52..0x5A].copy_from_slice(b"FAT32   ");
    boot[510..].copy_from_slice(&[0x55, 0xAA]);
    boot
}

/// An NTFS boot sector (`mkntfs`) of `sector` bytes per sector and `sectors`
/// sectors.
pub(crate) fn ntfs_boot_sector(sector: u16, sectors: u64) -> [u8; 512] {
    let mut boot = [0u8; 512];
    boot[3..11].copy_from_slice(b"NTFS    ");
    boot[0x0B..0x0D].copy_from_slice(&sector.to_le_bytes());
    boot[0x28..0x30].copy_from_slice(&sectors.to_le_bytes());
    boot[510..].copy_from_slice(&[0x55, 0xAA]);
    boot
}

/// An exFAT boot sector (`mkfs.exfat`) of `sectors` sectors of 2^`shift`
/// bytes each.
pub(crate) fn exfat_boot_sector(shift: u8, sectors: u64) -> [u8; 512] {
    let mut boot = [0u8; 512];
    boot[3..11].copy_from_slice(b"EXFAT   ");
    boot[0x48..0x50].copy_from_slice(&sectors.to_le_bytes());
    boot[0x6C] = shift;
    boot[510..].copy_from_slice(&[0x55, 0xAA]);
    boot
}

/// The first page of a swap area (`mkswap`): `version` and `last_page` as
/// the bytes the header holds, and the magic that ends the page.
pub(crate) fn swap_header(version: [u8; 4], last_page: [u8; 4]) -> [u8; 4096] {
    let mut page = [0u8; 4096];
    page[0x400..0x404].copy_from_slice(&version);
    page[0x404..0x408].copy_from_slice(&last_page);
    page[0xff6..].copy_from_slice(b"SWAPSPACE2");
    page
}

#[test]
fn the_recorded_size_of_a_fat_ntfs_or_exfat_comes_from_its_boot_sector() {
    use RecordedSize::{Bytes, Implausible};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("boot.img");
    let mut file = std::fs::File::create(&path).unwrap();
    file.set_len(1 << 20).unwrap();
    // A FAT16 counts its sectors in 16 bits, and in 32 where those are zero;
    // the 32-bit count of a FAT that has a 16-bit one is not read.
    put(&mut file, 0, &fat_boot_sector(512, 32768, 0));
    put(&mut file, 16 << 10, &fat_boot_sector(512, 0, 131_072));
    put(&mut file, 32 << 10, &fat_boot_sector(4096, 1000, 7));
    put(&mut file, 48 << 10, &fat_boot_sector(1024, 0, 0));
    // NTFS records one sector less than the volume, its backup boot sector.
    put(&mut file, 64 << 10, &ntfs_boot_sector(512, 131_071));
    put(&mut file, 80 << 10, &ntfs_boot_sector(4096, 3));
    put(&mut file, 96 << 10, &ntfs_boot_sector(512, 0));
    put(&mut file, 112 << 10, &exfat_boot_sector(9, 131_072));
    put(&mut file, 128 << 10, &exfat_boot_sector(12, 5));
    put(&mut file, 144 << 10, &exfat_boot_sector(9, 0));
    file.sync_all().unwrap();
    let source = RawSource::open(&path).unwrap();
    let size = |start, format| recorded_size(&source, start, format).unwrap();

    assert_eq!(size(0, "vfat"), Bytes(16 << 20));
    assert_eq!(size(16 << 10, "vfat"), Bytes(64 << 20));
    assert_eq!(size(32 << 10, "vfat"), Bytes(1000 * 4096));
    assert_eq!(size(48 << 10, "vfat"), Implausible);
    assert_eq!(size(64 << 10, "ntfs"), Bytes((64 << 20) - 512));
    assert_eq!(size(80 << 10, "ntfs"), Bytes(3 * 4096));
    assert_eq!(size(96 << 10, "ntfs"), Implausible);
    assert_eq!(size(112 << 10, "exfat"), Bytes(64 << 20));
    assert_eq!(size(128 << 10, "exfat"), Bytes(5 * 4096));
    assert_eq!(size(144 << 10, "exfat"), Implausible);
}

#[test]
fn a_boot_sector_with_a_sector_no_disk_has_is_implausible() {
    // A sector is a power of two from 512 bytes to 4 KiB, as the kernel's
    // FAT, ntfs3 and exFAT drivers take it.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("boot.img");
    let mut file = std::fs::File::create(&path).unwrap();
    file.set_len(1 << 20).unwrap();
    for (index, sector) in [0u16, 256, 1000, 2048 + 512, 8192].into_iter().enumerate() {
        let at = (index as u64) << 14;
        put(&mut file, at, &fat_boot_sector(sector, 100, 0));
        put(&mut file, at + (8 << 10), &ntfs_boot_sector(sector, 100));
    }
    for (index, shift) in [0u8, 8, 13, 64, 255].into_iter().enumerate() {
        put(
            &mut file,
            (512 << 10) + ((index as u64) << 14),
            &exfat_boot_sector(shift, 100),
        );
    }
    file.sync_all().unwrap();
    let source = RawSource::open(&path).unwrap();
    let size = |start, format| recorded_size(&source, start, format).unwrap();

    for index in 0..5u64 {
        assert_eq!(size(index << 14, "vfat"), RecordedSize::Implausible);
        assert_eq!(
            size((index << 14) + (8 << 10), "ntfs"),
            RecordedSize::Implausible
        );
        assert_eq!(
            size((512 << 10) + (index << 14), "exfat"),
            RecordedSize::Implausible
        );
    }
}

#[test]
fn the_recorded_size_of_a_swap_area_comes_from_its_last_page() {
    use RecordedSize::{Bytes, Implausible};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("swap.img");
    let mut file = std::fs::File::create(&path).unwrap();
    file.set_len(1 << 20).unwrap();
    // mkswap on 64 MiB: version 1, last page 16383.
    put(
        &mut file,
        0,
        &swap_header([1, 0, 0, 0], 16383u32.to_le_bytes()),
    );
    // Made on a big-endian machine.
    put(
        &mut file,
        64 << 10,
        &swap_header([0, 0, 0, 1], 16383u32.to_be_bytes()),
    );
    // A version the kernel does not read, the first one's page map among
    // them, and an area with no page past its header.
    put(
        &mut file,
        128 << 10,
        &swap_header([2, 0, 0, 0], [1, 0, 0, 0]),
    );
    put(&mut file, 192 << 10, &swap_header([0xFF; 4], [0xFF; 4]));
    put(&mut file, 256 << 10, &swap_header([1, 0, 0, 0], [0; 4]));
    put(&mut file, 320 << 10, &swap_header([0, 0, 0, 1], [0; 4]));
    file.sync_all().unwrap();
    let source = RawSource::open(&path).unwrap();
    let size = |start| recorded_size(&source, start, "swap").unwrap();

    assert_eq!(size(0), Bytes(64 << 20));
    assert_eq!(size(64 << 10), Bytes(64 << 20));
    for start in [128 << 10, 192 << 10, 256 << 10, 320 << 10] {
        assert_eq!(size(start), Implausible, "{start}");
    }
}

#[test]
fn the_encrypt_feature_of_an_ext4_or_f2fs_comes_from_its_superblock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("encrypt.img");
    let mut file = std::fs::File::create(&path).unwrap();
    file.set_len(1 << 20).unwrap();
    // The incompatible features of an ext4 at 0x460: mkfs.ext4's defaults
    // (0x2c2), and with -O encrypt.
    put(&mut file, 0x460, &0x2C2u32.to_le_bytes());
    put(&mut file, (64 << 10) + 0x460, &0x1_22C2u32.to_le_bytes());
    // The features of an f2fs at 0xC84: none, encrypt, and compression and
    // extra_attr without encrypt.
    put(&mut file, (128 << 10) + 0xC84, &0u32.to_le_bytes());
    put(&mut file, (192 << 10) + 0xC84, &1u32.to_le_bytes());
    put(&mut file, (256 << 10) + 0xC84, &0x2008u32.to_le_bytes());
    file.sync_all().unwrap();
    let source = RawSource::open(&path).unwrap();
    let encrypting = |start, format| encryption_feature(&source, start, format).unwrap();

    assert!(!encrypting(0, "ext2/3/4"));
    assert!(encrypting(64 << 10, "ext2/3/4"));
    assert!(!encrypting(128 << 10, "f2fs"));
    assert!(encrypting(192 << 10, "f2fs"));
    assert!(!encrypting(256 << 10, "f2fs"));
    // Each format's flags are its own: the f2fs flag is no ext4 flag.
    assert!(!encrypting(192 << 10, "ext2/3/4"));
    assert!(!encrypting(64 << 10, "f2fs"));
    // No other format has the feature, whatever its bytes there.
    put(&mut file, 0xC84, &[0xFF; 4]);
    put(&mut file, 0x460, &[0xFF; 4]);
    file.sync_all().unwrap();
    let source = RawSource::open(&path).unwrap();
    assert!(!encryption_feature(&source, 0, "xfs").unwrap());
    assert!(!encryption_feature(&source, 0, "vfat").unwrap());
    // A superblock the source ends inside, before its flags, counts as one
    // with the feature.
    assert!(encryption_feature(&source, (1 << 20) - 0x400, "ext2/3/4").unwrap());
    assert!(encryption_feature(&source, (1 << 20) - 0x800, "f2fs").unwrap());
}

#[test]
fn the_size_and_compression_of_an_f2fs_come_from_its_superblock() {
    use RecordedSize::{Bytes, Implausible};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f2fs.img");
    let mut file = std::fs::File::create(&path).unwrap();
    file.set_len(1 << 20).unwrap();
    // The superblock at 1 KiB: log2 of the block size at 0x10, the block
    // count at 0x24 and the feature flags at 0x884.
    let f2fs = |log_block: u32, blocks: u64, features: u32| {
        let mut sb = vec![0u8; 0x888];
        sb[..4].copy_from_slice(&[0x10, 0x20, 0xF5, 0xF2]);
        sb[0x10..0x14].copy_from_slice(&log_block.to_le_bytes());
        sb[0x24..0x2C].copy_from_slice(&blocks.to_le_bytes());
        sb[0x884..].copy_from_slice(&features.to_le_bytes());
        sb
    };
    put(&mut file, 0x400, &f2fs(12, 16384, 0x0008));
    put(&mut file, (64 << 10) + 0x400, &f2fs(12, 256, 0x2008));
    put(&mut file, (128 << 10) + 0x400, &f2fs(16, 3, 0));
    put(&mut file, (192 << 10) + 0x400, &f2fs(9, 100, 0x2000));
    file.sync_all().unwrap();
    let source = RawSource::open(&path).unwrap();
    let size = |start| recorded_size(&source, start, "f2fs").unwrap();

    assert_eq!(size(0), Bytes(16384 * 4096));
    assert_eq!(size(64 << 10), Bytes(256 * 4096));
    // 64 KiB blocks are the largest a page-sized f2fs block gets; 512 bytes
    // is none.
    assert_eq!(size(128 << 10), Bytes(3 << 16));
    assert_eq!(size(192 << 10), Implausible);

    assert!(!f2fs_compression(&source, 0).unwrap());
    assert!(f2fs_compression(&source, 64 << 10).unwrap());
    assert!(!f2fs_compression(&source, 128 << 10).unwrap());
    // A superblock the source ends inside, before its flags, counts as one
    // with the feature.
    assert!(f2fs_compression(&source, (1 << 20) - 0x800).unwrap());
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
fn a_recorded_table_keeps_what_runs_past_the_end_of_the_source() {
    // A 64 MiB disk with p1 from 1 MiB for 16 MiB and p2 from 17 MiB for
    // 32 MiB, copied only up to 24 MiB.
    let dir = tempfile::tempdir().unwrap();
    let (path, file) = mbr_image(&dir, 64 << 20, &[(0x83, 2048, 32768), (0x83, 34816, 65536)]);
    file.set_len(24 << 20).unwrap();
    file.sync_all().unwrap();
    let source = RawSource::open(&path).unwrap();

    let recorded = recorded_table(&source).unwrap();
    assert_eq!(recorded.table, TableKind::Mbr);
    assert_eq!(recorded.disk_end, None);
    assert!(recorded.consistent);
    let ends: Vec<u64> = recorded.partitions.iter().map(Partition::end).collect();
    assert_eq!(ends, vec![17 << 20, 49 << 20]);
    // The layout an examiner reads stops where the source does.
    let layout = read_table(&source).unwrap();
    assert_eq!(layout.partitions.len(), 2);
    assert_eq!(layout.partitions[1].end(), 24 << 20);
    assert_eq!(layout.gaps, vec![(512, 1 << 20)]);

    // Cut before the first partition, the table still lists both, while the
    // layout shows no table, as it always has.
    file.set_len(512 << 10).unwrap();
    file.sync_all().unwrap();
    let source = RawSource::open(&path).unwrap();
    assert_eq!(recorded_table(&source).unwrap().partitions.len(), 2);
    assert_eq!(read_table(&source).unwrap(), no_table());
}

#[test]
fn a_gpt_records_the_disk_it_was_written_for() {
    // A 64 MiB disk whose one partition runs from 1 MiB to its last usable
    // block, copied only up to 10 MiB.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gpt.img");
    let mut file = std::fs::File::create(&path).unwrap();
    file.set_len(64 << 20).unwrap();
    let mut entries = vec![0u8; 128 * 128];
    entries[..128].copy_from_slice(&gpt_entry(2048, 131_038));
    put(&mut file, 512, &gpt_header(34, 131_038, 131_071, &entries));
    put(&mut file, 1024, &entries);
    file.set_len(10 << 20).unwrap();
    file.sync_all().unwrap();
    let source = RawSource::open(&path).unwrap();

    let recorded = recorded_table(&source).unwrap();
    assert_eq!(recorded.table, TableKind::Gpt);
    assert!(recorded.consistent);
    // The backup header is the disk's last block.
    assert_eq!(recorded.disk_end, Some(64 << 20));
    assert_eq!(recorded.partitions[0].end(), 131_039 * 512);
    let layout = read_table(&source).unwrap();
    assert_eq!(layout.partitions[0].end(), 10 << 20);
    assert_eq!(layout.gaps, vec![(34 * 512, 1 << 20)]);
}

#[test]
fn a_gpt_is_consistent_only_while_its_entries_keep_its_rules() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gpt.img");
    let mut file = std::fs::File::create(&path).unwrap();
    file.set_len(16 << 20).unwrap();
    let mut entries = vec![0u8; 128 * 128];
    entries[..128].copy_from_slice(&gpt_entry(2048, 10_239));
    let header = gpt_header(34, 32_734, 32_767, &entries);
    put(&mut file, 512, &header);
    put(&mut file, 1024, &entries);
    file.sync_all().unwrap();
    let consistent = || {
        recorded_table(&RawSource::open(&path).unwrap())
            .unwrap()
            .consistent
    };
    assert!(consistent());

    // Entries written over since no longer match the checksum the header
    // keeps of them.
    put(&mut file, 1024 + 56, b"o\0v\0e\0r\0");
    file.sync_all().unwrap();
    assert!(!consistent());

    // A header whose own checksum fails vouches for no entry checksum...
    let mut broken = header;
    broken[16] ^= 0xFF;
    put(&mut file, 512, &broken);
    file.sync_all().unwrap();
    assert!(consistent());

    // ...but an entry outside the usable blocks, or one that runs backwards,
    // breaks the rules all the same.
    for (first, last) in [(0, 0), (2048, 40_000), (20_000, 19_999)] {
        put(&mut file, 1024 + 128, &gpt_entry(first, last));
        file.sync_all().unwrap();
        assert!(!consistent(), "{first}..{last}");
    }
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
