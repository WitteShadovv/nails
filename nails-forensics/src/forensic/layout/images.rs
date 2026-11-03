// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The start of a disk with a GUID partition table, byte for byte as a disk
//! keeps it: for the tests of this crate and of the crates whose checks read
//! a partition table. Compiled for tests and with the `test-support`
//! feature only.

use super::crc32;

/// The 16 bytes a GPT stores for the GUID `text`, written as
/// [`Partition::type_id`](super::Partition::type_id) holds one: its first
/// three fields little-endian, the rest as written.
///
/// # Panics
///
/// On text that is no GUID: this builds test images only.
pub fn guid_bytes(text: &str) -> [u8; 16] {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    assert_eq!(hex.len(), 32, "not a GUID: {text}");
    let mut bytes = [0u8; 16];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16)
            .unwrap_or_else(|_| panic!("not a GUID: {text}"));
    }
    bytes[..4].reverse();
    bytes[4..6].reverse();
    bytes[6..8].reverse();
    bytes
}

/// A GPT entry for a partition from block `first` to block `last`, of a type
/// no table names (sixteen bytes of 0xAF).
pub fn gpt_entry(first: u64, last: u64) -> [u8; 128] {
    let mut entry = [0u8; 128];
    entry[..16].copy_from_slice(&[0xAF; 16]);
    entry[32..40].copy_from_slice(&first.to_le_bytes());
    entry[40..48].copy_from_slice(&last.to_le_bytes());
    entry
}

/// A GPT entry for a partition of the type `type_id` from block `first` to
/// block `last`, with the attribute flags `attributes` and the name `name`
/// (at most 36 UTF-16 code units).
pub fn typed_gpt_entry(
    type_id: &str,
    first: u64,
    last: u64,
    attributes: u64,
    name: &str,
) -> [u8; 128] {
    let mut entry = gpt_entry(first, last);
    entry[..16].copy_from_slice(&guid_bytes(type_id));
    entry[48..56].copy_from_slice(&attributes.to_le_bytes());
    for (index, unit) in name.encode_utf16().take(36).enumerate() {
        entry[56 + 2 * index..58 + 2 * index].copy_from_slice(&unit.to_le_bytes());
    }
    entry
}

/// A GPT header for block 1 of a 512-byte-block disk, keeping both
/// checksums: its entry array is `entries` from block 2, its usable blocks
/// run from `first_usable` to `last_usable`, and its backup header lies at
/// block `backup`.
pub fn gpt_header(first_usable: u64, last_usable: u64, backup: u64, entries: &[u8]) -> [u8; 92] {
    let count = u32::try_from(entries.len() / 128).unwrap_or(u32::MAX);
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

/// The first 34 blocks of a disk of `blocks` 512-byte blocks with a GPT: a
/// protective MBR, the header in block 1 and an array of 128 entries from
/// block 2, holding `entries` in order. Written to the start of a sparse
/// file of the disk's size, they read as a disk does; its backup header,
/// in the last block, is left out.
pub fn gpt_disk(blocks: u64, entries: &[[u8; 128]]) -> Vec<u8> {
    let mut array = vec![0u8; 128 * 128];
    for (slot, entry) in array.as_chunks_mut::<128>().0.iter_mut().zip(entries) {
        *slot = *entry;
    }
    let mut disk = vec![0u8; 34 * 512];
    // The protective MBR: one entry of type 0xEE over the whole disk.
    disk[446 + 4] = 0xEE;
    disk[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    let covered = u32::try_from(blocks - 1).unwrap_or(u32::MAX);
    disk[446 + 12..446 + 16].copy_from_slice(&covered.to_le_bytes());
    disk[510] = 0x55;
    disk[511] = 0xAA;
    let header = gpt_header(34, blocks - 34, blocks - 1, &array);
    disk[512..512 + header.len()].copy_from_slice(&header);
    disk[1024..1024 + array.len()].copy_from_slice(&array);
    disk
}
