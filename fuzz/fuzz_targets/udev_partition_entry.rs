// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The partition entry in udev's record of a partition
//! (`/run/udev/data/b<major>:<minor>`), which the partition-type check reads
//! when it cannot read the disk's table itself: the kind of table, the type,
//! the attribute flags, the number and the start libblkid read.
//!
//! The input is a record. The target checks that:
//!
//! - reading it never panics, and an entry it finds has the record's first
//!   scheme and type, neither empty;
//! - the flags are 0 where the record has none, as libblkid writes them only
//!   when one is set, and else the number its first `0x` value spells;
//! - an entry written in front of the record as udev writes one, from
//!   numbers the input chooses, reads back unchanged, whatever the rest of
//!   the record says.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_base::filesystem::udev::{PartitionEntry, partition_entry, property};

fuzz_target!(|data: &[u8]| {
    let record = String::from_utf8_lossy(data);
    let value = |key: &str| {
        property(&record, key)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    };
    let entry = partition_entry(&record);
    match (value("ID_PART_ENTRY_SCHEME"), value("ID_PART_ENTRY_TYPE")) {
        (Some(scheme), Some(type_id)) => {
            let entry = entry.as_ref().expect("a scheme and a type make an entry");
            assert_eq!(
                (entry.scheme.as_str(), entry.type_id.as_str()),
                (scheme, type_id)
            );
            let flags = value("ID_PART_ENTRY_FLAGS").map_or(Some(0), |text| {
                text.strip_prefix("0x")
                    .or_else(|| text.strip_prefix("0X"))
                    .and_then(|hex| u64::from_str_radix(hex, 16).ok())
            });
            assert_eq!(entry.flags, flags, "{record:?}");
        }
        _ => assert_eq!(entry, None, "{record:?}"),
    }

    let mut numbers = [0u8; 20];
    for (slot, byte) in numbers.iter_mut().zip(data) {
        *slot = *byte;
    }
    let flags = u64::from_le_bytes(numbers[..8].try_into().unwrap_or_default());
    let offset = u64::from_le_bytes(numbers[8..16].try_into().unwrap_or_default());
    let number = u32::from_le_bytes(numbers[16..].try_into().unwrap_or_default());
    let written = format!(
        "E:ID_PART_ENTRY_SCHEME=gpt\n\
         E:ID_PART_ENTRY_TYPE=3b8f8425-20e0-4f3b-907f-1a25a76f98e8\n\
         E:ID_PART_ENTRY_FLAGS=0x{flags:x}\n\
         E:ID_PART_ENTRY_NUMBER={number}\n\
         E:ID_PART_ENTRY_OFFSET={offset}\n{record}"
    );
    assert_eq!(
        partition_entry(&written),
        Some(PartitionEntry {
            scheme: "gpt".into(),
            type_id: "3b8f8425-20e0-4f3b-907f-1a25a76f98e8".into(),
            flags: Some(flags),
            number: Some(number),
            offset: Some(offset),
        }),
        "{written:?}"
    );
});
