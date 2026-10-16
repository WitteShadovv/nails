// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A raw disk as the examiner checks read it: the MBR or GPT partition table,
//! the space the table leaves free, and what each region starts with. Every
//! number in a table is whatever the disk says.
//!
//! The input is the start of the disk, a sparse image of at least 1 GiB that
//! reads as zeros past it. The target checks that the layout is read without
//! an error (the image reads fine anywhere), and that it is consistent:
//! partitions in start order, numbered once each, non-empty and on the disk;
//! the free ranges in order, on the disk and outside every partition; at
//! most four partitions in an MBR and 256 in a GPT, none without a table.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_forensics::forensic::layout::{TableKind, read_layout, signature_at};
use nails_fuzz::image::MemImage;
use std::collections::HashSet;
use std::sync::OnceLock;

/// The smallest disk: partitions can start far past the input.
const DISK: u64 = 1 << 30;

static IMAGE: OnceLock<MemImage> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let image = IMAGE.get_or_init(MemImage::new);
    let size = DISK.max(data.len() as u64);
    let source = image.load(size, &[(0, data)]);
    let layout = read_layout(&source).expect("the image reads at any offset");

    match layout.table {
        TableKind::None => assert!(layout.partitions.is_empty() && layout.gaps.is_empty()),
        TableKind::Mbr => assert!(layout.partitions.len() <= 4),
        TableKind::Gpt => assert!(layout.partitions.len() <= 256),
    }
    let mut numbers = HashSet::new();
    let mut previous = 0;
    for partition in &layout.partitions {
        assert!(partition.start >= previous, "{layout:?}");
        previous = partition.start;
        assert!(numbers.insert(partition.number), "{layout:?}");
        let end = partition.start.checked_add(partition.size);
        assert!(
            partition.size > 0 && end.is_some_and(|end| end <= size),
            "{layout:?}"
        );
        signature_at(&source, partition.start).expect("the image reads at any offset");
    }
    let mut cursor = 0;
    for &(from, to) in &layout.gaps {
        assert!(cursor <= from && from < to && to <= size, "{layout:?}");
        cursor = to;
        assert!(
            layout
                .partitions
                .iter()
                .all(|p| to <= p.start || p.start + p.size <= from),
            "{layout:?}"
        );
    }
});
