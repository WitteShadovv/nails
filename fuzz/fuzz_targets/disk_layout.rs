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
//!
//! At the start of the disk and of each partition it also reads what a
//! rehearsal scan classifies a region by: its signature, the magic of a
//! filesystem that can compress, whether an f2fs was made with compression,
//! whether an ext4 or f2fs has the encrypt feature (or the image ends before
//! its flags, as a partition in its last sector does), and the size an ext4,
//! xfs or f2fs superblock, a FAT, NTFS or exFAT boot sector or a swap header
//! records. None of them may fail on an image that reads fine anywhere, and
//! each answers within its range.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_forensics::forensic::RawSource;
use nails_forensics::forensic::layout::{
    RecordedSize, Signature, TableKind, compressing_format_at, encryption_feature,
    f2fs_compression, read_layout, recorded_size, signature_at,
};
use nails_fuzz::image::MemImage;
use std::collections::HashSet;
use std::sync::OnceLock;

/// The smallest disk: partitions can start far past the input.
const DISK: u64 = 1 << 30;

/// The filesystems that can store file contents compressed.
const COMPRESSING: &[&str] = &["btrfs", "f2fs", "bcachefs"];

/// The formats whose superblock, boot sector or header records the bytes the
/// filesystem spans.
const SIZED: &[&str] = &["ext2/3/4", "xfs", "f2fs", "vfat", "ntfs", "exfat", "swap"];

/// The formats whose superblock can carry the encrypt feature.
const ENCRYPTING: &[&str] = &["ext2/3/4", "f2fs"];

static IMAGE: OnceLock<MemImage> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let image = IMAGE.get_or_init(MemImage::new);
    let size = DISK.max(data.len() as u64);
    let source = image.load(size, &[(0, data)]);
    let layout = read_layout(&source).expect("the image reads at any offset");
    classify(&source, 0);

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
        classify(&source, partition.start);
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

/// Read the region of `source` at `start` as a rehearsal scan classifies it.
fn classify(source: &RawSource, start: u64) {
    let signature = signature_at(source, start).expect("the image reads at any offset");
    let compressing = compressing_format_at(source, start).expect("the image reads at any offset");
    assert!(
        compressing.is_none_or(|fstype| COMPRESSING.contains(&fstype)),
        "{compressing:?}"
    );
    f2fs_compression(source, start).expect("the image reads at any offset");

    let mut formats = SIZED.to_vec();
    formats.extend(compressing);
    if let Signature::Format(fstype) = signature {
        formats.push(fstype);
    }
    for fstype in formats {
        let recorded = recorded_size(source, start, fstype).expect("the image reads at any offset");
        assert_eq!(
            recorded == RecordedSize::Unrecorded,
            !SIZED.contains(&fstype),
            "{fstype}: {recorded:?}"
        );
        // Only an ext4 or f2fs can have the encrypt feature, and only their
        // flags can lie past the end of the image.
        let encrypting =
            encryption_feature(source, start, fstype).expect("the image reads at any offset");
        assert!(
            encrypting == Some(false) || ENCRYPTING.contains(&fstype),
            "{fstype}: {encrypting:?}"
        );
    }
}
