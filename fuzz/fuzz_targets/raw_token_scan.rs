// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The raw-device search for the rehearsal canary: a token looked for in
//! ASCII and UTF-16LE through a whole disk, read in windows that carry a
//! tail into the next one, skipping the holes of a sparse image. The disk's
//! content is anyone's.
//!
//! The input is the token's length and its characters (mapped to the hex
//! digits of a canary), the window and the cap on hits, then the image:
//! every `HOLE` in it starts a new chunk of data, and each chunk ends on a
//! page boundary with a hole before and after it. The target checks that the
//! windowed scan of the sparse image reports exactly the hits a scan of the
//! same bytes in one buffer reports, and accounts for every byte as read or
//! skipped.
//!
//! memmem reports occurrences that do not overlap, so for a token that can
//! overlap itself (`abcab`) which of two overlapping occurrences is reported
//! depends on where a window starts; for such a token only whether anything
//! is found has to agree.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_forensics::forensic::TokenScan;
use nails_forensics::forensic::scan::utf16le;
use nails_fuzz::image::{MemImage, PAGE};
use std::sync::OnceLock;

/// The most chunks an image has; later `HOLE`s are data.
const CHUNKS: usize = 32;

static IMAGE: OnceLock<MemImage> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let Some((&length, rest)) = data.split_first() else {
        return;
    };
    let length = 16 + usize::from(length) % 49;
    if rest.len() < length + 2 {
        return;
    }
    let (token, rest) = rest.split_at(length);
    let token: String = token
        .iter()
        .map(|b| char::from(b"0123456789abcdef"[usize::from(b % 16)]))
        .collect();
    let (window, max_hits, image) = (rest[0], rest[1], &rest[2..]);

    let chunks = layout(image);
    let size = chunks
        .last()
        .map_or(0, |(at, bytes)| at + bytes.len() as u64)
        + PAGE;
    let mut whole = vec![0u8; usize::try_from(size).expect("a small image")];
    for (at, bytes) in &chunks {
        let at = usize::try_from(*at).expect("a small image");
        whole[at..at + bytes.len()].copy_from_slice(bytes);
    }
    let source = IMAGE.get_or_init(MemImage::new).load(size, &chunks);

    let scan = TokenScan::new(&token)
        .window(4 * token.len() + usize::from(window))
        .max_hits(1 + usize::from(max_hits % 64));
    let outcome = scan.scan(&source).expect("the image reads at any offset");
    let expected = scan.scan_bytes(&whole);
    if overlaps_itself(token.as_bytes()) || overlaps_itself(&utf16le(&token)) {
        assert_eq!(
            outcome.hits.is_empty(),
            expected.is_empty(),
            "token {token}"
        );
    } else {
        assert_eq!(outcome.hits, expected, "token {token}");
    }
    assert_eq!(outcome.bytes_scanned + outcome.bytes_skipped, size);
    assert!(!outcome.limit_reached);
});

/// Each chunk of `image` (split at `HOLE`) and where it lies: ending on a
/// page boundary, after at least one page of hole.
fn layout(image: &[u8]) -> Vec<(u64, &[u8])> {
    let mut chunks = Vec::new();
    let mut rest = image;
    let mut page = 0u64;
    while !rest.is_empty() {
        let len = if chunks.len() + 1 < CHUNKS {
            rest.windows(4)
                .position(|w| w == b"HOLE")
                .unwrap_or(rest.len())
        } else {
            rest.len()
        };
        let chunk = &rest[..len];
        rest = &rest[(len + 4).min(rest.len())..];
        page += 1 + (chunk.len() as u64).div_ceil(PAGE).max(1);
        chunks.push((page * PAGE - chunk.len() as u64, chunk));
    }
    chunks
}

/// Whether `needle` can overlap itself: a proper prefix is also a suffix.
fn overlaps_itself(needle: &[u8]) -> bool {
    (1..needle.len()).any(|k| needle[k..] == needle[..needle.len() - k])
}
