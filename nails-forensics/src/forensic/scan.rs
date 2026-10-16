// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Byte-level token search over a raw device or image.
//!
//! The scan reads the source in bounded windows (a fixed buffer, whatever the
//! device size), carries the tail of each window into the next so a token
//! straddling a boundary is still found, and looks for every token both as
//! ASCII and as UTF-16LE, the encoding Windows-format and many desktop files
//! use. It reads allocated and unallocated space alike: it has no idea of a
//! filesystem, which is the point.

use super::raw::RawSource;
use memchr::memmem;
use serde::Serialize;
use std::io;

/// Default read window: large enough for throughput, small enough to bound
/// memory on any machine.
pub const DEFAULT_WINDOW: usize = 8 << 20;

/// Default cap on recorded hits per token and encoding.
pub const DEFAULT_MAX_HITS: usize = 32;

/// How a token was encoded where it was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Encoding {
    /// One byte per character.
    Ascii,
    /// Two bytes per character, little-endian.
    Utf16Le,
}

/// One occurrence of a token on the source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hit {
    /// Byte offset of the first byte of the match.
    pub offset: u64,
    /// The encoding that matched.
    pub encoding: Encoding,
}

/// The result of scanning one source.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ScanOutcome {
    /// Occurrences found, in offset order.
    pub hits: Vec<Hit>,
    /// Bytes actually read.
    pub bytes_scanned: u64,
    /// Bytes skipped as holes of a sparse image (they read as zeros).
    pub bytes_skipped: u64,
    /// Whether some hits were not recorded because of the per-encoding cap.
    pub hits_capped: bool,
    /// Whether the scan stopped at its byte limit before the end.
    pub limit_reached: bool,
}

/// A token search over raw bytes.
#[derive(Debug, Clone)]
pub struct TokenScan {
    needles: Vec<(Encoding, Vec<u8>)>,
    window: usize,
    max_hits: usize,
    limit: Option<u64>,
}

/// The UTF-16LE bytes of an ASCII token.
pub fn utf16le(token: &str) -> Vec<u8> {
    token.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

impl TokenScan {
    /// A scan for `token` in ASCII and UTF-16LE.
    ///
    /// # Panics
    ///
    /// Panics on an empty token, which would match everywhere.
    pub fn new(token: &str) -> Self {
        assert!(!token.is_empty(), "an empty token matches everything");
        Self {
            needles: vec![
                (Encoding::Ascii, token.as_bytes().to_vec()),
                (Encoding::Utf16Le, utf16le(token)),
            ],
            window: DEFAULT_WINDOW,
            max_hits: DEFAULT_MAX_HITS,
            limit: None,
        }
    }

    /// Read in windows of `bytes` (at least twice the longest needle).
    #[must_use]
    pub fn window(mut self, bytes: usize) -> Self {
        let longest = self.longest();
        self.window = bytes.max(2 * longest);
        self
    }

    /// Record at most `hits` occurrences per encoding.
    #[must_use]
    pub fn max_hits(mut self, hits: usize) -> Self {
        self.max_hits = hits.max(1);
        self
    }

    /// Stop after reading `bytes` bytes.
    #[must_use]
    pub fn limit(mut self, bytes: Option<u64>) -> Self {
        self.limit = bytes;
        self
    }

    fn longest(&self) -> usize {
        self.needles.iter().map(|(_, n)| n.len()).max().unwrap_or(1)
    }

    /// Scan an in-memory buffer as if it were a source at offset 0. Lets the
    /// caller prove the matcher finds both encodings before trusting a clean
    /// device scan.
    pub fn scan_bytes(&self, bytes: &[u8]) -> Vec<Hit> {
        let mut counts = vec![0usize; self.needles.len()];
        let mut hits = Vec::new();
        let mut capped = false;
        self.search(bytes, 0, 0, &mut counts, &mut hits, &mut capped);
        hits.sort_by_key(|hit| (hit.offset, hit.encoding));
        hits
    }

    /// Scan every data extent of `source`, each with the bytes of the holes
    /// next to it that a token reaching into them would cover.
    ///
    /// # Errors
    ///
    /// Propagates a read error; the caller reports the source as not scanned.
    pub fn scan(&self, source: &RawSource) -> io::Result<ScanOutcome> {
        let carry_len = self.longest() - 1;
        let mut buffer = vec![0u8; self.window + carry_len];
        let mut counts = vec![0usize; self.needles.len()];
        let mut outcome = ScanOutcome::default();
        let extents = widened(source.data_extents(), carry_len as u64, source.size());
        let covered: u64 = extents.iter().map(|(start, end)| end - start).sum();
        outcome.bytes_skipped = source.size().saturating_sub(covered);

        'extents: for (start, end) in extents {
            let mut position = start;
            let mut carried = 0usize;
            while position < end {
                let mut want = (end - position).min(self.window as u64) as usize;
                if let Some(limit) = self.limit {
                    let left = limit.saturating_sub(outcome.bytes_scanned);
                    if left == 0 {
                        outcome.limit_reached = true;
                        break 'extents;
                    }
                    want = want.min(left as usize);
                }
                let read = source.read_at(&mut buffer[carried..carried + want], position)?;
                if read == 0 {
                    break;
                }
                let filled = carried + read;
                let base = position - carried as u64;
                self.search(
                    &buffer[..filled],
                    base,
                    carried,
                    &mut counts,
                    &mut outcome.hits,
                    &mut outcome.hits_capped,
                );
                outcome.bytes_scanned += read as u64;
                position += read as u64;
                // Keep the tail so a token across the boundary is seen whole.
                let keep = carry_len.min(filled);
                buffer.copy_within(filled - keep..filled, 0);
                carried = keep;
            }
        }
        outcome.hits.sort_by_key(|hit| (hit.offset, hit.encoding));
        Ok(outcome)
    }

    /// Record the matches in `window` (which starts at source offset `base`)
    /// that end past the first `carried` bytes: a match wholly inside the
    /// carried tail was already found in the previous window.
    fn search(
        &self,
        window: &[u8],
        base: u64,
        carried: usize,
        counts: &mut [usize],
        hits: &mut Vec<Hit>,
        capped: &mut bool,
    ) {
        for (index, (encoding, needle)) in self.needles.iter().enumerate() {
            for found in memmem::find_iter(window, needle) {
                if found + needle.len() <= carried {
                    continue;
                }
                if counts[index] >= self.max_hits {
                    *capped = true;
                    break;
                }
                counts[index] += 1;
                hits.push(Hit {
                    offset: base + found as u64,
                    encoding: *encoding,
                });
            }
        }
    }
}

/// `extents` (in order) widened by `reach` bytes into the holes on either
/// side, within `size`, and merged where they come to touch. A hole reads as
/// zeros, so it holds no token, but a token can end in one: the last byte of
/// a UTF-16LE token is the zero high byte of its last character, which a
/// hole holds when the data before it ends one byte short.
fn widened(extents: Vec<(u64, u64)>, reach: u64, size: u64) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::with_capacity(extents.len());
    for (start, end) in extents {
        let start = start.saturating_sub(reach);
        let end = end.saturating_add(reach).min(size);
        match out.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    const TOKEN: &str = "k7q2v9x4m1p8w3z6";

    fn image(dir: &tempfile::TempDir, size: u64, writes: &[(u64, &[u8])]) -> RawSource {
        let path = dir.path().join("disk.img");
        let mut file = std::fs::File::create(&path).unwrap();
        file.set_len(size).unwrap();
        for (offset, bytes) in writes {
            file.seek(SeekFrom::Start(*offset)).unwrap();
            file.write_all(bytes).unwrap();
        }
        file.sync_all().unwrap();
        RawSource::open(&path).unwrap()
    }

    #[test]
    fn finds_ascii_and_utf16le_tokens_with_their_offsets() {
        let dir = tempfile::tempdir().unwrap();
        let wide = utf16le(TOKEN);
        let source = image(
            &dir,
            1 << 20,
            &[(4096, TOKEN.as_bytes()), (700_001, wide.as_slice())],
        );

        let outcome = TokenScan::new(TOKEN).scan(&source).unwrap();

        assert_eq!(
            outcome.hits,
            vec![
                Hit {
                    offset: 4096,
                    encoding: Encoding::Ascii
                },
                Hit {
                    offset: 700_001,
                    encoding: Encoding::Utf16Le
                },
            ]
        );
    }

    #[test]
    fn a_token_across_a_window_boundary_is_found_once() {
        let dir = tempfile::tempdir().unwrap();
        // Straddle the first window boundary (window = 64 bytes here).
        let source = image(&dir, 4096, &[(60, TOKEN.as_bytes())]);

        let outcome = TokenScan::new(TOKEN).window(64).scan(&source).unwrap();

        assert_eq!(outcome.hits.len(), 1, "{:?}", outcome.hits);
        assert_eq!(outcome.hits[0].offset, 60);
    }

    #[test]
    fn a_clean_image_has_no_hits_and_reports_what_it_read() {
        let dir = tempfile::tempdir().unwrap();
        let source = image(&dir, 1 << 20, &[(0, b"unrelated bytes")]);

        let outcome = TokenScan::new(TOKEN).scan(&source).unwrap();

        assert!(outcome.hits.is_empty());
        assert!(outcome.bytes_scanned > 0);
        assert_eq!(outcome.bytes_scanned + outcome.bytes_skipped, 1 << 20);
    }

    #[test]
    fn a_token_in_a_sparse_image_tail_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let size = 256u64 << 20;
        let source = image(&dir, size, &[(size - 4096, TOKEN.as_bytes())]);

        let outcome = TokenScan::new(TOKEN).scan(&source).unwrap();

        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].offset, size - 4096);
    }

    /// A UTF-16LE token whose last byte, the zero high byte of its last
    /// character, lies in the hole after a data block. Found by the
    /// `raw_token_scan` fuzz target: the scan read the block only, so it
    /// missed a token a scan of the whole image finds.
    #[test]
    fn a_utf16_token_ending_in_a_hole_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let wide = utf16le(TOKEN);
        let short = &wide[..wide.len() - 1];
        let at = 8192 - short.len() as u64;
        let source = image(&dir, 64 << 10, &[(at, short)]);

        let outcome = TokenScan::new(TOKEN).window(64).scan(&source).unwrap();

        assert_eq!(
            outcome.hits,
            vec![Hit {
                offset: at,
                encoding: Encoding::Utf16Le
            }]
        );
        assert_eq!(outcome.bytes_scanned + outcome.bytes_skipped, 64 << 10);
    }

    #[test]
    fn extents_widen_into_their_holes_and_merge() {
        assert_eq!(widened(vec![], 31, 100), vec![]);
        assert_eq!(
            widened(vec![(0, 10), (50, 60), (70, 100)], 5, 100),
            vec![(0, 15), (45, 100)]
        );
        assert_eq!(widened(vec![(10, 20)], 31, 25), vec![(0, 25)]);
    }

    #[test]
    fn hits_are_capped_per_encoding() {
        let dir = tempfile::tempdir().unwrap();
        let repeated = TOKEN.repeat(10);
        let source = image(&dir, 8192, &[(0, repeated.as_bytes())]);

        let outcome = TokenScan::new(TOKEN).max_hits(3).scan(&source).unwrap();

        assert_eq!(outcome.hits.len(), 3);
        assert!(outcome.hits_capped);
    }

    #[test]
    fn the_byte_limit_bounds_the_scan() {
        let dir = tempfile::tempdir().unwrap();
        // A dense image, so the limit counts real data from the start.
        let filler = vec![b'.'; 1 << 20];
        let source = image(&dir, 1 << 20, &[(0, &filler), (900_000, TOKEN.as_bytes())]);

        let outcome = TokenScan::new(TOKEN)
            .window(4096)
            .limit(Some(8192))
            .scan(&source)
            .unwrap();

        assert!(outcome.hits.is_empty());
        assert!(outcome.limit_reached);
        assert!(outcome.bytes_scanned <= 8192);
    }

    #[test]
    fn scan_bytes_proves_both_encodings_match() {
        let mut buffer = TOKEN.as_bytes().to_vec();
        buffer.extend(utf16le(TOKEN));
        let hits = TokenScan::new(TOKEN).scan_bytes(&buffer);
        let encodings: Vec<Encoding> = hits.iter().map(|hit| hit.encoding).collect();
        assert_eq!(encodings, vec![Encoding::Ascii, Encoding::Utf16Le]);
    }
}
