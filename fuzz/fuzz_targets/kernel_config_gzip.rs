// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The gzip reader of the kernel's own config, `/proc/config.gz`, which the
//! memory-wipe check decodes itself instead of running the decoy's `gzip`.
//!
//! The input is a gzip stream. Whether it decodes or not, a member before it
//! adds that member's text and changes nothing else, so no back-reference
//! reaches out of its own member. When it decodes, the text stays within the
//! limit, decodes the same within the reader's own limit and with the limit at
//! its exact length, and is refused one byte below it; the stream cut short by
//! a byte, or followed by one more, is refused; a member after it adds that
//! member's text; and the text written again in stored blocks decodes the
//! same. The input is also the text of a stream the target writes itself, two
//! members of fixed-Huffman blocks with back-references and stored blocks,
//! which must decode back to the input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_core::preflight::checks::memory_wipe::gzip::{decompress, decompress_within};

/// The limit the target decodes within: four times the text of the larger
/// kernel config seed, and small enough that a stream which would decode to
/// megabytes costs little.
const LIMIT: usize = 1 << 18;

/// A whole member holding `stored\n` in a stored block (zlib, level 0).
const STORED: &[u8] = &[
    0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x03, 0x01, 0x07, 0x00, 0xF8, 0xFF, 0x73,
    0x74, 0x6F, 0x72, 0x65, 0x64, 0x0A, 0xE2, 0x9C, 0x53, 0xA5, 0x07, 0x00, 0x00, 0x00,
];

/// What [`STORED`] decodes to.
const STORED_TEXT: &[u8] = b"stored\n";

/// The text of each block the target writes, at most.
const BLOCK: usize = 1000;

/// Base lengths of the length symbols 257 to 285 (RFC 1951, 3.2.5).
const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];

/// Extra bits after each length symbol.
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// Base distances of the distance symbols 0 to 29.
const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];

/// Extra bits after each distance symbol.
const DISTANCE_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

fuzz_target!(|data: &[u8]| {
    let decoded = decompress_within(data, LIMIT);

    if !data.is_empty() {
        assert_eq!(
            decompress_within(&[STORED, data].concat(), STORED_TEXT.len() + LIMIT),
            decoded
                .clone()
                .map(|text| [STORED_TEXT, text.as_slice()].concat())
        );
    }

    if let Ok(text) = &decoded {
        assert!(text.len() <= LIMIT);
        assert_eq!(decompress(data).as_ref(), Ok(text));
        assert_eq!(decompress_within(data, text.len()).as_ref(), Ok(text));
        if let Some(less) = text.len().checked_sub(1) {
            assert!(decompress_within(data, less).is_err());
        }
        assert!(decompress_within(&data[..data.len() - 1], LIMIT).is_err());
        assert!(decompress_within(&[data, &[0]].concat(), LIMIT).is_err());
        assert_eq!(
            decompress_within(&[data, STORED].concat(), LIMIT + STORED_TEXT.len()),
            Ok([text.as_slice(), STORED_TEXT].concat())
        );
        assert_eq!(
            decompress_within(&stored_member(text), LIMIT).as_ref(),
            Ok(text)
        );
    }

    assert_eq!(decompress(&compressed(data)).as_deref(), Ok(data));
});

/// `text` as one member of stored blocks, as zlib writes it at level 0.
fn stored_member(text: &[u8]) -> Vec<u8> {
    let mut stream = header(false);
    let mut deflate = Writer::default();
    let mut chunks = text.chunks(usize::from(u16::MAX)).peekable();
    if chunks.peek().is_none() {
        stored_block(&mut deflate, &[], true);
    }
    while let Some(chunk) = chunks.next() {
        stored_block(&mut deflate, chunk, chunks.peek().is_none());
    }
    stream.extend_from_slice(&deflate.bytes);
    stream.extend_from_slice(&trailer(text));
    stream
}

/// `text` as two members, its first half and its second, the second behind a
/// header with every optional field.
fn compressed(text: &[u8]) -> Vec<u8> {
    let (first, second) = text.split_at(text.len() / 2);
    [member(first, false), member(second, true)].concat()
}

/// `text` as one member: blocks of at most [`BLOCK`] bytes, every third of
/// them stored and the others fixed-Huffman blocks, whose back-references
/// reach into the blocks before but never out of the member.
fn member(text: &[u8], flagged: bool) -> Vec<u8> {
    let mut deflate = Writer::default();
    let mut matches = Matches::new(text);
    let mut from = 0;
    for block in 0.. {
        let to = (from + BLOCK).min(text.len());
        let last = to == text.len();
        if block % 3 == 2 {
            stored_block(&mut deflate, &text[from..to], last);
            (from..to).for_each(|at| matches.written(at));
        } else {
            fixed_block(&mut deflate, &mut matches, from, to, last);
        }
        if last {
            break;
        }
        from = to;
    }
    [header(flagged), deflate.bytes, trailer(text)].concat()
}

/// A member's header (RFC 1952, 2.3): a bare one, or one with a text flag, an
/// extra field holding one empty subfield, a name, a comment and the header's
/// CRC.
fn header(flagged: bool) -> Vec<u8> {
    if !flagged {
        return vec![0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];
    }
    let mut header = vec![0x1F, 0x8B, 0x08, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03];
    header.extend_from_slice(&[0x04, 0x00, b'A', b'B', 0x00, 0x00]);
    header.extend_from_slice(b"config\0kernel config\0");
    let crc = crc32(&header);
    header.extend_from_slice(&crc.to_le_bytes()[..2]);
    header
}

/// A member's trailer: the CRC-32 of its text and the text's length, modulo
/// 2^32.
fn trailer(text: &[u8]) -> Vec<u8> {
    let length = text.len() as u32;
    [crc32(text).to_le_bytes(), length.to_le_bytes()].concat()
}

/// A stored block of `text` (RFC 1951, 3.2.4), the member's last when `last`.
fn stored_block(out: &mut Writer, text: &[u8], last: bool) {
    out.bits(u32::from(last), 1);
    out.bits(0, 2);
    out.align();
    let length = u16::try_from(text.len()).expect("a stored block holds at most 65535 bytes");
    out.bytes.extend_from_slice(&length.to_le_bytes());
    out.bytes.extend_from_slice(&(!length).to_le_bytes());
    out.bytes.extend_from_slice(text);
}

/// The member's text from `from` to `to` as a fixed-Huffman block (RFC 1951,
/// 3.2.6), the member's last when `last`: the longest copy of what the member
/// has written so far where there is one, else a literal.
fn fixed_block(out: &mut Writer, matches: &mut Matches<'_>, from: usize, to: usize, last: bool) {
    out.bits(u32::from(last), 1);
    out.bits(1, 2);
    let mut at = from;
    while at < to {
        if let Some((length, distance)) = matches.longest(at, to) {
            let (symbol, extra, bits) = symbol_for(&LENGTH_BASE, &LENGTH_EXTRA, length);
            literal_or_length(out, 257 + symbol);
            out.bits(extra, bits);
            let (symbol, extra, bits) = symbol_for(&DISTANCE_BASE, &DISTANCE_EXTRA, distance);
            out.code(symbol, 5);
            out.bits(extra, bits);
            (at..at + length).for_each(|copied| matches.written(copied));
            at += length;
        } else {
            literal_or_length(out, u32::from(matches.text[at]));
            matches.written(at);
            at += 1;
        }
    }
    literal_or_length(out, 256);
}

/// A literal/length symbol in the fixed code.
fn literal_or_length(out: &mut Writer, symbol: u32) {
    match symbol {
        0..=143 => out.code(0x30 + symbol, 8),
        144..=255 => out.code(0x190 + symbol - 144, 9),
        256..=279 => out.code(symbol - 256, 7),
        _ => out.code(0xC0 + symbol - 280, 8),
    }
}

/// The symbol of `value` in a table of base values and their extra bits, with
/// the extra bits' value and count.
fn symbol_for(base: &[u16], extra: &[u8], value: usize) -> (u32, u32, u32) {
    let symbol = base
        .iter()
        .rposition(|&start| usize::from(start) <= value)
        .expect("every length and distance has a symbol");
    let more = value - usize::from(base[symbol]);
    (symbol as u32, more as u32, u32::from(extra[symbol]))
}

/// The bits of the hash that chains the starts of equal three bytes.
const HASH_BITS: u32 = 15;

/// Where the three bytes at each position of a member's text start again
/// among the bytes written so far, chained by a hash of the three bytes as
/// zlib chains them. Positions are kept plus one, so zero ends a chain.
struct Matches<'a> {
    text: &'a [u8],
    /// The latest start of each hash.
    head: Vec<u32>,
    /// The start before each start that has the same hash.
    previous: Vec<u32>,
}

impl<'a> Matches<'a> {
    fn new(text: &'a [u8]) -> Self {
        Self {
            text,
            head: vec![0; 1 << HASH_BITS],
            previous: vec![0; text.len()],
        }
    }

    /// The hash of the three bytes at `at`, when there are three.
    fn hash(&self, at: usize) -> Option<usize> {
        let &[a, b, c] = self.text.get(at..at + 3)? else {
            return None;
        };
        let hash = (usize::from(a) << 10) ^ (usize::from(b) << 5) ^ usize::from(c);
        Some(hash & ((1 << HASH_BITS) - 1))
    }

    /// Note that the text at `at` is written.
    fn written(&mut self, at: usize) {
        if let Some(hash) = self.hash(at) {
            self.previous[at] = self.head[hash];
            self.head[hash] = u32::try_from(at + 1).expect("a fuzz input is far below 4 GiB");
        }
    }

    /// The longest copy of the text at `at`, up to `end`, from what is
    /// written, as `(length, distance)`: 3 to 258 bytes from at most 32768
    /// back, among the 16 nearest starts with the same hash. The copy may
    /// overlap what it writes.
    fn longest(&self, at: usize, end: usize) -> Option<(usize, usize)> {
        let mut next = self.head[self.hash(at)?];
        let mut best: Option<(usize, usize)> = None;
        for _ in 0..16 {
            let Some(start) = (next as usize).checked_sub(1) else {
                break;
            };
            let distance = at - start;
            if distance > 32768 {
                break;
            }
            let length = (0..(end - at).min(258))
                .take_while(|&offset| self.text[start + offset] == self.text[at + offset])
                .count();
            if length >= 3 && best.is_none_or(|(longest, _)| length > longest) {
                best = Some((length, distance));
            }
            next = self.previous[start];
        }
        best
    }
}

/// DEFLATE data written bit by bit, each byte from its least significant bit.
#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
    /// How many bits of the last byte are written, 0 when it is full.
    used: u32,
}

impl Writer {
    /// The low `count` bits of `value`, the lowest first, as a block header
    /// and extra bits are written.
    fn bits(&mut self, value: u32, count: u32) {
        for bit in 0..count {
            if self.used == 0 {
                self.bytes.push(0);
            }
            let last = self.bytes.last_mut().expect("a byte was pushed");
            *last |= u8::from((value >> bit) & 1 == 1) << self.used;
            self.used = (self.used + 1) % 8;
        }
    }

    /// A Huffman code of `length` bits, its highest bit first.
    fn code(&mut self, code: u32, length: u32) {
        for bit in (0..length).rev() {
            self.bits(code >> bit, 1);
        }
    }

    /// Leave the rest of the last byte zero, as a stored block starts on a
    /// byte boundary.
    fn align(&mut self) {
        self.used = 0;
    }
}

/// The CRC-32 gzip keeps of a member's text and of its header (RFC 1952, 8),
/// bit by bit.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}
