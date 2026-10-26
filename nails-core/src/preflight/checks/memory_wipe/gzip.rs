// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A gzip reader for the kernel's own copy of its config, `/proc/config.gz`.
//!
//! A kernel built with `CONFIG_IKCONFIG_PROC` (the NixOS and Arch kernels are)
//! serves its build configuration at `/proc/config.gz`, compressed the way its
//! build compresses it: `gzip -n -9`, RFC 1952 framing around RFC 1951 DEFLATE
//! data. No gzip crate is in NAILS's dependency tree, and running the decoy's
//! own `gzip` would stamp that binary's access time, so this is a small decoder
//! after Mark Adler's `puff.c`. It checks the header's CRC when a header carries
//! one and every member's CRC-32 and length, refuses anything malformed rather
//! than guess, and caps what it writes, so no input can make it exhaust memory
//! or loop. The extra field of a header is skipped unread, as zlib skips it.

/// The most bytes a stream may decode to. A kernel config is a few hundred KiB.
const MAX_OUTPUT: usize = 16 << 20;

/// The longest code, in bits, a DEFLATE Huffman code uses.
const MAX_BITS: usize = 15;

/// The most literal/length codes a dynamic block may define.
const MAX_LITERAL_CODES: usize = 286;

/// The literal/length codes of the fixed code.
const FIXED_LITERAL_CODES: usize = 288;

/// The most distance codes a block may define.
const MAX_DISTANCE_CODES: usize = 30;

/// Base lengths of the length symbols 257 to 285.
const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];

/// Extra bits read after each length symbol.
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

/// Base distances of the distance symbols 0 to 29.
const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];

/// Extra bits read after each distance symbol.
const DISTANCE_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// The order a dynamic block lists the lengths of its code-length code in.
const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// gzip header flags (RFC 1952, 2.3.1): a header CRC follows the header.
const FHCRC: u8 = 0x02;
/// An extra field follows the fixed header.
const FEXTRA: u8 = 0x04;
/// A zero-terminated file name follows.
const FNAME: u8 = 0x08;
/// A zero-terminated comment follows.
const FCOMMENT: u8 = 0x10;
/// Flags no gzip version defines, which a reader must refuse.
const FRESERVED: u8 = 0xE0;

/// Why a stream could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Malformed(&'static str);

/// Decode the gzip stream `data`: one member or several, back to back.
pub(super) fn decompress(data: &[u8]) -> Result<Vec<u8>, Malformed> {
    decompress_within(data, MAX_OUTPUT)
}

/// [`decompress`], refusing a stream that decodes to more than `limit` bytes.
fn decompress_within(data: &[u8], limit: usize) -> Result<Vec<u8>, Malformed> {
    let mut out = Output {
        bytes: Vec::new(),
        limit,
        start: 0,
    };
    let mut rest = data;
    loop {
        let after = member(rest, &mut out)?;
        // A member takes at least its header and trailer, so less is left
        // after each one, and the loop ends with the input.
        if after.len() >= rest.len() {
            return Err(Malformed("a member takes none of the input"));
        }
        if after.is_empty() {
            return Ok(out.bytes);
        }
        rest = after;
    }
}

/// What has been decoded so far, and how much may be.
struct Output {
    bytes: Vec<u8>,
    limit: usize,
    /// Where the member being decoded starts in `bytes`. Each member is a
    /// DEFLATE stream of its own, so a back-reference cannot reach into the
    /// member before it.
    start: usize,
}

impl Output {
    /// Refuse `more` bytes that would take the output past its limit.
    fn room(&self, more: usize) -> Result<(), Malformed> {
        if self.bytes.len().saturating_add(more) > self.limit {
            return Err(Malformed("decodes to more than the limit"));
        }
        Ok(())
    }
}

/// Decode the member at the start of `data` onto `out`, and return the bytes
/// that follow it.
fn member<'a>(data: &'a [u8], out: &mut Output) -> Result<&'a [u8], Malformed> {
    let header = data.get(..10).ok_or(Malformed("truncated header"))?;
    if !header.starts_with(&[0x1F, 0x8B]) {
        return Err(Malformed("not a gzip stream"));
    }
    if header[2] != 8 {
        return Err(Malformed("not DEFLATE data"));
    }
    let flags = header[3];
    if flags & FRESERVED != 0 {
        return Err(Malformed("a reserved header flag is set"));
    }
    let mut pos = header.len();
    if flags & FEXTRA != 0 {
        let len = data
            .get(pos..pos.saturating_add(2))
            .ok_or(Malformed("truncated header"))?;
        pos += 2 + usize::from(u16::from_le_bytes([len[0], len[1]]));
    }
    for flag in [FNAME, FCOMMENT] {
        if flags & flag != 0 {
            let end = data
                .get(pos..)
                .and_then(|rest| rest.iter().position(|&byte| byte == 0))
                .ok_or(Malformed("truncated header"))?;
            pos += end + 1;
        }
    }
    if flags & FHCRC != 0 {
        let crc = data
            .get(pos..pos.saturating_add(2))
            .ok_or(Malformed("truncated header"))?;
        // The two low bytes of the CRC-32 of the header up to them.
        if crc32(&data[..pos]).to_le_bytes()[..2] != *crc {
            return Err(Malformed("the header checksum does not match"));
        }
        pos += 2;
    }

    out.start = out.bytes.len();
    let mut input = Bits::new(data.get(pos..).ok_or(Malformed("truncated header"))?);
    inflate(&mut input, out)?;
    let (trailer, rest) = input
        .rest
        .split_first_chunk::<8>()
        .ok_or(Malformed("truncated trailer"))?;
    let crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    let size = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
    let decoded = &out.bytes[out.start..];
    // The trailer keeps the length modulo 2^32, hence the truncating cast.
    if crc != crc32(decoded) || size != decoded.len() as u32 {
        return Err(Malformed("the checksum or length does not match"));
    }
    Ok(rest)
}

/// The input, read bit by bit, each byte from its least significant bit.
struct Bits<'a> {
    /// The bytes not yet loaded. A load takes the first one off, so the
    /// reader only moves forward and every read ends with the input.
    rest: &'a [u8],
    /// Bits loaded and not yet used, the next one lowest.
    buffer: u32,
    /// How many bits `buffer` holds: fewer than 8 between reads.
    count: u32,
}

impl<'a> Bits<'a> {
    fn new(rest: &'a [u8]) -> Self {
        Self {
            rest,
            buffer: 0,
            count: 0,
        }
    }

    /// The next `need` bits (at most 16), the first one read lowest.
    fn take(&mut self, need: u32) -> Result<u32, Malformed> {
        let mut value = self.buffer;
        while self.count < need {
            let (&byte, rest) = self.rest.split_first().ok_or(Malformed("truncated data"))?;
            self.rest = rest;
            value |= u32::from(byte) << self.count;
            self.count += 8;
        }
        self.buffer = value >> need;
        self.count -= need;
        Ok(value & ((1 << need) - 1))
    }

    /// Drop what is left of the current byte, as a stored block starts on a
    /// byte boundary.
    fn align(&mut self) {
        self.buffer = 0;
        self.count = 0;
    }

    /// The next `len` whole bytes, after the ones loaded so far.
    fn bytes(&mut self, len: usize) -> Result<&'a [u8], Malformed> {
        let (bytes, rest) = self
            .rest
            .split_at_checked(len)
            .ok_or(Malformed("truncated data"))?;
        self.rest = rest;
        Ok(bytes)
    }
}

/// A canonical Huffman code, kept as `puff.c` keeps it: how many codes each
/// length has, and the symbols in code order.
struct Huffman {
    /// The number of codes of each length; `count[0]` counts the symbols
    /// without a code.
    count: [u16; MAX_BITS + 1],
    /// The symbols with a code, by length and then by value.
    symbol: Vec<u16>,
}

impl Huffman {
    /// The code for the symbols `0..lengths.len()` with these code lengths,
    /// and whether it is complete (every bit pattern is a code). A code with
    /// no symbols at all counts as complete; nothing decodes with it. Lengths
    /// that ask for more codes than exist are refused.
    fn new(lengths: &[u8]) -> Result<(Self, bool), Malformed> {
        let mut count = [0u16; MAX_BITS + 1];
        for &length in lengths {
            *count
                .get_mut(usize::from(length))
                .ok_or(Malformed("a code length is too long"))? += 1;
        }
        let mut symbol = vec![0u16; lengths.len()];
        if usize::from(count[0]) == lengths.len() {
            return Ok((Self { count, symbol }, true));
        }
        // One code of length zero to begin with; each bit more doubles what is
        // left, and each code of that length takes one.
        let mut left: i64 = 1;
        for &codes in &count[1..] {
            left = (left << 1) - i64::from(codes);
            if left < 0 {
                return Err(Malformed("the code lengths are over-subscribed"));
            }
        }
        // Where each length's symbols start.
        let mut offsets = [0usize; MAX_BITS + 1];
        let mut next = 0;
        for (offset, &codes) in offsets.iter_mut().zip(&count).skip(1) {
            *offset = next;
            next += usize::from(codes);
        }
        for (value, &length) in (0u16..).zip(lengths) {
            if length != 0 {
                let slot = &mut offsets[usize::from(length)];
                symbol[*slot] = value;
                *slot += 1;
            }
        }
        Ok((Self { count, symbol }, left == 0))
    }

    /// Decode one symbol from `input`, a bit at a time.
    fn decode(&self, input: &mut Bits<'_>) -> Result<u16, Malformed> {
        // The code read so far, its first bit highest; the first code of the
        // current length; and where that length's symbols start.
        let (mut code, mut first, mut index) = (0u32, 0u32, 0usize);
        for &codes in &self.count[1..] {
            code |= input.take(1)?;
            let codes = u32::from(codes);
            if code < first + codes {
                let offset = code.checked_sub(first).ok_or(Malformed("invalid code"))?;
                return self
                    .symbol
                    .get(index + offset as usize)
                    .copied()
                    .ok_or(Malformed("invalid code"));
            }
            index += codes as usize;
            first = (first + codes) << 1;
            code <<= 1;
        }
        Err(Malformed("invalid code"))
    }
}

/// Decode the DEFLATE blocks at `input` onto `out`, up to the last one.
fn inflate(input: &mut Bits<'_>, out: &mut Output) -> Result<(), Malformed> {
    loop {
        let last = input.take(1)? == 1;
        match input.take(2)? {
            0 => stored(input, out)?,
            1 => {
                let (literals, distances) = fixed_codes()?;
                codes(input, out, &literals, &distances)?;
            }
            2 => dynamic(input, out)?,
            _ => return Err(Malformed("invalid block type")),
        }
        if last {
            return Ok(());
        }
    }
}

/// Copy a stored block (RFC 1951, 3.2.4).
fn stored(input: &mut Bits<'_>, out: &mut Output) -> Result<(), Malformed> {
    input.align();
    let header = input.bytes(4)?;
    let len = u16::from_le_bytes([header[0], header[1]]);
    if len != !u16::from_le_bytes([header[2], header[3]]) {
        return Err(Malformed(
            "a stored block's length does not match its complement",
        ));
    }
    let bytes = input.bytes(usize::from(len))?;
    out.room(bytes.len())?;
    out.bytes.extend_from_slice(bytes);
    Ok(())
}

/// The codes of a block that uses the fixed code (RFC 1951, 3.2.6).
fn fixed_codes() -> Result<(Huffman, Huffman), Malformed> {
    let mut lengths = [0u8; FIXED_LITERAL_CODES];
    lengths[..144].fill(8);
    lengths[144..256].fill(9);
    lengths[256..280].fill(7);
    lengths[280..].fill(8);
    let (literals, _) = Huffman::new(&lengths)?;
    let (distances, _) = Huffman::new(&[5; MAX_DISTANCE_CODES])?;
    Ok((literals, distances))
}

/// Read a block's own codes, then decode the block (RFC 1951, 3.2.7).
fn dynamic(input: &mut Bits<'_>, out: &mut Output) -> Result<(), Malformed> {
    let literal_count = input.take(5)? as usize + 257;
    let distance_count = input.take(5)? as usize + 1;
    let code_length_count = input.take(4)? as usize + 4;
    if literal_count > MAX_LITERAL_CODES || distance_count > MAX_DISTANCE_CODES {
        return Err(Malformed("a block defines too many codes"));
    }
    let mut code_lengths = [0u8; 19];
    for &at in CODE_LENGTH_ORDER.iter().take(code_length_count) {
        code_lengths[at] = input.take(3)? as u8;
    }
    let (code_length_code, complete) = Huffman::new(&code_lengths)?;
    if !complete {
        return Err(Malformed("the code-length code is incomplete"));
    }

    let total = literal_count + distance_count;
    let mut lengths: Vec<u8> = Vec::with_capacity(total);
    while lengths.len() < total {
        let (length, times) = match code_length_code.decode(input)? {
            symbol @ 0..=15 => (symbol as u8, 1),
            16 => {
                let previous = *lengths
                    .last()
                    .ok_or(Malformed("a repeat with no length before it"))?;
                (previous, 3 + input.take(2)? as usize)
            }
            17 => (0, 3 + input.take(3)? as usize),
            _ => (0, 11 + input.take(7)? as usize),
        };
        if lengths.len() + times > total {
            return Err(Malformed("a block lists too many code lengths"));
        }
        lengths.resize(lengths.len() + times, length);
    }

    let (literal_lengths, distance_lengths) = lengths.split_at(literal_count);
    if literal_lengths[256] == 0 {
        return Err(Malformed("a block has no end-of-block code"));
    }
    let literals = usable(literal_lengths)?;
    let distances = usable(distance_lengths)?;
    codes(input, out, &literals, &distances)
}

/// The code for these lengths, refused when it is incomplete, unless it is the
/// lone one-bit code of a block that uses a single symbol.
fn usable(lengths: &[u8]) -> Result<Huffman, Malformed> {
    let (code, complete) = Huffman::new(lengths)?;
    let lone = usize::from(code.count[0]) + usize::from(code.count[1]) == lengths.len();
    if complete || lone {
        Ok(code)
    } else {
        Err(Malformed("a code is incomplete"))
    }
}

/// Decode a block's literals and back-references with its codes, up to its
/// end-of-block symbol (RFC 1951, 3.2.5).
fn codes(
    input: &mut Bits<'_>,
    out: &mut Output,
    literals: &Huffman,
    distances: &Huffman,
) -> Result<(), Malformed> {
    loop {
        let symbol = literals.decode(input)?;
        match symbol {
            0..=255 => {
                out.room(1)?;
                out.bytes.push(symbol as u8);
            }
            256 => return Ok(()),
            _ => {
                let at = usize::from(symbol - 257);
                let (&base, &extra) = LENGTH_BASE
                    .get(at)
                    .zip(LENGTH_EXTRA.get(at))
                    .ok_or(Malformed("invalid length symbol"))?;
                let length = usize::from(base) + input.take(u32::from(extra))? as usize;
                let at = usize::from(distances.decode(input)?);
                let (&base, &extra) = DISTANCE_BASE
                    .get(at)
                    .zip(DISTANCE_EXTRA.get(at))
                    .ok_or(Malformed("invalid distance symbol"))?;
                let distance = usize::from(base) + input.take(u32::from(extra))? as usize;
                if distance > out.bytes.len() - out.start {
                    return Err(Malformed(
                        "a back-reference reaches before the start of its member",
                    ));
                }
                out.room(length)?;
                // Byte by byte: a reference may overlap what it writes.
                for _ in 0..length {
                    let byte = out.bytes[out.bytes.len() - distance];
                    out.bytes.push(byte);
                }
            }
        }
    }
}

/// The CRC-32 gzip keeps of each member's data (the reflected polynomial
/// `0xEDB88320`).
fn crc32(data: &[u8]) -> u32 {
    !data.iter().fold(!0u32, |crc, &byte| {
        (0..8).fold(crc ^ u32::from(byte), |crc, _| {
            (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg())
        })
    })
}

#[cfg(test)]
mod tests;
