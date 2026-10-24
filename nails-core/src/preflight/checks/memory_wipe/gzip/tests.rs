// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

/// A kernel config compressed the way a kernel build compresses its own copy
/// for `/proc/config.gz`: `gzip -n -9` (GNU gzip 1.14), whose output is one
/// member of dynamic-Huffman blocks. The text is 10664 bytes in 413 lines,
/// laid out as Kconfig writes a `.config`.
const CONFIG_GZ: &[u8] = include_bytes!("../fixtures/config.gz");

/// A larger config in the same form, 64230 bytes in 2258 lines. GNU gzip ends
/// a block whenever its buffer of symbols fills, so a config of real size is
/// several blocks: this one is four dynamic-Huffman blocks, and 1331 of its
/// back-references reach into an earlier block.
const CONFIG_BLOCKS_GZ: &[u8] = include_bytes!("../fixtures/config-blocks.gz");

/// `stored\n` in a stored block (zlib, level 0).
const STORED: &[u8] = &[
    0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x03, 0x01, 0x07, 0x00, 0xF8, 0xFF, 0x73,
    0x74, 0x6F, 0x72, 0x65, 0x64, 0x0A, 0xE2, 0x9C, 0x53, 0xA5, 0x07, 0x00, 0x00, 0x00,
];

/// `fixed fixed fixed\n` in a fixed-Huffman block with back-references (zlib,
/// `Z_FIXED`).
const FIXED: &[u8] = &[
    0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x4B, 0xCB, 0xAC, 0x48, 0x4D, 0x51,
    0x48, 0x43, 0x90, 0x5C, 0x00, 0xC3, 0x3C, 0xE0, 0xA8, 0x12, 0x00, 0x00, 0x00,
];

/// Nothing, compressed.
const EMPTY: &[u8] = &[
    0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

/// `named\n` behind a header with every optional field: an extra field, the
/// name `config`, a comment and a header CRC.
const FLAGGED: &[u8] = &[
    0x1F, 0x8B, 0x08, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x04, 0x00, 0x41, 0x42, 0x02, 0x00,
    0x63, 0x6F, 0x6E, 0x66, 0x69, 0x67, 0x00, 0x61, 0x20, 0x63, 0x6F, 0x6D, 0x6D, 0x65, 0x6E, 0x74,
    0x00, 0xE2, 0xB1, 0xCB, 0x4B, 0xCC, 0x4D, 0x4D, 0xE1, 0x02, 0x00, 0xDC, 0xF0, 0x7A, 0x41, 0x06,
    0x00, 0x00, 0x00,
];

/// `CONFIG_A=y\nCONFIG_B=y\n` with a sync flush between the lines (zlib,
/// `Z_SYNC_FLUSH`): the first block is not the last, and an empty stored block
/// after it brings the stream to a byte boundary, as pigz ends each chunk it
/// compresses in parallel.
const SYNC_FLUSHED: &[u8] = &[
    0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x72, 0xF6, 0xF7, 0x73, 0xF3, 0x74,
    0x8F, 0x77, 0xB4, 0xAD, 0xE4, 0x02, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x73, 0x86, 0x30, 0x9D, 0x80,
    0x4C, 0x00, 0x65, 0x8A, 0x1E, 0x7D, 0x16, 0x00, 0x00, 0x00,
];

/// A bare member header: no flags, no name.
const HEADER: [u8; 10] = [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];

/// A member of `HEADER` and `body`, with a zeroed trailer.
fn framed(body: &[u8]) -> Vec<u8> {
    let mut stream = HEADER.to_vec();
    stream.extend_from_slice(body);
    stream.extend_from_slice(&[0; 8]);
    stream
}

/// A member of `HEADER` and the DEFLATE data `deflate`, with the trailer of
/// `decoded`.
fn member_of(deflate: &[u8], decoded: &[u8]) -> Vec<u8> {
    let mut stream = HEADER.to_vec();
    stream.extend_from_slice(deflate);
    stream.extend_from_slice(&crc32(decoded).to_le_bytes());
    stream.extend_from_slice(&u32::try_from(decoded.len()).unwrap().to_le_bytes());
    stream
}

/// DEFLATE data written bit by bit, for the blocks no encoder writes on
/// request.
#[derive(Default)]
struct Deflate {
    bytes: Vec<u8>,
    /// How many bits of the last byte are written.
    used: u32,
}

impl Deflate {
    /// The low `count` bits of `value`, the lowest first, as a header field or
    /// extra bits are packed.
    fn bits(&mut self, value: u32, count: u32) {
        for bit in 0..count {
            if self.used == 0 {
                self.bytes.push(0);
            }
            let byte = self.bytes.last_mut().unwrap();
            *byte |= u8::from((value >> bit) & 1 == 1) << self.used;
            self.used = (self.used + 1) % 8;
        }
    }

    /// A Huffman code, `(code, length)`, its highest bit first.
    fn code(&mut self, (code, length): (u32, u32)) {
        for bit in (0..length).rev() {
            self.bits(code >> bit, 1);
        }
    }
}

/// The canonical code of each symbol with these code lengths, as `(code,
/// length)` (RFC 1951, 3.2.2).
fn canonical(lengths: &[u8]) -> Vec<(u32, u32)> {
    let mut count = [0u32; MAX_BITS + 1];
    for &length in lengths.iter().filter(|&&length| length != 0) {
        count[usize::from(length)] += 1;
    }
    let mut next = [0u32; MAX_BITS + 1];
    for bits in 1..=MAX_BITS {
        next[bits] = (next[bits - 1] + count[bits - 1]) << 1;
    }
    lengths
        .iter()
        .map(|&length| {
            let slot = &mut next[usize::from(length)];
            *slot += 1;
            (*slot - 1, u32::from(length))
        })
        .collect()
}

/// A last block of the dynamic kind with these literal/length and distance
/// code lengths, its symbols written by `body` with the codes they make.
///
/// The code lengths go through the code-length code that gives each of the
/// lengths 0 to 15 four bits, a complete code, so none needs a repeat.
fn dynamic_block(
    literals: &[u8],
    distances: &[u8],
    body: impl FnOnce(&mut Deflate, &[(u32, u32)], &[(u32, u32)]),
) -> Vec<u8> {
    let mut block = Deflate::default();
    // BFINAL, BTYPE 2, then HLIT, HDIST and HCLEN: all 19 lengths of the
    // code-length code follow.
    block.bits(1, 1);
    block.bits(2, 2);
    block.bits(u32::try_from(literals.len() - 257).unwrap(), 5);
    block.bits(u32::try_from(distances.len() - 1).unwrap(), 5);
    block.bits(19 - 4, 4);
    // The repeat symbols 16 to 18 get no code.
    let mut code_lengths = [4u8; 19];
    code_lengths[16..].fill(0);
    for at in CODE_LENGTH_ORDER {
        block.bits(u32::from(code_lengths[at]), 3);
    }
    let length_code = canonical(&code_lengths);
    for &length in literals.iter().chain(distances) {
        block.code(length_code[usize::from(length)]);
    }
    body(&mut block, &canonical(literals), &canonical(distances));
    block.bytes
}

/// The code lengths of the most literal/length codes a block may define, 286,
/// as a complete code: 226 of eight bits and 60 of nine.
fn most_literals() -> Vec<u8> {
    [[8; 226].as_slice(), &[9; 60]].concat()
}

/// The code lengths of the most distance codes a block may define, 30, as a
/// complete code: 2 of four bits and 28 of five.
fn most_distances() -> Vec<u8> {
    [[4; 2].as_slice(), &[5; 28]].concat()
}

/// A block with these code lengths that holds `A` and nothing else.
fn just_a(literals: &[u8], distances: &[u8]) -> Vec<u8> {
    let block = dynamic_block(literals, distances, |out, literal, _| {
        out.code(literal[usize::from(b'A')]);
        out.code(literal[256]);
    });
    member_of(&block, b"A")
}

/// A literal/length code of four two-bit codes: `a`, `b`, the end of the
/// block and symbol 257, a length of 3.
fn four_literals() -> [u8; 258] {
    let mut lengths = [0; 258];
    for symbol in [usize::from(b'a'), usize::from(b'b'), 256, 257] {
        lengths[symbol] = 2;
    }
    lengths
}

/// `aaaa` as `a` and three bytes copied from one back, with this distance
/// code: the copy reaches back to the first byte written.
fn a_run(distances: &[u8]) -> Vec<u8> {
    let block = dynamic_block(&four_literals(), distances, |out, literal, distance| {
        out.code(literal[usize::from(b'a')]);
        out.code(literal[257]);
        out.code(distance[0]);
        out.code(literal[256]);
    });
    member_of(&block, b"aaaa")
}

#[test]
fn decodes_what_gzip_writes_for_a_kernel_config() {
    // The first block is a dynamic one: BFINAL set, BTYPE 2.
    assert_eq!(CONFIG_GZ[10] & 0b111, 0b101);
    let config = decompress(CONFIG_GZ).expect("the fixture decodes");
    assert_eq!(config.len(), 10664);
    let text = String::from_utf8(config).expect("a config is text");
    assert_eq!(text.lines().count(), 413);
    assert!(text.starts_with("#\n# Automatically generated file; DO NOT EDIT.\n"));
    assert!(text.contains("\n# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set\n"));
    assert!(text.contains("\nCONFIG_PAGE_POISONING=y\n"));
    assert!(text.ends_with("# end of Kernel hacking\n"));
}

#[test]
fn decodes_a_config_that_spans_several_blocks() {
    // The first block is a dynamic one that is not the last: BFINAL clear,
    // BTYPE 2.
    assert_eq!(CONFIG_BLOCKS_GZ[10] & 0b111, 0b100);
    let config = decompress(CONFIG_BLOCKS_GZ).expect("the fixture decodes");
    assert_eq!(config.len(), 64230);
    let text = String::from_utf8(config).expect("a config is text");
    assert_eq!(text.lines().count(), 2258);
    assert!(text.starts_with("#\n# Automatically generated file; DO NOT EDIT.\n"));
    assert!(text.contains("\n# CONFIG_INIT_ON_FREE_DEFAULT_ON is not set\n"));
    assert!(text.ends_with("\nCONFIG_PAGE_POISONING=y\n# end of Kernel hacking\n"));
}

#[test]
fn decodes_stored_fixed_and_empty_members() {
    assert_eq!(decompress(STORED).unwrap(), b"stored\n");
    assert_eq!(decompress(FIXED).unwrap(), b"fixed fixed fixed\n");
    assert_eq!(decompress(EMPTY).unwrap(), b"");
}

#[test]
fn reads_past_every_optional_header_field() {
    assert_eq!(decompress(FLAGGED).unwrap(), b"named\n");
}

#[test]
fn reads_past_an_extra_field_without_a_name() {
    // An extra field and nothing else, as bgzip writes its header: six bytes
    // that hold one two-byte `BC` subfield (RFC 1952, 2.3.1.1).
    let mut stream = vec![
        0x1F, 0x8B, 0x08, FEXTRA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x06, 0x00, b'B', b'C', 0x02,
        0x00, 0x24, 0x00,
    ];
    stream.extend_from_slice(&FIXED[HEADER.len()..]);
    assert_eq!(decompress(&stream).unwrap(), b"fixed fixed fixed\n");
}

#[test]
fn decodes_the_blocks_around_a_sync_flush() {
    // The empty stored block: a length of 0 and its complement.
    assert!(
        SYNC_FLUSHED
            .windows(4)
            .any(|window| window == [0x00, 0x00, 0xFF, 0xFF])
    );
    assert_eq!(
        decompress(SYNC_FLUSHED).unwrap(),
        b"CONFIG_A=y\nCONFIG_B=y\n"
    );
}

#[test]
fn decodes_a_block_that_defines_the_most_codes() {
    assert_eq!(
        decompress(&just_a(&most_literals(), &most_distances())).unwrap(),
        b"A"
    );
}

#[test]
fn refuses_a_block_that_defines_more_codes_than_there_are() {
    // One literal/length code more than the 286 there are, or one distance
    // code more than the 30.
    let literals = [most_literals().as_slice(), &[9]].concat();
    let distances = [most_distances().as_slice(), &[5]].concat();
    for stream in [
        just_a(&literals, &most_distances()),
        just_a(&most_literals(), &distances),
    ] {
        assert_eq!(
            decompress(&stream),
            Err(Malformed("a block defines too many codes"))
        );
    }
}

#[test]
fn accepts_a_lone_one_bit_distance_code() {
    // A block whose copies all reach the same distance may give it a code of
    // one bit and leave the other one-bit pattern unused (RFC 1951, 3.2.7):
    // the one incomplete code a block may hold.
    assert_eq!(decompress(&a_run(&[1, 0])).unwrap(), b"aaaa");
}

#[test]
fn refuses_any_other_incomplete_code() {
    // Two two-bit distance codes leave half the patterns unused.
    assert_eq!(
        decompress(&a_run(&[2, 2])),
        Err(Malformed("a code is incomplete"))
    );
}

#[test]
fn decodes_members_back_to_back() {
    let stream = [STORED, FIXED, EMPTY].concat();
    assert_eq!(decompress(&stream).unwrap(), b"stored\nfixed fixed fixed\n");
}

#[test]
fn refuses_a_stream_that_is_not_whole_and_valid() {
    let mut bad: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("trailing bytes", [FIXED, &[0]].concat()),
    ];
    for (what, at, value) in [
        ("another magic", 1, 0x8C),
        ("another method", 2, 0x07),
        ("a reserved flag", 3, 0x20),
        ("a CRC that does not match", FIXED.len() - 8, 0x00),
        ("a length that does not match", FIXED.len() - 4, 0x13),
    ] {
        let mut stream = FIXED.to_vec();
        stream[at] = value;
        bad.push((what, stream));
    }
    // Every prefix of a valid member is cut short somewhere.
    for len in 0..FLAGGED.len() {
        bad.push(("a truncated member", FLAGGED[..len].to_vec()));
    }
    for (what, stream) in bad {
        assert!(decompress(&stream).is_err(), "{what}: {stream:02X?}");
    }
}

#[test]
fn refuses_malformed_blocks() {
    // BFINAL set and BTYPE 3, which no block has.
    assert_eq!(
        decompress(&framed(&[0x07])),
        Err(Malformed("invalid block type"))
    );
    // A fixed block whose first symbol copies 3 bytes from 1 back, before
    // anything was written.
    assert_eq!(
        decompress(&framed(&[0x03, 0x02])),
        Err(Malformed("a back-reference reaches before the start"))
    );
    // A stored block whose length and its complement disagree.
    let mut stored = STORED.to_vec();
    stored[13] ^= 0x01;
    assert_eq!(
        decompress(&stored),
        Err(Malformed(
            "a stored block's length does not match its complement"
        ))
    );
}

#[test]
fn stops_at_the_output_limit() {
    assert_eq!(decompress_within(CONFIG_GZ, 10664).unwrap().len(), 10664);
    assert_eq!(
        decompress_within(CONFIG_GZ, 10663),
        Err(Malformed("decodes to more than the limit"))
    );
    assert!(decompress_within(STORED, 6).is_err());
}

#[test]
fn the_crc_is_gzips() {
    // The check value of the CRC-32 gzip uses (ISO 3309).
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b""), 0);
}

proptest::proptest! {
    /// No bytes make the decoder panic, whether as a whole stream or as the
    /// data after a valid header.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..600)) {
        let _ = decompress(&bytes);
        let _ = decompress(&framed(&bytes));
    }

    /// A real stream with bytes changed decodes or is refused, never panics.
    #[test]
    fn a_damaged_stream_never_panics(
        changes in proptest::collection::vec((0..CONFIG_GZ.len(), proptest::num::u8::ANY), 1..6)
    ) {
        let mut stream = CONFIG_GZ.to_vec();
        for (at, value) in changes {
            stream[at] = value;
        }
        let _ = decompress(&stream);
    }
}
