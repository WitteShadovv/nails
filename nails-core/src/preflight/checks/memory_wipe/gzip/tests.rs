// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

/// A kernel config compressed the way a kernel build compresses its own copy
/// for `/proc/config.gz`: `gzip -n -9` (GNU gzip 1.14), whose output is one
/// member of dynamic-Huffman blocks. The text is 10664 bytes in 413 lines,
/// laid out as Kconfig writes a `.config`.
const CONFIG_GZ: &[u8] = include_bytes!("../fixtures/config.gz");

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

/// A bare member header: no flags, no name.
const HEADER: [u8; 10] = [0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];

/// A member of `HEADER` and `body`, with a zeroed trailer.
fn framed(body: &[u8]) -> Vec<u8> {
    let mut stream = HEADER.to_vec();
    stream.extend_from_slice(body);
    stream.extend_from_slice(&[0; 8]);
    stream
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
