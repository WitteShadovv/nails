// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The UTF-8 decode NAILS applies to a systemd configuration file whose bytes
//! are not all valid UTF-8 (a decoy's Latin-1 comment or value, say). systemd
//! reads such a file line by line: it skips a comment whatever its bytes, and
//! stops at the first other line that is not valid UTF-8, keeping what it read
//! before. The decode puts U+FFFF, a character systemd refuses too, in place
//! of each byte sequence that is not UTF-8 and changes nothing else, so the
//! parser refuses the lines systemd refuses. The input is the raw file bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_core::preflight::checks::systemd_conf::{decode_config_bytes, parse_section};

fuzz_target!(|data: &[u8]| {
    let text = decode_config_bytes(data);
    // Valid UTF-8 comes through unchanged. Anything else is marked: no byte
    // that is not UTF-8 is dropped, or repaired into a character systemd
    // would accept.
    match std::str::from_utf8(data) {
        Ok(valid) => assert_eq!(text, valid),
        Err(_) => assert!(text.contains('\u{ffff}')),
    }
    // Every ASCII byte stays, in order: the line ends, comment marks,
    // backslashes, brackets and `=` systemd reads are where they were.
    assert!(
        text.bytes()
            .filter(u8::is_ascii)
            .eq(data.iter().copied().filter(u8::is_ascii))
    );
    // Parsing the decoded text, the real use of it, must never panic.
    let mut out = Vec::new();
    let _ = parse_section(&text, "Journal", &mut out);
});
