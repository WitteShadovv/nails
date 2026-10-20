// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The UTF-8 decode NAILS applies to a systemd configuration file whose bytes
//! are not all valid UTF-8 (a decoy's Latin-1 comment, say). systemd reads such
//! a file line by line and keeps the lines that are valid UTF-8, so one bad
//! line never hides the rest — in particular a `Storage=persistent` below a
//! Latin-1 comment. The input is the raw file bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_core::preflight::checks::systemd_conf::{decode_config_bytes, parse_section};

fuzz_target!(|data: &[u8]| {
    let text = decode_config_bytes(data);
    // The decode yields only valid UTF-8 (a String), and the only line
    // terminator it emits is the newline the parser splits on: a kept line
    // never carries a carriage return or a NUL.
    assert!(!text.contains(['\r', '\0']));
    // Every non-empty line survives a re-decode unchanged. (Runs of blank lines
    // coalesce, which the parser ignores, so the whole text need not be a fixed
    // point.) No content line is invented, dropped or mangled.
    let nonempty = |s: &str| {
        s.lines()
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        nonempty(&decode_config_bytes(text.as_bytes())),
        nonempty(&text)
    );
    // Parsing the decoded text, the real use of it, must never panic.
    let mut out = Vec::new();
    let _ = parse_section(&text, "Journal", &mut out);
});
