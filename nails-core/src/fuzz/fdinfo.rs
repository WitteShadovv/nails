// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `/proc/<pid>/fdinfo/<n>` `flags:` parser.

use crate::process::detection::parse_fdinfo_flags;
use proptest::prelude::*;

/// An fdinfo body as the kernel writes it: `pos`, `flags` (octal), `mnt_id`,
/// `ino`, then file-type specific lines, tab after each colon.
fn fdinfo(pos: u64, flags: u32, mnt_id: i32, extra: &[String]) -> String {
    let mut body = format!("pos:\t{pos}\nflags:\t0{flags:o}\nmnt_id:\t{mnt_id}\nino:\t42\n");
    for line in extra {
        body.push_str(line);
        body.push('\n');
    }
    body
}

proptest! {
    #[test]
    fn fuzz_fdinfo_flags_round_trip(
        pos in any::<u64>(),
        flags in 0u32..0o20000000,
        mnt_id in 0i32..100_000,
        extra in prop::collection::vec("[a-z_]{1,10}:\t[0-9a-f ]{0,20}", 0..4),
    ) {
        let body = fdinfo(pos, flags, mnt_id, &extra);
        prop_assert_eq!(parse_fdinfo_flags(&body), Some(u64::from(flags)));
    }

    #[test]
    fn fuzz_fdinfo_never_panics(text in "\\PC{0,200}") {
        let _ = parse_fdinfo_flags(&text);
    }
}
