// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Round trip of overlay paths through the mount option string and back out of
//! mountinfo.

use super::{abs_path, mountable_path, octal_escape};
use crate::filesystem::mountinfo::{escape_overlay_path, parse_overlay_opts};
use proptest::prelude::*;
use std::path::{Path, PathBuf};

/// What `seq_show_option` escapes in an option value.
const SHOW_OPTION: &str = ", \t\n\\";

/// The option string NAILS passes to `mount(2)`, as the kernel echoes it back in
/// mountinfo: the stored values are the strings NAILS passed (still carrying the
/// overlay backslash escapes), escaped once more by `seq_show_option`.
fn as_mountinfo_super_opts(lower: &[String], upper: &str, work: &str) -> String {
    let escape = |p: &str| escape_overlay_path(Path::new(p)).unwrap();
    let lowerdir: Vec<String> = lower.iter().map(|p| escape(p)).collect();
    format!(
        "rw,lowerdir={},upperdir={},workdir={},index=off",
        octal_escape(&lowerdir.join(":"), SHOW_OPTION),
        octal_escape(&escape(upper), SHOW_OPTION),
        octal_escape(&escape(work), SHOW_OPTION),
    )
}

proptest! {
    /// Paths survive escape_overlay_path, the kernel's option echo and
    /// parse_overlay_opts unchanged.
    #[test]
    fn fuzz_overlay_opts_round_trip(
        lower in prop::collection::vec(mountable_path(), 1..4),
        upper in mountable_path(),
        work in mountable_path(),
    ) {
        let opts = parse_overlay_opts(&as_mountinfo_super_opts(&lower, &upper, &work));
        let expected: Vec<PathBuf> = lower.iter().map(PathBuf::from).collect();
        prop_assert_eq!(opts.lowerdir, expected);
        prop_assert_eq!(opts.upperdir, Some(PathBuf::from(&upper)));
        prop_assert_eq!(opts.workdir, Some(PathBuf::from(&work)));
    }

    /// A newline is refused rather than mangled.
    #[test]
    fn fuzz_overlay_escape_rejects_newlines(path in abs_path()) {
        prop_assert_eq!(escape_overlay_path(Path::new(&path)).is_err(), path.contains('\n'));
    }

    /// Arbitrary option strings never panic the decoder.
    #[test]
    fn fuzz_overlay_opts_never_panic(text in "\\PC{0,300}") {
        let _ = parse_overlay_opts(&text);
    }
}
