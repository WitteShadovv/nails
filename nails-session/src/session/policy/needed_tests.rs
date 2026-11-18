// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the `noauto` lines another line needs.

use super::*;

/// systemd 260.5's fstab generator wrote these dependencies for
/// `x-systemd.requires=` with each value on a test root.
#[test]
fn a_pull_is_named_as_the_fstab_generator_names_it() {
    for (value, unit) in [
        ("/r/a", "r-a.mount"),
        ("/r//a/", "r-a.mount"),
        ("r/a", "r-a.mount"),
        ("r-a", "r-a.mount"),
        ("r-a.mount", "r-a.mount"),
        ("u4.mount", "u4.mount"),
        ("/r/a/sub", "r-a-sub.mount"),
        ("/dev/vdy1", "dev-vdy1.device"),
        ("%i.mount", "\\x25i.mount"),
        ("r+a.mount", "r\\x2ba.mount"),
        ("/r/../r/a", "-r-..-r-a.mount"),
    ] {
        assert_eq!(pulled_unit(value), unit, "{value}");
    }
}
