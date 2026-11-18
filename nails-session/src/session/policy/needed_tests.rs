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

/// systemd 260.5's and 261.3's fstab generators wrote `Requires=data.mount`
/// for `x-systemd.requires=/data,comment=a\,b` and none for
/// `comment=a\,x-systemd.requires=/data`, which they read as one option: an
/// option before the first with a backslash names the mount as it reads, one
/// after it only may.
#[test]
fn an_option_after_a_backslash_names_a_mount_only_may() {
    let lines = crate::session::fstab::parse_fstab(
        "/dev/vdb1 /data ext4 noauto 0 0\n\
         tmpfs /t1 tmpfs x-systemd.requires=/data,comment=a\\,b 0 0\n\
         tmpfs /t1 tmpfs comment=a\\,x-systemd.requires=/data 0 0\n",
    );
    assert_eq!(
        need(&lines[1], &lines[0]),
        Some(Need::Requires),
        "{:?}",
        lines[1]
    );
    assert_eq!(
        need(&lines[2], &lines[0]),
        Some(Need::Unread),
        "{:?}",
        lines[2]
    );
}
