// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The options the judge reads, as systemd 260.5's fstab and crypttab
//! generators read them.

use super::*;
use crate::crypttab::parse_crypttab;
use crate::fstab::parse_fstab;

fn fstab_line(vfstype: &str, options: &str) -> FstabEntry {
    parse_fstab(&format!("/dev/vda2 /home {vfstype} {options} 0 0\n")).remove(0)
}

fn crypttab_line(options: &str) -> CrypttabEntry {
    parse_crypttab(&format!("cryptroot /dev/nvme0n1p3 none {options}\n")).remove(0)
}

/// The fstab generator wrote `noauto=yes` for `noauto=1` and for
/// `auto,noauto=`, and pulled `opt.mount` into local-fs.target for
/// `noauto,auto=0` and `var.automount` for `x-systemd.automount=0`.
#[test]
fn noauto_and_an_automount_are_read_by_their_names_and_the_last_wins() {
    for options in [
        "noauto",
        "noauto=1",
        "noauto=yes",
        "noauto=0",
        "noauto=",
        "auto,noauto=",
        "auto=1,noauto",
        "defaults,noauto=x,nofail",
        "noauto,x-systemd.wanted-by=",
    ] {
        assert!(fstab_noauto(&fstab_line("btrfs", options)), "{options}");
    }
    for options in [
        "defaults",
        "noauto,auto",
        "noauto,auto=0",
        "noauto=1,auto=",
        "noauto,x-systemd.automount",
        "noauto,x-systemd.automount=0",
        "noauto,comment=systemd.automount",
        "noauto,comment=systemd.automount=x",
        "noauto,x-systemd.wanted-by=backup.service",
        "noauto,x-systemd.required-by=backup.service",
        "noautox",
        "autonoauto",
    ] {
        assert!(!fstab_noauto(&fstab_line("btrfs", options)), "{options}");
    }
    // systemd makes no automount for swap, and reads no unit to pull it in.
    assert!(fstab_noauto(&fstab_line(
        "swap",
        "noauto,x-systemd.automount=1"
    )));
    assert!(fstab_noauto(&fstab_line(
        "swap",
        "noauto,x-systemd.wanted-by=x.service"
    )));
}

/// The crypttab generator pulled `vn1` (`noauto=1,auto`) into
/// cryptsetup.target and left `vn2` (`auto,noauto=no`) out.
#[test]
fn a_crypttab_noauto_is_read_by_its_name_and_the_last_wins() {
    for options in [
        "luks,noauto",
        "luks,noauto=1",
        "auto,noauto=no",
        "noauto=,luks",
    ] {
        assert!(crypttab_noauto(&crypttab_line(options)), "{options}");
    }
    for options in [
        "luks",
        "noauto,auto",
        "noauto=1,auto",
        "noauto,auto=x",
        "noautox",
    ] {
        assert!(!crypttab_noauto(&crypttab_line(options)), "{options}");
    }
}

/// An empty `x-systemd.wanted-by=` took the place of local-fs.target: the
/// generator linked `home.mount` into `.wants/` only. One given alone is no
/// option to systemd, which reads it only with a `=`.
#[test]
fn an_option_with_no_value_where_systemd_or_btrfs_reads_one_is_not_plain() {
    for (options, why) in [
        (
            "subvol=/home,x-systemd.wanted-by=",
            vec![Unplain::NoValue("x-systemd.wanted-by")],
        ),
        (
            "x-systemd.required-by=,nofail",
            vec![Unplain::NoValue("x-systemd.required-by")],
        ),
        ("subvol,noatime", vec![Unplain::NoValue("subvol")]),
        ("subvol=", vec![Unplain::NoValue("subvol")]),
        ("subvolid", vec![Unplain::NoValue("subvolid")]),
        ("subvol=/home,subvolid=", vec![Unplain::NoValue("subvolid")]),
        (
            "x-systemd.wanted-by=,subvol",
            vec![
                Unplain::NoValue("x-systemd.wanted-by"),
                Unplain::NoValue("subvol"),
            ],
        ),
    ] {
        assert_eq!(
            unplain_fstab(&fstab_line("btrfs", options)),
            why,
            "{options}"
        );
    }
    for options in [
        "subvol=/home",
        "subvolid=257",
        "x-systemd.wanted-by",
        "x-systemd.wanted-by=backup.service",
        "x-systemd.required-by=a.service,x-systemd.wanted-by=b.service",
        "defaults",
    ] {
        assert_eq!(
            unplain_fstab(&fstab_line("btrfs", options)),
            [],
            "{options}"
        );
    }
}
