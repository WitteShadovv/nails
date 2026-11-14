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
    // systemd makes no automount for swap.
    assert!(fstab_noauto(&fstab_line(
        "swap",
        "noauto,x-systemd.automount=1"
    )));
}

/// A line counts as one the boot does not mount only when NAILS reads every
/// option it gives: an empty `x-systemd.wanted-by=`, which the generator
/// linked into a unit named by nothing, a unit named on a swap line, which it
/// reads not at all, and an option no list holds count as mounted.
#[test]
fn a_line_with_an_option_nails_does_not_read_counts_as_one_the_boot_mounts() {
    for (vfstype, options) in [
        ("btrfs", "noauto,x-systemd.wanted-by="),
        ("btrfs", "noauto,X-mount.subdir=x"),
        ("btrfs", "noauto,nofail=1"),
        ("ext4", "noauto,x-systemd.requires=backup.service"),
        ("swap", "noauto,x-systemd.wanted-by=x.service"),
    ] {
        assert!(!fstab_noauto(&fstab_line(vfstype, options)), "{options}");
    }
    for options in [
        "luks,noauto,foo",
        "noauto,keyscript=passdev",
        "noauto,discard=1",
    ] {
        assert!(!crypttab_noauto(&crypttab_line(options)), "{options}");
    }
}

/// The generator mounts a line for `/` or `/usr` whatever `noauto` says.
#[test]
fn a_line_for_slash_or_usr_is_one_the_boot_mounts() {
    for (at, noauto) in [
        ("/", false),
        ("/usr", false),
        ("/usr/", false),
        ("/home", true),
        ("/usr/local", true),
    ] {
        let line = parse_fstab(&format!("/dev/vda2 {at} ext4 noauto 0 0\n")).remove(0);
        assert_eq!(fstab_noauto(&line), noauto, "{at}");
    }
    let swap = parse_fstab("/dev/vda3 / swap noauto 0 0\n").remove(0);
    assert!(fstab_noauto(&swap));
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
