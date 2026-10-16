// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! A decoy's `/etc/fstab` and `/etc/crypttab`, and what the session does
//! with each fstab entry before the switch. A unit the session masks has to
//! be the unit systemd generates for the entry: masking any other name leaves
//! the hidden systemd free to mount a decoy filesystem read-write or to swap
//! onto a decoy disk.
//!
//! The input is the fstab text, then after a NUL the crypttab text, then
//! after another NUL the decoy's mount table (a typical one when it is
//! missing). The target checks that:
//!
//! - every swap entry whose device systemd would activate is masked, under
//!   the name systemd-fstab-generator gives its unit (the model in
//!   `nails_fuzz::systemd`);
//! - every masked mount entry is masked under the names systemd gives its
//!   `.mount` and `.automount` units;
//! - an entry bound or overlaid in the next root has a plain absolute path;
//! - every crypttab device that NAILS resolves is the node
//!   systemd-cryptsetup-generator opens.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_base::crypttab::parse_crypttab;
use nails_fuzz::systemd::{UnitName, fstab_node_to_udev_node, unit_name_from_path};
use nails_session::session::fstab::{FstabEntry, parse_fstab};
use nails_session::session::policy::{Decision, decide, decide_all, masks};
use nails_teardown::mountinfo::parse_mountinfo;
use std::path::{Component, Path};

const HIDDEN_ROOT: &str = "/mnt/data";

/// A decoy's mounts: an ext4 root, an ESP, a separate /home and a read-only
/// /srv, tmpfs, a NixOS test VM's store overlay over a 9p share, and the
/// hidden volume.
const MOUNTS: &str = "\
1 0 8:2 / / rw,relatime - ext4 /dev/vda2 rw
2 1 8:1 / /boot rw - vfat /dev/vda1 rw
3 1 8:3 / /home rw - ext4 /dev/vda3 rw
4 1 8:4 / /srv ro - ext4 /dev/vda4 ro
5 1 0:5 / /tmp rw - tmpfs tmpfs rw
6 1 0:6 / /nix/.rw-store rw - tmpfs tmpfs rw
7 1 0:7 / /nix/store rw - overlay overlay rw,lowerdir=/nix/.ro-store,upperdir=/nix/.rw-store/store,workdir=/nix/.rw-store/work
8 1 253:0 / /mnt/data rw - ext4 /dev/mapper/data rw
9 1 0:9 / /nix/.ro-store rw - 9p store rw,trans=virtio
";

fuzz_target!(|data: &[u8]| {
    let parts = nails_fuzz::parts(data, 3);
    let fstab = parse_fstab(&parts[0]);
    let mounts = parse_mountinfo(parts.get(2).map_or(MOUNTS, String::as_str));
    let hidden = Path::new(HIDDEN_ROOT);

    let decisions = decide_all(&fstab, &mounts, hidden);
    assert_eq!(decisions.len(), fstab.len());
    let masked = masks(&fstab, &decisions);
    for entry in &fstab {
        let decision = decide(entry, &mounts, hidden);
        check(entry, &decision);
        for unit in decision.masked_units() {
            assert!(masked.contains(unit), "{unit}");
        }
    }

    for entry in parse_crypttab(parts.get(1).map_or("", String::as_str)) {
        assert!(!entry.name.is_empty() && !entry.name.contains(char::is_whitespace));
        if let Some(device) = entry.device()
            && !entry.source.contains('\0')
        {
            assert_eq!(
                device,
                Path::new(&fstab_node_to_udev_node(&entry.source)),
                "the device of {:?}",
                entry.source
            );
        }
    }
});

/// The decision for `entry` keeps the hidden systemd off the decoy's disks
/// as systemd names its units.
fn check(entry: &FstabEntry, decision: &Decision) {
    if entry.is_swap() {
        if entry.spec.contains('\0') {
            return;
        }
        let device = fstab_node_to_udev_node(&entry.spec);
        // swapon(8) needs a path; anything else fails to activate.
        if !device.starts_with('/') {
            return;
        }
        let Decision::Mask { units, .. } = decision else {
            panic!(
                "swap {:?} on {device} is not masked: {decision:?}",
                entry.spec
            );
        };
        expect_unit(&units[0], &device, ".swap");
        return;
    }
    match decision {
        Decision::Mask { units, .. } => {
            let file = entry.file.to_string_lossy();
            expect_unit(&units[0], &file, ".mount");
            if entry.is_automount() {
                expect_unit(&units[1], &file, ".automount");
            }
        }
        Decision::ReadOnlyBind { target } | Decision::Overlay { target } => {
            assert!(
                target.is_absolute()
                    && target
                        .components()
                        .all(|c| matches!(c, Component::RootDir | Component::Normal(_))),
                "{target:?}"
            );
        }
        Decision::Leave { .. } | Decision::Refuse { .. } => {}
    }
}

/// `unit` is the unit systemd generates for `path` with `suffix`, wherever
/// the model knows that name.
fn expect_unit(unit: &str, path: &str, suffix: &str) {
    if let UnitName::Name(name) = unit_name_from_path(path, suffix) {
        assert_eq!(unit, name, "the {suffix} unit for {path:?}");
    }
}
