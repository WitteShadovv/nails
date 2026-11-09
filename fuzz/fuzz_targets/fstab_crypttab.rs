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
//! - every swap entry whose device systemd would activate is masked or
//!   skipped, under the name systemd-fstab-generator gives its unit (the model
//!   in `nails_fuzz::systemd`);
//! - every mount entry kept off is masked or skipped under the names systemd
//!   gives its `.mount` and `.automount` units: an automount skipped with its
//!   mount masked;
//! - a skip waits for a device only while that device is there, and a mask
//!   that leaves a boot target unreached names a device that is not;
//! - an entry bound or overlaid in the next root has a plain absolute path;
//! - an entry whose plain absolute mount point lies at or below the hidden
//!   root is refused, whatever its type and options, a `noauto`, automount or
//!   tmpfs line among them;
//! - an entry that a link the hidden session left leads into the hidden
//!   volume (decided as redirected) is kept off under those same names, never
//!   left to the bind of the volume;
//! - an entry of the next root's own fstab (decided as an entry without a
//!   build decides it) is kept off under those names when its plain absolute
//!   mount point lies at or below the hidden root, whatever its type and
//!   options, and decided as the decoy's own line anywhere else;
//! - the fstab decided twice keeps off what deciding it once does;
//! - every line that `entry_lines` takes for an entry, as an entry without a
//!   build reads the next root's own fstab, is read in its device, mount
//!   point, type and options, these split as systemd splits them, as glibc's
//!   `getmntent()` reads it for systemd up to 258 and as libmount reads it
//!   from 259 on, where libmount reads the line at all, and a line it takes
//!   for none is no mount to either (the models in `nails_fuzz::glibc` and
//!   `nails_fuzz::libmount`); a file whose first line libmount would take
//!   for one of another table is refused;
//! - every crypttab device that NAILS resolves is the node
//!   systemd-cryptsetup-generator opens.
//!
//! Every entry is decided twice, with every device there and with none.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nails_base::crypttab::parse_crypttab;
use nails_fuzz::systemd::{UnitName, fstab_node_to_udev_node, option_words, unit_name_from_path};
use nails_fuzz::{glibc, libmount};
use nails_session::session::fstab::{FstabEntry, entry_lines, parse_fstab};
use nails_session::session::policy::{
    Decision, Unskippable, decide, decide_all, decide_hidden_fstab, decide_redirected,
    runtime_units,
};
use nails_teardown::mountinfo::parse_mountinfo;
use std::os::unix::ffi::OsStrExt;
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

    for there in [true, false] {
        let present = |_: &Path| there;
        let decisions = decide_all(&fstab, &mounts, hidden, &present);
        assert_eq!(decisions.len(), fstab.len());
        let kept = runtime_units(&fstab, &decisions);
        let twice: Vec<Decision> = decisions.iter().chain(&decisions).cloned().collect();
        let doubled: Vec<FstabEntry> = fstab.iter().chain(&fstab).cloned().collect();
        assert_eq!(runtime_units(&doubled, &twice), kept);
        let skipped = |unit: &String| kept.skips.iter().any(|skip| skip.units.contains(unit));
        for entry in &fstab {
            let decision = decide(entry, &mounts, hidden, &present);
            check(entry, &decision, there);
            if entry.file.starts_with(hidden) && plain_absolute(&entry.file) && !entry.is_swap() {
                assert!(
                    matches!(decision, Decision::Refuse { .. }),
                    "{entry:?} lies at or below the hidden root: {decision:?}"
                );
            }
            for unit in decision.masked_units() {
                assert!(kept.masks.contains(unit), "{unit}");
            }
            for unit in decision.skip().map_or(&[][..], |skip| &skip.units) {
                assert!(
                    skipped(unit) || kept.masks.contains(unit),
                    "{unit} is neither skipped nor masked"
                );
            }
            let redirected = decide_redirected(entry, &mounts, hidden, &present);
            check(entry, &redirected, there);
            if entry.file.starts_with(hidden)
                && plain_absolute(&entry.file)
                && !entry.is_swap()
                && !entry.is_virtual()
            {
                assert!(
                    matches!(redirected, Decision::Mask { .. } | Decision::Skip { .. }),
                    "{entry:?} led into the hidden volume: {redirected:?}"
                );
            }
            let own = decide_hidden_fstab(entry, &mounts, hidden, &present);
            check(entry, &own, there);
            if entry.file.starts_with(hidden) && plain_absolute(&entry.file) && !entry.is_swap() {
                assert!(
                    matches!(own, Decision::Mask { .. } | Decision::Skip { .. }),
                    "{entry:?} of the next root's own fstab lies at or below the hidden root: \
                     {own:?}"
                );
            } else {
                assert_eq!(own, decision, "{entry:?} of the next root's own fstab");
            }
        }
    }

    let text = parts[0].as_bytes();
    if libmount::first_fstab_line(text).is_some_and(libmount::other_table) {
        assert!(entry_lines(text).is_err(), "{:?}", parts[0]);
    }
    for line in text.split(|&byte| byte == b'\n') {
        read_alike(line);
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

/// The fstab line `line`, if `entry_lines` takes it for an entry, is read in
/// its device, mount point, type and options as `parse_fstab` reads it, by
/// glibc, and by libmount where libmount reads it; if it takes it for none,
/// neither mounts anything from it.
fn read_alike(line: &[u8]) {
    let Ok(lines) = entry_lines(line) else {
        return;
    };
    let shown = String::from_utf8_lossy(line);
    let by_glibc = glibc::getmntent(line);
    let by_libmount = libmount::parse_fstab_line(line);
    if lines.is_empty() {
        // Blank, a comment, or one field: glibc gives that no mount point,
        // which systemd skips, and libmount does not read it.
        assert!(
            by_glibc.as_ref().is_none_or(|e| e.dir.is_empty()),
            "{shown:?}: {by_glibc:?}"
        );
        assert_eq!(by_libmount, None, "{shown:?}");
        return;
    }
    let entries = parse_fstab(&shown);
    let [entry] = entries.as_slice() else {
        panic!("{shown:?}: {entries:?}");
    };
    // NAILS reads the options as written: undo the escapes both undo there.
    let options: Vec<Vec<u8>> = entry
        .options
        .iter()
        .map(|option| {
            let option = option.replace("\\040", " ").replace("\\011", "\t");
            option.replace("\\012", "\n").into_bytes()
        })
        .collect();
    let nails = (
        entry.spec.as_bytes(),
        entry.file.as_os_str().as_bytes(),
        entry.vfstype.as_bytes(),
        options,
    );
    let words = |opts: &[u8]| -> Vec<Vec<u8>> {
        option_words(opts).into_iter().map(<[u8]>::to_vec).collect()
    };
    let read = by_glibc.unwrap_or_else(|| panic!("{shown:?} is no entry to glibc"));
    let kind = if read.kind.is_empty() {
        b"auto".as_slice()
    } else {
        read.kind.as_slice()
    };
    let opts = if read.opts.is_empty() {
        b"defaults".as_slice()
    } else {
        read.opts.as_slice()
    };
    assert_eq!(
        nails,
        (
            read.fsname.as_slice(),
            read.dir.as_slice(),
            kind,
            words(opts)
        ),
        "{shown:?} read by glibc"
    );
    if let Some(read) = by_libmount {
        let opts = read.options.as_deref().unwrap_or(b"defaults");
        assert_eq!(
            nails,
            (
                read.source.as_slice(),
                read.target.as_slice(),
                read.fstype.as_slice(),
                words(opts)
            ),
            "{shown:?} read by libmount"
        );
    }
}

/// The decision for `entry`, made with every device there or with none
/// (`there`), keeps the hidden systemd off the decoy's disks as systemd names
/// its units.
fn check(entry: &FstabEntry, decision: &Decision, there: bool) {
    match decision {
        Decision::Mask { unreached, .. } => {
            // A mask leaves a target unreached only for a device not there.
            if let Some(unreached) = unreached {
                assert!(!there, "{entry:?}: {unreached:?} with every device there");
                assert!(
                    matches!(unreached.cause, Unskippable::NoDevice(_)),
                    "{entry:?}: {unreached:?}"
                );
            }
        }
        Decision::Skip { skip, .. } => {
            // A skip waits for no device that is not there.
            assert!(there || skip.device.is_none(), "{entry:?}: {skip:?}");
        }
        _ => {}
    }
    if entry.is_swap() {
        if entry.spec.contains('\0') {
            return;
        }
        let device = fstab_node_to_udev_node(&entry.spec);
        // swapon(8) needs a path; anything else fails to activate.
        if !device.starts_with('/') {
            return;
        }
        let units = match decision {
            Decision::Mask { units, .. } => units,
            Decision::Skip { skip, .. } => &skip.units,
            _ => panic!(
                "swap {:?} on {device} is neither masked nor skipped: {decision:?}",
                entry.spec
            ),
        };
        expect_unit(&units[0], &device, ".swap");
        return;
    }
    let file = entry.file.to_string_lossy();
    match decision {
        Decision::Mask { units, .. } => {
            expect_unit(&units[0], &file, ".mount");
            if entry.is_automount() {
                expect_unit(&units[1], &file, ".automount");
            }
        }
        Decision::Skip { skip, masked, .. } => {
            if entry.is_automount() {
                expect_unit(&skip.units[0], &file, ".automount");
                expect_unit(&masked[0], &file, ".mount");
            } else {
                expect_unit(&skip.units[0], &file, ".mount");
            }
        }
        Decision::ReadOnlyBind { target } | Decision::Overlay { target } => {
            assert!(plain_absolute(target), "{target:?}");
        }
        Decision::Leave { .. } | Decision::Refuse { .. } => {}
    }
}

/// Whether `path` is absolute and has no `.` or `..` in it.
fn plain_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

/// `unit` is the unit systemd generates for `path` with `suffix`, wherever
/// the model knows that name.
fn expect_unit(unit: &str, path: &str, suffix: &str) {
    if let UnitName::Name(name) = unit_name_from_path(path, suffix) {
        assert_eq!(unit, name, "the {suffix} unit for {path:?}");
    }
}
