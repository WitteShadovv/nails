// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the hidden root keeps masked, whatever the decoy's fstab says.
//!
//! Some units of the decoy would only fail in the hidden root, where `/` is
//! the root overlay and the boot filesystems are bound read-only, and none of
//! them has a job there ([`UNITS`]). The entry masks those the hidden root
//! has, at the switch and in the hidden root alone, best effort and apart
//! from the fstab policy's masks ([`super::policy`]), without which the entry
//! must not happen. The masks go into `/run/systemd/system.control`, which
//! ranks above `/etc/systemd/system`, where NixOS links every unit. The decoy
//! runs the units at its own start, as it always does.
//!
//! The [`GENERATORS`] are masked at the switch as well, in
//! `/run/systemd/system-generators`, ahead of every other generator
//! directory. Those masks are not best effort: as for the fstab policy's
//! masks, the switch is refused when one cannot be written.
//!
//! All of them live in `/run` only: the return scrub removes them with the
//! rest of the session's `/run`, and the decoy side removes them when a switch
//! never happened.

use std::path::Path;

/// Units of the decoy that would only fail in the hidden root and whose job
/// it does not need:
///
/// | Unit | What it does at every start | In the hidden root |
/// | --- | --- | --- |
/// | `systemd-boot-random-seed.service` | refreshes the random seed systemd-boot hands to the next boot, on the ESP | the ESP is read-only, and the next boot is the decoy's |
/// | `grub-common.service` (Debian, Ubuntu 24.04), `grub2-common.service` (Ubuntu 26.04), `grub-initrd-fallback.service` (Ubuntu) | records a good boot in GRUB's environment block on `/boot` | `/boot` is read-only, and the next boot is the decoy's |
/// | `systemd-remount-fs.service` | gives `/`, `/usr` and the kernel filesystems the options the fstab names | `/` is the root overlay, which refuses any change, so the unit fails (Debian 13, Fedora 44); `/usr` is part of it or a mount the entry made, and the kernel filesystems come through the switch as the decoy's start set them |
/// | `systemd-growfs-root.service` | grows the root filesystem to fill its partition, where the fstab asks for it (`x-systemd.growfs`) | `/` is the root overlay, which it cannot grow, so the unit fails (Debian 13); the decoy's root filesystem is the decoy's to grow |
pub const UNITS: &[&str] = &[
    "systemd-boot-random-seed.service",
    "grub-common.service",
    "grub2-common.service",
    "grub-initrd-fallback.service",
    "systemd-remount-fs.service",
    "systemd-growfs-root.service",
];

/// Generators the hidden systemd must never run.
///
/// `systemd-gpt-auto-generator` mounts the partitions it finds by their GPT
/// type on the disk of the root filesystem (`/home`, `/srv`, `/var`, the ESP)
/// and turns on a swap partition, where the fstab does not cover them
/// already. The fstab policy never decides on those: in the hidden root they
/// would be mounted read-write, and the swap would take hidden RAM onto a
/// decoy disk. On the root overlay the generator finds no disk, so the mask is
/// a defence in depth for a decoy where it would find one all the same: one
/// whose separate `/usr` is mounted read-only. The fstab policy binds that
/// `/usr` read-only into the hidden root, and with `/` on no disk the
/// generator takes the disk of `/usr`.
pub const GENERATORS: &[&str] = &["systemd-gpt-auto-generator"];

/// The [`UNITS`] installed in `root`, the next root, without those already in
/// `masked` (the fstab policy's masks, which are written apart).
pub fn units(root: &Path, masked: &[String]) -> Vec<String> {
    super::systemd::units_in_root(root, UNITS)
        .into_iter()
        .filter(|unit| !masked.contains(unit))
        .collect()
}

/// The [`GENERATORS`], each whether or not the next root has it: a generator
/// can be installed in a directory of the init's own (the systemd package's,
/// on NixOS), and a mask of one that is not installed changes nothing.
pub fn generators() -> Vec<String> {
    GENERATORS.iter().map(|name| (*name).to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_teardown::whole_root::runtime_units::{valid_generator_name, valid_unit_name};

    /// A root with `units` installed in `dir`.
    fn root_with(dir: &str, units: &[&str]) -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(dir)).unwrap();
        for unit in units {
            std::fs::write(root.path().join(dir).join(unit), "[Unit]\n").unwrap();
        }
        root
    }

    #[test]
    fn every_name_is_one_the_switch_writes() {
        for unit in UNITS {
            assert!(valid_unit_name(unit), "{unit}");
        }
        for generator in GENERATORS {
            assert!(valid_generator_name(generator), "{generator}");
        }
    }

    #[test]
    fn every_entry_masks_the_gpt_auto_generator() {
        // What the entry records in the plan, whatever the next root holds.
        let generators = generators();
        assert_eq!(generators, GENERATORS);
        assert!(generators.iter().any(|g| g == "systemd-gpt-auto-generator"));
        for generator in &generators {
            assert!(valid_generator_name(generator), "{generator}");
        }
    }

    #[test]
    fn ubuntu_2604_s_grub_unit_is_masked() {
        // Ubuntu 26.04 names GRUB's boot record grub2-common.service: it
        // failed in every hidden session entered with /boot mounted.
        let root = root_with("usr/lib/systemd/system", &["grub2-common.service"]);
        assert_eq!(units(root.path(), &[]), ["grub2-common.service"]);
    }

    #[test]
    fn the_root_filesystem_units_are_masked_where_the_root_has_them() {
        // A Debian 13 root: GRUB's units and the two that remount and grow the
        // root filesystem, which failed on its root overlay.
        let root = root_with(
            "lib/systemd/system",
            &[
                "systemd-growfs-root.service",
                "systemd-remount-fs.service",
                "grub-initrd-fallback.service",
                "grub-common.service",
            ],
        );
        assert_eq!(
            units(root.path(), &[]),
            [
                "grub-common.service",
                "grub-initrd-fallback.service",
                "systemd-remount-fs.service",
                "systemd-growfs-root.service",
            ]
        );
        // A unit among the fstab policy's masks is written with those.
        let masked = ["systemd-remount-fs.service".to_string()];
        assert_eq!(
            units(root.path(), &masked),
            [
                "grub-common.service",
                "grub-initrd-fallback.service",
                "systemd-growfs-root.service",
            ]
        );
        assert!(units(tempfile::tempdir().unwrap().path(), &[]).is_empty());
    }
}
