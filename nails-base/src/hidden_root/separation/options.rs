// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The options of the decoy's fstab and crypttab lines that the judge reads,
//! read as systemd reads them.
//!
//! systemd's fstab and crypttab generators match an option by its name, given
//! alone or with a value (`fstab_test_option()`, [`option_named`]), and of
//! `noauto` and `auto` the last one given wins (`fstab_test_yes_no_option()`):
//! systemd 260.5 reads `noauto=1` and `auto,noauto=` as `noauto`,
//! `noauto,auto=0` as `auto`, and `x-systemd.automount=0` as an automount. So
//! the judge reads `noauto`, `auto`, `x-systemd.automount` and its older
//! spelling `comment=systemd.automount` by their names ([`fstab_noauto`],
//! [`crypttab_noauto`]), as it reads `bind` and `rbind`
//! ([`is_bind_option`](crate::fstab::is_bind_option)). The shared parsers'
//! own `has_option` matches a whole option, which the judge does not use for
//! these.
//!
//! An option the judge reads whose value changes what it means in a way the
//! judge does not read makes an fstab line that is not plain
//! ([`Unplain::NoValue`]): an `x-systemd.wanted-by=` or
//! `x-systemd.required-by=` that names no unit, which systemd takes for a unit
//! that takes the place of `local-fs.target`, so the boot mounts the line no
//! more, and `subvol` or `subvolid` given alone or with no value, which btrfs
//! does not mount as the judge would read it. `x-systemd.wanted-by` given
//! alone is no such option to systemd, which reads only one with a `=`.

use super::plain::Unplain;
use crate::crypttab::CrypttabEntry;
use crate::fstab::{FstabEntry, option_named};

/// The options that name the units that pull an fstab line in, which systemd
/// reads only with a `=` and a unit.
const PULLED_IN_BY: &[&str] = &["x-systemd.wanted-by", "x-systemd.required-by"];

/// The btrfs options that name the subvolume an fstab line mounts.
const SUBVOLUME: &[&str] = &["subvol", "subvolid"];

/// Whether an option of `options` has one of `names`, alone or with a value.
fn has_named(options: &[String], names: &[&str]) -> bool {
    options.iter().any(|option| {
        names
            .iter()
            .any(|name| option_named(option, name).is_some())
    })
}

/// Whether the last of `options` named `yes` or `no`, alone or with a value,
/// is named `yes`, as systemd's `fstab_test_yes_no_option()` reads such a
/// pair: neither is `no`.
fn last_is(options: &[String], yes: &str, no: &str) -> bool {
    options
        .iter()
        .rev()
        .find_map(|option| {
            if option_named(option, yes).is_some() {
                Some(true)
            } else {
                option_named(option, no).map(|_| false)
            }
        })
        .unwrap_or(false)
}

/// Whether systemd mounts the fstab line `entry` on demand through an
/// automount unit: an option named `x-systemd.automount` or
/// `comment=systemd.automount`, alone or with a value. Never for swap.
fn automount(entry: &FstabEntry) -> bool {
    !entry.is_swap()
        && has_named(
            &entry.options,
            &["x-systemd.automount", "comment=systemd.automount"],
        )
}

/// Whether the boot never mounts the fstab line `entry`, as systemd's fstab
/// generator reads it: the last of `noauto` and `auto` is `noauto`, by name,
/// and the line has no automount, which the boot sets up whatever `noauto`
/// says, and names no unit to pull it in
/// ([`names_units_that_pull_it_in`](FstabEntry::names_units_that_pull_it_in)).
pub(super) fn fstab_noauto(entry: &FstabEntry) -> bool {
    last_is(&entry.options, "noauto", "auto")
        && !automount(entry)
        && !entry.names_units_that_pull_it_in()
}

/// Whether the boot does not open the crypttab line `entry` by itself, as
/// systemd's crypttab generator reads it: the last of `noauto` and `auto` is
/// `noauto`, by name, so `cryptsetup.target` does not pull it in.
pub(super) fn crypttab_noauto(entry: &CrypttabEntry) -> bool {
    last_is(&entry.options, "noauto", "auto")
}

/// Why the options of the fstab line `entry` make a line that is not plain
/// (see the module docs): nothing for options the judge reads as systemd
/// and btrfs do.
pub(super) fn unplain_fstab(entry: &FstabEntry) -> Vec<Unplain> {
    let mut why = Vec::new();
    for name in PULLED_IN_BY {
        if entry
            .options
            .iter()
            .any(|option| option_named(option, name) == Some(Some("")))
        {
            why.push(Unplain::NoValue(name));
        }
    }
    for name in SUBVOLUME {
        if entry
            .options
            .iter()
            .any(|option| matches!(option_named(option, name), Some(None | Some(""))))
        {
            why.push(Unplain::NoValue(name));
        }
    }
    why
}

#[cfg(test)]
#[path = "options_tests.rs"]
mod tests;
