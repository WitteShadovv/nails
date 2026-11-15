// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Whether the boot mounts a line of the decoy's fstab or opens a line of its
//! crypttab, as systemd reads its options.
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
//! these. The generator mounts a line for `/` or `/usr` whatever `noauto`
//! says, and links one that names a unit by `x-systemd.wanted-by=` or
//! `x-systemd.required-by=` into that unit, whatever `noauto` says.
//!
//! A line counts as one the boot does not mount or open only when NAILS
//! reads every option it gives (see the `known` module): any other line may
//! be pulled in at boot by an option NAILS does not read, so the claims count
//! it as one the boot mounts or opens.
//!
//! How `systemd-cryptsetup` opens a crypttab line the judge reads by the
//! options that set its type, in their order, of which the last one wins, as
//! systemd 260.5 logged type=PLAIN for `luks,discard,swap` and type=LUKS for
//! `swap,luks`; the crypttab generator also has `systemd-makefs` make swap for
//! `swap`, and a filesystem for `tmp` or `tmp=`, on the mapping, whatever their
//! order ([`opens_as_luks`]). The decoy's own crypttab line is let be only
//! where it opens its LUKS mapping as LUKS and makes neither.

use super::known::{reads_every_known, reads_every_known_crypttab};
use super::paths::as_written;
use crate::crypttab::CrypttabEntry;
use crate::fstab::{FstabEntry, option_named};
use std::path::Path;

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

/// Whether systemd's fstab generator mounts the fstab line `entry` whatever
/// its options say: a line for `/` or `/usr`, which it takes for mandatory.
fn mandatory(entry: &FstabEntry) -> bool {
    !entry.is_swap()
        && as_written(&entry.file).is_some_and(|at| at == Path::new("/") || at == Path::new("/usr"))
}

/// Whether the boot never mounts the fstab line `entry`, as systemd's fstab
/// generator reads it: the last of `noauto` and `auto` is `noauto`, by name,
/// and the line has no automount, which the boot sets up whatever `noauto`
/// says, names no unit to pull it in
/// ([`names_units_that_pull_it_in`](FstabEntry::names_units_that_pull_it_in)),
/// is no line for `/` or `/usr` ([`mandatory`]), and gives only options
/// NAILS reads, each in a form it reads ([`reads_every_known`]).
pub(super) fn fstab_noauto(entry: &FstabEntry) -> bool {
    last_is(&entry.options, "noauto", "auto")
        && !automount(entry)
        && !entry.names_units_that_pull_it_in()
        && !mandatory(entry)
        && reads_every_known(entry)
}

/// Whether the boot does not open the crypttab line `entry` by itself, as
/// systemd's crypttab generator reads it: the last of `noauto` and `auto` is
/// `noauto`, by name, so `cryptsetup.target` does not pull it in, and the
/// line gives only options NAILS reads ([`reads_every_known_crypttab`]).
pub(super) fn crypttab_noauto(entry: &CrypttabEntry) -> bool {
    last_is(&entry.options, "noauto", "auto") && reads_every_known_crypttab(entry)
}

/// How `systemd-cryptsetup` opens a crypttab line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CryptType {
    /// As a LUKS volume: it loads the LUKS header, or fails.
    Luks,
    /// As a TrueCrypt or VeraCrypt volume.
    Tcrypt,
    /// As plain dm-crypt, with no header, or as a BitLocker volume.
    Other,
}

/// How `systemd-cryptsetup` opens the crypttab line `entry`, as it reads the
/// options in their order, of which the last that sets a type wins (systemd
/// 260.5 `parse_one_option()`): `luks`, `key-slot=` and `keyslot=` set LUKS,
/// `header=` sets it unless the type is TrueCrypt, `tcrypt`, its `tcrypt-*`
/// forms, `veracrypt` and `tcrypt-keyfile=` set TrueCrypt, `plain`, `swap`,
/// `tmp` and `tmp=` plain dm-crypt, and `bitlk` BitLocker. A line that sets
/// none it opens as LUKS: it loads a LUKS header, or fails.
fn crypt_type(entry: &CrypttabEntry) -> CryptType {
    let mut set = None;
    for option in &entry.options {
        let valued = |name: &str| option_named(option, name).flatten().is_some();
        set = match option.as_str() {
            "luks" => Some(CryptType::Luks),
            "tcrypt" | "tcrypt-hidden" | "tcrypthidden" | "tcrypt-system" | "tcrypt-veracrypt"
            | "veracrypt" => Some(CryptType::Tcrypt),
            "plain" | "swap" | "tmp" | "bitlk" => Some(CryptType::Other),
            _ if valued("key-slot") || valued("keyslot") => Some(CryptType::Luks),
            _ if valued("tcrypt-keyfile") => Some(CryptType::Tcrypt),
            _ if valued("tmp") => Some(CryptType::Other),
            _ if valued("header") && set != Some(CryptType::Tcrypt) => Some(CryptType::Luks),
            _ => set,
        };
    }
    set.unwrap_or(CryptType::Luks)
}

/// Whether the boot opens the crypttab line `entry` as a LUKS volume and
/// leaves what it opens as it is: `systemd-cryptsetup` opens it as LUKS
/// ([`crypt_type`]), and it gives neither `swap` nor `tmp`, by name, for which
/// systemd's crypttab generator has `systemd-makefs` make swap or a
/// filesystem on the mapping wherever it finds none.
pub(super) fn opens_as_luks(entry: &CrypttabEntry) -> bool {
    crypt_type(entry) == CryptType::Luks && !has_named(&entry.options, &["swap", "tmp"])
}

#[cfg(test)]
#[path = "options_tests.rs"]
mod tests;
