// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `/etc/fstab` as the hidden systemd will read it, and systemd's unit names.
//!
//! The hidden root runs the decoy's own fstab (or, on NixOS, the hidden
//! toplevel's). `systemd-fstab-generator` turns every entry into a `.mount` or
//! `.swap` unit, so the session policy ([`super::policy`]) needs the same view
//! of it, plus the unit names it would generate, what requires each unit at
//! boot ([`required_by`]), the device it waits for ([`waits_for`]) and the
//! units it pulls in that act on that device ([`checkers`]), to overlay,
//! bind, skip or mask each entry before the switch. The parser is
//! [`nails_base::fstab`], re-exported here; the unit names are the session's
//! own.

use std::path::{Path, PathBuf};

pub use nails_base::fstab::{FstabEntry, escape_path, is_virtual_type, parse_fstab, spec_device};

/// The `/etc/fstab` of the root at `root`, read as that root resolves it
/// ([`read_in_root`](nails_teardown::whole_root::nextroot::read_in_root)).
/// A root without one has no entries; any other error is returned, never
/// taken for an empty fstab, which would leave every entry undecided.
pub fn read_in_root(root: &Path) -> std::io::Result<Vec<u8>> {
    match nails_teardown::whole_root::nextroot::read_in_root(root, Path::new("/etc/fstab")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        result => result,
    }
}

/// The entries of the fstab `text` with every absolute mount point resolved
/// inside `root`, the way systemd's fstab generator resolves it: each symlink
/// on the way followed inside the root, a tail that does not exist yet kept
/// ([`canonical_in_root`](nails_teardown::whole_root::nextroot::canonical_in_root)).
/// A `/home` that the root keeps at `var/home` reads as `/var/home`, the path
/// of `var-home.mount` and `var-home.automount`. The decisions, the masks, the
/// way back and the `fstab-policy` check all take entries resolved here, so
/// they name the same mount points.
pub fn parse_in_root(text: &[u8], root: &Path) -> Vec<FstabEntry> {
    let mut entries = parse_fstab(&String::from_utf8_lossy(text));
    for entry in &mut entries {
        // A relative mount point (swap's `none`) comes back as it is.
        entry.file = nails_teardown::whole_root::nextroot::canonical_in_root(root, &entry.file);
    }
    entries
}

/// The `.mount` unit for a mount point.
pub fn mount_unit(path: &Path) -> String {
    format!("{}.mount", escape_path(path))
}

/// The `.automount` unit for a mount point.
pub fn automount_unit(path: &Path) -> String {
    format!("{}.automount", escape_path(path))
}

/// The `.swap` unit for a swap spec, when it names a device or file.
pub fn swap_unit(spec: &str) -> Option<String> {
    let path = spec_device(spec).or_else(|| spec.starts_with('/').then(|| PathBuf::from(spec)))?;
    Some(format!("{}.swap", escape_path(&path)))
}

/// The mount options that turn on quota for a filesystem, for which systemd's
/// fstab generator has the mount pull in its quota check and activation.
const QUOTA_OPTIONS: &[&str] = &[
    "usrquota",
    "grpquota",
    "quota",
    "usrjquota",
    "grpjquota",
    "prjquota",
];

/// The target that requires a `_netdev` swap line: the fstab generator links
/// every swap into `swap.target` up to systemd 260, and a `_netdev` one into
/// `remote-fs.target` from 261 on. Which systemd the hidden session runs is
/// not told here, so both are named.
const NETDEV_SWAP_TARGET: &str = "swap.target (remote-fs.target from systemd 261)";

/// What requires the unit systemd's fstab generator makes for `entry` (its
/// automount, if it has one) at boot, as the generator links it: the entry's
/// boot target, `local-fs.target`, or `remote-fs.target` for a network
/// filesystem, or `swap.target` for swap ([`NETDEV_SWAP_TARGET`] for a
/// `_netdev` swap); or the units its `x-systemd.required-by=` options name,
/// which then take the target's place. `None` when nothing requires it: `nofail` (the
/// target only wants the unit), `noauto` without an automount (nothing pulls
/// it in), `x-systemd.wanted-by=` alone, or an NFS `bg` mount, which the
/// generator makes `nofail`.
pub fn required_by(entry: &FstabEntry) -> Option<String> {
    if entry.is_swap() {
        if entry.yes_no_option("noauto", "auto") || entry.is_nofail() {
            return None;
        }
        let target = if entry.has_option("_netdev") {
            NETDEV_SWAP_TARGET
        } else {
            "swap.target"
        };
        return Some(target.to_string());
    }
    let named = |key: &str| -> Vec<&str> {
        entry
            .options
            .iter()
            .filter_map(|option| option.strip_prefix(key))
            .filter(|unit| !unit.is_empty())
            .collect()
    };
    let required = named("x-systemd.required-by=");
    if !required.is_empty() {
        return Some(required.join(" "));
    }
    let nfs_background = matches!(entry.vfstype.as_str(), "nfs" | "nfs4")
        && !entry.is_automount()
        && entry.yes_no_option("bg", "fg");
    if !named("x-systemd.wanted-by=").is_empty()
        || entry.is_noauto()
        || entry.is_nofail()
        || nfs_background
    {
        return None;
    }
    let target = if entry.is_network() {
        "remote-fs.target"
    } else {
        "local-fs.target"
    };
    Some(target.to_string())
}

/// The device the unit systemd makes for `entry` waits for at its start: the
/// node its spec names (`/dev/...`, or a `UUID=`-style tag as the link udev
/// makes for it), on whose device unit systemd makes the unit depend. A bind,
/// whose spec is a directory, and a swap file wait for no device, and neither
/// does a network filesystem named by its server.
pub fn waits_for(entry: &FstabEntry) -> Option<PathBuf> {
    if entry.is_bind() {
        return None;
    }
    entry
        .device()
        .filter(|device| device != Path::new("/dev/root") && device != Path::new("/dev/nfs"))
}

/// The units systemd's fstab generator has the unit of `entry` pull in that
/// act on its device or filesystem: for an entry on a device its fsck
/// (whatever its pass number: a unit nothing pulls in is skipped for
/// nothing), and its makefs or, for swap, its mkswap (`x-systemd.makefs`);
/// for a mount its growfs (`x-systemd.growfs`), pcrfs (`x-systemd.pcrfs`) and
/// validatefs (`x-systemd.validatefs`), and its quota check and activation (a
/// quota option). The fsck, makefs and mkswap units start before the unit
/// tests its own start condition, so a skip that left them free would have
/// them act on the decoy disk. The others are bound to the mount and ordered
/// after it, so they cannot start while it is skipped: they are skipped with
/// it for caution alone.
pub fn checkers(entry: &FstabEntry) -> Vec<String> {
    let mut units = Vec::new();
    let device = waits_for(entry).map(|device| escape_path(&device));
    if entry.is_swap() {
        if let Some(device) = device.filter(|_| entry.has_option("x-systemd.makefs")) {
            units.push(format!("systemd-mkswap@{device}.service"));
        }
        return units;
    }
    if let Some(device) = device {
        units.push(format!("systemd-fsck@{device}.service"));
        if entry.has_option("x-systemd.makefs") {
            units.push(format!("systemd-makefs@{device}.service"));
        }
    }
    let at = escape_path(&entry.file);
    for (option, template) in [
        ("x-systemd.growfs", "systemd-growfs"),
        ("x-systemd.pcrfs", "systemd-pcrfs"),
        ("x-systemd.validatefs", "systemd-validatefs"),
    ] {
        if entry.has_option(option) {
            units.push(format!("{template}@{at}.service"));
        }
    }
    if QUOTA_OPTIONS.iter().any(|option| entry.has_option(option)) {
        units.push(format!("systemd-quotacheck@{at}.service"));
        units.push(format!("quotaon@{at}.service"));
    }
    units
}

#[cfg(test)]
#[path = "fstab_tests.rs"]
mod tests;
