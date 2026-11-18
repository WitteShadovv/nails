// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `/etc/fstab` as the hidden systemd will read it, and systemd's unit names.
//!
//! The hidden root runs the fstab of its own `/etc`: the decoy's, one a hidden
//! session wrote over it, or on NixOS the hidden toplevel's, which a build
//! brings or the last activation linked. `systemd-fstab-generator` turns
//! every entry into a `.mount` or `.swap` unit, so the session policy
//! ([`super::policy`]) needs the same view of it, plus the unit names it would
//! generate, what requires each unit at boot ([`required_by`]), the device it
//! waits for ([`waits_for`]) and the units it pulls in that act on that device
//! ([`checkers`]), to overlay, bind, skip or mask each entry before the
//! switch. The parser is [`nails_base::fstab`], re-exported here; the unit
//! names are the session's own.
//!
//! The options are read by their names, alone or with a value, as systemd's
//! fstab generator reads them ([`FstabEntry::has_named`],
//! [`FstabEntry::yes_no_option`]): `noauto,auto=1` is `auto`, `nofail=1` is
//! `nofail`, and `x-systemd.makefs=1` has the mount pull in its makefs. The
//! policy leaves a line alone as never mounted only where NAILS reads every
//! option it gives
//! ([`unread_fstab_options`](nails_base::hidden_root::separation::unread_fstab_options)).
//!
//! That parser reads some lines otherwise than systemd's fstab generator
//! does, as it splits a line at any whitespace and undoes other escapes.
//! [`entry_lines`] gives the lines glibc reads as entries, which libmount
//! reads alike or skips, or the first either may read otherwise. An entry
//! without a build reads the next root's own fstab through it and refuses
//! such a line ([`super::entry`]); the decoy's fstab and the one a hidden
//! build brings are parsed as they are.

use std::path::{Path, PathBuf};

mod lines;

pub use lines::{Field, Unlike, entry_lines};
pub use nails_base::fstab::{
    FstabEntry, any_named, escape_path, is_bind_option, is_host_share_type, is_virtual_type,
    option_named, parse_fstab, spec_device,
};

/// The `/etc/fstab` of the root at `root`, read as that root resolves it
/// ([`read_in_root`](nails_teardown::whole_root::nextroot::read_in_root)).
/// A root without one has no entries; any other error is returned, never
/// taken for an empty fstab, which would leave every entry undecided.
pub fn read_in_root(root: &Path) -> std::io::Result<Vec<u8>> {
    read_fstab_in_root(root, Path::new("/etc/fstab"))
}

/// The entries of the fstab that the NixOS toplevel `system` brings,
/// `<system>/etc/fstab`, which its activation links as `/etc/fstab`: read in
/// the root at `root`, whose store holds `system`, as [`read_in_root`] reads
/// `/etc/fstab`, and resolved there ([`parse_in_root`]). The entry decides
/// them before it activates the toplevel.
pub fn of_system_in_root(root: &Path, system: &Path) -> std::io::Result<Vec<FstabEntry>> {
    let text = read_fstab_in_root(root, &system.join("etc/fstab"))?;
    Ok(parse_in_root(&text, root))
}

/// The fstab at `path` in the root at `root` ([`read_in_root`]).
fn read_fstab_in_root(root: &Path, path: &Path) -> std::io::Result<Vec<u8>> {
    match nails_teardown::whole_root::nextroot::read_in_root(root, path) {
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
    parse_in_root_guarded(text, root, None)
}

/// [`parse_in_root`], with each resolution asked of `guard` first, for a check
/// that reads the running system: a mount point at a direct automount point
/// that nothing is mounted on yet resolves to that point without a lookup
/// (an `x-systemd.automount` line keeps its path, as systemd mounts nothing
/// there before the switch), and one the guard does not resolve is kept as
/// it is written, while the guard keeps that lookup in its ledger.
pub fn parse_in_root_guarded(
    text: &[u8],
    root: &Path,
    guard: Option<super::mount_units::Guard<'_>>,
) -> Vec<FstabEntry> {
    use crate::filesystem::automount::Lookup;
    let mut entries = parse_fstab(&String::from_utf8_lossy(text));
    for entry in &mut entries {
        // A relative mount point (swap's `none`) comes back as it is.
        let asked = match guard {
            Some(guard) if entry.file.is_absolute() => {
                guard.ask(root, &entry.file, Lookup::Resolves { follow: true })
            }
            _ => Ok(None),
        };
        entry.file = match asked {
            Ok(None) => nails_teardown::whole_root::nextroot::canonical_in_root(root, &entry.file),
            // The point's own path, as the root sees it.
            Ok(Some(point)) => Path::new("/").join(point.strip_prefix(root).unwrap_or(&point)),
            Err(_) => entry.file.clone(),
        };
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
/// fstab generator has the mount pull in its quota check and activation. It
/// reads them by their names: `usrjquota=aquota.user`, the only form ext4
/// takes for a journaled quota, is `usrjquota` to it.
const QUOTA_OPTIONS: &[&str] = &[
    "usrquota",
    "grpquota",
    "quota",
    "usrjquota",
    "grpjquota",
    "prjquota",
];

/// The starts of the names of systemd's own options. systemd reads no other
/// option for what a line's units pull in, only flags it names (`noauto`,
/// `nofail`, `_netdev`, `bg`, `loop`, the quota options), which the session
/// reads by their names too ([`required_by`], [`checkers`],
/// [`super::mount_units`]). systemd 260.5's fstab generator wrote nothing for
/// the options of `mount.nfs` and `mount.cifs` (`hard`, `vers=4.2`, `uid=`),
/// `X-mount.subdir=` or `jqfmt=` on a test root.
const SYSTEMD_NAMESPACES: &[&str] = &["x-systemd.", "x-initrd."];

/// The options of systemd's own namespaces whose effect on what the units of
/// a line pull in the session reads: the units and paths they name, which a
/// skip's walk follows ([`super::mount_units`]), the units that link the line
/// in ([`required_by`]), the checkers they pull in ([`checkers`]), the
/// automount ([`FstabEntry::is_automount`]), and those that pull in nothing,
/// as systemd 260.5's fstab generator wrote them on a test root: an order
/// (`x-systemd.before=`, `after=`), a timeout, `x-systemd.rw-only`,
/// `x-systemd.device-bound`, `x-systemd.graceful-option=` and
/// `x-initrd.mount`.
const READ_SYSTEMD_OPTIONS: &[&str] = &[
    "x-systemd.requires",
    "x-systemd.wants",
    "x-systemd.requires-mounts-for",
    "x-systemd.wants-mounts-for",
    "x-systemd.wanted-by",
    "x-systemd.required-by",
    "x-systemd.automount",
    "x-systemd.makefs",
    "x-systemd.growfs",
    "x-systemd.pcrfs",
    "x-systemd.validatefs",
    "x-systemd.before",
    "x-systemd.after",
    "x-systemd.device-timeout",
    "x-systemd.mount-timeout",
    "x-systemd.idle-timeout",
    "x-systemd.rw-only",
    "x-systemd.device-bound",
    "x-systemd.graceful-option",
    "x-initrd.mount",
];

/// Whether the session reads what the option `option` has the units of its
/// line pull in: not for one that holds a backslash, as systemd keeps a
/// comma after a backslash in the option and reads `\054` as a comma, so it
/// splits such options otherwise than the parser; nor for one of systemd's
/// own namespaces that is not in [`READ_SYSTEMD_OPTIONS`]; for any other
/// option, which systemd does not read for what a unit pulls in, or reads as
/// a flag the session reads too ([`SYSTEMD_NAMESPACES`]). A double quote
/// changes nothing there: systemd 260.5's fstab generator split
/// `comment="x,x-systemd.makefs,y"` at every comma, as the parser does, and
/// had the mount pull in its makefs.
pub fn reads_pulls_of(option: &str) -> bool {
    if option.contains('\\') {
        return false;
    }
    !SYSTEMD_NAMESPACES
        .iter()
        .any(|namespace| option.starts_with(namespace))
        || READ_SYSTEMD_OPTIONS
            .iter()
            .any(|name| option_named(option, name).is_some())
}

/// The target that requires a `_netdev` swap line: the fstab generator links
/// every swap into `swap.target` up to systemd 260, and a `_netdev` one into
/// `remote-fs.target` from 261 on. Which systemd the hidden session runs is
/// not told here, so both are named.
const NETDEV_SWAP_TARGET: &str = "swap.target (remote-fs.target from systemd 261)";

/// What requires the unit systemd's fstab generator makes for `entry` (its
/// automount, if it has one) at boot, as the generator links it: the entry's
/// boot target ([`boot_target`]); or the units its `x-systemd.required-by=`
/// options name, which then take the target's place, `noauto` or not. `None`
/// when nothing requires it: `nofail` (the target only wants the unit),
/// `noauto` without an automount and without a unit named to pull it in
/// (nothing pulls it in), `x-systemd.wanted-by=` alone, or an NFS `bg` mount,
/// which the generator makes `nofail`. It reads the options as the parser
/// splits them, which systemd does otherwise where one holds a backslash
/// ([`may_be_required_by`]).
pub fn required_by(entry: &FstabEntry) -> Option<String> {
    if entry.is_swap() {
        if entry.yes_no_option("noauto", "auto") || entry.is_nofail() {
            return None;
        }
        return Some(boot_target(entry).to_string());
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
        return Some(required.join(" and "));
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
    Some(boot_target(entry).to_string())
}

/// The target the fstab generator links the unit of `entry` into when
/// nothing names another: `swap.target` for swap ([`NETDEV_SWAP_TARGET`] for
/// a `_netdev` swap), `remote-fs.target` for a network filesystem,
/// `local-fs.target` for any other.
pub fn boot_target(entry: &FstabEntry) -> &'static str {
    if entry.is_swap() {
        if entry.has_named("_netdev") {
            NETDEV_SWAP_TARGET
        } else {
            "swap.target"
        }
    } else if entry.is_network() {
        "remote-fs.target"
    } else {
        "local-fs.target"
    }
}

/// Whether an option of the fstab line `entry` holds a backslash, anywhere in
/// it: NAILS then cannot read the line's options as systemd does. The parser
/// splits the options at every comma and decodes nothing in them; systemd
/// keeps a comma after a backslash in the option and reads `\054` as a comma.
/// So the `noauto`, `nofail`, `x-systemd.wanted-by=` or
/// `x-systemd.required-by=` NAILS reads may be none to systemd, and one NAILS
/// does not read may hide in another option: systemd 260.5's fstab generator
/// linked the mounts of `comment=x\,nofail` and
/// `comment=x\,x-systemd.wanted-by=foo.service` into
/// `local-fs.target.requires` and a swap with `sw,comment=x\,noauto` into
/// `swap.target.requires`, and read `comment=x\054nofail` as `nofail`. The
/// session policy reads such a line, where it keeps it off (other than one
/// for `/usr`) and where it needs a `noauto` line's mount, as one a target
/// may require, never as one a target surely requires or one nothing
/// requires ([`super::policy`], [`may_be_required_by`]).
pub fn holds_a_backslash(entry: &FstabEntry) -> bool {
    entry.options.iter().any(|option| option.contains('\\'))
}

/// What requires the unit systemd's fstab generator makes for `entry` at
/// boot, or may: what [`required_by`] reads, or, where it reads nothing and
/// an option of the line holds a backslash ([`holds_a_backslash`]), the
/// line's [`boot_target`], which the generator links the unit into where the
/// `noauto`, `nofail` or `x-systemd.wanted-by=` NAILS reads is none to it,
/// and a line for `/` or `/usr` into whatever its options say: it ignored
/// `noauto`, `nofail`, `x-systemd.automount`, `x-systemd.wanted-by=` and
/// `x-systemd.required-by=` on `/usr`.
pub fn may_be_required_by(entry: &FstabEntry) -> Option<String> {
    required_by(entry).or_else(|| holds_a_backslash(entry).then(|| boot_target(entry).to_string()))
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
        if let Some(device) = device.filter(|_| entry.has_named("x-systemd.makefs")) {
            units.push(format!("systemd-mkswap@{device}.service"));
        }
        return units;
    }
    if let Some(device) = device {
        units.push(format!("systemd-fsck@{device}.service"));
        if entry.has_named("x-systemd.makefs") {
            units.push(format!("systemd-makefs@{device}.service"));
        }
    }
    let at = escape_path(&entry.file);
    for (option, template) in [
        ("x-systemd.growfs", "systemd-growfs"),
        ("x-systemd.pcrfs", "systemd-pcrfs"),
        ("x-systemd.validatefs", "systemd-validatefs"),
    ] {
        if entry.has_named(option) {
            units.push(format!("{template}@{at}.service"));
        }
    }
    if any_named(&entry.options, QUOTA_OPTIONS) {
        units.push(format!("systemd-quotacheck@{at}.service"));
        units.push(format!("quotaon@{at}.service"));
    }
    units
}

#[cfg(test)]
#[path = "fstab_tests.rs"]
mod tests;
