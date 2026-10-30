// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The mounts a skipped unit pulls in.
//!
//! A skipped unit gets its start job, and PID 1 starts what it requires and
//! wants before it tests the unit's condition. Among those can be a mount, a
//! swap or an automount: the mount unit of each parent directory of a mount
//! or automount (or of a swap file) that has a unit file of its own, which
//! systemd has it require, also the unit of a `noauto` fstab line; the units
//! its unit files name in `Requires=`, `BindsTo=`, `Wants=` or `Upholds=`, or
//! link in its `.requires`, `.wants` or `.upholds` directory; the mount units
//! of the paths, and their parents, of its `RequiresMountsFor=` and
//! `WantsMountsFor=`; and those its fstab line names with
//! `x-systemd.requires=`, `x-systemd.requires-mounts-for=` or
//! `x-systemd.wants-mounts-for=` ([`mount_pulls`]).
//!
//! The hidden systemd would mount such a filesystem read-write from the
//! decoy's disk unless the session keeps it off or puts it in place
//! ([`fate`]), so a skip that pulls one in is masked instead
//! ([`super::kept_off`]). One the session masks keeps a unit that requires it
//! from starting, and the boot target with it: that is warned of.

use super::unit_dirs::{Load, UnitDirs};
use super::unit_file::without_specifiers;
use super::unit_path;
use crate::session::fstab::{FstabEntry, is_virtual_type, mount_unit};
use crate::session::policy::Units;
use nails_teardown::whole_root::runtime_units::valid_unit_name;
use std::path::Path;

/// A mount, swap or automount unit a unit pulls in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pull {
    /// The unit pulled in.
    pub unit: String,
    /// Whether the unit that pulls it in requires it, and so does not start
    /// without it, rather than only wanting it.
    pub required: bool,
    /// How it is pulled in, for a warning.
    pub how: &'static str,
}

/// What becomes of a mount, swap or automount unit that a skipped unit
/// pulls in ([`fate`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// Nothing of a decoy disk: the session puts its mount point in place
    /// or skips it, it mounts the root, a RAM or kernel filesystem or a host
    /// share, or it does not load.
    Fine,
    /// The session masks it: a unit that requires it does not start.
    Masked,
    /// The hidden systemd would mount it, or swap onto it, from the decoy's
    /// disk: nothing keeps it off.
    Mounted,
}

/// Whether `name` is a mount, swap or automount unit.
fn is_storage_unit(name: &str) -> bool {
    [".mount", ".swap", ".automount"]
        .iter()
        .any(|suffix| name.ends_with(suffix))
}

/// The mount units of `path` and of each of its parents, the root's left
/// out (the root overlay is always there): what a `RequiresMountsFor=` of
/// `path` requires, as far as such units exist.
pub fn mounts_for(path: &Path) -> Vec<String> {
    path.ancestors()
        .filter(|dir| *dir != Path::new("/"))
        .map(mount_unit)
        .collect()
}

/// The parents of the mount point (or swap file) the unit `name` stands
/// for, whose mount units systemd has it require.
fn parent_mounts(name: &str) -> Vec<String> {
    let path = [".mount", ".automount"]
        .iter()
        .find_map(|suffix| unit_path(name, suffix))
        .or_else(|| unit_path(name, ".swap").filter(|path| !path.starts_with("/dev")));
    path.as_deref()
        .and_then(Path::parent)
        .map(mounts_for)
        .unwrap_or_default()
}

/// The units a value of `x-systemd.requires=` names: a unit, or the mount
/// unit of a mount point (a device node names a device unit, no mount).
fn required_by_option(value: &str) -> Option<String> {
    if value.starts_with("/dev/") {
        None
    } else if value.starts_with('/') {
        Some(mount_unit(Path::new(value)))
    } else {
        Some(value.to_string())
    }
}

/// The mount, swap and automount units the unit `name` pulls in when it
/// starts (see the module docs), each once, its own and the root's left
/// out. `fstab` holds the decided fstab lines, whose options the line that
/// makes `name` adds. `Err` with the reason when NAILS cannot tell them all:
/// its unit files cannot be read or name a unit or path by a specifier it
/// does not resolve, or a directory of its links cannot be listed.
pub fn mount_pulls(
    dirs: UnitDirs<'_>,
    name: &str,
    fstab: &[FstabEntry],
) -> Result<Vec<Pull>, &'static str> {
    let mut pulls: Vec<Pull> = Vec::new();
    let mut add = |unit: String, required: bool, how: &'static str| {
        if !is_storage_unit(&unit) || unit == name || unit == "-.mount" || !valid_unit_name(&unit) {
            return;
        }
        match pulls.iter_mut().find(|pull| pull.unit == unit) {
            Some(pull) if required && !pull.required => {
                pull.required = true;
                pull.how = how;
            }
            Some(_) => {}
            None => pulls.push(Pull {
                unit,
                required,
                how,
            }),
        }
    };
    for parent in parent_mounts(name) {
        add(parent, true, "the mount of a parent directory");
    }
    match dirs.load(name) {
        Load::Loaded { unit, .. } => {
            for (key, required, how) in [
                ("Requires", true, "its Requires="),
                ("BindsTo", true, "its BindsTo="),
                ("Wants", false, "its Wants="),
                ("Upholds", false, "its Upholds="),
            ] {
                for value in unit.values("Unit", key) {
                    for word in value.split_ascii_whitespace() {
                        let word = without_specifiers(word).ok_or(super::UNRESOLVED_PULL)?;
                        add(word, required, how);
                    }
                }
            }
            for (key, required, how) in [
                ("RequiresMountsFor", true, "its RequiresMountsFor="),
                ("WantsMountsFor", false, "its WantsMountsFor="),
            ] {
                for value in unit.values("Unit", key) {
                    for word in value.split_ascii_whitespace() {
                        let path = without_specifiers(word).ok_or(super::UNRESOLVED_PULL)?;
                        for mount in mounts_for(Path::new(&path)) {
                            add(mount, required, how);
                        }
                    }
                }
            }
        }
        Load::Unreadable => return Err(super::UNREADABLE),
        Load::Masked | Load::Missing => {}
    }
    for (kind, required, how) in [
        ("requires", true, "a link in its .requires directory"),
        ("wants", false, "a link in its .wants directory"),
        ("upholds", false, "a link in its .upholds directory"),
    ] {
        for unit in dirs
            .list(&format!("{name}.{kind}"))
            .map_err(|_| super::UNLISTED_PULL)?
        {
            add(unit, required, how);
        }
    }
    for entry in fstab.iter().filter(|entry| {
        let units = Units::of(entry);
        units.unit.as_deref() == Some(name) || units.automount.as_deref() == Some(name)
    }) {
        for option in &entry.options {
            if let Some(value) = option.strip_prefix("x-systemd.requires=") {
                if let Some(unit) = required_by_option(value) {
                    add(unit, true, "x-systemd.requires= on its fstab line");
                }
            } else if let Some(path) = option.strip_prefix("x-systemd.requires-mounts-for=") {
                for mount in mounts_for(Path::new(path)) {
                    add(
                        mount,
                        true,
                        "x-systemd.requires-mounts-for= on its fstab line",
                    );
                }
            } else if let Some(path) = option.strip_prefix("x-systemd.wants-mounts-for=") {
                for mount in mounts_for(Path::new(path)) {
                    add(
                        mount,
                        false,
                        "x-systemd.wants-mounts-for= on its fstab line",
                    );
                }
            }
        }
    }
    Ok(pulls)
}

/// What becomes of the unit `pull` in the hidden session when a skipped unit
/// pulls it in, given `covered`, the units the session's decisions keep off
/// or put in place, `masks`, those it masks, and `fstab`, the decided lines
/// (see [`Fate`]). A unit no decision covers is judged by what its fstab
/// line or its unit files mount; one whose files cannot be read counts as
/// one that mounts a disk.
pub fn fate(
    dirs: UnitDirs<'_>,
    pull: &str,
    covered: &[String],
    masks: &[String],
    fstab: &[FstabEntry],
) -> Fate {
    if masks.iter().any(|unit| unit == pull) {
        return Fate::Masked;
    }
    if covered.iter().any(|unit| unit == pull) {
        return Fate::Fine;
    }
    let line = fstab.iter().find(|entry| {
        let units = Units::of(entry);
        units.unit.as_deref() == Some(pull) || units.automount.as_deref() == Some(pull)
    });
    if let Some(entry) = line {
        return if entry.is_virtual() || entry.is_host_share() || entry.file == Path::new("/") {
            Fate::Fine
        } else {
            Fate::Mounted
        };
    }
    match dirs.load(pull) {
        Load::Missing | Load::Masked => Fate::Fine,
        Load::Unreadable => Fate::Mounted,
        Load::Loaded { unit, .. } => {
            let ram =
                pull.ends_with(".mount") && unit.last("Mount", "Type").is_some_and(is_virtual_type);
            if ram { Fate::Fine } else { Fate::Mounted }
        }
    }
}
