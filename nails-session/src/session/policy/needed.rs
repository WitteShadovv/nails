// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `noauto` lines that another line of the same fstab needs. systemd has
//! a mount require the mounts of its parent directories and of its source, a
//! swap those of its file, and a unit those `x-systemd.requires-mounts-for=`
//! names, or want those `x-systemd.wants-mounts-for=` names; the fstab
//! generator has it require the unit `x-systemd.requires=` names, or want the
//! one `x-systemd.wants=` names, a path standing for its mount. A `noauto`
//! line such a line needs is mounted at boot for that other line whatever
//! `noauto` says, and is kept off like any line the boot mounts
//! ([`super::decide_all`]).

use super::{Decision, NEVER_MOUNTED, Origin, Present, Units, gate};
use crate::session::fstab::{FstabEntry, escape_path, mount_unit, required_by};
use crate::session::mount_units::is_unit_name;
use nails_base::hidden_root::separation::unread_fstab_options;
use std::path::{Component, Path};

/// How the unit of one fstab line needs the mount of another, the strongest
/// first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Need {
    /// It requires it, and does not start without it: the mount is below
    /// it, its source, a swap file or a path `x-systemd.requires-mounts-for=`
    /// names lies in it, or `x-systemd.requires=` names it.
    Requires,
    /// NAILS cannot tell whether the line pulls it in: an option with a
    /// backslash, which systemd splits otherwise than the parser, or
    /// `x-systemd.requires=` or `x-systemd.wants=` with no value. Taken for
    /// a requirement.
    Unread,
    /// It wants it: `x-systemd.wants-mounts-for=` or `x-systemd.wants=`
    /// names it. A target that requires the line is reached without it.
    Wants,
}

/// The decision for `entries[at]`, a `noauto` line left alone as never
/// mounted ([`NEVER_MOUNTED`]), where the unit of another line that the boot
/// starts ([`starts`]) needs its mount ([`need`]): the boot mounts that line
/// whatever `noauto` says, so it is kept off. Every line that needs it is
/// read, and through the lines that require it in turn, every boot target
/// that requires it ([`boot_targets`]): where one does, it is skipped if its
/// device is there, and masked with a warning that the target will not be
/// reached if not; where none does, it is masked ([`gate`]). `None` where
/// the decision stands.
pub(super) fn needed_below(
    entries: &[FstabEntry],
    decided: &[Decision],
    at: usize,
    present: Present<'_>,
) -> Option<Decision> {
    let entry = &entries[at];
    if !matches!(&decided[at], Decision::Leave { reason, .. } if *reason == NEVER_MOUNTED) {
        return None;
    }
    let needers = needers(entries, decided, at);
    // The reason names a line that requires it, and one a target requires
    // where there is such a line.
    let &(other, how) = needers
        .iter()
        .filter(|(_, how)| *how != Need::Wants)
        .find(|(other, _)| required_by(&entries[*other]).is_some())
        .or_else(|| needers.iter().find(|(_, how)| *how != Need::Wants))
        .or_else(|| needers.first())?;
    let mut targets = Vec::new();
    boot_targets(entries, decided, at, &mut vec![at], &mut targets);
    let units = Units {
        required_by: (!targets.is_empty()).then(|| targets.join(" and ")),
        origin: Origin::Needed,
        ..Units::of(entry)
    };
    let line = &entries[other];
    // A noauto line starts only where an option NAILS does not read may
    // have it start.
    let may = how == Need::Unread || line.is_noauto();
    let reason = format!(
        "noauto, but the line for {} {}, so the boot {} it",
        line.file.display(),
        if how == Need::Unread {
            "gives an option NAILS cannot read that may pull in its mount"
        } else {
            "needs its mount"
        },
        if may { "may mount" } else { "mounts" }
    );
    // Only a mount starts: a swap is always kept off.
    Some(gate(
        entry.file.clone(),
        vec![mount_unit(&entry.file)],
        entry,
        &units,
        reason.into(),
        present,
    ))
}

/// The lines among `entries`, `entries[at]` aside, that the boot starts
/// ([`starts`]) and whose units need the mount of `entries[at]` ([`need`]),
/// each with how.
fn needers(entries: &[FstabEntry], decided: &[Decision], at: usize) -> Vec<(usize, Need)> {
    entries
        .iter()
        .zip(decided)
        .enumerate()
        .filter(|(other, (line, decision))| *other != at && starts(line, decision))
        .filter_map(|(other, (line, _))| Some((other, need(line, &entries[at])?)))
        .collect()
}

/// Add to `targets` the boot targets that require the mount of
/// `entries[at]`: those that require a line that requires it, or that
/// requires a line that does in turn, as far as such lines lead. `seen`
/// holds the lines read already.
fn boot_targets(
    entries: &[FstabEntry],
    decided: &[Decision],
    at: usize,
    seen: &mut Vec<usize>,
    targets: &mut Vec<String>,
) {
    for (other, how) in needers(entries, decided, at) {
        if how == Need::Wants || seen.contains(&other) {
            continue;
        }
        seen.push(other);
        if let Some(target) = required_by(&entries[other])
            && !targets.contains(&target)
        {
            targets.push(target);
        }
        boot_targets(entries, decided, other, seen, targets);
    }
}

/// Whether the boot starts the unit of the fstab line `line`, which
/// `decision` leaves to the hidden systemd or puts in place: a line that is
/// not `noauto` as systemd reads it, or that gives an option NAILS does not
/// read ([`unread_fstab_options`]). A start job for a unit put in place is
/// still one for what it requires. A `noauto` line nothing pulls in starts
/// nothing; what a skip pulls in is walked in the unit pass
/// ([`super::super::mount_units`]).
fn starts(line: &FstabEntry, decision: &Decision) -> bool {
    let left = match decision {
        Decision::Leave { reason, .. } => *reason != NEVER_MOUNTED,
        Decision::ReadOnlyBind { .. } | Decision::Overlay { .. } => true,
        _ => false,
    };
    left && (!line.is_noauto() || !unread_fstab_options(line).is_empty())
}

/// How the unit of the fstab line `line` needs the mount of the line
/// `entry`, the strongest way it does ([`Need`]); `None` where it does not.
fn need(line: &FstabEntry, entry: &FstabEntry) -> Option<Need> {
    let dir = entry.file.as_path();
    if entry.is_swap() || !dir.is_absolute() {
        return None;
    }
    let unit = mount_unit(dir);
    let mut needs: Vec<Need> = Vec::new();
    if !line.is_swap() && line.file != dir && line.file.starts_with(dir) {
        needs.push(Need::Requires);
    }
    if line.spec.starts_with('/') && Path::new(&line.spec).starts_with(dir) {
        needs.push(Need::Requires);
    }
    for option in &line.options {
        if option.contains('\\') {
            needs.push(Need::Unread);
            continue;
        }
        // A name alone names nothing: systemd 260.5's fstab generator wrote
        // no dependency for `x-systemd.requires`.
        let Some((name, value)) = option.split_once('=') else {
            continue;
        };
        let (wanted, by_path) = match name {
            "x-systemd.requires-mounts-for" => (false, true),
            "x-systemd.wants-mounts-for" => (true, true),
            "x-systemd.requires" => (false, false),
            "x-systemd.wants" => (true, false),
            _ => continue,
        };
        let names_it = if value.is_empty() {
            // The generator refused to make a unit name of it.
            None
        } else if by_path {
            Some(Path::new(value).starts_with(dir))
        } else {
            Some(pulled_unit(value) == unit)
        };
        match names_it {
            None => needs.push(Need::Unread),
            Some(true) if wanted => needs.push(Need::Wants),
            Some(true) => needs.push(Need::Requires),
            Some(false) => {}
        }
    }
    needs.into_iter().min()
}

/// The unit the fstab generator has a unit require or want for the value
/// `value` of `x-systemd.requires=` or `x-systemd.wants=`, as systemd's
/// `unit_name_mangle_with_suffix()` makes it with the suffix `.mount`: an
/// absolute path without a `..` the unit of its device or its mount, and
/// anything else with each `/` read as a `-`, every other character not
/// allowed in a unit name escaped as `\xNN`, and `.mount` added where it
/// has no type of unit. systemd 260.5's generator wrote `Requires=r-a.mount`
/// for `/r//a/`, `r/a` and `r-a`, `Requires=\x25i.mount` for `%i.mount`
/// and `Requires=-r-..-r-a.mount` for `/r/../r/a`. The caller reads a value
/// with a backslash as one it cannot tell.
fn pulled_unit(value: &str) -> String {
    let path = Path::new(value);
    if value.starts_with('/') && !path.components().any(|c| c == Component::ParentDir) {
        return if value.starts_with("/dev/") || value.starts_with("/sys/") {
            format!("{}.device", escape_path(path))
        } else {
            mount_unit(path)
        };
    }
    let mut name = String::new();
    for byte in value.bytes() {
        match byte {
            b'/' => name.push('-'),
            b if b.is_ascii_alphanumeric() || b":-_.@\\".contains(&b) => name.push(char::from(b)),
            b => name.push_str(&format!("\\x{b:02x}")),
        }
    }
    if is_unit_name(&name) {
        name
    } else {
        format!("{name}.mount")
    }
}

#[cfg(test)]
#[path = "needed_tests.rs"]
mod tests;
