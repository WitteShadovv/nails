// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `noauto` lines that another line of the same fstab needs. systemd has
//! a mount require the mounts of its parent directories and of its source, a
//! swap those of its file, and a unit those `x-systemd.requires-mounts-for=`
//! and `wants-mounts-for=` name: a `noauto` line with such a path in it is
//! mounted at boot for that other line whatever `noauto` says, and is kept
//! off like any line the boot mounts ([`super::decide_all`]).

use super::{Decision, NEVER_MOUNTED, Origin, Present, Units, gate};
use crate::session::fstab::{FstabEntry, mount_unit, option_named, required_by};
use nails_base::hidden_root::separation::unread_fstab_options;
use std::path::Path;

/// The decision for `entries[at]`, a `noauto` line left alone as never
/// mounted ([`NEVER_MOUNTED`]), where the unit of another line that the boot
/// starts ([`starts`]) needs a path at or below its mount point
/// ([`needs_a_path_in`]): systemd has a mount require the mounts of its
/// parent directories and of its source, a swap those of its file, and a
/// unit those `x-systemd.requires-mounts-for=` and `wants-mounts-for=` name,
/// so the boot mounts that line whatever `noauto` says. The line is kept
/// off: skipped where a boot target requires the other line's unit and the
/// device is there, and masked otherwise ([`gate`]). `None` where the
/// decision stands.
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
    let (other, _) = entries
        .iter()
        .zip(decided)
        .enumerate()
        .find(|(other, (line, decision))| {
            *other != at && starts(line, decision) && needs_a_path_in(line, &entry.file)
        })
        .map(|(_, pair)| pair)?;
    let units = Units {
        required_by: required_by(other),
        origin: Origin::Needed,
        ..Units::of(entry)
    };
    // Only a mount starts: a swap is always kept off.
    let reason = format!(
        "noauto, but the line for {} needs a path in it, so the boot mounts it",
        other.file.display()
    );
    Some(gate(
        entry.file.clone(),
        vec![mount_unit(&entry.file)],
        entry,
        &units,
        reason.into(),
        present,
    ))
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

/// Whether the unit of the fstab line `line` needs the mount of `dir`: its
/// mount point lies below `dir`, or its source, swap file or a path its
/// `x-systemd.requires-mounts-for=` or `wants-mounts-for=` names lies at or
/// below it.
fn needs_a_path_in(line: &FstabEntry, dir: &Path) -> bool {
    let mut paths: Vec<&Path> = Vec::new();
    if !line.is_swap() && line.file != dir {
        paths.push(&line.file);
    }
    if line.spec.starts_with('/') {
        paths.push(Path::new(&line.spec));
    }
    for option in &line.options {
        for name in [
            "x-systemd.requires-mounts-for",
            "x-systemd.wants-mounts-for",
        ] {
            if let Some(Some(path)) = option_named(option, name) {
                paths.push(Path::new(path));
            }
        }
    }
    paths.iter().any(|path| path.starts_with(dir))
}
