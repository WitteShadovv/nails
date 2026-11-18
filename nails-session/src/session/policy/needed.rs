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

use super::{Decision, NOAUTO_KEPT, Origin, Present, Units, Unreached, Unskippable, gate};
use crate::session::fstab::{
    FstabEntry, holds_a_backslash, may_be_required_by, mount_unit, unit_name,
};
use crate::session::mount_units::is_unit_name;
use nails_base::hidden_root::separation::unread_fstab_options;
use std::path::{Component, Path, PathBuf};

/// How the unit of one fstab line needs the mount of another, the strongest
/// first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Need {
    /// It requires it by name: `x-systemd.requires=` names it. It does not
    /// start while the mount is masked.
    Requires,
    /// It requires it as the mount for a path: the mount is below it, its
    /// source, a swap file or a path `x-systemd.requires-mounts-for=` names
    /// lies in it. Where the mount is masked, it may start without it:
    /// systemd 260.5 started a mount below a masked mount, and one naming it
    /// in `x-systemd.requires-mounts-for=`, without that mount, and listed no
    /// requirement of it.
    MountsFor,
    /// NAILS cannot tell whether the line pulls it in: an option with a
    /// backslash, which systemd splits otherwise than the parser, or
    /// `x-systemd.requires=` or `x-systemd.wants=` with no value. Taken for
    /// a requirement.
    Unread,
    /// It wants it: `x-systemd.wants-mounts-for=` or `x-systemd.wants=`
    /// names it. A target that requires the line is reached without it.
    Wants,
}

/// A boot target that requires the mount of a `noauto` line through a line
/// it requires itself, or may ([`boot_targets`]).
#[derive(Debug)]
struct Reach {
    /// The target.
    target: String,
    /// The line it requires (its mount point, or a swap's device), which
    /// holds the `noauto` mount up: where the target only wants that line,
    /// the target is reached without the mount.
    line: PathBuf,
    /// Whether the target requires the mount as far as NAILS reads the lines
    /// on the way: each requires the next as NAILS reads it
    /// ([`Need::Requires`], [`Need::MountsFor`]), and the line the target
    /// requires has no option with a backslash, of which NAILS reads neither
    /// what has a target require the line nor what keeps it out of one
    /// ([`holds_a_backslash`]).
    sure: bool,
    /// Whether the line on the way that needs the `noauto` mount names it
    /// ([`Need::Requires`]), so that it does not start while the mount is
    /// masked, rather than requiring it as the mount for a path
    /// ([`Need::MountsFor`]), which may hold nothing up.
    holds: bool,
}

/// The decision for `entries[at]`, a `noauto` line that its decision masks
/// as one nothing requires: the mask of a line
/// nothing NAILS reads pulls in ([`NOAUTO_KEPT`]), or of one kept off for
/// another reason (at or below the hidden root, a network filesystem), where
/// the unit of another line that the boot starts ([`starts`]) needs its mount
/// ([`need`]): the boot mounts that line whatever `noauto` says, so it is kept
/// off as a line the boot mounts is. Every line that needs it is
/// read, and through the lines that require it in turn, every boot target
/// that requires it, or may ([`boot_targets`]): where one does, or may, it is
/// skipped if its device is there, and masked with a warning if not; where
/// none does, it is masked ([`gate`]). Where NAILS reads that a target
/// requires it through a line that names it ([`Need::Requires`]), the
/// warning names those targets and says they will not be reached. Where the
/// lines that need it require it only as the mount for a path
/// ([`Need::MountsFor`]), the warning says the targets may not be reached,
/// and the mask is not recorded as a required one. Where a target only may
/// require it, through an option NAILS does not read or through a line whose
/// options hold a backslash ([`holds_a_backslash`]), the warning says the
/// target may require it, and the mask is not recorded as a required one. The warning names the lines
/// the targets require, or may, that hold the mount up ([`Origin::Needed`]).
/// A line with an option NAILS does not read ([`unread_fstab_options`]) stays
/// masked, as that option may have the boot mount it in other ways too:
/// where a target requires it, or may, the mask names that target
/// ([`Unskippable::Unread`]). `None` where the decision stands.
pub(super) fn needed_below(
    entries: &[FstabEntry],
    decided: &[Decision],
    at: usize,
    present: Present<'_>,
) -> Option<Decision> {
    let entry = &entries[at];
    let Decision::Mask {
        reason: kept_for,
        units: masked,
        unreached: None,
        ..
    } = &decided[at]
    else {
        return None;
    };
    if !entry.is_noauto() {
        return None;
    }
    let unread = !unread_fstab_options(entry).is_empty();
    let needers = needers(entries, decided, at);
    // The reason names a line that requires it, one the boot surely starts
    // (not `noauto`) and that requires it as NAILS reads it where there is
    // such a line, one without a backslash in its options, which may hide a
    // `noauto`, before one with, and one a target requires, or may, among
    // those.
    let &(other, how) = needers
        .iter()
        .filter(|(_, how)| *how != Need::Wants)
        .min_by_key(|(other, how)| {
            let line = &entries[*other];
            (
                !matches!(how, Need::Requires | Need::MountsFor) || line.is_noauto(),
                holds_a_backslash(line),
                may_be_required_by(line).is_none(),
            )
        })
        .or_else(|| needers.first())?;
    let mut reached = Vec::new();
    boot_targets(
        entries,
        decided,
        at,
        (true, None),
        &mut vec![(at, true, true)],
        &mut reached,
    );
    let may_require = !reached.iter().any(|reach| reach.sure);
    // Where a target surely requires the mount, the targets a line that
    // names it holds up are named, else those a line requires as the mount
    // for a path, which may not be held up.
    let held = reached.iter().any(|reach| reach.sure && reach.holds);
    let by_path = !may_require && !held;
    let mut targets: Vec<String> = Vec::new();
    let mut lines: Vec<PathBuf> = Vec::new();
    for reach in reached
        .into_iter()
        .filter(|reach| may_require || (reach.sure && (reach.holds || !held)))
    {
        if !targets.contains(&reach.target) {
            targets.push(reach.target);
        }
        if !lines.contains(&reach.line) {
            lines.push(reach.line);
        }
    }
    let units = Units {
        required_by: (!targets.is_empty()).then(|| targets.join(" and ")),
        origin: Origin::Needed {
            lines,
            may: may_require,
            by_path,
        },
        ..Units::of(entry)
    };
    let line = &entries[other];
    // A noauto line starts only where an option NAILS does not read may
    // have it start, and a backslash may hide a noauto.
    let may = how == Need::Unread || line.is_noauto() || holds_a_backslash(line);
    let needs = format!(
        "the line for {} {}, so the boot {} it",
        line.file.display(),
        if how == Need::Unread {
            "gives an option NAILS cannot read that may pull in its mount"
        } else {
            "needs its mount"
        },
        if may { "may mount" } else { "mounts" }
    );
    // The reason it was kept off for leads where there is one.
    let reason = if kept_for == NOAUTO_KEPT {
        format!("noauto, but {needs}")
    } else {
        format!("{kept_for}, and {needs}")
    };
    if unread {
        // An option NAILS does not read may have the boot mount it in other
        // ways too: the mask stands, and the targets that require the line
        // that needs it, or may, are named.
        let target = units.required_by?;
        return Some(Decision::Mask {
            target: entry.file.clone(),
            units: masked.clone(),
            reason: reason.into(),
            unreached: Some(Unreached {
                target,
                cause: Unskippable::Unread,
                origin: units.origin,
            }),
        });
    }
    // Only a mount starts: a swap is always kept off.
    let mut decision = gate(
        entry.file.clone(),
        vec![mount_unit(&entry.file)],
        entry,
        &units,
        reason.into(),
        present,
    );
    if let Decision::Skip { may, .. } = &mut decision {
        *may = may_require || by_path;
    }
    Some(decision)
}

/// What makes a boot target want the fstab `lines` that hold up a `noauto`
/// mount rather than require them ([`Origin::Needed`], [`Decision::warning`]): `nofail`, or, where
/// a line names the target with `x-systemd.required-by=`, which `nofail` does
/// not change, `x-systemd.wanted-by=` in its place.
pub(super) fn wanted_remedy(lines: &[PathBuf]) -> String {
    let names: Vec<String> = lines.iter().map(|l| l.display().to_string()).collect();
    let (entries, they) = if names.len() > 1 {
        ("entries", "they give")
    } else {
        ("entry", "it gives")
    };
    format!(
        "give the fstab {entries} for {} the nofail option (x-systemd.wanted-by= in place of an \
         x-systemd.required-by= {they})",
        names.join(" and ")
    )
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

/// Add to `reached` the boot targets that require the mount of
/// `entries[at]`, or may: those that require a line that requires it, or
/// that requires a line that does in turn, as far as such lines lead, each
/// with the line it requires, whether NAILS reads every step as a
/// requirement (the first of `path`, for the steps up to `entries[at]`,
/// [`Reach::sure`]) and whether the first step, from the line that needs the
/// `noauto` mount, names it (the second of `path`, `None` before that step,
/// [`Reach::holds`]). A target requires a line with a backslash in its
/// options only as far as NAILS can tell, whatever `nofail`, `noauto` or
/// `x-systemd.wanted-by=` it reads on it ([`holds_a_backslash`],
/// [`may_be_required_by`]); a line that requires such a line requires it
/// all the same, and that line requires what it names before its first
/// option with a backslash ([`need`]). So the backslash makes only the
/// target's own step a may. `seen` holds the lines read already, and whether
/// they were read as sure and as holding: a line read again as either where
/// it was not is read through once more.
fn boot_targets(
    entries: &[FstabEntry],
    decided: &[Decision],
    at: usize,
    path: (bool, Option<bool>),
    seen: &mut Vec<(usize, bool, bool)>,
    reached: &mut Vec<Reach>,
) {
    let (sure, holds) = path;
    for (other, how) in needers(entries, decided, at) {
        if how == Need::Wants {
            continue;
        }
        let line = &entries[other];
        // A line another one requires starts, `noauto` or not.
        let sure = sure && matches!(how, Need::Requires | Need::MountsFor);
        let holds = holds.unwrap_or(how == Need::Requires);
        if seen.iter().any(|&(read, was_sure, did_hold)| {
            read == other && (was_sure || !sure) && (did_hold || !holds)
        }) {
            continue;
        }
        seen.push((other, sure, holds));
        if let Some(target) = may_be_required_by(line) {
            reached.push(Reach {
                target,
                line: if line.is_swap() {
                    PathBuf::from(&line.spec)
                } else {
                    line.file.clone()
                },
                sure: sure && !holds_a_backslash(line),
                holds,
            });
        }
        boot_targets(entries, decided, other, (sure, Some(holds)), seen, reached);
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
    let left = matches!(
        decision,
        Decision::Leave { .. } | Decision::ReadOnlyBind { .. } | Decision::Overlay { .. }
    );
    left && (!line.is_noauto() || !unread_fstab_options(line).is_empty())
}

/// How the unit of the fstab line `line` needs the mount of the line
/// `entry`, the strongest way it does ([`Need`]); `None` where it does not.
/// systemd reads the options before the first one with a backslash as the
/// parser splits them, and may join any after it to that one: an option
/// there that names the mount only may ([`Need::Unread`]).
fn need(line: &FstabEntry, entry: &FstabEntry) -> Option<Need> {
    let dir = entry.file.as_path();
    if entry.is_swap() || !dir.is_absolute() {
        return None;
    }
    let unit = mount_unit(dir);
    let mut needs: Vec<Need> = Vec::new();
    if !line.is_swap() && line.file != dir && line.file.starts_with(dir) {
        needs.push(Need::MountsFor);
    }
    if line.spec.starts_with('/') && Path::new(&line.spec).starts_with(dir) {
        needs.push(Need::MountsFor);
    }
    let mut after_a_backslash = false;
    for option in &line.options {
        if option.contains('\\') {
            needs.push(Need::Unread);
            after_a_backslash = true;
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
            Some(true) if after_a_backslash => needs.push(Need::Unread),
            Some(true) if wanted => needs.push(Need::Wants),
            Some(true) if by_path => needs.push(Need::MountsFor),
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
            unit_name(path, ".device")
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
