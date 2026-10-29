// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The noise-subtracted residue: what changed from `before` to `after` that the
//! clean control cycle does not also show.
//!
//! A change goes either way. A finding new in `after` is residue unless the
//! control cycle has it too; a finding `before` and the control cycle both have
//! is residue when `after` lost it, since a plain reboot kept it. The restore
//! channel holds one entry per path ([`Tool::one_entry_per_path`]), so it is
//! compared path by path: a path whose entry `after` holds differently is
//! residue when `before` and the control cycle agree on it, and noise when the
//! control cycle changed it too, a file a plain reboot rewrites. Such a path is
//! kept apart when `after` holds there what neither of the others does: the
//! verdict could not judge that content and names the path as unseen (see
//! [`crate::unseen`]). The records and features of the other channels have no
//! such slot: each one is its own trace, subtracted only by the same record or
//! value in the control cycle.
//!
//! A carved login record is also subtracted by a record of the same key in
//! the control image's login files, read whole
//! ([`Scans::control_login_records`]). bulk_extractor carves only what is
//! stored plain, so on a filesystem that compresses, the records a compressed
//! extent holds in the control image are not carved there, and the same kind
//! of record written later into a plain block of `after` would otherwise
//! read as new. The keys must match exactly: a record of another type,
//! process range, terminal, id, user, host, exit status or address that only
//! `after` holds is residue as before.

use crate::carved::UTMP_CARVED;
use crate::model::{Change, Finding, Scans, Tool};
use std::collections::{BTreeMap, BTreeSet};

/// The residue of one run, with the counts that reconcile it.
pub(crate) struct Residue<'a> {
    /// Changes from `before` to `after`: residue and noise together.
    pub candidate: usize,
    /// Of those, the ones the control cycle shows too.
    pub noise_subtracted: usize,
    /// The residue, each finding with how it changed, in a fixed order.
    pub items: Vec<(&'a Finding, Change)>,
    /// The restore paths subtracted as noise although `after` holds there what
    /// neither `before` nor the control cycle does, in path order: files a
    /// plain reboot rewrites, whose content in `after` nothing explains.
    pub rewritten: Vec<&'a str>,
}

/// Compute the residue of `scans`.
pub(crate) fn compute_residue(scans: &Scans) -> Residue<'_> {
    let mut residue = Residue {
        candidate: 0,
        noise_subtracted: 0,
        items: Vec::new(),
        rewritten: Vec::new(),
    };
    records_residue(scans, &mut residue);
    entries_residue(scans, &mut residue);
    residue.items.sort();
    residue.candidate = residue.noise_subtracted + residue.items.len();
    residue
}

/// The findings in `set` of the channels that report many findings per path.
fn records(set: &BTreeSet<Finding>) -> BTreeSet<&Finding> {
    set.iter()
        .filter(|f| !f.tool.one_entry_per_path())
        .collect()
}

/// Whether `f` is a carved login record whose key the control image's login
/// files hold (see [`Scans::control_login_records`]).
fn in_control_login_records(scans: &Scans, f: &Finding) -> bool {
    f.tool == Tool::BulkExtractor
        && f.path == UTMP_CARVED
        && scans.control_login_records.contains(&f.field)
}

/// Compare the many-findings-per-path channels finding by finding: one new in
/// `after` is residue unless the control cycle has it too, carved or, for a
/// login record, in its login files, and one `before` and the control cycle
/// both have is residue when `after` lost it.
fn records_residue<'a>(scans: &'a Scans, residue: &mut Residue<'a>) {
    let before = records(&scans.before);
    let control = records(&scans.control);
    let after = records(&scans.after);
    for &f in after.difference(&before) {
        if control.contains(f) || in_control_login_records(scans, f) {
            residue.noise_subtracted += 1;
        } else {
            residue.items.push((f, Change::Added));
        }
    }
    for &f in before.difference(&after) {
        if control.contains(f) {
            residue.items.push((f, Change::Removed));
        } else {
            residue.noise_subtracted += 1;
        }
    }
}

/// The findings in `set` of the one-entry-per-path channels, by tool and path.
fn entries(set: &BTreeSet<Finding>) -> BTreeMap<(Tool, &str), BTreeSet<&Finding>> {
    let mut by_path: BTreeMap<(Tool, &str), BTreeSet<&Finding>> = BTreeMap::new();
    for f in set.iter().filter(|f| f.tool.one_entry_per_path()) {
        by_path
            .entry((f.tool, f.path.as_str()))
            .or_default()
            .insert(f);
    }
    by_path
}

/// Compare the one-entry-per-path channels path by path. A path that differs
/// counts once, as noise when the control cycle changed it too, and otherwise
/// as residue: the value new in `after` (added at a path `before` lacked, or
/// changed), or the value `after` lost. A noise path where `after` matches
/// neither `before` nor the control cycle is also recorded as rewritten.
fn entries_residue<'a>(scans: &'a Scans, residue: &mut Residue<'a>) {
    let none = BTreeSet::new();
    let before = entries(&scans.before);
    let control = entries(&scans.control);
    let after = entries(&scans.after);
    let paths: BTreeSet<&(Tool, &str)> = before
        .keys()
        .chain(control.keys())
        .chain(after.keys())
        .collect();
    for path in paths {
        let b = before.get(path).unwrap_or(&none);
        let c = control.get(path).unwrap_or(&none);
        let a = after.get(path).unwrap_or(&none);
        if a == b {
            continue;
        }
        if b != c {
            residue.noise_subtracted += 1;
            if a != c {
                residue.rewritten.push(path.1);
            }
            continue;
        }
        let new: Vec<&Finding> = a.difference(b).copied().collect();
        if new.is_empty() {
            let gone = b.difference(a).map(|&f| (f, Change::Removed));
            residue.items.extend(gone);
        } else {
            let change = if b.is_empty() {
                Change::Added
            } else {
                Change::Changed
            };
            residue.items.extend(new.into_iter().map(|f| (f, change)));
        }
    }
}
