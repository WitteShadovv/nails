// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What a skipped unit pulls in.
//!
//! A skipped unit gets its start job, and PID 1 gives a start job to every
//! unit it requires, binds to, wants or upholds, and to what those pull in in
//! turn, before it tests the skip's condition, whether such a unit is active
//! already or not. [`walk`] follows these pulls from a skipped unit as far as
//! they lead, unit by unit ([`edges`]), with the units they start later (a
//! trigger, `OnFailure=`) too.
//!
//! A mount, swap or automount it reaches that the session neither keeps off nor
//! puts in place, and that does not mount the root, a RAM or kernel filesystem
//! or a host share, the hidden systemd would mount from the decoy's disk
//! ([`fate`]): the skip is masked instead ([`super::kept_off`]). So it is where
//! NAILS cannot tell all a unit on the way pulls in: a unit file it cannot
//! read, a specifier it does not resolve, any specifier in an fstab option, a
//! unit that does not load (a generator of the hidden session may make it; a
//! checker of systemd's, which acts on its device alone, aside), a link or a
//! unit directory it cannot read, or a walk deeper or wider than it follows
//! ([`MAX_DEPTH`], [`MAX_UNITS`]). The walk stops at the targets the hidden
//! boot starts anyway ([`boot_targets`](super::deps::boot_targets)), which
//! bring nothing in that the boot does not, and at scopes. A mount the session
//! masks keeps a unit that requires it from starting, and the boot target with
//! it: that is warned of.

use super::deps::{Graph, edges, is_storage_unit, kind, lines_of};
use super::unit_dirs::Load;
use crate::session::fstab::{is_host_share_type, is_virtual_type};
use nails_teardown::whole_root::plan::MaskCause;
use std::collections::VecDeque;
use std::path::Path;

/// How many pulls deep the walk follows a skipped unit.
pub const MAX_DEPTH: usize = 8;

/// How many units the walk from one skipped unit reaches at most.
pub const MAX_UNITS: usize = 256;

/// What becomes of a mount, swap or automount unit the walk reaches
/// ([`fate`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// The session puts its mount point in place or skips it, or it mounts
    /// the root, a RAM or kernel filesystem or a host share: what it pulls
    /// in is followed in turn.
    Fine,
    /// No unit file and no fstab line: PID 1 cannot start it.
    Absent,
    /// The session masks it: a unit that requires it does not start.
    Masked,
    /// The hidden systemd would mount it, or swap onto it, from the decoy's
    /// disk: nothing keeps it off.
    Mounted,
}

/// What becomes of the mount, swap or automount unit `pull` in the hidden
/// session, given `masks`, the units the session masks. A unit no decision
/// covers is judged by what its fstab lines or its unit files mount; one
/// whose files cannot be read counts as one that mounts a disk.
pub fn fate(graph: &Graph<'_>, pull: &str, masks: &[String]) -> Fate {
    if masks.iter().any(|unit| unit == pull) {
        return Fate::Masked;
    }
    let lines = lines_of(graph.fstab, pull);
    let load = graph.dirs.load(pull);
    if matches!(load, Load::Masked) {
        return Fate::Masked;
    }
    if matches!(load, Load::Missing) && lines.is_empty() {
        return Fate::Absent;
    }
    if graph.covered.iter().any(|unit| unit == pull) {
        return Fate::Fine;
    }
    let lines_harmless = lines
        .iter()
        .all(|entry| entry.is_virtual() || entry.is_host_share() || entry.file == Path::new("/"));
    let file_harmless = match load {
        Load::Missing | Load::Masked => true,
        Load::Unreadable => false,
        // A RAM or kernel filesystem, or a host share, as for a line.
        Load::Loaded { unit, .. } => {
            kind(pull) == "mount"
                && unit
                    .last("Mount", "Type")
                    .is_some_and(|vfstype| is_virtual_type(vfstype) || is_host_share_type(vfstype))
        }
    };
    if lines_harmless && file_harmless {
        Fate::Fine
    } else {
        Fate::Mounted
    }
}

/// Why a skip must be masked instead: what the walk found, and the cause
/// that names it ([`MaskCause::PullsInMount`] for a mount it would make,
/// [`MaskCause::Undetermined`] where NAILS cannot tell).
pub type Blocked = (String, MaskCause);

/// A unit the walk reached: its name, the unit it reached it from (`None`
/// for the one it starts at), and how that one pulls it in.
struct Reached {
    unit: String,
    from: Option<usize>,
    how: &'static str,
}

/// How the walk reached `reached[at]` from where it started: `a (how), which
/// pulls in b (how)`.
fn chain(reached: &[Reached], at: usize) -> String {
    let mut steps: Vec<String> = Vec::new();
    let mut current = Some(at);
    while let Some(index) = current {
        let step = &reached[index];
        if step.from.is_some() {
            steps.push(format!("{} ({})", step.unit, step.how));
        }
        current = step.from;
    }
    steps.reverse();
    steps.join(", which pulls in ")
}

/// Walk the pulls of the skipped unit `start` (see the module docs), given
/// `masks`, the units the session masks. `Ok` with the masked units `start`
/// requires through a chain of requirements, each with that chain: they
/// keep it from starting. `Err` when the skip must be masked instead.
pub fn walk(graph: &Graph<'_>, start: &str, masks: &[String]) -> Result<Vec<String>, Blocked> {
    let mut reached = vec![Reached {
        unit: start.to_string(),
        from: None,
        how: "",
    }];
    let mut queue: VecDeque<(usize, usize, bool)> = VecDeque::from([(0, 0, true)]);
    let mut masked_required: Vec<String> = Vec::new();
    let unknown = |why: String| (why, MaskCause::Undetermined);
    while let Some((at, depth, required)) = queue.pop_front() {
        let unit = reached[at].unit.clone();
        if at != 0 {
            if is_storage_unit(&unit) {
                match fate(graph, &unit, masks) {
                    Fate::Masked => {
                        if required {
                            masked_required.push(chain(&reached, at));
                        }
                        continue;
                    }
                    Fate::Absent => continue,
                    Fate::Mounted => {
                        return Err((
                            format!(
                                "{start} pulls in {}, which the session does not keep off, and \
                                 the hidden systemd would mount it from the decoy's disk",
                                chain(&reached, at)
                            ),
                            MaskCause::PullsInMount,
                        ));
                    }
                    Fate::Fine => {}
                }
            } else if kind(&unit) == "scope" || graph.boot.contains(&unit) {
                continue;
            }
        }
        if depth >= MAX_DEPTH {
            return Err(unknown(format!(
                "{start} pulls in units more than {MAX_DEPTH} deep, which NAILS does not follow"
            )));
        }
        let pulled = edges(graph, &unit).map_err(|why| {
            let path = if at == 0 {
                String::new()
            } else {
                format!("{start} pulls in {}, and ", chain(&reached, at))
            };
            unknown(format!("{path}{why}"))
        })?;
        for edge in pulled {
            if reached.iter().any(|seen| seen.unit == edge.unit) {
                continue;
            }
            if reached.len() >= MAX_UNITS {
                return Err(unknown(format!(
                    "{start} pulls in more than {MAX_UNITS} units, which NAILS does not follow"
                )));
            }
            reached.push(Reached {
                unit: edge.unit,
                from: Some(at),
                how: edge.how,
            });
            queue.push_back((reached.len() - 1, depth + 1, required && edge.required));
        }
    }
    Ok(masked_required)
}
