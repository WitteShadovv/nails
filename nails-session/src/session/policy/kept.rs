// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the hidden session keeps from starting for the decisions of every
//! fstab it may read, and of the units outside them ([`runtime_units`]).

use super::{Decision, Origin, Unreached, Unskippable};
use crate::session::fstab::{
    FstabEntry, automount_unit, checkers, mount_unit, required_by, waits_for,
};
use nails_teardown::whole_root::plan::{MaskCause, RequiredMask, Skip};
use std::path::{Path, PathBuf};

/// Every unit the decisions mask.
pub fn masked_units(decisions: &[Decision]) -> Vec<String> {
    decisions
        .iter()
        .flat_map(|d| d.masked_units().iter().cloned())
        .collect()
}

/// What the hidden session keeps from starting: the units it masks, each
/// once, and the units it skips.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeptOff {
    /// The units masked in `/run`.
    pub masks: Vec<String>,
    /// The units skipped, with those they pull in and their device.
    pub skips: Vec<Skip>,
    /// The units among [`masks`](Self::masks) that a boot target requires,
    /// each once with why it is masked rather than skipped.
    pub required_masks: Vec<RequiredMask>,
    /// The units among [`masks`](Self::masks) that only the mask of a
    /// `noauto` line holds ([`Decision::is_noauto_mask`]): a unit that pulls
    /// one in reads it as a decoy disk the session keeps off by that mask
    /// alone ([`super::super::mount_units`]).
    pub noauto_masks: Vec<String>,
}

impl KeptOff {
    /// Record that `units`, which a boot target requires, are masked for
    /// `cause`, unless an earlier cause is recorded for one.
    pub fn record_masked(&mut self, units: &[String], cause: MaskCause, device: Option<&Path>) {
        for unit in units {
            if !self.required_masks.iter().any(|m| &m.unit == unit) {
                self.required_masks.push(RequiredMask {
                    unit: unit.clone(),
                    cause,
                    device: device.map(Path::to_path_buf),
                });
            }
        }
    }
}

/// The units of `decision` masked although a boot target requires them,
/// with why ([`Unreached`]).
fn required_masked(decision: &Decision) -> Option<(&[String], MaskCause, Option<&Path>)> {
    let Decision::Mask {
        units,
        unreached: Some(Unreached { cause, origin, .. }),
        ..
    } = decision
    else {
        return None;
    };
    if matches!(origin, Origin::Needed { may: true, .. }) {
        // NAILS cannot tell that a target requires it.
        return None;
    }
    match cause {
        Unskippable::NoDevice(device) => Some((units, MaskCause::DeviceAbsent, Some(device))),
        Unskippable::Unread => Some((units, MaskCause::Undetermined, None)),
        // NAILS cannot tell that a target requires it.
        Unskippable::MayRequire => None,
    }
}

/// The device the unit `unit` of the fstab lines among `fstab` waits for,
/// as each line gives it: none for an automount, which waits for no device.
/// `None` where no line makes the unit, or two give it different devices.
fn device_of(fstab: &[FstabEntry], unit: &str) -> Option<Option<PathBuf>> {
    if fstab
        .iter()
        .any(|entry| automount_unit(&entry.file) == unit)
    {
        return Some(None);
    }
    let mut devices = fstab
        .iter()
        .filter(|entry| !entry.is_swap() && mount_unit(&entry.file) == unit)
        .map(waits_for);
    let first = devices.next()?;
    devices.all(|device| device == first).then_some(first)
}

/// What the hidden session keeps from starting for `decisions` and every
/// entry of `fstab` the hidden systemd may read: what the decisions mask and
/// skip, and the automount of each entry whose filesystem they put in place
/// themselves, read-only or overlaid (see the module docs of
/// [`super`]), skipped where a boot target requires it and masked otherwise.
///
/// The hidden systemd reads one fstab, but the entry decides several (the
/// decoy's, its entries resolved elsewhere, a hidden generation's), and two
/// of them can disagree about a unit. A unit that one of them masks is
/// masked, and its skip goes: a mask starts nothing, while a skip made for
/// another line could leave a checker of the line the hidden systemd reads
/// free to start. Two skips of the same unit become one, pulling in what
/// either pulls in; when they wait for different devices the unit is masked.
/// A unit a boot target requires that ends up masked is recorded with why
/// ([`KeptOff::required_masks`]).
///
/// The mask of a `noauto` line that nothing NAILS reads pulls in
/// ([`Decision::is_noauto_mask`]) is the one exception: a skip of the same
/// unit that waits for the device the line gives keeps it off instead, as it
/// starts nothing either, and pulls in what the line's unit pulls in that
/// acts on its device too ([`checkers`]). A skip that waits for another
/// device is masked, as two skips are.
pub fn runtime_units(fstab: &[FstabEntry], decisions: &[Decision]) -> KeptOff {
    let placed = |file: &Path| {
        decisions.iter().any(|decision| match decision {
            Decision::ReadOnlyBind { target } | Decision::Overlay { target } => target == file,
            _ => false,
        })
    };
    let mut masks: Vec<String> = Vec::new();
    let mut noauto: Vec<String> = Vec::new();
    for decision in decisions {
        let into = if decision.is_noauto_mask() {
            &mut noauto
        } else {
            &mut masks
        };
        into.extend(decision.masked_units().iter().cloned());
    }
    let mut skips: Vec<Skip> = decisions
        .iter()
        .filter_map(Decision::skip)
        .cloned()
        .collect();
    for entry in fstab
        .iter()
        .filter(|entry| entry.is_automount() && placed(&entry.file))
    {
        let automount = automount_unit(&entry.file);
        if required_by(entry).is_some() {
            skips.push(Skip {
                units: vec![automount],
                pulled: Vec::new(),
                device: None,
            });
        } else {
            masks.push(automount);
        }
    }
    let mut kept = KeptOff::default();
    for (units, cause, device) in decisions.iter().filter_map(required_masked) {
        kept.record_masked(units, cause, device);
    }
    let mut merged: Vec<Skip> = Vec::new();
    for skip in skips {
        match merged.iter_mut().find(|other| other.units == skip.units) {
            Some(other) if other.device == skip.device => {
                for unit in skip.pulled {
                    if !other.pulled.contains(&unit) {
                        other.pulled.push(unit);
                    }
                }
            }
            Some(_) => masks.extend(skip.units),
            None => merged.push(skip),
        }
    }
    for unit in masks {
        if !kept.masks.contains(&unit) {
            kept.masks.push(unit);
        }
    }
    for unit in noauto {
        if kept.masks.contains(&unit) {
            continue;
        }
        let skip = merged.iter_mut().find(|skip| skip.units.contains(&unit));
        match (skip, device_of(fstab, &unit)) {
            (Some(skip), Some(device)) if skip.device == device => {
                let lines = fstab
                    .iter()
                    .filter(|entry| !entry.is_swap() && mount_unit(&entry.file) == unit);
                for checker in lines.flat_map(checkers) {
                    if !skip.pulled.contains(&checker) {
                        skip.pulled.push(checker);
                    }
                }
            }
            _ => {
                kept.masks.push(unit.clone());
                if !kept.noauto_masks.contains(&unit) {
                    kept.noauto_masks.push(unit);
                }
            }
        }
    }
    for skip in merged {
        if skip.units.iter().any(|unit| kept.masks.contains(unit)) {
            kept.record_masked(&skip.units, MaskCause::ConflictingLines, None);
        } else {
            kept.skips.push(skip);
        }
    }
    kept
}

/// The units the hidden session keeps masked ([`runtime_units`]).
pub fn masks(fstab: &[FstabEntry], decisions: &[Decision]) -> Vec<String> {
    runtime_units(fstab, decisions).masks
}
