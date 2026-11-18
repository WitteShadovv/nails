// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The mask of a `noauto` line of a decoy disk ([`Decision::is_noauto_mask`])
//! against the units outside the fstab (see [`super`]).

use super::unit_dirs::Load;
use super::{NativeUnit, UnitDirs, deps, pulls};
use crate::session::fstab::{FstabEntry, automount_unit, mount_unit, required_by};
use crate::session::policy::{Decision, KeptOff, NoautoNeeded, Present};
use nails_teardown::whole_root::plan::MaskCause;

/// `decisions` with each unit of a `noauto` line's mask
/// ([`Decision::is_noauto_mask`]) left out whose file the hidden systemd
/// loads from a unit directory it reads before the fstab generator's
/// ([`UnitDirs::outranks_fstab_generator`]) and that a boot target links
/// (`native`): no fstab line makes what that name loads, and the unit pass
/// decided the file it loads ([`super::decide`]). A mask left without units goes.
pub(super) fn yield_masks(
    dirs: UnitDirs<'_>,
    native: &[NativeUnit],
    decisions: &[Decision],
) -> Vec<Decision> {
    let decided = |unit: &String| {
        native.iter().any(|native| native.name == *unit) && dirs.outranks_fstab_generator(unit)
    };
    decisions
        .iter()
        .filter_map(|decision| match decision {
            Decision::Mask {
                target,
                units,
                reason,
                unreached,
            } if decision.is_noauto_mask() && units.iter().any(decided) => {
                let units: Vec<String> = units
                    .iter()
                    .filter(|unit| !decided(unit))
                    .cloned()
                    .collect();
                (!units.is_empty()).then(|| Decision::Mask {
                    target: target.clone(),
                    units,
                    reason: reason.clone(),
                    unreached: unreached.clone(),
                })
            }
            _ => Some(decision.clone()),
        })
        .collect()
}

/// Weigh each unit only the mask of a `noauto` line holds
/// ([`KeptOff::noauto_masks`]) against what else describes it and what
/// pulls it in, and return the warnings. Where a decision leaves a line or
/// unit file of the same name to the hidden systemd, NAILS cannot tell which
/// of them the hidden systemd reads: the unit stays masked, with a warning,
/// recorded where a boot target requires that line or unit file
/// ([`MaskCause::ConflictingLines`]). Otherwise, where a unit a boot target
/// links in its `.requires` directory (`native`) that the session does not
/// keep off requires it through a chain of requirements NAILS reads
/// ([`pulls::requires_among`]), it is kept off as a line the boot mounts:
/// skipped where its device is there, and masked with a warning and a record
/// where it is not ([`KeptOff::needed_noauto`]).
pub(super) fn weigh_masks(
    dirs: UnitDirs<'_>,
    fstab: &[FstabEntry],
    native: &[NativeUnit],
    decisions: &[Decision],
    covered: &[String],
    kept: &mut KeptOff,
    present: Present<'_>,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut conflicting: Vec<String> = Vec::new();
    for unit in kept.noauto_masks.clone() {
        let left = decisions.iter().any(|decision| match decision {
            Decision::Leave { target, .. } => {
                mount_unit(target) == unit
                    || (automount_unit(target) == unit
                        && (native.iter().any(|native| native.name == unit)
                            || fstab
                                .iter()
                                .any(|entry| entry.file == *target && entry.is_automount())))
            }
            _ => false,
        });
        if !left {
            continue;
        }
        let automount = unit.ends_with(".automount");
        let required = native
            .iter()
            .any(|native| native.name == unit && native.required_by.is_some())
            || fstab.iter().any(|entry| {
                let named = if automount {
                    entry.is_automount() && automount_unit(&entry.file) == unit
                } else {
                    !entry.is_automount() && mount_unit(&entry.file) == unit
                };
                !entry.is_swap() && named && required_by(entry).is_some()
            });
        if required {
            kept.record_masked(
                std::slice::from_ref(&unit),
                MaskCause::ConflictingLines,
                None,
            );
        }
        warnings.push(noauto_conflict_warning(&unit, required));
        conflicting.push(unit);
    }
    let needed: Vec<String> = kept
        .noauto_masks
        .iter()
        .filter(|unit| !conflicting.contains(unit))
        .cloned()
        .collect();
    let starts: Vec<&NativeUnit> = native
        .iter()
        .filter(|native| {
            native.required_by.is_some()
                && !kept.masks.contains(&native.name)
                && !kept
                    .skips
                    .iter()
                    .any(|skip| skip.units.contains(&native.name))
                && matches!(dirs.load(&native.name), Load::Loaded { .. })
        })
        .collect();
    if needed.is_empty() || starts.is_empty() {
        return warnings;
    }
    let graph = deps::Graph::new(dirs, fstab, covered);
    // Each mount with the first unit found to require it, and how.
    let mut requirers: Vec<(String, &NativeUnit, String)> = Vec::new();
    for start in starts {
        for (unit, chain) in pulls::requires_among(&graph, &start.name, &kept.masks, &needed) {
            if !requirers.iter().any(|(seen, ..)| *seen == unit) {
                requirers.push((unit, start, chain));
            }
        }
    }
    for (unit, start, chain) in requirers {
        let target = start.required_by.as_deref().unwrap_or_default();
        let held = format!(
            "{}, which {target} requires, requires {chain}, the mount of a noauto line of a \
             decoy disk, so the hidden session will not reach {target}, and the units only that \
             target pulls in will not start there",
            start.name
        );
        let remedy = format!(
            "or have {target} want {} rather than require it",
            start.name
        );
        match kept.needed_noauto(fstab, &unit, present) {
            NoautoNeeded::Skipped => {}
            NoautoNeeded::Absent(device) => warnings.push(format!(
                "{unit} is masked rather than skipped, as its device {} is not there: {held}. \
                 Attach the device before activating, {remedy}",
                device.display()
            )),
            NoautoNeeded::Disagree => warnings.push(format!(
                "{unit} is masked rather than skipped, as the fstab lines that describe it name \
                 two devices: {held}. Make them agree before activating, {remedy}"
            )),
        }
    }
    warnings
}

/// The warning for `unit`, the mount or automount of a `noauto` line of a
/// decoy disk that the session masks, which a line or unit file the session
/// leaves to the hidden systemd describes too; `required` where a boot target
/// requires that one.
fn noauto_conflict_warning(unit: &str, required: bool) -> String {
    let unreached = if required {
        ", and the hidden session will not reach the boot target that requires it, and the units \
         only that target pulls in will not start there"
    } else {
        ""
    };
    format!(
        "{unit} is masked, as a noauto line of a decoy disk names it, and another fstab line or \
         unit file that the session leaves to the hidden systemd describes it too: NAILS cannot \
         tell which of them the hidden systemd reads, so the hidden session does not start it\
         {unreached}. Make them agree before activating"
    )
}
