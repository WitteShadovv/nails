// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The mask of a `noauto` line of a decoy disk ([`Decision::is_noauto_mask`])
//! against the units outside the fstab (see [`super`]).

use super::unit_dirs::Load;
use super::{NativeUnit, UnitDirs, deps, pulls};
use crate::session::fstab::{FstabEntry, automount_unit, mount_unit, required_by};
use crate::session::policy::{
    Decision, KeptOff, NoautoNeeded, Origin, Present, Unreached, Unskippable,
};
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
/// ([`MaskCause::ConflictingLines`]). Otherwise, where a mount, swap or
/// automount unit a boot target links in its `.requires` directory
/// (`native`) that the session does not keep off requires it through a chain
/// of requirements NAILS reads
/// ([`pulls::requires_among`]), it is kept off as a line the boot mounts:
/// skipped where its device is there, and masked with a warning where it is
/// not ([`KeptOff::needed_noauto`]). The warning says the target will not be
/// reached, and the mask is recorded, where the chain's last step requires
/// the mount by name; where it requires it only as the mount for a path
/// ([`deps::Edge::by_path`]), the warning says the target may not be
/// reached, and the mask is not recorded.
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
    // Each mount with the first unit found to require it, how, and whether
    // only by a path: one found to require it by name wins.
    let mut requirers: Vec<(String, &NativeUnit, String, bool)> = Vec::new();
    for start in starts {
        for (unit, chain, by_path) in
            pulls::requires_among(&graph, &start.name, &kept.masks, &needed)
        {
            match requirers.iter_mut().find(|(seen, ..)| *seen == unit) {
                Some(seen) if seen.3 && !by_path => *seen = (unit, start, chain, by_path),
                Some(_) => {}
                None => requirers.push((unit, start, chain, by_path)),
            }
        }
    }
    for (unit, start, chain, by_path) in requirers {
        let target = start.required_by.as_deref().unwrap_or_default();
        // A requirement by a path of a masked mount may hold nothing up
        // (see [`deps::Edge::by_path`]): the target may still be reached.
        let held = if by_path {
            format!(
                "{}, which {target} requires, requires {chain}, the mount of a noauto line of a \
                 decoy disk, only as the mount for a path, so the hidden session may not reach \
                 {target}, and the units only that target pulls in may not start there",
                start.name
            )
        } else {
            format!(
                "{}, which {target} requires, requires {chain}, the mount of a noauto line of a \
                 decoy disk, so the hidden session will not reach {target}, and the units only \
                 that target pulls in will not start there",
                start.name
            )
        };
        let remedy = format!(
            "or have {target} want {} rather than require it",
            start.name
        );
        match kept.needed_noauto(fstab, &unit, present, !by_path) {
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

/// Weigh what NAILS reads as held up only for a path, or only may be
/// ([`KeptOff::unsure`], [`Origin::Needed`] with `may` or `by_path`),
/// against the mount, swap and automount units a boot target links in its
/// `.requires` directory (`native`): the skips among [`KeptOff::unsure`],
/// and each mount the decisions mask for a target that needs it only for a
/// path, or only may require it, without recording it. Where such a unit
/// names the mount, as the link itself does or as the unit requires it
/// through a chain of requirements NAILS reads whose last step names it
/// ([`pulls::requires_among`]), the unit does not start while the mount is
/// masked, so the target is not reached: the skip leaves
/// [`KeptOff::unsure`], so that where it is masked after all the warning
/// says will not and the mask is recorded ([`super::kept_off`]), and the
/// mask is recorded now, among [`KeptOff::sure_needed`], with a warning
/// that names that unit in place of the decision's own
/// ([`KeptOff::warning`]). Returns the warnings.
///
/// NAILS reads two rare shapes so too, where systemd ignores a step and
/// reaches the target: a chain with a step for a path (a mount point below,
/// a source, `RequiresMountsFor=` or `x-systemd.requires-mounts-for=`) into a
/// unit that [`super::kept_off`] masks only after this ran, as a skip it
/// masks after all, and a link in a `.requires` directory on the way, the
/// target's or that of a unit on the chain, that points to `/dev/null`.
/// [`weigh_masks`] reads both shapes the same way. The warning says will not there,
/// and the mask is recorded, but no disk is mounted in either.
pub(super) fn weigh_unsure(
    dirs: UnitDirs<'_>,
    fstab: &[FstabEntry],
    native: &[NativeUnit],
    decisions: &[Decision],
    covered: &[String],
    kept: &mut KeptOff,
) -> Vec<String> {
    // Each such mask with its decision, as a target that names it would
    // record it.
    let masked: Vec<(&String, &Decision)> = decisions
        .iter()
        .filter_map(|decision| match decision {
            Decision::Mask {
                units,
                unreached:
                    Some(Unreached {
                        cause: Unskippable::NoDevice(_) | Unskippable::Unread,
                        origin: Origin::Needed { may, by_path, .. },
                        ..
                    }),
                ..
            } if *may || *by_path => {
                // The line that needs it requires its mount, the first unit.
                Some((units.first()?, decision))
            }
            _ => None,
        })
        .filter(|(unit, _)| {
            kept.masks.contains(unit) && !kept.required_masks.iter().any(|mask| mask.unit == **unit)
        })
        .collect();
    let candidates: Vec<String> = kept
        .unsure
        .iter()
        .chain(masked.iter().map(|(unit, _)| *unit))
        .cloned()
        .collect();
    if candidates.is_empty() {
        return Vec::new();
    }
    // Each candidate a unit a target requires names, with that target, the
    // unit it requires, and how: the link itself, or that unit's chain.
    let mut named: Vec<(String, String, String, String)> = Vec::new();
    for unit in &candidates {
        if let Some(target) = native
            .iter()
            .find(|native| native.name == *unit)
            .and_then(|native| native.required_by.clone())
        {
            let how = format!("{target} requires {unit} through a link in a .requires directory");
            named.push((unit.clone(), target, unit.clone(), how));
        }
    }
    // A skipped unit gets its start job too, and with it what it requires.
    let starts: Vec<&NativeUnit> = native
        .iter()
        .filter(|native| {
            native.required_by.is_some()
                && !kept.masks.contains(&native.name)
                && matches!(dirs.load(&native.name), Load::Loaded { .. })
        })
        .collect();
    if !starts.is_empty() {
        let graph = deps::Graph::new(dirs, fstab, covered);
        for start in starts {
            let target = start.required_by.as_deref().unwrap_or_default();
            for (unit, chain, by_path) in
                pulls::requires_among(&graph, &start.name, &kept.masks, &candidates)
            {
                if !by_path && !named.iter().any(|(seen, ..)| *seen == unit) {
                    let how = format!("{}, which {target} requires, requires {chain}", start.name);
                    named.push((unit, target.to_string(), start.name.clone(), how));
                }
            }
        }
    }
    let mut warnings = Vec::new();
    for (unit, target, required, how) in named {
        kept.unsure.retain(|known| *known != unit);
        let Some(&(_, decision)) = masked.iter().find(|(masked, _)| **masked == unit) else {
            continue;
        };
        let Decision::Mask {
            target: path,
            reason,
            unreached: Some(Unreached { cause, .. }),
            ..
        } = decision
        else {
            continue;
        };
        let unreached = format!(
            "{how}, so the hidden session will not reach {target}, and the units only that \
             target pulls in will not start there"
        );
        let path = path.display();
        warnings.push(match cause {
            Unskippable::NoDevice(device) => {
                kept.record_masked(
                    std::slice::from_ref(&unit),
                    MaskCause::DeviceAbsent,
                    Some(device),
                );
                format!(
                    "{path} is masked rather than skipped, as its device {} is not there: \
                     {unreached}. Attach the device before activating, or have {target} want \
                     {required} rather than require it",
                    device.display()
                )
            }
            _ => {
                kept.record_masked(std::slice::from_ref(&unit), MaskCause::Undetermined, None);
                format!("{path} is masked, as {reason}: {unreached}")
            }
        });
        kept.sure_needed.push(unit);
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
