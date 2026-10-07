// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Executing a plan's undo, reconciled against the live mount table.
//!
//! Every teardown path runs this one executor: activation rollback, standard
//! deactivation, recovery and emergency. For each recorded step it first asks
//! whether the step's mount is still at its target ([`Presence`]); a mount
//! already gone is skipped and a foreign one (the decoy's own filesystem that
//! lay beneath an overlay) is never touched, which is what makes a repeated or
//! partial run safe. An owned mount is unmounted normally first, and detached
//! lazily (`MNT_DETACH`) only when something still holds it.
//!
//! Around the recorded steps sits the reconcile: NAILS mounts the plan does not
//! name (a persona bind or staging mount from a plan that is stale) come off
//! first, and a final sweep detaches any NAILS mount still in the table, so a
//! stale or missing plan can never leave a mount behind.

use crate::mountinfo::NailsMounts;
use crate::mounts::{MountOps, Presence};
use crate::plan::{MountKind, Phase, Plan, Undo};
use std::path::{Path, PathBuf};

/// What happened to one undo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The mount came down; `lazy` when only `MNT_DETACH` could remove it
    /// because a process still held it.
    Detached {
        /// Whether the lazy detach was needed.
        lazy: bool,
    },
    /// The read-only guard was removed.
    GuardRemoved,
    /// The step's mount was no longer there.
    AlreadyGone,
    /// Something else is mounted at the target; left alone.
    NotOurs,
    /// The undo failed.
    Failed(String),
}

/// One executed undo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    /// The path the undo acted on.
    pub target: PathBuf,
    /// What was mounted there (`None` for a guard).
    pub kind: Option<MountKind>,
    /// Whether the mount came from the recorded plan or from the reconcile.
    pub reconciled: bool,
    /// What happened.
    pub outcome: Outcome,
}

/// Every undo an execution ran, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UndoReport {
    /// The executed undos.
    pub actions: Vec<Action>,
}

impl UndoReport {
    /// The targets of `kind` that came down, in order, each with whether it
    /// needed the lazy detach.
    pub fn detached(&self, kinds: &[MountKind]) -> Vec<(PathBuf, bool)> {
        self.actions
            .iter()
            .filter(|a| a.kind.is_some_and(|k| kinds.contains(&k)))
            .filter_map(|a| match a.outcome {
                Outcome::Detached { lazy } => Some((a.target.clone(), lazy)),
                _ => None,
            })
            .collect()
    }

    /// The undos that failed, with why.
    pub fn failures(&self) -> Vec<(PathBuf, String)> {
        self.actions
            .iter()
            .filter_map(|a| match &a.outcome {
                Outcome::Failed(why) => Some((a.target.clone(), why.clone())),
                _ => None,
            })
            .collect()
    }

    /// Append another report's actions.
    pub fn extend(&mut self, other: UndoReport) {
        self.actions.extend(other.actions);
    }
}

/// Unmount `target`, normally first and lazily when that fails.
fn take_down<M: MountOps>(m: &M, target: &Path, kind: MountKind) -> Outcome {
    let outcome = match m.unmount(target, kind, false) {
        Ok(()) => Outcome::Detached { lazy: false },
        Err(_) => match m.unmount(target, kind, true) {
            Ok(()) => Outcome::Detached { lazy: true },
            Err(e) => Outcome::Failed(e.to_string()),
        },
    };
    if kind == MountKind::RuntimeRoot && matches!(outcome, Outcome::Detached { .. }) {
        let _ = m.remove_dir(target);
    }
    outcome
}

/// Execute one undo. `None` for an undo the mount executor does not run (a unit
/// stop, which the emergency interpreter handles).
pub fn undo_one<M: MountOps>(m: &M, undo: &Undo) -> Option<Action> {
    let (target, kind, outcome) = match undo {
        Undo::Unmount {
            target,
            kind,
            mount_id,
        } => {
            let outcome = match m.presence(target, *kind, *mount_id) {
                Ok(Presence::Absent) => {
                    if *kind == MountKind::RuntimeRoot {
                        let _ = m.remove_dir(target);
                    }
                    Outcome::AlreadyGone
                }
                Ok(Presence::Foreign) => Outcome::NotOurs,
                Ok(Presence::Owned) => take_down(m, target, *kind),
                Err(e) => Outcome::Failed(e.to_string()),
            };
            (target.clone(), Some(*kind), outcome)
        }
        Undo::UnmountInInitNamespace { target } => {
            let outcome = match m.unmount_in_init_namespace(target) {
                Ok(true) => Outcome::Detached { lazy: false },
                Ok(false) => Outcome::AlreadyGone,
                Err(e) => Outcome::Failed(e.to_string()),
            };
            (target.clone(), Some(MountKind::StoreBind), outcome)
        }
        Undo::RemoveReadOnlyGuard { tree } => {
            let outcome = match m.guard_present(tree) {
                Ok(false) => Outcome::AlreadyGone,
                Ok(true) | Err(_) => match m.remove_guard(tree) {
                    Ok(()) => Outcome::GuardRemoved,
                    Err(e) => Outcome::Failed(e.to_string()),
                },
            };
            (tree.clone(), None, outcome)
        }
        Undo::StopUnit { .. } => return None,
    };
    Some(Action {
        target,
        kind,
        reconciled: false,
        outcome,
    })
}

/// The NAILS mounts in `mounts` in the order to take them down: staging mounts
/// inside the runtime root (the snapshot tmpfs after the staging overlay on
/// it), persona binds, the `/nix/store` bind, the overlays in reverse, and the
/// runtime root itself last when `with_runtime_root`.
pub fn teardown_order(mounts: &NailsMounts, with_runtime_root: bool) -> Vec<(PathBuf, MountKind)> {
    let mut order = Vec::new();
    let mut staging = mounts.pivot_binds.clone();
    staging.sort_by_key(|p| {
        p.file_name()
            .is_some_and(|n| n.to_string_lossy().ends_with("-snapshot"))
    });
    order.extend(staging.into_iter().map(|p| {
        let snapshot = p
            .file_name()
            .is_some_and(|n| n.to_string_lossy().ends_with("-snapshot"));
        let kind = if snapshot {
            MountKind::Tmpfs
        } else {
            MountKind::Overlay
        };
        (p, kind)
    }));
    order.extend(
        mounts
            .persona_binds
            .iter()
            .rev()
            .map(|p| (p.clone(), MountKind::Overlay)),
    );
    if mounts.nix_overlay_present
        && let Some(bind) = &mounts.nix_store_bind
    {
        order.push((bind.clone(), MountKind::StoreBind));
    }
    let overlays: Vec<_> = mounts
        .persistent_overlays
        .iter()
        .chain(mounts.ephemeral_overlays.iter())
        .cloned()
        .collect();
    order.extend(overlays.into_iter().rev().map(|p| (p, MountKind::Overlay)));
    if with_runtime_root && let Some(root) = &mounts.runtime_tmpfs {
        order.push((root.clone(), MountKind::RuntimeRoot));
    }
    order
}

/// Take down every NAILS mount `m` still shows, up to `rounds` passes (a pass
/// that removes nothing ends early). Stacked mounts at one point need one pass
/// per layer.
pub fn sweep<M: MountOps>(m: &M, rounds: usize) -> UndoReport {
    let mut report = UndoReport::default();
    for _ in 0..rounds {
        let Ok(mounts) = m.nails_mounts() else {
            break;
        };
        let order = teardown_order(&mounts, true);
        if order.is_empty() {
            break;
        }
        let mut progressed = false;
        for (target, kind) in order {
            // Classified per mount point; only take the top mount down when it
            // is the NAILS one, never a later mount stacked above it.
            if !matches!(m.presence(&target, kind, None), Ok(Presence::Owned)) {
                continue;
            }
            let outcome = take_down(m, &target, kind);
            progressed |= matches!(outcome, Outcome::Detached { .. });
            report.actions.push(Action {
                target,
                kind: Some(kind),
                reconciled: true,
                outcome,
            });
        }
        if !progressed {
            break;
        }
    }
    report
}

/// Run the undo of every step of `plan` in `phases`, in reverse step order.
///
/// With `reconcile`, NAILS mounts the plan does not name are taken down before
/// the recorded steps (they sit on top of them: a persona bind over `/home`, a
/// staging mount inside the runtime root), and a sweep afterwards detaches
/// anything NAILS-owned still mounted.
pub fn run_plan<M: MountOps>(m: &M, plan: &Plan, phases: &[Phase], reconcile: bool) -> UndoReport {
    let mut report = UndoReport::default();
    if reconcile
        && phases.contains(&Phase::Main)
        && let Ok(mounts) = m.nails_mounts()
    {
        let named: Vec<&Path> = plan.steps.iter().filter_map(|s| s.undo.target()).collect();
        for (target, kind) in teardown_order(&mounts, false) {
            if named.contains(&target.as_path())
                || !matches!(m.presence(&target, kind, None), Ok(Presence::Owned))
            {
                continue;
            }
            let outcome = take_down(m, &target, kind);
            report.actions.push(Action {
                target,
                kind: Some(kind),
                reconciled: true,
                outcome,
            });
        }
    }
    for undo in plan.undo_order() {
        if !phases.contains(&undo.phase()) {
            continue;
        }
        if let Some(action) = undo_one(m, undo) {
            report.actions.push(action);
        }
    }
    if reconcile {
        report.extend(sweep(m, 4));
    }
    report
}

/// The NAILS mounts still in the table after a teardown, in teardown order. An
/// unreadable table counts every recorded overlay target as still live, so it
/// can never pass for a clean teardown.
pub fn remaining<M: MountOps>(m: &M, plan: &Plan) -> Vec<PathBuf> {
    match m.nails_mounts() {
        Ok(mounts) => teardown_order(&mounts, true)
            .into_iter()
            .map(|(p, _)| p)
            .collect(),
        Err(_) => plan
            .steps
            .iter()
            .filter_map(|s| match &s.undo {
                Undo::Unmount {
                    target,
                    kind: MountKind::Overlay,
                    ..
                } => Some(target.clone()),
                _ => None,
            })
            .collect(),
    }
}

#[cfg(test)]
#[path = "undo_tests.rs"]
mod tests;
