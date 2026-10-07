// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Activation-scope overlay rollback.
//!
//! Activation records every step's undo in the teardown plan (see
//! [`crate::manager::teardown_plan`]); rolling back is undoing that plan with
//! the executor deactivation and emergency use too ([`undo_plan`]). It is run
//! by [`MountTracker`](crate::MountTracker)'s mid-mount safety net and by
//! [`ActivationMounts`], the guard that rolls back when activation fails
//! *after* the mounts have been taken out of the tracker.
//!
//! # Why a second guard exists
//!
//! `mount_overlays` hands its mount list to the caller and empties the tracker,
//! so the tracker can no longer roll back once activation continues past the
//! mount phase. Activation can still fail after that point — a failed session
//! restart or a failed `Active` state write — and on that path the overlays must
//! come down before [`StateGuard`](crate::StateGuard) records the rolled-back
//! state. [`ActivationMounts`] owns that late window: it keeps its own clone of
//! the filesystem (so it never borrows the filesystem back out of the
//! `StateGuard`'s exclusive `&mut` borrow of the manager) and unmounts on drop.

use super::MountInfo;
use crate::Filesystem;
use crate::manager::teardown_plan::{FsMountOps, PlanRecorder};
use nails_teardown::undo::UndoReport;
use nails_teardown::{Phase, Plan};
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

/// What the activation-scope overlay rollback did when activation failed.
///
/// The CLI reads this after a failed activation so it reports the rollback
/// truthfully: it must never claim "rollback completed" for a failure raised
/// before any overlay was mounted (option validation, lock acquisition, the
/// session kill), nor when the rollback itself could not unmount everything.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RollbackOutcome {
    /// No rollback ran: either activation succeeded, or it failed before any
    /// overlay or read-only guard was in place.
    #[default]
    NotNeeded,
    /// The overlays and guards were rolled back cleanly.
    Completed,
    /// The rollback ran but could not undo everything; each string names a
    /// mount or guard it left behind.
    Failed(Vec<String>),
}

/// Undo every step of `plan`, in reverse, through the plan executor every
/// teardown shares, and log what it did. Unit stops are left out: a failed
/// activation's hidden units are stopped by the session restart onto the decoy.
pub(crate) fn undo_plan<F: Filesystem>(filesystem: &F, plan: &Plan) -> UndoReport {
    let ops = FsMountOps::for_plan(filesystem, plan);
    let report = nails_teardown::undo::run_plan(
        &ops,
        plan,
        &[Phase::Dependents, Phase::Store, Phase::Main],
        false,
    );
    crate::manager::teardown_plan::log_undo(&report);
    #[cfg(test)]
    for (path, _) in report.detached(&[
        nails_teardown::MountKind::Overlay,
        nails_teardown::MountKind::NestedOverlay,
        nails_teardown::MountKind::Attachment,
        nails_teardown::MountKind::StoreBind,
        nails_teardown::MountKind::Tmpfs,
        nails_teardown::MountKind::RuntimeRoot,
    ]) {
        test_events::record(test_events::ActivationEvent::Unmounted(path));
    }
    report
}

/// Undo the plan `recorder` holds and keep only what could not be undone in
/// it. Returns the targets left behind (empty on full success).
pub(crate) fn undo_recorded<F: Filesystem>(
    filesystem: &F,
    recorder: &PlanRecorder,
) -> Vec<PathBuf> {
    let report = undo_plan(filesystem, &recorder.snapshot());
    recorder.retain_failed(&report);
    report
        .failures()
        .into_iter()
        .map(|(path, _)| path)
        .collect()
}

/// Unmount a set of tracked mounts in reverse (LIFO) order, best-effort, as
/// the plan they make: the undo of a tracker that belongs to no activation.
///
/// Returns the targets that could not be unmounted (empty on full success), so
/// the caller can persist them as the still-live mounts of a degraded state.
pub(crate) fn rollback_mounts<F: Filesystem>(filesystem: &F, mounts: &[MountInfo]) -> Vec<PathBuf> {
    let recorder = PlanRecorder::memory(PathBuf::new());
    for mount in mounts {
        recorder.record_mount(filesystem, mount);
    }
    undo_recorded(filesystem, &recorder)
}

/// Activation-scope rollback guard.
///
/// Armed with the plan the mount phase recorded, this guard undoes it in
/// reverse on drop unless it has been disarmed by a successful activation:
/// the read-only guards (recorded last) first, then the mounts. Every later
/// activation step appends its undo to the same plan, so the guard needs no
/// list of its own. It owns a clone of the filesystem, so its drop never needs
/// to reach back through the [`StateGuard`](crate::StateGuard)'s exclusive
/// borrow of the manager.
///
/// Declaring the guard *after* the [`StateGuard`](crate::StateGuard) makes drop
/// order do the sequencing for free: the mounts come down first, then the
/// `StateGuard` writes the rolled-back state, then the session is restarted
/// onto the decoy.
///
/// Any target the rollback could not undo is written into the shared `residue`
/// handle, which the [`StateGuard`](crate::StateGuard) reads to persist
/// `Degraded` (with those mounts listed) instead of `Inactive`.
pub(super) struct ActivationMounts<F: Filesystem> {
    filesystem: F,
    plan: PlanRecorder,
    residue: Rc<RefCell<Vec<PathBuf>>>,
    /// Records, on drop, whether a rollback ran and whether it succeeded, so the
    /// CLI can report it truthfully. Left at `NotNeeded` on the disarmed (success)
    /// path and whenever there was nothing to roll back.
    outcome: Rc<RefCell<RollbackOutcome>>,
    disarmed: bool,
}

impl<F: Filesystem> ActivationMounts<F> {
    /// Arm the guard with the filesystem clone, the activation's plan, the
    /// shared handle that receives anything rollback could not undo, and the
    /// shared handle that records the rollback outcome.
    pub(super) fn arm(
        filesystem: F,
        plan: PlanRecorder,
        residue: Rc<RefCell<Vec<PathBuf>>>,
        outcome: Rc<RefCell<RollbackOutcome>>,
    ) -> Self {
        Self {
            filesystem,
            plan,
            residue,
            outcome,
            disarmed: false,
        }
    }

    /// Disarm the guard after a successful activation so the overlays stay mounted.
    pub(super) fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl<F: Filesystem> Drop for ActivationMounts<F> {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        let plan = self.plan.snapshot();
        if !plan
            .steps
            .iter()
            .any(|step| !matches!(step.undo, nails_teardown::Undo::StopUnit { .. }))
        {
            return;
        }

        tracing::warn!(
            steps = plan.steps.len(),
            "Activation failed after mounting; rolling back the recorded steps before state is restored"
        );

        let remaining = undo_recorded(&self.filesystem, &self.plan);
        if remaining.is_empty() {
            *self.outcome.borrow_mut() = RollbackOutcome::Completed;
        } else {
            tracing::error!(
                remaining = ?remaining,
                "Rollback left mounts behind; system will be marked Degraded"
            );
            *self.outcome.borrow_mut() = RollbackOutcome::Failed(
                remaining.iter().map(|p| p.display().to_string()).collect(),
            );
            self.residue.borrow_mut().extend(remaining);
        }
    }
}

/// Test-only ordering recorder.
///
/// Lets a regression test prove that overlay unmounts run before the error-path
/// session restart (the drop-order guarantee), without reaching into real
/// `systemctl` commands. Armed per-thread; a disarmed recorder makes
/// [`record`] a no-op.
#[cfg(test)]
pub(super) mod test_events {
    use std::cell::RefCell;
    use std::path::PathBuf;

    /// An observable step of the failure path, in the order it happened.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum ActivationEvent {
        /// An overlay target was unmounted during rollback.
        Unmounted(PathBuf),
    }

    thread_local! {
        static EVENTS: RefCell<Option<Vec<ActivationEvent>>> = const { RefCell::new(None) };
    }

    /// Guard that records ordering events on this thread until dropped.
    pub(crate) struct EventRecorder {
        _private: (),
    }

    impl EventRecorder {
        pub(crate) fn arm() -> Self {
            EVENTS.with(|cell| *cell.borrow_mut() = Some(Vec::new()));
            Self { _private: () }
        }

        pub(crate) fn events() -> Vec<ActivationEvent> {
            EVENTS.with(|cell| cell.borrow().clone().unwrap_or_default())
        }
    }

    impl Drop for EventRecorder {
        fn drop(&mut self) {
            EVENTS.with(|cell| *cell.borrow_mut() = None);
        }
    }

    pub(crate) fn record(event: ActivationEvent) {
        EVENTS.with(|cell| {
            if let Some(events) = cell.borrow_mut().as_mut() {
                events.push(event);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MockFilesystem, MountInfo};
    use std::path::Path;

    /// Mount two overlays on the mock and mark them NAILS-owned so unmount is
    /// permitted, returning their `MountInfo` in mount order.
    /// The plan an activation would have recorded for `mounts`.
    fn plan_of(fs: &MockFilesystem, mounts: &[MountInfo]) -> PlanRecorder {
        let recorder = PlanRecorder::memory(PathBuf::from("/mnt/hidden"));
        for mount in mounts {
            recorder.record_mount(fs, mount);
        }
        recorder
    }

    fn mount_pair(fs: &MockFilesystem) -> Vec<MountInfo> {
        for target in ["/home", "/etc"] {
            fs.mock_set_mounted(Path::new(target), true);
        }
        vec![
            MountInfo::persistent(PathBuf::from("/home")),
            MountInfo::persistent(PathBuf::from("/etc")),
        ]
    }

    #[test]
    fn rollback_mounts_unmounts_in_reverse_order() {
        let fs = MockFilesystem::new();
        let mounts = mount_pair(&fs);

        let remaining = rollback_mounts(&fs, &mounts);

        assert!(remaining.is_empty(), "all overlays should unmount");
        assert!(!fs.is_mounted(Path::new("/home")).unwrap());
        assert!(!fs.is_mounted(Path::new("/etc")).unwrap());
    }

    #[test]
    fn rollback_mounts_reports_targets_it_could_not_unmount() {
        let fs = MockFilesystem::new();
        let mounts = mount_pair(&fs);
        fs.mock_set_unmount_should_fail("/etc", true);

        let remaining = rollback_mounts(&fs, &mounts);

        assert_eq!(remaining, vec![PathBuf::from("/etc")]);
        // Best-effort: /home still comes down despite /etc failing.
        assert!(!fs.is_mounted(Path::new("/home")).unwrap());
        assert!(fs.is_mounted(Path::new("/etc")).unwrap());
    }

    #[test]
    fn rollback_unmounts_and_removes_the_runtime_scaffolding_tmpfs() {
        // The umbrella tmpfs is pushed first, so LIFO reaches it last. Rollback
        // unmounts it as a tmpfs and removes the now-empty directory, rather than
        // treating it as a managed overlay.
        let fs = MockFilesystem::new();
        let root = "/run/0123456789abcdef";
        fs.mock_set_path_exists(root, true);
        fs.mount_tmpfs(Path::new(root), "16M").unwrap();
        let mounts = vec![MountInfo::tmpfs(PathBuf::from(root))];

        let remaining = rollback_mounts(&fs, &mounts);

        assert!(remaining.is_empty(), "runtime tmpfs should come down");
        assert!(!fs.is_mounted(Path::new(root)).unwrap());
        assert!(
            !fs.path_exists(Path::new(root)).unwrap(),
            "the umbrella directory should be removed after unmount"
        );
    }

    #[test]
    fn rollback_mounts_cascades_ephemeral_tmpfs() {
        let fs = MockFilesystem::new();
        fs.mock_set_mounted(Path::new("/var"), true);
        let upper = Path::new("/run/0123456789abcdef/var/upper");
        let work = Path::new("/run/0123456789abcdef/var/work");
        fs.mock_set_path_exists(upper.to_str().unwrap(), true);
        fs.mock_set_path_exists(work.to_str().unwrap(), true);
        fs.mount_tmpfs(upper, "64M").unwrap();
        fs.mount_tmpfs(work, "64M").unwrap();
        let mounts = vec![MountInfo::ephemeral(
            PathBuf::from("/var"),
            vec![upper.to_path_buf(), work.to_path_buf()],
        )];

        let remaining = rollback_mounts(&fs, &mounts);

        assert!(remaining.is_empty());
        assert!(!fs.is_mounted(Path::new("/var")).unwrap());
        // `mount_tmpfs` records the backing paths in the mounted set, so once the
        // cascade tears them down they no longer read as mounted.
        assert!(!fs.is_mounted(upper).unwrap());
        assert!(!fs.is_mounted(work).unwrap());
    }

    #[test]
    fn activation_mounts_disarm_prevents_rollback() {
        let fs = MockFilesystem::new();
        let mounts = mount_pair(&fs);
        let residue = Rc::new(RefCell::new(Vec::new()));
        let outcome = Rc::new(RefCell::new(RollbackOutcome::default()));

        {
            let mut guard = ActivationMounts::arm(
                fs.clone(),
                plan_of(&fs, &mounts),
                residue.clone(),
                outcome.clone(),
            );
            guard.disarm();
        }

        assert!(fs.is_mounted(Path::new("/home")).unwrap());
        assert!(fs.is_mounted(Path::new("/etc")).unwrap());
        assert!(residue.borrow().is_empty());
        // A disarmed (successful) activation never ran a rollback.
        assert_eq!(*outcome.borrow(), RollbackOutcome::NotNeeded);
    }

    #[test]
    fn activation_mounts_drop_reports_completed_on_clean_rollback() {
        let fs = MockFilesystem::new();
        let mounts = mount_pair(&fs);
        let residue = Rc::new(RefCell::new(Vec::new()));
        let outcome = Rc::new(RefCell::new(RollbackOutcome::default()));

        drop(ActivationMounts::arm(
            fs.clone(),
            plan_of(&fs, &mounts),
            residue.clone(),
            outcome.clone(),
        ));

        assert!(!fs.is_mounted(Path::new("/home")).unwrap());
        assert!(!fs.is_mounted(Path::new("/etc")).unwrap());
        assert!(residue.borrow().is_empty());
        assert_eq!(*outcome.borrow(), RollbackOutcome::Completed);
    }

    #[test]
    fn activation_mounts_drop_rolls_back_and_records_residue() {
        let fs = MockFilesystem::new();
        let mounts = mount_pair(&fs);
        fs.mock_set_unmount_should_fail("/etc", true);
        let residue = Rc::new(RefCell::new(Vec::new()));
        let outcome = Rc::new(RefCell::new(RollbackOutcome::default()));

        drop(ActivationMounts::arm(
            fs.clone(),
            plan_of(&fs, &mounts),
            residue.clone(),
            outcome.clone(),
        ));

        assert!(!fs.is_mounted(Path::new("/home")).unwrap());
        assert_eq!(*residue.borrow(), vec![PathBuf::from("/etc")]);
        // A rollback that left a mount behind is reported as failed, naming it.
        assert_eq!(
            *outcome.borrow(),
            RollbackOutcome::Failed(vec!["/etc".to_string()])
        );
    }
}
