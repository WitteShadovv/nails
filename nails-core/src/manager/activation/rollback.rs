// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Activation-scope overlay rollback.
//!
//! [`rollback_mounts`] is the single unmount routine. It is shared by
//! [`MountTracker`](crate::MountTracker)'s mid-mount safety net and by
//! [`ActivationMounts`], the guard that unmounts overlays when activation fails
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

use super::{MountInfo, MountType};
use crate::Filesystem;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

/// Unmount a set of tracked overlays in reverse (LIFO) order, best-effort.
///
/// Each overlay is unmounted gracefully first and forcibly only if that fails.
/// Ephemeral overlays additionally have their tmpfs upper/work filesystems
/// unmounted after the overlay itself (cascade). Unmounting continues past
/// individual failures so one stuck mount cannot strand the rest.
///
/// Returns the targets that could not be unmounted (empty on full success), so
/// the caller can persist them as the still-live mounts of a degraded state.
pub(crate) fn rollback_mounts<F: Filesystem>(filesystem: &F, mounts: &[MountInfo]) -> Vec<PathBuf> {
    let mut remaining: Vec<PathBuf> = Vec::new();

    // LIFO: unmount in reverse of mount order.
    for mount_info in mounts.iter().rev() {
        let path = &mount_info.target;
        let mount_type_str = match mount_info.mount_type {
            MountType::Persistent => "persistent",
            MountType::Ephemeral => "ephemeral",
            MountType::Bind => "bind",
            MountType::NestedOverlay => "nested-overlay",
        };

        tracing::info!(
            path = %path.display(),
            mount_type = mount_type_str,
            phase = "rollback",
            "Unmounting overlay"
        );

        // A submount bind is not a managed overlay, so its idempotent bind unmount
        // is used instead of the overlay graceful-then-force path (which would
        // refuse it as an unmanaged target).
        let unmounted = if mount_info.mount_type == MountType::Bind {
            match filesystem.unmount_bind(path) {
                Ok(()) => true,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "Submount bind unmount failed");
                    false
                }
            }
        } else {
            unmount_graceful_then_force(filesystem, path)
        };

        if unmounted {
            #[cfg(test)]
            test_events::record(test_events::ActivationEvent::Unmounted(path.clone()));
        } else {
            remaining.push(path.clone());
        }

        // For ephemeral mounts, also tear down the backing tmpfs filesystems.
        if mount_info.mount_type == MountType::Ephemeral {
            for tmpfs_path in &mount_info.tmpfs_paths {
                tracing::info!(
                    path = %tmpfs_path.display(),
                    filesystem_type = "tmpfs",
                    "Unmounting tmpfs"
                );

                if let Err(e) = filesystem.unmount_tmpfs(tmpfs_path) {
                    tracing::warn!(
                        path = %tmpfs_path.display(),
                        error = %e,
                        filesystem_type = "tmpfs",
                        "Tmpfs unmount failed"
                    );
                    remaining.push(tmpfs_path.clone());
                } else {
                    tracing::info!(
                        path = %tmpfs_path.display(),
                        filesystem_type = "tmpfs",
                        "Tmpfs unmounted"
                    );
                }
            }
        }
    }

    remaining
}

/// Try a graceful unmount, then force. Returns `true` if either succeeded.
fn unmount_graceful_then_force<F: Filesystem>(filesystem: &F, path: &Path) -> bool {
    match filesystem.unmount(path, false) {
        Ok(()) => {
            tracing::info!(path = %path.display(), method = "graceful", "Unmount succeeded");
            true
        }
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                attempt = "graceful",
                "Unmount failed, trying force unmount"
            );
            match filesystem.unmount(path, true) {
                Ok(()) => {
                    tracing::info!(path = %path.display(), method = "force", "Unmount succeeded");
                    true
                }
                Err(force_err) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %force_err,
                        attempts = "both",
                        "Force unmount also failed"
                    );
                    false
                }
            }
        }
    }
}

/// Activation-scope rollback guard for mounted overlays.
///
/// Armed with the overlays `mount_overlays` took out of the [`MountTracker`],
/// this guard unmounts them in reverse order on drop unless it has been
/// disarmed by a successful activation. It owns a clone of the filesystem, so
/// its drop never needs to reach back through the [`StateGuard`]'s exclusive
/// borrow of the manager.
///
/// Declaring the guard *after* the [`StateGuard`] makes drop order do the
/// sequencing for free: the overlays come down first, then the `StateGuard`
/// writes the rolled-back state, then the session is restarted onto the decoy.
///
/// Any target the rollback could not unmount is written into the shared
/// `residue` handle, which the [`StateGuard`] reads to persist `Degraded`
/// (with those mounts listed) instead of `Inactive`.
pub(super) struct ActivationMounts<F: Filesystem> {
    filesystem: F,
    mounts: Vec<MountInfo>,
    read_only_guards: Vec<PathBuf>,
    residue: Rc<RefCell<Vec<PathBuf>>>,
    disarmed: bool,
}

impl<F: Filesystem> ActivationMounts<F> {
    /// Arm the guard with the filesystem clone, the overlays to roll back, and
    /// the shared handle that receives any mounts rollback could not remove.
    pub(super) fn arm(
        filesystem: F,
        mounts: Vec<MountInfo>,
        residue: Rc<RefCell<Vec<PathBuf>>>,
    ) -> Self {
        Self {
            filesystem,
            mounts,
            read_only_guards: Vec::new(),
            residue,
            disarmed: false,
        }
    }

    /// Record the read-only guards applied after the overlays, so a rollback
    /// returns write access to the decoy OS trees before the overlays come down.
    pub(super) fn set_read_only_guards(&mut self, guards: Vec<PathBuf>) {
        self.read_only_guards = guards;
    }

    /// Disarm the guard after a successful activation so the overlays stay mounted.
    pub(super) fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl<F: Filesystem> Drop for ActivationMounts<F> {
    fn drop(&mut self) {
        if self.disarmed || (self.mounts.is_empty() && self.read_only_guards.is_empty()) {
            return;
        }

        // Undo the read-only guards first so the decoy OS trees are writable again
        // before the overlays stacked on them are removed. Best-effort: a failure
        // here must not stop the overlay rollback.
        for tree in self.read_only_guards.iter().rev() {
            if let Err(error) = self.filesystem.unmount_bind(tree) {
                tracing::error!(
                    tree = %tree.display(),
                    error = %error,
                    "Rollback could not remove the read-only guard; the decoy tree may stay read-only"
                );
            }
        }

        if self.mounts.is_empty() {
            return;
        }

        tracing::warn!(
            mount_count = self.mounts.len(),
            "Activation failed after mounting; rolling back overlays before state is restored"
        );

        let remaining = rollback_mounts(&self.filesystem, &self.mounts);
        if !remaining.is_empty() {
            tracing::error!(
                remaining = ?remaining,
                "Overlay rollback left mounts behind; system will be marked Degraded"
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
        /// The error-path session restart ran (`SessionRestartGuard::drop`).
        SessionRestart,
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
    fn rollback_mounts_cascades_ephemeral_tmpfs() {
        let fs = MockFilesystem::new();
        fs.mock_set_mounted(Path::new("/var"), true);
        let upper = Path::new("/run/nails/var/upper");
        let work = Path::new("/run/nails/var/work");
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

        {
            let mut guard = ActivationMounts::arm(fs.clone(), mounts, residue.clone());
            guard.disarm();
        }

        assert!(fs.is_mounted(Path::new("/home")).unwrap());
        assert!(fs.is_mounted(Path::new("/etc")).unwrap());
        assert!(residue.borrow().is_empty());
    }

    #[test]
    fn activation_mounts_drop_rolls_back_and_records_residue() {
        let fs = MockFilesystem::new();
        let mounts = mount_pair(&fs);
        fs.mock_set_unmount_should_fail("/etc", true);
        let residue = Rc::new(RefCell::new(Vec::new()));

        drop(ActivationMounts::arm(fs.clone(), mounts, residue.clone()));

        assert!(!fs.is_mounted(Path::new("/home")).unwrap());
        assert_eq!(*residue.borrow(), vec![PathBuf::from("/etc")]);
    }
}
