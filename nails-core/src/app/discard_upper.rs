// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `discard-upper` operation (the CLI's `discard`): drop a path's hidden
//! copy so the decoy's own files show through again at the next entry.
//!
//! It deletes a path's hidden copy from the root upper on the hidden volume and
//! the layers of a separate decoy filesystem mounted at that path. It refuses in
//! the hidden session (the upper is the live root there). The plan and the apply
//! are separate so a front end can list what it will delete and confirm between
//! the two, both on the handle [`ReadyDiscard::lock`] hands out, which holds the
//! exclusive state lock.

use std::path::Path;

use serde::Serialize;

use super::lock::LockError;
use crate::hidden_root::Allow;
use crate::{Config, NailsManager, RealFilesystem, ResetUpperPlan, Result, RuntimeEnv, StateLock};

/// The machine-readable payload of a discard.
#[derive(Debug, Serialize)]
pub struct DiscardData {
    /// The path whose hidden copy was deleted.
    pub target: String,
    /// The directories that were removed (empty when there was nothing to do).
    pub removed: Vec<String>,
}

impl DiscardData {
    /// The payload for a plan: its target and the directories it removes (none
    /// for an empty plan).
    pub fn from_plan(plan: &ResetUpperPlan) -> Self {
        Self {
            target: plan.target.display().to_string(),
            removed: plan
                .removals()
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
        }
    }
}

/// A discard whose configuration is loaded and manager built, ready to lock.
/// It can neither plan nor apply: only the [`LockedDiscard`] its
/// [`lock`](Self::lock) step hands out can, so no concurrent activation mounts
/// the target out from under it.
///
/// ```compile_fail
/// fn apply_unlocked(
///     ready: &nails_core::app::discard_upper::ReadyDiscard,
///     plan: &nails_core::ResetUpperPlan,
/// ) {
///     let _ = ready.apply(plan);
/// }
/// ```
///
/// ```
/// fn apply_locked(
///     locked: &nails_core::app::discard_upper::LockedDiscard,
///     plan: &nails_core::ResetUpperPlan,
/// ) {
///     let _ = locked.apply(plan);
/// }
/// ```
pub struct ReadyDiscard {
    manager: NailsManager<RealFilesystem>,
}

impl ReadyDiscard {
    /// Take the exclusive state lock, created only on the hidden volume or, with
    /// `allow`, on a root the operator accepted. Hands out the only handle that
    /// plans and applies, which holds the lock until it is dropped.
    pub fn lock(self, allow: Allow) -> std::result::Result<LockedDiscard, LockError> {
        self.lock_with(allow, super::lock::acquire_mutating)
    }

    /// [`lock`](Self::lock), taking the lock with `acquire`.
    fn lock_with(
        self,
        allow: Allow,
        acquire: impl FnOnce(&Path, Allow, &Path) -> std::result::Result<StateLock, LockError>,
    ) -> std::result::Result<LockedDiscard, LockError> {
        let config = self.manager.config();
        let lock = acquire(&config.hidden_volume_root, allow, &config.state_file_path)?;
        Ok(LockedDiscard {
            ready: self,
            _lock: lock,
        })
    }
}

/// A discard that holds the exclusive state lock: the only handle that plans
/// and applies. The lock is released when it is dropped.
pub struct LockedDiscard {
    ready: ReadyDiscard,
    /// Held for its `Drop`, which releases the lock.
    _lock: StateLock,
}

impl LockedDiscard {
    /// Plan what removing `target`'s hidden upper would delete. Refuses in the
    /// hidden session with [`NailsError::InvalidState`](crate::NailsError).
    pub fn plan(&self, target: &Path) -> Result<ResetUpperPlan> {
        self.ready.manager.plan_reset_upper(target)
    }

    /// Apply a plan: delete the hidden upper it names.
    pub fn apply(&self, plan: &ResetUpperPlan) -> Result<()> {
        self.ready.manager.apply_reset_upper(plan)
    }
}

/// Build the discard from the resolved configuration.
pub fn prepare(env: &RuntimeEnv, config: Config) -> ReadyDiscard {
    let state_path = config.state_file_path.clone();
    let manager =
        NailsManager::new(RealFilesystem, config, state_path).with_runtime_env(env.clone());
    ReadyDiscard { manager }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn ready_rooted_at(root: &Path) -> ReadyDiscard {
        let config = Config {
            hidden_volume_root: root.to_path_buf(),
            state_file_path: root.join("state.json"),
            log_path: root.join("logs"),
            ..Config::test_default()
        };
        prepare(&RuntimeEnv::default(), config)
    }

    /// The locked handle of a discard rooted at `root`, taking the lock beside
    /// its state file without the attach gate (a scratch directory is no
    /// mount point).
    fn discard_rooted_at(root: &Path) -> LockedDiscard {
        ready_rooted_at(root)
            .lock_with(Allow::Nothing, crate::app::lock::acquire_unattached)
            .unwrap_or_else(|error| panic!("the lock step refused: {error:?}"))
    }

    /// The handle that plans and applies holds the state lock for as long as
    /// it lives, and the real lock step runs the attach gate first, with the
    /// allowance it is given.
    #[test]
    fn the_lock_step_holds_the_lock_for_the_handle_that_applies() {
        let root = tempfile::tempdir().unwrap();
        let locked = discard_rooted_at(root.path());
        assert!(crate::StateLock::try_acquire(root.path()).is_err());
        drop(locked);
        assert!(crate::StateLock::try_acquire(root.path()).is_ok());
        for allow in [Allow::Nothing, Allow::DecoyStorage] {
            assert!(matches!(
                ready_rooted_at(root.path()).lock(allow),
                Err(LockError::Refused(_))
            ));
        }
    }

    /// The allowance reaches the gate the lock is taken behind.
    #[test]
    fn the_lock_step_hands_its_allowance_to_the_gate() {
        let root = tempfile::tempdir().unwrap();
        for allow in [Allow::Nothing, Allow::DecoyStorage] {
            let mut seen = None;
            let _ = ready_rooted_at(root.path()).lock_with(allow, |_, given, state| {
                seen = Some(given);
                crate::app::lock::acquire_unattached(root.path(), given, state)
            });
            assert_eq!(seen, Some(allow));
        }
    }

    #[test]
    fn apply_deletes_exactly_the_directories_and_files_the_plan_names() {
        let root = tempfile::tempdir().unwrap();
        // A hidden directory copy and a hidden file, both named by the plan.
        let removed_dir = root.path().join("root/upper/home");
        std::fs::create_dir_all(removed_dir.join("alice")).unwrap();
        let removed_file = root.path().join("root/upper/motd");
        std::fs::create_dir_all(removed_file.parent().unwrap()).unwrap();
        std::fs::write(&removed_file, b"decoy banner").unwrap();
        // An unrelated sibling the plan does not name: it must survive.
        let kept = root.path().join("root/upper/etc");
        std::fs::create_dir_all(&kept).unwrap();

        let ready = discard_rooted_at(root.path());
        let plan = ResetUpperPlan {
            target: PathBuf::from("/home"),
            removals: vec![removed_dir.clone(), removed_file.clone()],
            resets_nix_store: false,
        };

        ready.apply(&plan).unwrap();

        // The stub (`Ok(())`) would leave all three in place; the real apply
        // removes precisely the two the plan names and nothing else.
        assert!(!removed_dir.exists(), "the named directory was not removed");
        assert!(!removed_file.exists(), "the named file was not removed");
        assert!(kept.exists(), "an unnamed sibling must be left untouched");
    }

    #[test]
    fn apply_of_an_empty_plan_removes_nothing_and_succeeds() {
        let root = tempfile::tempdir().unwrap();
        let untouched = root.path().join("root/upper/home");
        std::fs::create_dir_all(&untouched).unwrap();

        let ready = discard_rooted_at(root.path());
        let plan = ResetUpperPlan {
            target: PathBuf::from("/home"),
            removals: Vec::new(),
            resets_nix_store: false,
        };

        ready.apply(&plan).unwrap();

        assert!(untouched.exists(), "an empty plan must delete nothing");
    }
}
