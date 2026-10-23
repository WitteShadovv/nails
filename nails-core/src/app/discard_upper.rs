// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `discard-upper` operation (the CLI's `discard`): drop a path's hidden
//! copy so the decoy's own files show through again at the next entry.
//!
//! It deletes a path's hidden copy from the root upper on the hidden volume and
//! the layers of a separate decoy filesystem mounted at that path. It refuses in
//! the hidden session (the upper is the live root there). The plan and the apply
//! are separate so a front end can list what it will delete and confirm between
//! the two, under the state lock the front end holds.

use std::path::Path;

use serde::Serialize;

use crate::{Config, NailsManager, RealFilesystem, ResetUpperPlan, Result, RuntimeEnv};

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

/// A discard whose configuration is loaded and manager built, ready to plan and
/// apply under the caller's state lock.
pub struct ReadyDiscard {
    manager: NailsManager<RealFilesystem>,
}

impl ReadyDiscard {
    /// The hidden volume root, for taking the state lock.
    pub fn hidden_root(&self) -> &Path {
        &self.manager.config().hidden_volume_root
    }

    /// The state file path, for taking the state lock.
    pub fn state_path(&self) -> &Path {
        &self.manager.config().state_file_path
    }

    /// Plan what removing `target`'s hidden upper would delete. Refuses in the
    /// hidden session with [`NailsError::InvalidState`](crate::NailsError).
    pub fn plan(&self, target: &Path) -> Result<ResetUpperPlan> {
        self.manager.plan_reset_upper(target)
    }

    /// Apply a plan: delete the hidden upper it names.
    pub fn apply(&self, plan: &ResetUpperPlan) -> Result<()> {
        self.manager.apply_reset_upper(plan)
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

    fn discard_rooted_at(root: &Path) -> ReadyDiscard {
        let config = Config {
            hidden_volume_root: root.to_path_buf(),
            state_file_path: root.join("state.json"),
            log_path: root.join("logs"),
            ..Config::test_default()
        };
        prepare(&RuntimeEnv::default(), config)
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
