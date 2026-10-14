// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! State file access for NailsManager, and `reset-upper`.
//!
//! The state file on the hidden volume is a record next to the live facts
//! (see [`crate::session::probe`]): it is loaded lazily, cached, and written
//! whole. `reset-upper` deletes a path's hidden copy from the root upper.

use super::NailsManager;
use crate::session::{Layout, SessionView, fstab::escape_path};
use crate::{Filesystem, NailsError, Result, StateFile, SystemState};
use chrono::Utc;
use std::path::{Path, PathBuf};

/// What a `reset-upper` would delete for one path.
///
/// The root upper on the hidden volume keeps every hidden change; deleting
/// `<upper>/<path>` makes the decoy's own files show through again at the next
/// entry. When `path` is the mount point of a decoy filesystem the session
/// overlays separately (a separate `/home`), its own layers go too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetUpperPlan {
    /// The path whose hidden copy is being reset (e.g. `/home`).
    pub target: PathBuf,
    /// The existing directories (or files) that would be removed.
    pub removals: Vec<PathBuf>,
    /// True when the target is `/nix`: resetting it drops the hidden Nix
    /// database and store paths, so the caller must warn especially loudly.
    pub resets_nix_store: bool,
}

impl ResetUpperPlan {
    /// The paths that would be removed.
    pub fn removals(&self) -> Vec<&Path> {
        self.removals.iter().map(PathBuf::as_path).collect()
    }

    /// True when nothing exists to remove.
    pub fn is_empty(&self) -> bool {
        self.removals.is_empty()
    }
}

impl<F: Filesystem> NailsManager<F> {
    /// The recorded state, loaded lazily and cached. A missing or unusable file
    /// reads as [`SystemState::Inactive`].
    pub fn current_state(&self) -> Result<SystemState> {
        let mut cached = self.cached_state.borrow_mut();
        if let Some(ref state_file) = *cached {
            return Ok(state_file.state.clone());
        }
        let state_file = StateFile::load(&self.state_file_path)?;
        let state = state_file.state.clone();
        *cached = Some(state_file);
        Ok(state)
    }

    /// The recorded state together with how it was obtained, bypassing the
    /// cache, so a caller can refuse to act on a file it cannot trust.
    pub fn current_state_with_outcome(&self) -> Result<(SystemState, crate::LoadOutcome)> {
        let result = StateFile::load_with_outcome(&self.state_file_path)?;
        Ok((result.state_file.state.clone(), result.outcome))
    }

    /// Record `new_state`. Every transition is allowed: the live facts decide
    /// where the machine is, and the state file follows them. Returning to
    /// Inactive clears the platform section.
    pub fn force_state(&mut self, new_state: SystemState) -> Result<()> {
        let mut cached = self.cached_state.borrow_mut();
        let mut state_file = match cached.take() {
            Some(state_file) => state_file,
            None => StateFile::load(&self.state_file_path).unwrap_or_default(),
        };
        if new_state.is_inactive() {
            state_file.clear_platform();
        }
        state_file.state = new_state;
        state_file.last_modified = Utc::now();
        let saved = self.save_state_file(&state_file);
        *cached = Some(state_file);
        saved
    }

    fn save_state_file(&self, state_file: &StateFile) -> Result<()> {
        let state_dir = self
            .state_file_path
            .parent()
            .unwrap_or(&self.config.hidden_volume_root);
        crate::hidden_root::ensure_state_dir_attached(
            &self.filesystem,
            &self.config.hidden_volume_root,
            state_dir,
        )?;
        state_file.save_with_custom_root(&self.state_file_path, &self.config.hidden_volume_root)
    }

    /// Plan a `reset-upper` for `target`. Refused in the hidden session (the
    /// upper is the live root there) and for a relative path or `/` itself.
    pub fn plan_reset_upper(&self, target: &Path) -> Result<ResetUpperPlan> {
        if self.session_view().is_hidden() {
            return Err(NailsError::InvalidState(
                "reset-upper cannot run in the hidden session: the upper is the live root; \
                 deactivate first"
                    .to_string(),
            ));
        }
        self.plan_reset_upper_on(target, &SessionView::Decoy)
    }

    /// [`plan_reset_upper`](Self::plan_reset_upper) for a given session view.
    pub fn plan_reset_upper_on(&self, target: &Path, view: &SessionView) -> Result<ResetUpperPlan> {
        if view.is_hidden() {
            return Err(NailsError::InvalidState(
                "reset-upper cannot run in the hidden session".to_string(),
            ));
        }
        if !target.is_absolute()
            || target == Path::new("/")
            || target.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(NailsError::InvalidArgument(format!(
                "{} is not a resettable path: give an absolute path below /",
                target.display()
            )));
        }
        let layout = Layout::new(&self.config.hidden_volume_root);
        let mounts = self.config.hidden_volume_root.join("root/mounts");
        let candidates = [layout.in_upper(target), mounts.join(escape_path(target))];
        let mut removals = Vec::new();
        for candidate in candidates {
            if self.filesystem.path_exists(&candidate)? {
                removals.push(candidate);
            }
        }
        Ok(ResetUpperPlan {
            resets_nix_store: target == Path::new("/nix"),
            target: target.to_path_buf(),
            removals,
        })
    }

    /// Apply a [`ResetUpperPlan`]: remove what it found.
    pub fn apply_reset_upper(&self, plan: &ResetUpperPlan) -> Result<()> {
        for path in &plan.removals {
            if self.filesystem.is_directory(path)? {
                self.filesystem.remove_dir_all(path)?;
            } else {
                self.filesystem.remove_file(path)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Config, RealFilesystem};

    fn manager(root: &Path) -> NailsManager<RealFilesystem> {
        let config = Config {
            hidden_volume_root: root.to_path_buf(),
            state_file_path: root.join("state.json"),
            log_path: root.join("logs"),
            ..Config::test_default()
        };
        NailsManager::new(RealFilesystem, config, root.join("state.json"))
    }

    #[test]
    fn reset_upper_removes_the_hidden_copy_and_a_separate_filesystems_layers() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("root/upper/home/alice")).unwrap();
        std::fs::create_dir_all(root.path().join("root/mounts/home/upper")).unwrap();
        std::fs::create_dir_all(root.path().join("root/upper/etc")).unwrap();
        let m = manager(root.path());
        let plan = m
            .plan_reset_upper_on(Path::new("/home"), &SessionView::Decoy)
            .unwrap();
        assert_eq!(plan.removals.len(), 2);
        m.apply_reset_upper(&plan).unwrap();
        assert!(!root.path().join("root/upper/home").exists());
        assert!(!root.path().join("root/mounts/home").exists());
        assert!(root.path().join("root/upper/etc").exists());
        let again = m
            .plan_reset_upper_on(Path::new("/home"), &SessionView::Decoy)
            .unwrap();
        assert!(again.is_empty());
    }

    #[test]
    fn reset_upper_refuses_the_hidden_session_the_root_and_relative_paths() {
        let root = tempfile::tempdir().unwrap();
        let m = manager(root.path());
        let hidden = SessionView::HiddenWithoutPlan("test".into());
        assert!(m.plan_reset_upper_on(Path::new("/home"), &hidden).is_err());
        for bad in ["/", "home", "/home/../etc"] {
            assert!(
                m.plan_reset_upper_on(Path::new(bad), &SessionView::Decoy)
                    .is_err(),
                "{bad}"
            );
        }
        let nix = m
            .plan_reset_upper_on(Path::new("/nix"), &SessionView::Decoy)
            .unwrap();
        assert!(nix.resets_nix_store);
    }
}
