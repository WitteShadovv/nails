// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Fresh-home persona bind mount.
//!
//! In [`PersonaMode::FreshHome`](crate::config::PersonaMode::FreshHome) the hidden
//! session must not see the decoy home. After the `/home` overlay is mounted, a
//! fresh directory on the hidden volume (`{hidden_root}/persona/home`) is
//! bind-mounted over the operator's home: a plain bind with no decoy lower, so the
//! decoy home contents are invisible while the hidden session's writes land on the
//! hidden volume.
//!
//! The bind is pushed onto the same [`MountTracker`] as the overlays, after them,
//! so it is unmounted first on rollback and recorded in the Active state for
//! deactivation to tear down. In the default
//! [`SharedHome`](crate::config::PersonaMode::SharedHome) mode this is a no-op.

use super::{MountInfo, MountTracker};
use crate::config::{PersonaMode, persona_home_source};
use crate::{Filesystem, NailsManager, Result, TargetUser, Verbosity};

impl<F: Filesystem> NailsManager<F> {
    /// Bind the fresh persona home over the operator's home when fresh-home mode
    /// is active. No-op in shared-home mode.
    ///
    /// Resolves the operator with [`TargetUser::resolve`]; fresh-home cannot
    /// proceed without knowing whose home to replace, so a resolution failure is
    /// returned rather than silently skipped.
    pub(in crate::manager::activation) fn mount_persona_home(
        &self,
        tracker: &mut MountTracker<F>,
        verbosity: Verbosity,
    ) -> Result<()> {
        if self.config.persona.mode != PersonaMode::FreshHome {
            return Ok(());
        }

        let user = TargetUser::resolve()?;
        self.bind_persona_home_over(tracker, &user, verbosity)
    }

    /// Create and bind the persona home over `user`'s home, tracking the bind for
    /// rollback. Factored out of [`mount_persona_home`] so it can be driven with an
    /// explicit user in tests without touching the real environment.
    pub(in crate::manager::activation) fn bind_persona_home_over(
        &self,
        tracker: &mut MountTracker<F>,
        user: &TargetUser,
        verbosity: Verbosity,
    ) -> Result<()> {
        let source = persona_home_source(&self.config.hidden_volume_root);
        let home = user.home().to_path_buf();

        // Create the persona home owned by the operator at 0700. `write_user_file`
        // creates missing parent directories owned by the target user (and chowns
        // them on a real host); removing the marker leaves the home empty on first
        // use and untouched on later cycles.
        let marker = source.join(".nails-keep");
        self.filesystem.write_user_file(&marker, "", user, 0o600)?;
        let _ = self.filesystem.remove_file(&marker);

        if verbosity >= Verbosity::Normal {
            tracing::info!(
                source = %source.display(),
                home = %home.display(),
                "Binding fresh persona home over the operator's home (decoy home hidden)"
            );
        }

        self.filesystem.bind_mount(&source, &home)?;
        // Tracked as a persistent mount: it is torn down with `unmount`, which the
        // mount-table classifier recognises as NAILS-owned via its persona-home
        // root. Pushed after the overlays so LIFO rollback unmounts it first.
        tracker.push_mount(MountInfo::persistent(home));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MockFilesystem;
    use crate::config::{Config, PersonaConfig, PersonaMode};
    use std::path::{Path, PathBuf};

    fn manager_with_mode(mode: PersonaMode) -> NailsManager<MockFilesystem> {
        let hidden_root = PathBuf::from("/mnt/data");
        let config = Config {
            hidden_volume_root: hidden_root.clone(),
            state_file_path: hidden_root.join("state.json"),
            log_path: hidden_root.join("logs"),
            persona: PersonaConfig {
                mode,
                ..Default::default()
            },
            ..Config::test_default()
        };
        let state_path = config.state_file_path.clone();
        NailsManager::new(MockFilesystem::new(), config, state_path)
    }

    #[test]
    fn fresh_home_binds_persona_home_over_operator_home() {
        let manager = manager_with_mode(PersonaMode::FreshHome);
        let user = TargetUser::for_test(1000, 100, "op", "/home/op", "/bin/bash");
        let mut tracker = MountTracker::new(manager.filesystem());

        manager
            .bind_persona_home_over(&mut tracker, &user, Verbosity::Normal)
            .expect("fresh-home bind should succeed");

        let home = Path::new("/home/op");
        let source = Path::new("/mnt/data/persona/home");
        assert_eq!(
            manager.filesystem().mock_bind_source(home).as_deref(),
            Some(source),
            "persona home must be bound over the operator's home"
        );
        assert_eq!(
            manager.filesystem().mock_get_owner(source),
            Some((1000, 100)),
            "persona home must be owned by the operator"
        );
        assert!(
            tracker.mounted.iter().any(|m| m.target == home),
            "the persona bind must be tracked for rollback"
        );
    }

    #[test]
    fn persona_bind_rolls_back_with_the_tracker() {
        let manager = manager_with_mode(PersonaMode::FreshHome);
        let user = TargetUser::for_test(1000, 100, "op", "/home/op", "/bin/bash");
        let mut tracker = MountTracker::new(manager.filesystem());

        manager
            .bind_persona_home_over(&mut tracker, &user, Verbosity::Normal)
            .unwrap();
        assert!(
            manager
                .filesystem()
                .is_mounted(Path::new("/home/op"))
                .unwrap()
        );

        tracker
            .rollback_all()
            .expect("rollback should unmount the bind");
        assert!(
            !manager
                .filesystem()
                .is_mounted(Path::new("/home/op"))
                .unwrap(),
            "the persona bind must come down on rollback"
        );
    }

    #[test]
    fn shared_home_records_no_bind() {
        let manager = manager_with_mode(PersonaMode::SharedHome);
        let mut tracker = MountTracker::new(manager.filesystem());

        // shared-home returns before resolving the operator, so no bind is made.
        manager
            .mount_persona_home(&mut tracker, Verbosity::Normal)
            .expect("shared-home is a no-op");

        assert!(
            tracker.mounted.is_empty(),
            "shared-home must not bind a persona home"
        );
        assert!(
            manager
                .filesystem()
                .mock_bind_source(Path::new("/home/op"))
                .is_none()
        );
    }
}
