//! NixOS toplevel build + switch logic (Step 9)
//!
//! Builds the hidden NixOS system toplevel explicitly and switches to it. Both
//! the flake and legacy paths share the same control flow:
//!
//! 1. If a fast-path toplevel was carried forward (fingerprint unchanged and the
//!    cached store path still present), switch straight to it.
//! 2. Otherwise build the toplevel (`nix build …#…system.build.toplevel`) and
//!    switch to the resulting `/nix/store/…-nixos-system-*` path.
//! 3. Persist the toplevel store path and the new fingerprint, so the next
//!    activation with an unchanged config can take the fast path.
//!
//! Only `switch-to-configuration test` is ever run — never a `switch`/`boot` that
//! would rewrite the bootloader, ESP or EFI NVRAM and leave evidence the hidden
//! mode existed.

use super::{HiddenConfigOutcome, ensure_run_current_system_symlink, select_system_profile};
use crate::platform::ConfigLayer;
use crate::{Filesystem, NailsError, NailsManager, Result, Verbosity};

impl<F: Filesystem> NailsManager<F> {
    /// Build (if needed) and switch to the hidden NixOS toplevel — unified for
    /// flake and legacy (Step 9).
    ///
    /// The build and switch run through the platform
    /// [`ConfigLayer`](crate::platform::ConfigLayer): a host without a layer (FHS /
    /// Debian, or an overlay-only run) skips them entirely and reports
    /// [`HiddenConfigOutcome::NotRequested`]. The manager keeps ownership of the
    /// `/run/current-system` preparation and of persisting the resulting toplevel
    /// store path + fingerprint into its state cache.
    ///
    /// Returns [`HiddenConfigOutcome::Applied`] on a successful switch (carrying
    /// the toplevel store path and whether the fast path was taken), or `Err` when
    /// the build or switch failed — the caller turns that into
    /// [`HiddenConfigOutcome::Failed`].
    pub(super) fn switch_nixos_profile(
        &self,
        fast_path_toplevel: &Option<String>,
        new_fingerprint: &Option<String>,
        verbosity: Verbosity,
    ) -> Result<HiddenConfigOutcome> {
        let Some(layer) = self.config_layer() else {
            return Ok(HiddenConfigOutcome::NotRequested);
        };
        let Some(builder) = self.nixos_builder.as_ref() else {
            return Ok(HiddenConfigOutcome::NotRequested);
        };

        // The fast path is taken when a cached toplevel was carried forward
        // (fingerprint unchanged and the store path still present).
        let fast_path = fast_path_toplevel.is_some();

        // Ensure /run/current-system points at the right profile.
        if let Some(system_profile) = select_system_profile(&self.filesystem)? {
            ensure_run_current_system_symlink(&self.filesystem, &system_profile).map_err(|e| {
                NailsError::NixOSError(format!(
                    "Failed to prepare /run/current-system for NixOS switch: {}",
                    e
                ))
            })?;
        }

        // Build and switch to the hidden toplevel through the config layer. `apply`
        // takes no filesystem argument, so name the layer's `F` explicitly.
        let applied_toplevel = ConfigLayer::<F>::apply(
            &layer,
            &self.filesystem,
            builder,
            fast_path_toplevel.as_deref(),
            verbosity,
        )?;

        // --- Persist toplevel store path + fingerprint --------------------
        // The flake path (and the fast path) yields a store path to cache; the
        // legacy `nixos-rebuild test` path yields none, so the fingerprint is
        // still recorded but no toplevel is cached. The toplevel reported in the
        // outcome falls back to the carried-forward fast-path path when the layer
        // returned none.
        let toplevel = applied_toplevel.or_else(|| fast_path_toplevel.clone());
        {
            let mut cached = self.cached_state.borrow_mut();
            if let Some(ref mut state_file) = *cached {
                // An Applied switch is always NixOS; record the generation (keeping
                // any prior one when this switch produced no fresh toplevel).
                state_file.set_nixos_generation(toplevel.clone());
                state_file.config_fingerprint = new_fingerprint.clone();

                drop(cached);
                if let Err(e) = self.save_cached_state()
                    && verbosity >= Verbosity::Debug
                {
                    tracing::warn!("Failed to save hidden_toplevel to state: {}", e);
                }
            }
        }

        Ok(HiddenConfigOutcome::Applied {
            toplevel,
            fast_path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::PathKind;
    use crate::nixos::{CommandExecutor, NixOSBuilder, SwitchAction};
    use crate::test_support::EnvGuard;
    use crate::{MockFilesystem, StateFile, TestWorld};
    use serial_test::serial;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    const TOPLEVEL: &str = "/nix/store/0000000000000000000000000000000a-nixos-system-host-24.11";

    /// A command executor that returns a canned toplevel store path for
    /// `nix build --print-out-paths` and records every invocation.
    #[derive(Clone)]
    struct StubExecutor {
        toplevel: String,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl StubExecutor {
        fn new() -> Self {
            Self {
                toplevel: TOPLEVEL.to_string(),
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandExecutor for StubExecutor {
        fn execute_nixos_rebuild(
            &self,
            args: &[&str],
            _clear_nix_path: bool,
        ) -> Result<(bool, String, String)> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("nixos-rebuild {}", args.join(" ")));
            Ok((true, String::new(), String::new()))
        }

        fn execute_nix(
            &self,
            args: &[&str],
            _clear_nix_path: bool,
        ) -> Result<(bool, String, String)> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("nix {}", args.join(" ")));
            if args.first() == Some(&"build") {
                return Ok((true, format!("{}\n", self.toplevel), String::new()));
            }
            Ok((true, String::new(), String::new()))
        }

        fn execute_switch_to_configuration(
            &self,
            script_path: &Path,
            action: SwitchAction,
        ) -> Result<(bool, String, String)> {
            self.calls.lock().unwrap().push(format!(
                "switch-to-configuration {} {}",
                script_path.display(),
                action.as_arg()
            ));
            Ok((true, String::new(), String::new()))
        }
    }

    fn flake_builder(hidden_root: &Path, executor: StubExecutor) -> NixOSBuilder {
        NixOSBuilder::new_with_flake_ref(
            "/etc/nixos#host".to_string(),
            hidden_root.join("nails-system"),
        )
        .with_executor(Box::new(executor))
    }

    #[test]
    #[serial]
    fn test_switch_wraps_run_current_system_preparation_error() {
        let mut env = EnvGuard::lock();

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path();
        let profiles_dir = hidden_root.join("profiles");
        let system_profile = profiles_dir.join("system");
        let generation_dir = profiles_dir.join("system-123-link");
        std::fs::create_dir_all(generation_dir.join("bin")).unwrap();

        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(profiles_dir.to_str().unwrap(), true);
        fs.mock_set_path_type(profiles_dir.to_str().unwrap(), PathKind::Dir);
        fs.mock_set_directory_contents(&profiles_dir, vec![generation_dir]);
        fs.mock_set_path_exists("/run/current-system", true);
        fs.mock_set_path_type("/run/current-system", PathKind::Dir);

        env.set("NAILS_SYSTEM_PROFILE_PATH", &system_profile);

        let builder = flake_builder(hidden_root, StubExecutor::new());
        let (manager, _tempdir) = TestWorld::new()
            .with_filesystem(fs)
            .with_hidden_root(hidden_root)
            .with_nixos(builder)
            .inactive()
            .manager();

        let err = manager
            .switch_nixos_profile(&None, &Some("fp".to_string()), Verbosity::Quiet)
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("Failed to prepare /run/current-system for NixOS switch")
        );
    }

    #[test]
    #[serial]
    fn test_switch_builds_toplevel_and_persists_store_path() {
        let mut env = EnvGuard::lock();
        env.remove("NAILS_SYSTEM_PROFILE_PATH");

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path();

        let executor = StubExecutor::new();
        let recorded = executor.clone();
        let builder = flake_builder(hidden_root, executor);
        let (manager, _tempdir) = TestWorld::new()
            .with_filesystem(MockFilesystem::new())
            .with_hidden_root(hidden_root)
            .with_nixos(builder)
            .inactive()
            .manager();

        let outcome = manager
            .switch_nixos_profile(&None, &Some("new-fp".to_string()), Verbosity::Quiet)
            .unwrap();
        assert!(
            matches!(
                outcome,
                HiddenConfigOutcome::Applied {
                    fast_path: false,
                    toplevel: Some(_)
                }
            ),
            "a full build reports Applied on the slow path: {outcome:?}"
        );

        let calls = recorded.calls();
        assert!(
            calls.iter().any(|c| c.starts_with("nix build")),
            "a full activation must build the toplevel: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|c| c.contains("switch-to-configuration") && c.ends_with(" test")),
            "the built toplevel must be switched to with `test`: {calls:?}"
        );

        let saved = StateFile::load(&hidden_root.join("state.json")).unwrap();
        let toplevel = saved
            .hidden_toplevel()
            .expect("toplevel store path persisted");
        assert!(
            toplevel.starts_with("/nix/store/") && toplevel.contains("nixos-system"),
            "the stored value must be a /nix/store/...-nixos-system-* path, got {toplevel}"
        );
        assert_eq!(saved.config_fingerprint, Some("new-fp".to_string()));
    }

    #[test]
    #[serial]
    fn test_switch_fast_path_reuses_cached_toplevel_without_building() {
        let mut env = EnvGuard::lock();
        env.remove("NAILS_SYSTEM_PROFILE_PATH");

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path();

        // The cached toplevel is present on the (overlaid) /nix.
        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(TOPLEVEL, true);

        let executor = StubExecutor::new();
        let recorded = executor.clone();
        let builder = flake_builder(hidden_root, executor);
        let (manager, _tempdir) = TestWorld::new()
            .with_filesystem(fs)
            .with_hidden_root(hidden_root)
            .with_nixos(builder)
            .inactive()
            .manager();

        let outcome = manager
            .switch_nixos_profile(
                &Some(TOPLEVEL.to_string()),
                &Some("fp".to_string()),
                Verbosity::Quiet,
            )
            .unwrap();
        assert!(
            matches!(
                outcome,
                HiddenConfigOutcome::Applied {
                    fast_path: true,
                    ..
                }
            ),
            "reusing the cached toplevel reports the fast path: {outcome:?}"
        );

        let calls = recorded.calls();
        assert!(
            !calls.iter().any(|c| c.starts_with("nix build")),
            "the fast path must not build: {calls:?}"
        );
        assert!(
            calls
                .iter()
                .any(|c| c.contains("switch-to-configuration") && c.contains(TOPLEVEL)),
            "the fast path must switch to the cached toplevel: {calls:?}"
        );

        let saved = StateFile::load(&hidden_root.join("state.json")).unwrap();
        assert_eq!(saved.hidden_toplevel(), Some(TOPLEVEL));
    }

    #[test]
    #[serial]
    fn test_overlay_only_switch_is_not_requested_and_writes_no_rebuild_notification() {
        let mut env = EnvGuard::lock();
        env.remove("NAILS_SYSTEM_PROFILE_PATH");

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path();

        // No NixOS builder is attached: this is the overlay-only / non-NixOS
        // (FHS) case, where there is no declarative layer to build or switch.
        let (manager, _tempdir) = TestWorld::new()
            .with_filesystem(MockFilesystem::new())
            .with_hidden_root(hidden_root)
            .inactive()
            .manager();

        // The switch itself reports that no rebuild was requested, without
        // running any build or switch command.
        let outcome = manager
            .switch_nixos_profile(&None, &None, Verbosity::Quiet)
            .unwrap();
        assert!(
            matches!(outcome, HiddenConfigOutcome::NotRequested),
            "overlay-only activation must not request a NixOS switch: {outcome:?}"
        );

        // The full post-overlay step carries the same outcome through and, on
        // NotRequested, writes no "NixOS Rebuild Complete" notification: the
        // rebuild step is honestly absent rather than faked.
        let post = manager.run_post_overlay_nixos_switch(&None, &None, Verbosity::Quiet);
        assert!(
            matches!(post, HiddenConfigOutcome::NotRequested),
            "the post-overlay step must stay NotRequested overlay-only: {post:?}"
        );

        let notifications = hidden_root.join("notifications");
        let has_notification = notifications
            .read_dir()
            .map(|mut entries| entries.next().is_some())
            .unwrap_or(false);
        assert!(
            !has_notification,
            "overlay-only activation must write no rebuild notification"
        );
    }

    #[test]
    #[serial]
    fn test_switch_fast_path_rebuilds_when_cached_toplevel_missing() {
        let mut env = EnvGuard::lock();
        env.remove("NAILS_SYSTEM_PROFILE_PATH");

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path();

        // The cached toplevel is NOT present on /nix (decoy GC removed it), so the
        // fast path is dropped and a full build runs.
        let executor = StubExecutor::new();
        let recorded = executor.clone();
        let builder = flake_builder(hidden_root, executor);
        let (manager, _tempdir) = TestWorld::new()
            .with_filesystem(MockFilesystem::new())
            .with_hidden_root(hidden_root)
            .with_nixos(builder)
            .inactive()
            .manager();

        manager
            .switch_nixos_profile(
                &Some("/nix/store/deadbeef-nixos-system-gone".to_string()),
                &Some("fp".to_string()),
                Verbosity::Quiet,
            )
            .unwrap();

        let calls = recorded.calls();
        assert!(
            calls.iter().any(|c| c.starts_with("nix build")),
            "a missing cached toplevel must fall back to a full build: {calls:?}"
        );

        // The freshly built toplevel, not the vanished cached one, is persisted.
        let saved = StateFile::load(&hidden_root.join("state.json")).unwrap();
        assert_eq!(saved.hidden_toplevel(), Some(TOPLEVEL));
    }
}
