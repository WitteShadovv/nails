//! NixOS Profile Switching Logic (Step 9)
//!
//! Handles building (if needed) and switching to the hidden NixOS profile.
//! Both flake and legacy paths share the same control flow:
//!
//! 1. If Step 7 supplied a fast-path generation, attempt
//!    `switch-to-configuration test` directly.
//! 2. On failure (or if no cached generation), fall back to
//!    `nixos-rebuild test` which does a combined build + switch.
//! 3. Persist the resulting generation and fingerprint.

use super::{ensure_run_current_system_symlink, select_system_profile};
use crate::platform::ConfigLayer;
use crate::{Filesystem, NailsError, NailsManager, Result, Verbosity};

impl<F: Filesystem> NailsManager<F> {
    /// Switch NixOS profile — unified for flake and legacy (Step 9).
    ///
    /// The build and switch themselves run through the platform
    /// [`ConfigLayer`](crate::platform::ConfigLayer): a host without a layer (FHS /
    /// Debian, or an overlay-only run) skips them entirely, so `nixos-rebuild` and
    /// `switch-to-configuration` never run there. The manager keeps ownership of
    /// the `/run/current-system` preparation and of persisting the resulting
    /// generation + fingerprint into its state cache.
    pub(super) fn switch_nixos_profile(
        &self,
        generation: &Option<String>,
        new_fingerprint: &Option<String>,
        verbosity: Verbosity,
    ) -> Result<()> {
        let Some(layer) = self.config_layer() else {
            return Ok(());
        };
        let Some(builder) = self.nixos_builder.as_ref() else {
            return Ok(());
        };

        // Ensure /run/current-system points at the right profile.
        if let Some(system_profile) = select_system_profile(&self.filesystem)? {
            ensure_run_current_system_symlink(&self.filesystem, &system_profile).map_err(|e| {
                NailsError::NixOSError(format!(
                    "Failed to prepare /run/current-system for NixOS switch: {}",
                    e
                ))
            })?;
        }

        // Build and switch to the hidden configuration through the config layer.
        // `apply` takes no filesystem argument, so name the layer's `F` explicitly.
        ConfigLayer::<F>::apply(&layer, builder, generation.as_deref(), verbosity)?;

        // --- Persist generation + fingerprint -----------------------------
        let mut cached = self.cached_state.borrow_mut();
        if let Some(ref mut state_file) = *cached {
            if let Some(generation_id) = generation {
                state_file.nixos_generation = Some(generation_id.clone());
            } else if let Ok(current_gen) = builder.current_system_generation() {
                state_file.nixos_generation = current_gen;
            }
            state_file.config_fingerprint = new_fingerprint.clone();

            drop(cached);
            if let Err(e) = self.save_cached_state()
                && verbosity >= Verbosity::Debug
            {
                tracing::warn!("Failed to save nixos_generation to state: {}", e);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::PathKind;
    use crate::nixos::{NixOSBuilder, RealCommandExecutor};
    use crate::test_support::EnvGuard;
    use crate::{MockFilesystem, StateFile, TestWorld};
    use serial_test::serial;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn write_executable_script(path: &std::path::Path, body: &str) {
        fs::write(path, body).unwrap();
        let mut perms = fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).unwrap();

        assert!(
            fs::metadata(path).unwrap().permissions().mode() & 0o111 != 0,
            "script should be executable: {}",
            path.display()
        );
    }

    #[test]
    #[serial]
    fn test_switch_nixos_profile_wraps_run_current_system_preparation_error() {
        let mut env = EnvGuard::lock();

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path();
        let profiles_dir = hidden_root.join("profiles");
        let system_profile = profiles_dir.join("system");
        let generation_dir = profiles_dir.join("system-123-link");
        fs::create_dir_all(generation_dir.join("bin")).unwrap();

        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(profiles_dir.to_str().unwrap(), true);
        fs.mock_set_path_type(profiles_dir.to_str().unwrap(), PathKind::Dir);
        fs.mock_set_directory_contents(&profiles_dir, vec![generation_dir]);
        fs.mock_set_path_exists("/run/current-system", true);
        fs.mock_set_path_type("/run/current-system", PathKind::Dir);

        env.set("NAILS_SYSTEM_PROFILE_PATH", &system_profile);

        let builder =
            NixOSBuilder::new(hidden_root.join("config"), hidden_root.join("nails-system"));
        let (manager, _tempdir) = TestWorld::new()
            .with_filesystem(fs)
            .with_hidden_root(hidden_root)
            .with_nixos(builder)
            .inactive()
            .manager();

        let err = manager
            .switch_nixos_profile(
                &Some("123".to_string()),
                &Some("fp".to_string()),
                Verbosity::Quiet,
            )
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("Failed to prepare /run/current-system for NixOS switch")
        );
        assert!(
            err.to_string()
                .contains("/run/current-system exists but is not a symlink")
        );
    }

    #[test]
    #[cfg(unix)]
    #[serial]
    fn test_switch_nixos_profile_fast_path_falls_back_and_persists_generation() {
        let mut env = EnvGuard::lock();

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path();
        let profiles_dir = hidden_root.join("profiles");
        fs::create_dir_all(&profiles_dir).unwrap();
        let system_profile = profiles_dir.join("system");
        let system_generation = profiles_dir.join("system-123-link");
        fs::create_dir_all(system_generation.join("bin")).unwrap();
        write_executable_script(
            &system_generation.join("bin/switch-to-configuration"),
            "#!/usr/bin/env bash\nexit 1\n",
        );
        symlink(&system_generation, &system_profile).unwrap();
        env.set("NAILS_SYSTEM_PROFILE_PATH", &system_profile);

        let bin_dir = hidden_root.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let marker = hidden_root.join("rebuild-called");
        write_executable_script(
            &bin_dir.join("nixos-rebuild"),
            &format!("#!/usr/bin/env bash\n: > '{}'\nexit 0\n", marker.display()),
        );

        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(profiles_dir.to_str().unwrap(), true);
        fs.mock_set_path_type(profiles_dir.to_str().unwrap(), PathKind::Dir);
        fs.mock_set_directory_contents(&profiles_dir, vec![system_generation.clone()]);

        let builder =
            NixOSBuilder::new(hidden_root.join("config"), hidden_root.join("nails-system"))
                .with_executor(Box::new(RealCommandExecutor::with_search_path(&bin_dir)));
        let (manager, _tempdir) = TestWorld::new()
            .with_filesystem(fs.clone())
            .with_hidden_root(hidden_root)
            .with_nixos(builder)
            .inactive()
            .manager();

        manager
            .switch_nixos_profile(
                &Some("123".to_string()),
                &Some("new-fp".to_string()),
                Verbosity::Quiet,
            )
            .unwrap();

        assert!(marker.exists());
        assert_eq!(
            fs.mock_get_symlink_target(std::path::Path::new("/run/current-system")),
            Some(system_generation)
        );

        let saved = StateFile::load(&hidden_root.join("state.json")).unwrap();
        assert_eq!(saved.nixos_generation, Some("123".to_string()));
        assert_eq!(saved.config_fingerprint, Some("new-fp".to_string()));
    }

    #[test]
    #[cfg(unix)]
    #[serial]
    fn test_switch_nixos_profile_wraps_build_and_switch_nixos_errors() {
        let mut env = EnvGuard::lock();
        env.remove("NAILS_SYSTEM_PROFILE_PATH");

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path();
        let bin_dir = hidden_root.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        write_executable_script(
            &bin_dir.join("nixos-rebuild"),
            "#!/usr/bin/env bash\nprintf 'boom\\n' 1>&2\nexit 2\n",
        );

        let builder =
            NixOSBuilder::new(hidden_root.join("config"), hidden_root.join("nails-system"))
                .with_executor(Box::new(RealCommandExecutor::with_search_path(&bin_dir)));
        let (manager, _tempdir) = TestWorld::new()
            .with_filesystem(MockFilesystem::new())
            .with_hidden_root(hidden_root)
            .with_nixos(builder)
            .inactive()
            .manager();

        let err = manager
            .switch_nixos_profile(&None, &Some("fp".to_string()), Verbosity::Quiet)
            .unwrap_err();
        let err_text = err.to_string();
        assert!(err_text.contains("NixOS build+switch failed:"));
        assert!(err_text.contains("boom"));
    }
}
