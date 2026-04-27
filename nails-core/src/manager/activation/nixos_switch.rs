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
use crate::{
    Filesystem, NailsError, NailsManager, Result, Stopwatch, Verbosity,
    classify_nixos_failure_category, format_classified_nixos_failure,
};

impl<F: Filesystem> NailsManager<F> {
    /// Switch NixOS profile — unified for flake and legacy (Step 9).
    pub(super) fn switch_nixos_profile(
        &self,
        generation: &Option<String>,
        new_fingerprint: &Option<String>,
        verbosity: Verbosity,
    ) -> Result<()> {
        if self.nixos_builder.is_none() {
            return Ok(());
        }

        if verbosity >= Verbosity::Normal {
            tracing::info!("Switching to hidden NixOS configuration...");
        }

        // Ensure /run/current-system points at the right profile.
        if let Some(system_profile) = select_system_profile(&self.filesystem)? {
            ensure_run_current_system_symlink(&self.filesystem, &system_profile).map_err(|e| {
                NailsError::NixOSError(format!(
                    "Failed to prepare /run/current-system for NixOS switch: {}",
                    e
                ))
            })?;
        }

        let step_timer = Stopwatch::start();
        let builder = self.nixos_builder.as_ref().unwrap();

        // --- Fast path: try switching to cached generation directly -------
        // Both flake and legacy slow-paths use `nixos-rebuild test` which
        // writes to the system profile, so the cached generation ID is always
        // a system generation number.
        let mut switched = false;
        if let Some(generation_id) = generation {
            if verbosity >= Verbosity::Normal {
                tracing::info!(
                    generation = %generation_id,
                    "Attempting fast-path switch-to-configuration"
                );
            }

            match builder.switch_system_generation(generation_id, "test") {
                Ok(()) => {
                    switched = true;
                    if verbosity >= Verbosity::Normal {
                        tracing::info!(
                            step = "nixos_switch",
                            duration_ms = step_timer.elapsed().as_millis() as u64,
                            "NixOS switch complete via fast path ({})",
                            step_timer
                        );
                    }
                }
                Err(e) => {
                    if verbosity >= Verbosity::Normal {
                        tracing::warn!(
                            error = %e,
                            "Fast-path switch failed, falling back to nixos-rebuild"
                        );
                    }
                }
            }
        }

        // --- Slow path: nixos-rebuild test (build + switch) ---------------
        if !switched {
            builder.build_and_switch().map_err(|e| {
                let error_msg = match &e {
                    NailsError::NixOSError(message) => {
                        let category = classify_nixos_failure_category(message, "");
                        format!(
                            "NixOS build+switch failed: [{}] {}",
                            category,
                            format_classified_nixos_failure(
                                "nixos-rebuild test failed",
                                message,
                                ""
                            )
                        )
                    }
                    other => format!("NixOS build+switch failed: {}", other),
                };

                tracing::error!(
                    error = %e,
                    phase = "nixos_switch",
                    rollback = true,
                    "NixOS build+switch failed"
                );

                match e {
                    NailsError::NixOSError(_) => NailsError::NixOSError(error_msg),
                    other => other,
                }
            })?;

            if verbosity >= Verbosity::Normal {
                tracing::info!(
                    step = "nixos_switch",
                    duration_ms = step_timer.elapsed().as_millis() as u64,
                    "NixOS build+switch complete ({})",
                    step_timer
                );
            }
        }

        // --- Persist generation + fingerprint -----------------------------
        let mut cached = self
            .cached_state
            .lock()
            .map_err(|e| crate::NailsError::LockPoisoned(e.to_string()))?;
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
    use crate::nixos::NixOSBuilder;
    use crate::{Config, MockFilesystem, StateFile, SystemState};
    use serial_test::serial;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn clear_system_profile_env() {
        unsafe {
            std::env::remove_var("NAILS_SYSTEM_PROFILE_PATH");
        }
    }

    fn restore_path_env(old_path: Option<std::ffi::OsString>) {
        if let Some(path) = old_path {
            unsafe {
                std::env::set_var("PATH", path);
            }
        } else {
            unsafe {
                std::env::remove_var("PATH");
            }
        }
    }

    fn prepend_path(dir: &std::path::Path, old_path: &Option<std::ffi::OsString>) {
        let mut paths = vec![dir.to_path_buf()];
        if let Some(existing) = old_path {
            paths.extend(std::env::split_paths(existing));
        }

        unsafe {
            std::env::set_var(
                "PATH",
                std::env::join_paths(paths).expect("failed to compose PATH for test"),
            );
        }
    }

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

    fn make_manager(
        fs: MockFilesystem,
        hidden_root: &std::path::Path,
        builder: NixOSBuilder,
    ) -> NailsManager<MockFilesystem> {
        let state_path = hidden_root.join("state.json");
        let manager = NailsManager::with_nixos(
            fs,
            Config {
                hidden_volume_root: hidden_root.to_path_buf(),
                state_file_path: state_path.clone(),
                overlays: vec![],
                ..Config::test_default()
            },
            state_path,
            builder,
        );
        let mut cached = manager.cached_state.lock().expect("manager mutex poisoned");
        *cached = Some(StateFile {
            state: SystemState::Inactive,
            ..StateFile::default()
        });
        drop(cached);
        manager
    }

    #[test]
    #[serial]
    fn test_switch_nixos_profile_wraps_run_current_system_preparation_error() {
        clear_system_profile_env();

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path();
        let profiles_dir = hidden_root.join("profiles");
        let system_profile = profiles_dir.join("system");
        let generation_dir = profiles_dir.join("system-123-link");
        fs::create_dir_all(generation_dir.join("bin")).unwrap();

        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(profiles_dir.to_str().unwrap(), true);
        fs.mock_set_path_type(profiles_dir.to_str().unwrap(), "directory");
        fs.mock_set_directory_contents(&profiles_dir, vec![generation_dir]);
        fs.mock_set_path_exists("/run/current-system", true);
        fs.mock_set_path_type("/run/current-system", "directory");

        unsafe {
            std::env::set_var("NAILS_SYSTEM_PROFILE_PATH", &system_profile);
        }

        let builder =
            NixOSBuilder::new(hidden_root.join("config"), hidden_root.join("nails-system"));
        let manager = make_manager(fs, hidden_root, builder);

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

        clear_system_profile_env();
    }

    #[test]
    #[cfg(unix)]
    #[serial]
    fn test_switch_nixos_profile_fast_path_falls_back_and_persists_generation() {
        clear_system_profile_env();

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
        unsafe {
            std::env::set_var("NAILS_SYSTEM_PROFILE_PATH", &system_profile);
        }

        let bin_dir = hidden_root.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let marker = hidden_root.join("rebuild-called");
        write_executable_script(
            &bin_dir.join("nixos-rebuild"),
            &format!("#!/usr/bin/env bash\n: > '{}'\nexit 0\n", marker.display()),
        );

        let old_path = std::env::var_os("PATH");
        prepend_path(&bin_dir, &old_path);

        let fs = MockFilesystem::new();
        fs.mock_set_path_exists(profiles_dir.to_str().unwrap(), true);
        fs.mock_set_path_type(profiles_dir.to_str().unwrap(), "directory");
        fs.mock_set_directory_contents(&profiles_dir, vec![system_generation.clone()]);

        let builder =
            NixOSBuilder::new(hidden_root.join("config"), hidden_root.join("nails-system"));
        let manager = make_manager(fs.clone(), hidden_root, builder);

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

        restore_path_env(old_path);
        clear_system_profile_env();
    }

    #[test]
    #[cfg(unix)]
    #[serial]
    fn test_switch_nixos_profile_wraps_build_and_switch_nixos_errors() {
        clear_system_profile_env();

        let temp_dir = tempfile::tempdir().unwrap();
        let hidden_root = temp_dir.path();
        let bin_dir = hidden_root.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        write_executable_script(
            &bin_dir.join("nixos-rebuild"),
            "#!/usr/bin/env bash\nprintf 'boom\\n' 1>&2\nexit 2\n",
        );

        let old_path = std::env::var_os("PATH");
        prepend_path(&bin_dir, &old_path);

        let builder =
            NixOSBuilder::new(hidden_root.join("config"), hidden_root.join("nails-system"));
        let manager = make_manager(MockFilesystem::new(), hidden_root, builder);

        let err = manager
            .switch_nixos_profile(&None, &Some("fp".to_string()), Verbosity::Quiet)
            .unwrap_err();
        let err_text = err.to_string();
        assert!(err_text.contains("NixOS build+switch failed:"));
        assert!(err_text.contains("boom"));

        restore_path_env(old_path);
        clear_system_profile_env();
    }
}
