//! Preflight Check Runner for NailsManager
//!
//! Extracted from state_management.rs to keep modules under 500 lines.
//! Contains the `run_preflight_checks` method that registers and runs
//! all pre-flight validation checks before activation.

use super::NailsManager;
use crate::{Filesystem, NailsError, Result, StateFile, build_overlay_targets};

impl<F: Filesystem> NailsManager<F> {
    /// Run read-only NixOS preflight checks that are safe before detach/session kill.
    pub fn run_read_only_nixos_preflight(&self, overlay_only: bool) -> Result<()> {
        if overlay_only {
            return Ok(());
        }

        if let Some(builder) = self.nixos_builder.as_ref()
            && builder.is_flake()
        {
            let summary = builder
                .preflight_flake_reference_fast()
                .map_err(|err| match err {
                    NailsError::NixOSPreflightError { message, .. } => {
                        NailsError::PreFlightCheckFailed(vec![(
                            "nixos-build-target".to_string(),
                            message,
                        )])
                    }
                    other => other,
                })?;
            tracing::info!(
                metadata_checked = summary.metadata_checked,
                attr_checked = summary.attr_checked,
                "Read-only flake preflight completed"
            );
        }

        Ok(())
    }

    /// Run all pre-flight checks before activation
    ///
    /// Creates a PreFlightRegistry, registers all validation checks, and executes them.
    /// Returns comprehensive error information if any checks fail.
    ///
    /// # Pre-flight Checks Executed (Stories 3.1-3.7, 4.12, 15.2)
    ///
    /// 1. **HiddenVolumeCheck** - Validates hidden volume is mounted
    /// 2. **StorageReadinessCheck** - Validates directory structure + overlay accessibility
    /// 3. **NixOSConfigCheck** - Validates NixOS config overlay structure
    /// 4. **SwapCheck** - Validates swap is disabled
    /// 5. **SpaceCheck** - Validates sufficient disk space
    /// 6. **StateCheck** - Validates current state allows activation
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All checks passed (or only warnings)
    /// * `Err(NailsError::PreFlightCheckFailed)` - One or more checks failed
    ///
    /// # Example
    ///
    /// This is a private method called automatically during activation.
    /// To run preflight checks, use `activate()`:
    ///
    /// ```rust,no_run
    /// use nails_core::{NailsManager, MockFilesystem, Config};
    /// use std::path::PathBuf;
    /// use std::sync::{Arc, Mutex};
    ///
    /// let fs = MockFilesystem::new();
    /// let config = Config::default();
    /// let state_path = PathBuf::from("/mnt/hidden-volume/state.json");
    /// let manager = Arc::new(Mutex::new(NailsManager::new(fs, config, state_path)));
    ///
    /// // Activate with preflight checks (no_preflight = false)
    /// let result = NailsManager::activate(manager, false);
    /// ```
    pub fn run_preflight_checks(&self, overlay_only: bool) -> Result<()> {
        use crate::preflight::{
            HiddenVolumeCheck, NixOSBuildTargetCheck, NixOSConfigCheck, OverlayCompatibilityCheck,
            PreFlightRegistry, SpaceCheck, StateCheck, StorageReadinessCheck, SwapCheck,
            SymlinkSupportCheck,
        };

        let mut registry = PreFlightRegistry::new();

        // Register all checks (Stories 3.1-3.7, merged in Story 14.5)
        registry.add_check(Box::new(HiddenVolumeCheck::new(
            self.config.hidden_volume_root.clone(),
        )));

        registry.add_check(Box::new(SymlinkSupportCheck::new(
            self.config.hidden_volume_root.clone(),
        )));

        // Compute overlay directories based on mode (Auto or Explicit)
        // For Auto mode: use build_overlay_targets() to enumerate dynamically
        // For Explicit mode: use config.overlays directly
        let overlay_dirs: Vec<crate::preflight::OverlayDirs> = match self.config.overlay_mode {
            crate::config::OverlayMode::Auto => {
                // Use build_overlay_targets to get dynamic list
                let targets = build_overlay_targets(&self.filesystem, &self.config)?;
                targets
                    .iter()
                    .map(|target| {
                        let dir_name = target
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string();
                        let upper = self.config.hidden_volume_root.join(&dir_name);
                        let work = self.config.hidden_volume_root.join(".work").join(&dir_name);

                        crate::preflight::OverlayDirs::new(dir_name, target.clone(), upper, work)
                    })
                    .collect()
            }
            crate::config::OverlayMode::Explicit => {
                // Use explicit overlays from config
                self.config
                    .overlays
                    .iter()
                    .map(|o| {
                        crate::preflight::OverlayDirs::new(
                            o.name.clone(),
                            o.lower.clone(),
                            o.upper.clone(),
                            o.work.clone(),
                        )
                    })
                    .collect()
            }
        };

        registry.add_check(Box::new(StorageReadinessCheck::new(
            self.config.hidden_volume_root.clone(),
            overlay_dirs,
        )));

        // Compute overlay targets for compatibility check
        let persistent_overlay_target_paths: Vec<std::path::PathBuf> =
            match self.config.overlay_mode {
                crate::config::OverlayMode::Auto => {
                    build_overlay_targets(&self.filesystem, &self.config)?
                }
                crate::config::OverlayMode::Explicit => self
                    .config
                    .overlays
                    .iter()
                    .map(|o| o.lower.clone())
                    .collect(),
            };

        let ephemeral_overlay_target_paths: Vec<std::path::PathBuf> =
            if self.config.extended_overlays.enabled {
                self.config
                    .extended_overlays
                    .directories
                    .iter()
                    .map(|dir| dir.path.clone())
                    .collect()
            } else {
                Vec::new()
            };

        registry.add_check(Box::new(OverlayCompatibilityCheck::new(
            persistent_overlay_target_paths,
            ephemeral_overlay_target_paths,
            self.config.hidden_volume_root.clone(),
        )));

        let flake_target_already_validated = self
            .nixos_builder
            .as_ref()
            .is_some_and(|builder| builder.is_flake());

        if !overlay_only {
            registry.add_check(Box::new(NixOSConfigCheck::new(
                self.config.hidden_volume_root.clone(),
            )));

            if !flake_target_already_validated {
                let selected_flake_dir = self
                    .nixos_builder
                    .as_ref()
                    .and_then(|builder| builder.flake_dir().map(|path| path.to_path_buf()));

                registry.add_check(Box::new(NixOSBuildTargetCheck::with_selected_flake_dir(
                    self.config.nixos_flake.clone(),
                    selected_flake_dir,
                    self.config.hidden_volume_root.clone(),
                )));
            }
        }

        registry.add_check(Box::new(SwapCheck));

        registry.add_check(Box::new(SpaceCheck::new(
            self.config.hidden_volume_root.clone(),
            self.config.minimum_space_mb,
        )));

        registry.add_check(Box::new(StateCheck::new(self.current_state()?)));

        // Run all checks (always get full results for display)
        let (results, all_passed) = registry.run_all_detailed(&self.filesystem);

        // Display each check result and collect failures
        let mut failed_checks: Vec<(String, String)> = Vec::new();

        for (name, result) in &results {
            // Print each check result to stderr so the user sees progress
            crate::output::check_result(name, result);

            match result {
                crate::preflight::CheckResult::Pass(msg) => {
                    tracing::info!(check = %name, result = "pass", msg = %msg, "Preflight check passed");
                }
                crate::preflight::CheckResult::Warn(msg) => {
                    tracing::warn!(check = %name, result = "warn", msg = %msg, "Preflight check warning");
                }
                crate::preflight::CheckResult::Fail(msg) => {
                    tracing::error!(check = %name, result = "fail", msg = %msg, "Preflight check failed");
                    failed_checks.push((name.clone(), msg.clone()));
                }
            }
        }

        if all_passed {
            self.ensure_state_file_exists()?;
            tracing::info!("All pre-flight checks passed");
            Ok(())
        } else {
            Err(crate::NailsError::PreFlightCheckFailed(failed_checks))
        }
    }

    fn ensure_state_file_exists(&self) -> Result<()> {
        if self.state_file_path.exists() {
            if !self.state_file_path.is_file() {
                return Err(NailsError::InvalidState(format!(
                    "State path must be a file, not a directory: {}",
                    self.state_file_path.display()
                )));
            }

            return Ok(());
        }

        StateFile::default()
            .save_with_custom_root(&self.state_file_path, &self.config.hidden_volume_root)
    }
}
