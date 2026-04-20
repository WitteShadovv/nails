//! NixOS profile switch/activation methods for `NixOSBuilder`.

use super::{system_profile_path, system_profiles_dir};
use crate::error::{NailsError, Result};
use crate::nixos::{NixOSBuildMode, NixOSBuilder};
use std::path::PathBuf;

impl NixOSBuilder {
    /// Switch to the specified NixOS profile generation
    ///
    /// Implements the profile switching functionality with:
    /// - Profile existence validation before switch
    /// - Automatic rollback on failure
    /// - Detailed error messages with stderr capture
    pub fn switch_profile(&self, generation: &str, action: &str) -> Result<()> {
        // Validate profile exists before attempting switch
        if !self.profile_exists(generation)? {
            return Err(NailsError::NixOSError(format!(
                "Profile not found: {}. Run 'nails activate' to rebuild.",
                generation
            )));
        }

        // Track current generation for rollback
        let previous_gen = self.get_current_generation()?;

        // Execute switch command using the profile's switch-to-configuration script
        tracing::info!(
            "Switching to NixOS profile: generation {} (action: {})",
            generation,
            action
        );

        // Construct path to the profile's activation script
        // Profile path format: /nix/var/nix/profiles/nails-system-{generation}-link/bin/switch-to-configuration
        let profile_generation_path = PathBuf::from(format!(
            "{}-{}-link",
            self.profile_path.to_string_lossy(),
            generation
        ));

        let switch_script = profile_generation_path.join("bin/switch-to-configuration");

        let (success, _stdout, stderr) = self
            .executor
            .execute_switch_to_configuration(&switch_script, &[action])?;

        if !success {
            // Attempt rollback to previous generation
            if let Some(prev) = previous_gen {
                tracing::warn!("Switch failed, attempting rollback to generation {}", prev);
                if let Err(e) = self.switch_to_generation(&prev, "switch") {
                    tracing::error!("Rollback failed: {}", e);
                }
            }

            return Err(NailsError::NixOSError(format!("Switch failed: {}", stderr)));
        }

        tracing::info!("Switched to NixOS profile: generation {}", generation);
        Ok(())
    }

    /// Switch to a specific system generation (non-flake fast path).
    pub fn switch_system_generation(&self, generation: &str, action: &str) -> Result<()> {
        if !self.system_generation_exists(generation)? {
            return Err(NailsError::NixOSError(format!(
                "System generation not found: {}",
                generation
            )));
        }
        self.switch_to_generation(generation, action)
    }

    /// Check if a system generation exists under /nix/var/nix/profiles.
    pub fn system_generation_exists(&self, generation: &str) -> Result<bool> {
        let path = system_profiles_dir().join(format!("system-{}-link", generation));
        Ok(path.exists())
    }

    /// Get the current active system generation (if any).
    pub fn current_system_generation(&self) -> Result<Option<String>> {
        self.get_current_generation()
    }

    /// Check if profile exists for given generation
    fn profile_exists(&self, generation: &str) -> Result<bool> {
        // Check if the specific generation profile exists
        // Profile path format: /nix/var/nix/profiles/nails-system-{generation}-link
        let profile_generation_path = PathBuf::from(format!(
            "{}-{}-link",
            self.profile_path.to_string_lossy(),
            generation
        ));

        Ok(profile_generation_path.exists())
    }

    /// Get current active generation for rollback tracking
    fn get_current_generation(&self) -> Result<Option<String>> {
        // Read the current system generation from /nix/var/nix/profiles/system
        // This is the currently active NixOS system, not our custom profile
        let system_profile = system_profile_path();

        if !system_profile.exists() {
            return Ok(None);
        }

        // Read symlink target to get current generation
        let target = std::fs::read_link(&system_profile)?;

        // Extract generation ID from system profile
        match NixOSBuilder::extract_generation_id(&target) {
            Ok(generation_id) => Ok(Some(generation_id)),
            Err(_) => Ok(None), // If we can't parse, treat as no generation
        }
    }

    /// Switch to specific generation (internal use for rollback)
    fn switch_to_generation(&self, generation: &str, action: &str) -> Result<()> {
        // Construct path to the profile's activation script for rollback
        // This uses the system profile path, not our custom nails profile
        let system_profile_path = system_profiles_dir().join(format!("system-{}-link", generation));

        let switch_script = system_profile_path.join("bin/switch-to-configuration");

        let (success, _stdout, _stderr) = self
            .executor
            .execute_switch_to_configuration(&switch_script, &[action])?;

        if !success {
            return Err(NailsError::NixOSError(format!("NixOS {} failed", action)));
        }

        Ok(())
    }

    /// Switch back to the current system profile (decoy) generation.
    ///
    /// Uses the system profile's switch-to-configuration script directly.
    pub fn switch_to_system_profile(&self) -> Result<()> {
        let system_profile = system_profile_path();

        if !system_profile.exists() {
            return Ok(());
        }

        let switch_script = system_profile.join("bin/switch-to-configuration");

        let (success, _stdout, stderr) = self
            .executor
            .execute_switch_to_configuration(&switch_script, &["switch"])?;

        if !success {
            return Err(NailsError::NixOSError(format!(
                "System profile switch failed: {}",
                stderr
            )));
        }

        Ok(())
    }

    /// Combined build + switch via `nixos-rebuild test`.
    ///
    /// Works for both flake and legacy configs — the only difference is the
    /// arguments passed to `nixos-rebuild`:
    ///
    /// - **Flake**:  `nixos-rebuild test --flake <ref> --no-update-lock-file`
    /// - **Legacy**: `nixos-rebuild test -I nixos-config=<path>`
    pub fn build_and_switch(&self) -> Result<()> {
        let (success, _stdout, stderr) = match &self.build_mode {
            NixOSBuildMode::Flake => {
                let flake_arg = self.effective_flake_arg();
                self.executor.execute_nixos_rebuild(&[
                    "test",
                    "--flake",
                    &flake_arg,
                    "--no-update-lock-file",
                    "--impure",
                ])?
            }
            NixOSBuildMode::Legacy { config_path } => {
                let arg = format!("nixos-config={}", config_path.display());
                self.executor.execute_nixos_rebuild(&["test", "-I", &arg])?
            }
        };

        if !success {
            return Err(NailsError::NixOSError(format!(
                "nixos-rebuild test failed: {}",
                stderr
            )));
        }

        Ok(())
    }
}
