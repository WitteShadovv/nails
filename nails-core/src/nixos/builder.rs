//! NixOS profile builder implementation
//!
//! Contains the core build/switch methods for `NixOSBuilder`.

use super::{NixOSBuildMode, NixOSBuilder};
use crate::error::{NailsError, Result};
use crate::obfuscate;
use std::path::PathBuf;

fn system_profile_path() -> PathBuf {
    std::env::var_os(obfuscate::env_system_profile_path())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/nix/var/nix/profiles/system"))
}

fn system_profiles_dir() -> PathBuf {
    system_profile_path()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/nix/var/nix/profiles"))
}

impl NixOSBuilder {
    /// Get cached generation ID if profile exists
    ///
    /// Checks if profile_path symlink exists and reads the generation ID
    /// from the symlink target path.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(generation_id))` if cached profile exists and is valid
    /// - `Ok(None)` if no cached profile exists (needs build)
    /// - `Err(...)` if profile exists but cannot be read or parsed
    pub(super) fn get_cached_generation(&self) -> Result<Option<String>> {
        // Check if profile symlink exists
        if !self.profile_path.exists() {
            return Ok(None);
        }

        // Read symlink target
        let target = std::fs::read_link(&self.profile_path)?;

        // Extract generation ID from symlink target
        // Profile symlinks look like: /nix/var/nix/profiles/system-123-link
        let generation_id = Self::extract_generation_id(&target)?;

        tracing::debug!(
            "Found cached profile: {} -> generation {}",
            self.profile_path.display(),
            generation_id
        );

        Ok(Some(generation_id))
    }

    /// Extract generation ID from profile path
    ///
    /// Parses generation ID from NixOS profile paths like:
    /// - `/nix/var/nix/profiles/system-123-link` → "123"
    /// - `/nix/var/nix/profiles/nails-system-456-link` → "456"
    pub(super) fn extract_generation_id(path: &std::path::Path) -> Result<String> {
        let filename = path
            .file_name()
            .ok_or_else(|| NailsError::NixOSError("Invalid profile path: no filename".into()))?
            .to_string_lossy();

        // Profile symlinks typically end with "-{generation}-link"
        // Examples: "system-123-link", "nails-system-456-link"
        let parts: Vec<&str> = filename.split('-').collect();

        // Need at least 3 parts: name, generation, "link"
        if parts.len() < 3 {
            return Err(NailsError::NixOSError(format!(
                "Invalid profile path format: {}",
                filename
            )));
        }

        // Second-to-last part should be the generation number
        let generation_str = parts[parts.len() - 2];

        // Verify it's a valid number
        generation_str
            .parse::<u64>()
            .map_err(|_| {
                NailsError::NixOSError(format!(
                    "Could not extract generation ID from path: {}",
                    filename
                ))
            })
            .map(|generation_num| generation_num.to_string())
    }

    /// Build NixOS profile with lazy build pattern
    ///
    /// Implements the lazy build pattern:
    /// 1. Check for cached profile
    /// 2. If cached, return generation ID (<1s)
    /// 3. If not cached, build profile (~30-60s)
    /// 4. Return generation ID
    ///
    /// # Returns
    ///
    /// - `Ok(generation_id)` on success (cached or built)
    /// - `Err(NixOSError)` if build fails
    ///
    /// # Performance
    ///
    /// - Cached: <1s (symlink read + parse)
    /// - Build: 30-60s (one-time cost)
    pub fn build_profile(&self) -> Result<String> {
        // Check for cached profile (FR16: Fast subsequent activations)
        if let Some(generation) = self.get_cached_generation()? {
            tracing::info!("Using cached NixOS profile: generation {}", generation);
            return Ok(generation);
        }

        // No cache found, need to build (FR15: Lazy build pattern)
        // FR17: Graceful fallback to build if cache invalid
        // Distinguish between expected first activation vs unexpected cache loss
        if self.profile_path.exists() {
            tracing::warn!(
                "Cached profile exists but is invalid/corrupt at '{}', rebuilding...",
                self.profile_path.display()
            );
        } else {
            tracing::info!("No cached profile found (first activation expected), building...");
        }
        tracing::info!("Building NixOS profile (first activation, may take 30-60s)...");
        let start = std::time::Instant::now();

        // Execute nixos-rebuild build command
        // AC1 (Story 15.5): --no-update-lock-file prevents any package version updates.
        let flake_arg = self.effective_flake_arg();
        let (success, stdout, stderr) = self.executor.execute_nixos_rebuild(&[
            "build",
            "--flake",
            &flake_arg,
            "--no-update-lock-file",
            "--impure",
        ])?;

        // Check if build succeeded
        if !success {
            return Err(NailsError::NixOSError(format!("Build failed: {}", stderr)));
        }

        // Parse generation ID from build output
        let generation_id = self.parse_generation_from_build_output(&stdout)?;

        let duration = start.elapsed();
        tracing::info!(
            "NixOS profile built successfully: generation {} ({:.1}s)",
            generation_id,
            duration.as_secs_f64()
        );

        Ok(generation_id)
    }

    /// Build NixOS profile with config fingerprint fast-path (Story 15.4)
    ///
    /// Implements the fingerprint-based fast path:
    ///
    /// 1. If `stored_fingerprint` matches `current_fingerprint` **and** the cached
    ///    profile exists → skip build, return cached generation (fast path).
    /// 2. Otherwise → fall back to [`build_profile`], store new fingerprint on success.
    ///
    /// # Arguments
    ///
    /// * `current_fingerprint` - Freshly computed fingerprint of config inputs
    /// * `stored_fingerprint` - Fingerprint recorded after the previous successful
    ///   activation (may be `None` on first run).
    ///
    /// # Returns
    ///
    /// * `Ok((generation_id, new_fingerprint, fast_path_used))`:
    ///   - `generation_id`    - Generation to switch to
    ///   - `new_fingerprint`  - Fingerprint to persist (always equals `current_fingerprint`)
    ///   - `fast_path_used`   - `true` if build was skipped, `false` if build ran
    /// * `Err(NixOSError)` if build fails
    pub fn build_profile_with_fingerprint(
        &self,
        current_fingerprint: &str,
        stored_fingerprint: Option<&str>,
    ) -> Result<(String, String, bool)> {
        // AC2: Fast path – fingerprint matches and cached profile exists
        if let Some(stored) = stored_fingerprint {
            if stored == current_fingerprint {
                if let Some(generation) = self.get_cached_generation()? {
                    tracing::info!(
                        fingerprint = current_fingerprint,
                        generation = %generation,
                        "⚡ Fast path: config fingerprint matches and profile exists — skipping build (AC2)"
                    );
                    return Ok((generation, current_fingerprint.to_owned(), true));
                }
                // Fingerprint matched but profile is missing → fall through to build
                tracing::warn!(
                    fingerprint = current_fingerprint,
                    "Fingerprint matches but cached profile is missing — rebuilding"
                );
            } else {
                tracing::info!(
                    stored_fingerprint = stored,
                    current_fingerprint = current_fingerprint,
                    "Config fingerprint mismatch — rebuilding NixOS profile"
                );
            }
        } else {
            tracing::info!("No stored fingerprint — building NixOS profile for the first time");
        }

        // AC3: Fall back to missing-only build (Story 15.5).
        // build_profile_missing_only() checks whether the store path already exists
        // before invoking nixos-rebuild, and always passes --no-update-lock-file (AC1).
        let (generation, _store_path_reused) = self.build_profile_missing_only()?;
        Ok((generation, current_fingerprint.to_owned(), false))
    }

    /// Get the current result store path (if result symlink exists and target is valid)
    ///
    /// Reads `{config_path}/result` symlink and resolves the target path.  Returns
    /// `Ok(Some(path))` when the symlink exists *and* its target directory exists.
    /// Returns `Ok(None)` when the symlink is absent, broken, or the target is not present.
    pub fn get_result_store_path(&self) -> Result<Option<PathBuf>> {
        let result_symlink = self.config_path.join("result");

        // Symlink must exist
        if !result_symlink.exists() && std::fs::symlink_metadata(&result_symlink).is_err() {
            tracing::debug!(
                symlink = %result_symlink.display(),
                "Result symlink does not exist — store path absent"
            );
            return Ok(None);
        }

        // Read the symlink target
        let target = match std::fs::read_link(&result_symlink) {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!(
                    symlink = %result_symlink.display(),
                    error = %e,
                    "Could not read result symlink — treating store path as absent"
                );
                return Ok(None);
            }
        };

        // The store path must actually exist (i.e. not GC-collected)
        if target.exists() {
            tracing::debug!(
                store_path = %target.display(),
                "Result store path is present"
            );
            Ok(Some(target))
        } else {
            tracing::debug!(
                store_path = %target.display(),
                "Result store path is absent (GC-collected or never built)"
            );
            Ok(None)
        }
    }

    /// Build NixOS profile using the missing-only path (Story 15.5)
    ///
    /// 1. **Store-path reuse** (AC2): If `{config_path}/result` already points to a
    ///    live Nix store path, extract the generation ID and return immediately.
    /// 2. **Missing-only build** (AC1 + AC3): If the store path is absent, run
    ///    `nixos-rebuild build --no-update-lock-file`.
    ///
    /// # Returns
    ///
    /// * `Ok((generation_id, store_path_reused))`:
    ///   - `generation_id`     – Generation to switch to (8-char store hash prefix)
    ///   - `store_path_reused` – `true` if build was skipped, `false` if build ran
    /// * `Err(NixOSError)` if the build fails
    pub fn build_profile_missing_only(&self) -> Result<(String, bool)> {
        if !self.is_flake() {
            return Err(NailsError::NixOSError(
                "Legacy NixOS builds are not supported in the missing-only path".into(),
            ));
        }
        // AC2: Check whether the result store path is already present.
        if let Some(store_path) = self.get_result_store_path()? {
            let generation_id = self.extract_generation_from_store_path(&store_path)?;
            tracing::info!(
                store_path = %store_path.display(),
                generation = %generation_id,
                "Missing-only path: store path already present — skipping build (AC2)"
            );
            return Ok((generation_id, true));
        }

        // AC1 + AC3: Store path missing — build only missing derivations.
        tracing::info!(
            "Missing-only path: store path absent — building with --no-update-lock-file (AC1, AC3)"
        );
        let start = std::time::Instant::now();

        let flake_arg = self.effective_flake_arg();
        let (success, stdout, stderr) = self.executor.execute_nixos_rebuild(&[
            "build",
            "--flake",
            &flake_arg,
            "--no-update-lock-file",
            "--impure",
        ])?;

        if !success {
            return Err(NailsError::NixOSError(format!("Build failed: {}", stderr)));
        }

        // AC3: Parse generation from the result symlink created by nixos-rebuild build.
        let generation_id = self.parse_generation_from_build_output(&stdout)?;

        let duration = start.elapsed();
        tracing::info!(
            generation = %generation_id,
            duration_s = duration.as_secs_f64(),
            "Missing-only build complete: generation {} ({:.1}s)",
            generation_id,
            duration.as_secs_f64()
        );

        Ok((generation_id, false))
    }

    /// Extract a generation ID (8-char store hash prefix) from an absolute store path.
    fn extract_generation_from_store_path(&self, store_path: &std::path::Path) -> Result<String> {
        let filename = store_path
            .file_name()
            .ok_or_else(|| NailsError::NixOSError("Invalid store path: no filename".into()))?
            .to_string_lossy();

        if let Some(hash_part) = filename.split('-').next()
            && hash_part.len() >= 8
        {
            return Ok(hash_part[0..8].to_string());
        }

        Err(NailsError::NixOSError(format!(
            "Could not extract generation ID from store path: {}",
            filename
        )))
    }

    /// Parse generation ID from nixos-rebuild build output
    fn parse_generation_from_build_output(&self, _output: &str) -> Result<String> {
        // nixos-rebuild build creates a ./result symlink in the flake directory
        // pointing to /nix/store/hash-nixos-system-hostname-generation
        // We'll read this symlink to get the store path, then extract generation

        let result_symlink = self.config_path.join("result");

        if !result_symlink.exists() {
            return Err(NailsError::NixOSError(
                "Build succeeded but result symlink not found. Unable to determine generation ID."
                    .into(),
            ));
        }

        // Read the symlink target
        let target = std::fs::read_link(&result_symlink)?;

        tracing::debug!("Build result symlink points to: {}", target.display());

        // Extract a unique identifier from the store path hash
        let filename = target
            .file_name()
            .ok_or_else(|| NailsError::NixOSError("Invalid result path: no filename".into()))?
            .to_string_lossy();

        // Extract hash prefix as pseudo-generation (first 8 chars of store hash)
        // Format: hash-nixos-system-...
        #[allow(clippy::collapsible_if)] // More readable as nested
        if let Some(hash_part) = filename.split('-').next() {
            if hash_part.len() >= 8 {
                let pseudo_generation = &hash_part[0..8];
                tracing::info!(
                    "Using store hash as generation identifier: {}",
                    pseudo_generation
                );
                return Ok(pseudo_generation.to_string());
            }
        }

        Err(NailsError::NixOSError(
            "Could not extract generation ID from build result path".into(),
        ))
    }

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
        match Self::extract_generation_id(&target) {
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
