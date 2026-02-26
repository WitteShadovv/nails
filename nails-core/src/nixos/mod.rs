//! NixOS Profile Builder
//!
//! Implements the lazy build pattern for NixOS profiles:
//! - Build on first activation (one-time ~30-60s cost)
//! - Cache profile for subsequent activations (<1s)
//! - Graceful fallback to rebuild if cache invalidated
//!
//! # Architecture
//!
//! The `NixOSBuilder` struct manages NixOS profile building with a lazy
//! evaluation pattern optimized for the NAILS use case:
//!
//! 1. **First Activation**: Build NixOS profile from flake configuration
//! 2. **Subsequent Activations**: Reuse cached profile symlink
//! 3. **Cache Invalidation**: Detect missing/corrupt profiles and rebuild
//!
//! # Performance
//!
//! - First activation: 30-60s (one-time build cost)
//! - Cached activations: <1s (symlink read + generation parse)
//! - Graceful degradation: Falls back to build if cache invalid
//!
//! # Example
//!
//! ```no_run
//! use nails_core::nixos::NixOSBuilder;
//! use std::path::PathBuf;
//!
//! let builder = NixOSBuilder::new(
//!     PathBuf::from("/mnt/hidden/nixos"),
//!     PathBuf::from("/nix/var/nix/profiles/nails-system"),
//! );
//!
//! // First call: builds profile (~30-60s)
//! let generation = builder.build_profile()?;
//!
//! // Subsequent calls: returns cached generation (<1s)
//! let cached_generation = builder.build_profile()?;
//! # Ok::<(), nails_core::NailsError>(())
//! ```

use crate::error::{NailsError, Result};
use std::path::PathBuf;

// Module declarations
pub mod command;
pub mod config;
pub mod fingerprint;

// Re-exports for public API
pub use command::{CommandExecutor, RealCommandExecutor};
pub use config::{
    NixOSConfigInfo, contains_nails_import, ensure_nails_import_block, inject_import_block,
    prepare_nixos_config_overlay, stage_hidden_config_symlink, verify_base_config_clean,
};
pub use fingerprint::compute_config_fingerprint;

// Internal imports
use command::CommandExecutor as CommandExecutorTrait;
use command::RealCommandExecutor as RealCommandExecutorImpl;

#[derive(Debug, Clone, PartialEq, Eq)]
enum NixOSBuildMode {
    Flake,
    Legacy { config_path: PathBuf },
}

/// NixOS Profile Builder with Lazy Build Pattern
///
/// Manages NixOS profile building with intelligent caching:
/// - Checks for cached profile before building
/// - Builds profile on first activation
/// - Reuses cached profile on subsequent activations
/// - Gracefully falls back to build if cache invalid
///
/// # Fields
///
/// - `config_path`: Path to NixOS flake configuration directory
/// - `profile_path`: Path to profile symlink for caching
///
/// # References
///
/// - [FR15: Lazy build pattern](docs/prd.md#FR15)
/// - [FR16: Fast subsequent activations](docs/prd.md#FR16)
/// - [FR17: Graceful fallback](docs/prd.md#FR17)
/// - [NFR2: First activation 10-60s](docs/prd.md#NFR2)
pub struct NixOSBuilder {
    /// Path to flake configuration directory (e.g., /mnt/hidden/nixos)
    config_path: PathBuf,
    /// Path to profile symlink for caching (e.g., /nix/var/nix/profiles/nails-system)
    profile_path: PathBuf,
    /// Command executor (for testability)
    executor: Box<dyn CommandExecutorTrait + Send + Sync>,
    /// Build mode (flake or legacy)
    build_mode: NixOSBuildMode,
}

impl NixOSBuilder {
    /// Create a new NixOSBuilder with real command execution
    ///
    /// # Arguments
    ///
    /// - `config_path`: Path to NixOS flake configuration directory
    /// - `profile_path`: Path to profile symlink for caching
    ///
    /// # Example
    ///
    /// ```
    /// use nails_core::nixos::NixOSBuilder;
    /// use std::path::PathBuf;
    ///
    /// let builder = NixOSBuilder::new(
    ///     PathBuf::from("/mnt/hidden/nixos"),
    ///     PathBuf::from("/nix/var/nix/profiles/nails-system"),
    /// );
    /// ```
    pub fn new(config_path: PathBuf, profile_path: PathBuf) -> Self {
        Self {
            config_path,
            profile_path,
            executor: Box::new(RealCommandExecutorImpl),
            build_mode: NixOSBuildMode::Flake,
        }
    }

    /// Create a new legacy (non-flake) NixOSBuilder
    ///
    /// # Arguments
    ///
    /// - `config_path`: Path to /etc/nixos/configuration.nix
    /// - `profile_path`: Path to profile symlink for caching
    pub fn new_legacy(config_path: PathBuf, profile_path: PathBuf) -> Self {
        let config_dir = config_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/etc/nixos"));
        Self {
            config_path: config_dir,
            profile_path,
            executor: Box::new(RealCommandExecutorImpl),
            build_mode: NixOSBuildMode::Legacy { config_path },
        }
    }

    /// Create a new NixOSBuilder with custom executor (for testing)
    #[cfg(test)]
    fn new_with_executor(
        config_path: PathBuf,
        profile_path: PathBuf,
        executor: Box<dyn CommandExecutorTrait + Send + Sync>,
    ) -> Self {
        Self {
            config_path,
            profile_path,
            executor,
            build_mode: NixOSBuildMode::Flake,
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn new_legacy_with_executor(
        config_path: PathBuf,
        profile_path: PathBuf,
        executor: Box<dyn CommandExecutorTrait + Send + Sync>,
    ) -> Self {
        let config_dir = config_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/etc/nixos"));
        Self {
            config_path: config_dir,
            profile_path,
            executor,
            build_mode: NixOSBuildMode::Legacy { config_path },
        }
    }

    pub fn is_flake(&self) -> bool {
        matches!(self.build_mode, NixOSBuildMode::Flake)
    }

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
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use nails_core::nixos::NixOSBuilder;
    /// # use std::path::PathBuf;
    /// // Internal method used by build_profile()
    /// // Not directly accessible - use build_profile() instead
    /// let builder = NixOSBuilder::new(
    ///     PathBuf::from("/mnt/hidden/nixos"),
    ///     PathBuf::from("/nix/var/nix/profiles/nails-system"),
    /// );
    ///
    /// // This method is private, called internally by build_profile()
    /// // build_profile() will check cache automatically
    /// let generation = builder.build_profile()?;
    /// # Ok::<(), nails_core::NailsError>(())
    /// ```
    fn get_cached_generation(&self) -> Result<Option<String>> {
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
    ///
    /// # Arguments
    ///
    /// - `path`: Path to profile symlink or target
    ///
    /// # Returns
    ///
    /// - `Ok(generation_id)` if successfully parsed
    /// - `Err(NixOSError)` if path format is invalid
    fn extract_generation_id(path: &std::path::Path) -> Result<String> {
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
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use nails_core::nixos::NixOSBuilder;
    /// # use std::path::PathBuf;
    /// let builder = NixOSBuilder::new(
    ///     PathBuf::from("/mnt/hidden/nixos"),
    ///     PathBuf::from("/nix/var/nix/profiles/nails-system"),
    /// );
    ///
    /// // First call: builds profile
    /// let generation = builder.build_profile()?;
    /// println!("Built generation: {}", generation);
    ///
    /// // Subsequent calls: use cache
    /// let cached_generation = builder.build_profile()?;
    /// println!("Cached generation: {}", cached_generation);
    /// # Ok::<(), nails_core::NailsError>(())
    /// ```
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
        let (success, stdout, stderr) = self.executor.execute_nixos_rebuild(&[
            "build",
            "--flake",
            &self.config_path.to_string_lossy(),
            "--no-update-lock-file",
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
    ///   (see [`compute_config_fingerprint`]).
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
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use nails_core::nixos::{NixOSBuilder, compute_config_fingerprint};
    /// # use std::path::PathBuf;
    /// let builder = NixOSBuilder::new(
    ///     PathBuf::from("/mnt/hidden/nixos"),
    ///     PathBuf::from("/nix/var/nix/profiles/nails-system"),
    /// );
    ///
    /// let fp = compute_config_fingerprint("hw = {}", "hidden = {}");
    ///
    /// // First run: no stored fingerprint → full build
    /// let (generation_id, new_fp, fast) = builder.build_profile_with_fingerprint(&fp, None)?;
    /// assert!(!fast);
    ///
    /// // Second run: fingerprint matches → fast path
    /// let (gen2, _, fast2) = builder.build_profile_with_fingerprint(&fp, Some(&new_fp))?;
    /// assert!(fast2);
    /// # Ok::<(), nails_core::NailsError>(())
    /// ```
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
    /// `Ok(Some(path))` when the symlink exists *and* its target directory exists (i.e.
    /// the store path is present in the Nix store).  Returns `Ok(None)` when the symlink
    /// is absent, broken, or the target is not present.
    ///
    /// This is the detection primitive for Story 15.5 AC2/AC3: the missing-only build
    /// path only invokes `nixos-rebuild` when this returns `None`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use nails_core::nixos::NixOSBuilder;
    /// # use std::path::PathBuf;
    /// let builder = NixOSBuilder::new(
    ///     PathBuf::from("/mnt/hidden/nixos"),
    ///     PathBuf::from("/nix/var/nix/profiles/nails-system"),
    /// );
    ///
    /// match builder.get_result_store_path()? {
    ///     Some(p) => println!("Store path present: {}", p.display()),
    ///     None    => println!("Store path absent — build required"),
    /// }
    /// # Ok::<(), nails_core::NailsError>(())
    /// ```
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
    /// Implements a two-stage fast path on top of the fingerprint check:
    ///
    /// 1. **Store-path reuse** (AC2): If `{config_path}/result` already points to a
    ///    live Nix store path, extract the generation ID from that path and return it
    ///    immediately without invoking `nixos-rebuild`.
    /// 2. **Missing-only build** (AC1 + AC3): If the store path is absent, run
    ///    `nixos-rebuild build --no-update-lock-file` to build *only* the missing
    ///    derivations, then parse and return the new generation ID.
    ///
    /// The `--no-update-lock-file` flag (AC1) prevents any flake lock file or package
    /// version updates during the build.  This keeps the decoy system packages
    /// completely stable.
    ///
    /// # Returns
    ///
    /// * `Ok((generation_id, store_path_reused))`:
    ///   - `generation_id`     – Generation to switch to (8-char store hash prefix)
    ///   - `store_path_reused` – `true` if build was skipped, `false` if build ran
    /// * `Err(NixOSError)` if the build fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use nails_core::nixos::NixOSBuilder;
    /// # use std::path::PathBuf;
    /// let builder = NixOSBuilder::new(
    ///     PathBuf::from("/mnt/hidden/nixos"),
    ///     PathBuf::from("/nix/var/nix/profiles/nails-system"),
    /// );
    ///
    /// // First run: store path absent → build runs
    /// let (r#gen, reused) = builder.build_profile_missing_only()?;
    /// assert!(!reused);
    ///
    /// // Second run (same config): store path present → reused
    /// let (r#gen2, reused2) = builder.build_profile_missing_only()?;
    /// assert!(reused2);
    /// assert_eq!(r#gen, r#gen2);
    /// # Ok::<(), nails_core::NailsError>(())
    /// ```
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

        let (success, stdout, stderr) = self.executor.execute_nixos_rebuild(&[
            "build",
            "--flake",
            &self.config_path.to_string_lossy(),
            "--no-update-lock-file",
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
    ///
    /// Store paths follow the Nix naming convention:
    /// `/nix/store/<hash32>-<name>` — the first 32 hex characters are the store hash.
    /// We use the first 8 characters as a human-readable pseudo-generation identifier,
    /// consistent with `parse_generation_from_build_output`.
    ///
    /// # Arguments
    ///
    /// * `store_path` – Absolute path such as
    ///   `/nix/store/abc12345defg6789…-nixos-system-hostname-24.11`
    ///
    /// # Returns
    ///
    /// * `Ok(generation_id)` – First 8 characters of the store hash
    /// * `Err(NixOSError)` – Path has no filename or hash is too short
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
    ///
    /// Extracts generation ID from the build command output by parsing the result symlink.
    /// The `nixos-rebuild build` command outputs a line like:
    /// `/nix/store/...-nixos-system-<hostname>-<generation>`
    ///
    /// Or creates a `./result` symlink pointing to the store path.
    ///
    /// # Arguments
    ///
    /// - `output`: stdout from nixos-rebuild command
    ///
    /// # Returns
    ///
    /// - `Ok(generation_id)` if successfully parsed
    /// - `Err(NixOSError)` if generation cannot be determined
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

        // The target path contains the generation in its name
        // Example: /nix/store/abc123-nixos-system-hostname-24.11
        // For now, we'll use a timestamp-based pseudo-generation
        // since nixos-rebuild build doesn't create generation numbers
        // (generations are only created by nixos-rebuild switch)

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
    ///
    /// # Arguments
    ///
    /// * `generation` - The generation ID to switch to
    ///
    /// # Returns
    ///
    /// * `Ok(())` on successful switch
    /// * `Err(NailsError::NixOSError)` if switch fails or profile not found
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use nails_core::nixos::NixOSBuilder;
    /// # use std::path::PathBuf;
    /// let builder = NixOSBuilder::new(
    ///     PathBuf::from("/mnt/hidden/nixos"),
    ///     PathBuf::from("/nix/var/nix/profiles/nails-system"),
    /// );
    ///
    /// // Build profile first
    /// let generation = builder.build_profile()?;
    ///
    /// // Switch to the built profile
    /// builder.switch_profile(&generation, "switch")?;
    /// # Ok::<(), nails_core::NailsError>(())
    /// ```
    pub fn switch_profile(&self, generation: &str, action: &str) -> Result<()> {
        if !self.is_flake() {
            return self.switch_legacy(action);
        }
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
    ///
    /// Validates that the profile path exists in the filesystem.
    ///
    /// # Arguments
    ///
    /// * `generation` - The generation ID to check
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if profile exists
    /// * `Ok(false)` if profile does not exist
    /// * `Err(...)` on filesystem errors
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

    /// Get current active generation
    ///
    /// Queries the current active NixOS generation from the system profile.
    /// Used for rollback tracking.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(generation_id))` if current generation can be determined
    /// * `Ok(None)` if no current generation (fresh system)
    /// * `Err(...)` on query errors
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
    ///
    /// Direct switch without validation, used internally for rollback operations.
    ///
    /// # Arguments
    ///
    /// * `generation` - The generation ID to switch to
    ///
    /// # Returns
    ///
    /// * `Ok(())` on successful switch
    /// * `Err(NailsError::NixOSError)` if switch fails
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

    fn switch_legacy(&self, action: &str) -> Result<()> {
        let config_path = match &self.build_mode {
            NixOSBuildMode::Legacy { config_path } => config_path,
            NixOSBuildMode::Flake => {
                return Err(NailsError::NixOSError(
                    "switch_legacy called for flake builder".into(),
                ));
            }
        };

        let arg = format!("nixos-config={}", config_path.display());
        let (success, _stdout, stderr) =
            self.executor.execute_nixos_rebuild(&[action, "-I", &arg])?;

        if !success {
            return Err(NailsError::NixOSError(format!(
                "Legacy nixos-rebuild {} failed: {}",
                action, stderr
            )));
        }

        Ok(())
    }
}

fn system_profile_path() -> PathBuf {
    std::env::var_os("NAILS_SYSTEM_PROFILE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/nix/var/nix/profiles/system"))
}

fn system_profiles_dir() -> PathBuf {
    system_profile_path()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/nix/var/nix/profiles"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock command executor for testing
    struct MockCommandExecutor {
        /// Whether command should succeed
        should_succeed: bool,
        /// Stdout to return
        stdout: String,
        /// Stderr to return
        stderr: String,
    }

    impl MockCommandExecutor {
        fn success() -> Self {
            Self {
                should_succeed: true,
                stdout: String::from("nixos-rebuild output here"),
                stderr: String::new(),
            }
        }

        #[allow(dead_code)]
        fn failure(stderr: String) -> Self {
            Self {
                should_succeed: false,
                stdout: String::new(),
                stderr,
            }
        }
    }

    impl CommandExecutorTrait for MockCommandExecutor {
        fn execute_nixos_rebuild(&self, _args: &[&str]) -> Result<(bool, String, String)> {
            Ok((
                self.should_succeed,
                self.stdout.clone(),
                self.stderr.clone(),
            ))
        }

        fn execute_switch_to_configuration(
            &self,
            _script_path: &std::path::Path,
            _args: &[&str],
        ) -> Result<(bool, String, String)> {
            // For build tests, we don't actually call switch-to-configuration
            // Return success by default
            Ok((true, String::new(), String::new()))
        }
    }

    #[test]
    fn test_nixos_builder_construction() {
        let config_path = PathBuf::from("/mnt/hidden/nixos");
        let profile_path = PathBuf::from("/nix/var/nix/profiles/nails-system");

        let builder = NixOSBuilder::new(config_path.clone(), profile_path.clone());

        // Verify struct is constructed with correct values
        assert_eq!(builder.config_path, config_path);
        assert_eq!(builder.profile_path, profile_path);
    }

    #[test]
    fn test_extract_generation_id_valid_paths() {
        // Test standard system profile format
        let path = PathBuf::from("/nix/var/nix/profiles/system-123-link");
        let generation = NixOSBuilder::extract_generation_id(&path).unwrap();
        assert_eq!(generation, "123");

        // Test custom profile format
        let path = PathBuf::from("/nix/var/nix/profiles/nails-system-456-link");
        let generation = NixOSBuilder::extract_generation_id(&path).unwrap();
        assert_eq!(generation, "456");

        // Test profile with multiple hyphens in name
        let path = PathBuf::from("/nix/var/nix/profiles/my-custom-profile-789-link");
        let generation = NixOSBuilder::extract_generation_id(&path).unwrap();
        assert_eq!(generation, "789");
    }

    #[test]
    fn test_extract_generation_id_invalid_paths() {
        // Test path without generation number
        let path = PathBuf::from("/nix/var/nix/profiles/invalid");
        assert!(NixOSBuilder::extract_generation_id(&path).is_err());

        // Test path with non-numeric generation
        let path = PathBuf::from("/nix/var/nix/profiles/system-abc-link");
        assert!(NixOSBuilder::extract_generation_id(&path).is_err());

        // Test empty path
        let path = PathBuf::from("");
        assert!(NixOSBuilder::extract_generation_id(&path).is_err());
    }

    #[test]
    fn test_get_cached_generation_no_profile() {
        // Create builder with non-existent profile path
        let config_path = PathBuf::from("/mnt/hidden/nixos");
        let profile_path = PathBuf::from("/tmp/nonexistent-profile-12345");

        let builder = NixOSBuilder::new(config_path, profile_path);

        // Should return Ok(None) when profile doesn't exist
        let result = builder.get_cached_generation().unwrap();
        assert_eq!(result, None);
    }

    #[test]
    #[cfg(unix)] // Symlink operations are Unix-specific
    fn test_get_cached_generation_with_profile() {
        use tempfile::TempDir;

        // Create temporary directory for test
        let temp_dir = TempDir::new().unwrap();
        let profile_path = temp_dir.path().join("test-profile");

        // Create a symlink to simulate NixOS profile
        // Symlink target format: /nix/store/hash-nixos-system-123-link
        let target = temp_dir.path().join("system-123-link");
        std::fs::write(&target, "dummy").unwrap();

        std::os::unix::fs::symlink(&target, &profile_path).unwrap();

        let builder = NixOSBuilder::new(PathBuf::from("/mnt/hidden/nixos"), profile_path);

        // Should extract generation ID from symlink target
        let result = builder.get_cached_generation().unwrap();
        assert_eq!(result, Some("123".to_string()));
    }

    #[test]
    #[cfg(unix)] // Symlink operations are Unix-specific
    fn test_build_profile_uses_cached_generation() {
        use tempfile::TempDir;

        // Create temporary directory with cached profile
        let temp_dir = TempDir::new().unwrap();
        let profile_path = temp_dir.path().join("test-profile");
        let target = temp_dir.path().join("system-456-link");
        std::fs::write(&target, "dummy").unwrap();

        std::os::unix::fs::symlink(&target, &profile_path).unwrap();

        let builder = NixOSBuilder::new_with_executor(
            PathBuf::from("/mnt/hidden/nixos"),
            profile_path,
            Box::new(MockCommandExecutor::success()),
        );

        // Should use cached generation without building
        let generation = builder.build_profile().unwrap();
        assert_eq!(generation, "456");
    }
}
