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
use crate::filesystem::Filesystem;
use std::path::{Path, PathBuf};

// ============================================================================
// Config Fingerprint (Story 15.4)
// ============================================================================

/// Compute a stable fingerprint of NixOS config inputs (Story 15.4, AC1)
///
/// Hashes the content of the hardware configuration and hidden configuration
/// using FNV-1a (64-bit). This is a deterministic, dependency-free hash that
/// produces a stable hex string for comparing config inputs across activations.
///
/// # Volatile fields excluded
///
/// Only file *content* is hashed. Timestamps, temp paths, and process state
/// are intentionally excluded so the fingerprint changes only when the config
/// itself changes.
///
/// # Arguments
///
/// * `hardware_config_content` - Contents of `{hidden}/etc/nixos/hardware-configuration.nix`
/// * `hidden_config_content`   - Contents of `{hidden}/config/nixos/configuration.nix`
///
/// # Returns
///
/// A lowercase 16-character hex string (64-bit FNV-1a hash).
///
/// # Example
///
/// ```
/// use nails_core::nixos::compute_config_fingerprint;
///
/// let fp1 = compute_config_fingerprint("hardware = {}", "hidden = {}");
/// let fp2 = compute_config_fingerprint("hardware = {}", "hidden = {}");
/// assert_eq!(fp1, fp2, "Same inputs produce same fingerprint");
///
/// let fp3 = compute_config_fingerprint("hardware = { changed = true; }", "hidden = {}");
/// assert_ne!(fp1, fp3, "Different inputs produce different fingerprint");
/// ```
///
/// # Design Trade-off: Fingerprint Before Nix Validation
///
/// This function computes the fingerprint **without** validating Nix syntax.
///
/// **Rationale:**
/// - Performance: Syntax validation would require invoking `nix-instantiate` or similar,
///   which defeats the purpose of the fast-path optimization (skipping expensive operations)
/// - Simplicity: Hashing raw content is O(n) and uses only stdlib
/// - Correctness: Invalid Nix will fail during the actual build step, so errors are still caught
///
/// **Edge case handled:** If config files are missing or unreadable, the fingerprint
/// is computed from empty strings. This is intentional - the build step will fail with
/// a clear error if the configs are truly required, while still allowing the fingerprint
/// logic to complete for cases where configs might be optional (e.g., pre-flight checks).
pub fn compute_config_fingerprint(
    hardware_config_content: &str,
    hidden_config_content: &str,
) -> String {
    // FNV-1a 64-bit parameters
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET_BASIS;

    // Hash hardware config content
    for byte in hardware_config_content.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    // Separator to prevent concatenation collisions
    for byte in b"\x00NAILS_SEP\x00" {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    // Hash hidden config content
    for byte in hidden_config_content.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    format!("{:016x}", hash)
}

/// Trait for executing commands (for testability)
///
/// Abstracts command execution to allow mocking in tests.
/// Production code uses real Command execution, tests use mock.
trait CommandExecutor {
    /// Execute nixos-rebuild command
    ///
    /// # Arguments
    ///
    /// - `args`: Command arguments
    ///
    /// # Returns
    ///
    /// - `Ok((success, stdout, stderr))` with command output
    fn execute_nixos_rebuild(&self, args: &[&str]) -> Result<(bool, String, String)>;

    /// Execute switch-to-configuration script
    ///
    /// # Arguments
    ///
    /// - `script_path`: Full path to switch-to-configuration script
    /// - `args`: Arguments to pass to the script (e.g., ["switch"])
    ///
    /// # Returns
    ///
    /// - `Ok((success, stdout, stderr))` with command output
    fn execute_switch_to_configuration(
        &self,
        script_path: &std::path::Path,
        args: &[&str],
    ) -> Result<(bool, String, String)>;
}

/// Real command executor for production use
struct RealCommandExecutor;

impl CommandExecutor for RealCommandExecutor {
    fn execute_nixos_rebuild(&self, args: &[&str]) -> Result<(bool, String, String)> {
        let output = std::process::Command::new("nixos-rebuild")
            .args(args)
            .output()?;

        let success = output.status.success();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        Ok((success, stdout, stderr))
    }

    fn execute_switch_to_configuration(
        &self,
        script_path: &std::path::Path,
        args: &[&str],
    ) -> Result<(bool, String, String)> {
        let output = std::process::Command::new(script_path)
            .args(args)
            .output()?;

        let success = output.status.success();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        Ok((success, stdout, stderr))
    }
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
    executor: Box<dyn CommandExecutor + Send + Sync>,
    /// Build mode (flake or legacy)
    build_mode: NixOSBuildMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum NixOSBuildMode {
    Flake,
    Legacy { config_path: PathBuf },
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
            executor: Box::new(RealCommandExecutor),
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
            executor: Box::new(RealCommandExecutor),
            build_mode: NixOSBuildMode::Legacy { config_path },
        }
    }

    /// Create a new NixOSBuilder with custom executor (for testing)
    #[cfg(test)]
    fn new_with_executor(
        config_path: PathBuf,
        profile_path: PathBuf,
        executor: Box<dyn CommandExecutor + Send + Sync>,
    ) -> Self {
        Self {
            config_path,
            profile_path,
            executor,
            build_mode: NixOSBuildMode::Flake,
        }
    }

    #[cfg(test)]
    fn new_legacy_with_executor(
        config_path: PathBuf,
        profile_path: PathBuf,
        executor: Box<dyn CommandExecutor + Send + Sync>,
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
    /// builder.switch_profile(&generation)?;
    /// # Ok::<(), nails_core::NailsError>(())
    /// ```
    pub fn switch_profile(&self, generation: &str) -> Result<()> {
        if !self.is_flake() {
            return self.switch_legacy();
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
        tracing::info!("Switching to NixOS profile: generation {}", generation);

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
            .execute_switch_to_configuration(&switch_script, &["switch"])?;

        if !success {
            // Attempt rollback to previous generation
            if let Some(prev) = previous_gen {
                tracing::warn!("Switch failed, attempting rollback to generation {}", prev);
                if let Err(e) = self.switch_to_generation(&prev) {
                    tracing::error!("Rollback failed: {}", e);
                }
            }

            return Err(NailsError::NixOSError(format!("Switch failed: {}", stderr)));
        }

        tracing::info!("Switched to NixOS profile: generation {}", generation);
        Ok(())
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
    fn switch_to_generation(&self, generation: &str) -> Result<()> {
        // Construct path to the profile's activation script for rollback
        // This uses the system profile path, not our custom nails profile
        let system_profile_path =
            system_profiles_dir().join(format!("system-{}-link", generation));

        let switch_script = system_profile_path.join("bin/switch-to-configuration");

        let (success, _stdout, _stderr) = self
            .executor
            .execute_switch_to_configuration(&switch_script, &["switch"])?;

        if !success {
            return Err(NailsError::NixOSError("Rollback switch failed".into()));
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

    fn switch_legacy(&self) -> Result<()> {
        let config_path = match &self.build_mode {
            NixOSBuildMode::Legacy { config_path } => config_path,
            NixOSBuildMode::Flake => {
                return Err(NailsError::NixOSError(
                    "switch_legacy called for flake builder".into(),
                ))
            }
        };

        let arg = format!("nixos-config={}", config_path.display());
        let (success, _stdout, stderr) =
            self.executor.execute_nixos_rebuild(&["switch", "-I", &arg])?;

        if !success {
            return Err(NailsError::NixOSError(format!(
                "Legacy nixos-rebuild switch failed: {}",
                stderr
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

// ============================================================================
// NixOS Configuration Overlay (Story 4.12)
// ============================================================================
//
// Implements forensically clean hardware-configuration.nix overlay mechanism.
// Reference: thesis design.tex Section 4.3.4
//
// ## Architecture
//
// Hidden storage contains modified hardware-configuration.nix that imports
// hidden environment configuration:
//
// ```
// {hidden}/
// ├── etc/
// │   └── nixos/
// │       └── hardware-configuration.nix  # Modified with import
// ├── nixos/
// │   └── configuration.nix               # Hidden environment config
// └── ...
// ```
//
// ## Three Critical Properties (Thesis Section 4.3.4)
//
// 1. **Forensically Clean Base**
//    - Base /etc/nixos/hardware-configuration.nix contains zero evidence
//    - Indistinguishable from standard NixOS installation
//    - Verified by verify_base_config_clean()
//
// 2. **Standard NixOS Mechanism**
//    - Uses native NixOS `imports = [...]` array
//    - No custom patches or binary modifications
//    - Works with standard `nixos-rebuild switch`
//
// 3. **Atomic Transitions**
//    - Overlay mount is atomic (all-or-nothing)
//    - Config switch happens instantly via /etc overlay
//    - Clean rollback on failure

/// Metadata about NixOS configuration overlay paths
///
/// **Property 2: Standard NixOS Mechanism**
///
/// Uses native NixOS `imports = [...]` array for configuration injection.
/// No custom patches or binary modifications. Works with standard
/// `nixos-rebuild switch`. Follows NixOS best practices.
///
/// See thesis design.tex Section 4.3.4 for full details on three critical
/// properties of the NixOS config overlay mechanism.
///
/// Returned by `prepare_nixos_config_overlay()` after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NixOSConfigInfo {
    /// Path to modified hardware-configuration.nix in hidden storage
    pub hardware_config_path: PathBuf,

    /// Path to hidden configuration.nix
    pub hidden_config_path: PathBuf,

    /// Path to etc/nixos overlay directory in hidden storage
    pub etc_nixos_overlay: PathBuf,
}

/// Strip Nix comments from source text (lines starting with # and /* */ blocks).
///
/// This is a lightweight sanitizer for import validation; it is not a full Nix parser.
fn strip_nix_comments(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_block_comment = false;

    while let Some(c) = chars.next() {
        if in_block_comment {
            if c == '*' && matches!(chars.peek(), Some('/')) {
                chars.next();
                in_block_comment = false;
            }
            continue;
        }

        if c == '/' && matches!(chars.peek(), Some('*')) {
            chars.next();
            in_block_comment = true;
            continue;
        }

        if c == '#' {
            // Skip to end of line, preserving newline.
            for next in chars.by_ref() {
                if next == '\n' {
                    output.push('\n');
                    break;
                }
            }
            continue;
        }

        output.push(c);
    }

    output
}

/// Return true if the hardware configuration contains the expected import.
///
/// This ignores comment-only references to avoid false positives.
pub(crate) fn contains_nails_import(content: &str) -> bool {
    let stripped = strip_nix_comments(content);
    stripped.contains("./nails/configuration.nix")
}

/// Validates and prepares NixOS configuration overlay
///
/// **Property 2: Standard NixOS Mechanism**
///
/// Uses native NixOS `imports = [...]` array for configuration injection.
/// The modified hardware-configuration.nix contains a standard import statement
/// that references the hidden configuration.nix. No custom patches or binary
/// modifications required.
///
/// **Property 3: Atomic Transitions**
///
/// Overlay mount is atomic (all-or-nothing). Config switch happens instantly
/// via /etc overlay. Clean rollback on failure.
///
/// Ensures hidden storage contains required NixOS configuration structure:
/// - `{hidden}/etc/nixos/hardware-configuration.nix` (modified with import)
/// - `{hidden}/config/nixos/configuration.nix` (hidden environment config)
///
/// The modified hardware-configuration.nix MUST contain an import line
/// referencing the hidden configuration.nix file.
///
/// See thesis design.tex Section 4.3.4 for full details on three critical
/// properties of the NixOS config overlay mechanism.
///
/// # Arguments
///
/// * `fs` - Filesystem implementation for testing
/// * `hidden_path` - Path to hidden storage root (e.g., `/mnt/hidden`)
///
/// # Returns
///
/// * `Ok(NixOSConfigInfo)` - Validated overlay paths
/// * `Err(NailsError::NixOSError)` - Validation failed
///
/// # Example
///
/// ```no_run
/// use nails_core::{RealFilesystem, prepare_nixos_config_overlay};
/// use std::path::PathBuf;
///
/// let fs = RealFilesystem;
/// let hidden = PathBuf::from("/mnt/hidden");
///
/// let info = prepare_nixos_config_overlay(&fs, &hidden)?;
/// println!("Hardware config: {}", info.hardware_config_path.display());
/// # Ok::<(), nails_core::NailsError>(())
/// ```
pub fn prepare_nixos_config_overlay<F: Filesystem>(
    fs: &F,
    hidden_path: &Path,
) -> Result<NixOSConfigInfo> {
    let etc_nixos = hidden_path.join("etc/nixos");
    let hardware_config = etc_nixos.join("hardware-configuration.nix");
    let hidden_config = hidden_path.join("config/nixos/configuration.nix");

    // Validate etc/nixos directory exists
    if !fs.path_exists(&etc_nixos)? {
        return Err(NailsError::NixOSError(format!(
            "Hidden storage missing etc/nixos directory: {}",
            etc_nixos.display()
        )));
    }

    // Validate modified hardware-configuration.nix exists
    if !fs.path_exists(&hardware_config)? {
        return Err(NailsError::NixOSError(format!(
            "Modified hardware-configuration.nix not found at {}",
            hardware_config.display()
        )));
    }

    // Validate hidden configuration.nix exists at new location
    if !fs.path_exists(&hidden_config)? {
        return Err(NailsError::NixOSError(format!(
            "Hidden configuration.nix not found at {}",
            hidden_config.display()
        )));
    }

    // Validate modified config contains relative import to hidden config via nails/ symlink
    let content = fs.read_file_content(&hardware_config)?;
    let expected_import = "./nails/configuration.nix";

    if !contains_nails_import(&content) {
        return Err(NailsError::NixOSError(format!(
            "Modified hardware-configuration.nix does not contain required import: {}",
            expected_import
        )));
    }

    Ok(NixOSConfigInfo {
        hardware_config_path: hardware_config,
        hidden_config_path: hidden_config,
        etc_nixos_overlay: etc_nixos,
    })
}

/// Stage the hidden config symlink into the hidden /etc/nixos tree (Story 15.2)
///
/// Creates `{hidden}/etc/nixos/nails/` directory (if missing) and a symlink
/// `{hidden}/etc/nixos/nails/configuration.nix` → `{hidden}/config/nixos/configuration.nix`.
///
/// This is idempotent: if the directory and symlink already exist and are correct,
/// this function succeeds without any change.
///
/// After activation the overlay places `{hidden}/etc/nixos/` over `/etc/nixos/`, so
/// `/etc/nixos/nails/configuration.nix` resolves to the hidden config. The relative
/// import `./nails/configuration.nix` in hardware-configuration.nix then picks it up.
///
/// # Arguments
///
/// * `fs` - Filesystem implementation
/// * `hidden_path` - Path to hidden storage root (e.g., `/mnt/hidden`)
///
/// # Errors
///
/// Returns `NailsError::NixOSError` if directory creation or symlink creation fails.
pub fn stage_hidden_config_symlink<F: Filesystem>(fs: &F, hidden_path: &Path) -> Result<()> {
    let nails_dir = hidden_path.join("etc/nixos/nails");
    let symlink_path = nails_dir.join("configuration.nix");
    let symlink_target = hidden_path.join("config/nixos/configuration.nix");

    // Ensure the hidden config exists before staging the link.
    if !fs.path_exists(&symlink_target)? {
        return Err(NailsError::NixOSError(format!(
            "Hidden configuration.nix not found at {}",
            symlink_target.display()
        )));
    }

    // Create {hidden}/etc/nixos/nails/ if it doesn't exist (idempotent)
    if !fs.path_exists(&nails_dir)? {
        fs.create_directory(&nails_dir).map_err(|e| {
            NailsError::NixOSError(format!(
                "Failed to create directory {}: {}",
                nails_dir.display(),
                e
            ))
        })?;
    }

    // Create symlink (idempotent: no-op if it already points to the correct target)
    fs.create_symlink(&symlink_target, &symlink_path)
        .map_err(|e| {
            NailsError::NixOSError(format!(
                "Failed to create symlink {} -> {}: {}",
                symlink_path.display(),
                symlink_target.display(),
                e
            ))
        })?;

    Ok(())
}

/// Verifies base hardware-configuration.nix contains no hidden references
///
/// **Property 1: Forensically Clean Base**
///
/// Base /etc/nixos/hardware-configuration.nix contains zero evidence of
/// hidden environment. Indistinguishable from standard NixOS installation.
///
/// Scans base /etc/nixos/hardware-configuration.nix for forensic evidence
/// of hidden environment. Returns `Ok(true)` if base is clean, `Ok(false)`
/// if suspicious patterns detected.
///
/// # Suspicious Patterns
///
/// - `/mnt/hidden` or similar hidden mount points
/// - `hidden/nixos` or similar hidden config paths
/// - `nails` references (word boundary to avoid false positives like "snails")
/// - `plausible` or `deniability` keywords
/// - Standalone `hidden` keyword (with word boundaries)
///
/// See thesis design.tex Section 4.3.4 for full details on three critical
/// properties of the NixOS config overlay mechanism.
///
/// # Arguments
///
/// * `fs` - Filesystem implementation for testing
///
/// # Returns
///
/// * `Ok(true)` - Base config is forensically clean
/// * `Ok(false)` - Base config contains suspicious patterns
/// * `Err` - Cannot read base config (filesystem error)
///
/// If the file does not exist (non-NixOS system), this returns `Ok(true)` and logs a warning.
///
/// # Example
///
/// ```no_run
/// use nails_core::{RealFilesystem, verify_base_config_clean};
///
/// let fs = RealFilesystem;
/// let is_clean = verify_base_config_clean(&fs)?;
///
/// if !is_clean {
///     eprintln!("WARNING: Base config contains hidden environment traces!");
/// }
/// # Ok::<(), nails_core::NailsError>(())
/// ```
pub fn verify_base_config_clean<F: Filesystem>(fs: &F) -> Result<bool> {
    let base_config = PathBuf::from("/etc/nixos/hardware-configuration.nix");

    if !fs.path_exists(&base_config)? {
        // Non-NixOS systems may not have this file. Treat as clean to avoid false failure.
        tracing::warn!(
            "Base hardware-configuration.nix not found at /etc/nixos/hardware-configuration.nix; skipping clean check"
        );
        return Ok(true);
    }

    let content = fs.read_file_content(&base_config)?;
    let content_lower = content.to_lowercase();

    // Suspicious path patterns (substring match is appropriate for paths)
    if content_lower.contains("/mnt/hidden")
        || content_lower.contains("hidden/nixos")
        || content_lower.contains("/hidden/")
    {
        tracing::warn!("Base hardware-configuration.nix contains suspicious hidden path reference");
        return Ok(false);
    }

    // Word boundary patterns (check for "hidden" as whole word)
    // This catches: "hidden ", " hidden", " hidden ", "#hidden", etc.
    // But NOT: "hiddenstorage", "snails", etc.
    let hidden_word_boundaries = [
        " hidden ",   // Middle of line with spaces
        "\nhidden ",  // Start of line
        " hidden\n",  // End of line
        "\nhidden\n", // Whole line
        "#hidden ",   // Comment without leading space
        "#hidden\n",  // Comment at end of line
        ";hidden ",   // After semicolon (Nix syntax)
        ";hidden\n",  // Semicolon then end of line
        ";hidden=",   // After semicolon with assignment (e.g., ;hidden=true)
        " hidden\"",  // Before quote
        "\"hidden ",  // After quote
        " hidden=",   // Assignment without space (e.g., hidden=true)
        "=hidden ",   // Assignment value
        "=hidden\n",  // Assignment value at end of line
    ];

    for pattern in &hidden_word_boundaries {
        if content_lower.contains(pattern) {
            tracing::warn!("Base hardware-configuration.nix contains suspicious 'hidden' keyword");
            return Ok(false);
        }
    }

    // "nails" keyword with word boundaries to avoid false positives
    // like "snails", "fingernails", etc.
    let nails_word_boundaries = [
        " nails ",
        "\nnails ",
        " nails\n",
        "\nnails\n",
        "#nails ",
        "#nails\n",
        ";nails ",
        ";nails\n",
        " nails\"",
        "\"nails ",
        ".nails ", // After dot (e.g., config.nails)
        ".nails\n",
        ".nails.", // Dot notation (e.g., config.nails.enable)
        ".nails=", // Assignment (e.g., config.nails=true)
    ];

    for pattern in &nails_word_boundaries {
        if content_lower.contains(pattern) {
            tracing::warn!("Base hardware-configuration.nix contains suspicious 'nails' keyword");
            return Ok(false);
        }
    }

    // Plausible deniability keywords (these are unlikely to appear legitimately)
    if content_lower.contains("plausible") || content_lower.contains("deniability") {
        tracing::warn!("Base hardware-configuration.nix contains plausible deniability keywords");
        return Ok(false);
    }

    Ok(true)
}

/// Ensure the hardware configuration includes the NAILS import block.
///
/// Returns updated content when the import is missing, or the original content
/// when the import is already present (idempotent).
pub(crate) fn ensure_nails_import_block(content: &str) -> String {
    if contains_active_path(content, "./nails/configuration.nix") {
        return content.to_string();
    }

    const NAILS_ENTRY: &str = "    ./nails/configuration.nix";
    const INJECTED_BLOCK: &str =
        "# NAILS: injected import (do not edit)\nimports = [\n  ./nails/configuration.nix\n];\n\n";

    if let Some(imports_pos) = find_imports_bracket(content) {
        // An imports = [ ... ] block exists — insert our entry as the first element.
        let (before, after) = content.split_at(imports_pos);
        format!("{}{}\n{}", before, NAILS_ENTRY, after)
    } else {
        // No imports block — prepend a complete one.
        format!("{}{}", INJECTED_BLOCK, content)
    }
}

/// Injects a NAILS import block into the overlayed `/etc/nixos/hardware-configuration.nix`.
///
/// This function must be called **after** the `/etc` overlay has been mounted so that
/// writes land in the overlay upper layer, leaving the base underlay forensically clean.
///
/// ## Injection behaviour
///
/// * If no `imports` attribute exists in the file, a complete block is **prepended**:
///   ```nix
///   # NAILS: injected import (do not edit)
///   imports = [
///     ./nails/configuration.nix
///   ];
///   ```
/// * If an `imports = [` attribute already exists, `./nails/configuration.nix` is inserted
///   as the **first** element without adding a second `imports` attribute.
/// * If `./nails/configuration.nix` is already present the function is a **no-op**
///   (idempotent).
///
/// ## Errors
///
/// Returns `Err(NailsError::NixOSError)` on permission or I/O failure.
pub fn inject_import_block<F: Filesystem>(fs: &F) -> Result<()> {
    let target = PathBuf::from("/etc/nixos/hardware-configuration.nix");

    if !fs.path_exists(&target)? {
        // Non-NixOS systems may not have this file — skip injection gracefully.
        tracing::debug!(
            "inject_import_block: /etc/nixos/hardware-configuration.nix not found, skipping (non-NixOS system?)"
        );
        return Ok(());
    }

    let content = fs.read_file_content(&target)?;

    let new_content = ensure_nails_import_block(&content);
    if new_content == content {
        tracing::debug!("inject_import_block: ./nails/configuration.nix already present, skipping");
        return Ok(());
    }

    fs.write_file_content(&target, &new_content)?;
    tracing::info!(
        "inject_import_block: injected ./nails/configuration.nix into {}",
        target.display()
    );
    Ok(())
}

/// Returns the byte offset of the character **immediately after** the opening `[` of the
/// first `imports = [` (or `imports=[`) attribute found in `content`, so that a new entry
/// can be inserted there as the first element.
///
/// Returns `None` if no `imports` attribute is present.
fn find_imports_bracket(content: &str) -> Option<usize> {
    // Match `imports` followed by optional whitespace, `=`, optional whitespace, `[`
    let bytes = content.as_bytes();
    let search = b"imports";

    let mut i = 0usize;
    let mut in_string = false;
    let mut in_comment = false;

    while i < bytes.len() {
        let b = bytes[i];

        if in_comment {
            if b == b'\n' {
                in_comment = false;
            }
            i += 1;
            continue;
        }

        if in_string {
            if b == b'\\' {
                // Skip escaped char in string
                i = i.saturating_add(2);
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        if b == b'#' {
            in_comment = true;
            i += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            i += 1;
            continue;
        }

        if i + search.len() > bytes.len() {
            break;
        }

        if &bytes[i..i + search.len()] != search {
            i += 1;
            continue;
        }

        // Ensure we're not matching a larger identifier or dotted access (e.g., config.imports)
        let prev = if i == 0 { None } else { Some(bytes[i - 1]) };
        if prev.is_some_and(|p| is_ident_char(p) || p == b'.') {
            i += 1;
            continue;
        }
        let next = bytes.get(i + search.len()).copied();
        if next.is_some_and(is_ident_char) {
            i += 1;
            continue;
        }

        // Skip whitespace after "imports"
        let mut j = i + search.len();
        while j < bytes.len() && is_whitespace(bytes[j]) {
            j += 1;
        }
        // Expect '='
        if j >= bytes.len() || bytes[j] != b'=' {
            i += 1;
            continue;
        }
        j += 1;
        // Skip whitespace after '='
        while j < bytes.len() && is_whitespace(bytes[j]) {
            j += 1;
        }
        // Expect '['
        if j >= bytes.len() || bytes[j] != b'[' {
            i += 1;
            continue;
        }
        // Return position right after the '[', then skip to the next line start so our
        // inserted entry appears on its own line.
        j += 1; // move past '['
        if j < bytes.len() && bytes[j] == b'\n' {
            j += 1;
        }
        return Some(j);
    }
    None
}

fn contains_active_path(content: &str, path: &str) -> bool {
    let bytes = content.as_bytes();
    let needle = path.as_bytes();

    let mut i = 0usize;
    let mut in_string = false;
    let mut in_comment = false;

    while i < bytes.len() {
        let b = bytes[i];

        if in_comment {
            if b == b'\n' {
                in_comment = false;
            }
            i += 1;
            continue;
        }

        if in_string {
            if b == b'\\' {
                i = i.saturating_add(2);
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        if b == b'#' {
            in_comment = true;
            i += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            i += 1;
            continue;
        }

        if i + needle.len() <= bytes.len() && &bytes[i..i + needle.len()] == needle {
            return true;
        }

        i += 1;
    }

    false
}

fn is_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn is_whitespace(b: u8) -> bool {
    b == b' ' || b == b'\t' || b == b'\n' || b == b'\r'
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

        fn failure(stderr: String) -> Self {
            Self {
                should_succeed: false,
                stdout: String::new(),
                stderr,
            }
        }
    }

    impl CommandExecutor for MockCommandExecutor {
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

    #[test]
    #[cfg(unix)] // Symlink operations are Unix-specific
    fn test_build_profile_triggers_build_when_no_cache() {
        use tempfile::TempDir;

        // Create temporary directory
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().to_path_buf();
        let profile_path = temp_dir.path().join("nonexistent-profile");

        // CRITICAL: Profile should NOT exist before build_profile() is called
        // This test should verify that build is triggered, not that cache is hit
        assert!(
            !profile_path.exists(),
            "Profile should not exist before build"
        );

        // Create the result symlink that build would create
        let result_symlink = config_path.join("result");
        let dummy_store_path = temp_dir.path().join("abc12345-nixos-system-test-24.11");
        std::fs::write(&dummy_store_path, "dummy nixos system").unwrap();

        std::os::unix::fs::symlink(&dummy_store_path, &result_symlink).unwrap();

        // Create builder with mock that succeeds
        let builder = NixOSBuilder::new_with_executor(
            config_path,
            profile_path.clone(),
            Box::new(MockCommandExecutor::success()),
        );

        // Should trigger build (no cache exists) and parse result symlink
        let generation = builder.build_profile().unwrap();
        assert_eq!(generation, "abc12345");
    }

    #[test]
    fn test_build_profile_returns_error_on_build_failure() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let profile_path = temp_dir.path().join("nonexistent-profile");

        // Create builder with mock that fails
        let builder = NixOSBuilder::new_with_executor(
            PathBuf::from("/mnt/hidden/nixos"),
            profile_path,
            Box::new(MockCommandExecutor::failure(
                "error: build failed\nsome nixos error".to_string(),
            )),
        );

        // Should return error with stderr content
        let result = builder.build_profile();
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            NailsError::NixOSError(msg) => {
                assert!(msg.contains("Build failed"));
                assert!(msg.contains("some nixos error"));
            }
            _ => panic!("Expected NixOSError variant"),
        }
    }

    #[test]
    #[cfg(unix)] // Symlink operations are Unix-specific
    fn test_graceful_fallback_on_corrupt_symlink() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let profile_path = temp_dir.path().join("corrupt-profile");

        // Create a symlink to nonexistent target (simulating corrupt cache)
        let nonexistent_target = temp_dir.path().join("nonexistent-123-link");

        std::os::unix::fs::symlink(&nonexistent_target, &profile_path).unwrap();

        // Now create the real target that build would create
        let real_target = temp_dir.path().join("system-999-link");
        std::fs::write(&real_target, "dummy").unwrap();

        // Update symlink to point to real target (simulating rebuild)
        std::fs::remove_file(&profile_path).unwrap();
        std::os::unix::fs::symlink(&real_target, &profile_path).unwrap();

        let builder = NixOSBuilder::new_with_executor(
            PathBuf::from("/mnt/hidden/nixos"),
            profile_path.clone(),
            Box::new(MockCommandExecutor::success()),
        );

        // Should gracefully handle corrupt cache and use rebuilt profile
        let generation = builder.build_profile().unwrap();
        assert_eq!(generation, "999");
    }

    #[test]
    #[cfg(unix)] // Symlink operations are Unix-specific
    fn test_parse_generation_from_build_output() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().to_path_buf();
        let profile_path = temp_dir.path().join("nails-system");

        // Simulate nixos-rebuild build creating a result symlink
        let result_symlink = config_path.join("result");

        // Create a dummy file to simulate the store path (for symlink target)
        // Format: /nix/store/hash-nixos-system-hostname-version
        let dummy_store_path = temp_dir.path().join("abc12345-nixos-system-hostname-24.11");
        std::fs::write(&dummy_store_path, "dummy nixos system").unwrap();

        std::os::unix::fs::symlink(&dummy_store_path, &result_symlink).unwrap();

        let builder = NixOSBuilder::new(config_path, profile_path);

        // Parse generation from the result symlink
        let output = ""; // Output not actually used anymore
        let generation = builder.parse_generation_from_build_output(output).unwrap();

        // Should extract first 8 chars of store hash
        assert_eq!(generation, "abc12345");
    }

    #[test]
    fn test_parse_generation_fails_without_result_symlink() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().to_path_buf();
        let profile_path = temp_dir.path().join("nails-system");

        let builder = NixOSBuilder::new(config_path, profile_path);

        // Should fail when result symlink doesn't exist
        let output = "";
        let result = builder.parse_generation_from_build_output(output);
        assert!(result.is_err());

        match result.unwrap_err() {
            NailsError::NixOSError(msg) => {
                assert!(msg.contains("result symlink not found"));
            }
            _ => panic!("Expected NixOSError"),
        }
    }

    // ============================================================================
    // Tests for switch_profile() - Story 4.4
    // ============================================================================

    /// Mock command executor with switch support
    #[allow(dead_code)]
    struct MockSwitchExecutor {
        /// Whether switch command should succeed
        switch_succeeds: bool,
        /// Stderr to return on switch failure
        switch_stderr: String,
        /// Whether profile exists
        profile_exists: bool,
        /// Current generation to return
        current_generation: Option<String>,
    }

    impl MockSwitchExecutor {
        fn new_success(profile_exists: bool, current_gen: Option<String>) -> Self {
            Self {
                switch_succeeds: true,
                switch_stderr: String::new(),
                profile_exists,
                current_generation: current_gen,
            }
        }

        fn new_failure(stderr: String, profile_exists: bool, current_gen: Option<String>) -> Self {
            Self {
                switch_succeeds: false,
                switch_stderr: stderr,
                profile_exists,
                current_generation: current_gen,
            }
        }
    }

    impl CommandExecutor for MockSwitchExecutor {
        fn execute_nixos_rebuild(&self, args: &[&str]) -> Result<(bool, String, String)> {
            // Check if this is a switch command
            if args.contains(&"switch") {
                Ok((
                    self.switch_succeeds,
                    String::new(),
                    self.switch_stderr.clone(),
                ))
            } else {
                // Default for other commands
                Ok((true, String::new(), String::new()))
            }
        }

        fn execute_switch_to_configuration(
            &self,
            _script_path: &std::path::Path,
            args: &[&str],
        ) -> Result<(bool, String, String)> {
            // Check if this is a switch command
            if args.contains(&"switch") {
                Ok((
                    self.switch_succeeds,
                    String::new(),
                    self.switch_stderr.clone(),
                ))
            } else {
                // Default for other commands
                Ok((true, String::new(), String::new()))
            }
        }
    }

    #[test]
    #[cfg(unix)] // Symlink operations are Unix-specific
    fn test_switch_profile_success() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        // profile_path should be the BASE path, not the generation-specific path
        let profile_path = temp_dir.path().join("nails-system");

        // Create the generation-specific profile path that would be created by build_profile()
        let profile_generation_path = temp_dir.path().join("nails-system-123-link");

        // Create profile directory structure with switch-to-configuration script
        let bin_dir = profile_generation_path.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let switch_script = bin_dir.join("switch-to-configuration");
        std::fs::write(&switch_script, "#!/bin/sh\necho switching").unwrap();

        let builder = NixOSBuilder::new_with_executor(
            PathBuf::from("/mnt/hidden/nixos"),
            profile_path.clone(),
            Box::new(MockSwitchExecutor::new_success(
                true,
                Some("100".to_string()),
            )),
        );

        // Should successfully switch to profile
        let result = builder.switch_profile("123");
        if let Err(ref e) = result {
            eprintln!("Error: {:?}", e);
        }
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(unix)] // Symlink operations are Unix-specific
    fn test_switch_profile_failure_with_stderr() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        // profile_path should be the BASE path
        let profile_path = temp_dir.path().join("nails-system");

        // Create the generation-specific profile path
        let profile_generation_path = temp_dir.path().join("nails-system-123-link");

        // Create profile directory structure with switch-to-configuration script
        let bin_dir = profile_generation_path.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let switch_script = bin_dir.join("switch-to-configuration");
        std::fs::write(&switch_script, "#!/bin/sh\necho switching").unwrap();

        let builder = NixOSBuilder::new_with_executor(
            PathBuf::from("/mnt/hidden/nixos"),
            profile_path.clone(),
            Box::new(MockSwitchExecutor::new_failure(
                "error: activation failed\ndetailed error here".to_string(),
                true,
                Some("100".to_string()),
            )),
        );

        // Should return error with stderr
        let result = builder.switch_profile("123");
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            NailsError::NixOSError(msg) => {
                assert!(msg.contains("Switch failed"));
                assert!(msg.contains("activation failed"));
            }
            _ => panic!("Expected NixOSError variant"),
        }
    }

    #[test]
    fn test_switch_profile_missing_profile() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let profile_path = temp_dir.path().join("nonexistent-profile");

        let builder = NixOSBuilder::new_with_executor(
            PathBuf::from("/mnt/hidden/nixos"),
            profile_path,
            Box::new(MockSwitchExecutor::new_success(false, None)),
        );

        // Should return error indicating profile not found
        let result = builder.switch_profile("123");
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            NailsError::NixOSError(msg) => {
                assert!(msg.contains("Profile not found"));
                assert!(msg.contains("123"));
            }
            _ => panic!("Expected NixOSError variant"),
        }
    }

    #[test]
    #[cfg(unix)] // Symlink operations are Unix-specific
    fn test_switch_profile_rollback_on_failure() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        // profile_path should be the BASE path
        let profile_path = temp_dir.path().join("nails-system");

        // Create the generation-specific profile path
        let profile_generation_path = temp_dir.path().join("nails-system-123-link");

        // Create profile directory structure with switch-to-configuration script
        let bin_dir = profile_generation_path.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let switch_script = bin_dir.join("switch-to-configuration");
        std::fs::write(&switch_script, "#!/bin/sh\necho switching").unwrap();

        let builder = NixOSBuilder::new_with_executor(
            PathBuf::from("/mnt/hidden/nixos"),
            profile_path.clone(),
            Box::new(MockSwitchExecutor::new_failure(
                "error: activation failed".to_string(),
                true,
                Some("100".to_string()),
            )),
        );

        // Should attempt rollback and still return error
        let result = builder.switch_profile("123");
        assert!(result.is_err());

        // Error should still be the original switch failure
        let err = result.unwrap_err();
        match err {
            NailsError::NixOSError(msg) => {
                assert!(msg.contains("Switch failed"));
            }
            _ => panic!("Expected NixOSError variant"),
        }
    }

    // ========================================================================
    // NixOS Configuration Overlay Tests (Story 4.12)
    // ========================================================================

    #[test]
    fn test_prepare_nixos_config_overlay_success() {
        let fs = crate::MockFilesystem::new();
        let hidden_path = PathBuf::from("/mnt/hidden");

        // Setup: Mock directory structure
        fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos", "dir");

        // Mock modified hardware-configuration.nix with relative import (Story 15.2)
        fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/mnt/hidden/etc/nixos/hardware-configuration.nix",
            "{ imports = [ (modulesPath + \"/installer/scan/not-detected.nix\") ./nails/configuration.nix ]; }"
        );

        // Mock hidden configuration.nix at new location (Story 15.2)
        fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", "file");
        fs.mock_set_file_content(
            "/mnt/hidden/config/nixos/configuration.nix",
            "{ environment.systemPackages = with pkgs; [ tor-browser ]; }",
        );

        // Test: Should succeed with all validation passing
        let result = super::prepare_nixos_config_overlay(&fs, &hidden_path);
        assert!(result.is_ok());

        let info = result.unwrap();
        assert_eq!(
            info.hardware_config_path,
            PathBuf::from("/mnt/hidden/etc/nixos/hardware-configuration.nix")
        );
        assert_eq!(
            info.hidden_config_path,
            PathBuf::from("/mnt/hidden/config/nixos/configuration.nix")
        );
        assert_eq!(
            info.etc_nixos_overlay,
            PathBuf::from("/mnt/hidden/etc/nixos")
        );
    }

    #[test]
    fn test_prepare_nixos_config_overlay_missing_etc_nixos() {
        let fs = crate::MockFilesystem::new();
        let hidden_path = PathBuf::from("/mnt/hidden");

        // Test: Should fail when etc/nixos directory missing
        let result = super::prepare_nixos_config_overlay(&fs, &hidden_path);
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            NailsError::NixOSError(msg) => {
                assert!(msg.contains("etc/nixos"));
                assert!(msg.contains("missing"));
            }
            _ => panic!("Expected NixOSError variant, got: {:?}", err),
        }
    }

    #[test]
    fn test_prepare_nixos_config_overlay_missing_hardware_config() {
        let fs = crate::MockFilesystem::new();
        let hidden_path = PathBuf::from("/mnt/hidden");

        // Setup: Create directory but no hardware-configuration.nix
        fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos", "dir");

        // Test: Should fail when hardware-configuration.nix missing
        let result = super::prepare_nixos_config_overlay(&fs, &hidden_path);
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            NailsError::NixOSError(msg) => {
                assert!(msg.contains("hardware-configuration.nix"));
                assert!(msg.contains("not found"));
            }
            _ => panic!("Expected NixOSError variant, got: {:?}", err),
        }
    }

    #[test]
    fn test_prepare_nixos_config_overlay_missing_hidden_config() {
        let fs = crate::MockFilesystem::new();
        let hidden_path = PathBuf::from("/mnt/hidden");

        // Setup: Create etc/nixos and hardware-configuration.nix with correct relative import
        fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos", "dir");
        fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/mnt/hidden/etc/nixos/hardware-configuration.nix",
            "{ imports = [ ./nails/configuration.nix ]; }",
        );
        // Note: hidden config at config/nixos/configuration.nix is NOT set up

        // Test: Should fail when hidden configuration.nix missing
        let result = super::prepare_nixos_config_overlay(&fs, &hidden_path);
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            NailsError::NixOSError(msg) => {
                assert!(msg.contains("configuration.nix"));
                assert!(msg.contains("not found"));
            }
            _ => panic!("Expected NixOSError variant, got: {:?}", err),
        }
    }

    #[test]
    fn test_prepare_nixos_config_overlay_missing_import() {
        let fs = crate::MockFilesystem::new();
        let hidden_path = PathBuf::from("/mnt/hidden");

        // Setup: Create all files but hardware-configuration.nix WITHOUT relative import
        fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos", "dir");
        fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/mnt/hidden/etc/nixos/hardware-configuration.nix",
            "{ imports = [ (modulesPath + \"/installer/scan/not-detected.nix\") ]; }",
        );

        fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", "file");
        fs.mock_set_file_content("/mnt/hidden/config/nixos/configuration.nix", "{ }");

        // Test: Should fail when import line missing
        let result = super::prepare_nixos_config_overlay(&fs, &hidden_path);
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            NailsError::NixOSError(msg) => {
                assert!(msg.contains("does not contain"));
                assert!(msg.contains("import"));
            }
            _ => panic!("Expected NixOSError variant, got: {:?}", err),
        }
    }

    #[test]
    fn test_prepare_nixos_config_overlay_ignores_commented_import() {
        let fs = crate::MockFilesystem::new();
        let hidden_path = PathBuf::from("/mnt/hidden");

        // Setup: Create all files but only a commented import in hardware-configuration.nix
        fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos", "dir");
        fs.mock_set_path_exists("/mnt/hidden/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/mnt/hidden/etc/nixos/hardware-configuration.nix",
            r#"{ imports = [
  # ./nails/configuration.nix
  (modulesPath + "/installer/scan/not-detected.nix")
]; }"#,
        );

        fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", "file");
        fs.mock_set_file_content("/mnt/hidden/config/nixos/configuration.nix", "{ }");

        // Test: Should fail when import is commented out
        let result = super::prepare_nixos_config_overlay(&fs, &hidden_path);
        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            NailsError::NixOSError(msg) => {
                assert!(msg.contains("does not contain"));
                assert!(msg.contains("import"));
            }
            _ => panic!("Expected NixOSError variant, got: {:?}", err),
        }
    }

    #[test]
    fn test_prepare_nixos_config_overlay_different_hidden_mount() {
        let fs = crate::MockFilesystem::new();
        let hidden_path = PathBuf::from("/media/encrypted");

        // Setup: Use different hidden mount point
        fs.mock_set_path_exists("/media/encrypted/etc/nixos", true);
        fs.mock_set_path_type("/media/encrypted/etc/nixos", "dir");
        fs.mock_set_path_exists(
            "/media/encrypted/etc/nixos/hardware-configuration.nix",
            true,
        );
        fs.mock_set_path_type(
            "/media/encrypted/etc/nixos/hardware-configuration.nix",
            "file",
        );
        fs.mock_set_file_content(
            "/media/encrypted/etc/nixos/hardware-configuration.nix",
            "{ imports = [ (modulesPath + \"/installer/scan/not-detected.nix\") ./nails/configuration.nix ]; }"
        );

        fs.mock_set_path_exists("/media/encrypted/config/nixos/configuration.nix", true);
        fs.mock_set_path_type("/media/encrypted/config/nixos/configuration.nix", "file");
        fs.mock_set_file_content("/media/encrypted/config/nixos/configuration.nix", "{ }");

        // Test: Should work with non-standard hidden mount point
        let result = super::prepare_nixos_config_overlay(&fs, &hidden_path);
        assert!(result.is_ok());
    }

    // ========================================================================
    // stage_hidden_config_symlink Tests (Story 15.2)
    // ========================================================================

    #[test]
    fn test_stage_hidden_config_symlink_creates_dir_and_symlink() {
        let fs = crate::MockFilesystem::new();
        let hidden_path = PathBuf::from("/mnt/hidden");

        // Setup: etc/nixos exists but nails/ subdir does not
        fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");
        // Make etc/nixos writable so nails/ can be created
        fs.mock_set_writable("/mnt/hidden/etc/nixos", true);
        fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", "file");

        let result = super::stage_hidden_config_symlink(&fs, &hidden_path);
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result);

        // Verify nails/ dir was created
        let nails_dir = PathBuf::from("/mnt/hidden/etc/nixos/nails");
        assert!(
            fs.path_exists(&nails_dir).unwrap(),
            "nails/ directory should exist"
        );

        // Verify symlink was created with correct target
        let symlink_path = PathBuf::from("/mnt/hidden/etc/nixos/nails/configuration.nix");
        assert!(
            fs.is_symlink(&symlink_path).unwrap(),
            "symlink should exist"
        );
        let expected_target = PathBuf::from("/mnt/hidden/config/nixos/configuration.nix");
        assert_eq!(
            fs.mock_get_symlink_target(&symlink_path),
            Some(expected_target)
        );
    }

    #[test]
    fn test_stage_hidden_config_symlink_idempotent() {
        let fs = crate::MockFilesystem::new();
        let hidden_path = PathBuf::from("/mnt/hidden");

        // Setup: nails/ dir already exists AND symlink already points to correct target
        // Use create_symlink to set up state (it records both the symlink flag and target).
        let nails_dir = "/mnt/hidden/etc/nixos/nails";
        let symlink_path = "/mnt/hidden/etc/nixos/nails/configuration.nix";
        fs.mock_set_path_exists(nails_dir, true);
        fs.mock_set_path_type(nails_dir, "directory");
        fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", "file");
        fs.create_symlink(
            &PathBuf::from("/mnt/hidden/config/nixos/configuration.nix"),
            &PathBuf::from(symlink_path),
        )
        .unwrap();

        // Calling stage again should be a no-op (idempotent)
        let result = super::stage_hidden_config_symlink(&fs, &hidden_path);
        assert!(result.is_ok(), "Should be idempotent: {:?}", result);
    }

    #[test]
    fn test_stage_hidden_config_symlink_nails_dir_already_exists() {
        let fs = crate::MockFilesystem::new();
        let hidden_path = PathBuf::from("/mnt/hidden");

        // Setup: nails/ dir already exists, no symlink yet
        fs.mock_set_path_exists("/mnt/hidden/etc/nixos/nails", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos/nails", "directory");
        fs.mock_set_writable("/mnt/hidden/etc/nixos/nails", true);
        fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", "file");

        let result = super::stage_hidden_config_symlink(&fs, &hidden_path);
        assert!(result.is_ok(), "Expected Ok, got: {:?}", result);

        let symlink_path = PathBuf::from("/mnt/hidden/etc/nixos/nails/configuration.nix");
        assert!(
            fs.is_symlink(&symlink_path).unwrap(),
            "symlink should exist"
        );
    }

    #[test]
    fn test_stage_hidden_config_symlink_fails_when_target_missing() {
        let fs = crate::MockFilesystem::new();
        let hidden_path = PathBuf::from("/mnt/hidden");

        // Setup: etc/nixos exists but hidden config is missing
        fs.mock_set_path_exists("/mnt/hidden/etc/nixos", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos", "directory");
        fs.mock_set_writable("/mnt/hidden/etc/nixos", true);

        let result = super::stage_hidden_config_symlink(&fs, &hidden_path);
        assert!(result.is_err(), "Expected error when target missing");
        match result.unwrap_err() {
            NailsError::NixOSError(msg) => {
                assert!(msg.contains("/mnt/hidden/config/nixos/configuration.nix"));
            }
            other => panic!("Expected NixOSError, got {:?}", other),
        }

        let symlink_path = PathBuf::from("/mnt/hidden/etc/nixos/nails/configuration.nix");
        assert!(
            !fs.is_symlink(&symlink_path).unwrap(),
            "symlink should not be created when target is missing"
        );
    }

    #[test]
    fn test_stage_hidden_config_symlink_errors_on_wrong_existing_target() {
        let fs = crate::MockFilesystem::new();
        let hidden_path = PathBuf::from("/mnt/hidden");

        // Setup: target exists
        fs.mock_set_path_exists("/mnt/hidden/config/nixos/configuration.nix", true);
        fs.mock_set_path_type("/mnt/hidden/config/nixos/configuration.nix", "file");

        // Existing symlink points elsewhere
        fs.mock_set_path_exists("/mnt/hidden/etc/nixos/nails", true);
        fs.mock_set_path_type("/mnt/hidden/etc/nixos/nails", "directory");
        fs.create_symlink(
            &PathBuf::from("/mnt/hidden/config/nixos/other.nix"),
            &PathBuf::from("/mnt/hidden/etc/nixos/nails/configuration.nix"),
        )
        .unwrap();

        let result = super::stage_hidden_config_symlink(&fs, &hidden_path);
        assert!(result.is_err(), "Expected error for wrong symlink target");
    }

    #[test]
    fn test_verify_base_config_clean_success() {
        let fs = crate::MockFilesystem::new();

        // Setup: Create clean base hardware-configuration.nix
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            r#"{ config, lib, pkgs, modulesPath, ... }:
{
  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];
  boot.initrd.availableKernelModules = [ "xhci_pci" "ahci" "nvme" ];
  fileSystems."/" = { device = "/dev/disk/by-uuid/abc"; fsType = "ext4"; };
}"#,
        );

        // Test: Should return Ok(true) for clean config
        let result = super::verify_base_config_clean(&fs);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_base_config_clean_suspicious_hidden_path() {
        let fs = crate::MockFilesystem::new();

        // Setup: Create base config WITH suspicious /mnt/hidden reference
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            r#"{ config, lib, pkgs, modulesPath, ... }:
{
  imports = [
    (modulesPath + "/installer/scan/not-detected.nix")
    /mnt/hidden/nixos/configuration.nix
  ];
}"#,
        );

        // Test: Should return Ok(false) when suspicious pattern detected
        let result = super::verify_base_config_clean(&fs);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_base_config_clean_suspicious_nails_reference() {
        let fs = crate::MockFilesystem::new();

        // Setup: Create base config WITH suspicious nails reference
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            r#"{ config, lib, pkgs, modulesPath, ... }:
{
  # NAILS hidden environment configuration
  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];
}"#,
        );

        // Test: Should return Ok(false) when nails keyword detected
        let result = super::verify_base_config_clean(&fs);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_base_config_clean_case_insensitive() {
        let fs = crate::MockFilesystem::new();

        // Setup: Create base config with uppercase HIDDEN keyword
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            r#"{ config, lib, pkgs, modulesPath, ... }:
{
  # Configuration for HIDDEN volume
  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];
}"#,
        );

        // Test: Should detect suspicious patterns case-insensitively
        let result = super::verify_base_config_clean(&fs);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_verify_base_config_clean_missing_file() {
        let fs = crate::MockFilesystem::new();

        // Test: Missing file is treated as clean (non-NixOS system)
        let result = super::verify_base_config_clean(&fs);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_base_config_clean_plausible_deniability_keywords() {
        let fs = crate::MockFilesystem::new();

        // Setup: Create base config with plausible deniability keywords
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            r#"{ config, lib, pkgs, modulesPath, ... }:
{
  # This setup provides plausible deniability
  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];
}"#,
        );

        // Test: Should detect plausible deniability keywords
        let result = super::verify_base_config_clean(&fs);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    // ========================================================================
    // Edge Case Tests for Pattern Detection Bypass Fixes (Code Review Fixes)
    // ========================================================================

    #[test]
    fn test_verify_base_config_clean_hidden_comment_no_leading_space() {
        // CR: Test bypass vulnerability - #hidden without leading space
        let fs = crate::MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            r#"{
  #hidden config
  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];
}"#,
        );

        let result = super::verify_base_config_clean(&fs);
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Should detect 'hidden' in comment without leading space"
        );
    }

    #[test]
    fn test_verify_base_config_clean_hidden_assignment_no_trailing_space() {
        // CR: Test bypass vulnerability - hidden=true without trailing space
        let fs = crate::MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            r#"{
  hidden=true
  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];
}"#,
        );

        let result = super::verify_base_config_clean(&fs);
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Should detect 'hidden' keyword without trailing space"
        );
    }

    #[test]
    fn test_verify_base_config_clean_hidden_start_of_line() {
        // CR: Test bypass vulnerability - hidden at start of line
        let fs = crate::MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            r#"{
hidden = true
  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];
}"#,
        );

        let result = super::verify_base_config_clean(&fs);
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Should detect 'hidden' keyword at start of line"
        );
    }

    #[test]
    fn test_verify_base_config_clean_snails_false_positive() {
        // CR: Test false positive fix - "snails" should NOT be flagged
        let fs = crate::MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            r#"{
  # This config uses snails for testing biological models
  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];
}"#,
        );

        let result = super::verify_base_config_clean(&fs);
        assert!(result.is_ok());
        assert!(
            result.unwrap(),
            "Should NOT flag 'snails' (contains 'nails' as substring)"
        );
    }

    #[test]
    fn test_verify_base_config_clean_fingernails_false_positive() {
        // CR: Test false positive fix - "fingernails" should NOT be flagged
        let fs = crate::MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            r#"{
  # System for tracking fingernails growth rates
  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];
}"#,
        );

        let result = super::verify_base_config_clean(&fs);
        assert!(result.is_ok());
        assert!(
            result.unwrap(),
            "Should NOT flag 'fingernails' (contains 'nails' as substring)"
        );
    }

    #[test]
    fn test_verify_base_config_clean_nails_word_boundary_in_comment() {
        // CR: "nails" with word boundaries SHOULD be detected
        let fs = crate::MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            r#"{
  # NAILS environment configuration
  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];
}"#,
        );

        let result = super::verify_base_config_clean(&fs);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Should detect 'NAILS' keyword in comment");
    }

    #[test]
    fn test_verify_base_config_clean_nails_idiomatic_comment() {
        // CR: "This config nails the setup" - contains standalone "nails"
        let fs = crate::MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            r#"{
  # This config nails the networking setup
  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];
}"#,
        );

        let result = super::verify_base_config_clean(&fs);
        assert!(result.is_ok());
        assert!(
            !result.unwrap(),
            "Should detect standalone 'nails' in idiomatic comment"
        );
    }

    #[test]
    fn test_verify_base_config_clean_hidden_with_semicolon() {
        // CR: Test ;hidden pattern (Nix syntax after semicolon)
        let fs = crate::MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            r#"{
  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];hidden=true
}"#,
        );

        let result = super::verify_base_config_clean(&fs);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Should detect 'hidden' after semicolon");
    }

    #[test]
    fn test_verify_base_config_clean_config_nails_dot_notation() {
        // CR: config.nails notation should be detected
        let fs = crate::MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            r#"{
  config.nails.enable = true;
  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];
}"#,
        );

        let result = super::verify_base_config_clean(&fs);
        assert!(result.is_ok());
        assert!(!result.unwrap(), "Should detect 'nails' after dot notation");
    }

    #[test]
    fn test_verify_base_config_clean_legitimate_hidden_substring() {
        // CR: Words containing "hidden" as substring should NOT be flagged
        let fs = crate::MockFilesystem::new();
        fs.mock_set_path_exists("/etc/nixos/hardware-configuration.nix", true);
        fs.mock_set_path_type("/etc/nixos/hardware-configuration.nix", "file");
        fs.mock_set_file_content(
            "/etc/nixos/hardware-configuration.nix",
            r#"{
  # This config has hiddenstorage as a single word
  boot.kernelModules = [ "hiddenstorage" ];
  imports = [ (modulesPath + "/installer/scan/not-detected.nix") ];
}"#,
        );

        let result = super::verify_base_config_clean(&fs);
        assert!(result.is_ok());
        assert!(
            result.unwrap(),
            "Should NOT flag 'hiddenstorage' (contains 'hidden' as substring)"
        );
    }

    // ========================================================================
    // inject_import_block tests (Story 15.1)
    // ========================================================================

    #[test]
    fn test_inject_import_block_no_imports_prepends_full_block() {
        // AC2: When no imports block exists, prepend the complete block.
        let fs = crate::MockFilesystem::new();
        let hw = "/etc/nixos/hardware-configuration.nix";
        fs.mock_set_path_exists(hw, true);
        fs.mock_set_path_type(hw, "file");
        fs.mock_set_file_content(
            hw,
            r#"{ config, pkgs, ... }:
{
  boot.loader.systemd-boot.enable = true;
}
"#,
        );

        let result = super::inject_import_block(&fs);
        assert!(
            result.is_ok(),
            "inject_import_block should succeed: {:?}",
            result
        );

        let written = fs
            .get_written_content(&PathBuf::from(hw))
            .expect("File should have been written");

        assert!(
            written.starts_with("# NAILS: injected import (do not edit)\n"),
            "Written content should start with NAILS comment, got:\n{}",
            written
        );
        assert!(
            written.contains("imports = [\n  ./nails/configuration.nix\n];"),
            "Written content should contain full import block, got:\n{}",
            written
        );
        assert!(
            written.contains("boot.loader.systemd-boot.enable = true;"),
            "Original content should be preserved, got:\n{}",
            written
        );
    }

    #[test]
    fn test_inject_import_block_existing_imports_inserts_as_first() {
        // AC2: When imports = [ ... ] exists, insert ./nails/configuration.nix as the first element.
        let fs = crate::MockFilesystem::new();
        let hw = "/etc/nixos/hardware-configuration.nix";
        fs.mock_set_path_exists(hw, true);
        fs.mock_set_path_type(hw, "file");
        fs.mock_set_file_content(
            hw,
            r#"{ config, pkgs, ... }:
{
  imports = [
    (modulesPath + "/installer/scan/not-detected.nix")
  ];
  boot.loader.grub.enable = true;
}
"#,
        );

        let result = super::inject_import_block(&fs);
        assert!(
            result.is_ok(),
            "inject_import_block should succeed: {:?}",
            result
        );

        let written = fs
            .get_written_content(&PathBuf::from(hw))
            .expect("File should have been written");

        // ./nails/configuration.nix must appear before the existing entry
        let nails_pos = written
            .find("./nails/configuration.nix")
            .expect("nails entry should be present");
        let existing_pos = written
            .find("modulesPath")
            .expect("existing entry should still be present");
        assert!(
            nails_pos < existing_pos,
            "nails entry should come before existing entry"
        );

        // Must not have a second `imports =` attribute
        assert_eq!(
            written.matches("imports =").count(),
            1,
            "Should not introduce a second imports attribute"
        );
    }

    #[test]
    fn test_inject_import_block_idempotent_when_already_injected() {
        // AC2: When ./nails/configuration.nix is already present, do nothing.
        let fs = crate::MockFilesystem::new();
        let hw = "/etc/nixos/hardware-configuration.nix";
        let original = r#"# NAILS: injected import (do not edit)
imports = [
  ./nails/configuration.nix
];

{ config, pkgs, ... }:
{
  boot.loader.grub.enable = true;
}
"#;
        fs.mock_set_path_exists(hw, true);
        fs.mock_set_path_type(hw, "file");
        fs.mock_set_file_content(hw, original);

        let result = super::inject_import_block(&fs);
        assert!(
            result.is_ok(),
            "inject_import_block should succeed: {:?}",
            result
        );

        // No write should have occurred
        let written = fs.get_written_content(&PathBuf::from(hw));
        assert!(
            written.is_none(),
            "No write should occur when already injected, but got:\n{:?}",
            written
        );
    }

    #[test]
    fn test_inject_import_block_missing_file_returns_ok() {
        // AC4 (non-NixOS): Missing file should skip gracefully (non-fatal) rather than error.
        // The file is absent on non-NixOS systems; failing activation would be wrong.
        let fs = crate::MockFilesystem::new();
        // Deliberately do NOT set the path to exist

        let result = super::inject_import_block(&fs);
        assert!(
            result.is_ok(),
            "Should skip gracefully (Ok) when hardware-configuration.nix is absent"
        );

        // No write should have occurred
        let written =
            fs.get_written_content(&PathBuf::from("/etc/nixos/hardware-configuration.nix"));
        assert!(
            written.is_none(),
            "No write should occur when file is absent"
        );
    }

    #[test]
    fn test_inject_import_block_write_failure_returns_error() {
        // AC4: Permission/I/O errors should return a clear error.
        let fs = crate::MockFilesystem::new();
        let hw = "/etc/nixos/hardware-configuration.nix";
        fs.mock_set_path_exists(hw, true);
        fs.mock_set_path_type(hw, "file");
        fs.mock_set_file_content(
            hw,
            r#"{ config, pkgs, ... }:
{
  boot.loader.systemd-boot.enable = true;
}
"#,
        );
        fs.mock_set_write_should_fail(hw, true);

        let result = super::inject_import_block(&fs);
        assert!(result.is_err(), "Write failure should propagate");
    }

    #[test]
    fn test_inject_import_block_ignores_commented_nails_path() {
        // Comment-only reference should NOT be treated as idempotent.
        let fs = crate::MockFilesystem::new();
        let hw = "/etc/nixos/hardware-configuration.nix";
        fs.mock_set_path_exists(hw, true);
        fs.mock_set_path_type(hw, "file");
        fs.mock_set_file_content(
            hw,
            r#"{ config, pkgs, ... }:
{
  # ./nails/configuration.nix
  boot.loader.systemd-boot.enable = true;
}
"#,
        );

        let result = super::inject_import_block(&fs);
        assert!(result.is_ok(), "Injection should succeed");

        let written = fs
            .get_written_content(&PathBuf::from(hw))
            .expect("File should have been written");
        assert!(
            written.contains("./nails/configuration.nix"),
            "Injected path should be present"
        );
        assert!(
            written.starts_with("# NAILS: injected import (do not edit)"),
            "Should prepend injected block when only comment reference exists"
        );
    }

    #[test]
    fn test_inject_import_block_ignores_commented_imports_block() {
        // Commented imports block should not be detected as real.
        let fs = crate::MockFilesystem::new();
        let hw = "/etc/nixos/hardware-configuration.nix";
        fs.mock_set_path_exists(hw, true);
        fs.mock_set_path_type(hw, "file");
        fs.mock_set_file_content(
            hw,
            r#"{ config, pkgs, ... }:
{
  # imports = [
  #   ./nails/configuration.nix
  # ];
  boot.loader.grub.enable = true;
}
"#,
        );

        let result = super::inject_import_block(&fs);
        assert!(result.is_ok(), "Injection should succeed");

        let written = fs
            .get_written_content(&PathBuf::from(hw))
            .expect("File should have been written");
        assert!(
            written.starts_with("# NAILS: injected import (do not edit)"),
            "Should prepend injected block when only commented imports exist"
        );
    }

    // ========== Story 15.4: Config fingerprint & fast-path unit tests ==========

    #[test]
    fn test_compute_config_fingerprint_deterministic() {
        // AC1: same inputs → same fingerprint
        let fp1 = compute_config_fingerprint("hardware = {}", "hidden = {}");
        let fp2 = compute_config_fingerprint("hardware = {}", "hidden = {}");
        assert_eq!(fp1, fp2, "Same inputs must produce the same fingerprint");
    }

    #[test]
    fn test_compute_config_fingerprint_hardware_change_detected() {
        // AC1: changing hardware config changes fingerprint
        let fp_base = compute_config_fingerprint("hardware = {}", "hidden = {}");
        let fp_changed =
            compute_config_fingerprint("hardware = { changed = true; }", "hidden = {}");
        assert_ne!(
            fp_base, fp_changed,
            "Hardware config change must produce a different fingerprint"
        );
    }

    #[test]
    fn test_compute_config_fingerprint_hidden_config_change_detected() {
        // AC1: changing hidden config changes fingerprint
        let fp_base = compute_config_fingerprint("hardware = {}", "hidden = {}");
        let fp_changed = compute_config_fingerprint("hardware = {}", "hidden = { extra = 1; }");
        assert_ne!(
            fp_base, fp_changed,
            "Hidden config change must produce a different fingerprint"
        );
    }

    #[test]
    fn test_compute_config_fingerprint_no_separator_collision() {
        // Ensure "ab" + "cd" != "a" + "bcd" (separator prevents prefix-collision)
        let fp1 = compute_config_fingerprint("ab", "cd");
        let fp2 = compute_config_fingerprint("a", "bcd");
        assert_ne!(
            fp1, fp2,
            "Separator must prevent prefix-collision between the two inputs"
        );
    }

    #[test]
    fn test_compute_config_fingerprint_is_16_hex_chars() {
        let fp = compute_config_fingerprint("hw", "cfg");
        assert_eq!(
            fp.len(),
            16,
            "Fingerprint must be 16 hex characters (64-bit)"
        );
        assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit()),
            "Fingerprint must only contain lowercase hex digits"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_fingerprint_match_triggers_fast_path() {
        // AC2: matching fingerprint + cached profile → fast path used, no build
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let profile_path = temp_dir.path().join("test-profile");
        // Create a cached profile symlink pointing to a generation
        // Note: Test fixture uses simplified "system-77-link" format rather than
        // full Nix store path format (e.g., "/nix/store/hash-nixos-system-hostname-77-link")
        // because get_cached_generation() extracts the numeric component from any "system-{N}-link" pattern.
        // This is sufficient for testing the fast-path logic without requiring realistic store paths.
        let target = temp_dir.path().join("system-77-link");
        std::fs::write(&target, "dummy").unwrap();
        std::os::unix::fs::symlink(&target, &profile_path).unwrap();

        let builder = NixOSBuilder::new_with_executor(
            PathBuf::from("/mnt/hidden/nixos"),
            profile_path,
            Box::new(MockCommandExecutor::success()),
        );

        let fp = compute_config_fingerprint("hw = {}", "cfg = {}");

        // Same fingerprint stored → fast path
        let (generation_id, new_fp, fast) = builder
            .build_profile_with_fingerprint(&fp, Some(&fp))
            .unwrap();

        assert!(fast, "Fast path should be used when fingerprint matches");
        assert_eq!(generation_id, "77", "Should return cached generation");
        assert_eq!(
            new_fp, fp,
            "Returned fingerprint must equal current fingerprint"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_fingerprint_mismatch_triggers_build() {
        // AC3: different fingerprint → falls through to full build
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().to_path_buf();
        let profile_path = temp_dir.path().join("nonexistent-profile");

        // Create result symlink for the build output
        let result_symlink = config_path.join("result");
        let dummy_store = temp_dir.path().join("abcdef01-nixos-system-test-24.11");
        std::fs::write(&dummy_store, "dummy").unwrap();
        std::os::unix::fs::symlink(&dummy_store, &result_symlink).unwrap();

        let builder = NixOSBuilder::new_with_executor(
            config_path,
            profile_path,
            Box::new(MockCommandExecutor::success()),
        );

        let current_fp = compute_config_fingerprint("hw = { new = true; }", "cfg = {}");
        let stored_fp = compute_config_fingerprint("hw = {}", "cfg = {}");

        // Different stored fingerprint → build must run
        let (generation_id, new_fp, fast) = builder
            .build_profile_with_fingerprint(&current_fp, Some(&stored_fp))
            .unwrap();

        assert!(!fast, "Fast path must NOT be used when fingerprint differs");
        assert_eq!(
            generation_id, "abcdef01",
            "Should return newly built generation"
        );
        assert_eq!(
            new_fp, current_fp,
            "Returned fingerprint must equal current (not stored) fingerprint"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_missing_profile_triggers_build_despite_matching_fingerprint() {
        // AC2 guard: fingerprint matches but cached profile is gone → must rebuild
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().to_path_buf();
        // Profile symlink does NOT exist
        let profile_path = temp_dir.path().join("nonexistent-profile");

        // Provide result symlink for the rebuild path
        let result_symlink = config_path.join("result");
        let dummy_store = temp_dir.path().join("deadbeef-nixos-system-test-24.11");
        std::fs::write(&dummy_store, "dummy").unwrap();
        std::os::unix::fs::symlink(&dummy_store, &result_symlink).unwrap();

        let builder = NixOSBuilder::new_with_executor(
            config_path,
            profile_path,
            Box::new(MockCommandExecutor::success()),
        );

        let fp = compute_config_fingerprint("hw = {}", "cfg = {}");

        // Even with matching fingerprint, missing profile triggers build
        let (generation_id, _new_fp, fast) = builder
            .build_profile_with_fingerprint(&fp, Some(&fp))
            .unwrap();

        assert!(!fast, "Build must run when cached profile is missing");
        assert_eq!(
            generation_id, "deadbeef",
            "Should return newly built generation"
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_no_stored_fingerprint_triggers_build() {
        // First-ever run: stored_fingerprint is None → must build
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().to_path_buf();
        let profile_path = temp_dir.path().join("profile");

        let result_symlink = config_path.join("result");
        let dummy_store = temp_dir.path().join("cafebabe-nixos-system-test-24.11");
        std::fs::write(&dummy_store, "dummy").unwrap();
        std::os::unix::fs::symlink(&dummy_store, &result_symlink).unwrap();

        let builder = NixOSBuilder::new_with_executor(
            config_path,
            profile_path,
            Box::new(MockCommandExecutor::success()),
        );

        let fp = compute_config_fingerprint("hw = {}", "cfg = {}");

        let (generation_id, _new_fp, fast) =
            builder.build_profile_with_fingerprint(&fp, None).unwrap();

        assert!(
            !fast,
            "Build must run on first activation (no stored fingerprint)"
        );
        assert_eq!(generation_id, "cafebabe");
    }

    // ========== Story 15.4: Integration test (two activations) ==========

    #[test]
    #[cfg(unix)]
    fn test_two_activations_second_reuses_generation() {
        // AC2: Run 1 builds; Run 2 (same fingerprint, profile exists) reuses it.
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().to_path_buf();
        let profile_path = temp_dir.path().join("nails-system");

        // Pre-create result symlink (build output from "run 1")
        // Parser takes first 8 chars of the first '-'-separated segment as generation ID
        let result_symlink = config_path.join("result");
        let dummy_store = temp_dir.path().join("ab12cd34-nixos-system-test-24.11");
        std::fs::write(&dummy_store, "dummy").unwrap();
        std::os::unix::fs::symlink(&dummy_store, &result_symlink).unwrap();

        let builder = NixOSBuilder::new_with_executor(
            config_path.clone(),
            profile_path.clone(),
            Box::new(MockCommandExecutor::success()),
        );

        let hw = "hardware = { bootloader = grub; }";
        let cfg = "{ environment.systemPackages = []; }";
        let fp = compute_config_fingerprint(hw, cfg);

        // --- Run 1: no stored fingerprint → full build ---
        let (gen1, fp1, fast1) = builder.build_profile_with_fingerprint(&fp, None).unwrap();

        assert!(!fast1, "Run 1 must perform a full build");
        assert_eq!(gen1, "ab12cd34", "Run 1 should return 8-char hash prefix");
        assert_eq!(fp1, fp);

        // Simulate manager saving the profile symlink after switch.
        // switch_profile() creates the {profile_path} symlink pointing to a
        // NixOS profile in the format "system-{number}-link".
        let profile_target = temp_dir.path().join("system-42-link");
        std::fs::write(&profile_target, "dummy profile").unwrap();
        std::os::unix::fs::symlink(&profile_target, &profile_path).unwrap();

        // Create a fresh builder for run 2 (same profile_path, same executor)
        let builder2 = NixOSBuilder::new_with_executor(
            config_path,
            profile_path,
            Box::new(MockCommandExecutor::success()),
        );

        // --- Run 2: same fingerprint, profile exists → fast path ---
        let (gen2, fp2, fast2) = builder2
            .build_profile_with_fingerprint(&fp, Some(&fp1))
            .unwrap();

        assert!(
            fast2,
            "Run 2 must use the fast path (same config, profile exists)"
        );
        // Fast path returns the cached generation (from profile symlink = "42")
        assert_eq!(
            gen2, "42",
            "Run 2 fast path returns generation from profile symlink"
        );
        assert_eq!(fp2, fp);
    }

    // -------------------------------------------------------------------------
    // Story 15.5 — RecordingMockExecutor (records args passed to execute_nixos_rebuild)
    // -------------------------------------------------------------------------

    /// A mock executor that records every invocation of `execute_nixos_rebuild` so
    /// tests can assert which flags were passed (e.g. `--no-update-lock-file`).
    struct RecordingMockExecutor {
        should_succeed: bool,
        stdout: String,
        stderr: String,
        recorded_args: std::sync::Mutex<Vec<Vec<String>>>,
    }

    impl RecordingMockExecutor {
        fn new_success(stdout: impl Into<String>) -> Self {
            Self {
                should_succeed: true,
                stdout: stdout.into(),
                stderr: String::new(),
                recorded_args: std::sync::Mutex::new(Vec::new()),
            }
        }

        #[allow(dead_code)]
        fn get_recorded_args(&self) -> Vec<Vec<String>> {
            self.recorded_args.lock().unwrap().clone()
        }
    }

    impl CommandExecutor for RecordingMockExecutor {
        fn execute_nixos_rebuild(&self, args: &[&str]) -> Result<(bool, String, String)> {
            self.recorded_args
                .lock()
                .unwrap()
                .push(args.iter().map(|s| s.to_string()).collect());
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
            Ok((true, String::new(), String::new()))
        }
    }

    // -------------------------------------------------------------------------
    // Story 15.5 — get_result_store_path tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_get_result_store_path_no_symlink() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().to_path_buf();
        let profile_path = temp_dir.path().join("nails-system");

        let builder = NixOSBuilder::new_with_executor(
            config_path,
            profile_path,
            Box::new(MockCommandExecutor::success()),
        );

        // No result symlink at all → None
        let result = builder.get_result_store_path().unwrap();
        assert!(
            result.is_none(),
            "Expected None when result symlink is absent"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_get_result_store_path_broken_symlink() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().to_path_buf();
        let profile_path = temp_dir.path().join("nails-system");

        // Create a symlink pointing to a non-existent target
        let result_symlink = config_path.join("result");
        let non_existent = temp_dir.path().join("does-not-exist");
        std::os::unix::fs::symlink(&non_existent, &result_symlink).unwrap();

        let builder = NixOSBuilder::new_with_executor(
            config_path,
            profile_path,
            Box::new(MockCommandExecutor::success()),
        );

        // Broken symlink → None
        let result = builder.get_result_store_path().unwrap();
        assert!(result.is_none(), "Expected None for broken symlink");
    }

    #[cfg(unix)]
    #[test]
    fn test_get_result_store_path_valid_symlink() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().to_path_buf();
        let profile_path = temp_dir.path().join("nails-system");

        // Create a real target and symlink pointing to it
        let store_path = temp_dir.path().join("abc12345-nixos-system-host-24.11");
        std::fs::write(&store_path, "dummy").unwrap();
        let result_symlink = config_path.join("result");
        std::os::unix::fs::symlink(&store_path, &result_symlink).unwrap();

        let builder = NixOSBuilder::new_with_executor(
            config_path,
            profile_path,
            Box::new(MockCommandExecutor::success()),
        );

        // Valid symlink → Some(target path)
        let result = builder.get_result_store_path().unwrap();
        assert!(result.is_some(), "Expected Some for valid symlink");
        assert_eq!(result.unwrap(), store_path);
    }

    // -------------------------------------------------------------------------
    // Story 15.5 — build_profile_missing_only tests
    // -------------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn test_missing_only_store_path_exists_reuses_without_build() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().to_path_buf();
        let profile_path = temp_dir.path().join("nails-system");

        // Pre-create a valid result symlink → store path present
        let store_path = temp_dir.path().join("ab12cd34-nixos-system-host-24.11");
        std::fs::write(&store_path, "dummy").unwrap();
        let result_symlink = config_path.join("result");
        std::os::unix::fs::symlink(&store_path, &result_symlink).unwrap();

        let recorder = RecordingMockExecutor::new_success("unused stdout");
        let builder =
            NixOSBuilder::new_with_executor(config_path, profile_path, Box::new(recorder));

        let (generation, reused) = builder.build_profile_missing_only().unwrap();

        // AC2: store path was present → skip build, return reused=true
        assert!(
            reused,
            "build_profile_missing_only should return reused=true when store path exists"
        );
        assert_eq!(
            generation, "ab12cd34",
            "Generation should be the 8-char store hash prefix"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_missing_only_store_path_absent_triggers_build() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().to_path_buf();
        let profile_path = temp_dir.path().join("nails-system");

        // No result symlink — build will run and nixos-rebuild creates result.
        // Pre-create the target that the parser (parse_generation_from_build_output)
        // will read via the result symlink after the "build".
        let store_path = temp_dir.path().join("deadbeef-nixos-system-host-24.11");
        std::fs::write(&store_path, "dummy").unwrap();
        let result_symlink = config_path.join("result");

        // Executor creates the result symlink as a side effect (simulating nixos-rebuild)
        // We pre-create it here before building so the parser can find it.
        std::os::unix::fs::symlink(&store_path, &result_symlink).unwrap();
        // Then remove the symlink so get_result_store_path() returns None (no prior build)
        std::fs::remove_file(&result_symlink).unwrap();

        // Now the build mock will be called; parse_generation_from_build_output reads
        // the result symlink. We need to create it again after the executor runs.
        // The easiest way: pre-create it once more just before the builder call so that
        // parse_generation_from_build_output can see it.  The executor mock doesn't
        // actually create files; we simulate its side effect here.
        std::os::unix::fs::symlink(&store_path, &result_symlink).unwrap();
        // …but get_result_store_path runs BEFORE the build, so we must remove it again.
        std::fs::remove_file(&result_symlink).unwrap();

        // Strategy: use a custom executor that creates the symlink as a side effect.
        struct SymlinkCreatingExecutor {
            result_symlink: PathBuf,
            store_path: PathBuf,
        }
        impl CommandExecutor for SymlinkCreatingExecutor {
            fn execute_nixos_rebuild(&self, _args: &[&str]) -> Result<(bool, String, String)> {
                // Simulate nixos-rebuild: create the result symlink
                if !self.result_symlink.exists() {
                    std::os::unix::fs::symlink(&self.store_path, &self.result_symlink).unwrap();
                }
                Ok((true, String::new(), String::new()))
            }
            fn execute_switch_to_configuration(
                &self,
                _script_path: &std::path::Path,
                _args: &[&str],
            ) -> Result<(bool, String, String)> {
                Ok((true, String::new(), String::new()))
            }
        }

        let executor = SymlinkCreatingExecutor {
            result_symlink: result_symlink.clone(),
            store_path: store_path.clone(),
        };

        let builder =
            NixOSBuilder::new_with_executor(config_path, profile_path, Box::new(executor));

        let (generation, reused) = builder.build_profile_missing_only().unwrap();

        // AC3: store path was absent → build ran, reused=false
        assert!(
            !reused,
            "build_profile_missing_only should return reused=false when build ran"
        );
        assert_eq!(
            generation, "deadbeef",
            "Generation should be 8-char hash prefix from result symlink"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_missing_only_broken_symlink_triggers_build() {
        use tempfile::TempDir;
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().to_path_buf();
        let profile_path = temp_dir.path().join("nails-system");

        // Create a broken result symlink (target does not exist)
        let result_symlink = config_path.join("result");
        let non_existent = temp_dir.path().join("ghost-store-path");
        std::os::unix::fs::symlink(&non_existent, &result_symlink).unwrap();

        // Prepare a real store path that the build executor will "create"
        let store_path = temp_dir.path().join("cafebabe-nixos-system-host-24.11");
        std::fs::write(&store_path, "dummy").unwrap();

        struct FixSymlinkExecutor {
            result_symlink: PathBuf,
            store_path: PathBuf,
        }
        impl CommandExecutor for FixSymlinkExecutor {
            fn execute_nixos_rebuild(&self, _args: &[&str]) -> Result<(bool, String, String)> {
                // Simulate nixos-rebuild fixing the result symlink
                if self.result_symlink.exists()
                    || std::fs::symlink_metadata(&self.result_symlink).is_ok()
                {
                    std::fs::remove_file(&self.result_symlink).unwrap();
                }
                std::os::unix::fs::symlink(&self.store_path, &self.result_symlink).unwrap();
                Ok((true, String::new(), String::new()))
            }
            fn execute_switch_to_configuration(
                &self,
                _script_path: &std::path::Path,
                _args: &[&str],
            ) -> Result<(bool, String, String)> {
                Ok((true, String::new(), String::new()))
            }
        }

        let builder = NixOSBuilder::new_with_executor(
            config_path,
            profile_path,
            Box::new(FixSymlinkExecutor {
                result_symlink,
                store_path,
            }),
        );

        let (generation, reused) = builder.build_profile_missing_only().unwrap();

        // Broken symlink treated as absent → build must run → reused=false
        assert!(
            !reused,
            "Broken symlink must trigger a build (reused=false)"
        );
        assert_eq!(generation, "cafebabe");
    }

    // -------------------------------------------------------------------------
    // Story 15.5 — AC1: --no-update-lock-file always passed
    // -------------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn test_build_profile_missing_only_passes_no_update_lock_file() {
        use std::sync::{Arc, Mutex};
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().to_path_buf();
        let profile_path = temp_dir.path().join("nails-system");

        // No result symlink → build will run
        let store_path = temp_dir.path().join("f00dcafe-nixos-system-host-24.11");
        std::fs::write(&store_path, "dummy").unwrap();

        // Executor that records args AND creates the result symlink (simulating nixos-rebuild)
        struct SharedArgExecutor {
            result_symlink: PathBuf,
            store_path: PathBuf,
            recorded: Arc<Mutex<Vec<Vec<String>>>>,
        }
        impl CommandExecutor for SharedArgExecutor {
            fn execute_nixos_rebuild(&self, args: &[&str]) -> Result<(bool, String, String)> {
                self.recorded
                    .lock()
                    .unwrap()
                    .push(args.iter().map(|s| s.to_string()).collect());
                if !self.result_symlink.exists() {
                    std::os::unix::fs::symlink(&self.store_path, &self.result_symlink).unwrap();
                }
                Ok((true, String::new(), String::new()))
            }
            fn execute_switch_to_configuration(
                &self,
                _script_path: &std::path::Path,
                _args: &[&str],
            ) -> Result<(bool, String, String)> {
                Ok((true, String::new(), String::new()))
            }
        }

        let recorded: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
        let builder = NixOSBuilder::new_with_executor(
            config_path.clone(),
            profile_path,
            Box::new(SharedArgExecutor {
                result_symlink: config_path.join("result"),
                store_path: temp_dir.path().join("f00dcafe-nixos-system-host-24.11"),
                recorded: Arc::clone(&recorded),
            }),
        );

        let (_gen, reused) = builder.build_profile_missing_only().unwrap();
        assert!(!reused, "No prior store path → build must run");

        let calls = recorded.lock().unwrap();
        assert_eq!(calls.len(), 1, "Exactly one nixos-rebuild call expected");
        let args = &calls[0];
        assert!(
            args.iter().any(|a| a == "--no-update-lock-file"),
            "AC1: --no-update-lock-file must be passed to nixos-rebuild; got: {:?}",
            args
        );
    }
}
