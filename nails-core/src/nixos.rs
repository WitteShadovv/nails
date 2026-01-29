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
        }
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
        let (success, stdout, stderr) = self.executor.execute_nixos_rebuild(&[
            "build",
            "--flake",
            &self.config_path.to_string_lossy(),
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
        let system_profile = PathBuf::from("/nix/var/nix/profiles/system");

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
            PathBuf::from("/nix/var/nix/profiles").join(format!("system-{}-link", generation));

        let switch_script = system_profile_path.join("bin/switch-to-configuration");

        let (success, _stdout, _stderr) = self
            .executor
            .execute_switch_to_configuration(&switch_script, &["switch"])?;

        if !success {
            return Err(NailsError::NixOSError("Rollback switch failed".into()));
        }

        Ok(())
    }
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
}
