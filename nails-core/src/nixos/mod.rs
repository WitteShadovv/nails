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

use std::path::{Path, PathBuf};

// Module declarations
mod builder;
pub mod command;
pub mod config;
pub mod fingerprint;

// Re-exports for public API
pub use command::{CommandExecutor, RealCommandExecutor};
pub use config::{
    NixOSConfigInfo, contains_nails_import, ensure_hidden_configuration_module,
    ensure_hidden_hardware_configuration, ensure_nails_import_block, inject_import_block,
    prepare_nixos_config_overlay, stage_hidden_config_symlink, verify_base_config_clean,
};
pub use fingerprint::compute_config_fingerprint;

// Internal imports
use command::CommandExecutor as CommandExecutorTrait;
use command::RealCommandExecutor as RealCommandExecutorImpl;
#[cfg(test)]
pub(crate) use command::{FlakePreflightSummary, local_flake_dir};
pub(crate) use command::{
    classify_nixos_failure_category, format_classified_nixos_failure, resolve_local_flake_dir,
    split_flake_ref,
};

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
    /// Optional full flake reference (e.g., "/etc/nixos#amnesia-virtualbox")
    ///
    /// When set, this is used as the `--flake` argument to `nixos-rebuild`
    /// instead of `config_path`. This allows specifying a custom attribute
    /// name when the flake uses a different name than the hostname.
    pub(crate) flake_ref: Option<String>,
}

impl NixOSBuilder {
    pub(crate) fn should_clear_nix_path(&self) -> bool {
        self.is_flake()
    }

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
            flake_ref: None,
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
            flake_ref: None,
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
            flake_ref: None,
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
            flake_ref: None,
        }
    }

    pub fn is_flake(&self) -> bool {
        matches!(self.build_mode, NixOSBuildMode::Flake)
    }

    /// Create a new NixOSBuilder from a full flake reference string
    ///
    /// Parses the flake reference to extract the directory path and optional
    /// attribute fragment. If the reference contains `#`, the part before it
    /// is used as the config directory path and the full ref is stored for
    /// use as the `--flake` argument. If no `#` is present, behaves like `new()`.
    ///
    /// # Arguments
    ///
    /// - `flake_ref`: Full flake reference (e.g., "/etc/nixos#amnesia-virtualbox" or "/etc/nixos")
    /// - `profile_path`: Path to profile symlink for caching
    ///
    /// # Example
    ///
    /// ```
    /// use nails_core::nixos::NixOSBuilder;
    ///
    /// let builder = NixOSBuilder::new_with_flake_ref(
    ///     "/etc/nixos#amnesia-virtualbox".to_string(),
    ///     std::path::PathBuf::from("/nix/var/nix/profiles/nails-system"),
    /// );
    /// ```
    pub fn new_with_flake_ref(flake_ref: String, profile_path: PathBuf) -> Self {
        if let Some(hash_pos) = flake_ref.find('#') {
            let dir_part = &flake_ref[..hash_pos];
            Self {
                config_path: PathBuf::from(dir_part),
                profile_path,
                executor: Box::new(RealCommandExecutorImpl),
                build_mode: NixOSBuildMode::Flake,
                flake_ref: Some(flake_ref),
            }
        } else {
            Self {
                config_path: PathBuf::from(&flake_ref),
                profile_path,
                executor: Box::new(RealCommandExecutorImpl),
                build_mode: NixOSBuildMode::Flake,
                flake_ref: None,
            }
        }
    }

    /// Return the effective `--flake` argument for `nixos-rebuild`
    ///
    /// If a full flake reference with `#` attribute was provided, returns that.
    /// Otherwise, falls back to the config directory path.
    pub fn effective_flake_arg(&self) -> String {
        if let Some(ref flake_ref) = self.flake_ref {
            flake_ref.clone()
        } else {
            self.config_path.to_string_lossy().into_owned()
        }
    }

    fn preflight_flake_refs(&self) -> (String, Option<String>) {
        let flake_arg = self.effective_flake_arg();
        let (base_ref, fragment) = split_flake_ref(&flake_arg);
        (base_ref.to_string(), fragment.map(str::to_string))
    }

    pub(crate) fn flake_dir(&self) -> Option<&Path> {
        if self.is_flake() {
            Some(&self.config_path)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests;
