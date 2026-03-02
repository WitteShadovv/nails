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

use std::path::PathBuf;

// Module declarations
mod builder;
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
}

#[cfg(test)]
mod tests;
