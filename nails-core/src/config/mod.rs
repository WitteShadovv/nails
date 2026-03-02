//! Configuration management for NAILS
//!
//! This module provides configuration structures for the NAILS system,
//! including the `Config` struct with user-configurable options and
//! `ConfigBuilder` for fluent API construction with validation.
//!
//! # Example
//!
//! ```rust
//! use nails_core::config::DEFAULT_HIDDEN_VOLUME_ROOT;
//! use nails_core::ConfigBuilder;
//! use std::path::PathBuf;
//!
//! let config = ConfigBuilder::new()
//!     .hidden_volume_path(PathBuf::from(DEFAULT_HIDDEN_VOLUME_ROOT))
//!     .clear_history(false)
//!     .default_verbosity("debug")
//!     .build()
//!     .expect("Failed to build config");
//! ```

// Sub-modules for color configuration
pub mod colors;
pub mod ephemeral;
pub mod overlay;

// Sub-modules for config implementation (Phase 10B refactoring)
mod builder;
mod defaults;
mod dynamic;
mod loading;
mod overrides;
mod testing;
mod types;

// Re-exports for public API - color types
pub use colors::{ColorProfile, ColorSchemeConfig, DecoyProfile};
pub use ephemeral::EphemeralOverlayDir;
pub use overlay::{ExtendedOverlayConfig, OverlayConfig, OverlayMode};

// Re-exports for public API - core types
pub use types::{CliOverrides, Config, DEFAULT_HIDDEN_VOLUME_ROOT, DEFAULT_OVERLAY_EXCLUSIONS};

// Re-exports for public API - builder
pub use builder::ConfigBuilder;

// Re-exports for public API - loading
pub use loading::discover_config_path;

// Re-exports for public API - defaults
pub use defaults::derive_hidden_volume_root;

// Tests module
#[cfg(test)]
mod tests;
