// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Configuration management for NAILS
//!
//! Configuration lives in a strict TOML file, `nails.toml`, discovered next to
//! the binary (see [`discover_config_path`]). Every key is optional; unknown
//! keys at any level are rejected so a typo can never silently fall back to a
//! default. [`LoadedConfig`] records where each effective value came from, and
//! [`ConfigBuilder`] constructs a [`Config`] programmatically. Both reject an
//! unsafe path (see [`Config::validate_paths`] and [`PathProblem`]).
//!
//! # Example
//!
//! ```rust
//! use nails_base::ConfigBuilder;
//! use std::path::PathBuf;
//!
//! let config = ConfigBuilder::new()
//!     .hidden_volume_root(PathBuf::from("/mnt/hidden-volume"))
//!     .minimum_space_mb(1000)
//!     .build()
//!     .expect("Failed to build config");
//! ```

pub mod backend_watch;
pub mod persona;

// Sub-modules for config implementation
mod builder;
mod defaults;
mod effective;
mod loading;
mod overrides;
mod suggest;
mod types;
mod validation;

// Test-support utilities: available to this crate's tests and, via the
// `test-support` feature, to downstream test code.
#[cfg(any(test, feature = "test-support"))]
mod testing;

// Re-exports for public API - color types
pub use backend_watch::BackendWatchConfig;
pub use persona::{PersonaConfig, PersonaMode};

// Re-exports for public API - core types
pub use types::{
    CONFIG_KEYS, CliOverrides, Config, DEFAULT_HIDDEN_VOLUME_ROOT, SleepPolicyConfig,
    SleepPolicyMode, get_default_hidden_volume_root,
};

// Re-exports for public API - builder
pub use builder::ConfigBuilder;

// Re-exports for public API - loading
pub use effective::{LoadedConfig, ValueSource};
pub use loading::{CONFIG_DIR_NAME, CONFIG_FILE_NAME, discover_config_path};

// Re-exports for public API - defaults
pub use defaults::derive_hidden_volume_root;

// Re-exports for public API - path validation
pub use validation::PathProblem;

// Tests module
#[cfg(test)]
mod tests;
