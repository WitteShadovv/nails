// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Cleanup management for NAILS deactivation
//!
//! This module provides the [`CleanupManager`] which coordinates cleanup operations
//! for shell history, temporary files, and log files during deactivation.
//!
//! The cleanup system supports two execution modes:
//! - **Thorough**: Complete cleanup with optional verification (normal deactivation)
//! - **Fast**: Speed-priority cleanup without verification (emergency deactivation)
//!
//! # Submodules
//!
//! - [`history`] - Shell history cleanup for bash, zsh, fish
//! - [`temp_files`] - Temporary files cleanup
//! - [`logs`] - Log files cleanup
//!
//! # Example
//!
//! ```rust,ignore
//! use nails_core::{CleanupManager, CleanupConfig, CleanupMode, MockFilesystem};
//!
//! let fs = MockFilesystem::new();
//! let config = CleanupConfig::default();
//! let mode = CleanupMode::Thorough { verify_cleanup: true };
//!
//! let manager = CleanupManager::new(fs, config, mode);
//! let report = manager.cleanup()?;
//! println!("{}", report);
//! ```

// Submodules
pub mod canary;
pub mod history;
pub mod history_files;
pub mod logs;
pub mod temp_files;

// Internal modules
mod manager;
pub(crate) mod patterns;
mod types;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub mod test_utils;

// Public re-exports
pub use canary::{CanaryConfig, CanaryFinding, CanaryScanResult, CanaryScanner};
pub use history::{
    ShellType, get_extended_history_files_for_home, get_extended_history_files_for_homes,
    history_cleanup_homes,
};
pub use manager::CleanupManager;
pub use types::{CleanupConfig, CleanupMode, CleanupReport};
