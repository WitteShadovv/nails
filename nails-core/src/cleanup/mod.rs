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
//! - [`history`] - Shell history cleanup for bash, zsh, fish (Story 5.2)
//! - [`temp_files`] - Temporary files cleanup (Story 5.3)
//! - [`logs`] - Log files cleanup (Story 5.4)
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
mod types;

#[cfg(test)]
mod tests;

#[cfg(test)]
pub mod test_utils;

// Public re-exports
pub use canary::{CanaryConfig, CanaryFinding, CanaryScanResult, CanaryScanner};
pub use history::{ShellType, get_extended_history_files};
pub use manager::CleanupManager;
pub use types::{CleanupConfig, CleanupMode, CleanupReport};
