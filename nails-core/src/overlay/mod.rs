//! Overlay filesystem operations for extended overlay strategy
//!
//! This module provides operations for mounting and unmounting ephemeral overlays
//! with tmpfs-backed upper layers (Story 4.11) and the universal overlay mounting
//! strategy with intelligent process management (Story 4.15).
//!
//! # Forensic Rationale (Thesis Section 4.3.6)
//!
//! The extended overlay strategy provides defense-in-depth against forensic analysis:
//! - **Persistent overlays** (home/etc): Data on hidden encrypted storage
//! - **Ephemeral overlays** (var/tmp): Data in RAM, destroyed on unmount
//! - Different threat models for different data types
//!
//! # Architecture
//!
//! The module is organized into focused submodules:
//!
//! - [`types`] - Core types (OverlayStrategyOptions, MountMethod, MountResult)
//! - [`mount_info`] - Mount tracking structures (EphemeralMountInfo, PivotMountInfo)
//! - [`ephemeral`] - Ephemeral overlay operations with tmpfs backing
//! - [`pivot`] - Pivot mount strategy for active directories
//! - [`strategy`] - Universal 4-phase mounting algorithm
//!
//! # Universal Overlay Mounting Strategy
//!
//! The [`mount_overlay_with_strategy`] function implements a 4-phase algorithm:
//!
//! 1. **Detect** - Find processes using target directory
//! 2. **Classify & Restart** - Automatically restart safe processes, prompt for risky ones
//! 3. **Direct Mount** - Attempt optimal direct overlay mount
//! 4. **Pivot Fallback** - Use pivot mount as last resort (with user consent)
//!
//! See `/docs/architecture/universal-overlay-mounting-strategy.md` for details.
//!
//! # Example
//!
//! ```rust
//! use nails_core::overlay::{mount_ephemeral_overlay, EphemeralMountInfo};
//! use nails_core::config::EphemeralOverlayDir;
//! use nails_core::filesystem::MockFilesystem;
//! use std::path::{Path, PathBuf};
//!
//! let fs = MockFilesystem::new();
//! let config = EphemeralOverlayDir {
//!     path: PathBuf::from("/var"),
//!     tmpfs_upper_size: "1G".to_string(),
//!     tmpfs_work_size: "512M".to_string(),
//! };
//!
//! // Set up mock filesystem state
//! fs.mock_set_path_exists("/var", true);
//! fs.mock_set_directory_creatable("/run/nails/var-upper", true);
//! fs.mock_set_directory_creatable("/run/nails/var-work", true);
//!
//! let result = mount_ephemeral_overlay(&fs, &config, Path::new("/var"));
//! assert!(result.is_ok());
//! ```

// Module declarations
pub mod bind_sync;
mod ephemeral;
mod mount_info;
pub mod opaque;
mod pivot;
mod strategy;
mod types;

#[cfg(test)]
mod tests;

// Re-export public API from submodules

// Core types
pub use types::{MountMethod, MountResult, OverlayStrategyOptions};

// Mount information structures
pub use mount_info::{EphemeralMountInfo, PivotMountInfo};

// Ephemeral overlay operations
pub use ephemeral::{mount_ephemeral_overlay, unmount_ephemeral_overlay};

// Pivot mount operations
pub use pivot::{
    pivot_ephemeral_mount, pivot_overlay_mount, snapshot_pivot_overlay_mount, unmount_pivot_overlay,
};

// Universal mounting strategy
pub use strategy::mount_overlay_with_strategy;

// Constants
pub use pivot::PIVOT_STAGING_BASE;
pub use strategy::OVERLAY_INCOMPATIBLE_FSTYPES;
