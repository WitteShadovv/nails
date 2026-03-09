//! Pre-flight check implementations
//!
//! This module contains all concrete pre-flight check implementations.
//! Each check validates a specific aspect of the system before activation.

pub mod hidden_volume;
pub mod nixos_build_target;
pub mod nixos_config;
pub mod overlay_compatibility;
pub mod space;
pub mod state;
pub mod storage_readiness;
pub mod swap;
pub mod symlink_support;

// Re-exports for convenient access
pub use hidden_volume::HiddenVolumeCheck;
pub use nixos_build_target::NixOSBuildTargetCheck;
pub use nixos_config::NixOSConfigCheck;
pub use overlay_compatibility::OverlayCompatibilityCheck;
pub use space::{OverlayDirs, SpaceCheck};
pub use state::StateCheck;
pub use storage_readiness::StorageReadinessCheck;
pub use swap::SwapCheck;
pub use symlink_support::SymlinkSupportCheck;
