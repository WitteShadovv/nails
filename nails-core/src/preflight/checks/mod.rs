//! Pre-flight check implementations
//!
//! This module contains all concrete pre-flight check implementations.
//! Each check validates a specific aspect of the system before activation.

pub mod backend_detect;
pub mod hidden_volume;
pub mod mount_namespace;
pub mod nixos_build_target;
pub mod nixos_config;
pub mod overlay_compatibility;
pub mod overlay_targets;
pub mod space;
pub mod state;
pub mod storage_readiness;
pub mod suspicious_nails_reference;
pub mod swap;
pub mod symlink_support;
pub mod upper_fs_probe;

// Re-exports for convenient access
pub use backend_detect::BackendDetectCheck;
pub use hidden_volume::HiddenVolumeCheck;
pub use mount_namespace::MountNamespaceCheck;
pub use nixos_build_target::NixOSBuildTargetCheck;
pub use nixos_config::NixOSConfigCheck;
pub use overlay_compatibility::OverlayCompatibilityCheck;
pub use overlay_targets::OverlayTargetsCheck;
pub(crate) use overlay_targets::ensure_targets_clear;
pub use space::{OverlayDirs, SpaceCheck};
pub use state::StateCheck;
pub use storage_readiness::StorageReadinessCheck;
pub use suspicious_nails_reference::SuspiciousNailsReferenceCheck;
pub use swap::SwapCheck;
pub use symlink_support::SymlinkSupportCheck;
pub use upper_fs_probe::UpperFsCapabilityCheck;
