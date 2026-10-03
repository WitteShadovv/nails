//! Pre-flight check implementations
//!
//! This module contains all concrete pre-flight check implementations.
//! Each check validates a specific aspect of the system before activation.

pub mod backend_detect;
pub mod binary_location;
pub mod decoy_posture;
pub mod hidden_volume;
pub mod host_tools;
pub mod inherited_autostart;
pub mod journald_storage;
pub mod mount_namespace;
pub mod nixos_build_target;
pub mod nixos_config;
pub mod overlay_compatibility;
pub mod overlay_targets;
pub mod snapshot_memory;
pub mod space;
pub mod state;
pub mod storage_readiness;
pub mod suspicious_nails_reference;
pub mod swap;
pub mod symlink_support;
pub mod upper_fs_probe;
pub mod writable_trees;

// Re-exports for convenient access
pub use backend_detect::BackendDetectCheck;
pub use binary_location::BinaryLocationCheck;
pub use decoy_posture::DecoyPersistenceCheck;
pub use hidden_volume::HiddenVolumeCheck;
pub use host_tools::HostToolsCheck;
pub use inherited_autostart::InheritedAutostartCheck;
pub use journald_storage::{JournaldStorage, parse_journald_storage};
pub use mount_namespace::MountNamespaceCheck;
pub use nixos_build_target::NixOSBuildTargetCheck;
pub use nixos_config::NixOSConfigCheck;
pub use overlay_compatibility::OverlayCompatibilityCheck;
pub use overlay_targets::OverlayTargetsCheck;
pub(crate) use overlay_targets::ensure_targets_clear;
pub use snapshot_memory::SnapshotMemoryCheck;
pub use space::{OverlayDirs, SpaceCheck};
pub use state::StateCheck;
pub use storage_readiness::StorageReadinessCheck;
pub use suspicious_nails_reference::SuspiciousNailsReferenceCheck;
pub use swap::{SwapCheck, SwapPosture, SwapSeverity, classify_swap};
pub use symlink_support::SymlinkSupportCheck;
pub use upper_fs_probe::UpperFsCapabilityCheck;
pub use writable_trees::WritableTreesCheck;
