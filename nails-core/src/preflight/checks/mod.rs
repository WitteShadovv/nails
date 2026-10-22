// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pre-flight check implementations
//!
//! This module contains all concrete pre-flight check implementations.
//! Each check validates a specific aspect of the system before activation.

pub mod backend_detect;
pub mod backend_entries;
pub mod binary_location;
pub mod decoy_posture;
pub mod dma_protection;
pub mod hidden_volume;
pub mod host_tools;
pub mod incremental_history_flush;
pub mod inherited_autostart;
pub mod journald_storage;
pub mod memory_wipe;
pub mod mount_namespace;
pub mod nixos_build_target;
pub mod offline_update;
pub mod platform;
pub mod sleep_policy;
pub mod space;
pub mod state;
pub mod storage_readiness;
pub mod symlink_support;
pub mod systemd_conf;
pub mod upper_fs_probe;

// Re-exports for convenient access
pub use backend_detect::BackendDetectCheck;
pub use backend_detect::CryptsetupArgon2idCheck;
pub use backend_entries::BackendEntriesCheck;
pub use binary_location::BinaryLocationCheck;
pub use decoy_posture::DecoyPersistenceCheck;
pub use dma_protection::DmaProtectionCheck;
pub use hidden_volume::HiddenVolumeCheck;
pub use host_tools::HostToolsCheck;
pub use incremental_history_flush::IncrementalHistoryFlushCheck;
pub use inherited_autostart::InheritedAutostartCheck;
pub use journald_storage::{JournaldStorage, parse_journald_storage};
pub use memory_wipe::{InitOnFree, MemoryWipeCheck, parse_init_on_free};
pub use mount_namespace::MountNamespaceCheck;
pub use nixos_build_target::NixOSBuildTargetCheck;
pub use offline_update::OfflineUpdateCheck;
pub use platform::PlatformCheck;
pub use sleep_policy::SleepPolicyCheck;
pub use space::{OverlayDirs, SpaceCheck};
pub use state::StateCheck;
pub use storage_readiness::StorageReadinessCheck;
pub use symlink_support::SymlinkSupportCheck;
pub use upper_fs_probe::UpperFsCapabilityCheck;

// The NixOS configuration layer's checks live with the layer.
pub use nails_platform::preflight::{
    NixOSConfigCheck, SuspiciousNailsReferenceCheck, nixos_config, suspicious_nails_reference,
};

// The residue catalog's check lives with the catalog.
pub use nails_forensics::preflight::{ResidueCatalogCheck, residue_catalog};
