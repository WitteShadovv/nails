// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # NAILS platform library
//!
//! Everything host-specific: detection of the running distribution, the
//! `Platform` backends (NixOS, FHS, refused hosts), build-target discovery,
//! the NixOS configuration layer with its pre-flight checks and the hidden
//! NixOS configuration staging, and the resolution of the hidden volume's
//! device-mapper chain.
//!
//! It builds on `nails-base` only, so the session, the verification and the
//! orchestration in `nails-core` all consult one platform seam. The
//! dependency direction is recorded in ADR 0010.

// Unsafe code is denied workspace-wide (see the root Cargo.toml). Test code
// may use it freely; production code opts in per site with a scoped allow.
#![cfg_attr(test, allow(unsafe_code))]

// This crate's unit tests never reach the host, like the base crate's own.
nails_base::unit_test_mode!();

// The foundation modules the code below reaches through `crate::` paths.
use nails_base::{Filesystem, NailsError, Result};
#[cfg(test)]
use nails_base::{RealFilesystem, kernel_fixtures};
use nails_base::{artifacts, constants, error, filesystem, hidden_root, process, runtime_safety};

// Platform seam: host detection and per-platform behaviour (NixOS / FHS / refused).
pub mod platform;

// NixOS profile builder and the hidden NixOS configuration staging.
pub mod nixos;

// Backend chain resolution (the hidden volume's device-mapper stack).
pub mod backend_lock;

// The NixOS configuration layer's pre-flight checks.
pub mod preflight;

pub use nixos::{
    NixOSBuilder, NixOSConfigInfo, NixParser, RealNixParser, ensure_hidden_configuration_module,
    ensure_hidden_hardware_configuration, inject_import_block, parse_check_composed_config,
    prepare_nixos_config_overlay, stage_hidden_config_symlink, stage_hidden_nixos_config,
    verify_base_config_clean,
};
pub use platform::{
    ConfigLayer, HostProfile, HostTarget, NixOsConfigLayer, Platform, PlatformKind, detect,
    detect_platform, discover_host_target, discover_with_platform, platform_for,
};
pub use preflight::{NixOSConfigCheck, SuspiciousNailsReferenceCheck};

#[cfg(test)]
mod tests {
    #[test]
    fn unit_tests_never_reach_the_host() {
        // `unit_test_mode!` marks this binary before the first test, so the
        // base crate's host switches answer as they do in its own unit tests.
        assert!(nails_base::runtime_safety::in_unit_tests());
        assert!(nails_base::runtime_safety::should_skip_host_interaction());
    }
}
