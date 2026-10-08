// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The pre-flight checks of the NixOS configuration layer: the composed
//! hidden configuration parses, and the decoy's base configuration names no
//! NAILS path. [`NixOsConfigLayer`](crate::platform::NixOsConfigLayer) hands
//! them to the registry; the framework is `nails_base::preflight`.

pub use nails_base::preflight::{CheckResult, PreFlightCheck, PreFlightRegistry};

pub mod nixos_config;
pub mod suspicious_nails_reference;

pub use nixos_config::NixOSConfigCheck;
pub use suspicious_nails_reference::SuspiciousNailsReferenceCheck;
