// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Pre-flight validation for NAILS.
//!
//! The framework (the [`PreFlightCheck`] trait, [`CheckResult`] and the
//! [`PreFlightRegistry`]) and the swap check are in `nails_base::preflight`
//! and re-exported here; this module adds the checks that need the platform,
//! the session or the residue catalog. The registry activation and `check`
//! run is assembled by [`build_registry`](crate::manager::build_registry).

pub use nails_base::preflight::*;

pub mod checks;

// Re-export all checks for convenience
pub use checks::*;
