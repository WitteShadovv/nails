// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # Deactivation report types
//!
//! Shared result types for NAILS deactivation. The deactivation sequence
//! itself — state transitions, artifact cleanup, overlay unmounting and
//! StateGuard-based rollback — lives in [`crate::manager::deactivation`], which
//! runs `DeactivationOrchestrator` over a borrowed [`crate::NailsManager`]. This
//! module keeps only the report types that the sequence produces, so both the
//! manager and its callers can depend on them without pulling in the whole
//! orchestration layer.
//!
//! # Example
//!
//! ```rust,ignore
//! use nails_core::{DeactivationOrchestrator, DeactivationReport, CleanupConfig};
//!
//! let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());
//!
//! match orchestrator.run(&mut manager) {
//!     Ok(report) => println!("{}", report),
//!     Err(e) => eprintln!("Deactivation failed: {}", e),
//! }
//! ```

mod report;
pub(crate) mod test_gate;

#[cfg(test)]
mod tests;

// Public exports. The deactivation sequence itself now lives in the manager
// module (`manager::deactivation`); this module keeps only the shared report
// types and the test gate.
pub use report::{DeactivationReport, PostUnmountCleanupReport};
