// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Forensic validation system for NAILS
//!
//! The verify module provides forensic cleanliness validation by checking for:
//! - Active overlay mounts
//! - Artifact files in suspicious locations
//! - Running nails-related processes
//! - Memory persistence risks (swap enabled)
//! - Deep scans of temporary directories and logs
//!
//! # Example
//!
//! ```rust
//! use nails_core::{Verifier, VerifyStatus, MockFilesystem};
//!
//! let fs = MockFilesystem::new();
//! let verifier = Verifier::new(fs);
//! let result = verifier.run(false)?; // Standard scan
//!
//! match result.status {
//!     VerifyStatus::Secure => println!("System is clean"),
//!     VerifyStatus::Warning => println!("Potential issues found"),
//!     VerifyStatus::Critical => println!("Critical artifacts detected"),
//! }
//! # Ok::<(), nails_core::NailsError>(())
//! ```

mod residue_report;
mod types;
mod verifier;

#[cfg(test)]
mod tests;

// Re-export public types
pub use residue_report::{
    RESIDUE_REPORT_DIR, RESIDUE_REPORT_SCHEMA_VERSION, ResidueReport, ResidueReportSummary,
    write_activation_residue_report,
};
pub use types::{Finding, ScanDepth, Severity, StateFileStatus, VerifyResult, VerifyStatus};
pub use verifier::Verifier;
