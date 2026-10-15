// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! # NAILS forensics library
//!
//! Everything that looks for traces rather than making or removing them:
//! `verify` (live and offline residue scans, the examiner's view, the
//! platform drift scanners, the residue report), the read-only raw-device,
//! layout and tree readers (`forensic`), the residue catalog that ties every
//! trace class to its probes, docs and VM test (`residue_catalog`, with its
//! pre-flight check), and the `nails rehearse` canary self-test
//! (`rehearse`).
//!
//! It reads the session's probes but never drives the session or the
//! teardown mechanics; `tests/boundary.rs` holds it to that.

// Unsafe code is denied workspace-wide (see the root Cargo.toml). Test code
// may use it freely; production code opts in per site with a scoped allow.
#![cfg_attr(test, allow(unsafe_code))]

// This crate's unit tests never reach the host, like the base crate's own.
nails_base::unit_test_mode!();

// The foundation, platform and session modules the code below reaches
// through `crate::` paths.
use nails_base::{
    Filesystem, HiddenRoot, NailsError, RealFilesystem, Result, RuntimeEnv, SystemState, TargetUser,
};
#[cfg(test)]
use nails_base::{MockFilesystem, kernel_fixtures, test_path, test_support};
use nails_base::{artifacts, config, filesystem, hidden_root, notification, process, state};
use nails_platform::platform;
use nails_session::{session, sleep_guard};

// Read-only raw-device, layout and tree readers for the forensic self-checks
pub mod forensic;

// The residue catalog: every trace class, its probes, docs and VM test.
pub mod residue_catalog;

// The pre-flight check over the residue catalog's probes.
pub mod preflight;

// `nails rehearse`: the canary self-test.
pub mod rehearse;

// Forensic validation system
pub mod verify;

pub use verify::{
    ExaminerFinding, ExaminerGroup, ExaminerOptions, ExaminerReport, Finding, RESIDUE_REPORT_DIR,
    RESIDUE_REPORT_SCHEMA_VERSION, ResidueReport, ResidueReportSummary, ScanDepth, Severity,
    StateFileStatus, Verifier, VerifyResult, VerifyStatus, write_activation_residue_report,
};

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
