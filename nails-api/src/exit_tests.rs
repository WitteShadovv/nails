// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the exit-code table: each status's process code and whether
//! it reads as ok.

use super::*;

#[test]
fn only_success_and_success_with_warnings_report_ok() {
    assert!(ExitStatus::Ok.is_success());
    assert!(ExitStatus::SuccessWithWarnings.is_success());
    for status in [
        ExitStatus::Failed,
        ExitStatus::Usage,
        ExitStatus::Config,
        ExitStatus::PreflightRefused,
        ExitStatus::NeedsRoot,
        ExitStatus::InvalidState,
        ExitStatus::DegradedReboot,
        ExitStatus::Unsupported,
        ExitStatus::VerifyWarning,
        ExitStatus::VerifyCritical,
        ExitStatus::Cancelled,
    ] {
        assert!(!status.is_success(), "{status:?} must not be ok");
    }
}

#[test]
fn codes_match_the_documented_table() {
    assert_eq!(ExitStatus::Ok.code(), 0);
    assert_eq!(ExitStatus::Failed.code(), 1);
    assert_eq!(ExitStatus::Usage.code(), 2);
    assert_eq!(ExitStatus::Config.code(), 3);
    assert_eq!(ExitStatus::PreflightRefused.code(), 4);
    assert_eq!(ExitStatus::NeedsRoot.code(), 5);
    assert_eq!(ExitStatus::InvalidState.code(), 6);
    assert_eq!(ExitStatus::DegradedReboot.code(), 7);
    assert_eq!(ExitStatus::Unsupported.code(), 8);
    assert_eq!(ExitStatus::SuccessWithWarnings.code(), 9);
    assert_eq!(ExitStatus::VerifyWarning.code(), 10);
    assert_eq!(ExitStatus::VerifyCritical.code(), 11);
    assert_eq!(ExitStatus::Cancelled.code(), 130);
}

#[test]
fn to_exit_code_matches_the_documented_table() {
    // `ExitCode` provides `PartialEq`, so compare the process code against
    // one built from the documented number for every variant. This pins the
    // status -> process-code mapping end to end, so a body that ignored the
    // status (e.g. always returning the `SUCCESS` default) cannot pass.
    assert_eq!(ExitStatus::Ok.to_exit_code(), ExitCode::from(0));
    assert_eq!(ExitStatus::Failed.to_exit_code(), ExitCode::from(1));
    assert_eq!(ExitStatus::Usage.to_exit_code(), ExitCode::from(2));
    assert_eq!(ExitStatus::Config.to_exit_code(), ExitCode::from(3));
    assert_eq!(
        ExitStatus::PreflightRefused.to_exit_code(),
        ExitCode::from(4)
    );
    assert_eq!(ExitStatus::NeedsRoot.to_exit_code(), ExitCode::from(5));
    assert_eq!(ExitStatus::InvalidState.to_exit_code(), ExitCode::from(6));
    assert_eq!(ExitStatus::DegradedReboot.to_exit_code(), ExitCode::from(7));
    assert_eq!(ExitStatus::Unsupported.to_exit_code(), ExitCode::from(8));
    assert_eq!(
        ExitStatus::SuccessWithWarnings.to_exit_code(),
        ExitCode::from(9)
    );
    assert_eq!(ExitStatus::VerifyWarning.to_exit_code(), ExitCode::from(10));
    assert_eq!(
        ExitStatus::VerifyCritical.to_exit_code(),
        ExitCode::from(11)
    );
    assert_eq!(ExitStatus::Cancelled.to_exit_code(), ExitCode::from(130));
}
