// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The documented exit-code table for the CLI.
//!
//! Every command handler returns an [`ExitStatus`]; `main` turns the one the
//! dispatcher returns into a [`std::process::ExitCode`]. Keeping the mapping in
//! a single enum means the user-facing exit table and the process exit code can
//! never drift apart, and the numbers are stable enough for scripts to branch
//! on.

use std::process::ExitCode;

/// A result class the process exits with.
///
/// The numeric codes are a stable contract: 0 means success, 1 a plain failure,
/// and the rest name a specific refusal or outcome so a caller can tell them
/// apart without parsing text. Verify maps its own severities onto the 10/11
/// range so a warning and a critical finding are distinguishable from an
/// ordinary failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// The command produced its result.
    Ok,
    /// The command ran but the operation failed, or it stopped on an internal
    /// error (a panic, which the CLI reports as the error `internal_error`).
    Failed,
    /// The command line was used incorrectly (clap owns most of these).
    Usage,
    /// The configuration file or runtime environment was unusable.
    Config,
    /// A pre-flight check refused the operation.
    PreflightRefused,
    /// The operation needs privileges (or a safe environment) it did not have.
    NeedsRoot,
    /// The on-disk state could not be trusted, so the command refused to act.
    InvalidState,
    /// A degraded or interrupted session (`nails status` names the fix, usually
    /// `nails recover`), or a cleanup that `recover` or `emergency` could not
    /// finish (a mount stayed below `/run/nextroot`, or only the kernel could be
    /// asked to power off).
    DegradedReboot,
    /// The host is not one NAILS can operate on (ostree / image-based, or a
    /// non-systemd PID 1), so the command refused before touching any state.
    Unsupported,
    /// The operation completed but with a warning the caller should act on: an
    /// activation whose soft-reboot was enqueued with entry warnings, or a
    /// rehearsal scan that could not read every target or whose storage hides
    /// data from a raw scan. Distinct from success so a script can tell a clean
    /// run from one that needs a look: the envelope's `ok` is true for both, so
    /// a scan that is not clean is told apart by this code, never by `ok`.
    SuccessWithWarnings,
    /// `verify` found warnings.
    VerifyWarning,
    /// `verify` found critical artifacts.
    VerifyCritical,
    /// The operation was cancelled: the operator declined a confirmation
    /// prompt, or a signal (SIGINT/SIGTERM) stopped it at a prompt, during an
    /// emergency's countdown, or in an activation before its point of no
    /// return; under `--json`, a signal also stops a command that only reads
    /// (`init` and the writing `rehearse` steps too, partway through). A
    /// teardown that has begun runs to its end and does not report this. The
    /// code is 130, the conventional "terminated by Ctrl-C" value (128 +
    /// SIGINT), so a caller can tell a deliberate cancellation apart from an
    /// ordinary failure. A declined prompt or a stopped countdown changed
    /// nothing; an entry in progress is rolled back and the state returned to
    /// its previous value.
    Cancelled,
}

impl ExitStatus {
    /// The numeric exit code for this status.
    pub fn code(self) -> u8 {
        match self {
            ExitStatus::Ok => 0,
            ExitStatus::Failed => 1,
            ExitStatus::Usage => 2,
            ExitStatus::Config => 3,
            ExitStatus::PreflightRefused => 4,
            ExitStatus::NeedsRoot => 5,
            ExitStatus::InvalidState => 6,
            ExitStatus::DegradedReboot => 7,
            ExitStatus::Unsupported => 8,
            ExitStatus::SuccessWithWarnings => 9,
            ExitStatus::VerifyWarning => 10,
            ExitStatus::VerifyCritical => 11,
            ExitStatus::Cancelled => 130,
        }
    }

    /// The process exit code `main` returns.
    pub fn to_exit_code(self) -> ExitCode {
        ExitCode::from(self.code())
    }

    /// Whether a machine-readable envelope reports this outcome as `ok`.
    ///
    /// True only for a plain success (code 0) and a success with a warning
    /// (code 9); every other code is a failure a script branches on. This is
    /// the one rule the `ok` field of the JSON envelope follows, so the exit
    /// code and `ok` can never disagree.
    pub fn is_success(self) -> bool {
        matches!(self.code(), 0 | 9)
    }
}

#[cfg(test)]
mod tests {
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
}
