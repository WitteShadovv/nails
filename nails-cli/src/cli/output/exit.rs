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
    /// The command ran but the operation failed.
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
    /// The system is degraded or a reboot is required to finish.
    DegradedReboot,
    /// The host is not one NAILS can operate on (ostree / image-based, or a
    /// non-systemd PID 1), so the command refused before touching any state.
    Unsupported,
    /// The operation completed but with a warning the caller should act on — for
    /// `activate`/`reapply`, the overlays are up but the hidden NixOS
    /// configuration was not applied. Distinct from success so a script can tell a
    /// clean activation from one that only mounted the overlays.
    SuccessWithWarnings,
    /// `verify` found warnings.
    VerifyWarning,
    /// `verify` found critical artifacts.
    VerifyCritical,
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
        }
    }

    /// The process exit code `main` returns.
    pub fn to_exit_code(self) -> ExitCode {
        ExitCode::from(self.code())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
