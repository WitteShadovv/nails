//! Tests for the `reapply` command's outcome-to-exit mapping.

use super::*;
use nails_core::HiddenConfigOutcome;

fn settings() -> OutputSettings {
    OutputSettings {
        ascii: true,
        ..OutputSettings::default()
    }
}

#[test]
fn clean_reapply_exits_ok() {
    let result = Ok(ActivationOutcome::Activated {
        hidden_config: HiddenConfigOutcome::Applied {
            toplevel: Some("/nix/store/aaa-nixos-system-host".to_string()),
            fast_path: false,
        },
    });
    assert_eq!(report(&result, &settings(), false), ExitStatus::Ok);
}

#[test]
fn not_requested_reapply_exits_ok() {
    let result = Ok(ActivationOutcome::Activated {
        hidden_config: HiddenConfigOutcome::NotRequested,
    });
    assert_eq!(report(&result, &settings(), true), ExitStatus::Ok);
}

#[test]
fn failed_switch_exits_with_warnings_code() {
    let result = Ok(ActivationOutcome::Activated {
        hidden_config: HiddenConfigOutcome::Failed {
            reason: "build failed".to_string(),
        },
    });
    assert_eq!(
        report(&result, &settings(), false),
        ExitStatus::SuccessWithWarnings
    );
    assert_eq!(ExitStatus::SuccessWithWarnings.code(), 9);
}

#[test]
fn refusal_when_not_active_exits_invalid_state() {
    let result = Err(NailsError::InvalidState(
        "reapply needs a verifiably active hidden environment".to_string(),
    ));
    assert_eq!(report(&result, &settings(), true), ExitStatus::InvalidState);
}

#[test]
fn other_error_exits_failed() {
    let result = Err(NailsError::NixOSError("boom".to_string()));
    assert_eq!(report(&result, &settings(), false), ExitStatus::Failed);
}
