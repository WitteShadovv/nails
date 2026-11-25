// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::{DeactivateData, deactivate_error_body, print_deactivate_json};
use nails_core::NailsError;
use std::path::PathBuf;

#[test]
fn success_json_prints_one_parseable_envelope() {
    // Smoke test: the renderer prints to stdout without panicking and the shape
    // is exercised by the envelope's own serialization tests.
    print_deactivate_json(DeactivateData::enqueued());
}

/// A deactivation always ends in a power-off, and its data says so alone.
#[test]
fn the_data_says_the_power_off_and_nothing_of_a_return() {
    let data = serde_json::to_value(DeactivateData::enqueued()).unwrap();
    assert_eq!(data, serde_json::json!({"status": "poweroff_requested"}));
    assert_eq!(
        super::backend_left_open_warning("hidden-crypt"),
        "The hidden backend device hidden-crypt could not be marked to close: it stays open, \
         its key in RAM, until power-off"
    );
}

#[test]
fn mount_busy_error_folds_the_suggestion_into_the_message() {
    let error = NailsError::MountBusy {
        path: PathBuf::from("/home"),
        suggestion: "Close your browser".to_string(),
    };
    let body = deactivate_error_body(&error);
    assert_eq!(body.code, "mount_busy");
    // The suggestion is guidance, so it folds into the message (on its own
    // line) rather than a field of its own; the human renderer indents it.
    assert!(body.message.contains("/home"), "message={}", body.message);
    assert!(
        body.message.contains("Close your browser"),
        "message={}",
        body.message
    );
    assert!(body.next.is_none());
}

#[test]
fn unmount_error_maps_to_a_structured_error_with_guidance() {
    let error = NailsError::UnmountError {
        path: PathBuf::from("/etc"),
        reason: "device busy".to_string(),
    };
    let body = deactivate_error_body(&error);
    assert_eq!(body.code, "unmount_error");
    assert!(body.message.contains("/etc"));
    assert!(body.message.contains("device busy"));
    assert!(body.message.contains("in use"), "message={}", body.message);
}

#[test]
fn permission_denied_and_invalid_state_map_to_their_own_codes() {
    let perm = deactivate_error_body(&NailsError::PermissionDenied("cannot remove /etc".into()));
    assert_eq!(perm.code, "permission_denied");

    let state = deactivate_error_body(&NailsError::InvalidState("no active session".into()));
    assert_eq!(state.code, "invalid_state");
}

/// A deactivation that failed names the emergency, which powers off at once
/// without the lock or the record.
#[test]
fn an_invalid_state_names_the_emergency() {
    use nails_core::next_step::{NextStep, sudo_line};
    let body = deactivate_error_body(&NailsError::InvalidState(
        "systemctl could not enqueue poweroff.target".into(),
    ));
    assert_eq!(body.code, "invalid_state");
    let lines: Vec<&str> = body.message.lines().collect();
    assert_eq!(
        lines,
        [
            "systemctl could not enqueue poweroff.target",
            format!(
                "`{}` ends the session now: it powers off at once",
                sudo_line(NextStep::Emergency)
            )
            .as_str(),
        ]
    );
    assert_eq!(
        body.next.map(|next| next.command).as_deref(),
        Some("emergency")
    );
}

/// A refused check is not ready: the message says why, the fix follows, and
/// the next step is the emergency.
#[test]
fn a_refused_check_names_the_emergency() {
    let body = deactivate_error_body(&NailsError::PreFlightCheckFailed(vec![(
        "some-check".to_string(),
        "something is off".to_string(),
        Some("Fix it".to_string()),
    )]));
    assert_eq!(body.code, "not_ready");
    assert_eq!(
        body.message.lines().collect::<Vec<_>>(),
        ["the power-off is refused: something is off", "Fix it"]
    );
    assert_eq!(
        body.next.map(|next| next.command).as_deref(),
        Some("emergency")
    );
}

#[test]
fn other_errors_map_to_a_generic_deactivation_failure() {
    let body = deactivate_error_body(&NailsError::io(
        "/tmp/x",
        std::io::Error::other("unexpected"),
    ));
    assert_eq!(body.code, "deactivation_failed");
}
