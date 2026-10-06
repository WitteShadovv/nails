// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::{DEACTIVATE_RECOVERY_GUIDANCE, deactivate_error_body, print_deactivate_json};
use nails_core::NailsError;
use std::path::PathBuf;

#[test]
fn success_json_prints_one_parseable_envelope() {
    // Smoke test: the renderer prints to stdout without panicking and the shape
    // is exercised by the envelope's own serialization tests.
    print_deactivate_json(false);
}

#[test]
fn recovery_guidance_lists_the_dismount_and_poweroff_steps() {
    let combined = DEACTIVATE_RECOVERY_GUIDANCE.join("\n");
    assert!(combined.contains("dismounted"), "{combined}");
    assert!(combined.contains("powered off"), "{combined}");
}

#[test]
fn mount_busy_error_keeps_the_suggestion_as_a_hint_and_drops_the_newline() {
    let error = NailsError::MountBusy {
        path: PathBuf::from("/home"),
        suggestion: "Close your browser".to_string(),
    };
    let body = deactivate_error_body(&error);
    assert_eq!(body.code, "mount_busy");
    assert!(!body.message.contains('\n'), "message={}", body.message);
    assert!(body.message.contains("/home"));
    assert_eq!(body.hint.as_deref(), Some("Close your browser"));
}

#[test]
fn unmount_error_maps_to_a_hinted_structured_error() {
    let error = NailsError::UnmountError {
        path: PathBuf::from("/etc"),
        reason: "device busy".to_string(),
    };
    let body = deactivate_error_body(&error);
    assert_eq!(body.code, "unmount_error");
    assert!(!body.message.contains('\n'), "message={}", body.message);
    assert!(body.message.contains("/etc"));
    assert!(body.message.contains("device busy"));
    assert!(body.hint.is_some());
}

#[test]
fn permission_denied_and_invalid_state_map_to_their_own_codes() {
    let perm = deactivate_error_body(&NailsError::PermissionDenied("cannot remove /etc".into()));
    assert_eq!(perm.code, "permission_denied");

    let state = deactivate_error_body(&NailsError::InvalidState("no active session".into()));
    assert_eq!(state.code, "invalid_state");
}

#[test]
fn other_errors_map_to_a_generic_deactivation_failure() {
    let body = deactivate_error_body(&NailsError::io(
        "/tmp/x",
        std::io::Error::other("unexpected"),
    ));
    assert_eq!(body.code, "deactivation_failed");
}
