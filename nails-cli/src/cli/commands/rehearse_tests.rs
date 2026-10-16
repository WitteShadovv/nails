// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests for the rehearse command's same-session gate.

use super::*;

/// A canary planted in the session entered at 100, in boot `b1`.
fn planted() -> RehearsalState {
    RehearsalState {
        schema_version: 1,
        token: "0".repeat(32),
        phase: Phase::Planted,
        planted_at: "2026-10-15T20:00:00Z".to_string(),
        planted_boot_id: Some("b1".to_string()),
        planted_entered_at: Some(100),
        planted_soft_reboots: None,
        channels: Vec::new(),
        scans: Vec::new(),
    }
}

fn in_session(entered_at: u64) -> Here {
    Here {
        session: Some(LiveSession {
            entered_at: Some(entered_at),
        }),
        boot_id: Some("b1".to_string()),
        soft_reboots: None,
    }
}

#[test]
fn a_scan_in_the_planting_session_is_refused_unless_allowed() {
    let state = planted();
    let here = in_session(100);
    assert!(refuses_same_session(Some(&state), &here, false, false));
    assert!(
        !refuses_same_session(Some(&state), &here, false, true),
        "--allow-same-boot"
    );
    assert!(
        !refuses_same_session(Some(&state), &here, true, false),
        "an offline scan of images"
    );
}

#[test]
fn a_scan_elsewhere_or_without_a_state_is_not_refused() {
    let state = planted();
    assert!(!refuses_same_session(
        Some(&state),
        &in_session(200),
        false,
        false
    ));
    assert!(!refuses_same_session(
        Some(&state),
        &Here::default(),
        false,
        false
    ));
    assert!(!refuses_same_session(None, &in_session(100), false, false));
}
