// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests for the recorded [`SystemState`], through the public API.

use chrono::Utc;
use nails_core::SystemState;

#[test]
fn predicates_and_labels_match_each_state() {
    let now = Utc::now();
    let cases = [
        (SystemState::Inactive, "inactive"),
        (SystemState::Active { activated_at: now }, "active"),
        (
            SystemState::Degraded {
                since: now,
                reason: "power off to end the session".to_string(),
            },
            "degraded",
        ),
    ];
    for (state, label) in cases {
        assert_eq!(state.label(), label);
        assert_eq!(state.is_inactive(), label == "inactive");
        assert_eq!(state.is_active(), label == "active");
        assert_eq!(state.is_degraded(), label == "degraded");
    }
}

#[test]
fn every_state_round_trips_through_json() {
    let now = Utc::now();
    for state in [
        SystemState::Inactive,
        SystemState::Active { activated_at: now },
        SystemState::Degraded {
            since: now,
            reason: "x".to_string(),
        },
    ] {
        let json = serde_json::to_string(&state).unwrap();
        let back: SystemState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }
}

#[test]
fn a_live_overlay_era_state_does_not_parse() {
    assert!(
        serde_json::from_str::<SystemState>(
            r#"{"Activating":{"started_at":"2025-01-01T00:00:00Z"}}"#
        )
        .is_err()
    );
}
