// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::human::status_lines;
use super::json::status_envelope;
use nails_core::SystemState;
use nails_core::config::PersonaMode;
use nails_core::output::Style;
use nails_core::status::{PolicyMountView, Posture, StatusReport};
use std::path::PathBuf;

fn report(posture: Posture, session: &'static str) -> StatusReport {
    StatusReport {
        posture,
        session,
        reason: None,
        remediation: None,
        state: SystemState::Inactive,
        state_source: "loaded",
        entered_at: None,
        uptime: None,
        hidden_system: None,
        decoy_system: None,
        hidden_root: PathBuf::from("/mnt/data"),
        hidden_root_mounted: true,
        hidden_root_source: None,
        policy_mounts: Vec::new(),
        masked_units: Vec::new(),
        nextroot_mounted: false,
        last_activation: None,
        decoy_persistent: false,
        persona_mode: PersonaMode::SharedHome,
        opsec_reminders: Vec::new(),
    }
}

#[test]
fn an_active_session_lists_its_policy_mounts_and_system() {
    let mut active = report(Posture::Active, "hidden");
    active.hidden_system = Some("/nix/store/bbb-nixos-system".into());
    active.policy_mounts = vec![PolicyMountView {
        target: PathBuf::from("/boot"),
        kind: "read-only",
    }];
    active.masked_units = vec!["dev-vda3.swap".into()];
    let style = Style {
        ascii: true,
        ..Style::default()
    };
    let lines = status_lines(&active, false, style).join("\n");
    assert!(lines.contains("[ACTIVE]"), "{lines}");
    assert!(lines.contains("/boot (read-only)"), "{lines}");
    assert!(lines.contains("dev-vda3.swap"), "{lines}");
    assert!(lines.contains("/nix/store/bbb-nixos-system"), "{lines}");
    assert!(lines.is_ascii());
}

#[test]
fn a_degraded_posture_shows_its_reason_and_remedy() {
    let mut degraded = report(Posture::Degraded, "interrupted");
    degraded.reason = Some("an interrupted activation left a populated /run/nextroot".into());
    degraded.remediation = Some("Run `nails recover` to remove them");
    let lines = status_lines(&degraded, false, Style::default()).join("\n");
    assert!(lines.contains("/run/nextroot"), "{lines}");
    assert!(lines.contains("nails recover"), "{lines}");
}

#[test]
fn the_json_envelope_carries_the_live_view_and_the_record() {
    let decoy = report(Posture::Decoy, "decoy");
    let value = serde_json::to_value(status_envelope(&decoy)).unwrap();
    assert_eq!(value["command"], "status");
    assert_eq!(value["data"]["posture"], "decoy");
    assert_eq!(value["data"]["session"], "decoy");
    assert_eq!(value["data"]["state"]["kind"], "inactive");
    assert_eq!(value["data"]["hidden_root_mounted"], true);
    assert!(
        !value
            .to_string()
            .to_lowercase()
            .contains("overlay_verification")
    );
}
