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
        accepted_not_separate: None,
        hidden_root_covered_by: None,
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
fn a_cover_is_shown_in_both_forms() {
    let mut active = report(Posture::Active, "hidden");
    let value = serde_json::to_value(status_envelope(&active)).unwrap();
    assert!(value["data"].get("hidden_root_covered_by").is_none());

    active.hidden_root_covered_by = Some("/dev/sdc1".into());
    let lines = status_lines(&active, false, Style::default()).join("\n");
    assert!(
        lines.contains(
            "/dev/sdc1 is mounted over it: files saved there go to that disk \
             (`sudo umount /mnt/data` takes it off)"
        ),
        "{lines}"
    );
    let value = serde_json::to_value(status_envelope(&active)).unwrap();
    assert_eq!(value["data"]["hidden_root_covered_by"], "/dev/sdc1");
    // The committed schema the contract tests share admits it.
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../docs/schemas/status.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let errors: Vec<String> = validator
        .iter_errors(&value)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:#?}\n{value:#}");
}

#[test]
fn an_accepted_override_is_shown_in_both_forms() {
    let mut active = report(Posture::Active, "hidden");
    let lines = status_lines(&active, false, Style::default()).join("\n");
    assert!(!lines.contains("--allow-decoy-storage"), "{lines}");
    let value = serde_json::to_value(status_envelope(&active)).unwrap();
    assert!(value["data"].get("accepted_not_separate").is_none());

    let reason = "/mnt is not a volume of its own: it is a bind mount of a folder of /srv";
    active.accepted_not_separate = Some(reason.into());
    let lines = status_lines(&active, false, Style::default()).join("\n");
    assert!(
        lines.contains(&format!(
            "--allow-decoy-storage: {reason}; everything written there lands on that storage"
        )),
        "{lines}"
    );
    let value = serde_json::to_value(status_envelope(&active)).unwrap();
    assert_eq!(value["data"]["accepted_not_separate"], reason);
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

/// Write `lines` as `nails.log` in a fresh log directory.
fn log_dir(lines: &[String]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("nails.log"), lines.join("\n")).unwrap();
    dir
}

/// One JSON log line as the file layer writes it.
fn log_line(timestamp: &str, level: &str, message: &str) -> String {
    serde_json::json!({
        "timestamp": timestamp,
        "level": level,
        "fields": {"message": message},
    })
    .to_string()
}

fn plain() -> Style {
    Style {
        color: false,
        ascii: false,
    }
}

#[test]
fn the_config_label_notes_a_missing_file_and_names_a_present_one() {
    let dir = tempfile::tempdir().unwrap();
    let present = dir.path().join("nails.toml");
    std::fs::write(&present, "").unwrap();
    let absent = dir.path().join("absent.toml");

    assert_eq!(
        super::config_file_label(&present),
        present.display().to_string()
    );
    assert_eq!(
        super::config_file_label(&absent),
        format!("{} (not found, using defaults)", absent.display())
    );
}

#[test]
fn recent_logs_are_none_without_a_log_file() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        super::read_recent_logs(dir.path(), None, false, plain()),
        None
    );
}

#[test]
fn recent_logs_skip_entries_before_the_activation_and_debug_noise() {
    let dir = log_dir(&[
        log_line("2026-01-01T09:00:00Z", "INFO", "before the session"),
        log_line("2026-01-01T10:00:01Z", "INFO", "session entered"),
        log_line("2026-01-01T10:00:02Z", "DEBUG", "probe detail"),
        log_line("2026-01-01T10:00:03Z", "TRACE", "inner loop"),
        log_line("2026-01-01T10:00:04Z", "WARN", "backend slow"),
        "not json at all".to_string(),
        serde_json::json!({"level": "ERROR", "fields": {"message": "no timestamp"}}).to_string(),
    ]);
    let activated = chrono::DateTime::parse_from_rfc3339("2026-01-01T10:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);

    let lines = super::read_recent_logs(dir.path(), Some(activated), false, plain()).unwrap();

    assert_eq!(
        lines,
        vec![
            "[10:00:01] INFO session entered".to_string(),
            "[10:00:04] WARN backend slow".to_string(),
        ]
    );
}

#[test]
fn recent_logs_keep_debug_and_trace_when_asked() {
    let dir = log_dir(&[
        log_line("2026-01-01T10:00:02Z", "DEBUG", "probe detail"),
        log_line("2026-01-01T10:00:03Z", "TRACE", "inner loop"),
        log_line("2026-01-01T10:00:04Z", "NOTICE", "unknown level"),
    ]);

    let lines = super::read_recent_logs(dir.path(), None, true, plain()).unwrap();

    assert_eq!(
        lines,
        vec![
            "[10:00:02] DEBUG probe detail".to_string(),
            "[10:00:03] TRACE inner loop".to_string(),
            "[10:00:04] NOTICE unknown level".to_string(),
        ]
    );
}

#[test]
fn recent_logs_keep_only_the_newest_twenty_in_order() {
    let lines: Vec<String> = (0..25)
        .map(|i| {
            log_line(
                &format!("2026-01-01T10:00:{i:02}Z"),
                "INFO",
                &format!("entry {i}"),
            )
        })
        .collect();
    let dir = log_dir(&lines);

    let recent = super::read_recent_logs(dir.path(), None, false, plain()).unwrap();

    assert_eq!(recent.len(), super::RECENT_LOG_LIMIT);
    assert_eq!(recent.first().unwrap(), "[10:00:05] INFO entry 5");
    assert_eq!(recent.last().unwrap(), "[10:00:24] INFO entry 24");
}

#[test]
fn recent_logs_fall_back_to_a_top_level_message_and_paint_levels() {
    let dir = log_dir(&[serde_json::json!({
        "timestamp": "2026-01-01T10:00:01Z",
        "level": "ERROR",
        "message": "top-level text",
    })
    .to_string()]);
    let style = Style {
        color: true,
        ascii: false,
    };

    let lines = super::read_recent_logs(dir.path(), None, false, style).unwrap();

    assert_eq!(
        lines,
        vec!["[\x1b[2m10:00:01\x1b[0m] \x1b[1;31mERROR\x1b[0m top-level text".to_string()]
    );
}

#[test]
fn recent_logs_fold_a_unicode_mark_to_ascii_in_ascii_mode() {
    let dir = log_dir(&[log_line(
        "2026-01-01T10:00:01Z",
        "INFO",
        "\u{2713} Activation complete",
    )]);
    let ascii = Style {
        color: false,
        ascii: true,
    };

    let folded = super::read_recent_logs(dir.path(), None, false, ascii).unwrap();
    let kept = super::read_recent_logs(dir.path(), None, false, plain()).unwrap();

    assert_eq!(folded, vec!["[10:00:01] INFO [PASS] Activation complete"]);
    assert_eq!(kept, vec!["[10:00:01] INFO \u{2713} Activation complete"]);
}

#[test]
fn recent_logs_are_none_when_nothing_matches() {
    let dir = log_dir(&[log_line("2026-01-01T10:00:02Z", "DEBUG", "probe detail")]);
    assert_eq!(
        super::read_recent_logs(dir.path(), None, false, plain()),
        None
    );
}
