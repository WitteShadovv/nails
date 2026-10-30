// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

use super::*;
use serde_json::json;

fn status(data: serde_json::Value) -> serde_json::Value {
    json!({"schema_version": 2, "command": "status", "ok": true, "data": data})
}

#[test]
fn a_status_envelope_reads_with_the_fields_the_window_shows() {
    let value = status(json!({
        "place": "hidden",
        "attention": null,
        "uptime_seconds": 7800,
        "uptime_formatted": "2h 10m",
        "hidden_root": "/mnt/data",
        "hidden_root_mounted": true,
        "policy_mounts": [],
        "masked_units": [],
    }));
    let envelope: Envelope<StatusData> = read(&value, "status").unwrap();
    let data = envelope.data.unwrap();
    assert_eq!(data.place, Place::Hidden);
    assert_eq!(data.attention, None);
    assert_eq!(data.uptime_seconds, Some(7800));
    assert_eq!(data.hidden_root.as_deref(), Some("/mnt/data"));
    assert!(data.hidden_root_mounted);
}

#[test]
fn every_attention_the_schema_names_reads() {
    for (word, attention) in [
        ("interrupted", Attention::Interrupted),
        ("ended_abnormally", Attention::EndedAbnormally),
        ("switch_refused", Attention::SwitchRefused),
        ("record_unreadable", Attention::RecordUnreadable),
        ("no_way_back", Attention::NoWayBack),
        ("volume_lost", Attention::VolumeLost),
        ("volume_covered", Attention::VolumeCovered),
        ("almost_full", Attention::AlmostFull),
    ] {
        let value = status(json!({"place": "decoy", "attention": word}));
        let data = read::<StatusData>(&value, "status").unwrap().data.unwrap();
        assert_eq!(data.attention, Some(attention), "{word}");
    }
}

#[test]
fn a_failure_reads_with_its_code_message_and_next_step() {
    let value = json!({
        "schema_version": 2,
        "command": "status",
        "ok": false,
        "data": {"place": "unknown", "attention": "record_unreadable"},
        "error": {"code": "record_unreadable", "message": "the record is damaged", "next": {"command": "recover"}},
    });
    let envelope: Envelope<StatusData> = read(&value, "status").unwrap();
    assert!(!envelope.ok);
    let error = envelope.error.unwrap();
    assert_eq!(error.code, "record_unreadable");
    assert_eq!(error.next.unwrap().command, "recover");
    assert_eq!(envelope.data.unwrap().place, Place::Unknown);
}

#[test]
fn an_envelope_of_another_shape_version_or_command_is_refused() {
    let cases = [
        (
            json!({"schema_version": 1, "command": "status", "ok": true}),
            "contract 1",
        ),
        (
            json!({"schema_version": 2, "command": "check", "ok": true}),
            "came from check",
        ),
        (
            json!({"schema_version": 2, "command": "status", "ok": true, "extra": 1}),
            "not an envelope",
        ),
        (
            json!({"schema_version": 2, "command": "status"}),
            "not an envelope",
        ),
        (
            json!({"schema_version": 2, "command": "status", "ok": false, "error": {"code": "x", "message": "y"}}),
            "not an envelope",
        ),
        (status(json!({"place": "orbit"})), "not an envelope"),
    ];
    for (value, words) in cases {
        let error = read::<StatusData>(&value, "status").unwrap_err();
        assert!(error.to_string().contains(words), "{value}: {error}");
    }
}

#[test]
fn a_readiness_report_reads_its_rows_and_tally() {
    let value = json!({
        "schema_version": 2,
        "command": "check",
        "ok": false,
        "data": {
            "ready": false,
            "checks": [
                {"name": "swap", "status": "fail", "message": "swap is on", "remediation": "turn swap off"},
                {"name": "journal", "status": "pass", "message": "the journal is volatile"},
                {"name": "selinux", "status": "skipped", "message": "no SELinux"},
                {"name": "space", "status": "warn", "message": "1.8 GB free"},
            ],
            "summary": {"passed": 1, "warnings": 1, "failed": 1, "skipped": 1},
            "config": {"hidden_volume_root": "/mnt/data"},
        },
    });
    let report = read::<Readiness>(&value, "check").unwrap().data.unwrap();
    assert!(!report.ready);
    let statuses: Vec<CheckStatus> = report.checks.iter().map(|row| row.status).collect();
    assert_eq!(
        statuses,
        [
            CheckStatus::Fail,
            CheckStatus::Pass,
            CheckStatus::Skipped,
            CheckStatus::Warn
        ]
    );
    assert_eq!(
        report.checks[0].remediation.as_deref(),
        Some("turn swap off")
    );
    assert_eq!(
        report.summary,
        Summary {
            passed: 1,
            warnings: 1,
            failed: 1,
            skipped: 1
        }
    );
}
