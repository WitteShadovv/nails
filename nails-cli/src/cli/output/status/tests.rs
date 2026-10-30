// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::human::status_lines;
use super::json::{status_envelope, status_unknown_envelope};
use nails_core::SystemState;
use nails_core::config::PersonaMode;
use nails_core::output::Style;
use nails_core::status::{CoverView, PolicyMountView, Posture, RequiredUnitView, StatusReport};
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
        accepted_decoy_storage: None,
        hidden_root_covered_by: None,
        policy_mounts: Vec::new(),
        masked_units: Vec::new(),
        required_units: Vec::new(),
        nextroot_mounted: false,
        last_activation: None,
        decoy_persistent: false,
        decoy_kdump_armed: false,
        persona_mode: PersonaMode::SharedHome,
        switch_refusal: None,
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
    let lines = status_lines(&active, false, style, &chrono::Utc).join("\n");
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

    active.hidden_root_covered_by = Some(CoverView {
        source: "/dev/sdc1".into(),
        mount_point: "/mnt/data".into(),
    });
    let lines = status_lines(&active, false, Style::default(), &chrono::Utc).join("\n");
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

/// Fail unless `value` matches the committed status schema the contract tests
/// share.
fn assert_matches_the_schema(value: &serde_json::Value) {
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../docs/schemas/status.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).expect("the schema compiles");
    let errors: Vec<String> = validator
        .iter_errors(value)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:#?}\n{value:#}");
}

#[test]
fn a_refused_switch_is_shown_with_its_reason_and_time_in_both_forms() {
    use chrono::{FixedOffset, TimeZone, Utc};
    use nails_core::status::RefusedSwitch;

    // The entry recorded Active, then the soft-reboot refused the switch.
    let why = "the next root has neither /etc/os-release nor /usr/lib/os-release";
    let mut refused = report(Posture::Decoy, "decoy");
    refused.state = SystemState::Active {
        activated_at: Utc.with_ymd_and_hms(2026, 10, 14, 19, 41, 50).unwrap(),
    };
    refused.reason = Some(
        "the record still holds an active session, but none is running: the switch into it \
         was refused"
            .into(),
    );
    refused.remediation = Some("Run `sudo /mnt/data/nails recover` to reset the record".into());
    refused.switch_refusal = Some(RefusedSwitch {
        reason: why.into(),
        at: Utc.with_ymd_and_hms(2026, 10, 14, 19, 41, 59).unwrap(),
    });
    let zone = FixedOffset::east_opt(2 * 3600).unwrap();

    let lines = status_lines(&refused, false, plain(), &zone).join("\n");
    assert!(
        lines.contains("Last switch:        refused at 2026-10-14 21:41:59 +02:00"),
        "{lines}"
    );
    assert!(lines.contains(&format!("  \u{26a0} {why}")), "{lines}");
    assert!(lines.contains("the switch into it was refused"), "{lines}");

    // The JSON names the refusal as the attention, with its own reason, and
    // keeps UTC.
    let value = serde_json::to_value(status_envelope(&refused)).unwrap();
    assert_eq!(value["data"]["attention"], "switch_refused");
    assert_eq!(value["data"]["reason"], why);
    assert_eq!(
        value["data"]["remediation"],
        "Run `sudo /mnt/data/nails recover` to reset the record"
    );
    assert_eq!(value["data"]["switch_refusal"]["reason"], why);
    assert_eq!(
        value["data"]["switch_refusal"]["at"],
        "2026-10-14T19:41:59+00:00"
    );
    assert_matches_the_schema(&value);

    // An attention that outranks it keeps its own reason; the refusal is still
    // there to read.
    let mut interrupted = report(Posture::Degraded, "interrupted");
    interrupted.reason = Some("an interrupted activation left its runtime files in /run".into());
    interrupted.switch_refusal = refused.switch_refusal.clone();
    let value = serde_json::to_value(status_envelope(&interrupted)).unwrap();
    assert_eq!(value["data"]["attention"], "interrupted");
    assert_eq!(
        value["data"]["reason"],
        "an interrupted activation left its runtime files in /run"
    );
    assert_eq!(value["data"]["switch_refusal"]["reason"], why);

    // Without a refusal: no line, no field, and the record's own reason.
    let mut ended = refused.clone();
    ended.switch_refusal = None;
    ended.reason = Some("it ended without updating the record".into());
    let lines = status_lines(&ended, false, plain(), &zone).join("\n");
    assert!(!lines.contains("Last switch"), "{lines}");
    let value = serde_json::to_value(status_envelope(&ended)).unwrap();
    assert_eq!(value["data"]["attention"], "ended_abnormally");
    assert_eq!(
        value["data"]["reason"],
        "it ended without updating the record"
    );
    assert!(value["data"].get("switch_refusal").is_none());
}

#[test]
fn an_armed_kdump_is_shown_on_the_decoy_in_both_forms() {
    let mut decoy = report(Posture::Decoy, "decoy");
    let lines = status_lines(&decoy, false, plain(), &chrono::Utc).join("\n");
    assert!(!lines.contains("kdump"), "{lines}");

    decoy.decoy_kdump_armed = true;
    let lines = status_lines(&decoy, false, plain(), &chrono::Utc).join("\n");
    assert!(lines.contains("kdump is armed on the decoy"), "{lines}");
    assert!(lines.contains("activation refuses it"), "{lines}");
    let value = serde_json::to_value(status_envelope(&decoy)).unwrap();
    assert_eq!(value["data"]["decoy_kdump_armed"], true);
    assert_matches_the_schema(&value);

    // In the session the line is about the decoy, so it is left out.
    let mut active = report(Posture::Active, "hidden");
    active.decoy_kdump_armed = true;
    let lines = status_lines(&active, false, plain(), &chrono::Utc).join("\n");
    assert!(!lines.contains("kdump"), "{lines}");
}

#[test]
fn an_accepted_override_is_shown_in_both_forms() {
    let mut active = report(Posture::Active, "hidden");
    let lines = status_lines(&active, false, Style::default(), &chrono::Utc).join("\n");
    assert!(!lines.contains("--allow-decoy-storage"), "{lines}");
    let value = serde_json::to_value(status_envelope(&active)).unwrap();
    assert!(value["data"].get("accepted_decoy_storage").is_none());

    let reason = "/mnt is not a volume of its own: it is a bind mount of a folder of /srv";
    active.accepted_decoy_storage = Some(reason.into());
    let lines = status_lines(&active, false, Style::default(), &chrono::Utc).join("\n");
    assert!(
        lines.contains(&format!(
            "--allow-decoy-storage: {reason}; everything written there lands on that storage"
        )),
        "{lines}"
    );
    let value = serde_json::to_value(status_envelope(&active)).unwrap();
    assert_eq!(value["data"]["accepted_decoy_storage"], reason);
}

#[test]
fn the_units_a_boot_target_requires_are_listed_with_why_in_both_forms() {
    let mut active = report(Posture::Active, "hidden");
    let lines = status_lines(&active, false, plain(), &chrono::Utc).join("\n");
    assert!(!lines.contains("Required at boot"), "{lines}");
    let value = serde_json::to_value(status_envelope(&active)).unwrap();
    assert_eq!(value["data"]["required_units"], serde_json::json!([]));

    let unit = |unit: &str, action, reason, device: Option<&str>| RequiredUnitView {
        unit: unit.into(),
        action,
        reason,
        device: device.map(PathBuf::from),
    };
    active.required_units = vec![
        unit("srv-data.mount", "skipped", "required_at_boot", None),
        unit(
            "srv-gone.mount",
            "masked",
            "device_absent",
            Some("/dev/vdy1"),
        ),
        unit("srv-native.mount", "masked", "undetermined", None),
        unit("data.mount", "masked", "conflicting_lines", None),
    ];
    let lines = status_lines(&active, false, plain(), &chrono::Utc).join("\n");
    for line in [
        "Required at boot, kept off:",
        "srv-data.mount: skipped, as a boot target requires it",
        "srv-gone.mount: masked, as its device /dev/vdy1 was not there; the boot target that \
         requires it is not reached",
        "srv-native.mount: masked, as NAILS could not tell what it is or pulls in; the boot \
         target that requires it is not reached",
        "data.mount: masked, as the fstab lines or unit files for it disagree; where the one the \
         hidden systemd reads has a boot target require it, that target is not reached",
    ] {
        assert!(lines.contains(line), "{line}: {lines}");
    }
    // The decoy shows them only with --details, as it does the masks.
    let mut decoy = active.clone();
    decoy.posture = Posture::Decoy;
    decoy.session = "decoy";
    let lines = status_lines(&decoy, false, plain(), &chrono::Utc).join("\n");
    assert!(!lines.contains("srv-data.mount"), "{lines}");
    let lines = status_lines(&decoy, true, plain(), &chrono::Utc).join("\n");
    assert!(lines.contains("srv-data.mount"), "{lines}");

    let value = serde_json::to_value(status_envelope(&active)).unwrap();
    assert_matches_the_schema(&value);
    assert_eq!(
        value["data"]["required_units"],
        serde_json::json!([
            { "unit": "srv-data.mount", "action": "skipped", "reason": "required_at_boot" },
            {
                "unit": "srv-gone.mount",
                "action": "masked",
                "reason": "device_absent",
                "device": "/dev/vdy1"
            },
            { "unit": "srv-native.mount", "action": "masked", "reason": "undetermined" },
            { "unit": "data.mount", "action": "masked", "reason": "conflicting_lines" },
        ])
    );
}

#[test]
fn a_degraded_posture_shows_its_reason_and_remedy() {
    let mut degraded = report(Posture::Degraded, "interrupted");
    degraded.reason = Some("an interrupted activation left a populated /run/nextroot".into());
    degraded.remediation = Some("Run `sudo /mnt/data/nails recover` to remove them".to_string());
    let lines = status_lines(&degraded, false, Style::default(), &chrono::Utc).join("\n");
    assert!(lines.contains("/run/nextroot"), "{lines}");
    assert!(
        lines.contains("sudo") && lines.contains("recover"),
        "{lines}"
    );
}

#[test]
fn the_json_envelope_carries_the_place_and_the_attention() {
    let decoy = report(Posture::Decoy, "decoy");
    let value = serde_json::to_value(status_envelope(&decoy)).unwrap();
    assert_eq!(value["command"], "status");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["place"], "decoy");
    // A plain decoy needs no attention; the field is present and null.
    assert!(value["data"].get("attention").is_some());
    assert_eq!(value["data"]["attention"], serde_json::Value::Null);
    assert_eq!(value["data"]["hidden_root_mounted"], true);
    assert!(
        !value
            .to_string()
            .to_lowercase()
            .contains("overlay_verification")
    );
}

#[test]
fn an_active_session_is_hidden_and_a_cover_needs_attention() {
    let active = report(Posture::Active, "hidden");
    let value = serde_json::to_value(status_envelope(&active)).unwrap();
    assert_eq!(value["data"]["place"], "hidden");
    assert_eq!(value["data"]["attention"], serde_json::Value::Null);

    let mut covered = report(Posture::Active, "hidden");
    covered.hidden_root_covered_by = Some(CoverView {
        source: "/dev/sdc1".into(),
        mount_point: "/mnt/data".into(),
    });
    let value = serde_json::to_value(status_envelope(&covered)).unwrap();
    assert_eq!(value["data"]["attention"], "volume_covered");
}

#[test]
fn an_entering_session_is_activating() {
    // A session still entering the hidden root reports `activating`, the third
    // place alongside `decoy` and `hidden` — not the `decoy` fallback.
    let entering = report(Posture::Transitioning, "entering");
    let value = serde_json::to_value(status_envelope(&entering)).unwrap();
    assert_eq!(value["data"]["place"], "activating");
    // Nothing needs the operator while the entry is still in flight, and a
    // transitioning posture is a safe one.
    assert_eq!(value["data"]["attention"], serde_json::Value::Null);
    assert_eq!(value["ok"], true);
}

#[test]
fn an_interrupted_activation_is_on_the_decoy_and_needs_attention() {
    let interrupted = report(Posture::Degraded, "interrupted");
    let value = serde_json::to_value(status_envelope(&interrupted)).unwrap();
    assert_eq!(value["data"]["place"], "decoy");
    assert_eq!(value["data"]["attention"], "interrupted");
    // A degraded posture is not a safe one, so the envelope is not ok.
    assert_eq!(value["ok"], false);
}

/// A record that could not be read or trusted needs the operator wherever the
/// machine is: the place stays what the live view says, and the attention
/// names the record, also in the hidden session. Only what the live view says
/// needs action now comes first, as its remediation does: a hidden root
/// without a way back (power off) and an interrupted activation (recover).
#[test]
fn an_unreadable_record_needs_attention_in_every_place() {
    for (posture, session, place, attention) in [
        (Posture::Unknown, "decoy", "decoy", "record_unreadable"),
        (Posture::Active, "hidden", "hidden", "record_unreadable"),
        (
            Posture::Transitioning,
            "entering",
            "activating",
            "record_unreadable",
        ),
        (Posture::Degraded, "interrupted", "decoy", "interrupted"),
        (
            Posture::Degraded,
            "hidden_without_plan",
            "hidden",
            "no_way_back",
        ),
    ] {
        for source in ["corrupt", "unreadable"] {
            let mut unreadable = report(posture, session);
            unreadable.state_source = source;
            let value = serde_json::to_value(status_envelope(&unreadable)).unwrap();
            assert_eq!(value["data"]["place"], place, "{session} {source}");
            assert_eq!(value["data"]["attention"], attention, "{session} {source}");
        }
    }
    // It comes ahead of a refused switch and of a disk mounted over the volume.
    let mut unreadable = report(Posture::Active, "hidden");
    unreadable.state_source = "corrupt";
    unreadable.switch_refusal = Some(nails_core::status::RefusedSwitch {
        reason: "the unit masks failed".into(),
        at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
    });
    unreadable.hidden_root_covered_by = Some(CoverView {
        source: "/dev/sdc1".into(),
        mount_point: "/mnt/data".into(),
    });
    let value = serde_json::to_value(status_envelope(&unreadable)).unwrap();
    assert_eq!(value["data"]["attention"], "record_unreadable", "{value}");
    // A record read in full, or none at all, needs nothing of its own.
    for source in ["loaded", "missing"] {
        let mut readable = report(Posture::Active, "hidden");
        readable.state_source = source;
        let value = serde_json::to_value(status_envelope(&readable)).unwrap();
        assert_eq!(
            value["data"]["attention"],
            serde_json::Value::Null,
            "{source}"
        );
    }
}

/// The human report says the record is unknown rather than show the inactive
/// default that stands in for it.
#[test]
fn an_unreadable_record_is_shown_as_unknown_not_as_inactive() {
    let mut unreadable = report(Posture::Active, "hidden");
    unreadable.state_source = "corrupt";
    let lines = status_lines(&unreadable, false, plain(), &chrono::Utc).join("\n");
    assert!(
        lines.contains("State:              Unknown (the state file could not be read or trusted)"),
        "{lines}"
    );
    assert!(!lines.contains("Inactive"), "{lines}");
}

/// A status that could not be built (reading the record was refused) claims no
/// place it did not establish: the place is `unknown`, with the error and the
/// line that runs it as root.
#[test]
fn a_status_that_could_not_be_built_claims_no_place() {
    let line = status_unknown_envelope(
        "Permission denied accessing state file /mnt/data/state.json".to_string(),
        Some("sudo /mnt/data/nails status --json".to_string()),
    )
    .to_line();
    let value = crate::cli::output::test_support::envelope("status", &line);
    assert_eq!(value["ok"], false, "{value}");
    assert_eq!(value["data"]["place"], "unknown", "{value}");
    assert_eq!(value["data"]["attention"], "record_unreadable", "{value}");
    assert_eq!(value["error"]["code"], "record_unreadable", "{value}");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .ends_with("\nrun it as root: sudo /mnt/data/nails status --json"),
        "{value}"
    );
}

/// The report shows its times in the given zone with the offset, as the
/// desktop clock does, and the activation time as `activate` printed it; the
/// JSON keeps UTC.
#[test]
fn times_are_shown_in_the_local_zone_with_their_offset() {
    use chrono::{FixedOffset, TimeZone, Utc};

    let mut active = report(Posture::Active, "hidden");
    let entered = Utc.with_ymd_and_hms(2026, 10, 14, 19, 41, 59).unwrap();
    active.entered_at = Some(entered);
    active.last_activation = Some(nails_core::LastActivation {
        duration_ms: 10_960,
        finished_at: entered,
    });
    let zone = FixedOffset::east_opt(2 * 3600).unwrap();

    let lines = status_lines(&active, false, Style::default(), &zone).join("\n");

    assert!(
        lines.contains("Entered:            2026-10-14 21:41:59 +02:00"),
        "{lines}"
    );
    assert!(
        lines.contains("Last activation:    took 11.0s (finished 2026-10-14 21:41:59 +02:00)"),
        "{lines}"
    );
    assert!(!lines.contains("UTC"), "{lines}");
    let value = serde_json::to_value(status_envelope(&active)).unwrap();
    assert_eq!(value["data"]["entered_at"], "2026-10-14T19:41:59+00:00");
}

/// An activation under a second shows its tenths, as `activate` printed it,
/// never "took 0s".
#[test]
fn a_sub_second_activation_shows_its_tenths() {
    use chrono::{TimeZone, Utc};

    let mut decoy = report(Posture::Decoy, "decoy");
    decoy.last_activation = Some(nails_core::LastActivation {
        duration_ms: 640,
        finished_at: Utc.with_ymd_and_hms(2026, 10, 14, 19, 41, 59).unwrap(),
    });

    let lines = status_lines(&decoy, false, plain(), &Utc).join("\n");

    assert!(
        lines.contains("Last activation:    took 0.6s (finished 2026-10-14 19:41:59 +00:00)"),
        "{lines}"
    );
    assert!(!lines.contains("took 0s"), "{lines}");
}

/// The log lines of `status --details` are in the same zone as the report.
#[test]
fn recent_logs_are_shown_in_the_given_zone() {
    let dir = log_dir(&[log_line("2026-01-01T23:30:01Z", "INFO", "late")]);
    let zone = chrono::FixedOffset::east_opt(2 * 3600).unwrap();

    let lines = super::read_recent_logs(dir.path(), None, false, plain(), &zone).unwrap();

    assert_eq!(lines, vec!["[01:30:01] INFO late".to_string()]);
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
        super::read_recent_logs(dir.path(), None, false, plain(), &chrono::Utc),
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

    let lines =
        super::read_recent_logs(dir.path(), Some(activated), false, plain(), &chrono::Utc).unwrap();

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

    let lines = super::read_recent_logs(dir.path(), None, true, plain(), &chrono::Utc).unwrap();

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

    let recent = super::read_recent_logs(dir.path(), None, false, plain(), &chrono::Utc).unwrap();

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

    let lines = super::read_recent_logs(dir.path(), None, false, style, &chrono::Utc).unwrap();

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

    let folded = super::read_recent_logs(dir.path(), None, false, ascii, &chrono::Utc).unwrap();
    let kept = super::read_recent_logs(dir.path(), None, false, plain(), &chrono::Utc).unwrap();

    assert_eq!(folded, vec!["[10:00:01] INFO [PASS] Activation complete"]);
    assert_eq!(kept, vec!["[10:00:01] INFO \u{2713} Activation complete"]);
}

#[test]
fn recent_logs_are_none_when_nothing_matches() {
    let dir = log_dir(&[log_line("2026-01-01T10:00:02Z", "DEBUG", "probe detail")]);
    assert_eq!(
        super::read_recent_logs(dir.path(), None, false, plain(), &chrono::Utc),
        None
    );
}
