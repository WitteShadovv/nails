// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use nails_core::output::Style;
use nails_core::status::{
    OpSecReminder, OverlayMountStatus, Posture, ReminderSeverity, StatusReport, VerificationStatus,
};
use nails_core::{LoadOutcome, SystemState};
use std::path::PathBuf;

const COLOR: Style = Style {
    color: true,
    ascii: false,
};
const ASCII: Style = Style {
    color: false,
    ascii: true,
};

fn inactive_report() -> StatusReport {
    StatusReport {
        state: SystemState::Inactive,
        posture: Posture::Decoy,
        overlays: vec![],
        overlay_verification: VerificationStatus::NotApplicable,
        hidden_toplevel: None,
        activated_at: None,
        uptime: None,
        formatted_uptime: String::new(),
        opsec_reminders: vec![],
        overlay_details: None,
        overlay_mount_statuses: vec![],
        load_outcome: LoadOutcome::Missing,
        ..Default::default()
    }
}

fn active_report() -> StatusReport {
    let now = chrono::Utc::now();
    StatusReport {
        state: SystemState::Active {
            activated_at: now - chrono::Duration::hours(2),
            overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
            decoy_writers: Vec::new(),
        },
        posture: Posture::Active,
        overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
        overlay_verification: VerificationStatus::Verified,
        hidden_toplevel: Some("nails-gen-42".to_string()),
        activated_at: Some(now - chrono::Duration::hours(2)),
        uptime: Some(chrono::Duration::hours(2)),
        formatted_uptime: "2 hours".to_string(),
        opsec_reminders: vec![],
        overlay_details: None,
        overlay_mount_statuses: vec![
            OverlayMountStatus {
                path: PathBuf::from("/home"),
                expected_mounted: true,
                actually_mounted: true,
                owned: true,
                upperdir: Some(PathBuf::from("/mnt/hidden/home/.upper")),
            },
            OverlayMountStatus {
                path: PathBuf::from("/etc"),
                expected_mounted: true,
                actually_mounted: false,
                owned: false,
                upperdir: None,
            },
        ],
        load_outcome: LoadOutcome::Loaded,
        ..Default::default()
    }
}

fn active_report_with_overlay_details() -> StatusReport {
    let now = chrono::Utc::now();
    let mut overlay_details = std::collections::HashMap::new();
    overlay_details.insert(
        PathBuf::from("/home"),
        nails_core::OverlayInfo {
            mount_method: Default::default(),
            mount_path: PathBuf::from("/home"),
            lower_dir: PathBuf::from("/home"),
            upper_dir: PathBuf::from("/mnt/hidden/home/.upper"),
            work_dir: PathBuf::from("/mnt/hidden/home/.work"),
            mounted_at: now,
        },
    );
    StatusReport {
        state: SystemState::Active {
            activated_at: now,
            overlays: vec![PathBuf::from("/home")],
            decoy_writers: Vec::new(),
        },
        posture: Posture::Active,
        overlays: vec![PathBuf::from("/home")],
        overlay_verification: VerificationStatus::Verified,
        hidden_toplevel: None,
        activated_at: Some(now),
        uptime: Some(chrono::Duration::minutes(30)),
        formatted_uptime: "30 minutes".to_string(),
        opsec_reminders: vec![],
        overlay_details: Some(overlay_details),
        overlay_mount_statuses: vec![OverlayMountStatus {
            path: PathBuf::from("/home"),
            expected_mounted: true,
            actually_mounted: true,
            owned: true,
            upperdir: Some(PathBuf::from("/mnt/hidden/home/.upper")),
        }],
        load_outcome: LoadOutcome::Loaded,
        ..Default::default()
    }
}

fn active_report_with_reminders() -> StatusReport {
    let now = chrono::Utc::now();
    StatusReport {
        state: SystemState::Active {
            activated_at: now - chrono::Duration::hours(26),
            overlays: vec![],
            decoy_writers: Vec::new(),
        },
        posture: Posture::Degraded,
        remaining_mounts: vec![PathBuf::from("/home")],
        overlays: vec![],
        overlay_verification: VerificationStatus::Mismatch {
            errors: vec!["overlay mismatch".to_string()],
        },
        hidden_toplevel: None,
        activated_at: Some(now - chrono::Duration::hours(26)),
        uptime: Some(chrono::Duration::hours(26)),
        formatted_uptime: "1 day 2 hours".to_string(),
        opsec_reminders: vec![
            OpSecReminder {
                severity: ReminderSeverity::Info,
                message: "Take a break".to_string(),
            },
            OpSecReminder {
                severity: ReminderSeverity::Warning,
                message: "Extended session".to_string(),
            },
            OpSecReminder {
                severity: ReminderSeverity::Critical,
                message: "Session >24 hours".to_string(),
            },
        ],
        overlay_details: None,
        overlay_mount_statuses: vec![],
        load_outcome: LoadOutcome::Loaded,
        ..Default::default()
    }
}

fn degraded_report() -> StatusReport {
    StatusReport {
        state: SystemState::Degraded {
            since: chrono::Utc::now(),
            reason: "unmount failed".to_string(),
            remaining_mounts: vec![PathBuf::from("/home")],
        },
        posture: Posture::Inconsistent,
        remaining_mounts: vec![PathBuf::from("/home")],
        overlays: vec![],
        overlay_verification: VerificationStatus::Skipped,
        hidden_toplevel: None,
        activated_at: None,
        uptime: None,
        formatted_uptime: String::new(),
        opsec_reminders: vec![],
        overlay_details: None,
        overlay_mount_statuses: vec![],
        load_outcome: LoadOutcome::Missing,
        ..Default::default()
    }
}

// ── print_status_json ──────────────────────────────────────────────────────

#[test]
fn test_print_status_json_inactive() {
    print_status_json(&inactive_report());
}

#[test]
fn test_print_status_json_active() {
    print_status_json(&active_report());
}

#[test]
fn test_print_status_json_active_uptime_empty() {
    let mut r = inactive_report();
    r.formatted_uptime = String::new();
    print_status_json(&r);
}

#[test]
fn test_print_status_json_with_reminders() {
    print_status_json(&active_report_with_reminders());
}

#[test]
fn test_print_status_json_degraded() {
    print_status_json(&degraded_report());
}

/// An active, verified report whose activation left writers on the decoy.
fn active_report_with_decoy_writers() -> StatusReport {
    let mut report = active_report();
    report.overlay_verification = VerificationStatus::Verified;
    report.state = SystemState::Active {
        activated_at: chrono::Utc::now(),
        overlays: vec![PathBuf::from("/etc"), PathBuf::from("/var")],
        decoy_writers: vec![
            nails_core::DecoyWriter {
                pid: 812,
                name: "tail".to_string(),
                service: None,
                targets: vec![PathBuf::from("/var")],
                kind: nails_core::WriterKind::StaleLower,
            },
            nails_core::DecoyWriter {
                pid: 600,
                name: "NetworkManager".to_string(),
                service: Some("NetworkManager".to_string()),
                targets: vec![PathBuf::from("/etc"), PathBuf::from("/var")],
                kind: nails_core::WriterKind::Unverifiable,
            },
        ],
    };
    report
}

#[test]
fn test_status_json_lists_decoy_writers() {
    let data = super::json::build_status_data(&active_report_with_decoy_writers());
    let value = serde_json::to_value(&data).unwrap();
    assert_eq!(value["posture"], "active");
    assert_eq!(value["decoy_writers"][0]["name"], "tail");
    assert_eq!(value["decoy_writers"][0]["pid"], 812);
    assert_eq!(value["decoy_writers"][1]["service"], "NetworkManager");
    assert_eq!(
        value["decoy_writers"][1]["targets"],
        serde_json::json!(["/etc", "/var"])
    );
    // The post-mount classification is carried through to JSON so a consumer can
    // tell a stale-lower writer from an unverifiable one.
    assert_eq!(value["decoy_writers"][0]["kind"], "stale_lower");
    assert_eq!(value["decoy_writers"][1]["kind"], "unverifiable");
}

#[test]
fn test_status_json_has_empty_decoy_writers_when_none_remain() {
    let data = super::json::build_status_data(&inactive_report());
    let value = serde_json::to_value(&data).unwrap();
    assert_eq!(value["decoy_writers"], serde_json::json!([]));
}

#[test]
fn test_posture_lines_report_writers_still_on_the_decoy() {
    let lines = super::human::posture_lines(&active_report_with_decoy_writers(), ASCII);
    assert_eq!(
        lines[0],
        "Security Posture:   [ACTIVE] Hidden environment active, all overlays verified"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("[WARN] NOT OPTIMAL: 2 writers still on the decoy")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l == "    - tail (PID 812) on /var (still on the decoy after the mount)"),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|l| l
            == "    - NetworkManager (NetworkManager.service, PID 600) on /etc, /var \
                (unverifiable: outside the host namespace)"),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("Recorded at activation")),
        "{lines:?}"
    );
}

#[test]
fn test_posture_lines_without_writers_show_the_plain_posture() {
    let mut report = active_report();
    report.overlay_verification = VerificationStatus::Verified;
    let lines = super::human::posture_lines(&report, COLOR);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("ACTIVE"), "{lines:?}");
    assert!(!lines[0].contains("NOT OPTIMAL"), "{lines:?}");
}

#[test]
fn test_print_status_human_with_decoy_writers() {
    let log_dir = tempfile::tempdir().unwrap();
    print_status_human(
        &active_report_with_decoy_writers(),
        false,
        std::path::Path::new("/nonexistent/nails.toml"),
        std::path::Path::new("/mnt/hidden/state.json"),
        std::path::Path::new("/mnt/hidden"),
        log_dir.path(),
        COLOR,
    );
}

#[test]
fn test_status_json_includes_hidden_root_disk_figures() {
    let mut report = active_report();
    report.hidden_root_total = Some(10 * 1024 * 1024 * 1024);
    report.hidden_root_used = Some(6 * 1024 * 1024 * 1024);
    report.hidden_root_available = Some(4 * 1024 * 1024 * 1024);

    let data = super::json::build_status_data(&report);
    let value = serde_json::to_value(&data).unwrap();

    assert_eq!(value["hidden_root_total_bytes"], 10 * 1024 * 1024 * 1024u64);
    assert_eq!(value["hidden_root_used_bytes"], 6 * 1024 * 1024 * 1024u64);
    assert_eq!(
        value["hidden_root_available_bytes"],
        4 * 1024 * 1024 * 1024u64
    );
}

#[test]
fn test_status_json_includes_hidden_config_warning_when_switch_failed() {
    let mut report = active_report();
    report.last_switch_warning =
        Some("hidden NixOS configuration was not applied (boom)".to_string());

    let data = super::json::build_status_data(&report);
    let value = serde_json::to_value(&data).unwrap();

    assert_eq!(
        value["hidden_config_warning"],
        "hidden NixOS configuration was not applied (boom)"
    );
}

#[test]
fn test_status_json_omits_hidden_config_warning_when_applied() {
    // active_report() leaves last_switch_warning at None.
    let data = super::json::build_status_data(&active_report());
    let value = serde_json::to_value(&data).unwrap();

    assert!(value.get("hidden_config_warning").is_none());
}

#[test]
fn test_print_status_human_renders_not_applied_line() {
    let mut report = active_report();
    report.last_switch_warning =
        Some("hidden NixOS configuration was not applied (boom)".to_string());
    // Smoke: the human renderer accepts the warning without panicking; the line
    // itself is asserted through the report field in the core status tests.
    print_status_human(
        &report,
        false,
        std::path::Path::new("/etc/nails.toml"),
        std::path::Path::new("/mnt/hidden/state.json"),
        std::path::Path::new("/mnt/hidden"),
        std::path::Path::new("/mnt/hidden/logs/nails.log"),
        COLOR,
    );
}

#[test]
fn test_status_json_omits_hidden_root_disk_figures_when_absent() {
    // inactive_report() leaves the hidden_root_* figures at None.
    let data = super::json::build_status_data(&inactive_report());
    let value = serde_json::to_value(&data).unwrap();

    assert!(value.get("hidden_root_total_bytes").is_none());
    assert!(value.get("hidden_root_used_bytes").is_none());
    assert!(value.get("hidden_root_available_bytes").is_none());
}

#[test]
fn test_format_bytes_scales_to_binary_units() {
    use super::human::format_bytes;

    assert_eq!(format_bytes(0), "0 B");
    assert_eq!(format_bytes(512), "512 B");
    assert_eq!(format_bytes(1024), "1.0 KiB");
    assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
    assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
}

#[test]
fn test_hidden_volume_line_renders_all_three_figures() {
    let mut report = inactive_report();
    report.hidden_root_total = Some(10 * 1024 * 1024 * 1024);
    report.hidden_root_used = Some(6 * 1024 * 1024 * 1024);
    report.hidden_root_available = Some(4 * 1024 * 1024 * 1024);

    let line = super::human::hidden_volume_line(&report).expect("line should render");
    assert!(line.contains("6.0 GiB used"), "got: {line}");
    assert!(line.contains("of 10.0 GiB"), "got: {line}");
    assert!(line.contains("4.0 GiB free"), "got: {line}");
}

#[test]
fn test_hidden_volume_line_absent_without_figures() {
    assert!(super::human::hidden_volume_line(&inactive_report()).is_none());
}

// ── print_status_human ─────────────────────────────────────────────────────

#[test]
fn test_print_status_human_inactive() {
    print_status_human(
        &inactive_report(),
        false,
        &PathBuf::from("/etc/nails.toml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
        &PathBuf::from("/mnt/hidden/logs"),
        COLOR,
    );
}

#[test]
fn test_print_status_human_active_basic() {
    print_status_human(
        &active_report(),
        false,
        &PathBuf::from("/etc/nails.toml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
        &PathBuf::from("/mnt/hidden/logs"),
        COLOR,
    );
}

#[test]
fn test_print_status_human_active_verbose_with_details() {
    print_status_human(
        &active_report_with_overlay_details(),
        true,
        &PathBuf::from("/etc/nails.toml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
        &PathBuf::from("/mnt/hidden/logs"),
        COLOR,
    );
}

#[test]
fn test_print_status_human_active_verbose_no_details() {
    print_status_human(
        &active_report(),
        true,
        &PathBuf::from("/etc/nails.toml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
        &PathBuf::from("/mnt/hidden/logs"),
        COLOR,
    );
}

#[test]
fn test_print_status_human_with_reminders() {
    print_status_human(
        &active_report_with_reminders(),
        false,
        &PathBuf::from("/etc/nails.toml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
        &PathBuf::from("/mnt/hidden/logs"),
        COLOR,
    );
}

#[test]
fn test_print_status_human_with_logs() {
    use std::io::Write as _;
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("nails.log");
    let now = chrono::Utc::now();

    let mut f = std::fs::File::create(&log_path).unwrap();
    for level in &["INFO", "WARN", "ERROR", "DEBUG", "TRACE"] {
        writeln!(
            f,
            r#"{{"timestamp":"{}","level":"{}","fields":{{"message":"msg {level}"}}}}"#,
            now.to_rfc3339(),
            level
        )
        .unwrap();
    }
    drop(f);

    let mut report = active_report();
    report.activated_at = Some(now - chrono::Duration::hours(1));
    print_status_human(
        &report,
        false,
        &PathBuf::from("/etc/nails.toml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
        dir.path(),
        COLOR,
    );
}

#[test]
fn test_print_status_human_verbose_shows_debug_logs() {
    use std::io::Write as _;
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("nails.log");
    let now = chrono::Utc::now();

    let mut f = std::fs::File::create(&log_path).unwrap();
    writeln!(
        f,
        r#"{{"timestamp":"{}","level":"DEBUG","fields":{{"message":"debug msg"}}}}"#,
        now.to_rfc3339()
    )
    .unwrap();
    drop(f);

    let mut report = active_report_with_overlay_details();
    report.activated_at = Some(now - chrono::Duration::hours(1));
    print_status_human(
        &report,
        true,
        &PathBuf::from("/etc/nails.toml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
        dir.path(),
        COLOR,
    );
}

#[test]
fn test_print_status_human_logs_filtered_before_activation() {
    use std::io::Write as _;
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("nails.log");
    let now = chrono::Utc::now();

    let mut f = std::fs::File::create(&log_path).unwrap();
    writeln!(
        f,
        r#"{{"timestamp":"{}","level":"INFO","fields":{{"message":"old"}}}}"#,
        (now - chrono::Duration::hours(5)).to_rfc3339()
    )
    .unwrap();
    drop(f);

    let mut report = active_report();
    report.activated_at = Some(now - chrono::Duration::hours(1));
    print_status_human(
        &report,
        false,
        &PathBuf::from("/etc/nails.toml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
        dir.path(),
        COLOR,
    );
}

#[test]
fn test_print_status_human_logs_no_activation_time() {
    use std::io::Write as _;
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("nails.log");
    let now = chrono::Utc::now();

    let mut f = std::fs::File::create(&log_path).unwrap();
    writeln!(
        f,
        r#"{{"timestamp":"{}","level":"INFO","fields":{{"message":"msg"}}}}"#,
        now.to_rfc3339()
    )
    .unwrap();
    drop(f);

    let mut report = active_report();
    report.activated_at = None;
    print_status_human(
        &report,
        false,
        &PathBuf::from("/etc/nails.toml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
        dir.path(),
        COLOR,
    );
}

#[test]
fn test_print_status_human_logs_invalid_json_ignored() {
    use std::io::Write as _;
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("nails.log");

    let mut f = std::fs::File::create(&log_path).unwrap();
    writeln!(f, "not json").unwrap();
    writeln!(f, r#"{{"no_timestamp":1}}"#).unwrap();
    drop(f);

    let mut report = active_report();
    report.activated_at = None;
    print_status_human(
        &report,
        false,
        &PathBuf::from("/etc/nails.toml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
        dir.path(),
        COLOR,
    );
}

// ── print_status_human (ASCII style) ─────────────────────────────────────────────────────

#[test]
fn test_print_status_ascii_inactive() {
    print_status_human(
        &inactive_report(),
        false,
        &PathBuf::from("/etc/nails.toml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
        &PathBuf::from("/mnt/hidden/logs"),
        ASCII,
    );
}

#[test]
fn test_print_status_ascii_active_basic() {
    print_status_human(
        &active_report(),
        false,
        &PathBuf::from("/etc/nails.toml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
        &PathBuf::from("/mnt/hidden/logs"),
        ASCII,
    );
}

#[test]
fn test_print_status_ascii_active_verbose_with_details() {
    print_status_human(
        &active_report_with_overlay_details(),
        true,
        &PathBuf::from("/etc/nails.toml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
        &PathBuf::from("/mnt/hidden/logs"),
        ASCII,
    );
}

#[test]
fn test_print_status_ascii_verbose_no_details() {
    print_status_human(
        &active_report(),
        true,
        &PathBuf::from("/etc/nails.toml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
        &PathBuf::from("/mnt/hidden/logs"),
        ASCII,
    );
}

#[test]
fn test_print_status_ascii_with_all_reminder_severities() {
    print_status_human(
        &active_report_with_reminders(),
        false,
        &PathBuf::from("/etc/nails.toml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
        &PathBuf::from("/mnt/hidden/logs"),
        ASCII,
    );
}

#[test]
fn test_print_status_ascii_with_logs() {
    use std::io::Write as _;
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("nails.log");
    let now = chrono::Utc::now();

    let mut f = std::fs::File::create(&log_path).unwrap();
    writeln!(
        f,
        r#"{{"timestamp":"{}","level":"INFO","fields":{{"message":"ascii log"}}}}"#,
        now.to_rfc3339()
    )
    .unwrap();
    drop(f);

    let mut report = active_report();
    report.activated_at = Some(now - chrono::Duration::hours(1));
    print_status_human(
        &report,
        false,
        &PathBuf::from("/etc/nails.toml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
        dir.path(),
        ASCII,
    );
}

#[test]
fn config_file_label_notes_missing_file() {
    let missing = PathBuf::from("/nonexistent/config/nails.toml");
    assert_eq!(
        super::config_file_label(&missing),
        "/nonexistent/config/nails.toml (not found, using defaults)"
    );

    let file = tempfile::NamedTempFile::new().unwrap();
    assert_eq!(
        super::config_file_label(file.path()),
        file.path().display().to_string()
    );
}

// ── posture & identity in JSON ───────────────────────────────────────────────

#[test]
fn test_status_json_carries_posture_state_source_and_overlay_identity() {
    let data = super::json::build_status_data(&active_report());
    let value = serde_json::to_value(&data).unwrap();

    assert_eq!(value["posture"], "active");
    assert_eq!(value["state_source"], "loaded");

    let home = &value["overlays"][0];
    assert_eq!(home["mount_point"], "/home");
    assert_eq!(home["owned"], true);
    assert_eq!(home["status"], "mounted");
    assert_eq!(home["upperdir"], "/mnt/hidden/home/.upper");

    let etc = &value["overlays"][1];
    assert_eq!(etc["owned"], false);
    assert_eq!(etc["status"], "not_mounted");
}

#[test]
fn test_status_json_degraded_carries_remaining_mounts_and_remediation() {
    let data = super::json::build_status_data(&active_report_with_reminders());
    let value = serde_json::to_value(&data).unwrap();

    assert_eq!(value["posture"], "degraded");
    assert_eq!(value["remaining_mounts"][0], "/home");
    assert!(
        value["remediation"]
            .as_str()
            .unwrap()
            .contains("nails emergency")
    );
}

#[test]
fn test_status_json_unknown_posture_for_untrusted_state() {
    let data = super::json::build_status_data_unknown("state file could not be read".to_string());
    let value = serde_json::to_value(&data).unwrap();

    assert_eq!(value["posture"], "unknown");
    assert_eq!(value["state"]["kind"], "unknown");
    assert_eq!(value["state_source"], "unreadable");
}

// ── recent logs: newest N, chronological, read-only ──────────────────────────

#[test]
fn test_recent_logs_show_newest_entries_chronologically_without_touching_file() {
    use std::io::Write as _;
    let dir = tempfile::tempdir().unwrap();
    let log_file = dir.path().join("nails.log");
    let base = chrono::Utc::now() - chrono::Duration::hours(1);

    // 30 INFO entries, each a minute apart and numbered in order.
    let mut f = std::fs::File::create(&log_file).unwrap();
    for i in 0..30 {
        let ts = (base + chrono::Duration::minutes(i)).to_rfc3339();
        writeln!(
            f,
            r#"{{"timestamp":"{ts}","level":"INFO","fields":{{"message":"entry {i:02}"}}}}"#
        )
        .unwrap();
    }
    drop(f);

    let size_before = std::fs::metadata(&log_file).unwrap().len();
    let mtime_before = std::fs::metadata(&log_file).unwrap().modified().unwrap();

    let logs = super::read_recent_logs(
        dir.path(),
        Some(base - chrono::Duration::hours(1)),
        false,
        ASCII,
    )
    .expect("logs should be present");

    // Only the newest 20 survive, and they stay in chronological order.
    assert_eq!(logs.len(), 20);
    assert!(logs[0].contains("entry 10"), "first: {}", logs[0]);
    assert!(logs[19].contains("entry 29"), "last: {}", logs[19]);
    assert!(!logs.iter().any(|l| l.contains("entry 09")));

    // Reading must not rewrite the log file.
    let size_after = std::fs::metadata(&log_file).unwrap().len();
    let mtime_after = std::fs::metadata(&log_file).unwrap().modified().unwrap();
    assert_eq!(size_before, size_after);
    assert_eq!(mtime_before, mtime_after);
}

#[test]
fn test_logs_hidden_for_decoy_posture_unless_details() {
    use std::io::Write as _;
    let dir = tempfile::tempdir().unwrap();
    let now = chrono::Utc::now();
    let mut f = std::fs::File::create(dir.path().join("nails.log")).unwrap();
    writeln!(
        f,
        r#"{{"timestamp":"{}","level":"INFO","fields":{{"message":"decoy log"}}}}"#,
        now.to_rfc3339()
    )
    .unwrap();
    drop(f);

    // A decoy report prints no log section without --details (smoke: must not panic).
    print_status_human(
        &inactive_report(),
        false,
        &PathBuf::from("/etc/nails.toml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
        dir.path(),
        ASCII,
    );
}

#[test]
fn test_status_json_reports_persistent_decoy_flag() {
    // A volatile decoy reports the flag false and stays fully secure.
    let data = super::json::build_status_data(&active_report());
    let value = serde_json::to_value(&data).unwrap();
    assert_eq!(value["posture"], "active");
    assert_eq!(value["decoy_persistent"], false);

    // A persistent decoy surfaces the flag so an Active posture never reads as
    // fully secure downstream.
    let mut report = active_report();
    report.decoy_persistent = true;
    let data = super::json::build_status_data(&report);
    let value = serde_json::to_value(&data).unwrap();
    assert_eq!(value["posture"], "active");
    assert_eq!(value["decoy_persistent"], true);
}

#[test]
fn test_posture_lines_warn_on_persistent_decoy() {
    let mut report = active_report();
    report.overlay_verification = VerificationStatus::Verified;
    report.decoy_persistent = true;
    let lines = super::human::posture_lines(&report, ASCII);
    assert!(
        lines.iter().any(|l| l.contains("PERSISTENT DECOY")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("--accept-persistent-decoy")),
        "{lines:?}"
    );
}

fn sample_last_deactivation() -> nails_core::LastDeactivationReport {
    use nails_core::{CleanupReport, DeactivationReport, LastDeactivationReport};

    let teardown = DeactivationReport {
        cleanup_report: CleanupReport::default(),
        unmounted_overlays: vec!["/home".to_string(), "/etc".to_string()],
        failed_overlays: Vec::new(),
        remaining_mounts: Vec::new(),
        duration: std::time::Duration::from_millis(1500),
        final_state: SystemState::Inactive,
        was_already_inactive: false,
        post_unmount_cleanup: nails_core::PostUnmountCleanupReport::default(),
        force_detached_overlays: Vec::new(),
        page_cache_dropped: false,
        history_truncation_verified: None,
        runtime_journal_scrubbed: true,
        reboot_recommended: false,
    };
    LastDeactivationReport::from_report(&teardown, "2026-10-06T00:00:00Z")
}

#[test]
fn test_status_json_includes_last_deactivation_when_present() {
    // Absent by default, so the key is omitted entirely.
    let data = super::json::build_status_data(&inactive_report());
    let value = serde_json::to_value(&data).unwrap();
    assert!(value.get("last_deactivation").is_none());

    // Present when the report was surfaced by status.
    let mut report = inactive_report();
    report.last_deactivation = Some(sample_last_deactivation());
    let data = super::json::build_status_data(&report);
    let value = serde_json::to_value(&data).unwrap();
    assert_eq!(value["last_deactivation"]["status"], "Secure");
    assert_eq!(value["last_deactivation"]["outcome"]["successful"], true);
    assert_eq!(value["last_deactivation"]["duration_ms"], 1500);
}

#[test]
fn test_print_status_human_renders_last_deactivation() {
    // Smoke test: the human renderer handles a surfaced report without panicking.
    let mut report = inactive_report();
    report.last_deactivation = Some(sample_last_deactivation());
    print_status_human(
        &report,
        false,
        &PathBuf::from("/etc/nails.toml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
        &PathBuf::from("/mnt/hidden/logs"),
        COLOR,
    );
}

#[test]
fn activation_in_flight_lines_show_elapsed_without_a_progress_record() {
    let started_at = chrono::Utc::now() - chrono::Duration::seconds(65);
    let report = StatusReport {
        state: SystemState::Activating { started_at },
        posture: Posture::Transitioning,
        activation_in_flight: Some(nails_core::status::ActivationInFlight::new(
            started_at,
            started_at + chrono::Duration::seconds(65),
            None,
        )),
        ..Default::default()
    };
    assert_eq!(
        super::human::activation_in_flight_lines(&report, ASCII),
        vec!["Activation:         in progress: 1m05s".to_string()]
    );
    assert!(super::human::activation_in_flight_lines(&inactive_report(), ASCII).is_empty());
}

#[test]
fn last_activation_line_is_omitted_before_the_first_activation() {
    assert_eq!(super::human::last_activation_line(&inactive_report()), None);
}
