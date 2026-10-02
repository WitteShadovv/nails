use super::*;
use nails_core::output::Style;
use nails_core::status::{
    OpSecReminder, OverlayMountStatus, ReminderSeverity, StatusReport, VerificationStatus,
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
        overlays: vec![],
        overlay_verification: VerificationStatus::NotApplicable,
        nixos_generation: None,
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
        },
        overlays: vec![PathBuf::from("/home"), PathBuf::from("/etc")],
        overlay_verification: VerificationStatus::Verified,
        nixos_generation: Some("nails-gen-42".to_string()),
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
            },
            OverlayMountStatus {
                path: PathBuf::from("/etc"),
                expected_mounted: true,
                actually_mounted: false,
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
        },
        overlays: vec![PathBuf::from("/home")],
        overlay_verification: VerificationStatus::Verified,
        nixos_generation: None,
        activated_at: Some(now),
        uptime: Some(chrono::Duration::minutes(30)),
        formatted_uptime: "30 minutes".to_string(),
        opsec_reminders: vec![],
        overlay_details: Some(overlay_details),
        overlay_mount_statuses: vec![OverlayMountStatus {
            path: PathBuf::from("/home"),
            expected_mounted: true,
            actually_mounted: true,
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
        },
        overlays: vec![],
        overlay_verification: VerificationStatus::Mismatch {
            errors: vec!["overlay mismatch".to_string()],
        },
        nixos_generation: None,
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
            remaining_mounts: vec![],
        },
        overlays: vec![],
        overlay_verification: VerificationStatus::Skipped,
        nixos_generation: None,
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
