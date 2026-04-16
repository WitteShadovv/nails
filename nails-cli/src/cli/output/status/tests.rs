use super::*;
use nails_core::SystemState;
use nails_core::status::{
    OpSecReminder, OverlayMountStatus, ReminderSeverity, StatusReport, VerificationStatus,
};
use std::path::PathBuf;

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
    }
}

fn emergency_report() -> StatusReport {
    let now = chrono::Utc::now();
    StatusReport {
        state: SystemState::Emergency { triggered_at: now },
        overlays: vec![],
        overlay_verification: VerificationStatus::Skipped,
        nixos_generation: None,
        activated_at: None,
        uptime: None,
        formatted_uptime: String::new(),
        opsec_reminders: vec![],
        overlay_details: None,
        overlay_mount_statuses: vec![],
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
fn test_print_status_json_emergency() {
    print_status_json(&emergency_report());
}

// ── print_status_human ─────────────────────────────────────────────────────

#[test]
fn test_print_status_human_inactive() {
    print_status_human(
        &inactive_report(),
        false,
        &PathBuf::from("/etc/nails.yaml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
    );
}

#[test]
fn test_print_status_human_active_basic() {
    print_status_human(
        &active_report(),
        false,
        &PathBuf::from("/etc/nails.yaml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
    );
}

#[test]
fn test_print_status_human_active_verbose_with_details() {
    print_status_human(
        &active_report_with_overlay_details(),
        true,
        &PathBuf::from("/etc/nails.yaml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
    );
}

#[test]
fn test_print_status_human_active_verbose_no_details() {
    print_status_human(
        &active_report(),
        true,
        &PathBuf::from("/etc/nails.yaml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
    );
}

#[test]
fn test_print_status_human_with_reminders() {
    print_status_human(
        &active_report_with_reminders(),
        false,
        &PathBuf::from("/etc/nails.yaml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
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
        &PathBuf::from("/etc/nails.yaml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        dir.path(),
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
        &PathBuf::from("/etc/nails.yaml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        dir.path(),
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
        &PathBuf::from("/etc/nails.yaml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        dir.path(),
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
        &PathBuf::from("/etc/nails.yaml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        dir.path(),
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
        &PathBuf::from("/etc/nails.yaml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        dir.path(),
    );
}

// ── print_status_ascii ─────────────────────────────────────────────────────

#[test]
fn test_print_status_ascii_inactive() {
    print_status_ascii(
        &inactive_report(),
        false,
        &PathBuf::from("/etc/nails.yaml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
    );
}

#[test]
fn test_print_status_ascii_active_basic() {
    print_status_ascii(
        &active_report(),
        false,
        &PathBuf::from("/etc/nails.yaml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
    );
}

#[test]
fn test_print_status_ascii_active_verbose_with_details() {
    print_status_ascii(
        &active_report_with_overlay_details(),
        true,
        &PathBuf::from("/etc/nails.yaml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
    );
}

#[test]
fn test_print_status_ascii_verbose_no_details() {
    print_status_ascii(
        &active_report(),
        true,
        &PathBuf::from("/etc/nails.yaml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
    );
}

#[test]
fn test_print_status_ascii_with_all_reminder_severities() {
    print_status_ascii(
        &active_report_with_reminders(),
        false,
        &PathBuf::from("/etc/nails.yaml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        &PathBuf::from("/mnt/hidden"),
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
    print_status_ascii(
        &report,
        false,
        &PathBuf::from("/etc/nails.yaml"),
        &PathBuf::from("/mnt/hidden/state.json"),
        dir.path(),
    );
}
