// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::RealFilesystem;
use nails_teardown::mountinfo::parse_mountinfo;
use nails_teardown::whole_root::plan::{DecoyRoot, PLAN_VERSION, PolicyMount, RootSide, Tools};

fn plan(root: &Path) -> Plan {
    let side = RootSide {
        init: PathBuf::from("/run/current-system/systemd/lib/systemd/systemd"),
        system: Some(PathBuf::from("/nix/store/bbb-nixos-system")),
    };
    Plan {
        version: PLAN_VERSION,
        hidden_root: root.to_path_buf(),
        hidden_dev: None,
        accepted_decoy_storage: None,
        upper: root.join("root/upper"),
        work: root.join("root/work"),
        owner: None,
        decoy_root: DecoyRoot {
            source: PathBuf::from("/dev/vda2"),
            fstype: "ext4".into(),
            data: None,
        },
        decoy: RootSide {
            system: Some(PathBuf::from("/nix/store/aaa-nixos-system")),
            ..side.clone()
        },
        hidden: side,
        policy_mounts: vec![PolicyMount {
            target: PathBuf::from("/boot"),
            kind: PolicyMountKind::ReadOnlyBind,
        }],
        masks: vec!["dev-vda3.swap".into()],
        boot_masks: Vec::new(),
        generator_masks: Vec::new(),
        skips: Vec::new(),
        session_units: Vec::new(),
        backend: Vec::new(),
        tools: Tools::default(),
        armed: None,
        entered_at: Some(1_700_000_000),
        run_noexec: false,
        carried: Vec::new(),
        decoy_mounts: Vec::new(),
        read_only_disks: false,
        failed_at_entry: Vec::new(),
        kernel_settings: Vec::new(),
    }
}

/// The scratch `/` and `/run` a status command under `root` reads.
fn paths(root: &Path) -> Paths {
    Paths {
        root: root.join("decoy"),
        run: root.join("run"),
    }
}

fn command(root: &Path) -> StatusCommand<RealFilesystem> {
    let config = Config {
        hidden_volume_root: root.to_path_buf(),
        state_file_path: root.join("state.json"),
        log_path: root.join("logs"),
        ..Config::test_default()
    };
    StatusCommand::new(RealFilesystem, config, root.join("state.json")).with_paths(paths(root))
}

/// Keep a refused switch's record in `dir`, as the transition does.
fn refused_in(dir: &Path, reason: &str, at: u64) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        switch_refusal::refusal_path(dir),
        serde_json::json!({ "reason": reason, "at": at }).to_string(),
    )
    .unwrap();
}

#[test]
fn the_hidden_session_reports_active_with_its_uptime_policy_and_system() {
    let dir = tempfile::tempdir().unwrap();
    let cmd = command(dir.path());
    let view = SessionView::Hidden(Box::new(plan(dir.path())));
    let table = format!(
        "1 0 0:40 / / rw - overlay overlay rw,upperdir={}/root/upper\n2 1 253:0 / {} rw - ext4 /dev/mapper/data rw\n",
        dir.path().display(),
        dir.path().display()
    );
    let now = DateTime::<Utc>::from_timestamp(1_700_000_000 + 7 * 3600, 0).unwrap();
    let report = cmd.report(&view, &parse_mountinfo(&table), now).unwrap();
    assert_eq!(report.posture, Posture::Active);
    assert_eq!(report.session, "hidden");
    assert_eq!(report.uptime, Some(Duration::hours(7)));
    assert_eq!(
        report.hidden_system.as_deref(),
        Some("/nix/store/bbb-nixos-system")
    );
    assert_eq!(report.policy_mounts[0].kind, "read-only");
    assert_eq!(report.masked_units, ["dev-vda3.swap"]);
    assert!(report.hidden_root_mounted);
    assert_eq!(
        report.hidden_root_source.as_deref(),
        Some("/dev/mapper/data")
    );
    assert!(!report.opsec_reminders.is_empty(), "6 h and more remind");
}

fn covered_by(report: &StatusReport) -> Option<&str> {
    report
        .hidden_root_covered_by
        .as_ref()
        .map(|cover| cover.source.as_str())
}

#[test]
fn a_disk_mounted_over_the_hidden_volume_is_named() {
    let dir = tempfile::tempdir().unwrap();
    let cmd = command(dir.path());
    let mut recorded = plan(dir.path());
    recorded.hidden_dev = Some("253:0".into());
    let view = SessionView::Hidden(Box::new(recorded));
    let root = dir.path().display();
    let volume = format!(
        "1 0 0:40 / / rw - overlay overlay rw,upperdir={root}/root/upper
\
         2 1 253:0 / {root} rw - ext4 /dev/mapper/data rw
"
    );
    let report = cmd
        .report(&view, &parse_mountinfo(&volume), Utc::now())
        .unwrap();
    assert_eq!(report.hidden_root_covered_by, None);

    let covered = format!(
        "{volume}3 2 8:33 / {root} rw - vfat /dev/sdc1 rw
"
    );
    let report = cmd
        .report(&view, &parse_mountinfo(&covered), Utc::now())
        .unwrap();
    assert_eq!(covered_by(&report), Some("/dev/sdc1"));
    // A plan without the device still loads; the stack shows the cover.
    let report = cmd
        .report(
            &SessionView::Hidden(Box::new(plan(dir.path()))),
            &parse_mountinfo(&covered),
            Utc::now(),
        )
        .unwrap();
    assert_eq!(covered_by(&report), Some("/dev/sdc1"));
}

#[test]
fn a_cover_is_found_through_a_symlinked_root_and_on_its_parent() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().canonicalize().unwrap();
    let volume_dir = base.join("mnt/data");
    std::fs::create_dir_all(&volume_dir).unwrap();
    let link = base.join("hidden");
    std::os::unix::fs::symlink(&volume_dir, &link).unwrap();
    let cmd = command(&link);
    let mut recorded = plan(&link);
    recorded.hidden_dev = Some("253:0".into());
    let view = SessionView::Hidden(Box::new(recorded));
    let (base, volume_dir) = (base.display(), volume_dir.display());
    let volume = format!(
        "1 0 0:40 / / rw - overlay overlay rw\n\
         2 1 253:0 / {volume_dir} rw - ext4 /dev/mapper/data rw\n"
    );
    let report = cmd
        .report(&view, &parse_mountinfo(&volume), Utc::now())
        .unwrap();
    assert!(
        report.hidden_root_mounted,
        "the link resolves to the volume"
    );
    assert_eq!(report.hidden_root_covered_by, None);

    let covered = format!("{volume}3 2 8:33 / {volume_dir} rw - vfat /dev/sdc1 rw\n");
    let report = cmd
        .report(&view, &parse_mountinfo(&covered), Utc::now())
        .unwrap();
    assert_eq!(covered_by(&report), Some("/dev/sdc1"));

    // A stick on a parent of the volume hides it as well.
    let on_parent = format!("{volume}4 1 8:49 / {base}/mnt rw - vfat /dev/sdd1 rw\n");
    let report = cmd
        .report(&view, &parse_mountinfo(&on_parent), Utc::now())
        .unwrap();
    assert_eq!(covered_by(&report), Some("/dev/sdd1"));
    assert_eq!(
        report.hidden_root_covered_by.unwrap().mount_point,
        Path::new(&format!("{base}/mnt"))
    );
}

#[test]
fn every_live_view_maps_to_its_posture_and_remedy() {
    let (p, _, r) = posture_of(
        &SessionView::Interrupted {
            plan: None,
            nextroot_mounted: true,
        },
        false,
    );
    assert_eq!(p, Posture::Degraded);
    let r = r.unwrap();
    assert!(r.contains("sudo ") && r.contains("recover"), "{r}");
    let (p, _, r) = posture_of(&SessionView::HiddenWithoutPlan("x".into()), false);
    assert_eq!(p, Posture::Degraded);
    assert!(r.unwrap().contains("Power off"));
    assert_eq!(posture_of(&SessionView::Decoy, false).0, Posture::Decoy);
    assert_eq!(posture_of(&SessionView::Decoy, true).0, Posture::Unknown);
    // A corrupt record never hides a live hidden session.
    let dir = tempfile::tempdir().unwrap();
    let hidden = SessionView::Hidden(Box::new(plan(dir.path())));
    assert_eq!(posture_of(&hidden, true).0, Posture::Active);
}

#[test]
fn an_active_record_on_the_plain_decoy_is_explained_with_its_remedy() {
    // A hard reset in the session: the decoy boots, the record still says Active.
    let dir = tempfile::tempdir().unwrap();
    let record = StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
        },
        ..StateFile::default()
    };
    record
        .save_with_custom_root(&dir.path().join("state.json"), dir.path())
        .unwrap();
    let report = command(dir.path())
        .report(&SessionView::Decoy, &[], Utc::now())
        .unwrap();
    assert_eq!(report.posture, Posture::Decoy);
    assert!(
        report
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("none is running")),
        "{:?}",
        report.reason
    );
    let remediation = report.remediation.as_deref().expect("a remedy");
    assert!(
        remediation.contains("sudo ") && remediation.contains("recover"),
        "{remediation}"
    );
    assert!(
        remediation.ends_with("recover` to reset the record"),
        "{remediation}"
    );

    assert_eq!(report.switch_refusal, None);

    // An inactive record on the decoy needs no word.
    StateFile::default()
        .save_with_custom_root(&dir.path().join("state.json"), dir.path())
        .unwrap();
    let report = command(dir.path())
        .report(&SessionView::Decoy, &[], Utc::now())
        .unwrap();
    assert_eq!((report.reason, report.remediation), (None, None));
}

#[test]
fn an_entry_the_soft_reboot_refused_is_named_with_its_reason_and_time() {
    // The entry recorded Active before the soft-reboot, the transition refused
    // the switch and kept why on the hidden volume: the record is explained by
    // the refusal, not by a power loss.
    let dir = tempfile::tempdir().unwrap();
    StateFile {
        state: SystemState::Active {
            activated_at: Utc::now(),
        },
        ..StateFile::default()
    }
    .save_with_custom_root(&dir.path().join("state.json"), dir.path())
    .unwrap();
    refused_in(dir.path(), "the next root has no os-release", 1_700_000_000);

    let report = command(dir.path())
        .report(&SessionView::Decoy, &[], Utc::now())
        .unwrap();

    assert_eq!(report.posture, Posture::Decoy);
    assert_eq!(
        report.switch_refusal,
        Some(RefusedSwitch {
            reason: "the next root has no os-release".to_string(),
            at: DateTime::<Utc>::from_timestamp(1_700_000_000, 0).unwrap(),
        })
    );
    let reason = report.reason.expect("the record is explained");
    assert!(
        reason.ends_with("the switch into it was refused"),
        "{reason}"
    );
    assert!(!reason.contains("power loss"), "{reason}");
    assert!(
        report
            .remediation
            .is_some_and(|r| r.ends_with("recover` to reset the record")),
        "the record still needs resetting"
    );

    // Once the record is reset the refusal is still reported, until a new
    // switch clears it.
    StateFile::default()
        .save_with_custom_root(&dir.path().join("state.json"), dir.path())
        .unwrap();
    let report = command(dir.path())
        .report(&SessionView::Decoy, &[], Utc::now())
        .unwrap();
    assert_eq!((report.reason, report.remediation), (None, None));
    assert!(report.switch_refusal.is_some());
}

#[test]
fn a_way_back_the_soft_reboot_refused_is_read_from_the_runtime_directory() {
    // In the hidden session the volume is no longer mounted at its path: the
    // transition kept the reason in the runtime directory instead.
    let dir = tempfile::tempdir().unwrap();
    let cmd = command(dir.path());
    refused_in(
        &paths(dir.path()).runtime(),
        "the decoy's init does not resolve",
        1_700_000_060,
    );
    let view = SessionView::Hidden(Box::new(plan(dir.path())));

    let report = cmd.report(&view, &[], Utc::now()).unwrap();

    assert_eq!(report.posture, Posture::Active);
    let refused = report.switch_refusal.expect("the refused way back");
    assert_eq!(refused.reason, "the decoy's init does not resolve");
    assert_eq!(refused.at.timestamp(), 1_700_000_060);
    // Without the scratch tree, the system's runtime directory is read.
    assert_eq!(
        StatusCommand::new(RealFilesystem, Config::test_default(), dir.path().join("x")).paths,
        Paths::system()
    );
}

#[test]
fn a_tampered_state_file_on_the_decoy_is_unknown() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("state.json"), "{ not json").unwrap();
    let report = command(dir.path())
        .report(&SessionView::Decoy, &[], Utc::now())
        .unwrap();
    assert_eq!(report.posture, Posture::Unknown);
    assert_eq!(report.state_source, "corrupt");
    assert!(report.record_unreadable());
    assert_eq!(report.uptime, None);
}

/// In the hidden session the live view stays the verdict, but a corrupt
/// record is still reported, with what to do about it before the next
/// activation.
#[test]
fn a_tampered_state_file_in_the_hidden_session_is_reported_with_its_remedy() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("state.json"), "{ not json").unwrap();
    let view = SessionView::Hidden(Box::new(plan(dir.path())));
    let report = command(dir.path()).report(&view, &[], Utc::now()).unwrap();
    assert_eq!(report.posture, Posture::Active);
    assert!(report.record_unreadable(), "{}", report.state_source);
    let remediation = report.remediation.as_deref().expect("a remedy");
    assert!(
        remediation.contains("sudo ")
            && remediation.contains(" verify` and check the hidden volume"),
        "{remediation}"
    );

    // A readable record leaves the hidden session without a remedy.
    StateFile::default()
        .save_with_custom_root(&dir.path().join("state.json"), dir.path())
        .unwrap();
    let report = command(dir.path()).report(&view, &[], Utc::now()).unwrap();
    assert!(!report.record_unreadable());
    assert_eq!(report.remediation, None);
}

#[test]
fn uptime_reads_in_the_largest_two_units_with_singular_and_plural() {
    assert_eq!(format_uptime(Duration::zero()), "0 minutes");
    assert_eq!(format_uptime(Duration::seconds(59)), "0 minutes");
    assert_eq!(format_uptime(Duration::minutes(1)), "1 minute");
    assert_eq!(format_uptime(Duration::minutes(59)), "59 minutes");
    assert_eq!(format_uptime(Duration::hours(1)), "1 hour");
    assert_eq!(
        format_uptime(Duration::hours(1) + Duration::minutes(1)),
        "1 hour 1 minute"
    );
    assert_eq!(
        format_uptime(Duration::hours(23) + Duration::minutes(59)),
        "23 hours 59 minutes"
    );
    assert_eq!(format_uptime(Duration::days(1)), "1 day");
    // Past a day the minutes are dropped, even when there are no hours.
    assert_eq!(
        format_uptime(Duration::days(1) + Duration::minutes(30)),
        "1 day"
    );
    assert_eq!(
        format_uptime(Duration::days(1) + Duration::hours(1) + Duration::minutes(5)),
        "1 day 1 hour"
    );
    assert_eq!(format_uptime(Duration::days(365)), "365 days");
}

#[test]
fn a_negative_uptime_from_clock_skew_reads_as_zero() {
    assert_eq!(format_uptime(Duration::hours(-3)), "0 minutes");
}

#[test]
fn reminders_accumulate_at_six_twelve_and_twenty_four_hours() {
    let severities = |uptime| {
        generate_opsec_reminders(uptime, true)
            .into_iter()
            .map(|r| r.severity)
            .collect::<Vec<_>>()
    };
    assert!(severities(Duration::hours(5) + Duration::minutes(59)).is_empty());
    assert_eq!(severities(Duration::hours(6)), [ReminderSeverity::Info]);
    assert_eq!(
        severities(Duration::hours(12)),
        [ReminderSeverity::Info, ReminderSeverity::Warning]
    );
    assert_eq!(
        severities(Duration::hours(24)),
        [
            ReminderSeverity::Info,
            ReminderSeverity::Warning,
            ReminderSeverity::Critical
        ]
    );

    let critical = &generate_opsec_reminders(Duration::days(3), true)[2];
    assert_eq!(
        critical.message,
        "Session >24 hours - strongly recommend deactivation"
    );
}

#[test]
fn disabled_reminders_stay_silent_however_long_the_session() {
    assert_eq!(generate_opsec_reminders(Duration::days(30), false), []);
}

#[test]
fn each_severity_has_its_label_and_shared_mark() {
    for (severity, label, plain, mark) in [
        (ReminderSeverity::Info, "INFO", "[INFO]", crate::Mark::Info),
        (
            ReminderSeverity::Warning,
            "WARNING",
            "[WARNING]",
            crate::Mark::Warn,
        ),
        (
            ReminderSeverity::Critical,
            "CRITICAL",
            "[CRITICAL]",
            crate::Mark::Fail,
        ),
    ] {
        assert_eq!(severity.to_string(), label);
        assert_eq!(severity.to_plain(), plain);
        assert_eq!(severity.mark(), mark);
    }
}

#[test]
fn a_reminder_renders_its_label_in_ascii_and_its_mark_otherwise() {
    let reminder = OpSecReminder {
        severity: ReminderSeverity::Warning,
        message: "Extended session".to_string(),
    };
    assert_eq!(reminder.to_plain(), "[WARNING] Extended session");

    let ascii = crate::Style {
        color: true,
        ascii: true,
    };
    // ASCII output keeps the reminder's own label, uncoloured, rather than the
    // generic `[WARN]` mark.
    assert_eq!(reminder.render(ascii), "[WARNING] Extended session");

    let unicode = crate::Style {
        color: false,
        ascii: false,
    };
    assert_eq!(reminder.render(unicode), "⚠ Extended session");
    assert_eq!(reminder.to_string(), "⚠ Extended session");

    let coloured = crate::Style {
        color: true,
        ascii: false,
    };
    assert_eq!(
        reminder.render(coloured),
        "\x1b[1;33m⚠\x1b[0m Extended session"
    );
}

#[test]
fn a_reminder_round_trips_through_json() {
    let reminder = OpSecReminder {
        severity: ReminderSeverity::Critical,
        message: "Session >24 hours".to_string(),
    };
    let json = serde_json::to_string(&reminder).unwrap();
    assert_eq!(
        json,
        r#"{"severity":"Critical","message":"Session >24 hours"}"#
    );
    let back: OpSecReminder = serde_json::from_str(&json).unwrap();
    assert_eq!(back, reminder);
}
