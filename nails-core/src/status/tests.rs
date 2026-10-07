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
        session_units: Vec::new(),
        backend: Vec::new(),
        tools: Tools::default(),
        armed: None,
        entered_at: Some(1_700_000_000),
    }
}

fn command(root: &Path) -> StatusCommand<RealFilesystem> {
    let config = Config {
        hidden_volume_root: root.to_path_buf(),
        state_file_path: root.join("state.json"),
        log_path: root.join("logs"),
        ..Config::test_default()
    };
    StatusCommand::new(RealFilesystem, config, root.join("state.json"))
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
    assert!(r.unwrap().contains("nails recover"));
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
fn a_tampered_state_file_on_the_decoy_is_unknown() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("state.json"), "{ not json").unwrap();
    let report = command(dir.path())
        .report(&SessionView::Decoy, &[], Utc::now())
        .unwrap();
    assert_eq!(report.posture, Posture::Unknown);
    assert_eq!(report.state_source, "corrupt");
    assert_eq!(report.uptime, None);
}
