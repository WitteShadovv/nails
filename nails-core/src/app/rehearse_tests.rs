// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the `rehearse` service: the guided next step, the live
//! session, the plant and same-session checks, the offline scan, and the
//! views an outcome carries in place of the token.

use super::*;

/// A canary planted in the session entered at 100, in boot `b1`.
fn planted() -> RehearsalState {
    RehearsalState {
        schema_version: 1,
        token: "0".repeat(32),
        phase: Phase::Planted,
        planted_at: "2026-10-15T20:00:00Z".to_string(),
        planted_boot_id: Some("b1".to_string()),
        planted_entered_at: Some(100),
        planted_soft_reboots: None,
        channels: Vec::new(),
        scans: Vec::new(),
    }
}

/// The same canary, after a scan has run.
fn scanned() -> RehearsalState {
    RehearsalState {
        phase: Phase::Scanned,
        ..planted()
    }
}

fn in_session(entered_at: u64) -> Here {
    Here {
        session: Some(LiveSession {
            entered_at: Some(entered_at),
        }),
        boot_id: Some("b1".to_string()),
        soft_reboots: None,
    }
}

/// The view a command run `here` gets of `state`.
fn view(state: &RehearsalState, here: &Here) -> RehearsalView {
    RehearsalView::of(state, here)
}

/// A rehearsal whose token is in a planted file's name, its path and its
/// copy in the upper, and in a skipped channel's reason.
fn with_token_everywhere() -> RehearsalState {
    let token = HEX_TOKEN.to_string();
    RehearsalState {
        token: token.clone(),
        channels: vec![
            rehearse::ChannelRecord {
                kind: rehearse::ChannelKind::OverlayFile,
                location: format!("/var/tmp/rehearse-{token}"),
                upper_copy: Some(PathBuf::from(format!(
                    "/mnt/data/root/upper/var/tmp/rehearse-{token}"
                ))),
                skipped: None,
            },
            rehearse::ChannelRecord {
                kind: rehearse::ChannelKind::Notification,
                location: "desktop notification".to_string(),
                upper_copy: None,
                skipped: Some(format!("no session bus for {token}")),
            },
        ],
        ..planted()
    }
}

/// A view carries the fingerprint and the redacted channels, never the
/// token: printed with `Debug` it shows no trace of it.
#[test]
fn a_view_carries_the_fingerprint_and_never_the_token() {
    let state = with_token_everywhere();
    let view = view(&state, &Here::default());
    assert_eq!(view.fingerprint, rehearse::fingerprint(HEX_TOKEN));
    assert_eq!(view.channels, state.redacted_channels());
    assert_eq!(view.planted_at, state.planted_at);
    let shown = format!("{view:?}");
    assert!(!shown.contains(HEX_TOKEN), "{shown}");
    assert!(shown.contains("rehearse-<canary>"), "{shown}");
}

/// The status read from the hidden volume carries the view, not the state.
#[test]
fn the_status_outcome_carries_no_token() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(rehearse::REHEARSE_DIR)).unwrap();
    std::fs::write(
        dir.path().join(rehearse::state_relative_path()),
        serde_json::to_string(&with_token_everywhere()).unwrap(),
    )
    .unwrap();
    let outcome = rooted_at(dir.path())
        .status()
        .map_err(|e| e.message)
        .unwrap();
    let rehearsal = outcome.rehearsal.expect("a rehearsal is recorded");
    assert!(!format!("{rehearsal:?}").contains(HEX_TOKEN));
    assert_eq!(rehearsal.fingerprint, rehearse::fingerprint(HEX_TOKEN));
}

/// The removed paths name the canary's files with the token redacted.
#[test]
fn the_removed_paths_are_redacted() {
    let removed = vec![
        PathBuf::from(format!("/mnt/data/root/upper/var/tmp/rehearse-{HEX_TOKEN}")),
        PathBuf::from("/mnt/data/rehearse/state.json"),
    ];
    assert_eq!(
        redacted(removed, HEX_TOKEN),
        [
            PathBuf::from("/mnt/data/root/upper/var/tmp/rehearse-<canary>"),
            PathBuf::from("/mnt/data/rehearse/state.json"),
        ]
    );
}

/// The view decides the next step by whether its command runs in the
/// planting session, as the state does.
#[test]
fn a_view_knows_whether_it_was_read_in_the_planting_session() {
    assert!(view(&planted(), &in_session(100)).planted_here);
    assert!(!view(&planted(), &in_session(200)).planted_here);
    assert!(!view(&planted(), &Here::default()).planted_here);
}

/// A well-formed rehearsal token (32 hex digits).
const HEX_TOKEN: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"; // pragma: allowlist secret

/// A rehearsal service whose hidden root is an empty scratch directory, so
/// the offline scan and token paths never touch a real hidden volume.
fn rooted_at(root: &std::path::Path) -> Rehearsal {
    Rehearsal::new(Config {
        hidden_volume_root: root.to_path_buf(),
        ..Config::test_default()
    })
}

#[test]
fn phase_name_is_the_exact_contract_string_for_every_state() {
    let here = Here::default();
    assert_eq!(phase_name(None), "none");
    assert_eq!(phase_name(Some(&view(&planted(), &here))), "planted");
    assert_eq!(phase_name(Some(&view(&scanned(), &here))), "scanned");
}

#[test]
fn next_step_with_no_canary_in_a_session_guides_plant_in_this_session() {
    let guide = next_step(None, &in_session(100));
    assert!(
        guide.contains("in this hidden session"),
        "plant-active guidance: {guide}"
    );
}

#[test]
fn next_step_with_no_canary_on_the_decoy_guides_activate_first() {
    let guide = next_step(None, &Here::default());
    assert!(
        guide.contains("activate a hidden session"),
        "plant-inactive guidance: {guide}"
    );
}

#[test]
fn next_step_after_planting_in_this_session_guides_deactivate_then_scan() {
    let here = in_session(100);
    let guide = next_step(Some(&view(&planted(), &here)), &here);
    assert!(
        guide.contains("Step 2 of 3"),
        "scan-next-session guidance: {guide}"
    );
}

#[test]
fn next_step_after_planting_in_an_earlier_session_guides_scan_now() {
    let here = in_session(200);
    let guide = next_step(Some(&view(&planted(), &here)), &here);
    assert!(guide.contains("Step 3 of 3"), "scan-now guidance: {guide}");
}

#[test]
fn next_step_after_a_scan_guides_done_and_reset() {
    let here = in_session(100);
    let guide = next_step(Some(&view(&scanned(), &here)), &here);
    assert!(guide.contains("Done. Scan again"), "done guidance: {guide}");
}

#[test]
fn load_reads_the_rehearsal_state_written_under_the_hidden_root() {
    let dir = tempfile::tempdir().unwrap();
    let state = planted();
    std::fs::create_dir_all(dir.path().join(rehearse::REHEARSE_DIR)).unwrap();
    std::fs::write(
        dir.path().join(rehearse::state_relative_path()),
        serde_json::to_string(&state).unwrap(),
    )
    .unwrap();
    let loaded = rooted_at(dir.path()).load().unwrap();
    assert_eq!(loaded.expect("a state file is present").token, state.token);
}

#[test]
fn status_outside_a_hidden_session_reports_no_live_session() {
    // The hidden root is an unmounted scratch directory, so the live probe
    // of the real system finds the decoy, not a hidden session: `status`
    // must carry no live session. This pins `live_session`'s `None` result
    // outside a session against a mutant that always reports one.
    let dir = tempfile::tempdir().unwrap();
    // RehearseFailure is not Debug, so carry only its message into unwrap.
    let outcome = rooted_at(dir.path())
        .status()
        .map_err(|e| e.message)
        .unwrap();
    assert!(
        outcome.here.session.is_none(),
        "no hidden session is mounted at the scratch root, so none is reported"
    );
}

#[test]
fn scan_token_reads_and_trims_a_valid_token_from_the_token_file() {
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("token");
    std::fs::write(&token_file, format!("  {HEX_TOKEN}\n")).unwrap();
    let options = ScanOptions {
        token_file: Some(token_file),
        offline: true,
        ..ScanOptions::default()
    };
    let (token, state) = rooted_at(dir.path()).scan_token(&options).unwrap();
    assert_eq!(token, HEX_TOKEN);
    assert!(state.is_none(), "a token-file scan carries no state");
}

#[test]
fn scan_token_rejects_a_token_file_that_holds_no_valid_token() {
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("token");
    std::fs::write(&token_file, "not-a-valid-token!!").unwrap();
    let options = ScanOptions {
        token_file: Some(token_file),
        offline: true,
        ..ScanOptions::default()
    };
    let err = rooted_at(dir.path())
        .scan_token(&options)
        .expect_err("an invalid token must be refused");
    assert!(err.contains("no valid token"), "{err}");
}

#[test]
fn scan_targets_offline_reads_the_given_images() {
    let dir = tempfile::tempdir().unwrap();
    let images = vec![PathBuf::from("/x/a.img"), PathBuf::from("/x/b.img")];
    let options = ScanOptions {
        offline: true,
        images: images.clone(),
        ..ScanOptions::default()
    };
    let targets = rooted_at(dir.path()).scan_targets(&options).unwrap();
    assert_eq!(
        targets.iter().map(|t| t.device.clone()).collect::<Vec<_>>(),
        images
    );
}

#[test]
fn scan_targets_live_uses_the_explicit_devices_when_given() {
    let dir = tempfile::tempdir().unwrap();
    let device = PathBuf::from("/dev/nails-mutant-canary-device");
    let options = ScanOptions {
        offline: false,
        devices: vec![device.clone()],
        ..ScanOptions::default()
    };
    let targets = rooted_at(dir.path()).scan_targets(&options).unwrap();
    assert!(
        targets.iter().any(|t| t.device == device),
        "the explicit device is scanned, not the default set: {targets:?}"
    );
}

/// Run an offline scan over `images`, reading the token from a file.
fn offline_scan(images: Vec<PathBuf>) -> Result<ScanOutcome, RehearseFailure> {
    let dir = tempfile::tempdir().unwrap();
    let token_file = dir.path().join("token");
    std::fs::write(&token_file, HEX_TOKEN).unwrap();
    let options = ScanOptions {
        token_file: Some(token_file),
        offline: true,
        images,
        ..ScanOptions::default()
    };
    rooted_at(dir.path()).scan(&options)
}

#[test]
fn a_scan_that_finds_the_canary_is_critical() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("leaky.img");
    std::fs::write(&image, format!("padding {HEX_TOKEN} padding")).unwrap();
    let outcome = offline_scan(vec![image]).map_err(|e| e.message).unwrap();
    assert!(outcome.report.total_hits() >= 1, "the canary is found");
    assert_eq!(outcome.exit, ExitStatus::VerifyCritical);
}

/// Write an image the scan identifies as ext4 (its superblock magic at
/// 0x438), which keeps file contents verbatim, followed by `text`.
fn ext4_image(path: &std::path::Path, text: &str) {
    let mut bytes = vec![0u8; 4096];
    bytes[0x438..0x43A].copy_from_slice(&[0x53, 0xEF]);
    bytes.extend_from_slice(text.as_bytes());
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn a_clean_fully_read_scan_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("clean.img");
    ext4_image(&image, "nothing to see here");
    let outcome = offline_scan(vec![image]).map_err(|e| e.message).unwrap();
    assert_eq!(outcome.report.total_hits(), 0);
    assert!(!outcome.report.incomplete());
    assert!(!outcome.report.inconclusive());
    assert_eq!(outcome.exit, ExitStatus::Ok);
}

#[test]
fn a_clean_scan_of_storage_the_scan_does_not_identify_only_warns() {
    // No filesystem the scan knows: zfs, an encrypted volume or raw data
    // may hold the canary where a raw scan cannot see it.
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("raw.img");
    std::fs::write(&image, "nothing to see here").unwrap();
    let outcome = offline_scan(vec![image]).map_err(|e| e.message).unwrap();
    assert_eq!(outcome.report.total_hits(), 0);
    assert!(outcome.report.inconclusive());
    assert_eq!(outcome.exit, ExitStatus::SuccessWithWarnings);
}

#[test]
fn a_scan_of_an_empty_image_only_warns() {
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("empty.img");
    std::fs::write(&image, "").unwrap();
    let outcome = offline_scan(vec![image]).map_err(|e| e.message).unwrap();
    assert!(outcome.report.incomplete(), "nothing was read");
    assert_eq!(outcome.exit, ExitStatus::SuccessWithWarnings);
}

#[test]
fn a_clean_scan_that_could_not_read_a_device_only_warns() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.img");
    let outcome = offline_scan(vec![missing]).map_err(|e| e.message).unwrap();
    assert_eq!(outcome.report.total_hits(), 0);
    assert!(outcome.report.incomplete(), "the device could not be read");
    assert!(!outcome.report.inconclusive());
    assert_eq!(outcome.exit, ExitStatus::SuccessWithWarnings);
}

#[test]
fn a_scan_with_no_device_to_read_fails() {
    // ScanOutcome is not Debug, so discard it before expect_err.
    let err = offline_scan(Vec::new())
        .map(|_| ())
        .expect_err("no device, no scan");
    assert_eq!(err.code, "no_devices");
}

#[test]
fn a_scan_in_the_planting_session_is_refused_unless_allowed() {
    let state = planted();
    let here = in_session(100);
    assert!(refuses_same_session(Some(&state), &here, false, false));
    assert!(
        !refuses_same_session(Some(&state), &here, false, true),
        "--allow-same-boot"
    );
    assert!(
        !refuses_same_session(Some(&state), &here, true, false),
        "an offline scan of images"
    );
}

#[test]
fn a_scan_elsewhere_or_without_a_state_is_not_refused() {
    let state = planted();
    assert!(!refuses_same_session(
        Some(&state),
        &in_session(200),
        false,
        false
    ));
    assert!(!refuses_same_session(
        Some(&state),
        &Here::default(),
        false,
        false
    ));
    assert!(!refuses_same_session(None, &in_session(100), false, false));
}

/// A plan for the live-session view, entered at `entered_at`.
fn plan(entered_at: u64) -> Box<nails_teardown::whole_root::plan::Plan> {
    use nails_teardown::whole_root::plan::{PLAN_VERSION, Plan};
    let json = serde_json::json!({
        "version": PLAN_VERSION,
        "hidden_root": "/mnt/data",
        "upper": "/mnt/data/root/upper",
        "work": "/mnt/data/root/work",
        "decoy_root": {"source": "/dev/vda2", "fstype": "ext4"},
        "decoy": {"init": "/sbin/init"},
        "hidden": {"init": "/sbin/init"},
        "entered_at": entered_at,
    });
    Box::new(Plan::from_json(&json.to_string()).expect("a minimal plan"))
}

#[test]
fn a_hidden_root_is_a_live_session_with_its_entry_time() {
    assert_eq!(
        live_session_of(SessionView::Hidden(plan(100))),
        Some(LiveSession {
            entered_at: Some(100)
        })
    );
}

/// A hidden root whose `/run` plan cannot be read is still a live session:
/// read as the decoy, a scan there would read the disks before the
/// session's writes reach them and a reset would change the uppers under
/// the mounted overlay.
#[test]
fn a_hidden_root_without_its_plan_is_still_a_live_session() {
    let session = live_session_of(SessionView::HiddenWithoutPlan(
        "no session plan in /run (upper /mnt/data/root/upper)".to_string(),
    ));
    assert_eq!(session, Some(LiveSession { entered_at: None }));

    // A canary planted there, in this boot: the scan is refused.
    let state = RehearsalState {
        planted_entered_at: None,
        ..planted()
    };
    let here = Here {
        session,
        boot_id: Some("b1".to_string()),
        soft_reboots: None,
    };
    assert!(refuses_same_session(Some(&state), &here, false, false));
}

#[test]
fn the_decoy_and_an_entry_under_way_are_no_live_session() {
    assert_eq!(live_session_of(SessionView::Decoy), None);
    assert_eq!(live_session_of(SessionView::Entering(plan(100))), None);
    assert_eq!(
        live_session_of(SessionView::Interrupted {
            plan: Some(plan(100)),
            nextroot_mounted: true,
        }),
        None
    );
}

/// A channel record of `kind`, planted or skipped.
fn channel(kind: rehearse::ChannelKind, planted: bool) -> rehearse::ChannelRecord {
    rehearse::ChannelRecord {
        kind,
        location: "/somewhere".to_string(),
        upper_copy: None,
        skipped: (!planted).then(|| "not planted".to_string()),
    }
}

/// A plant that no overlaid tree took is refused, however many of the
/// other channels took the canary: a scan of the log, a process or the
/// home alone could prove nothing.
#[test]
fn a_plant_without_an_overlay_file_is_nothing_planted() {
    use rehearse::ChannelKind::{
        HomeFile, Notification, OverlayFile, ProcessCmdline, RecentFiles, SystemLog,
    };
    assert!(nothing_planted(&[]));
    assert!(nothing_planted(&[
        channel(OverlayFile, false),
        channel(HomeFile, true),
        channel(RecentFiles, true),
        channel(SystemLog, true),
        channel(ProcessCmdline, true),
        channel(Notification, true),
    ]));
}

/// One overlaid tree that took the canary is enough, whatever else was
/// skipped.
#[test]
fn a_plant_with_an_overlay_file_is_planted() {
    use rehearse::ChannelKind::{HomeFile, OverlayFile, SystemLog};
    assert!(!nothing_planted(&[
        channel(OverlayFile, false),
        channel(OverlayFile, true),
        channel(HomeFile, false),
        channel(SystemLog, false),
    ]));
}
