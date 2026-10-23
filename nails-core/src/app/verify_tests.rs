// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the `verify` operation.

use super::*;

/// A config whose state file and logs live under `root`, so `verify` reads
/// and writes only inside the temp dir.
fn config_rooted_at(root: &std::path::Path) -> Config {
    Config {
        hidden_volume_root: root.to_path_buf(),
        state_file_path: root.join("state.json"),
        log_path: root.join("logs"),
        ..Config::test_default()
    }
}

/// An offline scan under `root`, which skips every live-host check so the
/// run stays inside the temp tree.
fn offline_options(root: &std::path::Path) -> VerifyOptions {
    VerifyOptions {
        offline: true,
        root: Some(root.to_path_buf()),
        ..VerifyOptions::default()
    }
}

#[test]
fn a_missing_state_file_is_reported_as_missing_not_loaded() {
    // The state file does not exist. `verify` must report it Missing by the
    // `!state_path.exists()` guard, before ever calling `StateFile::load`.
    // Deleting the `!` sends a missing path down the load branch instead,
    // where `StateFile::load` collapses an absent file to the inactive
    // default and the status comes back `Present` rather than `Missing`.
    let root = tempfile::tempdir().unwrap();
    let config = config_rooted_at(root.path());
    let expected_path = config.state_file_path.clone();

    let result = verify(
        &RuntimeEnv::default(),
        config,
        &offline_options(root.path()),
    )
    .unwrap();

    match result.state_file_status {
        StateFileStatus::Missing { path } => assert_eq!(path, expected_path),
        other => panic!("a missing state file must be reported Missing, got {other:?}"),
    }
}

#[test]
fn a_present_state_file_is_reported_present_with_its_state() {
    // A valid state file exists, so `verify` takes the load branch and
    // reports it Present with its recorded state label. Deleting the `!`
    // inverts the guard, sending an existing file down the Missing branch.
    let root = tempfile::tempdir().unwrap();
    let config = config_rooted_at(root.path());
    let state_path = config.state_file_path.clone();
    StateFile::default()
        .save_with_custom_root(&state_path, root.path())
        .unwrap();
    let expected_label = StateFile::default().state.label().to_string();

    let result = verify(
        &RuntimeEnv::default(),
        config,
        &offline_options(root.path()),
    )
    .unwrap();

    match result.state_file_status {
        StateFileStatus::Present { path, state } => {
            assert_eq!(path, state_path);
            assert_eq!(state, expected_label);
        }
        other => panic!("an existing state file must be reported Present, got {other:?}"),
    }
}

#[test]
fn the_examiner_disk_option_is_wired_through_to_the_audit() {
    // With `examiner` and a `disk` set, the offline run must hand the disk
    // to the examiner, which records the `examiner-disk` check. Dropping the
    // `disk` field from the `ExaminerOptions` literal falls back to the
    // default (`None`), so the disk audit never runs and the check is absent.
    let root = tempfile::tempdir().unwrap();
    let disk_path = root.path().join("decoy.img");
    // A 1 MiB all-zero image: a readable raw source with no partition table
    // and no high-entropy regions, so the audit runs and finds nothing.
    std::fs::write(&disk_path, vec![0u8; 1 << 20]).unwrap();

    let options = VerifyOptions {
        examiner: true,
        disk: Some(disk_path),
        ..offline_options(root.path())
    };

    let result = verify(
        &RuntimeEnv::default(),
        config_rooted_at(root.path()),
        &options,
    )
    .unwrap();

    let report = result
        .examiner
        .expect("an examiner run must produce a report");
    assert!(
        report.checks_run.contains(&"examiner-disk"),
        "the disk audit must run when a disk is given: {:?}",
        report.checks_run
    );
}
