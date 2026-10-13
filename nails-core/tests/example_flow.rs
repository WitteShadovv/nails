// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Integration tests for NailsManager flows using MockFilesystem
//!
//! The state record, pre-flight, status and verify, all through the public API
//! and without root. The session itself (entry, return) needs a kernel and is
//! covered by the session module's kernel tests and the VM suite.

use nails_core::{
    Config, MockFilesystem, NailsManager, Posture, StatusCommand, SystemState, TestWorld, Verifier,
    VerifyStatus,
};

#[test]
fn the_state_record_follows_forced_states() {
    let (mut manager, _tmp) = TestWorld::new().manager();
    assert_eq!(manager.current_state().unwrap(), SystemState::Inactive);

    manager
        .force_state(SystemState::Active {
            activated_at: chrono::Utc::now(),
        })
        .unwrap();
    assert!(manager.current_state().unwrap().is_active());

    manager
        .force_state(SystemState::Degraded {
            since: chrono::Utc::now(),
            reason: "in the hidden root without a way back".into(),
        })
        .unwrap();
    assert!(manager.current_state().unwrap().is_degraded());

    manager.force_state(SystemState::Inactive).unwrap();
    assert_eq!(manager.current_state().unwrap(), SystemState::Inactive);
}

#[test]
fn the_manager_keeps_its_config() {
    let tmp = tempfile::tempdir().unwrap();
    let hidden_root = tmp.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists(hidden_root.to_str().unwrap(), true);
    let config = Config {
        hidden_volume_root: hidden_root,
        state_file_path: state_path.clone(),
        minimum_space_mb: 999,
        ..Config::default()
    };
    let manager = NailsManager::new(fs, config, state_path);
    assert_eq!(manager.config().minimum_space_mb, 999);
}

#[test]
fn preflight_rejects_a_missing_hidden_volume() {
    let tmp = tempfile::tempdir().unwrap();
    let hidden_root = tmp.path().to_path_buf();
    let state_path = hidden_root.join("state.json");
    let config = Config {
        hidden_volume_root: hidden_root,
        state_file_path: state_path.clone(),
        ..Config::default()
    };
    let manager = NailsManager::new(MockFilesystem::new(), config, state_path);
    assert!(
        manager
            .run_preflight_checks(&nails_core::PreflightOptions::default())
            .is_err()
    );
}

#[test]
fn status_on_the_decoy_reports_the_record_next_to_the_live_view() {
    let (mut manager, _tmp) = TestWorld::new().manager();
    manager
        .force_state(SystemState::Active {
            activated_at: chrono::Utc::now(),
        })
        .unwrap();
    let fs = manager.filesystem().clone();
    let config = manager.config().clone();
    let state_path = config.state_file_path.clone();
    let status = StatusCommand::new(fs, config, state_path)
        .report(
            &nails_core::session::SessionView::Decoy,
            &[],
            chrono::Utc::now(),
        )
        .unwrap();
    assert_eq!(status.posture, Posture::Decoy);
    assert!(status.state.is_active());
    assert!(status.uptime.is_none());
}

#[test]
fn verify_of_a_fresh_world_is_secure() {
    let (manager, _tmp) = TestWorld::new().manager();
    let fs = manager.filesystem().clone();
    let config = manager.config().clone();
    let state_path = config.state_file_path.clone();
    let verifier = Verifier::with_config(
        fs,
        config,
        Some(nails_core::StateFile::load(&state_path).unwrap()),
        nails_core::StateFileStatus::NotChecked,
    );
    assert_eq!(verifier.run(false).unwrap().status, VerifyStatus::Secure);
}
