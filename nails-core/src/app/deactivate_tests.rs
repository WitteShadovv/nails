// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the `deactivate` operation.

use super::*;
use crate::{Config, NailsManager, RealFilesystem, RuntimeEnv};

/// A [`ReadyDeactivation`] whose hidden volume and state file are under
/// `dir`. The live probe still reads the real machine, which is never a
/// hidden NAILS overlay root during the tests, so its view is the decoy.
fn ready_at(dir: &Path) -> ReadyDeactivation {
    let hidden = dir.to_path_buf();
    let config = Config {
        hidden_volume_root: hidden.clone(),
        state_file_path: hidden.join("state.json"),
        log_path: hidden.join("logs"),
        ..Config::test_default()
    };
    let state_path = config.state_file_path.clone();
    let manager = NailsManager::new(RealFilesystem, config, state_path);
    ReadyDeactivation { manager }
}

#[test]
fn leaving_outside_a_hidden_session_refuses_instead_of_reporting_success() {
    // `leave` commits the real way back. Off the hidden root the live
    // view is the decoy, so it must surface the refusal rather than
    // quietly return an empty success report.
    let dir = tempfile::tempdir().unwrap();
    let err = ready_at(dir.path()).leave(LeaveTo::Decoy).unwrap_err();
    assert!(
        matches!(&err, NailsError::InvalidState(msg) if msg.contains("not in a hidden session")),
        "expected a refusal, got {err:?}"
    );
}

#[test]
fn preparing_off_the_hidden_root_reports_not_hidden() {
    // On a machine that is not in a hidden session, prepare must refuse
    // the way back (NotHidden), never hand back a Ready deactivation.
    let env = RuntimeEnv::default();
    assert!(
        matches!(prepare(&env, None), Prepared::NotHidden),
        "a non-hidden machine must prepare NotHidden"
    );
}
