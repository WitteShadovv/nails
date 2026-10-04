// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
#[serial]
fn test_deactivation_gate_returns_immediately_when_disabled() {
    let _gate_guard = DeactivationGateTestGuard::enable();
    let _env = deactivation_gate_env(None, None);

    assert!(maybe_block_after_deactivating_state_transition().is_ok());
}
#[test]
#[serial]
fn test_deactivation_gate_writes_default_entered_marker() {
    let _gate_guard = DeactivationGateTestGuard::enable();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let gate_path = temp_dir.path().join("deactivation.gate");
    let entered_path = PathBuf::from(format!("{}.entered", gate_path.display()));
    std::fs::write(&gate_path, []).expect("gate file");
    let _env = deactivation_gate_env(Some(&gate_path), None);

    let releaser = spawn_deactivation_gate_releaser(gate_path.clone(), entered_path.clone());
    maybe_block_after_deactivating_state_transition().expect("gate should be released");
    releaser.join().expect("releaser thread should finish");

    assert!(
        entered_path.exists(),
        "default entered marker should be created"
    );
    assert!(!gate_path.exists(), "gate should be removed by releaser");
}
