// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;

#[test]
#[serial]
fn deactivate_degrades_when_a_target_cannot_unmount() {
    let (manager, _hidden_root) = active_manager_with_overlays(&["/home", "/etc", "/opt"]);
    // Fail the middle target; the teardown must still attempt the other two and
    // must NOT remount what it has already detached.
    manager
        .lock()
        .unwrap()
        .filesystem()
        .mock_set_unmount_should_fail("/etc", true);

    let worker = Arc::clone(&manager);
    let result = run_within_timeout(move || worker.lock().unwrap().deactivate());

    let err = result.expect_err("deactivate must fail when a target stays mounted");
    assert!(
        matches!(err, NailsError::DeactivationIncomplete { .. }),
        "unexpected error: {err:?}"
    );
    assert!(
        err.to_string().contains("/etc"),
        "error must name the live mount: {err}"
    );

    let guard = manager.lock().unwrap();
    // Never ACTIVE once an overlay is detached: the teardown ends DEGRADED.
    match guard.current_state().unwrap() {
        SystemState::Degraded {
            remaining_mounts, ..
        } => assert_eq!(remaining_mounts, vec![PathBuf::from("/etc")]),
        other => panic!("expected Degraded, got {other:?}"),
    }
    // All three targets were attempted: the two that can unmount are gone, and
    // the failing one stays live (no remount).
    assert!(!guard.filesystem().is_mounted(Path::new("/home")).unwrap());
    assert!(!guard.filesystem().is_mounted(Path::new("/opt")).unwrap());
    assert!(guard.filesystem().is_mounted(Path::new("/etc")).unwrap());
}
#[test]
#[serial]
fn emergency_deactivate_degrades_without_remount_when_a_target_cannot_unmount() {
    let (manager, _hidden_root) = active_manager_with_overlays(&["/home", "/etc", "/opt"]);
    manager
        .lock()
        .unwrap()
        .filesystem()
        .mock_set_unmount_should_fail("/etc", true);

    let worker = Arc::clone(&manager);
    let result = run_within_timeout(move || worker.lock().unwrap().emergency_deactivate());

    let err = result.expect_err("emergency deactivate must fail when a target stays mounted");
    assert!(
        matches!(err, NailsError::DeactivationIncomplete { .. }),
        "unexpected error: {err:?}"
    );

    let guard = manager.lock().unwrap();
    assert!(
        guard.current_state().unwrap().is_degraded(),
        "emergency teardown must end DEGRADED, not roll back to ACTIVE"
    );
    // Emergency mode also continues past the failure and never remounts: the two
    // unmountable targets are detached and the failing one is still live.
    assert!(!guard.filesystem().is_mounted(Path::new("/home")).unwrap());
    assert!(!guard.filesystem().is_mounted(Path::new("/opt")).unwrap());
    assert!(guard.filesystem().is_mounted(Path::new("/etc")).unwrap());
}
#[test]
#[serial]
fn deactivate_returns_err_within_timeout_when_deactivating_write_fails() {
    use crate::state::save_probe::{self, FailOn};

    let (manager, _hidden_root) = active_manager_no_profile();
    let worker = Arc::clone(&manager);

    let result = run_within_timeout(move || {
        save_probe::arm(&[FailOn::Deactivating]);
        let outcome = worker.lock().unwrap().deactivate();
        save_probe::disarm();
        outcome
    });

    assert!(
        result.is_err(),
        "deactivate must surface the failed ACTIVE->DEACTIVATING write"
    );
    // The ACTIVE->DEACTIVATING write fails before any overlay is detached, so
    // StateGuard::drop correctly rolls the state back to ACTIVE. (A teardown that
    // fails *after* detaching an overlay ends DEGRADED instead; see the degraded
    // teardown tests below.)
    assert!(manager.lock().unwrap().current_state().unwrap().is_active());
}
#[test]
#[serial]
fn emergency_completes_within_timeout_when_deactivating_write_fails() {
    use crate::state::save_probe::{self, FailOn};

    let (manager, _hidden_root) = active_manager_no_profile();
    let worker = Arc::clone(&manager);

    let result = run_within_timeout(move || {
        save_probe::arm(&[FailOn::Deactivating]);
        let outcome = worker.lock().unwrap().emergency_deactivate();
        save_probe::disarm();
        outcome
    });

    // Emergency is the panic button: a failed ACTIVE->DEACTIVATING write (a dead
    // or read-only backend) must not stop the teardown or roll the state back to
    // ACTIVE. A normal deactivate still fails closed here (see the test above).
    result.expect("emergency must complete even if the DEACTIVATING write fails");
    assert!(
        !manager.lock().unwrap().current_state().unwrap().is_active(),
        "emergency must not leave the state ACTIVE after tearing the session down"
    );
}
#[test]
#[serial]
fn deactivate_returns_err_within_timeout_when_inactive_write_fails() {
    use crate::state::save_probe::{self, FailOn};

    let (manager, _hidden_root) = active_manager_no_profile();
    let worker = Arc::clone(&manager);

    let result = run_within_timeout(move || {
        // The ACTIVE->DEACTIVATING write succeeds; only the final
        // DEACTIVATING->INACTIVE write fails, exercising the late `?` site.
        save_probe::arm(&[FailOn::Inactive]);
        let outcome = worker.lock().unwrap().deactivate();
        save_probe::disarm();
        outcome
    });

    assert!(
        result.is_err(),
        "deactivate must surface the failed DEACTIVATING->INACTIVE write"
    );
    assert!(manager.lock().unwrap().current_state().unwrap().is_active());
}
#[test]
#[serial]
fn emergency_completes_within_timeout_when_inactive_write_fails() {
    use crate::state::save_probe::{self, FailOn};

    let (manager, _hidden_root) = active_manager_no_profile();
    let worker = Arc::clone(&manager);

    let result = run_within_timeout(move || {
        save_probe::arm(&[FailOn::Inactive]);
        let outcome = worker.lock().unwrap().emergency_deactivate();
        save_probe::disarm();
        outcome
    });

    // The final DEACTIVATING->INACTIVE write lands on the hidden volume, which may
    // be gone by the end of an emergency teardown. The overlays are already
    // detached, so a failed write here must not fail the panic button or roll the
    // state back to ACTIVE; a normal deactivate still fails closed (test above).
    result.expect("emergency must complete even if the final INACTIVE write fails");
    assert!(
        !manager.lock().unwrap().current_state().unwrap().is_active(),
        "emergency must not leave the state ACTIVE after tearing the session down"
    );
}
#[test]
#[serial]
fn deactivate_returns_err_within_timeout_when_system_profile_lookup_fails() {
    let (manager, _hidden_root) = active_manager_with_failing_profile_lookup();
    let worker = Arc::clone(&manager);

    let result = run_within_timeout(move || worker.lock().unwrap().deactivate());

    assert!(
        result.is_err(),
        "deactivate must surface a failing decoy-profile lookup"
    );
    assert!(manager.lock().unwrap().current_state().unwrap().is_active());
}
#[test]
#[serial]
fn emergency_deactivate_returns_err_within_timeout_when_system_profile_lookup_fails() {
    let (manager, _hidden_root) = active_manager_with_failing_profile_lookup();
    let worker = Arc::clone(&manager);

    // Emergency mode has no up-front profile pre-check, so the failing lookup is
    // reached inside the guarded run, after the state is already INACTIVE; the
    // guard's drop then rolls back without hanging.
    let result = run_within_timeout(move || worker.lock().unwrap().emergency_deactivate());

    assert!(
        result.is_err(),
        "emergency deactivate must surface a failing decoy-profile lookup"
    );
}
#[test]
#[serial]
fn deactivate_returns_err_within_timeout_when_rollback_write_also_fails() {
    use crate::state::save_probe::{self, FailOn};

    let (manager, _hidden_root) = active_manager_no_profile();
    let worker = Arc::clone(&manager);

    // The exact shape of the original deadlock: the initial state write fails
    // AND the rollback write that StateGuard::drop then attempts also fails. The
    // drop must log and return rather than block.
    let result = run_within_timeout(move || {
        save_probe::arm(&[FailOn::Deactivating, FailOn::Active]);
        let outcome = worker.lock().unwrap().deactivate();
        save_probe::disarm();
        outcome
    });

    assert!(
        result.is_err(),
        "deactivate must surface the failed write even when rollback also fails"
    );
}
