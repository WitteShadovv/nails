use super::{
    PostDeactivationReboot, REBOOT_BINARY_OVERRIDE_ENV, SYSTEMCTL_REBOOT_OVERRIDE_ENV,
    dispatch_reboot_candidates, merge_protected_pids, reboot_candidates,
    reboot_then_restore_decoy_on_failure, request_reboot,
};
use crate::NailsError;
use crate::nixos::SwitchAction;
use crate::test_support::EnvGuard;
use serial_test::serial;
use std::cell::Cell;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn write_executable_script(path: &std::path::Path, body: &str) {
    fs::write(path, body).expect("write test script");
    let mut permissions = fs::metadata(path).expect("stat test script").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("chmod test script");
}

#[test]
#[serial]
fn request_reboot_uses_configured_systemctl_override() {
    let temp_dir = tempfile::tempdir().unwrap();
    let marker = temp_dir.path().join("systemctl-arg.txt");
    let systemctl = temp_dir.path().join("systemctl");

    write_executable_script(
        &systemctl,
        &format!(
            "#!/usr/bin/env bash\nprintf '%s' \"$1\" > '{}'\nexit 0\n",
            marker.display()
        ),
    );

    let mut env = EnvGuard::lock();
    env.set(SYSTEMCTL_REBOOT_OVERRIDE_ENV, &systemctl)
        .remove(REBOOT_BINARY_OVERRIDE_ENV);

    dispatch_reboot_candidates(reboot_candidates()).expect("override systemctl should be used");

    assert_eq!(fs::read_to_string(marker).unwrap(), "reboot");
}

#[test]
#[serial]
fn request_reboot_falls_back_to_override_reboot_binary_when_systemctl_fails() {
    let temp_dir = tempfile::tempdir().unwrap();
    let systemctl = temp_dir.path().join("systemctl");
    let reboot = temp_dir.path().join("reboot");
    let marker = temp_dir.path().join("reboot-called.txt");

    write_executable_script(
        &systemctl,
        "#!/usr/bin/env bash\nprintf 'denied\n' >&2\nexit 1\n",
    );
    write_executable_script(
        &reboot,
        &format!("#!/usr/bin/env bash\n: > '{}'\nexit 0\n", marker.display()),
    );

    let mut env = EnvGuard::lock();
    env.set(SYSTEMCTL_REBOOT_OVERRIDE_ENV, &systemctl)
        .set(REBOOT_BINARY_OVERRIDE_ENV, &reboot);

    dispatch_reboot_candidates(reboot_candidates()).expect("reboot fallback should succeed");

    assert!(marker.exists(), "reboot fallback should have been invoked");
}

#[test]
#[serial]
fn request_reboot_fails_closed_in_test_runtime() {
    let err = request_reboot().expect_err("request_reboot must be blocked in tests");
    assert!(err.to_string().contains("Refusing to trigger reboot"));
}

#[test]
#[serial]
fn reboot_override_never_falls_back_to_real_host_commands() {
    let temp_dir = tempfile::tempdir().unwrap();
    let broken_systemctl = temp_dir.path().join("systemctl");

    write_executable_script(
        &broken_systemctl,
        "#!/usr/bin/env bash\nprintf 'override failed\n' >&2\nexit 1\n",
    );

    let mut env = EnvGuard::lock();
    env.set(SYSTEMCTL_REBOOT_OVERRIDE_ENV, &broken_systemctl)
        .remove(REBOOT_BINARY_OVERRIDE_ENV);

    let err = dispatch_reboot_candidates(reboot_candidates())
        .expect_err("broken override must not fall back to host binaries");
    assert!(err.to_string().contains("override failed"));
}

#[test]
fn merge_protected_pids_without_handoff_returns_ancestry() {
    assert_eq!(merge_protected_pids(vec![10, 20], None), vec![10, 20]);
}

#[test]
fn merge_protected_pids_appends_handoff_and_dedups() {
    let merged = merge_protected_pids(vec![10, 20], Some(OsStr::new("20, 30, bad, 40")));
    assert_eq!(merged, vec![10, 20, 30, 40]);
}

#[test]
fn merge_protected_pids_handles_empty_ancestry() {
    let merged = merge_protected_pids(Vec::new(), Some(OsStr::new("7,8")));
    assert_eq!(merged, vec![7, 8]);
}

#[test]
fn successful_reboot_never_runs_a_decoy_switch() {
    // A dispatched reboot restores the decoy from the bootloader default, so no
    // switch-to-configuration runs at all.
    let restored = Cell::new(false);
    let outcome = reboot_then_restore_decoy_on_failure(
        || Ok(()),
        || {
            restored.set(true);
            Ok(())
        },
    )
    .expect("a successful reboot is not an error");

    assert_eq!(outcome, PostDeactivationReboot::Dispatched);
    assert!(
        !restored.get(),
        "a successful reboot must not run any switch-to-configuration"
    );
}

#[test]
fn reboot_failure_falls_back_to_non_installing_test_switch() {
    // If the reboot command fails, deactivation must still restore the decoy for
    // the running session — via the non-installing `test` fallback, never a
    // reinstalling `switch`/`boot`.
    let restored = Cell::new(false);
    let outcome = reboot_then_restore_decoy_on_failure(
        || Err(NailsError::NixOSError("no reboot command found".into())),
        || {
            restored.set(true);
            Ok(())
        },
    )
    .expect("the test fallback succeeds");

    assert_eq!(outcome, PostDeactivationReboot::FellBackToTest);
    assert!(
        restored.get(),
        "a failed reboot must fall back to the decoy session switch"
    );
    // The fallback can only ever request the non-installing `test` action.
    assert_eq!(SwitchAction::Test.as_arg(), "test");
}

#[test]
fn reboot_failure_propagates_a_failed_fallback() {
    let outcome = reboot_then_restore_decoy_on_failure(
        || Err(NailsError::NixOSError("no reboot command found".into())),
        || Err(NailsError::NixOSError("switch script missing".into())),
    );

    assert!(matches!(outcome, Err(NailsError::NixOSError(_))));
}
