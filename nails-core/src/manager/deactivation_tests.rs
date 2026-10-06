// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::process_teardown::merge_protected_pids;
use super::reboot::{
    PostDeactivationReboot, dispatch_reboot_candidates, reboot_candidates,
    reboot_then_restore_decoy_on_failure, request_reboot,
};
use crate::nixos::SwitchAction;
use crate::runtime_env::TestHooks;
use crate::{NailsError, RuntimeEnv};
use serial_test::serial;
use std::cell::Cell;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;

/// A snapshot carrying the fake `systemctl` and `reboot` paths.
fn reboot_overrides(
    systemctl: Option<&std::path::Path>,
    reboot: Option<&std::path::Path>,
) -> RuntimeEnv {
    RuntimeEnv::empty().with_test_hooks(TestHooks {
        systemctl_path: systemctl.map(|path| path.as_os_str().to_os_string()),
        reboot_path: reboot.map(|path| path.as_os_str().to_os_string()),
        ..TestHooks::default()
    })
}

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

    let env = reboot_overrides(Some(&systemctl), None);

    dispatch_reboot_candidates(reboot_candidates(&env)).expect("override systemctl should be used");

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

    let env = reboot_overrides(Some(&systemctl), Some(&reboot));

    dispatch_reboot_candidates(reboot_candidates(&env)).expect("reboot fallback should succeed");

    assert!(marker.exists(), "reboot fallback should have been invoked");
}

#[test]
#[serial]
fn request_reboot_fails_closed_in_test_runtime() {
    let err =
        request_reboot(&RuntimeEnv::empty()).expect_err("request_reboot must be blocked in tests");
    assert!(matches!(err, NailsError::RebootFailed(_)), "{err:?}");
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

    let env = reboot_overrides(Some(&broken_systemctl), None);

    let err = dispatch_reboot_candidates(reboot_candidates(&env))
        .expect_err("broken override must not fall back to host binaries");
    assert!(matches!(&err, NailsError::RebootFailed(_)), "{err:?}");
    // Behaviour: the override's own failure is surfaced, proving no fallback to
    // a real host reboot binary was attempted.
    assert!(err.to_string().contains("override failed"), "{err}");
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

#[test]
#[serial]
fn verify_history_truncation_fails_when_a_file_stays_large() {
    use crate::cleanup::history::{get_extended_history_files_for_homes, history_cleanup_homes};
    use crate::{Config, MockFilesystem, NailsManager};

    let files = get_extended_history_files_for_homes(&history_cleanup_homes());
    let target = files
        .first()
        .expect("at least one history file path")
        .clone();

    let fs = MockFilesystem::new();
    // A history file left at 150 bytes (>= the 100-byte threshold) must fail.
    fs.mock_add_file(target.to_str().unwrap(), &"x".repeat(150));

    let temp = tempfile::tempdir().unwrap();
    let state_path = temp.path().join("state.json");
    let config = Config {
        hidden_volume_root: temp.path().to_path_buf(),
        state_file_path: state_path.clone(),
        ..Config::test_default()
    };
    let manager = NailsManager::new(fs, config, state_path);

    assert!(
        !super::verify_history_truncation(&manager),
        "a 150-byte history file must fail truncation verification"
    );
}

#[test]
#[serial]
fn verify_history_truncation_passes_when_files_are_small() {
    use crate::cleanup::history::{get_extended_history_files_for_homes, history_cleanup_homes};
    use crate::{Config, MockFilesystem, NailsManager};

    let files = get_extended_history_files_for_homes(&history_cleanup_homes());
    let target = files
        .first()
        .expect("at least one history file path")
        .clone();

    let fs = MockFilesystem::new();
    // A truncated (small) history file passes verification.
    fs.mock_add_file(target.to_str().unwrap(), "x");

    let temp = tempfile::tempdir().unwrap();
    let state_path = temp.path().join("state.json");
    let config = Config {
        hidden_volume_root: temp.path().to_path_buf(),
        state_file_path: state_path.clone(),
        ..Config::test_default()
    };
    let manager = NailsManager::new(fs, config, state_path);

    assert!(super::verify_history_truncation(&manager));
}

#[test]
fn owner_pid_signalled_only_for_emergency_and_recover() {
    use super::{ManagerDeactivationKind, process_teardown::owner_pid_to_signal};

    // A live owner that is not us is signalled under the state-independent
    // teardowns...
    assert_eq!(
        owner_pid_to_signal(ManagerDeactivationKind::Emergency, 4242, 1),
        Some(4242)
    );
    assert_eq!(
        owner_pid_to_signal(ManagerDeactivationKind::Recover, 4242, 1),
        Some(4242)
    );

    // ...but never under a normal Active-only deactivate.
    assert_eq!(
        owner_pid_to_signal(ManagerDeactivationKind::Normal, 4242, 1),
        None
    );
}

#[test]
fn owner_pid_signal_skips_sentinel_and_self() {
    use super::{ManagerDeactivationKind, process_teardown::owner_pid_to_signal};

    // The unset sentinel (0) is never a live owner.
    assert_eq!(
        owner_pid_to_signal(ManagerDeactivationKind::Emergency, 0, 1),
        None
    );
    // Our own process must not be signalled.
    assert_eq!(
        owner_pid_to_signal(ManagerDeactivationKind::Emergency, 99, 99),
        None
    );
}

#[test]
fn own_invocation_process_spares_ancestry_session_and_group() {
    use super::process_teardown::is_own_invocation_process;

    let ancestry = [100u32, 200, 300];
    let self_sid = 100;
    let self_pgid = 100;

    // A pid anywhere in our ancestry is spared, whatever its session/group.
    assert!(is_own_invocation_process(
        200, 7, 8, &ancestry, self_sid, self_pgid
    ));

    // A pipe reader shares our session (and, in the pipeline shell, our group)
    // even though it is not an ancestor — it must be spared too.
    assert!(is_own_invocation_process(
        4242, self_sid, self_pgid, &ancestry, self_sid, self_pgid
    ));
    // Sharing only the session is enough.
    assert!(is_own_invocation_process(
        4242, self_sid, 999, &ancestry, self_sid, self_pgid
    ));
    // Sharing only the process group is enough.
    assert!(is_own_invocation_process(
        4242, 999, self_pgid, &ancestry, self_sid, self_pgid
    ));

    // An unrelated write-blocking process (different ancestry, session and group)
    // is not spared.
    assert!(!is_own_invocation_process(
        4242, 999, 888, &ancestry, self_sid, self_pgid
    ));
}

#[test]
fn own_invocation_process_ignores_zero_sentinels() {
    use super::process_teardown::is_own_invocation_process;

    // An unreadable self or candidate session/group collapses to 0; a 0 must
    // never match-by-accident and spare an unrelated process.
    assert!(!is_own_invocation_process(4242, 0, 0, &[], 0, 0));
    assert!(!is_own_invocation_process(4242, 0, 0, &[], 100, 100));
    // But a genuine ancestry hit still spares even with zeroed sessions.
    assert!(is_own_invocation_process(4242, 0, 0, &[4242], 0, 0));
}

#[test]
fn overlay_kill_candidate_is_gated_on_the_overlay_device() {
    use super::process_teardown::candidate_is_overlay_rooted;

    // A path-matched candidate whose references are on the overlay device is
    // genuinely inside the overlay and is killed.
    assert!(candidate_is_overlay_rooted(false, true, true));
    // A path-matched candidate whose references are on the decoy device (the
    // overlay device set is known, but it does not resolve onto it) is a decoy
    // process that only collided on the path string: it is spared.
    assert!(!candidate_is_overlay_rooted(false, false, true));
    // An unverifiable writer (foreign mount namespace / chroot) cannot be device
    // checked, so it is kept fail-safe even without a device match.
    assert!(candidate_is_overlay_rooted(true, false, true));
    // When no overlay device could be read at all, fall back to the path match so
    // the overlays are never left pinned by an unkilled writer.
    assert!(candidate_is_overlay_rooted(false, false, false));
}

#[test]
fn a_decoy_mount_point_left_after_its_overlay_is_not_a_leftover() {
    use super::unmount::still_nails_owned;
    use crate::filesystem::NailsMounts;
    use std::path::{Path, PathBuf};

    let boot = Path::new("/boot");
    // After the /boot overlay is detached the decoy's own VFAT /boot is still a
    // mount point, but it is not an overlay and not a NAILS mount: not live.
    let none_owned = NailsMounts::default();
    assert!(!still_nails_owned(true, false, Some(&none_owned), boot));

    // The overlay itself still mounted is a leftover.
    assert!(still_nails_owned(true, true, Some(&none_owned), boot));

    // A NAILS-created mount (here a pivot staging bind) is a leftover.
    let pivot = Path::new("/run/nails-pivot/boot");
    let owned = NailsMounts {
        pivot_binds: vec![PathBuf::from(pivot)],
        ..NailsMounts::default()
    };
    assert!(still_nails_owned(true, false, Some(&owned), pivot));

    // Discovery unavailable: fail closed.
    assert!(still_nails_owned(true, false, None, boot));

    // Nothing mounted at all: not live.
    assert!(!still_nails_owned(false, true, None, boot));
}

#[test]
fn cleanup_pivot_staging_detaches_and_removes_the_staging() {
    use crate::{
        CleanupConfig, Config, DeactivationOrchestrator, Filesystem, MockFilesystem, NailsManager,
    };
    use std::path::{Path, PathBuf};

    // A VFAT /boot pivot stages its scaffolding inside the per-activation runtime
    // root (a random-named tmpfs under /run): a staging overlay at <root>/boot and
    // a snapshot tmpfs at <root>/boot-snapshot. Model the umbrella tmpfs, the
    // staging overlay (which makes the root discoverable structurally) and the
    // snapshot tmpfs stacked inside it.
    let root = "/run/0123456789abcdef";
    let staging = format!("{root}/boot");
    let snapshot = format!("{root}/boot-snapshot");
    let fs = MockFilesystem::new();
    fs.mock_set_path_exists("/", true);
    fs.mount_tmpfs(Path::new(root), "16M").unwrap();
    fs.mock_set_path_exists("/boot", true);
    fs.mock_set_path_exists(&snapshot, true);
    fs.mount_tmpfs(Path::new(&snapshot), "128M").unwrap();
    fs.mock_set_path_exists(&staging, true);
    fs.mock_set_path_exists("/mnt/data/boot/.upper", true);
    fs.mock_set_path_exists("/mnt/data/boot/.work", true);
    fs.mount_overlay(
        &[Path::new(&snapshot)],
        Path::new("/mnt/data/boot/.upper"),
        Path::new("/mnt/data/boot/.work"),
        Path::new(&staging),
    )
    .unwrap();

    let temp_dir = tempfile::tempdir().unwrap();
    let config = Config {
        hidden_volume_root: PathBuf::from("/mnt/data"),
        state_file_path: temp_dir.path().join("state.json"),
        overlays: vec![],
        ..Config::test_default()
    };
    let manager = NailsManager::new(fs, config, temp_dir.path().join("state.json"));

    let orchestrator = DeactivationOrchestrator::new(CleanupConfig::default());
    orchestrator.cleanup_pivot_staging(&manager);

    // The staging overlay and snapshot tmpfs are detached, and the umbrella tmpfs
    // is unmounted and its directory removed, so nothing under the runtime root
    // points back at the hidden session.
    let fs = manager.filesystem();
    assert!(!fs.is_mounted(Path::new(&staging)).unwrap());
    assert!(!fs.is_mounted(Path::new(&snapshot)).unwrap());
    assert!(!fs.is_mounted(Path::new(root)).unwrap());
    assert!(!fs.path_exists(Path::new(root)).unwrap());
}
