// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use nails_core::RuntimeEnv;
use nails_core::notification::{Notification, dispatch_all, write_notification};
use nails_core::overlay::{OverlayStrategyOptions, mount_overlay_with_strategy};
use nails_core::process::{ProcessInfo, detect_processes_using};
use nails_core::runtime_env::{ScopedRuntimeEnv, TestHooks};
use nails_core::{
    MockFilesystem, prompt_pivot_mount_acceptance, prompt_risky_process_restart, prompt_yes_no,
};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

/// Opt the calling test into test-runtime mode until the guard is dropped (see
/// runtime_safety_regression).
///
/// The in-process guard tests below assert the test-like-runtime behaviour, which
/// is now keyed on `NAILS_TEST_RUNTIME` rather than the executable path. The
/// subprocess tests that exercise the real path strip the variable from the
/// child, so the opt-in never leaks into them.
fn test_runtime_env() -> ScopedRuntimeEnv {
    ScopedRuntimeEnv::new(RuntimeEnv::empty().with_test_hooks(TestHooks {
        test_runtime: Some("1".into()),
        ..TestHooks::default()
    }))
}

fn sample_process() -> ProcessInfo {
    ProcessInfo {
        pid: 4242,
        name: "sample".to_string(),
        cmdline: "/usr/bin/sample --flag".to_string(),
        cwd: "/tmp".into(),
        has_cwd_in_target: false,
        has_open_fds_in_target: true,
        has_mmap_in_target: false,
        has_writable_fd_in_target: false,
        has_dir_fd_in_target: false,
        has_shared_write_map_in_target: false,
        has_root_in_target: false,
        is_unverifiable_writer: false,
        service_name: Some("sample.service".to_string()),
        is_interactive: false,
    }
}

fn sample_notification() -> Notification {
    Notification {
        title: "Runtime guard".to_string(),
        body: "test notification".to_string(),
        urgency: "normal".to_string(),
        icon: Some("dialog-information".to_string()),
        created_at: chrono::Utc::now().to_rfc3339(),
    }
}

const SUBPROCESS_TEST_NAME: &str = "subprocess_notification_dispatch_entrypoint";

fn copied_test_binary() -> (tempfile::TempDir, std::path::PathBuf) {
    let temp_dir = tempfile::tempdir().unwrap();
    let copied_exe = temp_dir.path().join("runtime-guard-branches");

    fs::copy(std::env::current_exe().unwrap(), &copied_exe).unwrap();

    let mut perms = fs::metadata(&copied_exe).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&copied_exe, perms).unwrap();

    (temp_dir, copied_exe)
}

fn run_notification_subprocess(
    case: &str,
    hidden_root: &Path,
    path_override: Option<&Path>,
    disable_notifications: bool,
) -> std::process::Output {
    let (_temp_dir, copied_exe) = copied_test_binary();
    for attempt in 0..10 {
        let mut command = Command::new(&copied_exe);

        command
            .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
            .env("NAILS_RUNTIME_GUARD_SUBPROCESS_CASE", case)
            .env("NAILS_RUNTIME_GUARD_SUBPROCESS_ROOT", hidden_root)
            // These cases exercise the real (non-test) dispatch and mount paths,
            // so the child must not inherit a test-runtime opt-in from the parent.
            .env_remove("NAILS_TEST_RUNTIME");

        if let Some(path) = path_override {
            command.env("PATH", path);
        }

        if disable_notifications {
            command.env("NAILS_DISABLE_NOTIFICATIONS", "1");
        }

        match command.output() {
            Ok(output) => return output,
            Err(error) if error.kind() == ErrorKind::ExecutableFileBusy && attempt < 9 => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(error) => panic!("failed to run notification subprocess: {error}"),
        }
    }

    unreachable!("subprocess launch retry loop should have returned or panicked")
}

fn install_successful_notify_send(bin_dir: &Path) {
    let notify_send_path = bin_dir.join("notify-send");
    let shell_path = std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .flat_map(|dir| [dir.join("bash"), dir.join("sh")])
                .find(|candidate| candidate.is_file())
        })
        .expect("expected to locate a usable shell binary");

    fs::write(
        &notify_send_path,
        format!("#!{}\nexit 0\n", shell_path.to_string_lossy()),
    )
    .unwrap();

    let mut perms = fs::metadata(&notify_send_path).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&notify_send_path, perms).unwrap();
}

#[test]
fn prompt_yes_no_auto_answers_in_test_like_runtime() {
    let _env = test_runtime_env();
    assert!(prompt_yes_no("Proceed?", false).unwrap());
    assert!(!prompt_yes_no("Proceed?", true).unwrap());
}

#[test]
fn risky_process_prompt_auto_declines_in_test_like_runtime() {
    let _env = test_runtime_env();
    assert!(!prompt_risky_process_restart(&[sample_process()]).unwrap());
}

#[test]
fn pivot_prompt_auto_declines_in_test_like_runtime() {
    let _env = test_runtime_env();
    assert!(!prompt_pivot_mount_acceptance(Path::new("/home"), &[sample_process()]).unwrap());
}

#[test]
fn detect_processes_using_skips_host_proc_in_test_like_runtime() {
    let _env = test_runtime_env();
    let detected = detect_processes_using(Path::new("/home")).unwrap();
    assert!(detected.is_empty());
}

#[test]
fn dispatch_all_returns_zero_without_touching_pending_notifications_in_test_like_runtime() {
    let _env = test_runtime_env();
    let dir = tempfile::tempdir().unwrap();
    write_notification(dir.path(), &sample_notification()).unwrap();

    let count = dispatch_all(dir.path(), &nails_core::RuntimeEnv::empty()).unwrap();

    assert_eq!(count, 0);
    assert!(dir.path().join("notifications").exists());
}

#[test]
fn subprocess_notification_dispatch_entrypoint() {
    let Ok(case) = std::env::var("NAILS_RUNTIME_GUARD_SUBPROCESS_CASE") else {
        return;
    };

    let hidden_root = std::env::var_os("NAILS_RUNTIME_GUARD_SUBPROCESS_ROOT")
        .map(std::path::PathBuf::from)
        .expect("missing hidden root for notification subprocess");

    // Stand in for the CLI entry point: read the environment the parent
    // prepared once and install it for the leaf helpers.
    let env = nails_core::RuntimeEnv::from_process_env();
    nails_core::runtime_env::install(env.clone());

    match case.as_str() {
        "dispatch-success" => {
            assert_eq!(dispatch_all(&hidden_root, &env).unwrap(), 2);
        }
        "dispatch-disabled" => {
            assert_eq!(dispatch_all(&hidden_root, &env).unwrap(), 0);
        }
        "dispatch-without-notify-send" => {
            assert_eq!(dispatch_all(&hidden_root, &env).unwrap(), 0);
        }
        "overlay-direct-success" => {
            let fs = MockFilesystem::new();
            fs.mock_set_filesystem_type(Path::new("/srv"), "ext4");
            fs.mock_set_path_exists("/srv", true);
            fs.mock_set_path_exists("/mnt/hidden/srv/.upper", true);
            fs.mock_set_path_exists("/mnt/hidden/srv/.work", true);

            let result = mount_overlay_with_strategy(
                &fs,
                Path::new("/run/0123456789abcdef"),
                &[Path::new("/srv")],
                Path::new("/mnt/hidden/srv/.upper"),
                Path::new("/mnt/hidden/srv/.work"),
                Path::new("/srv"),
                &OverlayStrategyOptions {
                    auto_restart_safe: true,
                    risky_services: None,
                    terminate_processes: false,
                    allow_pivot: true,
                    auto_accept_pivot: false,
                    skip_process_detection: false,
                },
                &nails_core::process::detection::ProcSnapshot::empty(),
            )
            .unwrap();

            assert_eq!(result.method, nails_core::overlay::MountMethod::Direct);
            assert!(result.stopped_services.is_empty());
        }
        other => panic!("unknown notification subprocess case: {other}"),
    }
}

#[test]
fn dispatch_all_uses_notify_send_and_clears_pending_files_outside_test_like_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let bin_dir = dir.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    install_successful_notify_send(&bin_dir);

    let mut first = sample_notification();
    first.icon = Some("dialog-information".to_string());
    let mut second = sample_notification();
    second.title = "Second notification".to_string();
    second.icon = None;

    write_notification(dir.path(), &first).unwrap();
    write_notification(dir.path(), &second).unwrap();

    let output = run_notification_subprocess("dispatch-success", dir.path(), Some(&bin_dir), false);

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        nails_core::notification::read_pending(dir.path())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn dispatch_all_respects_disable_notifications_env_outside_test_like_runtime() {
    let dir = tempfile::tempdir().unwrap();
    write_notification(dir.path(), &sample_notification()).unwrap();

    let output = run_notification_subprocess("dispatch-disabled", dir.path(), None, true);

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        nails_core::notification::read_pending(dir.path())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn dispatch_all_keeps_pending_files_when_notify_send_is_missing_outside_test_like_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let empty_path = dir.path().join("empty-path");
    fs::create_dir_all(&empty_path).unwrap();
    write_notification(dir.path(), &sample_notification()).unwrap();

    let output = run_notification_subprocess(
        "dispatch-without-notify-send",
        dir.path(),
        Some(&empty_path),
        false,
    );

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        nails_core::notification::read_pending(dir.path())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn mount_overlay_strategy_runs_direct_mount_path_outside_test_like_runtime() {
    let dir = tempfile::tempdir().unwrap();

    let output = run_notification_subprocess("overlay-direct-success", dir.path(), None, false);

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
