use nails_core::{Notification, notification};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use nails_core::obfuscate;

const SUBPROCESS_TEST_NAME: &str = "subprocess_notification_runtime_entrypoint";

fn copy_current_exe_outside_deps(temp_dir: &Path) -> PathBuf {
    let copied = temp_dir.join("notification-runtime-helper");
    std::fs::copy(std::env::current_exe().unwrap(), &copied).unwrap();

    let mut permissions = std::fs::metadata(&copied).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&copied, permissions).unwrap();

    copied
}

fn run_subprocess_with_env(
    case: &str,
    hidden_root: &Path,
    path_override: Option<&Path>,
    extra_env: &[(&str, &str)],
) -> std::process::Output {
    let temp_dir = tempfile::tempdir().unwrap();
    let helper = copy_current_exe_outside_deps(temp_dir.path());

    let mut command = Command::new(helper);
    command
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env("NAILS_NOTIFICATION_RUNTIME_CASE", case)
        .env("NAILS_NOTIFICATION_RUNTIME_ROOT", hidden_root)
        .env_remove("NAILS_DISABLE_NOTIFICATIONS")
        .env_remove("NAILS_TEST_RUNTIME");

    if let Some(path) = path_override {
        command.env("PATH", path);
    }

    for (key, value) in extra_env {
        command.env(key, value);
    }

    for attempt in 0..5 {
        match command.output() {
            Ok(output) => return output,
            Err(err) if err.kind() == std::io::ErrorKind::ExecutableFileBusy && attempt < 4 => {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(err) => panic!("failed to run notification runtime subprocess: {err}"),
        }
    }

    unreachable!("exhausted executable-file-busy retry loop")
}

fn run_subprocess(
    case: &str,
    hidden_root: &Path,
    path_override: Option<&Path>,
) -> std::process::Output {
    run_subprocess_with_env(case, hidden_root, path_override, &[])
}

fn locate_shell_path() -> PathBuf {
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .flat_map(|dir| [dir.join("bash"), dir.join("sh")])
                .find(|candidate| candidate.is_file())
        })
        .expect("expected to locate a usable shell binary")
}

fn make_notification(title: &str, body: &str) -> Notification {
    Notification {
        title: title.to_string(),
        body: body.to_string(),
        urgency: "critical".to_string(),
        icon: Some("dialog-error".to_string()),
        created_at: "2026-01-01T00:00:00Z".to_string(),
    }
}

#[test]
fn subprocess_notification_runtime_entrypoint() {
    let Ok(case) = std::env::var("NAILS_NOTIFICATION_RUNTIME_CASE") else {
        return;
    };
    let hidden_root = PathBuf::from(std::env::var("NAILS_NOTIFICATION_RUNTIME_ROOT").unwrap());

    match case.as_str() {
        "explicit-test-runtime" => {
            notification::write_notification(&hidden_root, &make_notification("Queued", "Body"))
                .unwrap();
            assert_eq!(notification::dispatch_all(&hidden_root).unwrap(), 0);
            assert_eq!(notification::read_pending(&hidden_root).unwrap().len(), 1);
        }
        "disabled-env" => {
            notification::write_notification(&hidden_root, &make_notification("Queued", "Body"))
                .unwrap();
            assert_eq!(notification::dispatch_all(&hidden_root).unwrap(), 0);
            assert_eq!(notification::read_pending(&hidden_root).unwrap().len(), 1);
        }
        "missing-notify-send" => {
            notification::write_notification(&hidden_root, &make_notification("Queued", "Body"))
                .unwrap();
            assert_eq!(notification::dispatch_all(&hidden_root).unwrap(), 0);
            assert_eq!(notification::read_pending(&hidden_root).unwrap().len(), 1);
        }
        "no-pending" => {
            assert_eq!(notification::dispatch_all(&hidden_root).unwrap(), 0);
            assert!(notification::read_pending(&hidden_root).unwrap().is_empty());
        }
        "write-dir-blocked" => {
            std::fs::write(hidden_root.join("notifications"), "not a directory").unwrap();
            let err = notification::write_notification(
                &hidden_root,
                &make_notification("Queued", "Body"),
            )
            .unwrap_err();
            assert!(
                err.to_string()
                    .contains("Failed to create notifications dir")
            );
        }
        "read-dir-blocked" => {
            std::fs::write(hidden_root.join("notifications"), "not a directory").unwrap();
            let err = notification::read_pending(&hidden_root).unwrap_err();
            assert!(err.to_string().contains("Failed to read notifications dir"));
        }
        "clear-missing" => {
            let err =
                notification::clear_notification(&hidden_root.join("missing.json")).unwrap_err();
            assert!(
                err.to_string()
                    .contains("Failed to remove notification file")
            );
        }
        "clear-all-dir-blocked" => {
            std::fs::write(hidden_root.join("notifications"), "not a directory").unwrap();
            let err = notification::clear_all(&hidden_root).unwrap_err();
            assert!(err.to_string().contains("Failed to read notifications dir"));
        }
        "sudo-user-fallback-write" => {
            unsafe {
                std::env::remove_var("NAILS_TARGET_USER");
            }
            notification::write_notification(&hidden_root, &make_notification("Queued", "Body"))
                .unwrap();
            assert_eq!(notification::read_pending(&hidden_root).unwrap().len(), 1);
        }
        "notify-send-exec-error" => {
            notification::write_notification(&hidden_root, &make_notification("Queued", "Body"))
                .unwrap();
            assert_eq!(notification::dispatch_all(&hidden_root).unwrap(), 0);
            assert_eq!(notification::read_pending(&hidden_root).unwrap().len(), 1);
        }
        "successful-dispatch" => {
            notification::write_notification(
                &hidden_root,
                &make_notification("Queued Title", "Body payload"),
            )
            .unwrap();
            assert_eq!(notification::dispatch_all(&hidden_root).unwrap(), 1);
            assert!(notification::read_pending(&hidden_root).unwrap().is_empty());
        }
        "env-propagation" => {
            let env = notification::notification_runtime_environment();
            assert!(
                env.iter()
                    .any(|(k, v)| *k == "XDG_RUNTIME_DIR" && v == "/run/user/1000")
            );
            assert!(
                env.iter().any(|(k, v)| *k == "DBUS_SESSION_BUS_ADDRESS"
                    && v == "unix:path=/run/user/1000/bus")
            );
            assert!(env.iter().any(|(k, v)| *k == "DISPLAY" && v == ":0"));
            assert!(
                env.iter()
                    .any(|(k, v)| *k == "WAYLAND_DISPLAY" && v == "wayland-1")
            );
        }
        "failed-dispatch" => {
            notification::write_notification(&hidden_root, &make_notification("Queued", "Body"))
                .unwrap();
            assert_eq!(notification::dispatch_all(&hidden_root).unwrap(), 0);
            assert_eq!(notification::read_pending(&hidden_root).unwrap().len(), 1);
        }
        other => panic!("unknown notification runtime subprocess case: {other}"),
    }
}

#[test]
fn explicit_test_runtime_env_skips_dispatch_and_preserves_pending_notification() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let output = run_subprocess_with_env(
        "explicit-test-runtime",
        &hidden_root,
        None,
        &[("NAILS_TEST_RUNTIME", "1")],
    );

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn disable_notifications_env_skips_dispatch_before_notify_send_lookup() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let output = run_subprocess_with_env(
        "disabled-env",
        &hidden_root,
        None,
        &[("NAILS_DISABLE_NOTIFICATIONS", "1")],
    );

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn missing_notify_send_keeps_pending_notification() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let empty_path = temp_dir.path().join("empty-bin");
    std::fs::create_dir_all(&hidden_root).unwrap();
    std::fs::create_dir_all(&empty_path).unwrap();

    let output = run_subprocess("missing-notify-send", &hidden_root, Some(&empty_path));
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn dispatch_all_returns_zero_when_no_notifications_are_pending() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let output = run_subprocess("no-pending", &hidden_root, None);
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn write_notification_returns_error_when_notifications_directory_cannot_be_created() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let output = run_subprocess("write-dir-blocked", &hidden_root, None);
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn read_pending_returns_error_when_notifications_path_is_not_directory() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let output = run_subprocess("read-dir-blocked", &hidden_root, None);
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn clear_notification_returns_error_for_missing_file_in_production_build() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let output = run_subprocess("clear-missing", &hidden_root, None);
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn clear_all_returns_error_when_notifications_path_is_not_directory_in_production_build() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let output = run_subprocess("clear-all-dir-blocked", &hidden_root, None);
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn write_notification_uses_sudo_user_fallback_without_dispatching() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let output = run_subprocess_with_env(
        "sudo-user-fallback-write",
        &hidden_root,
        None,
        &[("SUDO_USER", "alice")],
    );
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn successful_dispatch_uses_fake_notify_send_and_clears_pending_notification() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let fake_bin = temp_dir.path().join("fake-bin");
    std::fs::create_dir_all(&hidden_root).unwrap();
    std::fs::create_dir_all(&fake_bin).unwrap();

    let notify_send_path = fake_bin.join("notify-send");
    let shell_path = locate_shell_path();
    std::fs::write(
        &notify_send_path,
        format!("#!{}\nexit 0\n", shell_path.display()),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&notify_send_path).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&notify_send_path, permissions).unwrap();

    let output = run_subprocess("successful-dispatch", &hidden_root, Some(&fake_bin));
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn failed_dispatch_keeps_pending_notification_for_retry() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let fake_bin = temp_dir.path().join("fake-bin");
    std::fs::create_dir_all(&hidden_root).unwrap();
    std::fs::create_dir_all(&fake_bin).unwrap();

    let notify_send_path = fake_bin.join("notify-send");
    let shell_path = locate_shell_path();
    std::fs::write(
        &notify_send_path,
        format!(
            "#!{}\nprintf 'mock notify-send failure' >&2\nexit 1\n",
            shell_path.display()
        ),
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&notify_send_path).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&notify_send_path, permissions).unwrap();

    let output = run_subprocess("failed-dispatch", &hidden_root, Some(&fake_bin));
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn notify_send_execution_error_keeps_pending_notification_for_retry() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let fake_bin = temp_dir.path().join("fake-bin");
    std::fs::create_dir_all(&hidden_root).unwrap();
    std::fs::create_dir_all(&fake_bin).unwrap();

    let notify_send_path = fake_bin.join("notify-send");
    std::fs::write(&notify_send_path, "not executable").unwrap();

    let output = run_subprocess("notify-send-exec-error", &hidden_root, Some(&fake_bin));
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn notification_dispatch_builds_runtime_environment_from_target_session_vars() {
    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let output = run_subprocess_with_env(
        "env-propagation",
        &hidden_root,
        None,
        &[
            (&obfuscate::env_target_uid(), "1000"),
            ("DISPLAY", ":0"),
            ("WAYLAND_DISPLAY", "wayland-1"),
        ],
    );

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
