use super::*;
use nails_core::constants::{ENV_DETACHED, ENV_FORCE_DETACH, ENV_SKIP_DETACH};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::Mutex;

// Serialize all tests that touch environment variables to avoid races.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn with_env<K: AsRef<str>, V: AsRef<str>, F: FnOnce()>(key: K, val: V, f: F) {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        env::set_var(key.as_ref(), val.as_ref());
    }
    f();
    unsafe {
        env::remove_var(key.as_ref());
    }
}

const SUBPROCESS_TEST_NAME: &str = "cli::detach::tests::subprocess_detach_entrypoint";

fn write_executable_script(path: &std::path::Path, body: &str) {
    fs::write(path, body).expect("write script");
    let mut perms = fs::metadata(path).expect("stat script").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("chmod script");
}

fn locate_shell_path() -> std::path::PathBuf {
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .flat_map(|dir| [dir.join("bash"), dir.join("sh")])
                .find(|candidate| candidate.is_file())
        })
        .expect("expected to locate a usable shell binary")
}

#[test]
fn does_nothing_when_kill_session_false() {
    with_env(ENV_SKIP_DETACH, "1", || {
        unsafe { env::set_var("DISPLAY", ":0") };
        let res = maybe_detach_for_session_kill(false, &[OsString::from("nails")], None, false);
        unsafe { env::remove_var("DISPLAY") };
        assert!(res.is_ok());
    });
}

#[test]
fn does_nothing_without_graphical_env() {
    with_env(ENV_SKIP_DETACH, "1", || {
        unsafe { env::remove_var("DISPLAY") };
        unsafe { env::remove_var("WAYLAND_DISPLAY") };
        let res = maybe_detach_for_session_kill(true, &[OsString::from("nails")], None, false);
        assert!(res.is_ok());
    });
}

#[test]
fn skips_when_already_detached() {
    with_env(ENV_SKIP_DETACH, "1", || {
        unsafe { env::set_var("DISPLAY", ":1") };
        unsafe { env::set_var(ENV_DETACHED, "1") };
        let res = maybe_detach_for_session_kill(true, &[OsString::from("nails")], None, false);
        unsafe { env::remove_var(ENV_DETACHED) };
        unsafe { env::remove_var("DISPLAY") };
        assert!(res.is_ok());
    });
}

#[test]
fn deactivation_detach_respects_skip_env() {
    with_env(ENV_SKIP_DETACH, "1", || {
        let res = maybe_detach_for_deactivation();
        assert!(res.is_ok());
    });
}

#[test]
fn deactivation_detach_skips_when_already_detached() {
    with_env(ENV_SKIP_DETACH, "1", || {
        unsafe { env::set_var(ENV_DETACHED, "1") };
        let res = maybe_detach_for_deactivation();
        unsafe { env::remove_var(ENV_DETACHED) };
        assert!(res.is_ok());
    });
}

#[test]
fn maybe_detach_for_session_kill_skips_when_kill_session_is_false_without_skip_env() {
    let result = maybe_detach_for_session_kill(false, &[OsString::from("nails")], None, false);
    assert!(result.is_ok());
}

#[test]
fn maybe_detach_for_session_kill_skips_non_graphical_context_without_skip_env() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ctx = SessionContext {
        kind: SessionKind::Tty,
        session_id: None,
        display_manager: None,
        target_uid: None,
        target_user: None,
        logind_available: false,
    };

    unsafe {
        env::remove_var(ENV_SKIP_DETACH);
        env::remove_var(ENV_DETACHED);
        env::remove_var(ENV_FORCE_DETACH);
    }

    let result = maybe_detach_for_session_kill(true, &[OsString::from("nails")], Some(&ctx), false);
    assert!(result.is_ok());
}

#[test]
fn maybe_detach_for_session_kill_skips_when_already_detached_without_skip_env() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ctx = SessionContext {
        kind: SessionKind::GraphicalUser,
        session_id: Some("7".into()),
        display_manager: Some("display-manager".into()),
        target_uid: Some(1000),
        target_user: Some("alice".into()),
        logind_available: true,
    };

    unsafe {
        env::set_var(ENV_DETACHED, "1");
        env::remove_var(ENV_SKIP_DETACH);
    }

    let result = maybe_detach_for_session_kill(true, &[OsString::from("nails")], Some(&ctx), false);

    unsafe {
        env::remove_var(ENV_DETACHED);
    }

    assert!(result.is_ok());
}

#[test]
fn set_target_identity_from_environment_prefers_explicit_target_values() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut command = Command::new("true");

    unsafe {
        env::set_var(ENV_TARGET_UID, "1001");
        env::set_var("SUDO_UID", "1000");
        env::set_var(ENV_TARGET_USER, "target-user");
        env::set_var("SUDO_USER", "sudo-user");
    }

    set_target_identity_from_environment(&mut command);

    unsafe {
        env::remove_var(ENV_TARGET_UID);
        env::remove_var("SUDO_UID");
        env::remove_var(ENV_TARGET_USER);
        env::remove_var("SUDO_USER");
    }

    let args: Vec<_> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert!(args.contains(&format!("--setenv={}={}", ENV_TARGET_UID, "1001")));
    assert!(args.contains(&format!("--setenv={}={}", ENV_TARGET_USER, "target-user")));
}

#[test]
fn set_target_identity_from_environment_falls_back_to_sudo_values() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut command = Command::new("true");

    unsafe {
        env::remove_var(ENV_TARGET_UID);
        env::set_var("SUDO_UID", "1000");
        env::remove_var(ENV_TARGET_USER);
        env::set_var("SUDO_USER", "sudo-user");
    }

    set_target_identity_from_environment(&mut command);

    unsafe {
        env::remove_var("SUDO_UID");
        env::remove_var("SUDO_USER");
    }

    let args: Vec<_> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert!(args.contains(&format!("--setenv={}={}", ENV_TARGET_UID, "1000")));
    assert!(args.contains(&format!("--setenv={}={}", ENV_TARGET_USER, "sudo-user")));
}

#[test]
fn propagate_shell_cleanup_protection_adds_env_when_present() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut command = Command::new("true");

    unsafe {
        env::set_var(SHELL_CLEANUP_PROTECTED_PIDS_ENV, "101,202");
    }

    propagate_shell_cleanup_protection(&mut command);

    unsafe {
        env::remove_var(SHELL_CLEANUP_PROTECTED_PIDS_ENV);
    }

    let args: Vec<_> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert!(args.contains(&format!(
        "--setenv={}={}",
        SHELL_CLEANUP_PROTECTED_PIDS_ENV, "101,202"
    )));
}

#[test]
fn systemd_run_program_allows_unsafe_real_ops_override() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    unsafe {
        env::remove_var(SYSTEMD_RUN_OVERRIDE_ENV);
        env::set_var("NAILS_UNSAFE_REAL_OPS", "1");
    }

    let result = systemd_run_program().expect("unsafe override should allow systemd-run");

    unsafe {
        env::remove_var("NAILS_UNSAFE_REAL_OPS");
    }

    assert_eq!(result, OsString::from("systemd-run"));
}

#[test]
fn systemd_run_program_uses_override_even_in_test_runtime() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let override_path = std::env::temp_dir().join("fake-systemd-run-override");

    unsafe {
        env::set_var(SYSTEMD_RUN_OVERRIDE_ENV, &override_path);
        env::remove_var("NAILS_UNSAFE_REAL_OPS");
    }

    let result = systemd_run_program().expect("override should bypass runtime guard");

    unsafe {
        env::remove_var(SYSTEMD_RUN_OVERRIDE_ENV);
    }

    assert_eq!(result, override_path.into_os_string());
}

#[test]
fn should_skip_detach_reflects_env_presence() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    unsafe {
        env::set_var(ENV_SKIP_DETACH, "1");
    }
    assert!(should_skip_detach());

    unsafe {
        env::remove_var(ENV_SKIP_DETACH);
    }
    assert!(!should_skip_detach());
}

#[test]
fn is_already_detached_reflects_env_presence() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    unsafe {
        env::set_var(ENV_DETACHED, "1");
    }
    assert!(is_already_detached());

    unsafe {
        env::remove_var(ENV_DETACHED);
    }
    assert!(!is_already_detached());
}

#[test]
fn propagate_shell_cleanup_protection_is_noop_when_env_absent() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut command = Command::new("true");

    unsafe {
        env::remove_var(SHELL_CLEANUP_PROTECTED_PIDS_ENV);
    }

    propagate_shell_cleanup_protection(&mut command);

    assert_eq!(command.get_args().count(), 0);
}

#[test]
fn deactivation_detach_force_detach_fails_closed_in_test_runtime() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    unsafe {
        env::set_var(ENV_FORCE_DETACH, "1");
        env::remove_var(ENV_SKIP_DETACH);
        env::remove_var(ENV_DETACHED);
        env::remove_var(SYSTEMD_RUN_OVERRIDE_ENV);
        env::remove_var("NAILS_UNSAFE_REAL_OPS");
    }

    let err = maybe_detach_for_deactivation().expect_err("test runtime must fail closed");

    unsafe {
        env::remove_var(ENV_FORCE_DETACH);
    }

    assert!(
        err.to_string()
            .contains("Refusing to start transient systemd units")
    );
}

#[test]
fn subprocess_detach_entrypoint() {
    let Ok(case) = std::env::var("NAILS_DETACH_SUBPROCESS_CASE") else {
        return;
    };

    match case.as_str() {
        "block-deactivate" => {
            unsafe {
                std::env::remove_var(ENV_SKIP_DETACH);
                std::env::remove_var(ENV_DETACHED);
                std::env::remove_var(ENV_FORCE_DETACH);
                std::env::remove_var(SYSTEMD_RUN_OVERRIDE_ENV);
                std::env::remove_var("NAILS_UNSAFE_REAL_OPS");
            }
            maybe_detach_for_deactivation().expect("deactivation should run in-process");
        }
        "block-session" => {
            unsafe {
                std::env::remove_var(ENV_SKIP_DETACH);
                std::env::remove_var(ENV_DETACHED);
                std::env::remove_var(ENV_FORCE_DETACH);
                std::env::remove_var(SYSTEMD_RUN_OVERRIDE_ENV);
                std::env::remove_var("NAILS_UNSAFE_REAL_OPS");
                std::env::set_var("DISPLAY", ":0");
            }
            let err = maybe_detach_for_session_kill(true, &[OsString::from("nails")], None, false)
                .expect_err("must fail closed");
            assert!(
                err.to_string()
                    .contains("Refusing to start transient systemd units")
            );
            unsafe {
                std::env::remove_var("DISPLAY");
            }
        }
        "allow-override" => {
            unsafe {
                std::env::remove_var(ENV_SKIP_DETACH);
                std::env::remove_var(ENV_DETACHED);
                std::env::set_var(ENV_FORCE_DETACH, "1");
            }
            maybe_detach_for_deactivation().expect("override fake systemd-run should succeed");
        }
        "detach-session-success" | "detach-session-success-json" => {
            unsafe {
                std::env::remove_var(ENV_SKIP_DETACH);
                std::env::remove_var(ENV_DETACHED);
                std::env::set_var(ENV_FORCE_DETACH, "1");
            }
            let json = case == "detach-session-success-json";
            let _ = maybe_detach_for_session_kill(true, &[OsString::from("nails")], None, json);
            // A successful handoff exits the process inside the call above, so
            // reaching here means the detach did not succeed.
            exit_process(7);
        }
        other => panic!("unknown detach subprocess case: {other}"),
    }
}

#[test]
fn deactivation_detach_defaults_to_in_process_execution() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env("NAILS_DETACH_SUBPROCESS_CASE", "block-deactivate")
        .env_remove(ENV_SKIP_DETACH)
        .env_remove(ENV_DETACHED)
        .env_remove(ENV_FORCE_DETACH)
        .env_remove(SYSTEMD_RUN_OVERRIDE_ENV)
        .env_remove("NAILS_UNSAFE_REAL_OPS")
        .output()
        .expect("run subprocess");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn session_detach_refuses_transient_units_in_test_like_runtime() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env("NAILS_DETACH_SUBPROCESS_CASE", "block-session")
        .env_remove(ENV_SKIP_DETACH)
        .env_remove(ENV_DETACHED)
        .env_remove(ENV_FORCE_DETACH)
        .env_remove(SYSTEMD_RUN_OVERRIDE_ENV)
        .env_remove("NAILS_UNSAFE_REAL_OPS")
        .output()
        .expect("run subprocess");

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn session_detach_reports_follow_up_command_on_success() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let fake_systemd_run = temp_dir.path().join("fake-systemd-run");
    let shell_path = locate_shell_path();
    write_executable_script(
        &fake_systemd_run,
        &format!("#!{}\nexit 0\n", shell_path.display()),
    );

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env("NAILS_DETACH_SUBPROCESS_CASE", "detach-session-success")
        .env(SYSTEMD_RUN_OVERRIDE_ENV, &fake_systemd_run)
        .env(ENV_FORCE_DETACH, "1")
        .env_remove(ENV_SKIP_DETACH)
        .env_remove(ENV_DETACHED)
        .output()
        .expect("run subprocess");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
    assert!(
        stderr.contains("Detached to background via systemd transient service."),
        "stderr={stderr}"
    );
    let exe = std::env::current_exe().unwrap();
    assert!(
        stderr.contains(&format!("sudo {} status", exe.display())),
        "stderr={stderr}"
    );
}

#[test]
fn session_detach_emits_detached_envelope_under_json() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let fake_systemd_run = temp_dir.path().join("fake-systemd-run");
    let shell_path = locate_shell_path();
    write_executable_script(
        &fake_systemd_run,
        &format!("#!{}\nexit 0\n", shell_path.display()),
    );

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env(
            "NAILS_DETACH_SUBPROCESS_CASE",
            "detach-session-success-json",
        )
        .env(SYSTEMD_RUN_OVERRIDE_ENV, &fake_systemd_run)
        .env(ENV_FORCE_DETACH, "1")
        .env_remove(ENV_SKIP_DETACH)
        .env_remove(ENV_DETACHED)
        .output()
        .expect("run subprocess");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "stdout={stdout}");
    // The nested test harness runs with --nocapture, so skip its banner lines
    // and parse the envelope line.
    let json_line = stdout
        .lines()
        .find(|line| line.trim_start().starts_with('{'))
        .unwrap_or_else(|| panic!("detached handoff must emit a JSON envelope: {stdout}"));
    let value: serde_json::Value = serde_json::from_str(json_line.trim())
        .unwrap_or_else(|e| panic!("detached handoff must be one JSON doc ({e}): {stdout}"));
    assert_eq!(value["command"], "activate", "{value}");
    assert_eq!(value["ok"], true, "{value}");
    assert_eq!(value["data"]["status"], "detached", "{value}");
}

#[test]
fn deactivation_detach_uses_explicit_systemd_run_override() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let fake_systemd_run = temp_dir.path().join("fake-systemd-run");
    let log = temp_dir.path().join("systemd-run.log");
    let shell_path = locate_shell_path();

    write_executable_script(
        &fake_systemd_run,
        &format!(
            "#!{}\nprintf '%s\\n' \"$@\" > '{}'\nexit 0\n",
            shell_path.display(),
            log.display()
        ),
    );
    assert!(fake_systemd_run.exists(), "fake systemd-run script missing");

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env("NAILS_DETACH_SUBPROCESS_CASE", "allow-override")
        .env(SYSTEMD_RUN_OVERRIDE_ENV, &fake_systemd_run)
        .env(ENV_FORCE_DETACH, "1")
        .env(
            DEACTIVATE_UNIT_NAME_OVERRIDE_ENV,
            "nails-deactivate-test.service",
        )
        .env("SUDO_UID", "1000")
        .env("SUDO_USER", "alice")
        .env_remove(ENV_SKIP_DETACH)
        .env_remove(ENV_DETACHED)
        .output()
        .expect("run subprocess");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
    assert!(stderr.contains("Detached to background via systemd transient service."));

    let logged_args = fs::read_to_string(log).expect("fake systemd-run log");
    assert!(logged_args.contains("nails-deactivate-test.service"));
    assert!(logged_args.contains("--working-directory=/"));
    assert!(logged_args.contains("--setenv=NAILS_TARGET_UID=1000"));
    assert!(logged_args.contains("--setenv=NAILS_TARGET_USER=alice"));
    assert!(logged_args.contains("--setenv=PATH="));
    assert!(logged_args.contains("/run/current-system/sw/bin"));
}

#[test]
fn deactivation_detach_propagates_protected_shell_cleanup_pids() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let fake_systemd_run = temp_dir.path().join("fake-systemd-run");
    let log = temp_dir.path().join("systemd-run.log");
    let shell_path = locate_shell_path();

    write_executable_script(
        &fake_systemd_run,
        &format!(
            "#!{}\nprintf '%s\\n' \"$@\" > '{}'\nexit 0\n",
            shell_path.display(),
            log.display()
        ),
    );

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env("NAILS_DETACH_SUBPROCESS_CASE", "allow-override")
        .env(SYSTEMD_RUN_OVERRIDE_ENV, &fake_systemd_run)
        .env(ENV_FORCE_DETACH, "1")
        .env(
            DEACTIVATE_UNIT_NAME_OVERRIDE_ENV,
            "nails-deactivate-test.service",
        )
        .env("SUDO_UID", "1000")
        .env("SUDO_USER", "alice")
        .env(SHELL_CLEANUP_PROTECTED_PIDS_ENV, "101,202")
        .env_remove(ENV_SKIP_DETACH)
        .env_remove(ENV_DETACHED)
        .output()
        .expect("run subprocess");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");

    let logged_args = fs::read_to_string(log).expect("fake systemd-run log");
    assert!(
        logged_args.contains("--setenv=NAILS_SHELL_CLEANUP_PROTECTED_PIDS=101,202"),
        "logged args were: {logged_args}"
    );
    assert!(
        logged_args.contains("--setenv=PATH="),
        "logged args were: {logged_args}"
    );
}
