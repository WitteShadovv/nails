use super::*;
use nails_core::constants::{ENV_DETACHED, ENV_FORCE_DETACH, ENV_SKIP_DETACH};
use nails_core::test_support::EnvGuard;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const SUBPROCESS_TEST_NAME: &str = "cli::detach::tests::subprocess_detach_entrypoint";

fn write_executable_script(path: &std::path::Path, body: &str) {
    fs::write(path, body).expect("write script");
    let mut perms = fs::metadata(path).expect("stat script").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("chmod script");
}

fn locate_shell_path() -> std::path::PathBuf {
    let _env = EnvGuard::lock();
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .flat_map(|dir| [dir.join("bash"), dir.join("sh")])
                .find(|candidate| candidate.is_file())
        })
        .expect("expected to locate a usable shell binary")
}

/// Runs this test binary's `subprocess_detach_entrypoint` with `case`.
///
/// The child inherits the environment at spawn time, so the spawn happens under
/// the environment lock: a variable another test set for itself (for example
/// `NAILS_UNSAFE_REAL_OPS`) must not leak into the child. Anything the caller
/// does not set or remove on `command` is inherited unchanged.
fn run_entrypoint(case: &str, configure: impl FnOnce(&mut Command)) -> std::process::Output {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env("NAILS_DETACH_SUBPROCESS_CASE", case);
    configure(&mut command);

    let _env = EnvGuard::lock();
    command.output().expect("run subprocess")
}

/// Assert the recorded `systemd-run` argv names no product unit and carries a
/// neutral description with no path or product name.
fn assert_neutral_unit_argv(logged_args: &str) {
    assert!(
        !logged_args.lines().any(|line| line == "--unit"),
        "detached unit must not pass --unit (systemd auto-names it): {logged_args}"
    );
    assert!(
        !logged_args.contains("nails-activate-") && !logged_args.contains("nails-deactivate-"),
        "detached unit name must not carry the product name: {logged_args}"
    );
    let description = logged_args
        .lines()
        .find_map(|line| line.strip_prefix("--description="))
        .expect("detached unit must pass a --description");
    assert!(
        !description.contains('/') && !description.to_lowercase().contains("nails"),
        "unit description must carry no path or product name: {description:?}"
    );
}

#[test]
fn does_nothing_when_kill_session_false() {
    let mut env = EnvGuard::lock();
    env.set(ENV_SKIP_DETACH, "1").set("DISPLAY", ":0");

    let res = maybe_detach_for_session_kill(false, &[OsString::from("nails")], None, false);

    assert!(res.is_ok());
}

#[test]
fn does_nothing_without_graphical_env() {
    let mut env = EnvGuard::lock();
    env.set(ENV_SKIP_DETACH, "1")
        .remove("DISPLAY")
        .remove("WAYLAND_DISPLAY");

    let res = maybe_detach_for_session_kill(true, &[OsString::from("nails")], None, false);

    assert!(res.is_ok());
}

#[test]
fn skips_when_already_detached() {
    let mut env = EnvGuard::lock();
    env.set(ENV_SKIP_DETACH, "1")
        .set("DISPLAY", ":1")
        .set(ENV_DETACHED, "1");

    let res = maybe_detach_for_session_kill(true, &[OsString::from("nails")], None, false);

    assert!(res.is_ok());
}

#[test]
fn deactivation_detach_respects_skip_env() {
    let mut env = EnvGuard::lock();
    env.set(ENV_SKIP_DETACH, "1");

    let res = maybe_detach_for_deactivation();

    assert!(res.is_ok());
}

#[test]
fn deactivation_detach_skips_when_already_detached() {
    let mut env = EnvGuard::lock();
    env.set(ENV_SKIP_DETACH, "1").set(ENV_DETACHED, "1");

    let res = maybe_detach_for_deactivation();

    assert!(res.is_ok());
}

#[test]
fn maybe_detach_for_session_kill_skips_when_kill_session_is_false_without_skip_env() {
    let mut env = EnvGuard::lock();
    env.remove(ENV_SKIP_DETACH);

    let result = maybe_detach_for_session_kill(false, &[OsString::from("nails")], None, false);

    assert!(result.is_ok());
}

#[test]
fn maybe_detach_for_session_kill_skips_non_graphical_context_without_skip_env() {
    let mut env = EnvGuard::lock();
    env.remove(ENV_SKIP_DETACH)
        .remove(ENV_DETACHED)
        .remove(ENV_FORCE_DETACH);
    let ctx = SessionContext {
        kind: SessionKind::Tty,
        session_id: None,
        display_manager: None,
        target_uid: None,
        target_user: None,
        logind_available: false,
    };

    let result = maybe_detach_for_session_kill(true, &[OsString::from("nails")], Some(&ctx), false);

    assert!(result.is_ok());
}

#[test]
fn maybe_detach_for_session_kill_skips_when_already_detached_without_skip_env() {
    let mut env = EnvGuard::lock();
    env.set(ENV_DETACHED, "1").remove(ENV_SKIP_DETACH);
    let ctx = SessionContext {
        kind: SessionKind::GraphicalUser,
        session_id: Some("7".into()),
        display_manager: Some("display-manager".into()),
        target_uid: Some(1000),
        target_user: Some("alice".into()),
        logind_available: true,
    };

    let result = maybe_detach_for_session_kill(true, &[OsString::from("nails")], Some(&ctx), false);

    assert!(result.is_ok());
}

#[test]
fn set_target_identity_from_environment_prefers_explicit_target_values() {
    let mut env = EnvGuard::lock();
    env.set(ENV_TARGET_UID, "1001")
        .set("SUDO_UID", "1000")
        .set(ENV_TARGET_USER, "target-user")
        .set("SUDO_USER", "sudo-user");
    let mut command = Command::new("true");

    set_target_identity_from_environment(&mut command);

    let args: Vec<_> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert!(args.contains(&format!("--setenv={}={}", ENV_TARGET_UID, "1001")));
    assert!(args.contains(&format!("--setenv={}={}", ENV_TARGET_USER, "target-user")));
}

#[test]
fn set_target_identity_from_environment_falls_back_to_sudo_values() {
    let mut env = EnvGuard::lock();
    env.remove(ENV_TARGET_UID)
        .set("SUDO_UID", "1000")
        .remove(ENV_TARGET_USER)
        .set("SUDO_USER", "sudo-user");
    let mut command = Command::new("true");

    set_target_identity_from_environment(&mut command);

    let args: Vec<_> = command
        .get_args()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    assert!(args.contains(&format!("--setenv={}={}", ENV_TARGET_UID, "1000")));
    assert!(args.contains(&format!("--setenv={}={}", ENV_TARGET_USER, "sudo-user")));
}

#[test]
fn propagate_shell_cleanup_protection_adds_env_when_present() {
    let mut env = EnvGuard::lock();
    env.set(SHELL_CLEANUP_PROTECTED_PIDS_ENV, "101,202");
    let mut command = Command::new("true");

    propagate_shell_cleanup_protection(&mut command);

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
    let mut env = EnvGuard::lock();
    env.remove(SYSTEMD_RUN_OVERRIDE_ENV)
        .set("NAILS_UNSAFE_REAL_OPS", "1");

    let result = systemd_run_program().expect("unsafe override should allow systemd-run");

    assert_eq!(result, OsString::from("systemd-run"));
}

#[test]
fn systemd_run_program_uses_override_even_in_test_runtime() {
    let override_path = std::env::temp_dir().join("fake-systemd-run-override");
    let mut env = EnvGuard::lock();
    env.set(SYSTEMD_RUN_OVERRIDE_ENV, &override_path)
        .remove("NAILS_UNSAFE_REAL_OPS");

    let result = systemd_run_program().expect("override should bypass runtime guard");

    assert_eq!(result, override_path.into_os_string());
}

#[test]
fn should_skip_detach_reflects_env_presence() {
    let mut env = EnvGuard::lock();

    env.set(ENV_SKIP_DETACH, "1");
    assert!(should_skip_detach());

    env.remove(ENV_SKIP_DETACH);
    assert!(!should_skip_detach());
}

#[test]
fn is_already_detached_reflects_env_presence() {
    let mut env = EnvGuard::lock();

    env.set(ENV_DETACHED, "1");
    assert!(is_already_detached());

    env.remove(ENV_DETACHED);
    assert!(!is_already_detached());
}

#[test]
fn propagate_shell_cleanup_protection_is_noop_when_env_absent() {
    let mut env = EnvGuard::lock();
    env.remove(SHELL_CLEANUP_PROTECTED_PIDS_ENV);
    let mut command = Command::new("true");

    propagate_shell_cleanup_protection(&mut command);

    assert_eq!(command.get_args().count(), 0);
}

#[test]
fn deactivation_detach_force_detach_fails_closed_in_test_runtime() {
    let mut env = EnvGuard::lock();
    env.set(ENV_FORCE_DETACH, "1")
        .remove(ENV_SKIP_DETACH)
        .remove(ENV_DETACHED)
        .remove(SYSTEMD_RUN_OVERRIDE_ENV)
        .remove("NAILS_UNSAFE_REAL_OPS");

    let err = maybe_detach_for_deactivation().expect_err("test runtime must fail closed");

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
    // Only this test runs in the child, but the guard keeps the rule uniform.
    let mut env = EnvGuard::lock();

    match case.as_str() {
        "block-deactivate" => {
            env.remove(ENV_SKIP_DETACH)
                .remove(ENV_DETACHED)
                .remove(ENV_FORCE_DETACH)
                .remove(SYSTEMD_RUN_OVERRIDE_ENV)
                .remove("NAILS_UNSAFE_REAL_OPS");
            maybe_detach_for_deactivation().expect("deactivation should run in-process");
        }
        "block-session" => {
            env.remove(ENV_SKIP_DETACH)
                .remove(ENV_DETACHED)
                .remove(ENV_FORCE_DETACH)
                .remove(SYSTEMD_RUN_OVERRIDE_ENV)
                .remove("NAILS_UNSAFE_REAL_OPS")
                .set("DISPLAY", ":0");
            let err = maybe_detach_for_session_kill(true, &[OsString::from("nails")], None, false)
                .expect_err("must fail closed");
            assert!(
                err.to_string()
                    .contains("Refusing to start transient systemd units")
            );
        }
        "allow-override" => {
            env.remove(ENV_SKIP_DETACH)
                .remove(ENV_DETACHED)
                .set(ENV_FORCE_DETACH, "1");
            maybe_detach_for_deactivation().expect("override fake systemd-run should succeed");
        }
        "detach-session-success" | "detach-session-success-json" => {
            env.remove(ENV_SKIP_DETACH)
                .remove(ENV_DETACHED)
                .set(ENV_FORCE_DETACH, "1");
            let json = case == "detach-session-success-json";
            let _ = maybe_detach_for_session_kill(true, &[OsString::from("nails")], None, json);
            // A successful handoff exits the process inside the call above, so
            // reaching here means the detach did not succeed.
            exit_process(7);
        }
        "panic-hook" => {
            // Install the hook, then provoke a panic whose payload carries a
            // path-like secret. The hook must keep that off stderr; catch_unwind
            // keeps the child from aborting so the parent can read stderr.
            install_panic_hook();
            let _ = std::panic::catch_unwind(|| {
                panic!("boom at /mnt/hidden-volume/nixos/flake.nix");
            });
            exit_process(0);
        }
        other => panic!("unknown detach subprocess case: {other}"),
    }
}

#[test]
fn deactivation_detach_defaults_to_in_process_execution() {
    let output = run_entrypoint("block-deactivate", |command| {
        command
            .env_remove(ENV_SKIP_DETACH)
            .env_remove(ENV_DETACHED)
            .env_remove(ENV_FORCE_DETACH)
            .env_remove(SYSTEMD_RUN_OVERRIDE_ENV)
            .env_remove("NAILS_UNSAFE_REAL_OPS");
    });

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn session_detach_refuses_transient_units_in_test_like_runtime() {
    let output = run_entrypoint("block-session", |command| {
        command
            .env_remove(ENV_SKIP_DETACH)
            .env_remove(ENV_DETACHED)
            .env_remove(ENV_FORCE_DETACH)
            .env_remove(SYSTEMD_RUN_OVERRIDE_ENV)
            .env_remove("NAILS_UNSAFE_REAL_OPS");
    });

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

    let output = run_entrypoint("detach-session-success", |command| {
        command
            .env(SYSTEMD_RUN_OVERRIDE_ENV, &fake_systemd_run)
            .env(ENV_FORCE_DETACH, "1")
            .env_remove(ENV_SKIP_DETACH)
            .env_remove(ENV_DETACHED);
    });

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

    let output = run_entrypoint("detach-session-success-json", |command| {
        command
            .env(SYSTEMD_RUN_OVERRIDE_ENV, &fake_systemd_run)
            .env(ENV_FORCE_DETACH, "1")
            .env_remove(ENV_SKIP_DETACH)
            .env_remove(ENV_DETACHED);
    });

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

    let output = run_entrypoint("allow-override", |command| {
        command
            .env(SYSTEMD_RUN_OVERRIDE_ENV, &fake_systemd_run)
            .env(ENV_FORCE_DETACH, "1")
            .env("SUDO_UID", "1000")
            .env("SUDO_USER", "alice")
            .env_remove(DETACH_DEBUG_JOURNAL_ENV)
            .env_remove(ENV_SKIP_DETACH)
            .env_remove(ENV_DETACHED);
    });

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
    assert!(stderr.contains("Detached to background via systemd transient service."));

    let logged_args = fs::read_to_string(log).expect("fake systemd-run log");
    assert_neutral_unit_argv(&logged_args);
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

    let output = run_entrypoint("allow-override", |command| {
        command
            .env(SYSTEMD_RUN_OVERRIDE_ENV, &fake_systemd_run)
            .env(ENV_FORCE_DETACH, "1")
            .env("SUDO_UID", "1000")
            .env("SUDO_USER", "alice")
            .env(SHELL_CLEANUP_PROTECTED_PIDS_ENV, "101,202")
            .env_remove(DETACH_DEBUG_JOURNAL_ENV)
            .env_remove(ENV_SKIP_DETACH)
            .env_remove(ENV_DETACHED);
    });

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

/// Helper: write a `systemd-run` fake that records its argv to `log`.
fn write_recording_systemd_run(fake_systemd_run: &std::path::Path, log: &std::path::Path) {
    let shell_path = locate_shell_path();
    write_executable_script(
        fake_systemd_run,
        &format!(
            "#!{}\nprintf '%s\\n' \"$@\" > '{}'\nexit 0\n",
            shell_path.display(),
            log.display()
        ),
    );
}

#[test]
fn session_detach_uses_neutral_unit_and_discards_output() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let fake_systemd_run = temp_dir.path().join("fake-systemd-run");
    let log = temp_dir.path().join("systemd-run.log");
    write_recording_systemd_run(&fake_systemd_run, &log);

    let output = run_entrypoint("detach-session-success", |command| {
        command
            .env(SYSTEMD_RUN_OVERRIDE_ENV, &fake_systemd_run)
            .env(ENV_FORCE_DETACH, "1")
            .env_remove(DETACH_DEBUG_JOURNAL_ENV)
            .env_remove(ENV_SKIP_DETACH)
            .env_remove(ENV_DETACHED);
    });

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");

    let logged_args = fs::read_to_string(log).expect("fake systemd-run log");
    assert_neutral_unit_argv(&logged_args);
    assert!(
        logged_args.contains("--property=StandardOutput=null"),
        "worker stdout must be discarded by default: {logged_args}"
    );
    assert!(
        logged_args.contains("--property=StandardError=null"),
        "worker stderr must be discarded by default: {logged_args}"
    );
    assert!(
        !logged_args.contains("StandardOutput=journal")
            && !logged_args.contains("StandardError=journal"),
        "worker streams must not reach the journal by default: {logged_args}"
    );
}

#[test]
fn session_detach_debug_flag_routes_output_to_journal() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let fake_systemd_run = temp_dir.path().join("fake-systemd-run");
    let log = temp_dir.path().join("systemd-run.log");
    write_recording_systemd_run(&fake_systemd_run, &log);

    let output = run_entrypoint("detach-session-success", |command| {
        command
            .env(SYSTEMD_RUN_OVERRIDE_ENV, &fake_systemd_run)
            .env(ENV_FORCE_DETACH, "1")
            .env(DETACH_DEBUG_JOURNAL_ENV, "1")
            .env_remove(ENV_SKIP_DETACH)
            .env_remove(ENV_DETACHED);
    });

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");

    let logged_args = fs::read_to_string(log).expect("fake systemd-run log");
    assert_neutral_unit_argv(&logged_args);
    assert!(
        logged_args.contains("--property=StandardOutput=journal")
            && logged_args.contains("--property=StandardError=journal"),
        "debug flag must route worker streams to the journal: {logged_args}"
    );
    assert!(
        !logged_args.contains("StandardOutput=null"),
        "debug flag must not also discard worker streams: {logged_args}"
    );
}

#[test]
fn panic_hook_keeps_paths_and_payload_off_stderr() {
    let output = run_entrypoint("panic-hook", |command| {
        command.env_remove(ENV_SKIP_DETACH).env_remove(ENV_DETACHED);
    });

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr={stderr}");
    assert!(
        stderr.contains("A fatal internal error occurred"),
        "operator must see a neutral abort line: {stderr}"
    );
    // Neither the panic payload, its source location, nor a crate path may leak.
    assert!(
        !stderr.contains("boom"),
        "payload leaked to stderr: {stderr}"
    );
    assert!(
        !stderr.contains("/mnt/hidden-volume"),
        "payload path leaked to stderr: {stderr}"
    );
    assert!(
        !stderr.contains(".rs:"),
        "a source path leaked to stderr: {stderr}"
    );
    assert!(
        !stderr.to_lowercase().contains("panicked"),
        "the default panic line leaked to stderr: {stderr}"
    );
}
