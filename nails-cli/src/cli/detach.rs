use std::env;
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use nails_core::obfuscate::{
    env_detached, env_display_manager, env_force_detach, env_logind_available, env_session_id,
    env_skip_detach, env_target_uid, env_target_user, systemd_unit_prefix,
};
use nails_core::{NailsError, SessionContext, SessionKind, detect_session_context};

const DEACTIVATE_UNIT_PREFIX: &str = "nails-deactivate-";
const TEST_RUNTIME_ENV: &str = "NAILS_TEST_RUNTIME";
const SYSTEMD_RUN_OVERRIDE_ENV: &str = "NAILS_SYSTEMD_RUN_PATH";
const DEACTIVATE_UNIT_NAME_OVERRIDE_ENV: &str = "NAILS_DEACTIVATE_UNIT_NAME";
const SHELL_CLEANUP_PROTECTED_PIDS_ENV: &str = "NAILS_SHELL_CLEANUP_PROTECTED_PIDS";

fn maybe_exit_after_detach(mut cmd: Command, success_message: &[&str]) -> Result<(), NailsError> {
    let output = cmd
        .output()
        .map_err(|e| NailsError::InvalidState(format!("Failed to execute systemd-run: {}", e)))?;

    if !output.status.success() {
        return Err(NailsError::InvalidState(format!(
            "systemd-run failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    for line in success_message {
        eprintln!("{line}");
    }

    std::process::exit(0);
}

fn should_skip_detach() -> bool {
    env::var_os(env_skip_detach()).is_some()
}

fn binary_looks_like_test_runtime() -> bool {
    if env::var_os(TEST_RUNTIME_ENV).is_some() {
        return true;
    }

    env::current_exe().ok().is_some_and(|exe| {
        let exe_display = exe.to_string_lossy();
        exe.components()
            .any(|component| component.as_os_str() == Path::new("deps").as_os_str())
            || exe_display.contains("/target/debug/")
            || exe_display.contains("/target/release/")
            || exe_display.contains("/target/llvm-cov-target/")
    })
}

fn systemd_run_program() -> Result<OsString, NailsError> {
    if let Some(path) = env::var_os(SYSTEMD_RUN_OVERRIDE_ENV) {
        return Ok(path);
    }

    if env::var("NAILS_UNSAFE_REAL_OPS").unwrap_or_default() == "1" {
        return Ok(OsString::from("systemd-run"));
    }

    if binary_looks_like_test_runtime() {
        return Err(NailsError::InvalidState(format!(
            "Refusing to start transient systemd units from a test/test-like runtime; set {} to a fake systemd-run, set {}=1 to bypass detach, or set NAILS_UNSAFE_REAL_OPS=1 to allow real host operations",
            SYSTEMD_RUN_OVERRIDE_ENV,
            env_skip_detach()
        )));
    }

    Ok(OsString::from("systemd-run"))
}

fn set_target_identity_from_environment(cmd: &mut Command) {
    if let Ok(uid) = env::var(env_target_uid()).or_else(|_| env::var("SUDO_UID")) {
        cmd.arg(format!("--setenv={}={}", env_target_uid(), uid));
    }

    if let Ok(user) = env::var(env_target_user()).or_else(|_| env::var("SUDO_USER")) {
        cmd.arg(format!("--setenv={}={}", env_target_user(), user));
    }
}

fn propagate_shell_cleanup_protection(cmd: &mut Command) {
    if let Some(protected) = env::var_os(SHELL_CLEANUP_PROTECTED_PIDS_ENV) {
        cmd.arg(format!(
            "--setenv={}={}",
            SHELL_CLEANUP_PROTECTED_PIDS_ENV,
            protected.to_string_lossy()
        ));
    }
}

fn is_already_detached() -> bool {
    env::var_os(env_detached()).is_some()
}

/// Detach using systemd-run to create a transient service in system.slice.
///
/// Creates a proper one-shot service that runs independently of any user session.
pub fn maybe_detach_for_session_kill(
    kill_session: bool,
    args: &[OsString],
    session_ctx: Option<&SessionContext>,
) -> Result<(), NailsError> {
    // Testing override: allow tests to bypass actual detaching/spawn.
    if should_skip_detach() {
        return Ok(());
    }

    // Only detach when --kill-session is requested and we look like a GUI session.
    if !kill_session {
        return Ok(());
    }

    // Prevent recursion - if already detached, just continue.
    if is_already_detached() {
        eprintln!("DEBUG: Already detached, continuing...");
        return Ok(());
    }

    // Allow integration tests or users to force detaching for safety.
    let force_detach = env::var_os(env_force_detach()).is_some();

    if !force_detach {
        // Prefer logind-aware detection to avoid detaching from TTY/SSH.
        if let Some(ctx) = session_ctx {
            if ctx.kind != SessionKind::GraphicalUser {
                return Ok(());
            }
        } else if let Ok(ctx) = detect_session_context() {
            if ctx.kind != SessionKind::GraphicalUser {
                return Ok(());
            }
        } else {
            // If detection fails, fall back to env markers.
            if env::var_os("DISPLAY").is_none() && env::var_os("WAYLAND_DISPLAY").is_none() {
                return Ok(());
            }
        }
    }

    // Get the current binary path
    let exe_path = std::env::current_exe().map_err(|e| {
        NailsError::InvalidState(format!("Failed to get current executable path: {}", e))
    })?;

    // Generate unique unit name
    let unit_name = format!("{}{}.service", systemd_unit_prefix(), std::process::id());

    // Build systemd-run command
    // Using no --scope flag creates a proper transient service
    let mut cmd = Command::new(systemd_run_program()?);
    cmd.arg("--unit")
        .arg(&unit_name)
        .arg("--slice=system.slice")
        .arg("--same-dir") // Keep current working directory
        .arg("--collect") // Clean up unit after it finishes
        .arg("--quiet");

    // Set environment variables for the service
    cmd.arg(format!("--setenv={}=1", env_detached()));
    cmd.arg("--setenv=XDG_SESSION_ID="); // Clear session tracking

    // Set PATH to include NixOS binaries (nixos-rebuild, etc.)
    cmd.arg("--setenv=PATH=/run/current-system/sw/bin:/run/wrappers/bin:/usr/bin:/bin");

    // Capture and pass through all NIX_* environment variables from current environment
    // This ensures nixos-rebuild has all the Nix configuration it needs
    for (key, value) in env::vars() {
        if key.starts_with("NIX_") {
            cmd.arg(format!("--setenv={}={}", key, value));
        }
    }

    if let Some(ctx) = session_ctx
        && ctx.kind == SessionKind::GraphicalUser
    {
        if let Some(ref session_id) = ctx.session_id {
            cmd.arg(format!("--setenv={}={}", env_session_id(), session_id));
        }
        if let Some(ref dm) = ctx.display_manager {
            cmd.arg(format!("--setenv={}={}", env_display_manager(), dm));
        }
        if let Some(uid) = ctx.target_uid {
            cmd.arg(format!("--setenv={}={}", env_target_uid(), uid));
        }
        if let Some(ref user) = ctx.target_user {
            cmd.arg(format!("--setenv={}={}", env_target_user(), user));
        }
        cmd.arg(format!(
            "--setenv={}={}",
            env_logind_available(),
            if ctx.logind_available { "1" } else { "0" }
        ));
    }

    set_target_identity_from_environment(&mut cmd);

    // Redirect output to the systemd journal for post-mortem debugging
    cmd.arg("--property=StandardOutput=journal");
    cmd.arg("--property=StandardError=journal");

    // Add the command to execute
    cmd.arg("--");
    cmd.arg(&exe_path);
    cmd.args(args.iter().skip(1));

    // Execute systemd-run
    maybe_exit_after_detach(
        cmd,
        &[
            "Detached to background via systemd transient service.",
            "Handoff complete; activation continues in background.",
        ],
    )
}

/// Detach deactivation to a transient service so shell cleanup cannot kill the caller.
pub fn maybe_detach_for_deactivation() -> Result<(), NailsError> {
    if should_skip_detach() || is_already_detached() {
        return Ok(());
    }

    // Deactivation should run synchronously in the invoking context by default.
    // Detached transient services are opt-in only.
    let force_detach = env::var_os(env_force_detach()).is_some();
    if !force_detach {
        return Ok(());
    }

    let exe_path = std::env::current_exe().map_err(|e| {
        NailsError::InvalidState(format!("Failed to get current executable path: {}", e))
    })?;

    let argv: Vec<OsString> = std::env::args_os().collect();
    let unit_name = env::var(DEACTIVATE_UNIT_NAME_OVERRIDE_ENV)
        .unwrap_or_else(|_| format!("{}{}.service", DEACTIVATE_UNIT_PREFIX, std::process::id()));

    let mut cmd = Command::new(systemd_run_program()?);
    cmd.arg("--unit")
        .arg(&unit_name)
        .arg("--slice=system.slice")
        .arg("--collect")
        .arg("--quiet")
        .arg("--working-directory=/")
        .arg(format!("--setenv={}=1", env_detached()))
        .arg("--setenv=XDG_SESSION_ID=")
        .arg("--setenv=PATH=/run/current-system/sw/bin:/run/wrappers/bin:/usr/bin:/bin")
        .arg("--property=StandardOutput=journal")
        .arg("--property=StandardError=journal")
        .arg("--")
        .arg(&exe_path)
        .args(argv.iter().skip(1));

    set_target_identity_from_environment(&mut cmd);
    propagate_shell_cleanup_protection(&mut cmd);

    maybe_exit_after_detach(
        cmd,
        &[
            "Detached to background via systemd transient service.",
            "Handoff complete; deactivation continues in background.",
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_core::obfuscate::{env_detached, env_skip_detach};
    use std::env;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
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
        with_env(env_skip_detach(), "1", || {
            unsafe { env::set_var("DISPLAY", ":0") };
            let res = maybe_detach_for_session_kill(false, &[OsString::from("nails")], None);
            unsafe { env::remove_var("DISPLAY") };
            assert!(res.is_ok());
        });
    }

    #[test]
    fn does_nothing_without_graphical_env() {
        with_env(env_skip_detach(), "1", || {
            unsafe { env::remove_var("DISPLAY") };
            unsafe { env::remove_var("WAYLAND_DISPLAY") };
            let res = maybe_detach_for_session_kill(true, &[OsString::from("nails")], None);
            assert!(res.is_ok());
        });
    }

    #[test]
    fn skips_when_already_detached() {
        with_env(env_skip_detach(), "1", || {
            unsafe { env::set_var("DISPLAY", ":1") };
            unsafe { env::set_var(env_detached(), "1") };
            let res = maybe_detach_for_session_kill(true, &[OsString::from("nails")], None);
            unsafe { env::remove_var(env_detached()) };
            unsafe { env::remove_var("DISPLAY") };
            assert!(res.is_ok());
        });
    }

    #[test]
    fn deactivation_detach_respects_skip_env() {
        with_env(env_skip_detach(), "1", || {
            let res = maybe_detach_for_deactivation();
            assert!(res.is_ok());
        });
    }

    #[test]
    fn deactivation_detach_skips_when_already_detached() {
        with_env(env_skip_detach(), "1", || {
            unsafe { env::set_var(env_detached(), "1") };
            let res = maybe_detach_for_deactivation();
            unsafe { env::remove_var(env_detached()) };
            assert!(res.is_ok());
        });
    }

    #[test]
    fn subprocess_detach_entrypoint() {
        let Ok(case) = std::env::var("NAILS_DETACH_SUBPROCESS_CASE") else {
            return;
        };

        match case.as_str() {
            "block-deactivate" => {
                unsafe {
                    std::env::remove_var(env_skip_detach());
                    std::env::remove_var(env_detached());
                }
                maybe_detach_for_deactivation().expect("deactivation should run in-process");
            }
            "block-session" => {
                unsafe {
                    std::env::remove_var(env_skip_detach());
                    std::env::remove_var(env_detached());
                    std::env::set_var("DISPLAY", ":0");
                }
                let err = maybe_detach_for_session_kill(true, &[OsString::from("nails")], None)
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
                    std::env::remove_var(env_skip_detach());
                    std::env::remove_var(env_detached());
                    std::env::set_var(env_force_detach(), "1");
                }
                maybe_detach_for_deactivation().expect("override fake systemd-run should succeed");
            }
            other => panic!("unknown detach subprocess case: {other}"),
        }
    }

    #[test]
    fn deactivation_detach_defaults_to_in_process_execution() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
            .env("NAILS_DETACH_SUBPROCESS_CASE", "block-deactivate")
            .env_remove(env_skip_detach())
            .env_remove(env_detached())
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
            .env_remove(env_skip_detach())
            .env_remove(env_detached())
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
            .env(env_force_detach(), "1")
            .env(
                DEACTIVATE_UNIT_NAME_OVERRIDE_ENV,
                "nails-deactivate-test.service",
            )
            .env("SUDO_UID", "1000")
            .env("SUDO_USER", "alice")
            .env_remove(env_skip_detach())
            .env_remove(env_detached())
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
    }
}
