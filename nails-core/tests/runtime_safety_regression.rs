use nails_core::test_support::EnvGuard;
use nails_core::{
    ProcessInfo, SessionContext, SessionKind, detect_processes_using,
    prompt_pivot_mount_acceptance, prompt_risky_process_restart, prompt_session_kill_confirmation,
};
use std::path::{Path, PathBuf};
use std::process::Command;

const SUBPROCESS_TEST_NAME: &str = "subprocess_runtime_safety_entrypoint";

/// Opt the calling test into test-runtime mode until the guard is dropped.
///
/// The runtime-safety skip is no longer inferred from the executable's path; a
/// build carrying the test hooks honours it only when `NAILS_TEST_RUNTIME` is
/// set. The guard sets it under the environment lock and restores it afterwards,
/// so no other test depends on whether this one ran first.
fn test_runtime_env() -> EnvGuard {
    let mut env = EnvGuard::lock();
    env.set("NAILS_TEST_RUNTIME", "1");
    env
}

fn run_subprocess(case: &str) -> std::process::Output {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env("NAILS_RUNTIME_SAFETY_SUBPROCESS_CASE", case)
        .env("NAILS_TEST_RUNTIME", "1")
        .output()
        .expect("failed to run runtime safety subprocess")
}

fn make_process(name: &str, pid: u32) -> ProcessInfo {
    ProcessInfo {
        pid,
        name: name.to_string(),
        cmdline: String::new(),
        cwd: PathBuf::from("/home/testuser"),
        has_cwd_in_target: true,
        has_open_fds_in_target: false,
        has_mmap_in_target: false,
        service_name: None,
        is_interactive: false,
    }
}

#[test]
fn detect_processes_using_returns_empty_in_test_like_runtime() {
    let _env = test_runtime_env();
    let detected = detect_processes_using(Path::new("/home"))
        .expect("test-like runtime should bypass host /proc inspection");

    assert!(
        detected.is_empty(),
        "test-like runtime must not surface host processes: {detected:?}"
    );
}

#[test]
fn risky_process_prompt_auto_declines_in_test_like_runtime() {
    let _env = test_runtime_env();
    let decision = prompt_risky_process_restart(&[make_process("pipewire", 6790)])
        .expect("test-like runtime should not block on risky-process prompt");

    assert!(!decision, "risky restarts must default to decline in tests");
}

#[test]
fn pivot_prompt_auto_declines_in_test_like_runtime() {
    let _env = test_runtime_env();
    let decision =
        prompt_pivot_mount_acceptance(Path::new("/home"), &[make_process("pipewire-pulse", 6791)])
            .expect("test-like runtime should not block on pivot prompt");

    assert!(
        !decision,
        "pivot acceptance must default to decline in tests"
    );
}

#[test]
fn session_kill_prompt_auto_declines_in_test_like_runtime() {
    let _env = test_runtime_env();
    let ctx = SessionContext {
        kind: SessionKind::GraphicalUser,
        session_id: Some("c2".to_string()),
        display_manager: Some("gdm.service".to_string()),
        target_uid: Some(1000),
        target_user: Some("alice".to_string()),
        logind_available: true,
    };

    let err = prompt_session_kill_confirmation(&ctx, false)
        .expect_err("test-like runtime must not prompt for session kill confirmation");

    assert!(err.to_string().contains("test/test-like runtime"));
}

#[test]
fn subprocess_runtime_safety_entrypoint() {
    let Ok(case) = std::env::var("NAILS_RUNTIME_SAFETY_SUBPROCESS_CASE") else {
        return;
    };

    match case.as_str() {
        "explicit-test-runtime" => {
            assert!(
                detect_processes_using(Path::new("/home"))
                    .expect("explicit test runtime should skip host process detection")
                    .is_empty()
            );
        }
        other => panic!("unknown runtime safety subprocess case: {other}"),
    }
}

#[test]
fn explicit_test_runtime_env_skips_host_interaction_outside_test_harness_binary_layout() {
    let output = run_subprocess("explicit-test-runtime");
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
