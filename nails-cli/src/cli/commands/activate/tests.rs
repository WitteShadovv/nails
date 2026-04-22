use super::execute;
use std::path::PathBuf;

const SUBPROCESS_TEST_NAME: &str = "cli::commands::activate::tests::subprocess_activate_entrypoint";

fn run_subprocess(case: &str, config_path: Option<&std::path::Path>) -> std::process::Output {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env("NAILS_ACTIVATE_SUBPROCESS_CASE", case);

    if let Some(path) = config_path {
        command.env("NAILS_ACTIVATE_SUBPROCESS_CONFIG", path);
    }

    command
        .output()
        .expect("failed to run activate subprocess test")
}

fn run_subprocess_with_env(
    case: &str,
    config_path: Option<&std::path::Path>,
    envs: &[(&str, &str)],
) -> std::process::Output {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env("NAILS_ACTIVATE_SUBPROCESS_CASE", case);

    if let Some(path) = config_path {
        command.env("NAILS_ACTIVATE_SUBPROCESS_CONFIG", path);
    }

    for (key, value) in envs {
        command.env(key, value);
    }

    command
        .output()
        .expect("failed to run activate subprocess test")
}

#[test]
fn subprocess_activate_entrypoint() {
    let Ok(case) = std::env::var("NAILS_ACTIVATE_SUBPROCESS_CASE") else {
        return;
    };

    let config_override = std::env::var_os("NAILS_ACTIVATE_SUBPROCESS_CONFIG").map(PathBuf::from);

    match case.as_str() {
        "interactive-requires-yes" => execute(
            false,
            false,
            0,
            false,
            false,
            false,
            false,
            false,
            false,
            true,
            None,
            false,
            false,
            None,
            |_| Ok(()),
        ),
        "invalid-config" => execute(
            false,
            false,
            0,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            None,
            false,
            false,
            config_override,
            |_| Ok(()),
        ),
        "safety-guard" => execute(
            true,
            false,
            0,
            false,
            false,
            false,
            false,
            true,
            false,
            false,
            None,
            false,
            false,
            config_override,
            |_| Err("activate guard blocked".to_string()),
        ),
        "dry-run" => execute(
            true,
            false,
            2,
            false,
            false,
            true,
            false,
            true,
            false,
            false,
            None,
            true,
            true,
            config_override,
            |_| Ok(()),
        ),
        "dry-run-no-color" => execute(
            true,
            false,
            0,
            false,
            true,
            false,
            false,
            true,
            false,
            false,
            None,
            true,
            true,
            config_override,
            |_| Ok(()),
        ),
        "safety-guard-plain" => execute(
            true,
            false,
            0,
            false,
            false,
            true,
            false,
            true,
            false,
            false,
            None,
            false,
            false,
            config_override,
            |_| Err("activate guard blocked".to_string()),
        ),
        other => panic!("unknown activate subprocess case: {other}"),
    }
}

#[test]
fn execute_rejects_interactive_kill_session_before_loading_config() {
    let output = run_subprocess("interactive-requires-yes", None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(stderr.contains("--kill-session is non-interactive after detach; use --yes"));
}

#[test]
fn execute_fails_closed_for_invalid_config() {
    use std::io::Write;

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(config, "hidden_volume_path: [broken").unwrap();

    let output = run_subprocess("invalid-config", Some(config.path()));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(stderr.contains("Error loading config"));
    assert!(stderr.contains("Invalid YAML"));
}

#[test]
fn execute_honors_safety_guard_after_loading_config() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(config, "hidden_volume_path: {}", hidden_root.display()).unwrap();

    let output = run_subprocess("safety-guard", Some(config.path()));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(stderr.contains("activate guard blocked"));
}

#[test]
fn execute_routes_into_dry_run_mode() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(config, "hidden_volume_path: {}", hidden_root.display()).unwrap();

    let output = run_subprocess("dry-run", Some(config.path()));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout={stdout}");
    assert!(stdout.contains("=== NAILS Dry-Run: Activation Preview ==="));
    assert!(stdout.contains("[WARN] Pre-flight checks skipped (--no-preflight)"));
}

#[test]
fn execute_no_color_keeps_unicode_but_strips_ansi_from_failures() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(config, "hidden_volume_path: {}", hidden_root.display()).unwrap();

    let output = run_subprocess("dry-run-no-color", Some(config.path()));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stdout={stdout} stderr={stderr}");
    assert!(stderr.trim().is_empty(), "stderr={stderr}");
    assert!(stdout.contains("⚠ Pre-flight checks skipped (--no-preflight)"));
    assert!(!stdout.contains("\u{001b}"), "stdout={stdout}");
}

#[test]
fn execute_plain_uses_ascii_for_failures() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(config, "hidden_volume_path: {}", hidden_root.display()).unwrap();

    let output = run_subprocess("safety-guard-plain", Some(config.path()));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(stderr.is_ascii(), "stderr={stderr}");
    assert!(!stderr.contains("✗"), "stderr={stderr}");
}

#[test]
fn execute_no_color_env_keeps_unicode_without_ansi_in_dry_run() {
    let output = run_subprocess_with_env("dry-run-no-color", None, &[("NO_COLOR", "1")]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout={stdout}");
    assert!(stdout.contains("⚠ Pre-flight checks skipped (--no-preflight)"));
    assert!(!stdout.contains("\u{001b}"), "stdout={stdout}");
    assert!(!stdout.is_ascii(), "stdout={stdout}");
}
