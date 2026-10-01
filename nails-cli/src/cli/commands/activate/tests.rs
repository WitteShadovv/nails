use super::execute;
use crate::cli::args::ActivateArgs;
use crate::cli::output::OutputSettings;
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

#[test]
fn subprocess_activate_entrypoint() {
    let Ok(case) = std::env::var("NAILS_ACTIVATE_SUBPROCESS_CASE") else {
        return;
    };

    let config_override = std::env::var_os("NAILS_ACTIVATE_SUBPROCESS_CONFIG").map(PathBuf::from);

    let config = config_override.as_deref();
    let ascii = OutputSettings {
        ascii: true,
        ..OutputSettings::default()
    };
    let keep_session = ActivateArgs {
        no_kill_session: true,
        ..ActivateArgs::default()
    };
    let guarded = ActivateArgs {
        no_preflight: true,
        ..keep_session.clone()
    };
    let dry_run = ActivateArgs {
        dry_run: true,
        overlay_only: true,
        ..guarded.clone()
    };

    let status = match case.as_str() {
        "interactive-requires-yes" => execute(
            &OutputSettings::default(),
            &ActivateArgs {
                interactive: true,
                ..ActivateArgs::default()
            },
            None,
            |_| Ok(()),
        ),
        "invalid-config" => execute(
            &OutputSettings::default(),
            &keep_session,
            config,
            |_| Ok(()),
        ),
        "safety-guard" => execute(&OutputSettings::default(), &guarded, config, |_| {
            Err("activate guard blocked".to_string())
        }),
        "dry-run" => execute(
            &OutputSettings {
                verbosity: nails_core::Verbosity::Debug,
                ..ascii
            },
            &dry_run,
            config,
            |_| Ok(()),
        ),
        "dry-run-no-color" => execute(&OutputSettings::default(), &dry_run, config, |_| Ok(())),
        "dry-run-color" => execute(
            &OutputSettings {
                color_stdout: true,
                color_stderr: true,
                ..OutputSettings::default()
            },
            &dry_run,
            config,
            |_| Ok(()),
        ),
        "safety-guard-plain" => execute(&ascii, &guarded, config, |_| {
            Err("activate guard blocked".to_string())
        }),
        other => panic!("unknown activate subprocess case: {other}"),
    };
    crate::cli::detach::exit_process(status.code());
}

#[test]
fn execute_rejects_interactive_kill_session_before_loading_config() {
    let output = run_subprocess("interactive-requires-yes", None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(stderr.contains("--kill-session is non-interactive after detach; use --yes"));
}

#[test]
fn execute_exits_3_with_hint_for_unknown_key() {
    use std::io::Write;

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config,
        "hidden_volume_root = \"/mnt/hv\"\nnixos_flak = \"x\""
    )
    .unwrap();

    let output = run_subprocess("invalid-config", Some(config.path()));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(3), "stderr={stderr}");
    assert!(stderr.contains("invalid config"), "{stderr}");
    assert!(
        stderr.contains("unknown key `nixos_flak` (did you mean `nixos_flake`?)"),
        "{stderr}"
    );
    assert_eq!(stderr.trim().lines().count(), 1, "one error line: {stderr}");
}

#[test]
fn execute_exits_3_for_unknown_nested_key() {
    use std::io::Write;

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(config, "[color_scheme.decoy]\nrest = true").unwrap();

    let output = run_subprocess("invalid-config", Some(config.path()));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(3), "stderr={stderr}");
    assert!(stderr.contains("did you mean `reset`?"), "{stderr}");
}

#[test]
fn execute_exits_3_with_one_line_for_missing_explicit_config() {
    let temp_dir = tempfile::tempdir().unwrap();
    let missing = temp_dir.path().join("missing.toml");

    let output = run_subprocess("invalid-config", Some(&missing));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(3), "stderr={stderr}");
    assert_eq!(
        stderr.trim(),
        format!(
            "error: config file not found: {} (run `nails init <root>` or pass --config)",
            missing.display()
        )
    );
}

#[test]
fn execute_honors_safety_guard_after_loading_config() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(config, "hidden_volume_root = \"{}\"", hidden_root.display()).unwrap();

    let output = run_subprocess("safety-guard", Some(config.path()));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(5), "stderr={stderr}");
    assert!(stderr.contains("activate guard blocked"));
}

#[test]
fn execute_routes_into_dry_run_mode() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(config, "hidden_volume_root = \"{}\"", hidden_root.display()).unwrap();

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
    writeln!(config, "hidden_volume_root = \"{}\"", hidden_root.display()).unwrap();

    let output = run_subprocess("dry-run-no-color", Some(config.path()));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stdout={stdout} stderr={stderr}");
    assert!(stderr.trim().is_empty(), "stderr={stderr}");
    assert!(stdout.contains("⚠ Pre-flight checks skipped (--no-preflight)"));
    assert!(!stdout.contains("\u{001b}"), "stdout={stdout}");
}

#[test]
fn execute_ascii_uses_ascii_for_failures() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(config, "hidden_volume_root = \"{}\"", hidden_root.display()).unwrap();

    let output = run_subprocess("safety-guard-plain", Some(config.path()));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(5), "stderr={stderr}");
    assert!(stderr.is_ascii(), "stderr={stderr}");
    assert!(!stderr.contains("✗"), "stderr={stderr}");
}

#[test]
fn execute_colour_settings_paint_dry_run_marks() {
    let output = run_subprocess("dry-run-color", None);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout={stdout}");
    assert!(
        stdout.contains("\u{001b}[1;33m⚠\u{001b}[0m Pre-flight checks skipped (--no-preflight)"),
        "stdout={stdout}"
    );
}
