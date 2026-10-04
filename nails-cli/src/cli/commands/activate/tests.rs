// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::execute;
use crate::cli::args::{ActivateArgs, SessionPolicy};
use crate::cli::output::OutputSettings;
use nails_core::test_support::EnvGuard;
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

    let _env = EnvGuard::lock();
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
        session: SessionPolicy::Keep,
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
        "needs-confirmation-off-tty" => {
            execute(&OutputSettings::default(), &ActivateArgs::default(), config)
        }
        "needs-confirmation-plain" => execute(&ascii, &ActivateArgs::default(), config),
        "invalid-config" => execute(&OutputSettings::default(), &keep_session, config),
        "dry-run" => execute(
            &OutputSettings {
                verbosity: nails_core::Verbosity::Debug,
                ..ascii
            },
            &dry_run,
            config,
        ),
        "dry-run-no-color" => execute(&OutputSettings::default(), &dry_run, config),
        "dry-run-color" => execute(
            &OutputSettings {
                color_stdout: true,
                color_stderr: true,
                ..OutputSettings::default()
            },
            &dry_run,
            config,
        ),
        other => panic!("unknown activate subprocess case: {other}"),
    };
    crate::cli::detach::exit_process(status.code());
}

#[test]
fn execute_refuses_off_tty_without_yes() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(config, "hidden_volume_root = \"{}\"", hidden_root.display()).unwrap();

    let output = run_subprocess("needs-confirmation-off-tty", Some(config.path()));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(
        stderr.contains("stdin is not a terminal"),
        "stderr={stderr}"
    );
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
fn execute_routes_into_dry_run_mode() {
    use std::io::Write;

    let temp_dir = tempfile::tempdir().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(config, "hidden_volume_root = \"{}\"", hidden_root.display()).unwrap();

    // --dry-run is a thin alias for `check`; the tempdir is not a mounted hidden
    // volume, so the readiness check refuses with exit 4 but still reports.
    let output = run_subprocess("dry-run", Some(config.path()));
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(4), "stdout={stdout}");
    assert!(stdout.contains("NAILS Readiness Check"), "stdout={stdout}");
    assert!(stdout.contains("Pre-flight checks:"), "stdout={stdout}");
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

    assert_eq!(output.status.code(), Some(4), "stdout={stdout}");
    // A failing check renders the Unicode fail mark without any ANSI colour.
    assert!(stdout.contains("✗"), "stdout={stdout}");
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

    // Off a terminal without -y, activate refuses at the confirmation gate; in
    // ASCII mode that failure renders without any non-ASCII mark.
    let output = run_subprocess("needs-confirmation-plain", Some(config.path()));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(2), "stderr={stderr}");
    assert!(stderr.is_ascii(), "stderr={stderr}");
    assert!(!stderr.contains("✗"), "stderr={stderr}");
}

#[test]
fn execute_colour_settings_paint_dry_run_marks() {
    let output = run_subprocess("dry-run-color", None);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert_eq!(output.status.code(), Some(4), "stdout={stdout}");
    // A failing check paints its mark red when colour is on.
    assert!(
        stdout.contains("\u{001b}[1;31m✗\u{001b}[0m"),
        "stdout={stdout}"
    );
}
