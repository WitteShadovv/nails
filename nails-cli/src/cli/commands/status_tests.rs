// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::{execute, status_exit_code};
use crate::cli::args::StatusArgs;
use crate::cli::output::{ExitStatus, OutputMode, OutputSettings};
use nails_core::status::Posture;
use std::io::Write;
use std::path::PathBuf;

#[test]
fn status_exit_code_is_driven_by_the_posture() {
    assert_eq!(status_exit_code(Posture::Decoy), ExitStatus::Ok);
    assert_eq!(status_exit_code(Posture::Active), ExitStatus::Ok);
    assert_eq!(status_exit_code(Posture::Transitioning), ExitStatus::Ok);
    assert_eq!(
        status_exit_code(Posture::Degraded),
        ExitStatus::DegradedReboot
    );
    assert_eq!(status_exit_code(Posture::Unknown), ExitStatus::InvalidState);
}

const SUBPROCESS_TEST_NAME: &str = "cli::commands::status::tests::subprocess_status_entrypoint";

fn run_subprocess(case: &str, config_path: &std::path::Path) -> std::process::Output {
    std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env("NAILS_STATUS_SUBPROCESS_CASE", case)
        .env("NAILS_STATUS_SUBPROCESS_CONFIG", config_path)
        .output()
        .expect("failed to run status subprocess test")
}

#[test]
fn subprocess_status_entrypoint() {
    let Ok(case) = std::env::var("NAILS_STATUS_SUBPROCESS_CASE") else {
        return;
    };
    let env = nails_core::RuntimeEnv::from_process_env();
    nails_core::runtime_env::install(env);
    let config = std::env::var_os("NAILS_STATUS_SUBPROCESS_CONFIG").map(PathBuf::from);
    let config = config.as_deref();
    let details = StatusArgs { details: true };
    let status = match case.as_str() {
        "ascii" => execute(
            &OutputSettings {
                ascii: true,
                ..OutputSettings::default()
            },
            &details,
            config,
        ),
        "json" => execute(
            &OutputSettings {
                mode: OutputMode::Json,
                ..OutputSettings::default()
            },
            &StatusArgs::default(),
            config,
        ),
        "no-color" => execute(&OutputSettings::default(), &details, config),
        other => panic!("unknown status subprocess case: {other}"),
    };
    crate::cli::chokepoint::exit_process(status.code());
}

fn config_for(hidden_root: &std::path::Path) -> tempfile::NamedTempFile {
    let mut config = tempfile::NamedTempFile::new().unwrap();
    writeln!(
        config,
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"",
        hidden_root.display(),
        hidden_root.join("state.json").display()
    )
    .unwrap();
    config
}

#[test]
fn a_plain_decoy_reports_decoy_in_ascii_with_details() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(dir.path());
    let output = run_subprocess("ascii", config.path());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "stdout={stdout}");
    assert!(stdout.contains("[DECOY]"), "stdout={stdout}");
    assert!(stdout.contains("State file:"), "stdout={stdout}");
    assert!(stdout.is_ascii(), "stdout={stdout}");
}

#[test]
fn json_status_is_one_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(dir.path());
    let output = run_subprocess("json", config.path());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find(|line| line.starts_with('{'))
        .unwrap_or_else(|| panic!("no JSON line: {stdout}"));
    let value: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(value["command"], "status");
    assert_eq!(value["data"]["place"], "decoy");
    assert_eq!(value["data"]["attention"], serde_json::Value::Null);
}

#[test]
fn a_corrupt_record_on_the_decoy_is_unknown_and_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("state.json"), "{ definitely-not-json").unwrap();
    let config = config_for(dir.path());
    let output = run_subprocess("no-color", config.path());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(6), "stdout={stdout}");
    assert!(stdout.contains("UNKNOWN"), "stdout={stdout}");
    assert!(!stdout.contains('\u{001b}'), "stdout={stdout}");
}
