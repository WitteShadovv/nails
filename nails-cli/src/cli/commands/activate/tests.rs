// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

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

    // The child stands in for the CLI entry point: it reads the environment the
    // parent prepared on the `Command` exactly once and installs it, as `main`
    // does.
    let env = nails_core::RuntimeEnv::from_process_env();
    nails_core::runtime_env::install(env.clone());

    let execute =
        |settings: &OutputSettings, args: &ActivateArgs, config: Option<&std::path::Path>| {
            execute(settings, &env, args, config)
        };

    let config_override = std::env::var_os("NAILS_ACTIVATE_SUBPROCESS_CONFIG").map(PathBuf::from);

    let config = config_override.as_deref();
    let ascii = OutputSettings {
        ascii: true,
        ..OutputSettings::default()
    };
    let keep_session = ActivateArgs::default();
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
    crate::cli::chokepoint::exit_process(status.code());
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
    writeln!(config, "[sleep_policy]\nmod = \"warn\"").unwrap();

    let output = run_subprocess("invalid-config", Some(config.path()));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(3), "stderr={stderr}");
    assert!(stderr.contains("did you mean `mode`?"), "{stderr}");
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

/// The progress line names the hidden NixOS build only when there is one (not
/// on Debian or Ubuntu, not with `--overlay-only`) and the pre-flight checks
/// only when they run.
#[test]
fn the_progress_line_names_only_the_steps_the_entry_runs() {
    assert_eq!(
        super::preparing_line(true, true),
        "Preparing the hidden session (pre-flight, next root, hidden NixOS system)..."
    );
    assert_eq!(
        super::preparing_line(true, false),
        "Preparing the hidden session (pre-flight, next root)..."
    );
    assert_eq!(
        super::preparing_line(false, false),
        "Preparing the hidden session (next root)..."
    );
    assert_eq!(
        super::preparing_line(false, true),
        "Preparing the hidden session (next root, hidden NixOS system)..."
    );
}

/// The notes every baseline carries are not findings: a clean decoy is "no
/// known residue" without a count, and the other states count only their
/// warnings and critical findings, in the right number.
#[test]
fn the_residue_baseline_counts_only_warnings_and_critical_findings() {
    use nails_core::{Finding, ScanDepth, Severity, VerifyResult, VerifyStatus};
    let note = |text: &str| Finding::new(Severity::Info, "memory", text);
    let warn = |text: &str| Finding::new(Severity::Warn, "file", text);
    let critical = |text: &str| Finding::new(Severity::Critical, "mount", text);
    let notes = vec![
        note("RAM keeps the session's data until power-off"),
        note("Decoy-scoped baseline"),
        note("noted: timesync-clock"),
    ];
    let result = |status, mut findings: Vec<Finding>| {
        findings.extend(notes.clone());
        VerifyResult::new(status, findings, ScanDepth::Standard)
    };

    let clean = result(VerifyStatus::Secure, Vec::new());
    assert_eq!(super::baseline_summary(&clean), "no known residue");

    let one = result(VerifyStatus::Warning, vec![warn("a")]);
    assert_eq!(super::baseline_summary(&one), "1 warning");
    let two = result(VerifyStatus::Warning, vec![warn("a"), warn("b")]);
    assert_eq!(super::baseline_summary(&two), "2 warnings");

    let only_critical = result(VerifyStatus::Critical, vec![critical("c")]);
    assert_eq!(
        super::baseline_summary(&only_critical),
        "1 critical finding"
    );
    let mixed = result(
        VerifyStatus::Critical,
        vec![critical("c"), critical("d"), warn("a")],
    );
    assert_eq!(
        super::baseline_summary(&mixed),
        "2 critical findings, 1 warning"
    );
}

/// Without a config file activation says so before it asks, because every
/// opt-in protection then keeps its default; with one it says nothing.
#[test]
fn a_missing_config_file_is_announced_and_a_present_one_is_not() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nails.toml");
    let defaults = nails_core::LoadedConfig::defaults(&missing);
    assert_eq!(
        super::defaults_notice(&defaults),
        Some(format!(
            "No config file at {}: activation uses the built-in defaults.",
            missing.display()
        ))
    );

    std::fs::write(&missing, "show_opsec_reminders = false\n").unwrap();
    let found = nails_core::LoadedConfig::load(&missing).unwrap();
    assert_eq!(super::defaults_notice(&found), None);
}

/// `activate --dry-run` runs `check` with the options activation itself runs
/// the pre-flight checks with, for every combination of the shared flags.
#[test]
fn a_dry_run_checks_with_the_options_activation_uses() {
    for bits in 0..8u8 {
        let args = ActivateArgs {
            overlay_only: bits & 1 != 0,
            accept_persistent_decoy: bits & 2 != 0,
            allow_decoy_storage: bits & 4 != 0,
            dry_run: true,
            ..ActivateArgs::default()
        };
        assert_eq!(
            crate::cli::commands::check::preflight_options(&super::dry_run_check_args(&args)),
            super::enter_options(&args).preflight(),
            "{args:?}"
        );
    }
}

/// The prompt's answer, from a pipe standing in for the terminal.
fn answer_to(input: &[u8], cancelled: bool) -> super::Answer {
    use std::io::Write;
    use std::os::fd::AsFd;
    let (reader, mut writer) = std::io::pipe().unwrap();
    writer.write_all(input).unwrap();
    drop(writer);
    let poll_end = reader.try_clone().unwrap();
    super::read_answer(
        poll_end.as_fd(),
        &mut std::io::BufReader::new(reader),
        || cancelled,
    )
}

/// `n` ends the activation with exit 1, Ctrl+C at the prompt with 130, the
/// code of every other signal cancel; only `y` goes on.
#[test]
fn the_answer_decides_how_the_activation_ends() {
    use crate::cli::output::ExitStatus;
    assert_eq!(super::stop_status(super::Answer::Yes), None);
    assert_eq!(
        super::stop_status(super::Answer::No).map(ExitStatus::code),
        Some(1)
    );
    assert_eq!(
        super::stop_status(super::Answer::Cancelled).map(ExitStatus::code),
        Some(130)
    );
}

#[test]
fn the_prompt_takes_yes_and_nothing_else() {
    assert_eq!(answer_to(b"y\n", false), super::Answer::Yes);
    assert_eq!(answer_to(b" YES \n", false), super::Answer::Yes);
    assert_eq!(answer_to(b"n\n", false), super::Answer::No);
    assert_eq!(answer_to(b"", false), super::Answer::No, "end of input");
}

/// Ctrl+C at the prompt ends it at once, with nothing typed: the read is
/// never left waiting for Enter.
#[test]
fn a_cancel_at_the_prompt_ends_it_without_waiting_for_enter() {
    use std::os::fd::AsFd;
    let (reader, _writer) = std::io::pipe().unwrap();
    let poll_end = reader.try_clone().unwrap();
    let asked = std::cell::Cell::new(0);
    let answer = super::read_answer(
        poll_end.as_fd(),
        &mut std::io::BufReader::new(reader),
        || {
            asked.set(asked.get() + 1);
            asked.get() > 2
        },
    );
    assert_eq!(answer, super::Answer::Cancelled);
    assert!(asked.get() > 2, "the flag was read while the prompt waited");
    assert_eq!(answer_to(b"y\n", true), super::Answer::Cancelled);
}
