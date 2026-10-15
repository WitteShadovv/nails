// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use std::io;
use std::sync::{Arc, Mutex};

use tracing_subscriber::layer::SubscriberExt;

use super::logging_init_line;
use crate::cli::output::{OutputMode, OutputSettings};
use nails_core::Verbosity;

#[derive(Clone, Default)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuffer {
    type Writer = SharedWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SharedWriter(Arc::clone(&self.0))
    }
}

impl io::Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// What the console layer for `settings` writes while `emit` runs.
fn console_output(settings: &OutputSettings, emit: impl FnOnce()) -> String {
    let buffer = SharedBuffer::default();
    let captured = Arc::clone(&buffer.0);
    let subscriber = tracing_subscriber::registry().with(super::console::layer(settings, buffer));
    tracing::subscriber::with_default(subscriber, emit);
    let bytes = captured.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

/// A field rendered the way the stock formatter writes it: `key=value`.
fn has_raw_field(text: &str) -> bool {
    text.split_whitespace()
        .any(|word| word.split_once('=').is_some_and(|(key, _)| !key.is_empty()))
}

#[test]
fn the_default_console_prints_an_info_event_as_its_message_alone() {
    let output = console_output(&OutputSettings::default(), || {
        tracing::info!(
            event = "progress",
            phase = "nixos_build",
            files = 3,
            "copying 3 files (2 MB) onto the hidden volume"
        );
        // The progress fallback, as the store copy reports it.
        nails_core::reporter::progress::detail("nixos_build", "checking the hidden store database");
    });

    assert_eq!(
        output,
        "copying 3 files (2 MB) onto the hidden volume\nchecking the hidden store database\n"
    );
    assert!(!output.contains("INFO"), "{output}");
    assert!(!has_raw_field(&output), "{output}");
}

#[test]
fn the_default_console_marks_a_warning_and_keeps_its_fields() {
    let output = console_output(&OutputSettings::default(), || {
        tracing::warn!(
            file = %"/etc/nixos/configuration.nix",
            reason = "the mapper name",
            "Base NixOS config contains a hidden-environment reference"
        );
    });

    assert_eq!(
        output,
        "\u{26a0} Base NixOS config contains a hidden-environment reference \
         (file: /etc/nixos/configuration.nix, reason: the mapper name)\n"
    );
    assert!(!output.contains("WARN"), "{output}");
    assert!(!has_raw_field(&output), "{output}");
}

#[test]
fn the_default_console_uses_ascii_marks_and_colour_when_asked() {
    let ascii = OutputSettings {
        ascii: true,
        ..OutputSettings::default()
    };
    let output = console_output(&ascii, || {
        tracing::warn!("inherited-autostart: 3 items");
        tracing::error!(error = %"boom", "could not write the report");
    });
    assert_eq!(
        output,
        "[WARN] inherited-autostart: 3 items\n[FAIL] could not write the report (error: boom)\n"
    );

    let colour = OutputSettings {
        color_stderr: true,
        ..OutputSettings::default()
    };
    let output = console_output(&colour, || tracing::warn!("careful"));
    assert_eq!(output, "\u{1b}[1;33m\u{26a0}\u{1b}[0m careful\n");
}

#[test]
fn the_default_console_hides_debug_events() {
    let output = console_output(&OutputSettings::default(), || {
        tracing::debug!(check = "state", result = "pass", "Preflight check passed");
        tracing::trace!("a trace line");
    });
    assert_eq!(output, "");
}

#[test]
fn the_quiet_console_shows_errors_only() {
    let quiet = OutputSettings {
        verbosity: Verbosity::Quiet,
        ..OutputSettings::default()
    };
    let output = console_output(&quiet, || {
        tracing::info!("an info line");
        tracing::warn!("a warning");
        tracing::error!("an error");
    });
    assert_eq!(output, "\u{2717} an error\n");
}

#[test]
fn the_verbose_console_shows_full_records() {
    let verbose = OutputSettings {
        verbosity: Verbosity::Verbose,
        ..OutputSettings::default()
    };
    let output = console_output(&verbose, || {
        tracing::debug!(check = "state", "Preflight check passed");
    });
    assert!(output.contains("DEBUG"), "{output}");
    assert!(output.contains("check=\"state\""), "{output}");
    assert!(output.contains("Preflight check passed"), "{output}");
}

#[test]
fn the_panic_event_never_reaches_the_console() {
    for verbosity in [Verbosity::Quiet, Verbosity::Normal, Verbosity::Debug] {
        let settings = OutputSettings {
            verbosity,
            ..OutputSettings::default()
        };
        let output = console_output(&settings, || {
            tracing::error!(
                target: super::console::PANIC_TARGET,
                detail = "panicked at nails-cli/src/main.rs:1:1",
                "aborted by an internal error"
            );
        });
        assert_eq!(output, "", "{verbosity:?}");
    }
}

#[test]
fn test_log_file_created_with_mode_0o600() {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("test.log");

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_path)
        .unwrap();
    drop(file);

    let mode = log_path.metadata().unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "Log file should be 0o600, got {:#o}", mode);
}

#[test]
fn test_existing_log_file_normalized_to_0o600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("test.log");

    std::fs::write(&log_path, "old log data\n").unwrap();
    std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let file = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .unwrap();
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    drop(file);

    let mode = log_path.metadata().unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "Reopened log file should be normalized to 0o600, got {:#o}",
        mode
    );
}

fn settings(verbosity: Verbosity, color_stderr: bool, ascii: bool) -> OutputSettings {
    OutputSettings {
        verbosity,
        color_stderr,
        ascii,
        ..OutputSettings::default()
    }
}

#[test]
fn logging_init_warning_uses_ascii_marks_in_ascii_mode() {
    let line = logging_init_line(&settings(Verbosity::Normal, false, true), false, "w").unwrap();
    assert_eq!(line, "[WARN] w");
    let line = logging_init_line(&settings(Verbosity::Normal, false, true), true, "e").unwrap();
    assert_eq!(line, "[FAIL] e");
}

#[test]
fn logging_init_warning_without_colour_keeps_unicode_without_ansi() {
    let line = logging_init_line(&settings(Verbosity::Normal, false, false), false, "w").unwrap();
    assert_eq!(line, "⚠ w");
    let line = logging_init_line(&settings(Verbosity::Normal, false, false), true, "e").unwrap();
    assert_eq!(line, "✗ e");
}

#[test]
fn logging_init_message_follows_stderr_colour() {
    let line = logging_init_line(&settings(Verbosity::Normal, true, false), true, "e").unwrap();
    assert!(line.contains('\u{001b}'), "{line}");
}

#[test]
fn logging_init_warning_is_dropped_in_quiet_mode_but_errors_are_not() {
    let quiet = settings(Verbosity::Quiet, false, false);
    assert_eq!(logging_init_line(&quiet, false, "w"), None);
    assert_eq!(logging_init_line(&quiet, true, "e").as_deref(), Some("✗ e"));
}

const SUBPROCESS_TEST_NAME: &str = "cli::logging::tests::subprocess_logging_entrypoint";

fn run_subprocess(case: &str, config_path: Option<&std::path::Path>) -> std::process::Output {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", SUBPROCESS_TEST_NAME, "--nocapture"])
        .env("NAILS_LOGGING_SUBPROCESS_CASE", case);

    if let Some(path) = config_path {
        command.env("NAILS_LOGGING_SUBPROCESS_CONFIG", path);
    }

    command
        .output()
        .expect("failed to run logging subprocess test")
}

#[test]
fn subprocess_logging_entrypoint() {
    let Ok(case) = std::env::var("NAILS_LOGGING_SUBPROCESS_CASE") else {
        return;
    };

    // Stand in for the CLI entry point: read the environment the parent prepared
    // once and install it for the leaf helpers (the attach gate among them).
    nails_core::runtime_env::install(nails_core::RuntimeEnv::from_process_env());

    let config_override =
        std::env::var_os("NAILS_LOGGING_SUBPROCESS_CONFIG").map(std::path::PathBuf::from);

    let normal = OutputSettings::default();
    let with = |verbosity| OutputSettings {
        verbosity,
        ..OutputSettings::default()
    };
    let json = OutputSettings {
        mode: OutputMode::Json,
        ..OutputSettings::default()
    };
    let config = config_override.as_deref();

    match case.as_str() {
        "stdout-human" => {
            super::init_subscriber(&with(Verbosity::Verbose), false, config);
            tracing::debug!(phase = "logging", "debug line from subprocess");
        }
        "stdout-human-color" => {
            let colored = OutputSettings {
                color_stderr: true,
                ..OutputSettings::default()
            };
            super::init_subscriber(&colored, false, config);
            tracing::warn!(phase = "logging", "coloured line from subprocess");
        }
        "stdout-human-with-file-layer" => {
            super::init_subscriber(&with(Verbosity::Verbose), true, config);
            tracing::debug!(phase = "logging", "debug line with file layer");
        }
        "stdout-json" => {
            super::init_subscriber(&json, false, config);
            tracing::info!(
                event = "progress",
                phase = "logging",
                "json line from subprocess"
            );
            tracing::warn!(file = "/x", "json warning from subprocess");
        }
        "stdout-json-with-file-layer" => {
            super::init_subscriber(&json, true, config);
            tracing::info!(
                event = "progress",
                phase = "logging",
                "json line with file layer"
            );
        }
        "stdout-quiet" => {
            super::init_subscriber(&with(Verbosity::Quiet), false, config);
            tracing::info!(phase = "logging", "quiet info line");
            tracing::warn!(phase = "logging", "quiet warn line");
            tracing::error!(phase = "logging", "quiet error line");
        }
        "stdout-trace" => {
            super::init_subscriber(&with(Verbosity::Debug), false, config);
            tracing::trace!(phase = "logging", "trace line from subprocess");
        }
        "stdout-normal" => {
            super::init_subscriber(&normal, false, config);
            tracing::debug!(phase = "logging", "hidden debug line");
            tracing::info!(phase = "logging", "visible info line");
        }
        "emit-ascii-warning" => {
            let ascii = OutputSettings {
                ascii: true,
                ..OutputSettings::default()
            };
            super::emit_logging_init_message(&ascii, false, "ascii warning");
        }
        "emit-no-color-error" => {
            super::emit_logging_init_message(&normal, true, "no color error");
        }
        "invalid-file-layer-config" => {
            super::init_subscriber(&normal, true, config);
            tracing::info!(phase = "logging", "fallback stdout line");
        }
        "unreadable-config-no-silent-default" => {
            // The config path is invalid, so file logging must stay off rather
            // than fall back to the binary-derived default root. The marker line
            // may reach the console but must never land in a log file under that
            // default root.
            super::init_subscriber(&normal, true, config);
            tracing::info!(phase = "logging", "no-silent-default marker line");
        }
        "directory-log-target-human" => {
            super::init_subscriber(&normal, true, config);
            tracing::info!(phase = "logging", "directory fallback line");
        }
        "directory-log-target-quiet" => {
            super::init_subscriber(&with(Verbosity::Quiet), true, config);
            tracing::error!(phase = "logging", "quiet directory fallback line");
        }
        other => panic!("unknown logging subprocess case: {other}"),
    }
}

#[test]
fn init_subscriber_wrapper_emits_debug_to_stderr_in_subprocess() {
    let output = run_subprocess("stdout-human", None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr={stderr}");
    assert!(stderr.contains("DEBUG"), "stderr={stderr}");
    assert!(
        stderr.contains("debug line from subprocess"),
        "stderr={stderr}"
    );
}

/// Under `--json` stdout carries the command's documented JSON alone, so the
/// log stays on stderr, in the same compact form as without `--json`.
#[test]
fn init_subscriber_json_mode_keeps_the_log_off_stdout_in_subprocess() {
    let output = run_subprocess("stdout-json", None);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr={stderr}");
    assert!(!stdout.contains("json line"), "stdout={stdout}");
    assert!(!stdout.contains("json warning"), "stdout={stdout}");
    assert!(stderr.contains("json line from subprocess\n"), "{stderr}");
    assert!(
        stderr.contains("\u{26a0} json warning from subprocess (file: /x)"),
        "{stderr}"
    );
}

#[test]
fn init_subscriber_quiet_mode_shows_only_errors() {
    let output = run_subprocess("stdout-quiet", None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr={stderr}");
    assert!(stderr.contains("quiet error line"), "stderr={stderr}");
    assert!(!stderr.contains("quiet warn line"), "stderr={stderr}");
    assert!(!stderr.contains("quiet info line"), "stderr={stderr}");
}

#[test]
fn init_subscriber_human_output_has_no_timestamps() {
    let output = run_subprocess("stdout-normal", None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr={stderr}");
    let line = stderr
        .lines()
        .find(|line| line.contains("visible info line"))
        .expect("expected the info line on stderr");
    // A default tracing timestamp leads the line with an ISO-8601 date
    // (`2026-10-03T...`). With `.without_time()` the line opens with the level
    // or the message, so its first non-space character is never a digit.
    let first = line.trim_start().chars().next().expect("non-empty line");
    assert!(
        !first.is_ascii_digit(),
        "human log line still carries a leading timestamp: {line:?}"
    );
}

#[test]
fn init_subscriber_normal_mode_hides_debug() {
    let output = run_subprocess("stdout-normal", None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr={stderr}");
    assert!(stderr.contains("visible info line"), "stderr={stderr}");
    assert!(!stderr.contains("hidden debug line"), "stderr={stderr}");
}

/// The installed subscriber is the compact console: an info event is its
/// message, with neither the level word nor its fields.
#[test]
fn init_subscriber_normal_mode_prints_the_message_alone() {
    let output = run_subprocess("stdout-normal", None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr={stderr}");
    assert!(
        stderr.lines().any(|line| line == "visible info line"),
        "stderr={stderr}"
    );
    assert!(!stderr.contains("INFO"), "stderr={stderr}");
    assert!(!stderr.contains("phase="), "stderr={stderr}");
}

#[test]
fn init_subscriber_emits_ansi_only_when_stderr_colour_is_on() {
    let plain = run_subprocess("stdout-normal", None);
    let plain_stderr = String::from_utf8_lossy(&plain.stderr);
    assert!(!plain_stderr.contains('\u{001b}'), "stderr={plain_stderr}");

    let colored = run_subprocess("stdout-human-color", None);
    let colored_stderr = String::from_utf8_lossy(&colored.stderr);
    assert!(colored.status.success(), "stderr={colored_stderr}");
    assert!(
        colored_stderr.contains('\u{001b}'),
        "stderr={colored_stderr}"
    );
}

#[test]
fn init_subscriber_trace_verbosity_emits_trace_lines() {
    let output = run_subprocess("stdout-trace", None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr={stderr}");
    assert!(stderr.contains("TRACE"), "stderr={stderr}");
    assert!(
        stderr.contains("trace line from subprocess"),
        "stderr={stderr}"
    );
}

#[test]
fn emit_logging_init_message_ascii_warning_is_ascii_in_subprocess() {
    let output = run_subprocess("emit-ascii-warning", None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr={stderr}");
    assert!(stderr.contains("[WARN] ascii warning"), "stderr={stderr}");
    assert!(stderr.is_ascii(), "stderr={stderr}");
}

#[test]
fn emit_logging_init_message_no_color_error_uses_unicode_without_ansi() {
    let output = run_subprocess("emit-no-color-error", None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr={stderr}");
    assert!(stderr.contains("✗ no color error"), "stderr={stderr}");
    assert!(!stderr.contains("\u{001b}"), "stderr={stderr}");
}

// The attached happy path (init_file_layer returns Some and writes the log) is
// covered by the subprocess file-layer tests in `kernel_tests`, whose hidden
// root is a tmpfs in a user + mount namespace the subprocess inherits. An
// in-process equivalent would need this whole test binary in that namespace.

#[test]
fn init_file_layer_gracefully_returns_none_for_missing_hidden_volume() {
    use std::io::Write;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let hidden_root = temp_dir.path().join("missing-hidden-volume");
    let config_path = temp_dir.path().join("nails.toml");

    let mut config_file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "hidden_volume_root = \"{}\"\nlog_path = \"{}\"",
        hidden_root.display(),
        hidden_root.join("logs").display(),
    )
    .unwrap();

    let file_layer =
        super::init_file_layer(Some(&config_path), &OutputSettings::default()).unwrap();
    assert!(file_layer.is_none());
}

#[test]
fn invalid_explicit_config_never_logs_to_the_default_root() {
    // An explicit `--config` that cannot be loaded must not be silently replaced
    // by the binary-derived default configuration. Before this was fixed, file
    // logging re-loaded the config on its own and fell back to `Config::default`,
    // which — on an attached root like the subprocess's own directory — opened a
    // log file right next to the binary even though the operator named a config
    // that failed to load. File logging must now simply stay off; the
    // command surfaces the config error and exits.
    let temp_dir = tempfile::TempDir::new().unwrap();
    let config_path = temp_dir.path().join("nails.toml");
    // Unknown key: strict loading rejects it, so resolution fails.
    std::fs::write(&config_path, "definitely_not_a_key = true\n").unwrap();

    // Where a silent default would place the log: `{binary parent}/logs`, the
    // subprocess's default root. The subprocess runs the same test binary, so
    // its derived root matches this one.
    let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
    let default_log = exe.parent().unwrap().join("logs").join("nails.log");
    // Start from a clean slate so a log left by a regressed earlier run cannot
    // make this assertion stick after the fix.
    let _ = std::fs::remove_file(&default_log);

    let output = run_subprocess("unreadable-config-no-silent-default", Some(&config_path));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr={stderr}");
    // The marker still reaches the console (stdout-only fallback).
    assert!(
        stderr.contains("no-silent-default marker line"),
        "stderr={stderr}"
    );
    // But it must not have been written to a log file under the default root.
    let leaked = std::fs::read_to_string(&default_log).unwrap_or_default();
    assert!(
        !leaked.contains("no-silent-default marker line"),
        "a log was silently written to the default root {}",
        default_log.display()
    );
}

/// The file-layer cases, which need the attach gate to accept the hidden root:
/// each runs in an unprivileged user + mount namespace with a tmpfs as the
/// hidden root, and the logging subprocess inherits that namespace.
mod kernel_tests {
    use super::run_subprocess;
    use nails_core::test_path;
    use nails_core::test_support::{Rerun, ScratchTmpfs};

    #[test]
    fn init_subscriber_json_mode_with_file_layer_keeps_stdout_clean_and_writes_log() {
        let _ = Rerun::new(test_path!(
            init_subscriber_json_mode_with_file_layer_keeps_stdout_clean_and_writes_log
        ))
        .in_user_mount_ns()
        .run(|| {
            use std::io::Write;

            let temp_dir = tempfile::TempDir::new().unwrap();
            let volume = ScratchTmpfs::new("");
            let hidden_root = volume.path().to_path_buf();
            let log_dir = hidden_root.join("logs");
            let config_path = temp_dir.path().join("nails.toml");

            std::fs::create_dir_all(&log_dir).unwrap();

            let mut config_file = std::fs::File::create(&config_path).unwrap();
            writeln!(
                config_file,
                "hidden_volume_root = \"{}\"\nlog_path = \"{}\"",
                hidden_root.display(),
                log_dir.display(),
            )
            .unwrap();

            let output = run_subprocess("stdout-json-with-file-layer", Some(&config_path));
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let log_contents = std::fs::read_to_string(log_dir.join("nails.log")).unwrap();

            assert!(output.status.success(), "stderr={stderr}");
            assert!(!stdout.contains("json line"), "stdout={stdout}");
            assert!(stderr.contains("json line with file layer"), "{stderr}");
            assert!(
                log_contents.contains("json line with file layer"),
                "log_contents={log_contents}"
            );
        });
    }

    #[test]
    fn init_subscriber_with_file_layer_writes_json_log_and_stderr() {
        let _ = Rerun::new(test_path!(
            init_subscriber_with_file_layer_writes_json_log_and_stderr
        ))
        .in_user_mount_ns()
        .run(|| {
            use std::io::Write;

            let temp_dir = tempfile::TempDir::new().unwrap();
            let volume = ScratchTmpfs::new("");
            let hidden_root = volume.path().to_path_buf();
            let log_dir = hidden_root.join("logs");
            let config_path = temp_dir.path().join("nails.toml");

            std::fs::create_dir_all(&log_dir).unwrap();

            let mut config_file = std::fs::File::create(&config_path).unwrap();
            writeln!(
                config_file,
                "hidden_volume_root = \"{}\"\nlog_path = \"{}\"",
                hidden_root.display(),
                log_dir.display(),
            )
            .unwrap();

            let output = run_subprocess("stdout-human-with-file-layer", Some(&config_path));
            let stderr = String::from_utf8_lossy(&output.stderr);
            let log_contents = std::fs::read_to_string(log_dir.join("nails.log")).unwrap();

            assert!(output.status.success(), "stderr={stderr}");
            assert!(
                stderr.contains("debug line with file layer"),
                "stderr={stderr}"
            );
            assert!(
                log_contents.contains("debug line with file layer"),
                "log_contents={log_contents}"
            );
            assert!(
                log_contents.contains("\"level\":\"DEBUG\""),
                "log_contents={log_contents}"
            );
        });
    }

    #[test]
    fn init_subscriber_falls_back_when_log_path_is_invalid() {
        let _ = Rerun::new(test_path!(
            init_subscriber_falls_back_when_log_path_is_invalid
        ))
        .in_user_mount_ns()
        .run(|| {
            use std::io::Write;

            let temp_dir = tempfile::TempDir::new().unwrap();
            let volume = ScratchTmpfs::new("");
            let hidden_root = volume.path().to_path_buf();
            let config_path = temp_dir.path().join("nails.toml");
            std::fs::create_dir_all(&hidden_root).unwrap();
            // A log path outside the hidden volume no longer loads at all, so make
            // the log directory impossible to create instead: its parent is a file.
            let blocker = hidden_root.join("blocker");
            std::fs::write(&blocker, "").unwrap();

            let mut config_file = std::fs::File::create(&config_path).unwrap();
            writeln!(
                config_file,
                "hidden_volume_root = \"{}\"\nlog_path = \"{}\"",
                hidden_root.display(),
                blocker.join("logs").display(),
            )
            .unwrap();

            let output = run_subprocess("invalid-file-layer-config", Some(&config_path));
            let stderr = String::from_utf8_lossy(&output.stderr);

            assert!(output.status.success(), "stderr={stderr}");
            assert!(stderr.contains("Logging init failed"), "stderr={stderr}");
            assert!(stderr.contains("fallback stdout line"), "stderr={stderr}");
        });
    }

    #[test]
    fn init_subscriber_warns_when_log_file_target_is_a_directory() {
        let _ = Rerun::new(test_path!(
            init_subscriber_warns_when_log_file_target_is_a_directory
        ))
        .in_user_mount_ns()
        .run(|| {
            use std::io::Write;

            let temp_dir = tempfile::TempDir::new().unwrap();
            let volume = ScratchTmpfs::new("");
            let hidden_root = volume.path().to_path_buf();
            let log_dir = hidden_root.join("logs");
            let config_path = temp_dir.path().join("nails.toml");

            std::fs::create_dir_all(log_dir.join("nails.log")).unwrap();

            let mut config_file = std::fs::File::create(&config_path).unwrap();
            writeln!(
                config_file,
                "hidden_volume_root = \"{}\"\nlog_path = \"{}\"",
                hidden_root.display(),
                log_dir.display(),
            )
            .unwrap();

            let output = run_subprocess("directory-log-target-human", Some(&config_path));
            let stderr = String::from_utf8_lossy(&output.stderr);

            assert!(output.status.success(), "stderr={stderr}");
            assert!(
                stderr.contains("Failed to open log file"),
                "stderr={stderr}"
            );
            assert!(
                stderr.contains("directory fallback line"),
                "stderr={stderr}"
            );
        });
    }

    #[test]
    fn init_subscriber_quiet_mode_suppresses_log_file_open_warning() {
        let _ = Rerun::new(test_path!(
            init_subscriber_quiet_mode_suppresses_log_file_open_warning
        ))
        .in_user_mount_ns()
        .run(|| {
            use std::io::Write;

            let temp_dir = tempfile::TempDir::new().unwrap();
            let volume = ScratchTmpfs::new("");
            let hidden_root = volume.path().to_path_buf();
            let log_dir = hidden_root.join("logs");
            let config_path = temp_dir.path().join("nails.toml");

            std::fs::create_dir_all(log_dir.join("nails.log")).unwrap();

            let mut config_file = std::fs::File::create(&config_path).unwrap();
            writeln!(
                config_file,
                "hidden_volume_root = \"{}\"\nlog_path = \"{}\"",
                hidden_root.display(),
                log_dir.display(),
            )
            .unwrap();

            let output = run_subprocess("directory-log-target-quiet", Some(&config_path));
            let stderr = String::from_utf8_lossy(&output.stderr);

            assert!(output.status.success(), "stderr={stderr}");
            assert!(
                stderr.contains("quiet directory fallback line"),
                "stderr={stderr}"
            );
            assert!(
                !stderr.contains("Failed to open log file"),
                "stderr={stderr}"
            );
            assert!(!stderr.contains('\u{001b}'), "stderr={stderr}");
        });
    }
}
