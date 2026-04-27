use std::io;
use std::sync::{Arc, Mutex};

use super::{RenderMode, StdoutFormat, render_mode};

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

#[test]
fn activate_json_stream_formats_progress_events_as_structured_json() {
    let output = SharedBuffer::default();
    let captured = Arc::clone(&output.0);

    let subscriber = tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_target(false)
        .with_level(true)
        .with_writer(output)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(
            event = "progress",
            phase = "session_management",
            current = 1,
            total = 6,
            "[1/6] Preparing session management..."
        );
    });

    let payload = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    let line = payload
        .lines()
        .find(|line| !line.trim().is_empty())
        .expect("expected one JSON log line");
    let json: serde_json::Value = serde_json::from_str(line).unwrap();

    assert_eq!(
        json.get("event").and_then(|value| value.as_str()),
        Some("progress")
    );
    assert_eq!(
        json.get("phase").and_then(|value| value.as_str()),
        Some("session_management")
    );
    assert_eq!(
        json.get("current").and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(json.get("total").and_then(|value| value.as_u64()), Some(6));
    assert_eq!(
        json.get("level").and_then(|value| value.as_str()),
        Some("INFO")
    );
    assert_eq!(
        json.get("message").and_then(|value| value.as_str()),
        Some("[1/6] Preparing session management...")
    );
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

#[test]
fn render_mode_treats_plain_as_stricter_than_no_color() {
    nails_core::set_plain_mode(false);
    nails_core::set_color_enabled(true);

    assert_eq!(render_mode(false, false), RenderMode::Human);
    assert_eq!(render_mode(true, false), RenderMode::NoColor);
    assert_eq!(render_mode(true, true), RenderMode::Plain);
}

#[test]
fn logging_init_warning_uses_ascii_in_plain_mode() {
    let rendered = match RenderMode::Plain {
        RenderMode::Plain => {
            let message = "Failed to open log file: denied, continuing without file logging";
            let mut out = String::new();
            let _ = std::fmt::write(&mut out, format_args!("[WARN] {message}"));
            out
        }
        _ => unreachable!(),
    };

    assert!(rendered.is_ascii());
    assert!(rendered.starts_with("[WARN]"));
}

#[test]
fn logging_init_warning_no_color_keeps_unicode_without_ansi() {
    let rendered = match RenderMode::NoColor {
        RenderMode::NoColor => {
            let message = "Failed to open log file: denied, continuing without file logging";
            let mut out = String::new();
            let _ = std::fmt::write(&mut out, format_args!("⚠ {message}"));
            out
        }
        _ => unreachable!(),
    };

    assert_eq!(
        rendered,
        "⚠ Failed to open log file: denied, continuing without file logging"
    );
    assert!(!rendered.contains("\u{001b}"));
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

    let config_override =
        std::env::var_os("NAILS_LOGGING_SUBPROCESS_CONFIG").map(std::path::PathBuf::from);

    match case.as_str() {
        "stdout-human" => {
            super::init_stdout_subscriber(1, false, true, config_override.as_deref());
            tracing::debug!(phase = "logging", "debug line from subprocess");
        }
        "stdout-human-with-file-layer" => {
            super::init_stdout_subscriber(1, false, false, config_override.as_deref());
            tracing::debug!(phase = "logging", "debug line with file layer");
        }
        "stdout-json" => {
            super::init_stdout_subscriber_with_mode(
                0,
                false,
                true,
                false,
                false,
                config_override.as_deref(),
                StdoutFormat::ActivateJsonStream,
            );
            tracing::info!(
                event = "progress",
                phase = "logging",
                current = 1,
                total = 1,
                "json line from subprocess"
            );
        }
        "stdout-json-with-file-layer" => {
            super::init_stdout_subscriber_with_mode(
                0,
                false,
                false,
                false,
                false,
                config_override.as_deref(),
                StdoutFormat::ActivateJsonStream,
            );
            tracing::info!(
                event = "progress",
                phase = "logging",
                current = 1,
                total = 1,
                "json line with file layer"
            );
        }
        "stdout-quiet" => {
            super::init_stdout_subscriber(0, true, true, config_override.as_deref());
            tracing::info!(phase = "logging", "quiet info line");
            tracing::warn!(phase = "logging", "quiet warn line");
        }
        "stdout-trace" => {
            super::init_stdout_subscriber(2, false, true, config_override.as_deref());
            tracing::trace!(phase = "logging", "trace line from subprocess");
        }
        "emit-plain-warning" => {
            super::emit_logging_init_message(RenderMode::Plain, false, "plain warning");
        }
        "emit-no-color-error" => {
            super::emit_logging_init_message(RenderMode::NoColor, true, "no color error");
        }
        "invalid-file-layer-config" => {
            super::init_stdout_subscriber(0, false, false, config_override.as_deref());
            tracing::info!(phase = "logging", "fallback stdout line");
        }
        "directory-log-target-human" => {
            super::init_stdout_subscriber(0, false, false, config_override.as_deref());
            tracing::info!(phase = "logging", "directory fallback line");
        }
        "directory-log-target-plain" => {
            super::init_stdout_subscriber_with_mode(
                0,
                false,
                false,
                false,
                true,
                config_override.as_deref(),
                StdoutFormat::Human,
            );
            tracing::info!(phase = "logging", "plain directory fallback line");
        }
        other => panic!("unknown logging subprocess case: {other}"),
    }
}

#[test]
fn init_stdout_subscriber_wrapper_emits_debug_to_stderr_in_subprocess() {
    let output = run_subprocess("stdout-human", None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr={stderr}");
    assert!(stderr.contains("DEBUG"), "stderr={stderr}");
    assert!(
        stderr.contains("debug line from subprocess"),
        "stderr={stderr}"
    );
}

#[test]
fn init_stdout_subscriber_json_mode_emits_structured_stdout_in_subprocess() {
    let output = run_subprocess("stdout-json", None);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success(), "stdout={stdout}");
    assert!(stdout.contains("\"event\":\"progress\""), "stdout={stdout}");
    assert!(stdout.contains("\"phase\":\"logging\""), "stdout={stdout}");
    assert!(
        stdout.contains("\"message\":\"json line from subprocess\""),
        "stdout={stdout}"
    );
}

#[test]
fn init_stdout_subscriber_json_mode_with_file_layer_emits_stdout_and_writes_log() {
    use std::io::Write;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let log_dir = hidden_root.join("logs");
    let config_path = temp_dir.path().join("nails.yaml");

    std::fs::create_dir_all(&log_dir).unwrap();

    let mut config_file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "hidden_volume_path: {}\nlog_path: {}\noverlays: []",
        hidden_root.display(),
        log_dir.display(),
    )
    .unwrap();

    let output = run_subprocess("stdout-json-with-file-layer", Some(&config_path));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let log_contents = std::fs::read_to_string(log_dir.join("nails.log")).unwrap();

    assert!(output.status.success(), "stdout={stdout}");
    assert!(
        stdout.contains("\"message\":\"json line with file layer\""),
        "stdout={stdout}"
    );
    assert!(
        log_contents.contains("json line with file layer"),
        "log_contents={log_contents}"
    );
}

#[test]
fn init_stdout_subscriber_quiet_mode_filters_info_but_keeps_warn() {
    let output = run_subprocess("stdout-quiet", None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr={stderr}");
    assert!(stderr.contains("WARN"), "stderr={stderr}");
    assert!(stderr.contains("quiet warn line"), "stderr={stderr}");
    assert!(!stderr.contains("quiet info line"), "stderr={stderr}");
}

#[test]
fn init_stdout_subscriber_trace_verbosity_emits_trace_lines() {
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
fn emit_logging_init_message_plain_warning_is_ascii_in_subprocess() {
    let output = run_subprocess("emit-plain-warning", None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr={stderr}");
    assert!(stderr.contains("[WARN] plain warning"), "stderr={stderr}");
    assert!(stderr.is_ascii(), "stderr={stderr}");
}

#[test]
fn emit_logging_init_message_no_color_error_uses_plain_unicode_without_ansi() {
    let output = run_subprocess("emit-no-color-error", None);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr={stderr}");
    assert!(stderr.contains("X no color error"), "stderr={stderr}");
    assert!(!stderr.contains("\u{001b}"), "stderr={stderr}");
}

#[test]
fn init_file_layer_returns_some_for_existing_hidden_volume() {
    use std::io::Write;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let log_dir = hidden_root.join("logs");
    let config_path = temp_dir.path().join("nails.yaml");

    std::fs::create_dir_all(&hidden_root).unwrap();
    std::fs::create_dir_all(&log_dir).unwrap();

    let mut config_file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "hidden_volume_path: {}\nlog_path: {}\noverlays: []",
        hidden_root.display(),
        log_dir.display(),
    )
    .unwrap();

    let file_layer = super::init_file_layer(Some(&config_path), RenderMode::Human).unwrap();
    assert!(file_layer.is_some());
    assert!(log_dir.join("nails.log").exists());
}

#[test]
fn init_file_layer_gracefully_returns_none_for_missing_hidden_volume() {
    use std::io::Write;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let hidden_root = temp_dir.path().join("missing-hidden-volume");
    let config_path = temp_dir.path().join("nails.yaml");

    let mut config_file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "hidden_volume_path: {}\nlog_path: {}\noverlays: []",
        hidden_root.display(),
        hidden_root.join("logs").display(),
    )
    .unwrap();

    let file_layer = super::init_file_layer(Some(&config_path), RenderMode::Human).unwrap();
    assert!(file_layer.is_none());
}

#[test]
fn init_stdout_subscriber_with_file_layer_writes_json_log_and_stderr() {
    use std::io::Write;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let log_dir = hidden_root.join("logs");
    let config_path = temp_dir.path().join("nails.yaml");

    std::fs::create_dir_all(&log_dir).unwrap();

    let mut config_file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "hidden_volume_path: {}\nlog_path: {}\noverlays: []",
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
}

#[test]
fn init_stdout_subscriber_falls_back_when_log_path_is_invalid() {
    use std::io::Write;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let config_path = temp_dir.path().join("nails.yaml");
    std::fs::create_dir_all(&hidden_root).unwrap();

    let mut config_file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "hidden_volume_path: {}\nlog_path: /var/log\noverlays: []",
        hidden_root.display(),
    )
    .unwrap();

    let output = run_subprocess("invalid-file-layer-config", Some(&config_path));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr={stderr}");
    assert!(stderr.contains("Logging init failed"), "stderr={stderr}");
    assert!(stderr.contains("fallback stdout line"), "stderr={stderr}");
}

#[test]
fn init_stdout_subscriber_warns_when_log_file_target_is_a_directory() {
    use std::io::Write;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let log_dir = hidden_root.join("logs");
    let config_path = temp_dir.path().join("nails.yaml");

    std::fs::create_dir_all(log_dir.join("nails.log")).unwrap();

    let mut config_file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "hidden_volume_path: {}\nlog_path: {}\noverlays: []",
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
}

#[test]
fn init_stdout_subscriber_plain_mode_suppresses_log_file_open_warning_noise() {
    use std::io::Write;

    let temp_dir = tempfile::TempDir::new().unwrap();
    let hidden_root = temp_dir.path().join("hidden-volume");
    let log_dir = hidden_root.join("logs");
    let config_path = temp_dir.path().join("nails.yaml");

    std::fs::create_dir_all(log_dir.join("nails.log")).unwrap();

    let mut config_file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        config_file,
        "hidden_volume_path: {}\nlog_path: {}\noverlays: []",
        hidden_root.display(),
        log_dir.display(),
    )
    .unwrap();

    let output = run_subprocess("directory-log-target-plain", Some(&config_path));
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "stderr={stderr}");
    assert!(
        stderr.contains("plain directory fallback line"),
        "stderr={stderr}"
    );
    assert!(
        !stderr.contains("Failed to open log file"),
        "stderr={stderr}"
    );
    assert!(!stderr.contains('\u{001b}'), "stderr={stderr}");
}
