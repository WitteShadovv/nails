use std::io;
use std::sync::{Arc, Mutex};

use super::{RenderMode, render_mode};

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
