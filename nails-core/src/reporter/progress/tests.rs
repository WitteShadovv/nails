// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use serial_test::serial;

/// A cloneable in-memory writer, so a test keeps a handle on what a reporter
/// wrote after handing it a boxed copy.
#[derive(Clone, Default)]
struct Buffer(Arc<Mutex<Vec<u8>>>);

impl Buffer {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }

    fn boxed(&self) -> Box<dyn Write + Send> {
        Box::new(self.clone())
    }
}

impl Write for Buffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A writer whose every write fails as a closed pipe would.
struct BrokenPipe(Arc<Mutex<usize>>);

impl Write for BrokenPipe {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        *self.0.lock().unwrap() += 1;
        Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }
}

fn step<'a>(index: u32, phase: &'a str, label: &'a str) -> Step<'a> {
    Step {
        index,
        total: 5,
        phase,
        label,
    }
}

const PLAIN: Style = Style {
    color: false,
    ascii: false,
};

#[test]
fn plain_reporter_prints_one_line_per_event_and_no_build_line() {
    let out = Buffer::default();
    let mut reporter = PlainReporter::new(out.boxed());

    reporter.step(step(1, "preflight", "Running preflight checks"));
    reporter.step(step(4, "overlay_mount", "Mounting overlays"));
    reporter.detail("mounting /home (1/2)");
    reporter.heartbeat(
        "building",
        Duration::from_secs(130),
        Some("building /nix/store/secret-hidden.drv"),
    );
    reporter.finish(true);

    assert_eq!(
        out.text(),
        "[1/5] Running preflight checks...\n\
         [4/5] Mounting overlays...\n\
         \x20 mounting /home (1/2)\n\
         \x20 still building, 2m10s\n"
    );
}

#[test]
fn json_reporter_emits_typed_progress_events() {
    let out = Buffer::default();
    let mut reporter = JsonReporter::new(out.boxed(), 1, "activate");

    reporter.step(step(4, "overlay_mount", "Mounting overlays"));
    reporter.detail("mounting /home (1/2)");
    reporter.heartbeat(
        "building",
        Duration::from_secs(61),
        Some("raw build output"),
    );

    let events: Vec<serde_json::Value> = out
        .text()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        events,
        vec![
            serde_json::json!({
                "schema_version": 1, "command": "activate", "type": "progress",
                "phase": "overlay_mount", "step": 4, "total_steps": 5,
                "label": "Mounting overlays"
            }),
            serde_json::json!({
                "schema_version": 1, "command": "activate", "type": "progress",
                "phase": "overlay_mount", "detail": "mounting /home (1/2)"
            }),
            serde_json::json!({
                "schema_version": 1, "command": "activate", "type": "progress",
                "phase": "overlay_mount", "elapsed_seconds": 61
            }),
        ]
    );
}

#[test]
fn a_closed_pipe_stops_the_reporter_after_one_failed_write() {
    let attempts = Arc::new(Mutex::new(0));
    let mut reporter = PlainReporter::new(Box::new(BrokenPipe(attempts.clone())));

    reporter.step(step(1, "preflight", "Running preflight checks"));
    reporter.step(step(
        2,
        "session_management",
        "Preparing session management",
    ));
    reporter.heartbeat("building", Duration::from_secs(30), None);
    reporter.finish(false);

    assert_eq!(
        *attempts.lock().unwrap(),
        1,
        "no write after the first EPIPE"
    );
}

/// A manually advanced clock for the TTY reporter.
fn manual_clock() -> (Arc<Mutex<Instant>>, Clock) {
    let now = Arc::new(Mutex::new(Instant::now()));
    let handle = now.clone();
    (now, Arc::new(move || *handle.lock().unwrap()))
}

fn advance(clock: &Arc<Mutex<Instant>>, secs: u64) {
    *clock.lock().unwrap() += Duration::from_secs(secs);
}

/// The text a terminal would show for `raw`: carriage returns and the
/// clear-line / cursor-up sequences applied, so assertions see the screen.
fn screen(raw: &str) -> Vec<String> {
    let mut lines: Vec<String> = vec![String::new()];
    let mut rest = raw;
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix("\x1b[2K") {
            lines.last_mut().unwrap().clear();
            rest = after;
        } else if let Some(after) = rest.strip_prefix("\x1b[1A") {
            lines.pop();
            if lines.is_empty() {
                lines.push(String::new());
            }
            rest = after;
        } else if let Some(after) = rest.strip_prefix('\r') {
            rest = after;
        } else if let Some(after) = rest.strip_prefix('\n') {
            lines.push(String::new());
            rest = after;
        } else {
            let ch = rest.chars().next().unwrap();
            lines.last_mut().unwrap().push(ch);
            rest = &rest[ch.len_utf8()..];
        }
    }
    if lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    lines
}

#[test]
#[serial]
fn tty_reporter_shows_step_and_elapsed_and_leaves_finished_steps_behind() {
    let out = Buffer::default();
    let (clock, now) = manual_clock();
    let mut reporter = TtyReporter::with_clock(out.boxed(), PLAIN, now, None);

    reporter.step(step(3, "config_prepare", "Preparing hidden configuration"));
    advance(&clock, 2);
    reporter.step(step(4, "overlay_mount", "Mounting overlays"));
    advance(&clock, 7);
    reporter.detail("mounting /home (2/3)");

    assert_eq!(
        screen(&out.text()),
        vec![
            "✓ [3/5] Preparing hidden configuration (2s)".to_string(),
            "⠋ [4/5] Mounting overlays · 7s".to_string(),
            "  mounting /home (2/3)".to_string(),
        ]
    );

    // The ticker advances the frame and the elapsed time in place.
    advance(&clock, 60);
    reporter.tick();
    assert_eq!(screen(&out.text())[1], "⠙ [4/5] Mounting overlays · 1m07s",);

    reporter.finish(false);
    assert_eq!(
        screen(&out.text()),
        vec![
            "✓ [3/5] Preparing hidden configuration (2s)".to_string(),
            "✗ [4/5] Mounting overlays (1m07s)".to_string(),
        ]
    );
}

#[test]
#[serial]
fn tty_reporter_shows_the_last_build_line_under_the_spinner() {
    let out = Buffer::default();
    let (_clock, now) = manual_clock();
    let mut reporter = TtyReporter::with_clock(out.boxed(), PLAIN, now, None);

    reporter.step(step(5, "profile_switch", "Applying hidden configuration"));
    reporter.heartbeat(
        "building",
        Duration::from_secs(30),
        Some("building '/nix/store/abc-foo.drv'"),
    );

    let shown = screen(&out.text());
    assert_eq!(shown.len(), 2, "{shown:?}");
    assert_eq!(shown[1], "  building '/nix/store/abc-foo.drv'");
}

#[test]
#[serial]
fn log_lines_are_written_above_the_spinner() {
    let out = Buffer::default();
    let (_clock, now) = manual_clock();
    let mut reporter = TtyReporter::with_clock(out.boxed(), PLAIN, now, None);
    reporter.step(step(
        2,
        "session_management",
        "Preparing session management",
    ));

    write_log(b"WARN persona mode is shared-home\n").unwrap();

    assert_eq!(
        screen(&out.text()),
        vec![
            "WARN persona mode is shared-home".to_string(),
            "⠋ [2/5] Preparing session management · 0s".to_string(),
        ]
    );
    reporter.finish(true);
    drop(reporter);
    assert!(
        tty_active().is_none(),
        "dropping the reporter unregisters it"
    );
}

#[test]
#[serial]
fn tty_lines_are_truncated_so_they_never_wrap() {
    let out = Buffer::default();
    let (_clock, now) = manual_clock();
    let mut reporter = TtyReporter::with_clock(out.boxed(), PLAIN, now, None);
    reporter.step(step(5, "profile_switch", "Applying hidden configuration"));
    reporter.detail(&"x".repeat(300));

    for line in screen(&out.text()) {
        assert!(line.chars().count() <= TTY_LINE_MAX, "{line}");
    }
}

/// Records every event it receives, for routing tests.
#[derive(Default)]
struct Recorder(Arc<Mutex<Vec<String>>>);

impl Reporter for Recorder {
    fn step(&mut self, step: Step<'_>) {
        self.0.lock().unwrap().push(format!("step {}", step.phase));
    }
    fn detail(&mut self, detail: &str) {
        self.0.lock().unwrap().push(format!("detail {detail}"));
    }
    fn heartbeat(&mut self, activity: &str, elapsed: Duration, last_line: Option<&str>) {
        self.0.lock().unwrap().push(format!(
            "heartbeat {activity} {} {}",
            elapsed.as_secs(),
            last_line.unwrap_or("-")
        ));
    }
    fn finish(&mut self, success: bool) {
        self.0.lock().unwrap().push(format!("finish {success}"));
    }
}

#[test]
#[serial]
fn free_functions_route_to_the_active_reporter_only_while_installed() {
    let events = Arc::new(Mutex::new(Vec::new()));
    {
        let _scope = install(shared(Recorder(events.clone())));
        heartbeat("building", Duration::from_secs(30), Some("line"));
        detail("overlay_mount", "mounting /home (1/1)");
    }
    // After the scope ends nothing reaches the recorder.
    heartbeat("building", Duration::from_secs(60), None);

    assert_eq!(
        *events.lock().unwrap(),
        vec![
            "heartbeat building 30 line".to_string(),
            "detail mounting /home (1/1)".to_string(),
        ]
    );
}

#[test]
fn tee_mutes_the_primary_but_always_feeds_the_secondary() {
    let primary = Arc::new(Mutex::new(Vec::new()));
    let secondary = Arc::new(Mutex::new(Vec::new()));
    let mut tee = Tee::new(shared(Recorder(primary.clone())), false);
    tee.attach(Box::new(Recorder(secondary.clone())));

    tee.step(step(1, "preflight", "Running preflight checks"));
    tee.finish(true);

    assert!(primary.lock().unwrap().is_empty(), "quiet mutes the UI");
    assert_eq!(
        *secondary.lock().unwrap(),
        vec!["step preflight".to_string(), "finish true".to_string()]
    );
}
