// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Activation progress reporting.
//!
//! Activation phases report what the operator watches — a numbered step, a
//! detail within the step (the overlay being mounted), and a heartbeat while a
//! long, uninterruptible step runs — through the [`Reporter`] trait. The log is
//! separate: phases still write their own tracing events, and the reporter only
//! decides how progress is *presented*. One implementation exists per surface:
//!
//! - [`TtyReporter`]: an interactive terminal. A spinner line shows the step and
//!   its elapsed time, redrawn continuously; the step detail (or, during a long
//!   build, the most recent build line) sits on a line under it. Finished steps
//!   are left behind as one line each with their duration. Log lines written
//!   while the spinner is up go through [`write_log`], which lifts the spinner,
//!   prints the line and redraws, so the two never garble each other.
//! - [`PlainReporter`]: a pipe, a file or `TERM=dumb`. One line per step, one per
//!   detail, and a `still <activity>, <elapsed>` line at every heartbeat. The
//!   most recent build line is never shown here: off a terminal it is raw tool
//!   output that only widens the activity fingerprint if the stream is captured.
//! - [`JsonReporter`]: typed progress events in the `activate --json` NDJSON
//!   stream.
//! - [`SilentReporter`]: a detached worker. Nothing reaches stdout or stderr;
//!   steps go to the hidden-root log at debug level only.
//! - [`TracingReporter`]: the library default, reporting as tracing events, so
//!   an embedding without a configured reporter keeps the previous behaviour.
//!
//! Writes never fail the activation: a reporter that cannot write (a closed
//! pipe, a full disk) stops writing and the activation carries on.
//!
//! Heartbeats and details originate deep inside the build and mount code, which
//! has no handle on the manager. While an activation runs, its reporter is
//! installed as the [active reporter](install) of the activating thread and the
//! free functions [`heartbeat`] and [`detail`] route to it; with no active
//! reporter they fall back to tracing events.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::output::{Mark, Style};

/// One activation step as reported to the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step<'a> {
    /// 1-based index of the step.
    pub index: u32,
    /// Number of steps this activation runs.
    pub total: u32,
    /// Stable machine identifier of the phase (e.g. `overlay_mount`).
    pub phase: &'a str,
    /// Human-readable label (e.g. `Mounting overlays`).
    pub label: &'a str,
}

/// A sink for activation progress.
pub trait Reporter: Send {
    /// A new step started; the previous one (if any) finished successfully.
    fn step(&mut self, step: Step<'_>);
    /// Finer-grained detail within the current step.
    fn detail(&mut self, detail: &str);
    /// A long step is still running after `elapsed`; `last_line` is the most
    /// recent line it printed, if any.
    fn heartbeat(&mut self, activity: &str, elapsed: Duration, last_line: Option<&str>);
    /// The activation ended: the current step succeeded or failed.
    fn finish(&mut self, success: bool);
}

/// A reporter shared between the activation and the code paths it calls.
pub type SharedReporter = Arc<Mutex<dyn Reporter>>;

/// Wrap `reporter` for sharing.
pub fn shared<R: Reporter + 'static>(reporter: R) -> SharedReporter {
    Arc::new(Mutex::new(reporter))
}

fn lock(reporter: &SharedReporter) -> std::sync::MutexGuard<'_, dyn Reporter + 'static> {
    reporter
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ---------------------------------------------------------------------------
// Active reporter routing
// ---------------------------------------------------------------------------

thread_local! {
    /// The reporter of the activation running on this thread. Thread-local
    /// because heartbeats and details are raised on the activating thread (the
    /// streaming runner calls back from its wait loop), and so concurrent
    /// activations in one process (as in the test suite) never cross-talk.
    static ACTIVE: std::cell::RefCell<Option<SharedReporter>> =
        const { std::cell::RefCell::new(None) };
}

fn active() -> Option<SharedReporter> {
    ACTIVE.with(|slot| slot.borrow().clone())
}

/// Restores the previously active reporter when dropped.
#[must_use = "the reporter is only active while the scope is alive"]
pub struct ActiveScope {
    previous: Option<SharedReporter>,
}

impl Drop for ActiveScope {
    fn drop(&mut self) {
        let previous = self.previous.take();
        ACTIVE.with(|slot| *slot.borrow_mut() = previous);
    }
}

/// Make `reporter` the target of [`heartbeat`] and [`detail`] on this thread
/// until the returned scope is dropped.
pub fn install(reporter: SharedReporter) -> ActiveScope {
    let previous = ACTIVE.with(|slot| slot.borrow_mut().replace(reporter));
    ActiveScope { previous }
}

/// Report a heartbeat for a long step to the active reporter, or as a tracing
/// event (with the build line only on a terminal) when none is active.
pub fn heartbeat(activity: &str, elapsed: Duration, last_line: Option<&str>) {
    match active() {
        Some(reporter) => lock(&reporter).heartbeat(activity, elapsed, last_line),
        None => tracing::info!(
            "{}",
            crate::process::run::heartbeat_line(activity, elapsed, last_line)
        ),
    }
}

/// Report detail within the current step to the active reporter, or as a
/// tracing progress event when none is active.
pub fn detail(phase: &str, text: &str) {
    match active() {
        Some(reporter) => lock(&reporter).detail(text),
        None => tracing::info!(event = "progress", phase = phase, "{}", text),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The widest a progress line may get on a terminal. Kept under 80 columns so a
/// redrawn line never wraps (a wrapped line could not be cleared in place).
const TTY_LINE_MAX: usize = 76;

fn truncate(text: &str, max: usize) -> String {
    let text = text.trim();
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let kept: String = text.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

fn elapsed_label(elapsed: Duration) -> String {
    crate::timing::format_elapsed(elapsed)
}

/// A writer that remembers a failed write and stops writing, so a closed pipe
/// costs one error, not one per event, and never fails the activation.
struct Sink {
    out: Box<dyn Write + Send>,
    closed: bool,
}

impl Sink {
    fn new(out: Box<dyn Write + Send>) -> Self {
        Self { out, closed: false }
    }

    fn write(&mut self, bytes: &[u8]) {
        if self.closed {
            return;
        }
        if self
            .out
            .write_all(bytes)
            .and_then(|()| self.out.flush())
            .is_err()
        {
            self.closed = true;
        }
    }

    fn line(&mut self, text: &str) {
        self.write(format!("{text}\n").as_bytes());
    }
}

// ---------------------------------------------------------------------------
// Tracing (library default)
// ---------------------------------------------------------------------------

/// Reports progress as tracing events, as activation did before reporters
/// existed. The default for a manager no caller configured.
#[derive(Debug, Default)]
pub struct TracingReporter;

impl Reporter for TracingReporter {
    fn step(&mut self, step: Step<'_>) {
        tracing::info!(
            event = "progress",
            phase = step.phase,
            current = step.index,
            total = step.total,
            "[{}/{}] {}...",
            step.index,
            step.total,
            step.label
        );
    }

    fn detail(&mut self, detail: &str) {
        tracing::info!(event = "progress", "{}", detail);
    }

    fn heartbeat(&mut self, activity: &str, elapsed: Duration, last_line: Option<&str>) {
        tracing::info!(
            "{}",
            crate::process::run::heartbeat_line(activity, elapsed, last_line)
        );
    }

    fn finish(&mut self, _success: bool) {}
}

// ---------------------------------------------------------------------------
// Plain (non-terminal)
// ---------------------------------------------------------------------------

/// One line per event, for a pipe, a file or a dumb terminal.
pub struct PlainReporter {
    sink: Sink,
}

impl PlainReporter {
    /// Report to `out` (normally stderr).
    pub fn new(out: Box<dyn Write + Send>) -> Self {
        Self {
            sink: Sink::new(out),
        }
    }
}

impl Reporter for PlainReporter {
    fn step(&mut self, step: Step<'_>) {
        self.sink.line(&format!(
            "[{}/{}] {}...",
            step.index, step.total, step.label
        ));
    }

    fn detail(&mut self, detail: &str) {
        self.sink.line(&format!("  {}", detail.trim()));
    }

    /// The neutral `still <activity>, <elapsed>` form only: the build line is
    /// raw tool output and stays off non-terminal streams.
    fn heartbeat(&mut self, activity: &str, elapsed: Duration, _last_line: Option<&str>) {
        self.sink.line(&format!(
            "  {}",
            crate::process::run::progress_line(activity, elapsed, None)
        ));
    }

    fn finish(&mut self, _success: bool) {}
}

// ---------------------------------------------------------------------------
// JSON (activate --json NDJSON stream)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct JsonProgressEvent<'a> {
    schema_version: u32,
    command: &'static str,
    #[serde(rename = "type")]
    event_type: &'static str,
    phase: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    step: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    total_steps: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    elapsed_seconds: Option<u64>,
}

/// Typed `progress` events in an NDJSON stream: one per step, detail and
/// heartbeat. Heartbeats carry the elapsed time, never the build line.
pub struct JsonReporter {
    sink: Sink,
    schema_version: u32,
    command: &'static str,
    phase: String,
}

impl JsonReporter {
    /// Report to `out` (normally stdout) as events of `command`'s stream at
    /// `schema_version`.
    pub fn new(out: Box<dyn Write + Send>, schema_version: u32, command: &'static str) -> Self {
        Self {
            sink: Sink::new(out),
            schema_version,
            command,
            phase: String::new(),
        }
    }

    fn emit(&mut self, event: &JsonProgressEvent<'_>) {
        if let Ok(line) = serde_json::to_string(event) {
            self.sink.line(&line);
        }
    }

    fn event<'a>(&self, phase: &'a str) -> JsonProgressEvent<'a> {
        JsonProgressEvent {
            schema_version: self.schema_version,
            command: self.command,
            event_type: "progress",
            phase,
            step: None,
            total_steps: None,
            label: None,
            detail: None,
            elapsed_seconds: None,
        }
    }
}

impl Reporter for JsonReporter {
    fn step(&mut self, step: Step<'_>) {
        self.phase = step.phase.to_string();
        let event = JsonProgressEvent {
            step: Some(step.index),
            total_steps: Some(step.total),
            label: Some(step.label),
            ..self.event(step.phase)
        };
        self.emit(&event);
    }

    fn detail(&mut self, detail: &str) {
        let phase = self.phase.clone();
        let event = JsonProgressEvent {
            detail: Some(detail.trim()),
            ..self.event(&phase)
        };
        self.emit(&event);
    }

    fn heartbeat(&mut self, _activity: &str, elapsed: Duration, _last_line: Option<&str>) {
        let phase = self.phase.clone();
        let event = JsonProgressEvent {
            elapsed_seconds: Some(elapsed.as_secs()),
            ..self.event(&phase)
        };
        self.emit(&event);
    }

    fn finish(&mut self, _success: bool) {}
}

// ---------------------------------------------------------------------------
// Silent (detached worker)
// ---------------------------------------------------------------------------

/// Writes nothing to stdout or stderr. Steps are logged at debug level, which
/// reaches only the hidden-root log file at the default verbosity.
#[derive(Debug, Default)]
pub struct SilentReporter;

impl Reporter for SilentReporter {
    fn step(&mut self, step: Step<'_>) {
        tracing::debug!(
            event = "progress",
            phase = step.phase,
            current = step.index,
            total = step.total,
            "[{}/{}] {}",
            step.index,
            step.total,
            step.label
        );
    }

    fn detail(&mut self, detail: &str) {
        tracing::debug!(event = "progress", "{}", detail);
    }

    fn heartbeat(&mut self, activity: &str, elapsed: Duration, _last_line: Option<&str>) {
        tracing::debug!(
            "{}",
            crate::process::run::progress_line(activity, elapsed, None)
        );
    }

    fn finish(&mut self, _success: bool) {}
}

// ---------------------------------------------------------------------------
// Tee (UI reporter plus the hidden-volume progress record)
// ---------------------------------------------------------------------------

/// Forwards every event to the operator-facing reporter (unless it is muted)
/// and to an optional secondary reporter such as the hidden-volume progress
/// record.
pub struct Tee {
    primary: SharedReporter,
    primary_enabled: bool,
    secondary: Option<Box<dyn Reporter>>,
}

impl Tee {
    /// Forward to `primary`; `primary_enabled = false` mutes it (quiet mode)
    /// while the secondary still receives every event.
    pub fn new(primary: SharedReporter, primary_enabled: bool) -> Self {
        Self {
            primary,
            primary_enabled,
            secondary: None,
        }
    }

    /// Attach the secondary reporter.
    pub fn attach(&mut self, secondary: Box<dyn Reporter>) {
        self.secondary = Some(secondary);
    }

    fn each(&mut self, mut f: impl FnMut(&mut dyn Reporter)) {
        if self.primary_enabled {
            f(&mut *lock(&self.primary));
        }
        if let Some(secondary) = self.secondary.as_mut() {
            f(secondary.as_mut());
        }
    }
}

impl Reporter for Tee {
    fn step(&mut self, step: Step<'_>) {
        self.each(|r| r.step(step));
    }

    fn detail(&mut self, detail: &str) {
        self.each(|r| r.detail(detail));
    }

    fn heartbeat(&mut self, activity: &str, elapsed: Duration, last_line: Option<&str>) {
        self.each(|r| r.heartbeat(activity, elapsed, last_line));
    }

    fn finish(&mut self, success: bool) {
        self.each(|r| r.finish(success));
    }
}

// ---------------------------------------------------------------------------
// TTY (spinner)
// ---------------------------------------------------------------------------

const SPINNER_UNICODE: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SPINNER_ASCII: &[&str] = &["|", "/", "-", "\\"];
/// How often the spinner frame and elapsed time are redrawn.
pub const TTY_TICK: Duration = Duration::from_millis(120);

type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

struct CurrentStep {
    index: u32,
    total: u32,
    label: String,
    started: Instant,
}

struct TtyState {
    sink: Sink,
    style: Style,
    clock: Clock,
    step: Option<CurrentStep>,
    detail: Option<String>,
    frame: usize,
    lines_drawn: usize,
    finished: bool,
}

impl TtyState {
    fn clear(&mut self) {
        match self.lines_drawn {
            0 => {}
            1 => self.sink.write(b"\r\x1b[2K"),
            _ => self.sink.write(b"\r\x1b[2K\x1b[1A\r\x1b[2K"),
        }
        self.lines_drawn = 0;
    }

    fn draw(&mut self) {
        if self.finished {
            return;
        }
        let Some(step) = self.step.as_ref() else {
            return;
        };
        let frames = if self.style.ascii {
            SPINNER_ASCII
        } else {
            SPINNER_UNICODE
        };
        let spinner = frames[self.frame % frames.len()];
        let elapsed = elapsed_label((self.clock)().saturating_duration_since(step.started));
        let headline = truncate(
            &format!("[{}/{}] {} · {elapsed}", step.index, step.total, step.label),
            TTY_LINE_MAX - 2,
        );
        let mut text = format!(
            "\r\x1b[2K{} {headline}",
            self.style.paint(spinner, crate::output::Tone::Cyan)
        );
        let mut lines = 1;
        if let Some(detail) = self.detail.as_deref() {
            text.push_str(&format!(
                "\n\x1b[2K  {}",
                self.style
                    .paint(truncate(detail, TTY_LINE_MAX - 2), crate::output::Tone::Dim)
            ));
            lines = 2;
        }
        self.clear();
        self.sink.write(text.as_bytes());
        self.lines_drawn = lines;
    }

    /// Leave the current step behind as one finished line with its duration.
    fn complete(&mut self, success: bool) {
        self.clear();
        if let Some(step) = self.step.take() {
            let elapsed = elapsed_label((self.clock)().saturating_duration_since(step.started));
            let mark = if success { Mark::Pass } else { Mark::Fail };
            let line = format!(
                "{} [{}/{}] {} ({elapsed})",
                self.style.mark(mark),
                step.index,
                step.total,
                step.label
            );
            self.sink.line(&line);
        }
        self.detail = None;
    }
}

struct TtyShared {
    state: Mutex<TtyState>,
    stop: AtomicBool,
}

impl TtyShared {
    fn state(&self) -> std::sync::MutexGuard<'_, TtyState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// The TTY reporter whose spinner is currently on screen, for [`write_log`].
static TTY_ACTIVE: Mutex<Option<Weak<TtyShared>>> = Mutex::new(None);

fn tty_active() -> Option<Arc<TtyShared>> {
    TTY_ACTIVE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
        .and_then(Weak::upgrade)
}

/// Write a log line to stderr without garbling a spinner that may be on
/// screen: the spinner is lifted, the line written, and the spinner redrawn.
/// With no spinner active this is a plain stderr write.
pub fn write_log(bytes: &[u8]) -> std::io::Result<()> {
    match tty_active() {
        Some(shared) => {
            let mut state = shared.state();
            state.clear();
            state.sink.write(bytes);
            state.draw();
            Ok(())
        }
        None => std::io::stderr().write_all(bytes),
    }
}

/// A [`Write`] handle over [`write_log`], for a logging layer that shares the
/// terminal with the spinner.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProgressAwareStderr;

impl Write for ProgressAwareStderr {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        write_log(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if tty_active().is_none() {
            std::io::stderr().flush()?;
        }
        Ok(())
    }
}

/// A spinner with the step and its elapsed time, for an interactive terminal.
pub struct TtyReporter {
    shared: Arc<TtyShared>,
    ticker: Option<JoinHandle<()>>,
}

impl TtyReporter {
    /// Report to `out` (the terminal on stderr) in `style`, redrawing every
    /// [`TTY_TICK`].
    pub fn new(out: Box<dyn Write + Send>, style: Style) -> Self {
        Self::build(out, style, Arc::new(Instant::now), Some(TTY_TICK))
    }

    /// A reporter with an injected clock and, when `tick` is `None`, no
    /// background redraw thread, so tests render deterministically.
    pub fn with_clock(
        out: Box<dyn Write + Send>,
        style: Style,
        clock: Arc<dyn Fn() -> Instant + Send + Sync>,
        tick: Option<Duration>,
    ) -> Self {
        Self::build(out, style, clock, tick)
    }

    fn build(
        out: Box<dyn Write + Send>,
        style: Style,
        clock: Clock,
        tick: Option<Duration>,
    ) -> Self {
        let shared = Arc::new(TtyShared {
            state: Mutex::new(TtyState {
                sink: Sink::new(out),
                style,
                clock,
                step: None,
                detail: None,
                frame: 0,
                lines_drawn: 0,
                finished: false,
            }),
            stop: AtomicBool::new(false),
        });
        *TTY_ACTIVE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::downgrade(&shared));
        let ticker = tick.map(|interval| {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || {
                while !shared.stop.load(Ordering::Relaxed) {
                    std::thread::sleep(interval);
                    let mut state = shared.state();
                    if !state.finished && state.step.is_some() {
                        state.frame = state.frame.wrapping_add(1);
                        state.draw();
                    }
                }
            })
        });
        Self { shared, ticker }
    }

    /// Advance the spinner one frame and redraw, as the ticker does.
    pub fn tick(&self) {
        let mut state = self.shared.state();
        state.frame = state.frame.wrapping_add(1);
        state.draw();
    }

    fn stop_ticker(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.ticker.take() {
            let _ = handle.join();
        }
    }
}

impl Reporter for TtyReporter {
    fn step(&mut self, step: Step<'_>) {
        let mut state = self.shared.state();
        state.complete(true);
        state.step = Some(CurrentStep {
            index: step.index,
            total: step.total,
            label: step.label.to_string(),
            started: (state.clock)(),
        });
        state.draw();
    }

    fn detail(&mut self, detail: &str) {
        let mut state = self.shared.state();
        state.detail = Some(detail.trim().to_string());
        state.draw();
    }

    /// The spinner already shows the elapsed time; a heartbeat puts the most
    /// recent build line under it.
    fn heartbeat(&mut self, _activity: &str, _elapsed: Duration, last_line: Option<&str>) {
        if let Some(line) = last_line.filter(|line| !line.trim().is_empty()) {
            let mut state = self.shared.state();
            state.detail = Some(line.trim().to_string());
            state.draw();
        }
    }

    fn finish(&mut self, success: bool) {
        {
            let mut state = self.shared.state();
            state.complete(success);
            state.finished = true;
        }
        self.stop_ticker();
    }
}

impl Drop for TtyReporter {
    fn drop(&mut self) {
        self.stop_ticker();
        self.shared.state().clear();
        let mut active = TTY_ACTIVE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if active
            .as_ref()
            .is_some_and(|weak| std::ptr::eq(weak.as_ptr(), Arc::as_ptr(&self.shared)))
        {
            *active = None;
        }
    }
}

#[cfg(test)]
mod tests;
