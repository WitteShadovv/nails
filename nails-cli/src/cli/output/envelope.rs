// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The JSON envelope the CLI writes under `--json`, with the helpers that print
//! it on a terminal.
//!
//! The wire types — [`Envelope`], [`ErrorBody`], [`NextStep`], [`error_envelope`]
//! and [`SCHEMA_VERSION`] — live in [`nails_api::envelope`] and serialize
//! themselves; this module re-exports them and adds the terminal-facing
//! helpers: [`report_error`], [`report_cancelled`], and [`EnvelopePrint::print`]
//! for printing an envelope on stdout tolerating a broken pipe.
//!
//! A process prints exactly one envelope. Every envelope goes out through
//! [`print_envelope_line`], which holds the one slot while it prints, so the
//! paths that can race the command's own result — the cancel a signal reports
//! ([`crate::cli::interrupt`]) and the failure a panic reports
//! ([`crate::cli::chokepoint`]) — never add a second document to it. A
//! signal's cancel keeps the slot until the process has ended
//! ([`end_with_signal_cancel`]), so a command that finishes at that moment
//! waits on it instead of ending the process with no envelope or with its own
//! exit code.

use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

use serde::Serialize;

pub use nails_api::envelope::{Envelope, ErrorBody, NextStep, SCHEMA_VERSION, error_envelope};

use super::exit::ExitStatus;

/// Whether this process has printed its one envelope, behind the lock every
/// envelope is printed under.
static ENVELOPE_PRINTED: Mutex<bool> = Mutex::new(false);

/// The cancel envelope a signal stands for, set for a command that reports a
/// SIGINT or SIGTERM as its cancel ([`crate::cli::interrupt`]).
static SIGNAL_CANCEL: OnceLock<String> = OnceLock::new();

/// The one envelope slot. A panic while it was held leaves the flag as it
/// was, so a poisoned lock is taken as it is.
fn envelope_slot() -> MutexGuard<'static, bool> {
    ENVELOPE_PRINTED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Print `line`, one serialized envelope, on stdout, unless this process has
/// already printed its envelope. Returns whether it printed.
///
/// Once a signal the command reports as its cancel has arrived
/// ([`report_signals_as`]), that cancel is printed instead and the process
/// ends with exit 130: the signal came before the result, which may be a
/// failure the signal itself caused (a child killed by the same Ctrl+C).
pub(crate) fn print_envelope_line(line: &str) -> bool {
    if let Some(captured) = capture_line(line) {
        return captured;
    }
    let mut printed = envelope_slot();
    if *printed {
        return false;
    }
    *printed = true;
    if nails_core::cancel::watched_signal_arrived()
        && let Some(cancel) = SIGNAL_CANCEL.get()
    {
        end_with_cancel(cancel);
    }
    super::println_tolerating_broken_pipe(line);
    true
}

#[cfg(feature = "gui")]
thread_local! {
    /// The envelope of the command running on this thread under [`capture`]:
    /// `None` outside a capture, `Some(None)` before it printed one.
    static CAPTURED: std::cell::RefCell<Option<Option<String>>> =
        const { std::cell::RefCell::new(None) };
}

/// Take `line` into the capture running on this thread, if there is one:
/// `Some(true)` when it is the capture's first envelope, `Some(false)` for a
/// second, which is dropped, and `None` outside a capture.
#[cfg(feature = "gui")]
fn capture_line(line: &str) -> Option<bool> {
    CAPTURED.with(|slot| {
        let mut slot = slot.borrow_mut();
        let captured = slot.as_mut()?;
        if captured.is_some() {
            return Some(false);
        }
        *captured = Some(line.to_string());
        Some(true)
    })
}

/// Without the window's helper nothing captures an envelope.
#[cfg(not(feature = "gui"))]
fn capture_line(_line: &str) -> Option<bool> {
    None
}

/// Run `command`, one command handler under `--json`, and take the envelope
/// it prints instead of printing it: the window's helper answers with the
/// envelope the CLI's own code builds for the same command. The capture holds
/// one envelope, as a process does, and leaves the process's own slot alone,
/// so the helper can run one command after another. Only what is printed on
/// this thread is captured.
#[cfg(feature = "gui")]
pub(crate) fn capture<R>(command: impl FnOnce() -> R) -> (R, Option<String>) {
    struct Restore(Option<Option<String>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            let outer = self.0.take();
            CAPTURED.with(|slot| *slot.borrow_mut() = outer);
        }
    }
    let outer = CAPTURED.with(|slot| slot.borrow_mut().replace(None));
    let restore = Restore(outer);
    let result = command();
    let line = CAPTURED.with(|slot| slot.borrow_mut().take()).flatten();
    drop(restore);
    (result, line)
}

/// Report a SIGINT or SIGTERM as `cancel`, the serialized cancel envelope of
/// the running command (see [`print_envelope_line`] and
/// [`end_with_signal_cancel`]). The first call wins.
pub(crate) fn report_signals_as(cancel: String) {
    let _ = SIGNAL_CANCEL.set(cancel);
}

/// What a signal reported as a cancel does once its watcher wakes: print the
/// cancel envelope and end the process with exit 130, unless the command's own
/// envelope is already out; then nothing, and the command ends as it would
/// have.
pub(crate) fn end_with_signal_cancel() {
    let Some(cancel) = SIGNAL_CANCEL.get() else {
        return;
    };
    let mut printed = envelope_slot();
    if !*printed {
        *printed = true;
        end_with_cancel(cancel);
    }
}

/// Print `cancel` and end the process with exit 130. Called with the slot
/// held, which is never released: nothing else prints or ends the process
/// first.
fn end_with_cancel(cancel: &str) -> ! {
    super::println_tolerating_broken_pipe(cancel);
    super::flush_stdio();
    crate::cli::chokepoint::exit_process(ExitStatus::Cancelled.code())
}

/// Print a machine-readable [`Envelope`] on stdout.
pub trait EnvelopePrint {
    /// Serialize to one compact line and print it on stdout, as the one
    /// envelope of this process ([`print_envelope_line`]).
    ///
    /// Tolerant of a broken pipe: a reader that has already exited must not turn
    /// the final envelope into a fatal abort (see
    /// [`super::println_tolerating_broken_pipe`]).
    fn print(&self);
}

impl<T: Serialize> EnvelopePrint for Envelope<T> {
    fn print(&self) {
        print_envelope_line(&self.to_line());
    }
}

/// Report a failure: one envelope on stdout under `--json`, otherwise
/// `error: <message>` (and any hint) on stderr. Returns `status` so a handler
/// can `return report_error(...)`.
pub fn report_error(
    json: bool,
    command: &'static str,
    status: ExitStatus,
    error: ErrorBody,
) -> ExitStatus {
    if json {
        error_envelope(command, error).print();
    } else {
        write_human_error(&mut std::io::stderr().lock(), &error);
    }
    status
}

/// Report a cancel before the command changed anything (an answer other than
/// yes at a confirmation prompt, or Ctrl+C at one or during an emergency's
/// countdown): for a human the neutral notice `activate` gives, on `err`
/// (stderr, whose `style` it takes), in JSON the error envelope with the code
/// `cancelled` on stdout. The command exits 130, the cancelled code: a "no" at
/// any prompt reads the same as Ctrl+C.
pub fn report_cancelled<W: std::io::Write>(
    err: &mut W,
    json: bool,
    style: nails_core::output::Style,
    command: &'static str,
    message: &str,
) -> ExitStatus {
    if json {
        error_envelope(command, ErrorBody::new("cancelled", message)).print();
    } else {
        write_cancelled(err, style, message);
    }
    ExitStatus::Cancelled
}

/// Write the notice of a cancel to `writer`, tolerating a broken pipe.
pub(crate) fn write_cancelled<W: std::io::Write>(
    writer: &mut W,
    style: nails_core::output::Style,
    message: &str,
) {
    let notice = style.marked(nails_core::output::Mark::Neutral, message);
    let _ = super::write_line_tolerating_broken_pipe(writer, &notice);
}

/// Write the human form of `error` to `writer`, tolerating a broken pipe: the
/// failure being reported must never turn into a panic because the reader of
/// stderr is gone (an emergency severs its own journal stream). The first line
/// of the message follows `error: `; every continuation line is indented under
/// it, so a message that folded guidance in reads as "what happened" then the
/// indented advice.
pub(crate) fn write_human_error<W: std::io::Write>(writer: &mut W, error: &ErrorBody) {
    let mut lines = error.message.lines();
    let first = lines.next().unwrap_or_default();
    let _ = super::write_line_tolerating_broken_pipe(writer, &format!("error: {first}"));
    for line in lines {
        let _ = super::write_line_tolerating_broken_pipe(writer, &format!("  {line}"));
    }
}

#[cfg(test)]
#[path = "envelope_tests.rs"]
mod tests;
