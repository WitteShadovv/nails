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

use serde::Serialize;

pub use nails_api::envelope::{Envelope, ErrorBody, NextStep, SCHEMA_VERSION, error_envelope};

use super::exit::ExitStatus;

/// Print a machine-readable [`Envelope`] on stdout.
pub trait EnvelopePrint {
    /// Serialize to one compact line and print it on stdout.
    ///
    /// Tolerant of a broken pipe: a reader that has already exited must not turn
    /// the final envelope into a fatal abort (see
    /// [`super::println_tolerating_broken_pipe`]).
    fn print(&self);
}

impl<T: Serialize> EnvelopePrint for Envelope<T> {
    fn print(&self) {
        super::println_tolerating_broken_pipe(&self.to_line());
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

/// Report an answer of `n` at a confirmation prompt, which changed nothing:
/// for a human the neutral notice `activate` gives, on `err` (stderr, whose
/// `style` it takes), in JSON the error envelope with the code `cancelled` on
/// stdout. The command exits 130, the cancelled code: a "no" at any prompt
/// reads the same as Ctrl+C.
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
