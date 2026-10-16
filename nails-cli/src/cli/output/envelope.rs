// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The stable JSON envelope every command writes under `--json`.
//!
//! One shape carries every machine-readable result: a success carries typed
//! `data`, a failure carries a typed `error`, and both carry the schema version
//! and the command name so a reader can tell what produced the document and
//! which contract it follows. `serde_json` does the escaping, so the envelope is
//! always a single valid document even when a message contains a newline.

use serde::Serialize;

use super::exit::ExitStatus;

/// The version of the machine-readable contract. Bump when a field's meaning
/// changes incompatibly.
pub const SCHEMA_VERSION: u32 = 1;

/// A machine-readable command result.
#[derive(Debug, Serialize)]
pub struct Envelope<T: Serialize> {
    /// The contract version this document follows.
    pub schema_version: u32,
    /// The command that produced the document (`status`, `verify`, …).
    pub command: &'static str,
    /// Whether the command succeeded.
    pub ok: bool,
    /// The typed success payload, absent on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// The typed failure payload, absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

/// The structured description of a failure.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    /// A stable, snake_case code a caller can branch on.
    pub code: &'static str,
    /// A human-readable explanation.
    pub message: String,
    /// An optional next step or remedy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

impl ErrorBody {
    /// A failure with a code and message and no hint.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            hint: None,
        }
    }

    /// Attach a next step or remedy.
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

impl<T: Serialize> Envelope<T> {
    /// A success envelope carrying typed `data`.
    pub fn success(command: &'static str, data: T) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            command,
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    /// A failure envelope that still carries typed `data`: what the command did
    /// after the failure (an emergency's power action and backend close run on
    /// every outcome, and a caller must learn whether they happened).
    pub fn failure_with_data(command: &'static str, error: ErrorBody, data: T) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            command,
            ok: false,
            data: Some(data),
            error: Some(error),
        }
    }

    /// Serialize to one compact line and print it on stdout.
    ///
    /// Tolerant of a broken pipe: a reader that has already exited must not turn
    /// the final envelope into a fatal abort (see
    /// [`super::println_tolerating_broken_pipe`]).
    pub fn print(&self) {
        super::println_tolerating_broken_pipe(&self.to_line());
    }

    /// The compact single-line JSON for this envelope.
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).expect("envelope serialization cannot fail")
    }
}

/// A failure envelope with no typed data payload.
pub fn error_envelope(command: &'static str, error: ErrorBody) -> Envelope<()> {
    Envelope {
        schema_version: SCHEMA_VERSION,
        command,
        ok: false,
        data: None,
        error: Some(error),
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
/// stdout. The command exits 1.
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
    ExitStatus::Failed
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
/// stderr is gone (an emergency severs its own journal stream). Every line of
/// the hint is indented under the message.
pub(crate) fn write_human_error<W: std::io::Write>(writer: &mut W, error: &ErrorBody) {
    let _ = super::write_line_tolerating_broken_pipe(writer, &format!("error: {}", error.message));
    for line in error.hint.iter().flat_map(|hint| hint.lines()) {
        let _ = super::write_line_tolerating_broken_pipe(writer, &format!("  {line}"));
    }
}

#[cfg(test)]
#[path = "envelope_tests.rs"]
mod tests;
