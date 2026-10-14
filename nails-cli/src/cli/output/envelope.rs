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
mod tests {
    use super::*;

    #[test]
    fn success_envelope_has_schema_version_command_and_ok() {
        let env = Envelope::success("status", serde_json::json!({"state": "ok"}));
        let value: serde_json::Value = serde_json::from_str(&env.to_line()).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["command"], "status");
        assert_eq!(value["ok"], true);
        assert_eq!(value["data"]["state"], "ok");
        assert!(value.get("error").is_none());
    }

    #[test]
    fn error_envelope_carries_code_message_hint() {
        let env = error_envelope(
            "activate",
            ErrorBody::new("preflight", "checks failed").with_hint("mount the volume"),
        );
        let value: serde_json::Value = serde_json::from_str(&env.to_line()).unwrap();
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "preflight");
        assert_eq!(value["error"]["message"], "checks failed");
        assert_eq!(value["error"]["hint"], "mount the volume");
        assert!(value.get("data").is_none());
    }

    #[test]
    fn human_error_survives_a_closed_stderr_pipe() {
        // A real pipe whose reader is gone: the write fails with EPIPE, which must
        // be swallowed rather than panic as eprintln! would.
        let (reader, mut writer) = std::io::pipe().unwrap();
        drop(reader);
        write_human_error(
            &mut writer,
            &ErrorBody::new("teardown_incomplete", "busy").with_hint("reboot"),
        );

        let (mut reader, mut writer) = std::io::pipe().unwrap();
        write_human_error(&mut writer, &ErrorBody::new("x", "boom").with_hint("retry"));
        drop(writer);
        let mut text = String::new();
        std::io::Read::read_to_string(&mut reader, &mut text).unwrap();
        assert_eq!(text, "error: boom\n  retry\n");
    }

    #[test]
    fn every_hint_line_is_indented() {
        let mut out = Vec::new();
        write_human_error(
            &mut out,
            &ErrorBody::new("x", "boom").with_hint("first\nsecond"),
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "error: boom\n  first\n  second\n"
        );
    }

    #[test]
    fn a_newline_in_a_message_stays_one_parseable_line() {
        let env = error_envelope("deactivate", ErrorBody::new("mount_busy", "busy\nretry"));
        let line = env.to_line();
        assert_eq!(line.lines().count(), 1, "one physical line: {line}");
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["error"]["message"], "busy\nretry");
    }
}
