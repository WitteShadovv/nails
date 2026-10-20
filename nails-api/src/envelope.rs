// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The stable JSON envelope every command writes under `--json`.
//!
//! One shape carries every machine-readable result: a success carries typed
//! `data`, a failure carries a typed `error`, and both carry the schema version
//! and the command name so a reader can tell what produced the document and
//! which contract it follows. `serde_json` does the escaping, so the envelope is
//! always a single valid document even when a message contains a newline.
//!
//! Version 2 of the contract. `ok` is true only for a success (exit 0) or a
//! success with a warning (exit 9); every other outcome sets it false, so a
//! script can branch on one field. An [`ErrorBody`] carries a stable `code`, the
//! human `message`, and an optional typed [`NextStep`] the reader renders as a
//! `Next:` line or a button; free-form guidance lives in the message, not in a
//! field of its own.

use serde::Serialize;

/// The version of the machine-readable contract. Bump when a field's meaning
/// changes incompatibly.
pub const SCHEMA_VERSION: u32 = 2;

/// The command the operator runs next, as the machine-readable contract carries
/// it.
///
/// Only the subcommand words are on the wire (`deactivate`, `recover`); the
/// running binary's path is filled in by whoever renders it, so the document
/// does not pin a path. The CLI renders it as a `Next: sudo <path> <command>`
/// line and a window as a button, both from this one value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NextStep {
    /// The subcommand words after the binary.
    pub command: String,
}

impl NextStep {
    /// A next step naming `command` (the subcommand words).
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
        }
    }
}

/// A machine-readable command result.
#[derive(Debug, Serialize)]
pub struct Envelope<T: Serialize> {
    /// The contract version this document follows.
    pub schema_version: u32,
    /// The command that produced the document (`status`, `verify`, …).
    pub command: &'static str,
    /// Whether the command succeeded: true only when the exit code is 0 or 9.
    pub ok: bool,
    /// The typed success payload, absent on a pure failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// The typed failure payload, absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

/// The structured description of a failure.
///
/// `code` is a stable, snake_case string a caller branches on; `message` is the
/// catalogue string a person reads (it may run to several lines); `next` is the
/// one NAILS command the reader should run next, when the remedy is a command.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    /// A stable, snake_case code a caller can branch on.
    pub code: &'static str,
    /// A human-readable explanation, which may be several lines.
    pub message: String,
    /// The next NAILS command, when the remedy is one; `null` otherwise. Always
    /// present so a reader can branch on it.
    pub next: Option<NextStep>,
}

impl ErrorBody {
    /// A failure with a code and message and no next step.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            next: None,
        }
    }

    /// Append free-form guidance to the message, each line of it on its own
    /// line.
    ///
    /// Guidance that is not a single NAILS command belongs in the message (the
    /// copy rules put the action in the message); this keeps the existing call
    /// sites while the error body carries no free-form field of its own. A
    /// renderer that indents the message's continuation lines reproduces the
    /// old "message, then an indented hint" shape exactly.
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        let hint = hint.into();
        if !hint.is_empty() {
            if !self.message.is_empty() {
                self.message.push('\n');
            }
            self.message.push_str(&hint);
        }
        self
    }

    /// Attach the next NAILS command to run.
    pub fn with_next(mut self, next: NextStep) -> Self {
        self.next = Some(next);
        self
    }
}

impl<T: Serialize> Envelope<T> {
    /// A success envelope carrying typed `data` (`ok` is true).
    pub fn success(command: &'static str, data: T) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            command,
            ok: true,
            data: Some(data),
            error: None,
        }
    }

    /// A result envelope carrying typed `data`, with `ok` taken from the
    /// command's own outcome (true only for exit 0 or 9). A command whose
    /// result is the data itself — `verify`, `status`, `emergency`, `recover` —
    /// uses this so a warning or a degraded outcome reads as `ok: false` without
    /// inventing an error body.
    pub fn outcome(command: &'static str, ok: bool, data: T) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            command,
            ok,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_envelope_has_schema_version_command_and_ok() {
        let env = Envelope::success("status", serde_json::json!({"place": "decoy"}));
        let value: serde_json::Value = serde_json::from_str(&env.to_line()).unwrap();
        assert_eq!(value["schema_version"], 2);
        assert_eq!(value["command"], "status");
        assert_eq!(value["ok"], true);
        assert_eq!(value["data"]["place"], "decoy");
        assert!(value.get("error").is_none());
    }

    #[test]
    fn an_outcome_envelope_carries_the_commands_own_ok() {
        let env = Envelope::outcome("verify", false, serde_json::json!({"status": "warning"}));
        let value: serde_json::Value = serde_json::from_str(&env.to_line()).unwrap();
        assert_eq!(value["ok"], false);
        assert_eq!(value["data"]["status"], "warning");
        assert!(value.get("error").is_none());
    }

    #[test]
    fn error_envelope_carries_code_message_and_a_null_next() {
        let env = error_envelope(
            "activate",
            ErrorBody::new("not_ready", "Not ready: 2 problems."),
        );
        let value: serde_json::Value = serde_json::from_str(&env.to_line()).unwrap();
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "not_ready");
        assert_eq!(value["error"]["message"], "Not ready: 2 problems.");
        // next is always present, null when there is no command to run next.
        assert!(value["error"].get("next").is_some());
        assert_eq!(value["error"]["next"], serde_json::Value::Null);
        assert!(value.get("data").is_none());
    }

    #[test]
    fn a_hint_folds_into_the_message_as_its_own_line() {
        let env = error_envelope(
            "status",
            ErrorBody::new("config", "cannot read config").with_hint("run it as root: sudo nails"),
        );
        let value: serde_json::Value = serde_json::from_str(&env.to_line()).unwrap();
        assert_eq!(
            value["error"]["message"],
            "cannot read config\nrun it as root: sudo nails"
        );
    }

    #[test]
    fn a_typed_next_names_the_subcommand() {
        let env = error_envelope(
            "deactivate",
            ErrorBody::new("invalid_state", "not in a hidden session")
                .with_next(NextStep::new("recover")),
        );
        let value: serde_json::Value = serde_json::from_str(&env.to_line()).unwrap();
        assert_eq!(value["error"]["next"]["command"], "recover");
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
