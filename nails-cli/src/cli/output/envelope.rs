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

    /// Serialize to one compact line and print it on stdout.
    pub fn print(&self) {
        println!("{}", self.to_line());
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
        eprintln!("error: {}", error.message);
        if let Some(hint) = error.hint {
            eprintln!("  {hint}");
        }
    }
    status
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
    fn a_newline_in_a_message_stays_one_parseable_line() {
        let env = error_envelope("deactivate", ErrorBody::new("mount_busy", "busy\nretry"));
        let line = env.to_line();
        assert_eq!(line.lines().count(), 1, "one physical line: {line}");
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["error"]["message"], "busy\nretry");
    }
}
