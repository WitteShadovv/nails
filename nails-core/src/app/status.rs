// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `status` operation: read the live session view and the recorded state.

use std::path::Path;

use crate::status::StatusCommand;
use crate::{Config, NailsError, RealFilesystem, StatusReport};

/// What reading the status produced.
pub enum StatusOutcome {
    /// The live report.
    Report(Box<StatusReport>),
    /// The state could not be read, so the record is unknown. `message` explains
    /// why in one line; `source` is the underlying error a caller can use to
    /// decide a next step (a refused read suggests running as root).
    Unknown {
        /// The one-line explanation shown to the operator.
        message: String,
        /// The error that made the state unknown.
        source: NailsError,
    },
}

/// Read the live status for `config`.
///
/// Probes the live session and reads the recorded state. A hard error (a
/// permission-denied or corrupt state file) does not fail the operation: it
/// means the real state is unknown, which is itself the answer, so it is
/// returned as [`StatusOutcome::Unknown`] with the one-line reason.
pub fn status(config: Config) -> StatusOutcome {
    let state_path = config.state_file_path.clone();
    let command = StatusCommand::new(RealFilesystem, config, state_path.clone());
    match command.run() {
        Ok(report) => StatusOutcome::Report(Box::new(report)),
        Err(source) => {
            let message = unknown_message(&source, &state_path);
            StatusOutcome::Unknown { message, source }
        }
    }
}

/// The one-line reason a state file could not be read, named for the operator.
fn unknown_message(error: &NailsError, state_path: &Path) -> String {
    match error {
        NailsError::IoError { source, .. } => {
            if source.kind() == std::io::ErrorKind::NotFound {
                format!("State file not found: {}", state_path.display())
            } else {
                format!("I/O error reading state file: {error}")
            }
        }
        NailsError::PermissionDenied(msg) => {
            format!(
                "Permission denied accessing state file {}: {}",
                state_path.display(),
                msg
            )
        }
        NailsError::ConfigError(msg) => {
            format!(
                "State file corrupted or invalid at {}: {}",
                state_path.display(),
                msg
            )
        }
        _ => {
            format!(
                "Error reading state file {}: {}",
                state_path.display(),
                error
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::path::PathBuf;

    fn state_path() -> PathBuf {
        PathBuf::from("/var/lib/nails/state.json")
    }

    #[test]
    fn io_not_found_names_a_missing_state_file() {
        let error = NailsError::io(
            state_path(),
            io::Error::new(io::ErrorKind::NotFound, "no such file"),
        );

        let message = unknown_message(&error, &state_path());

        // The NotFound branch must win over the generic I/O branch and the
        // catch-all. Flipping `==` to `!=` sends NotFound to the else branch,
        // and deleting the IoError arm sends it to the `_` catch-all; both
        // produce text without this phrase.
        assert!(
            message.starts_with("State file not found: "),
            "expected the missing-file message, got: {message}"
        );
        assert!(
            message.contains("/var/lib/nails/state.json"),
            "the message must name the state path, got: {message}"
        );
    }

    #[test]
    fn io_other_kind_is_reported_as_an_io_error() {
        let error = NailsError::io(state_path(), io::Error::other("disk on fire"));

        let message = unknown_message(&error, &state_path());

        // A non-NotFound I/O error takes the else branch of the kind check.
        // Flipping `==` to `!=` would instead claim the file was not found,
        // and deleting the IoError arm would drop to the `_` catch-all whose
        // wording is "Error reading state file", not "I/O error reading".
        assert!(
            message.starts_with("I/O error reading state file: "),
            "expected the generic I/O message, got: {message}"
        );
        assert!(
            message.contains("disk on fire"),
            "the underlying error text must be shown, got: {message}"
        );
    }

    #[test]
    fn permission_denied_suggests_the_state_file_was_refused() {
        let error = NailsError::PermissionDenied("root required".into());

        let message = unknown_message(&error, &state_path());

        // Deleting the PermissionDenied arm drops to the `_` catch-all, which
        // omits this distinctive wording and the context message.
        assert!(
            message.starts_with("Permission denied accessing state file "),
            "expected the permission-denied message, got: {message}"
        );
        assert!(
            message.contains("/var/lib/nails/state.json"),
            "the message must name the state path, got: {message}"
        );
        assert!(
            message.ends_with(": root required"),
            "the context message must be appended, got: {message}"
        );
    }

    #[test]
    fn config_error_reports_a_corrupt_state_file() {
        let error = NailsError::ConfigError("unexpected EOF".into());

        let message = unknown_message(&error, &state_path());

        // Deleting the ConfigError arm drops to the `_` catch-all, which does
        // not describe the file as corrupted or invalid.
        assert!(
            message.starts_with("State file corrupted or invalid at "),
            "expected the corrupt-state message, got: {message}"
        );
        assert!(
            message.contains("/var/lib/nails/state.json"),
            "the message must name the state path, got: {message}"
        );
        assert!(
            message.ends_with(": unexpected EOF"),
            "the context message must be appended, got: {message}"
        );
    }

    #[test]
    fn other_errors_fall_back_to_the_generic_reader_message() {
        // A variant with no dedicated arm exercises the `_` catch-all, which
        // the whole-function stubs (`String::new()` / `"xyzzy"`) would blank
        // out or replace.
        let error = NailsError::InvalidState("locked".into());

        let message = unknown_message(&error, &state_path());

        assert!(
            message.starts_with("Error reading state file /var/lib/nails/state.json: "),
            "expected the generic fallback message, got: {message}"
        );
        assert!(
            message.contains("locked"),
            "the underlying error text must be shown, got: {message}"
        );
    }
}
