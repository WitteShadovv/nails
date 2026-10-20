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
