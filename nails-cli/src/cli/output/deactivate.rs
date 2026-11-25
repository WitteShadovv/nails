// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Output formatting for the deactivate command.
//!
//! Deactivation enqueues the power-off, so its machine-readable result is a
//! small typed envelope printed once the power-off is enqueued, and its
//! failures are mapped to a structured error that folds the remedy into its
//! `message` (the error body carries no separate hint field).

use nails_core::NailsError;
use serde::Serialize;

use crate::cli::output::envelope::{Envelope, EnvelopePrint, ErrorBody, NextStep};

/// The `data` payload for a successful `deactivate --json`.
#[derive(Debug, Serialize)]
pub struct DeactivateData {
    /// What happens: `poweroff_requested`. A hidden session ends in a
    /// power-off; `return_requested` is no longer sent.
    status: &'static str,
}

impl DeactivateData {
    /// The payload of a deactivation whose power-off is enqueued.
    pub fn enqueued() -> Self {
        Self {
            status: "poweroff_requested",
        }
    }
}

/// Print the success envelope for an enqueued deactivation.
pub fn print_deactivate_json(data: DeactivateData) {
    Envelope::success("deactivate", data).print();
}

/// What a hidden backend device an emergency's cleanup could not mark to
/// close leaves behind.
pub fn backend_left_open_warning(name: &str) -> String {
    format!(
        "The hidden backend device {name} could not be marked to close: it stays open, its \
         key in RAM, until power-off"
    )
}

/// Map a deactivation failure to a structured error: a stable code, a `message`
/// that folds the remedy in after the library explanation (there is no separate
/// hint field), and a typed `next` command where one applies.
pub fn deactivate_error_body(error: &NailsError) -> ErrorBody {
    match error {
        NailsError::PermissionDenied(msg) => {
            ErrorBody::new("permission_denied", format!("cleanup error: {msg}"))
                .with_hint("check file permissions and retry with sudo")
        }
        NailsError::MountBusy { path, suggestion } => {
            ErrorBody::new("mount_busy", format!("overlay busy: {}", path.display()))
                .with_hint(suggestion.clone())
        }
        NailsError::UnmountError { path, reason } => ErrorBody::new(
            "unmount_error",
            format!("unmount failed: {}: {reason}", path.display()),
        )
        .with_hint("check if the overlay is in use and retry"),
        // A refused check: the fix names the emergency, which needs none.
        NailsError::PreFlightCheckFailed(failures) => {
            let reasons: Vec<&str> = failures
                .iter()
                .map(|(_, reason, _)| reason.as_str())
                .collect();
            let fix = failures
                .iter()
                .find_map(|(_, _, fix)| fix.clone())
                .unwrap_or_default();
            ErrorBody::new(
                "not_ready",
                format!("the power-off is refused: {}", reasons.join("; ")),
            )
            .with_hint(fix)
            .with_next(NextStep::new("emergency"))
        }
        // The emergency powers off at once, without the lock or the record.
        NailsError::InvalidState(msg) => ErrorBody::new("invalid_state", msg.clone())
            .with_hint(format!(
                "`{}` ends the session now: it powers off at once",
                nails_core::next_step::sudo_line(nails_core::next_step::NextStep::Emergency),
            ))
            .with_next(NextStep::new("emergency")),
        other => ErrorBody::new("deactivation_failed", other.to_string())
            .with_hint("check system state and retry"),
    }
}

#[cfg(test)]
#[path = "deactivate_tests.rs"]
mod tests;
