// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Output formatting for the deactivate command.
//!
//! Deactivation enqueues the soft-reboot back to the decoy (or a power-off),
//! so its machine-readable result is a small typed envelope printed once the
//! switch is enqueued, and its failures are mapped to a structured error that
//! folds the remedy into its `message` (the error body carries no separate hint
//! field).

use nails_core::NailsError;
use serde::Serialize;

use crate::cli::output::envelope::{Envelope, EnvelopePrint, ErrorBody, NextStep};

/// The `data` payload for a successful `deactivate --json`.
#[derive(Debug, Serialize)]
pub struct DeactivateData {
    /// What happens (`return_requested` or `poweroff_requested`).
    status: &'static str,
    /// What the return does not put back, one sentence each, as a person
    /// reads them; absent when there is nothing to say.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
    /// The hidden backend's device-mapper devices that could not be marked to
    /// close: they stay open after the switch, their key in RAM, until
    /// power-off. Absent when every device was marked.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    backend_left_open: Vec<String>,
}

impl DeactivateData {
    /// The payload of a deactivation whose soft-reboot back to the decoy, or
    /// power-off when `poweroff` is set, is enqueued, with the `warnings` it
    /// gives and the backend devices it `left_open`.
    pub fn enqueued(poweroff: bool, warnings: Vec<String>, left_open: Vec<String>) -> Self {
        Self {
            status: if poweroff {
                "poweroff_requested"
            } else {
                "return_requested"
            },
            warnings,
            backend_left_open: left_open,
        }
    }
}

/// Print the success envelope for an enqueued deactivation.
pub fn print_deactivate_json(data: DeactivateData) {
    Envelope::success("deactivate", data).print();
}

/// What a hidden backend device the way back could not mark to close leaves
/// behind, as `deactivate` and `emergency` both say it.
pub fn backend_left_open_warning(name: &str) -> String {
    format!(
        "The hidden backend device {name} could not be marked to close: it stays open after \
         the switch, its key in RAM, until power-off"
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
        // A plain emergency returns to the decoy only where it can prepare the
        // return, as this way back could not: otherwise it powers off.
        NailsError::InvalidState(msg) => ErrorBody::new("invalid_state", msg.clone())
            .with_hint(format!(
                "`{}` ends the session now: it returns to the decoy where it can prepare the \
                 return and powers off where it cannot; `{}` always powers off",
                nails_core::next_step::sudo_line(nails_core::next_step::NextStep::Emergency),
                nails_core::next_step::sudo_line(
                    nails_core::next_step::NextStep::EmergencyPoweroff
                )
            ))
            .with_next(NextStep::new("emergency")),
        other => ErrorBody::new("deactivation_failed", other.to_string())
            .with_hint("check system state and retry"),
    }
}

#[cfg(test)]
#[path = "deactivate_tests.rs"]
mod tests;
