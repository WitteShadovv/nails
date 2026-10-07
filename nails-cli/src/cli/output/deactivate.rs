// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Output formatting for the deactivate command.
//!
//! Deactivation enqueues the soft-reboot back to the decoy (or a power-off),
//! so its machine-readable result is a small typed envelope printed before the
//! switch, and its failures are mapped to a structured error whose `hint`
//! carries the remedy.

use nails_core::NailsError;
use serde::Serialize;

use crate::cli::output::envelope::{Envelope, ErrorBody};

/// The `data` payload for a successful `deactivate --json`.
#[derive(Debug, Serialize)]
pub struct DeactivateData {
    /// What happens (`return_requested` or `poweroff_requested`).
    status: &'static str,
}

/// Print the success envelope for a deactivation that is returning to the
/// decoy, or powering off when `poweroff` is set.
pub fn print_deactivate_json(poweroff: bool) {
    let data = DeactivateData {
        status: if poweroff {
            "poweroff_requested"
        } else {
            "return_requested"
        },
    };
    Envelope::success("deactivate", data).print();
}

/// Map a deactivation failure to a structured error, folding any multi-line
/// library message into a one-line message plus a `hint`.
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
        NailsError::InvalidState(msg) => ErrorBody::new("invalid_state", msg.clone()).with_hint(
            "'nails emergency' kills the hidden session and returns, or powers off with --poweroff",
        ),
        other => ErrorBody::new("deactivation_failed", other.to_string())
            .with_hint("check system state and retry"),
    }
}

#[cfg(test)]
#[path = "deactivate_tests.rs"]
mod tests;
