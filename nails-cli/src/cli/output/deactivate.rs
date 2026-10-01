//! Output formatting for the deactivate command.
//!
//! The quick-deactivation flow restores the decoy configuration and reboots, so
//! its machine-readable result is a small typed envelope rather than a
//! hand-built string, and its failures are mapped to a structured error whose
//! `hint` carries the remedy (keeping any multi-line library message out of the
//! JSON document).

use nails_core::NailsError;
use serde::Serialize;

use crate::cli::output::envelope::{Envelope, ErrorBody};

/// Recovery guidance shown after deactivation; the operator must still dismount
/// the hidden volume and reboot for a fully clean state.
pub const DEACTIVATE_RECOVERY_GUIDANCE: &[&str] = &[
    "Important: Hidden storage may still be mounted. Your system is not in a fully safe state until:",
    "  1. The hidden volume is dismounted",
    "  2. The system is rebooted",
];

/// The `data` payload for a successful `deactivate --json`.
#[derive(Debug, Serialize)]
pub struct DeactivateData {
    /// What happened (`reboot_requested`).
    status: &'static str,
    /// The recovery steps the operator should still take.
    recovery_guidance: Vec<&'static str>,
}

/// Print the success envelope for a deactivation that requested a reboot.
pub fn print_deactivate_json() {
    let data = DeactivateData {
        status: "reboot_requested",
        recovery_guidance: DEACTIVATE_RECOVERY_GUIDANCE.to_vec(),
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
        NailsError::InvalidState(msg) => ErrorBody::new("invalid_state", msg.clone())
            .with_hint("verify the system is in the ACTIVE state"),
        other => ErrorBody::new("deactivation_failed", other.to_string())
            .with_hint("check system state and retry"),
    }
}

#[cfg(test)]
#[path = "deactivate_tests.rs"]
mod tests;
