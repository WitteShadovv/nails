// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Recover command handler
//!
//! An activation that dies after building `/run/nextroot` (a crash, a kill, a
//! failed `systemctl`) leaves a populated next root, its runtime directory and
//! the transition drop-in behind. A later plain `reboot` would then turn into a
//! soft-reboot into that tree (systemd 255 and newer); the transition step
//! refuses an unarmed tree anyway, but `recover` removes it outright: it
//! detaches `/run/nextroot`, removes the runtime pieces, reloads the service
//! manager and resets the state. It also closes the hidden backend's
//! device-mapper devices where nothing uses them, so the key leaves RAM, and
//! reports any it had to leave open because they are in use (the hidden volume
//! mounted on the decoy). It never reboots. In the hidden session it
//! refuses and points at `deactivate`; while an activation is entering it
//! refuses and says to wait for that activation's soft-reboot.

use std::path::Path;

use nails_core::app::recover::{RecoverData, RecoverError};
use nails_core::output::{Mark, Style};

use crate::cli::args::RecoverArgs;
use crate::cli::output::envelope::{Envelope, EnvelopePrint, ErrorBody, NextStep, report_error};
use crate::cli::output::{ExitStatus, OutputSettings};

/// Execute the recover command.
///
/// # Returns
///
/// - [`ExitStatus::Ok`] once nothing of an interrupted entry is left
/// - [`ExitStatus::DegradedReboot`] when a mount below `/run/nextroot` stayed
/// - [`ExitStatus::InvalidState`] in the hidden session or during an entry
/// - [`ExitStatus::Failed`] when the recovery itself failed
pub fn execute(
    settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    _args: &RecoverArgs,
    config_override: Option<&Path>,
) -> ExitStatus {
    let json = settings.is_json();
    match nails_core::app::recover::recover(env, config_override) {
        Ok(outcome) => {
            if json {
                // `ok` follows recover's own exit code: a clean recovery is
                // ok, a degraded one (a mount stayed below /run/nextroot) is not.
                Envelope::outcome("recover", outcome.exit.is_success(), outcome.data).print();
            } else {
                for line in human_lines(&outcome.data, settings.stdout_style()) {
                    crate::cli::output::println_tolerating_broken_pipe(&line);
                }
            }
            outcome.exit
        }
        Err(error) => {
            let (status, body) = recover_error(&error);
            report_error(json, "recover", status, body)
        }
    }
}

/// The exit status and error body of a recovery that did not run, each
/// refusal with the next step that fits it.
///
/// In the hidden session the way out is `deactivate`, the typed next step (the
/// message names `emergency` too, for when that fails). While an activation is
/// entering, nothing is to be run but its own soft-reboot, so there is no next
/// step, only the advice to wait for it. A failure of the recovery itself is a
/// plain failure.
fn recover_error(error: &RecoverError) -> (ExitStatus, ErrorBody) {
    use nails_core::next_step::{NextStep as Step, sudo_line};
    let body = ErrorBody::new("invalid_state", error.to_string());
    match error {
        RecoverError::HiddenSession => (
            ExitStatus::InvalidState,
            body.with_next(NextStep::new(Step::Deactivate.command())),
        ),
        RecoverError::Entering => (
            ExitStatus::InvalidState,
            body.with_hint(format!(
                "Wait for its soft-reboot. If it hangs, stop that activation (Ctrl+C where it \
                 runs), then run `{}` again.",
                sudo_line(Step::Recover)
            )),
        ),
        RecoverError::Switching => (
            ExitStatus::InvalidState,
            body.with_hint(format!(
                "Wait for that soft-reboot (at most the decoy's InhibitDelayMaxSec), then run \
                 `{}`.",
                sudo_line(Step::Status)
            )),
        ),
        RecoverError::Failed(cause) => (
            ExitStatus::Failed,
            ErrorBody::new("recover_failed", cause.to_string()),
        ),
    }
}

/// The human report: the outcome, each mount left behind, each backend device.
fn human_lines(data: &RecoverData, style: Style) -> Vec<String> {
    let headline = if data.outcome == "clean" {
        "Nothing to recover: no interrupted activation"
    } else {
        "Removed the interrupted activation's next root and runtime files"
    };
    let mut lines = vec![style.marked(Mark::Pass, headline)];
    for mount in &data.remaining_mounts {
        lines.push(format!("  ! still mounted: {mount} (a reboot clears it)"));
    }
    for device in &data.backend {
        lines.push(if device.state == "closed" {
            style.marked(
                Mark::Pass,
                format!("Closed the hidden backend device {}", device.name),
            )
        } else {
            style.marked(
                Mark::Warn,
                format!(
                    "The hidden backend device {} is still open and in use: its key stays \
                     in RAM until you unmount it and close it",
                    device.name
                ),
            )
        });
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use nails_core::app::recover::recover_data;
    use nails_core::manager::SessionRecovery;
    use nails_teardown::whole_root::ret::BackendClose;

    const ASCII: Style = Style {
        color: false,
        ascii: true,
    };

    /// In the hidden session recover points at `deactivate`, the way out,
    /// never at `emergency`, which loses unsaved work.
    #[test]
    fn a_refusal_in_the_hidden_session_names_deactivate_next() {
        let (status, body) = recover_error(&RecoverError::HiddenSession);
        assert_eq!(status, ExitStatus::InvalidState);
        assert_eq!(body.code, "invalid_state");
        assert_eq!(
            body.next.map(|next| next.command),
            Some("deactivate".to_string())
        );
        assert!(body.message.contains(" deactivate`"), "{}", body.message);
    }

    /// While an activation is entering there is nothing to run but its
    /// soft-reboot: no next step, and no word of killing a session.
    #[test]
    fn a_refusal_during_an_entry_says_to_wait_with_no_next_step() {
        let (status, body) = recover_error(&RecoverError::Entering);
        assert_eq!(status, ExitStatus::InvalidState);
        assert_eq!(body.code, "invalid_state");
        assert!(body.next.is_none(), "{:?}", body.next);
        assert!(
            body.message
                .starts_with("an activation is entering the hidden root right now\n"),
            "{}",
            body.message
        );
        assert!(
            body.message.contains("Wait for its soft-reboot"),
            "{}",
            body.message
        );
        assert!(!body.message.contains("emergency"), "{}", body.message);
    }

    /// While the interrupted activation's soft-reboot may still come, recover
    /// leaves its leftovers for it and says to wait for it, then look.
    #[test]
    fn a_refusal_while_a_soft_reboot_still_comes_says_to_wait_and_look() {
        let (status, body) = recover_error(&RecoverError::Switching);
        assert_eq!(status, ExitStatus::InvalidState);
        assert_eq!(body.code, "invalid_state");
        assert!(body.next.is_none(), "{:?}", body.next);
        assert!(
            body.message
                .starts_with("the interrupted activation's soft-reboot may still come"),
            "{}",
            body.message
        );
        assert!(
            body.message.contains("Wait for that soft-reboot") && body.message.contains(" status`"),
            "{}",
            body.message
        );
    }

    /// A recovery that failed is a plain failure, with no next step.
    #[test]
    fn a_failed_recovery_is_a_plain_failure() {
        let (status, body) = recover_error(&RecoverError::Failed(nails_core::NailsError::io(
            "/mnt/data/state.json",
            std::io::Error::other("full"),
        )));
        assert_eq!(status, ExitStatus::Failed);
        assert_eq!(body.code, "recover_failed");
        assert!(body.next.is_none());
        assert!(body.message.contains("full"), "{}", body.message);
    }

    #[test]
    fn a_clean_recovery_is_one_line() {
        let data = recover_data(&SessionRecovery::Clean);
        assert_eq!(
            human_lines(&data, ASCII),
            vec!["[PASS] Nothing to recover: no interrupted activation"]
        );
    }

    #[test]
    fn a_rollback_reports_leftover_mounts_and_each_backend_device() {
        let data = recover_data(&SessionRecovery::RolledBack {
            remaining: vec!["/run/nextroot/home".into()],
            backend: vec![
                ("hidden-crypt".to_string(), BackendClose::Closed),
                ("hidden-loop".to_string(), BackendClose::InUse),
            ],
        });
        assert_eq!(
            human_lines(&data, ASCII),
            vec![
                "[PASS] Removed the interrupted activation's next root and runtime files",
                "  ! still mounted: /run/nextroot/home (a reboot clears it)",
                "[PASS] Closed the hidden backend device hidden-crypt",
                "[WARN] The hidden backend device hidden-loop is still open and in use: its \
                 key stays in RAM until you unmount it and close it",
            ]
        );
    }
}
