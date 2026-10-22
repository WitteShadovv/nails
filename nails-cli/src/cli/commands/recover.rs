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
//! refuses and points at `deactivate`.

use std::path::Path;

use nails_core::app::recover::RecoverData;
use nails_core::output::{Mark, Style};

use crate::cli::args::RecoverArgs;
use crate::cli::output::deactivate::deactivate_error_body;
use crate::cli::output::envelope::{Envelope, EnvelopePrint, report_error};
use crate::cli::output::{ExitStatus, OutputSettings};

/// Execute the recover command.
///
/// # Returns
///
/// - [`ExitStatus::Ok`] once nothing of an interrupted entry is left
/// - [`ExitStatus::DegradedReboot`] when a mount below `/run/nextroot` stayed
/// - [`ExitStatus::InvalidState`] in the hidden session or during an entry
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
        Err(e) => report_error(
            json,
            "recover",
            ExitStatus::InvalidState,
            deactivate_error_body(&e),
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
