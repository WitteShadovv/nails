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

use nails_core::manager::SessionRecovery;
use nails_core::output::{Mark, Style};
use nails_teardown::whole_root::ret::BackendClose;
use serde::Serialize;

use crate::cli::args::RecoverArgs;
use crate::cli::output::deactivate::deactivate_error_body;
use crate::cli::output::envelope::{Envelope, report_error};
use crate::cli::output::{ExitStatus, OutputSettings};

#[derive(Debug, Serialize)]
struct RecoverData {
    /// `clean` (nothing to do) or `rolled_back`.
    outcome: &'static str,
    /// Mounts still below `/run/nextroot`.
    remaining_mounts: Vec<String>,
    /// The hidden backend's devices that were still open.
    backend: Vec<BackendData>,
}

#[derive(Debug, Serialize)]
struct BackendData {
    /// The device-mapper name.
    name: String,
    /// `closed`, or `in_use` (left open: its key is still in RAM).
    state: &'static str,
}

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
    use nails_core::{NailsManager, RealFilesystem};

    let json = settings.is_json();
    let (config, config_source) = super::load_config_for_teardown(config_override);
    tracing::info!("Recovery using the {}", config_source.describe());
    let state_path = config.state_file_path.clone();
    let mut manager =
        NailsManager::new(RealFilesystem, config, state_path.clone()).with_runtime_env(env.clone());
    let _state_lock = super::acquire_state_lock_for_emergency(&state_path);

    match manager.recover_session(&nails_core::session::RealEntryHost) {
        Ok(outcome) => {
            let data = recover_data(&outcome);
            let status = if data.remaining_mounts.is_empty() {
                ExitStatus::Ok
            } else {
                ExitStatus::DegradedReboot
            };
            if json {
                Envelope::success("recover", data).print();
            } else {
                for line in human_lines(&data, settings.stdout_style()) {
                    crate::cli::output::println_tolerating_broken_pipe(&line);
                }
            }
            status
        }
        Err(e) => report_error(
            json,
            "recover",
            ExitStatus::InvalidState,
            deactivate_error_body(&e),
        ),
    }
}

/// The `data` payload for `outcome`.
fn recover_data(outcome: &SessionRecovery) -> RecoverData {
    let (name, remaining, backend): (_, &[std::path::PathBuf], &[(String, BackendClose)]) =
        match outcome {
            SessionRecovery::Clean => ("clean", &[], &[]),
            SessionRecovery::RolledBack { remaining, backend } => {
                ("rolled_back", remaining, backend)
            }
        };
    RecoverData {
        outcome: name,
        remaining_mounts: remaining.iter().map(|p| p.display().to_string()).collect(),
        backend: backend
            .iter()
            .map(|(name, state)| BackendData {
                name: name.clone(),
                state: match state {
                    BackendClose::Closed => "closed",
                    BackendClose::InUse => "in_use",
                },
            })
            .collect(),
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

    const ASCII: Style = Style {
        color: false,
        ascii: true,
    };

    #[test]
    fn a_clean_recovery_is_one_line_and_an_empty_payload() {
        let data = recover_data(&SessionRecovery::Clean);
        assert_eq!(
            serde_json::to_value(&data).unwrap(),
            serde_json::json!({"outcome": "clean", "remaining_mounts": [], "backend": []})
        );
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
            serde_json::to_value(&data).unwrap(),
            serde_json::json!({
                "outcome": "rolled_back",
                "remaining_mounts": ["/run/nextroot/home"],
                "backend": [
                    {"name": "hidden-crypt", "state": "closed"},
                    {"name": "hidden-loop", "state": "in_use"},
                ],
            })
        );
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
