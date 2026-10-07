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
use nails_core::output::Mark;
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
            let (name, remaining, backend) = match &outcome {
                SessionRecovery::Clean => ("clean", Vec::new(), Vec::new()),
                SessionRecovery::RolledBack { remaining, backend } => {
                    ("rolled_back", remaining.clone(), backend.clone())
                }
            };
            let remaining: Vec<String> =
                remaining.iter().map(|p| p.display().to_string()).collect();
            let backend: Vec<BackendData> = backend
                .into_iter()
                .map(|(name, state)| BackendData {
                    name,
                    state: match state {
                        BackendClose::Closed => "closed",
                        BackendClose::InUse => "in_use",
                    },
                })
                .collect();
            if json {
                Envelope::success(
                    "recover",
                    RecoverData {
                        outcome: name,
                        remaining_mounts: remaining.clone(),
                        backend,
                    },
                )
                .print();
            } else {
                let style = settings.stdout_style();
                let line = match outcome {
                    SessionRecovery::Clean => "Nothing to recover: no interrupted activation",
                    SessionRecovery::RolledBack { .. } => {
                        "Removed the interrupted activation's next root and runtime files"
                    }
                };
                crate::cli::output::println_tolerating_broken_pipe(&style.marked(Mark::Pass, line));
                for mount in &remaining {
                    crate::cli::output::println_tolerating_broken_pipe(&format!(
                        "  ! still mounted: {mount} (a reboot clears it)"
                    ));
                }
                for device in &backend {
                    let line = if device.state == "closed" {
                        style.marked(
                            Mark::Pass,
                            format!("Closed the hidden backend device {}", device.name),
                        )
                    } else {
                        style.marked(
                            Mark::Warn,
                            format!(
                                "The hidden backend device {} is still open and in use: its \
                                 key stays in RAM until you unmount it and close it",
                                device.name
                            ),
                        )
                    };
                    crate::cli::output::println_tolerating_broken_pipe(&line);
                }
            }
            if remaining.is_empty() {
                ExitStatus::Ok
            } else {
                ExitStatus::DegradedReboot
            }
        }
        Err(e) => report_error(
            json,
            "recover",
            ExitStatus::InvalidState,
            deactivate_error_body(&e),
        ),
    }
}
