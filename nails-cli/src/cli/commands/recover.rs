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
//! manager and resets the state. It never reboots. In the hidden session it
//! refuses and points at `deactivate`.

use std::path::Path;

use nails_core::manager::SessionRecovery;
use nails_core::output::Mark;
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
            let (name, remaining) = match &outcome {
                SessionRecovery::Clean => ("clean", Vec::new()),
                SessionRecovery::RolledBack(remaining) => ("rolled_back", remaining.clone()),
            };
            let remaining: Vec<String> =
                remaining.iter().map(|p| p.display().to_string()).collect();
            if json {
                Envelope::success(
                    "recover",
                    RecoverData {
                        outcome: name,
                        remaining_mounts: remaining.clone(),
                    },
                )
                .print();
            } else {
                let style = settings.stdout_style();
                let line = match outcome {
                    SessionRecovery::Clean => "Nothing to recover: no interrupted activation",
                    SessionRecovery::RolledBack(_) => {
                        "Removed the interrupted activation's next root and runtime files"
                    }
                };
                crate::cli::output::println_tolerating_broken_pipe(&style.marked(Mark::Pass, line));
                for mount in &remaining {
                    crate::cli::output::println_tolerating_broken_pipe(&format!(
                        "  ! still mounted: {mount} (a reboot clears it)"
                    ));
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
