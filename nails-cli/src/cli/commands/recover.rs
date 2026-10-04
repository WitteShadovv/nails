// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Recover command handler
//!
//! `recover` reconciles the recorded state against the live kernel mount table
//! and finishes an interrupted, degraded, or corrupt-state teardown. It never
//! requires an Active state and never reboots, so it is the right tool for a
//! system left stuck after a crash, a killed activation, or a state file that can
//! no longer be trusted — the cases where `deactivate` refuses and a reboot alone
//! would not clean up the live overlays.

use std::path::Path;

use nails_core::output::Mark;
use serde::Serialize;

use crate::cli::args::RecoverArgs;
use crate::cli::output::deactivate::deactivate_error_body;
use crate::cli::output::envelope::{Envelope, ErrorBody, report_error};
use crate::cli::output::{ExitStatus, OutputSettings};

/// Execute the recover command.
///
/// A missing or invalid config is logged as a warning and defaults are used, so
/// recovery is never blocked by an unreadable configuration — the teardown only
/// touches what the live mount table shows NAILS created.
///
/// # Returns
///
/// - [`ExitStatus::Ok`] once the system is inactive (including when it already
///   was)
/// - [`ExitStatus::DegradedReboot`] when some NAILS mount could not be removed
/// - [`ExitStatus::Failed`] on any other failure
pub fn execute(
    settings: &OutputSettings,
    _args: &RecoverArgs,
    config_override: Option<&Path>,
) -> ExitStatus {
    use nails_core::{NailsError, NailsManager, RealFilesystem};

    let json = settings.is_json();
    let verbosity = settings.verbosity;

    // A broken or missing config must never block recovery of a stuck system.
    // When the hidden volume is gone the config comes from the RAM-backed copy
    // under /run; report which source was used.
    let (config, config_source) = super::load_config_for_teardown(config_override);
    if !json {
        tracing::info!("Recovery using the {}", config_source.describe());
    }

    let state_path = config.state_file_path.clone();
    let lock_state_path = state_path.clone();

    let filesystem = RealFilesystem;
    let mut manager = NailsManager::new(filesystem, config, state_path);
    manager.set_verbosity(verbosity);

    // Take the state lock when free, but never let a crashed holder block a
    // recovery: proceed without it after a short timeout, as emergency does.
    let _state_lock = super::acquire_state_lock_for_emergency(&lock_state_path);

    match manager.recover() {
        Ok(outcome) => {
            if json {
                print_recover_json(&outcome);
            } else {
                render_recover_success(settings, &outcome);
            }
            ExitStatus::Ok
        }
        Err(NailsError::DeactivationIncomplete { remaining_mounts }) => {
            let remaining = remaining_mounts
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            report_error(
                json,
                "recover",
                ExitStatus::DegradedReboot,
                ErrorBody::new(
                    "recovery_incomplete",
                    format!("recovery could not remove every NAILS mount: {remaining}"),
                )
                .with_hint(
                    "identify the processes holding the mounts and reboot to finish teardown",
                ),
            )
        }
        Err(e) => report_error(
            json,
            "recover",
            ExitStatus::Failed,
            deactivate_error_body(&e),
        ),
    }
}

/// The `data` payload for a successful `recover --json`.
#[derive(Debug, Serialize)]
struct RecoverData {
    /// `already_inactive` when there was nothing to do, otherwise `recovered`.
    status: &'static str,
    /// Where a corrupt state file was backed up, if one was found.
    state_backed_up: Option<String>,
}

/// Print the success envelope for a completed recovery.
fn print_recover_json(outcome: &nails_core::RecoverOutcome) {
    let data = RecoverData {
        status: if outcome.was_already_inactive {
            "already_inactive"
        } else {
            "recovered"
        },
        state_backed_up: outcome
            .state_backed_up
            .as_ref()
            .map(|path| path.display().to_string()),
    };
    Envelope::success("recover", data).print();
}

/// Render the human-readable success output for a completed recovery.
fn render_recover_success(settings: &OutputSettings, outcome: &nails_core::RecoverOutcome) {
    use crate::cli::output::println_tolerating_broken_pipe;
    let style = settings.stdout_style();
    if outcome.was_already_inactive {
        println_tolerating_broken_pipe(
            &style.marked(Mark::Pass, "Nothing to recover: system is already inactive"),
        );
        return;
    }

    println_tolerating_broken_pipe(&style.marked(
        Mark::Pass,
        "Recovery complete: remaining NAILS mounts torn down",
    ));
    if let Some(path) = &outcome.state_backed_up {
        println_tolerating_broken_pipe(&format!(
            "  Corrupt state file backed up to {}",
            path.display()
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::{RecoverData, print_recover_json, render_recover_success};
    use crate::cli::output::OutputSettings;
    use nails_core::RecoverOutcome;
    use std::path::PathBuf;

    #[test]
    fn recover_data_status_reflects_the_outcome() {
        let data = RecoverData {
            status: "recovered",
            state_backed_up: Some("/mnt/hidden/state.json.bad".to_string()),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("\"status\":\"recovered\""), "{json}");
        assert!(json.contains("state.json.bad"), "{json}");
    }

    #[test]
    fn already_inactive_renders_a_no_op_line() {
        // Smoke test: the renderer must not panic for either outcome shape.
        render_recover_success(
            &OutputSettings::default(),
            &RecoverOutcome {
                state_backed_up: None,
                was_already_inactive: true,
            },
        );
        render_recover_success(
            &OutputSettings::default(),
            &RecoverOutcome {
                state_backed_up: Some(PathBuf::from("/mnt/hidden/state.json.bad")),
                was_already_inactive: false,
            },
        );
    }

    #[test]
    fn recover_json_serializes_for_both_outcomes() {
        print_recover_json(&RecoverOutcome {
            state_backed_up: None,
            was_already_inactive: true,
        });
        print_recover_json(&RecoverOutcome {
            state_backed_up: Some(PathBuf::from("/mnt/hidden/state.json.bad")),
            was_already_inactive: false,
        });
    }
}
