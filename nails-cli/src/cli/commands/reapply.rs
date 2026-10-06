// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reapply command handler
//!
//! Re-runs the hidden NixOS build + `switch-to-configuration test` against the
//! current hidden configuration while the system is already active, without
//! remounting anything. It exists so a fixed hidden configuration can be applied
//! in place after an activation whose switch failed (reported as "activated with
//! warnings"), instead of a full `nails deactivate` (which reboots) followed by a
//! fresh `nails activate`.

use crate::cli::args::ReapplyArgs;
use crate::cli::output::envelope::SCHEMA_VERSION;
use crate::cli::output::envelope::{ErrorBody, report_error};
use crate::cli::output::{ExitStatus, OutputSettings};

use nails_core::output::{Mark, Tone};
use nails_core::{ActivationOutcome, NailsError};
use serde::Serialize;
use std::path::Path;

/// The final NDJSON line for `reapply --json`.
#[derive(Debug, Serialize)]
struct ReapplyResultEvent {
    schema_version: u32,
    command: &'static str,
    #[serde(rename = "type")]
    event_type: &'static str,
    ok: bool,
    status: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
    message: String,
}

/// Execute the `reapply` command.
///
/// Returns [`ExitStatus::Ok`] when the hidden configuration was reapplied
/// cleanly, [`ExitStatus::SuccessWithWarnings`] when it still could not be
/// applied (the same code `activate` uses), [`ExitStatus::InvalidState`] when the
/// system is not active, [`ExitStatus::Config`] for a configuration load failure
/// and [`ExitStatus::Failed`] for any other error.
pub fn execute(
    settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    _args: &ReapplyArgs,
    config_override: Option<&Path>,
) -> ExitStatus {
    let json = settings.is_json();

    let loaded = match super::load_config_or_report(config_override, "reapply", json) {
        Ok(loaded) => loaded,
        Err(status) => return status,
    };
    let config = loaded.into_config();
    let state_path = config.state_file_path.clone();
    let lock_state_path = state_path.clone();

    // Build the manager with the same NixOS build target activation would pick, so
    // reapply rebuilds and switches to exactly the configuration a fresh
    // activation would.
    let mut manager = super::build_nixos_manager(config, state_path, false, env);
    manager.set_verbosity(settings.verbosity);
    if let Err(e) = manager.initialize_platform() {
        tracing::debug!(error = %e, "platform detection failed; continuing without a host profile");
    }

    // Take the exclusive state lock: a concurrent activate/deactivate must not run
    // a switch at the same time.
    let _state_lock = match super::acquire_state_lock_or_report(&lock_state_path, "reapply", json) {
        Ok(lock) => lock,
        Err(status) => return status,
    };

    let result = manager.reapply_hidden_config();
    report(&result, settings, json)
}

/// Render the reapply outcome and map it to an exit status.
fn report(
    result: &Result<ActivationOutcome, NailsError>,
    settings: &OutputSettings,
    json: bool,
) -> ExitStatus {
    match result {
        Ok(outcome) => {
            let warnings = outcome.warnings();
            if json {
                let (status, message) = if warnings.is_empty() {
                    ("success", "Hidden configuration reapplied".to_string())
                } else {
                    (
                        "success_with_warnings",
                        format!("Reapplied with warnings: {}", warnings.join("; ")),
                    )
                };
                let event = ReapplyResultEvent {
                    schema_version: SCHEMA_VERSION,
                    command: "reapply",
                    event_type: "result",
                    ok: true,
                    status,
                    warnings: warnings.clone(),
                    message,
                };
                println!(
                    "{}",
                    serde_json::to_string(&event)
                        .expect("reapply result serialization cannot fail")
                );
            } else {
                let out = settings.stdout_style();
                if warnings.is_empty() {
                    println!(
                        "{}",
                        out.paint_bold(
                            format_args!(
                                "{} Hidden configuration reapplied",
                                out.glyph(Mark::Pass)
                            ),
                            Tone::Green
                        )
                    );
                } else {
                    for warning in &warnings {
                        println!(
                            "{}",
                            out.paint(
                                format_args!(
                                    "{} Reapplied with warnings: {}",
                                    out.glyph(Mark::Warn),
                                    warning
                                ),
                                Tone::Yellow
                            )
                        );
                    }
                }
            }

            if warnings.is_empty() {
                ExitStatus::Ok
            } else {
                ExitStatus::SuccessWithWarnings
            }
        }
        Err(e) => {
            let (exit, code) = match e {
                NailsError::InvalidState(_) => (ExitStatus::InvalidState, "invalid_state"),
                _ => (ExitStatus::Failed, "reapply"),
            };
            report_error(json, "reapply", exit, ErrorBody::new(code, e.to_string()))
        }
    }
}

#[cfg(test)]
#[path = "reapply_tests.rs"]
mod tests;
