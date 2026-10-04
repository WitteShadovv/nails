// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! reset-upper command handler

use std::io::IsTerminal;
use std::path::Path;

use nails_core::output::Mark;

use crate::cli::args::ResetUpperArgs;
use crate::cli::output::envelope::{Envelope, ErrorBody, report_error};
use crate::cli::output::{ExitStatus, OutputSettings};

/// The `data` payload for `reset-upper --json`.
#[derive(Debug, serde::Serialize)]
struct ResetUpperData {
    /// The overlay target whose upper was reset.
    target: String,
    /// The directories that were removed (empty when there was nothing to do).
    removed: Vec<String>,
}

/// Execute the reset-upper command.
///
/// Deletes a target's persistent overlay upper and work directories on the
/// hidden volume so the target falls back to its decoy lower on the next
/// activation. It refuses unless the system is Inactive and the target is not
/// mounted, lists what it will delete, and confirms on a terminal (`-y` skips
/// the prompt).
///
/// # Returns
///
/// - [`ExitStatus::Ok`] once the upper was removed (or there was nothing to do)
/// - [`ExitStatus::Config`] when the configuration file could not be loaded
/// - [`ExitStatus::InvalidState`] when the system is Active or the target is mounted
/// - [`ExitStatus::Usage`] when confirmation is needed but stdin is not a terminal
/// - [`ExitStatus::Failed`] when the operator declines, or on a lock or removal failure
pub fn execute(
    settings: &OutputSettings,
    args: &ResetUpperArgs,
    config_override: Option<&Path>,
) -> ExitStatus {
    use nails_core::{NailsManager, RealFilesystem};

    let json = settings.is_json();

    // reset-upper deletes data on the hidden volume, so it must not run against
    // a config file the operator did not mean.
    let loaded = match super::load_config_or_report(config_override, "reset-upper", json) {
        Ok(loaded) => loaded,
        Err(status) => return status,
    };
    let config = loaded.into_config();

    let state_path = config.state_file_path.clone();
    let lock_state_path = state_path.clone();
    let target = args.target.clone();

    let manager = NailsManager::new(RealFilesystem, config, state_path);

    // Hold the exclusive state lock while we plan and delete, so a concurrent
    // activation cannot mount the target out from under the reset.
    let _state_lock =
        match super::acquire_state_lock_or_report(&lock_state_path, "reset-upper", json) {
            Ok(lock) => lock,
            Err(status) => return status,
        };

    let plan = match manager.plan_reset_upper(&target) {
        Ok(plan) => plan,
        Err(e) => {
            use nails_core::NailsError;
            let status = match e {
                NailsError::InvalidState(_) => ExitStatus::InvalidState,
                _ => ExitStatus::Failed,
            };
            return report_error(
                json,
                "reset-upper",
                status,
                ErrorBody::new("reset_upper", e.to_string()),
            );
        }
    };

    if plan.is_empty() {
        if json {
            Envelope::success(
                "reset-upper",
                ResetUpperData {
                    target: plan.target.display().to_string(),
                    removed: Vec::new(),
                },
            )
            .print();
        } else {
            println!(
                "{}",
                settings.stdout_style().marked(
                    Mark::Info,
                    format_args!("Nothing to reset for {}", plan.target.display())
                )
            );
        }
        return ExitStatus::Ok;
    }

    // Confirmation gate: the removal is destructive, so without -y it lists the
    // directories and confirms on a terminal, refusing off one.
    if !args.yes {
        if std::io::stdin().is_terminal() {
            if !prompt_reset_confirmation(settings, &plan) {
                return report_error(
                    json,
                    "reset-upper",
                    ExitStatus::Failed,
                    ErrorBody::new("cancelled", "reset-upper cancelled; nothing was removed"),
                );
            }
        } else {
            return report_error(
                json,
                "reset-upper",
                ExitStatus::Usage,
                ErrorBody::new(
                    "needs_confirmation",
                    "reset-upper deletes the target's hidden upper and needs confirmation, but stdin is not a terminal; pass -y/--yes to run non-interactively",
                ),
            );
        }
    }

    if let Err(e) = manager.apply_reset_upper(&plan) {
        return report_error(
            json,
            "reset-upper",
            ExitStatus::Failed,
            ErrorBody::new("reset_upper", e.to_string()),
        );
    }

    let removed: Vec<String> = plan
        .removals()
        .iter()
        .map(|p| p.display().to_string())
        .collect();

    if json {
        Envelope::success(
            "reset-upper",
            ResetUpperData {
                target: plan.target.display().to_string(),
                removed,
            },
        )
        .print();
    } else {
        let style = settings.stdout_style();
        println!(
            "{}",
            style.marked(
                Mark::Pass,
                format_args!("Reset the hidden upper for {}", plan.target.display())
            )
        );
        for path in &removed {
            println!("  removed {path}");
        }
        println!(
            "  {} falls back to its decoy on the next activation",
            plan.target.display()
        );
    }

    ExitStatus::Ok
}

/// Prompt on the terminal before deleting, returning whether the operator
/// confirmed. The warning and the list of directories go to stderr so stdout
/// stays clean for `--json`.
fn prompt_reset_confirmation(settings: &OutputSettings, plan: &nails_core::ResetUpperPlan) -> bool {
    use std::io::{BufRead, Write};

    let style = settings.stderr_style();
    let mut stderr = std::io::stderr();
    let _ = writeln!(
        stderr,
        "{}",
        style.marked(
            Mark::Warn,
            format_args!(
                "This permanently deletes the hidden upper for {}.",
                plan.target.display()
            )
        )
    );
    for path in plan.removals() {
        let _ = writeln!(stderr, "    remove {}", path.display());
    }
    if plan.resets_nix_store {
        let _ = writeln!(
            stderr,
            "    WARNING: resetting /nix drops the hidden Nix database and store paths."
        );
    }
    let _ = write!(stderr, "    Continue? [y/N]: ");
    let _ = stderr.flush();

    let mut input = String::new();
    if std::io::stdin().lock().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}
