//! Deactivate command handler

use std::io::IsTerminal;
use std::path::Path;

use nails_core::output::Mark;

use crate::cli::args::DeactivateArgs;
use crate::cli::detach::maybe_detach_for_deactivation;
use crate::cli::output::deactivate::{deactivate_error_body, print_deactivate_json};
use crate::cli::output::envelope::{ErrorBody, report_error};
use crate::cli::output::{ExitStatus, OutputSettings};

/// Execute the deactivate command.
///
/// Deactivate and reboot into the decoy state (unmount + cleanup + reboot). A
/// missing or invalid config is logged as a warning and defaults are used,
/// since a broken config must never block returning to the decoy.
///
/// # Returns
///
/// - [`ExitStatus::Ok`] once the restore + reboot was requested
/// - [`ExitStatus::Usage`] when confirmation is needed but stdin is not a terminal
/// - [`ExitStatus::Failed`] when the operator declines, or on a detach, lock, or
///   deactivation failure
pub fn execute(
    settings: &OutputSettings,
    args: &DeactivateArgs,
    config_override: Option<&Path>,
) -> ExitStatus {
    use nails_core::{NailsManager, RealFilesystem};

    let json = settings.is_json();
    let verbosity = settings.verbosity;

    // A broken or missing config must never block returning to the decoy.
    let mut config = super::load_config_or_defaults(config_override).into_config();

    // Apply --no-clear-history CLI override
    if args.no_clear_history {
        config.clear_history = false;
    }

    // Confirmation gate: deactivation restores the decoy and reboots, so without
    // -y it confirms on a terminal and refuses off one, before any teardown. A
    // detached worker was already confirmed by its parent.
    let already_detached = std::env::var_os(nails_core::constants::ENV_DETACHED).is_some();
    if !args.yes && !already_detached {
        if std::io::stdin().is_terminal() {
            if !prompt_deactivate_confirmation(settings) {
                return report_error(
                    json,
                    "deactivate",
                    ExitStatus::Failed,
                    ErrorBody::new(
                        "cancelled",
                        "deactivation cancelled; the system is unchanged",
                    ),
                );
            }
        } else {
            return report_error(
                json,
                "deactivate",
                ExitStatus::Usage,
                ErrorBody::new(
                    "needs_confirmation",
                    "deactivate reboots into the decoy and needs confirmation, but stdin is not a terminal; pass -y/--yes to run non-interactively",
                ),
            );
        }
    }

    let state_path = config.state_file_path.clone();
    // Retained for the state lock after detach, since `config` and the clone
    // above are moved into the manager below.
    let lock_state_path = state_path.clone();

    // Create manager
    let filesystem = RealFilesystem;
    let mut manager = NailsManager::new(filesystem, config, state_path);
    manager.set_verbosity(verbosity);

    if let Err(e) = maybe_detach_for_deactivation() {
        return report_error(
            json,
            "deactivate",
            ExitStatus::Failed,
            ErrorBody::new("detach", e.to_string()),
        );
    }

    // Take the exclusive state lock after any detach, so a concurrent operation
    // fails fast instead of racing this teardown.
    let _state_lock =
        match super::acquire_state_lock_or_report(&lock_state_path, "deactivate", json) {
            Ok(lock) => lock,
            Err(status) => return status,
        };

    // Print the recovery guidance before handing off to the core deactivation,
    // which reboots as its final step: anything printed afterwards would be lost
    // when the machine goes down.
    if !json {
        eprintln!();
        for line in deactivate_recovery_guidance(settings) {
            eprintln!("{line}");
        }
    }

    // Run quick deactivation (restore symlink + reboot)
    match manager.deactivate() {
        Ok(_report) => {
            if json {
                print_deactivate_json();
            } else {
                println!(
                    "{}",
                    settings
                        .stdout_style()
                        .marked(Mark::Pass, "System configuration restored")
                );
                println!("  Rebooting to decoy environment...");
            }
            // Note: the reboot was already issued, so this may not run.
            ExitStatus::Ok
        }
        Err(e) => report_error(
            json,
            "deactivate",
            ExitStatus::Failed,
            deactivate_error_body(&e),
        ),
    }
}

/// Prompt on the terminal before deactivating, returning whether the operator
/// confirmed. The warning and question go to stderr so stdout stays clean.
fn prompt_deactivate_confirmation(settings: &OutputSettings) -> bool {
    use std::io::{BufRead, Write};

    let style = settings.stderr_style();
    let mut stderr = std::io::stderr();
    let _ = writeln!(
        stderr,
        "{}",
        style.marked(
            Mark::Warn,
            "This restores the decoy configuration and reboots now."
        )
    );
    let _ = writeln!(
        stderr,
        "    The hidden overlays are unmounted and the machine reboots into the decoy."
    );
    let _ = write!(stderr, "    Continue? [y/N]: ");
    let _ = stderr.flush();

    let mut input = String::new();
    if std::io::stdin().lock().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Recovery guidance printed to stderr after deactivation; the first line
/// carries the shared warning mark in the stderr style.
fn deactivate_recovery_guidance(settings: &OutputSettings) -> Vec<String> {
    use crate::cli::output::deactivate::DEACTIVATE_RECOVERY_GUIDANCE;
    let mut lines: Vec<String> = DEACTIVATE_RECOVERY_GUIDANCE
        .iter()
        .map(|line| line.to_string())
        .collect();
    lines[0] = settings.stderr_style().marked(Mark::Warn, &lines[0]);
    lines
}

#[cfg(test)]
mod tests;
