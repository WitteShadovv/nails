// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Status command handler

use crate::cli::args::StatusArgs;
use crate::cli::output::status::print_status_json_unknown;
use crate::cli::output::{self, ExitStatus, OutputSettings};
use nails_core::status::Posture;
use std::io::Write;
use std::path::Path;

/// The exit status a status run reports, driven entirely by the posture.
///
/// The posture is the kernel-truth verdict, so it always drives the exit code —
/// there is no opt-in flag. The safe postures (decoy, active) exit 0; the
/// dangerous one (degraded) exit [`ExitStatus::DegradedReboot`] so
/// a script fails closed and is pointed at recovery; an unknown state exits
/// [`ExitStatus::InvalidState`].
fn status_exit_code(posture: Posture) -> ExitStatus {
    match posture {
        Posture::Decoy | Posture::Active | Posture::Transitioning => ExitStatus::Ok,
        Posture::Degraded => ExitStatus::DegradedReboot,
        Posture::Unknown => ExitStatus::InvalidState,
    }
}

/// Execute the status command.
///
/// Shows current system status and uptime. Status always reports an exit status
/// of [`ExitStatus::Ok`] for a safe posture (decoy or active), and a non-zero
/// posture-driven code (`DegradedReboot` or `InvalidState`) when the kernel truth
/// is dangerous or unknown; [`ExitStatus::Config`] when the configuration file
/// itself could not be loaded.
///
/// # Arguments
///
/// * `settings` - Output settings resolved once from the global flags
/// * `args` - The `status` arguments (`--details`)
/// * `config_override` - Optional config file path override
pub fn execute(
    settings: &OutputSettings,
    args: &StatusArgs,
    config_override: Option<&Path>,
) -> ExitStatus {
    use nails_core::{NailsError, RealFilesystem, StatusCommand};

    let json = settings.is_json();
    let style = settings.stdout_style();

    let loaded = match super::load_config_or_report(config_override, "status", json) {
        Ok(loaded) => loaded,
        Err(status) => return status,
    };
    let config_path = loaded.path.clone();
    let config = loaded.into_config();

    let state_path = config.state_file_path.clone();
    let hidden_volume_root = config.hidden_volume_root.clone();
    let log_path = config.log_path.clone();

    // Create StatusCommand and run
    let filesystem = RealFilesystem;
    let command = StatusCommand::new(filesystem, config, state_path.clone());

    // A hard error (e.g. a permission-denied state file) means the real state is
    // unknown: report the UNKNOWN posture and fail closed.
    let report = match command.run() {
        Ok(report) => report,
        Err(e) => {
            let error_msg = match e {
                NailsError::IoError { ref source, .. } => {
                    if source.kind() == std::io::ErrorKind::NotFound {
                        format!("State file not found: {}", state_path.display())
                    } else {
                        format!("I/O error reading state file: {e}")
                    }
                }
                NailsError::PermissionDenied(ref msg) => {
                    format!(
                        "Permission denied accessing state file {}: {}",
                        state_path.display(),
                        msg
                    )
                }
                NailsError::ConfigError(ref msg) => {
                    format!(
                        "State file corrupted or invalid at {}: {}",
                        state_path.display(),
                        msg
                    )
                }
                _ => {
                    format!("Error reading state file {}: {}", state_path.display(), e)
                }
            };

            let sudo = super::sudo_line_for(&e, "status");
            if json {
                print_status_json_unknown(error_msg, sudo);
            } else {
                output::print_status_header(style);
                println!("State:              UNKNOWN");
                println!("Security Posture:   {}", Posture::Unknown.render(style));
                println!();
                println!("Error: {}", error_msg);
                println!();
                match sudo {
                    Some(line) => println!("Run it as root: {line}"),
                    None => println!("Fix access to the state file, then run status again"),
                }
            }
            let _ = std::io::stdout().flush();
            return status_exit_code(Posture::Unknown);
        }
    };

    if json {
        output::print_status_json(&report);
    } else {
        output::print_status_human(
            &report,
            args.details,
            &config_path,
            &state_path,
            &hidden_volume_root,
            &log_path,
            style,
        );
    }

    let _ = std::io::stdout().flush();
    status_exit_code(report.posture)
}

#[cfg(test)]
#[path = "status_tests.rs"]
mod tests;
