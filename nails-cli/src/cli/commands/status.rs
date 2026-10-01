//! Status command handler

use crate::cli::args::StatusArgs;
use crate::cli::output::status::print_status_json_unknown;
use crate::cli::output::{self, ExitStatus, OutputSettings};
use nails_core::status::SecurityPosture;
use std::io::Write;
use std::path::Path;

/// The exit status a status run reports.
///
/// Without `--exit-status`, status always exits 0 once it produced a report. With
/// `--exit-status`, the exit code reflects the security posture so scripts can
/// branch on it: a transitional/inconsistent posture is a failure, a degraded
/// system asks for a reboot, and the normal decoy or a verified-active system is
/// a success.
fn status_exit_code(posture: SecurityPosture, degraded: bool, exit_status: bool) -> ExitStatus {
    if !exit_status {
        return ExitStatus::Ok;
    }
    match posture {
        SecurityPosture::Secure | SecurityPosture::Decoy => ExitStatus::Ok,
        SecurityPosture::Warning => ExitStatus::Failed,
        SecurityPosture::Critical if degraded => ExitStatus::DegradedReboot,
        SecurityPosture::Critical => ExitStatus::Failed,
    }
}

/// Execute the status command.
///
/// Shows current system status and uptime. Status always reports an exit status
/// of [`ExitStatus::Ok`] once it has produced a report (even for an unreadable
/// state file), and [`ExitStatus::Config`] when the configuration file itself
/// could not be loaded.
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

    // Status collection/runtime failures after config is loaded still exit 0.
    let report = match command.run_truthful() {
        Ok(report) => report,
        Err(e) => {
            // State file error - report an UNKNOWN status with error details.
            // Status always succeeds (exit code 0) once it produced a report.
            let error_msg = match e {
                NailsError::IoError(ref io_err) => {
                    if io_err.kind() == std::io::ErrorKind::NotFound {
                        format!("State file not found: {}", state_path.display())
                    } else {
                        format!(
                            "I/O error reading state file {}: {}",
                            state_path.display(),
                            io_err
                        )
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

            if json {
                print_status_json_unknown(error_msg);
            } else {
                output::print_status_header(style);
                println!("State:              UNKNOWN");
                println!(
                    "Security Posture:   {}",
                    SecurityPosture::Warning.render(style)
                );
                println!();
                println!("Error: {}", error_msg);
                println!();
                println!("Run status with sufficient privileges or fix state file access");
            }
            let _ = std::io::stdout().flush();
            // An untrusted state file is a Warning posture, not Degraded.
            return status_exit_code(SecurityPosture::Warning, false, args.exit_status);
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

    // Status exits 0 once it produced a report, unless --exit-status asks for the
    // posture to be reflected in the exit code.
    let _ = std::io::stdout().flush();
    status_exit_code(
        report.security_posture(),
        matches!(report.state, nails_core::SystemState::Degraded { .. }),
        args.exit_status,
    )
}

#[cfg(test)]
#[path = "status_tests.rs"]
mod tests;
