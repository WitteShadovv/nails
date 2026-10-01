//! Status command handler

use crate::cli::args::StatusArgs;
use crate::cli::output::{self, OutputSettings};
use std::io::Write;
use std::path::Path;

/// Execute the status command
///
/// Shows current system status and uptime.
///
/// # Arguments
///
/// * `settings` - Output settings resolved once from the global flags
/// * `args` - The `status` arguments (`--details`)
/// * `config_override` - Optional config file path override
///
/// # Returns
///
/// Never returns - exits with code 0 for status results, 3 for config load failures
pub fn execute(settings: &OutputSettings, args: &StatusArgs, config_override: Option<&Path>) -> ! {
    use nails_core::{NailsError, RealFilesystem, StatusCommand, status::SecurityPosture};

    let json = settings.is_json();
    let style = settings.stdout_style();

    let loaded = super::load_config_or_exit(config_override);
    let config_path = loaded.path.clone();
    let config = loaded.into_config();

    let state_path = config.state_file_path.clone();
    let hidden_volume_root = config.hidden_volume_root.clone();
    let log_path = config.log_path.clone();

    // Create StatusCommand and run
    let filesystem = RealFilesystem;
    let command = StatusCommand::new(filesystem, config, state_path.clone());

    // Preserve FR63 for status collection/runtime failures after config is loaded.
    let report = match command.run_truthful() {
        Ok(report) => report,
        // FIX #4 & #7: Better error context with specific messages
        Err(e) => {
            // State file error - show INACTIVE status with error details
            // FR63: Status always succeeds (exit code 0)
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

            // FIX #5: Use SecurityPosture constant instead of duplicated strings
            let posture = SecurityPosture::Warning;

            if json {
                println!(
                    "{{\"state\":\"UNKNOWN\",\"security_posture\":\"warning\",\"error\":\"{}\"}}",
                    error_msg.replace('"', "\\\"")
                );
            } else {
                output::print_status_header(style);
                println!("State:              UNKNOWN");
                println!("Security Posture:   {}", posture.render(style));
                println!();
                println!("Error: {}", error_msg);
                println!();
                println!("Run status with sufficient privileges or fix state file access");
            }
            let _ = std::io::stdout().flush();
            std::process::exit(0); // Status always exits 0 once it produced a report
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

    // Status always succeeds (exit code 0) once it produced a report.
    let _ = std::io::stdout().flush();
    std::process::exit(0);
}

#[cfg(test)]
#[path = "status_tests.rs"]
mod tests;
