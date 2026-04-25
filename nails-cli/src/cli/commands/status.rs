//! Status command handler

use crate::cli::output;
use std::io::Write;
use std::path::PathBuf;

/// Execute the status command
///
/// Shows current system status and uptime.
///
/// # Arguments
///
/// * `config_override` - Optional config file path override
/// * `json` - Output results in JSON format
/// * `no_color` - Disable colored output
/// * `plain` - ASCII-only output (no Unicode symbols)
/// * `verbose` - Display detailed overlay mount information
///
/// # Returns
///
/// Never returns - exits with code 0 for status results, 2 for config load failures
pub fn execute(
    config_override: Option<PathBuf>,
    json: bool,
    no_color: bool,
    plain: bool,
    verbose: bool,
) -> ! {
    use nails_core::{NailsError, RealFilesystem, StatusCommand, status::SecurityPosture};

    // Configure color output (must be done before any colored output)
    // Story 14.7: Integrate output module with NO_COLOR/--no-color/--plain support
    // Note: set_plain_mode() already handles colored::control::set_override()
    nails_core::set_plain_mode(plain);
    nails_core::set_color_enabled(
        !(plain
            || no_color
            || std::env::var("NO_COLOR").is_ok()
            || std::env::var(nails_core::obfuscate::env_no_color()).is_ok()),
    );

    // Load configuration (Story 14.1)
    let config_path = nails_core::config::discover_config_path(config_override.as_deref());

    let mut config = super::load_config_or_exit(&config_path, config_override.as_deref());
    config.loaded_config_path = config_override
        .clone()
        .or_else(|| Some(config_path.clone()));

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
            } else if plain {
                println!("=== NAILS Status Report ===");
                println!();
                println!("State:              UNKNOWN");
                println!("Security Posture:   {}", posture.to_plain());
                println!();
                println!("Error: {}", error_msg);
                println!();
                println!("Run status with sufficient privileges or fix state file access");
            } else {
                println!("╭─────────────────────────────────────╮");
                println!("│  NAILS Status Report                │");
                println!("╰─────────────────────────────────────╯");
                println!();
                println!("State:              UNKNOWN");
                println!("Security Posture:   {}", posture);
                println!();
                println!("Error: {}", error_msg);
                println!();
                println!("Run status with sufficient privileges or fix state file access");
            }
            let _ = std::io::stdout().flush();
            std::process::exit(0); // FR63: Always exit 0
        }
    };

    // Format output based on flags
    if json {
        output::print_status_json(&report);
    } else if plain {
        output::print_status_ascii(
            &report,
            verbose,
            &config_path,
            &state_path,
            &hidden_volume_root,
            &log_path,
        );
    } else {
        output::print_status_human(
            &report,
            verbose,
            &config_path,
            &state_path,
            &hidden_volume_root,
            &log_path,
        );
    }

    // FR63: Status always succeeds (exit code 0)
    let _ = std::io::stdout().flush();
    std::process::exit(0);
}

#[cfg(test)]
#[path = "status_tests.rs"]
mod tests;
