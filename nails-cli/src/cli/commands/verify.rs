//! Verify command handler

use crate::cli::args::VerifyArgs;
use crate::cli::output::{self, OutputSettings};
use std::io::Write;
use std::path::Path;

/// Execute the verify command
///
/// Verifies that the system is clean of NAILS artifacts.
/// Uses the resolved CLI config (or defaults when no config file exists)
/// to perform config-aware verification of config-specific paths.
///
/// # Arguments
///
/// * `settings` - Output settings resolved once from the global flags
/// * `args` - The `verify` arguments (`--deep`)
/// * `config_override` - Optional config file path override
///
/// # Returns
///
/// Never returns - exits with appropriate exit code:
/// - 0: System is secure
/// - 1: Warning or critical issues found
/// - 2: Error running verification
pub fn execute(settings: &OutputSettings, args: &VerifyArgs, config_override: Option<&Path>) -> ! {
    use nails_core::{RealFilesystem, StateFile, StateFileStatus, Verifier};

    // Create verifier with real filesystem
    let filesystem = RealFilesystem;

    // Load config fail-closed for malformed or unreadable files; missing config still uses defaults.
    let config = super::load_config_or_exit(config_override).into_config();

    // Load state file status explicitly for verify reporting.
    let state_path = config.state_file_path.clone();
    let (state, state_file_status) = if !state_path.exists() {
        (
            None,
            StateFileStatus::Missing {
                path: state_path.clone(),
            },
        )
    } else {
        match StateFile::load(&state_path) {
            Ok(loaded_state) => {
                let state_name = format!("{:?}", loaded_state.state).to_uppercase();
                (
                    Some(loaded_state),
                    StateFileStatus::Present {
                        path: state_path.clone(),
                        state: state_name,
                    },
                )
            }
            Err(error) => (
                None,
                StateFileStatus::Error {
                    path: state_path.clone(),
                    message: error.to_string(),
                },
            ),
        }
    };

    let verifier = Verifier::with_config(filesystem, config, state, state_file_status);

    // Run verification
    let result = match verifier.run(args.deep) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error running verification: {}", e);
            std::process::exit(2); // Exit code 2 for verify command errors
        }
    };

    // Output results
    if settings.is_json() {
        // JSON output
        let json_output =
            serde_json::to_string_pretty(&result).expect("Failed to serialize verification result");
        println!("{}", json_output);
    } else {
        // Human-readable output
        output::print_verify_result(&result, settings.stdout_style());
    }

    // Set exit code based on status
    let _ = std::io::stdout().flush();
    match result.status {
        nails_core::VerifyStatus::Secure => std::process::exit(0),
        nails_core::VerifyStatus::Warning | nails_core::VerifyStatus::Critical => {
            std::process::exit(1)
        }
    }
}
