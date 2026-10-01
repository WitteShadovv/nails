//! Verify command handler

use crate::cli::args::VerifyArgs;
use crate::cli::output::dto::system_state_kind;
use crate::cli::output::envelope::{ErrorBody, report_error};
use crate::cli::output::verify::{print_verify_json, verify_exit_status};
use crate::cli::output::{self, ExitStatus, OutputSettings};
use std::io::Write;
use std::path::Path;

/// Execute the verify command.
///
/// Verifies that the system is clean of NAILS artifacts, using the resolved CLI
/// config (or defaults when no config file exists) for config-aware checks.
///
/// # Arguments
///
/// * `settings` - Output settings resolved once from the global flags
/// * `args` - The `verify` arguments (`--deep`)
/// * `config_override` - Optional config file path override
///
/// # Returns
///
/// - [`ExitStatus::Ok`] when the system is secure
/// - [`ExitStatus::VerifyWarning`] / [`ExitStatus::VerifyCritical`] for findings
/// - [`ExitStatus::Config`] when the config file could not be loaded
/// - [`ExitStatus::Failed`] when the verification itself could not run
pub fn execute(
    settings: &OutputSettings,
    args: &VerifyArgs,
    config_override: Option<&Path>,
) -> ExitStatus {
    use nails_core::{RealFilesystem, StateFile, StateFileStatus, Verifier};

    let json = settings.is_json();
    let filesystem = RealFilesystem;

    // Load config fail-closed for malformed or unreadable files; missing config
    // still uses defaults.
    let config = match super::load_config_or_report(config_override, "verify", json) {
        Ok(loaded) => loaded.into_config(),
        Err(status) => return status,
    };

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
                let state_name = system_state_kind(&loaded_state.state).to_string();
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

    let result = match verifier.run(args.deep) {
        Ok(result) => result,
        Err(e) => {
            return report_error(
                json,
                "verify",
                ExitStatus::Failed,
                ErrorBody::new("verify_error", format!("Error running verification: {e}")),
            );
        }
    };

    if json {
        print_verify_json(&result);
    } else {
        output::print_verify_result(&result, settings.stdout_style());
    }

    let _ = std::io::stdout().flush();
    verify_exit_status(result.status)
}
