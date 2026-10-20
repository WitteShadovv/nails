// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Verify command handler

use crate::cli::args::VerifyArgs;
use crate::cli::output::envelope::{ErrorBody, report_error};
use crate::cli::output::verify::{print_verify_json, verify_exit_status};
use crate::cli::output::{self, ExitStatus, OutputSettings};
use nails_core::app::verify::VerifyOptions;
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
    env: &nails_core::RuntimeEnv,
    args: &VerifyArgs,
    config_override: Option<&Path>,
) -> ExitStatus {
    let json = settings.is_json();

    // Load config fail-closed for malformed or unreadable files; missing config
    // still uses defaults.
    let config = match super::load_config_or_report(config_override, "verify", json) {
        Ok(loaded) => loaded.into_config(),
        Err(status) => return status,
    };

    let options = VerifyOptions {
        deep: args.deep,
        offline: args.offline,
        root: args.root.clone(),
        examiner: args.examiner,
        disk: args.disk.clone(),
    };

    let result = match nails_core::app::verify::verify(env, config, &options) {
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
