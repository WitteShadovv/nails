// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Check command handler.
//!
//! A strictly read-only readiness check. It loads the configuration, then calls
//! the [`readiness`](nails_core::app::readiness) operation, which builds the same
//! pre-flight registry activation would run, runs it without staging or mutating
//! anything, and gathers the effective configuration, the overlay targets, how
//! the session would be handled and which NixOS profile would be built.
//! `activate --dry-run` is a thin alias for this command, so the two always agree.
//!
//! A root the attach gate refuses is reported first, on stderr and in the words
//! `init` and `activate` use, then the readiness report follows; under `--json`
//! the refusal is the report's `refusal`.

use std::io::Write;
use std::path::Path;

use nails_core::{CliOverrides, PreflightOptions};

use crate::cli::args::CheckArgs;
use crate::cli::output::check::{print_check_human, print_check_json};
use crate::cli::output::envelope::{ErrorBody, report_error, write_human_error};
use crate::cli::output::{ExitStatus, OutputSettings};

/// The command name used in the JSON envelope and error reports.
const COMMAND: &str = "check";

/// Execute the `check` command.
///
/// Returns [`ExitStatus::Ok`] when every check passed (warnings allowed),
/// [`ExitStatus::PreflightRefused`] when any check failed,
/// [`ExitStatus::Config`] when the configuration file could not be loaded, and
/// [`ExitStatus::Failed`] when the checks could not be assembled.
pub fn execute(
    settings: &OutputSettings,
    env: &nails_core::RuntimeEnv,
    args: &CheckArgs,
    config_override: Option<&Path>,
) -> ExitStatus {
    let json = settings.is_json();

    let mut loaded = match super::load_config_or_report(config_override, COMMAND, json) {
        Ok(loaded) => loaded,
        Err(status) => return status,
    };
    loaded.apply_cli_overrides(&CliOverrides {
        nixos_flake: args.nixos_flake.clone(),
    });

    let config_path = loaded.path.clone();
    let config = loaded.into_config();
    let options = preflight_options(args);

    let report = match nails_core::app::readiness::readiness(env, &config_path, config, &options) {
        Ok(report) => report,
        Err(e) => {
            return report_error(
                json,
                COMMAND,
                ExitStatus::Failed,
                ErrorBody::new("check_error", format!("could not assemble checks: {e}")),
            );
        }
    };

    // The human surface prints the attach-gate refusal first, on stderr and in
    // the words `init` and `activate` use; under `--json` it is the report's
    // `refusal` field.
    if let Some(error) = report.refusal.as_ref().filter(|_| !json) {
        write_human_error(&mut std::io::stderr().lock(), error);
    }

    if json {
        print_check_json(&report);
    } else {
        print_check_human(&report, settings.stdout_style());
    }
    let _ = std::io::stdout().flush();

    if report.ready {
        ExitStatus::Ok
    } else {
        ExitStatus::PreflightRefused
    }
}

/// The pre-flight options of `check`: what activation builds from the same
/// flags (`EnterOptions::preflight`), so both run the same checks.
pub(super) fn preflight_options(args: &CheckArgs) -> PreflightOptions {
    PreflightOptions {
        overlay_only: args.overlay_only,
        allow_persistent_decoy: args.allow_persistent_decoy,
        allow_decoy_storage: args.allow_decoy_storage,
        allow_discards: args.allow_discards,
        ..PreflightOptions::default()
    }
}
