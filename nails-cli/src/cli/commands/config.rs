// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Config command handler
//!
//! `nails config path|show|validate` inspects the configuration file. Every
//! subcommand is read-only: nothing is mounted, written or logged to the
//! hidden volume beyond what any command's logging setup does. Under `--json`
//! each subcommand prints exactly one version-2 envelope line on stdout, errors
//! included.

use std::path::Path;

use nails_core::{CliOverrides, Config, LoadedConfig, NailsError};
use serde::Serialize;
use serde_json::json;

use super::{config_error_line, config_read_hint};
use crate::cli::args::ConfigCommand;
use crate::cli::output::envelope::{Envelope, ErrorBody, error_envelope};
use crate::cli::output::{ExitStatus, OutputSettings};

/// Exit code for a command-line usage error.
const EXIT_USAGE: i32 = 2;

/// Exit code for a configuration file that is missing (when required),
/// unreadable or invalid.
const EXIT_CONFIG_ERROR: i32 = 3;

/// What a config subcommand prints and how it exits.
#[derive(Debug, Default, PartialEq, Eq)]
struct Outcome {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Outcome {
    fn ok(stdout: String) -> Self {
        Self {
            stdout,
            ..Self::default()
        }
    }

    fn config_error(line: &str) -> Self {
        Self {
            code: EXIT_CONFIG_ERROR,
            stderr: format!("error: {line}\n"),
            ..Self::default()
        }
    }

    /// A configuration that could not be loaded for `command`: the error line
    /// and, when the read was refused for lack of permission, the `sudo` line.
    fn load_error(error: &NailsError, command: &str) -> Self {
        let mut outcome = Self::config_error(&config_error_line(error));
        if let Some(hint) = config_read_hint(error, command) {
            outcome.stderr.push_str(&format!("  {hint}\n"));
        }
        outcome
    }
}

/// One envelope line on stdout carrying `data`.
fn envelope_line<T: Serialize>(data: T) -> String {
    format!("{}\n", Envelope::success("config", data).to_line())
}

/// A configuration load failure for `command`, as one error envelope line on
/// stdout: the error line, with the `sudo` line folded in when the read was
/// refused for lack of permission.
fn json_load_error(error: &NailsError, command: &str, code: i32) -> Outcome {
    let mut body = ErrorBody::new("config", config_error_line(error));
    if let Some(hint) = config_read_hint(error, command) {
        body = body.with_hint(hint);
    }
    Outcome {
        code,
        stdout: format!("{}\n", error_envelope("config", body).to_line()),
        stderr: String::new(),
    }
}

/// Execute a `nails config` subcommand.
///
/// Returns [`ExitStatus::Ok`] on success, [`ExitStatus::Usage`] for
/// `show --example --json`, and [`ExitStatus::Config`] when the configuration
/// file is missing (where one is required), unreadable or invalid.
pub fn execute(
    settings: &OutputSettings,
    config_override: Option<&Path>,
    command: &ConfigCommand,
) -> ExitStatus {
    let outcome = run(config_override, command, settings.is_json());
    crate::cli::output::print_tolerating_broken_pipe(&outcome.stdout);
    crate::cli::output::eprint_tolerating_broken_pipe(&outcome.stderr);
    match outcome.code {
        0 => ExitStatus::Ok,
        EXIT_USAGE => ExitStatus::Usage,
        _ => ExitStatus::Config,
    }
}

fn run(config_override: Option<&Path>, command: &ConfigCommand, json: bool) -> Outcome {
    match command {
        ConfigCommand::Path => path(config_override, json),
        ConfigCommand::Show { example: true, .. } if json => Outcome {
            code: EXIT_USAGE,
            stdout: format!(
                "{}\n",
                error_envelope(
                    "config",
                    ErrorBody::new(
                        "usage",
                        "--example prints commented TOML and cannot be combined with --json",
                    ),
                )
                .to_line()
            ),
            stderr: String::new(),
        },
        ConfigCommand::Show { example: true, .. } => Outcome::ok(Config::example_config()),
        ConfigCommand::Show { nixos_flake, .. } => {
            let overrides = CliOverrides {
                nixos_flake: nixos_flake.clone(),
            };
            show(config_override, json, &overrides)
        }
        ConfigCommand::Validate { path } => validate(config_override, path.as_deref(), json),
    }
}

fn path(config_override: Option<&Path>, json: bool) -> Outcome {
    let path = nails_core::config::discover_config_path(config_override);
    let exists = path.is_file();

    if json {
        return Outcome::ok(envelope_line(json!({ "path": path, "exists": exists })));
    }

    let status = match (exists, config_override.is_some()) {
        (true, _) => "exists",
        (false, true) => "not found",
        (false, false) => "not found, using defaults",
    };
    Outcome::ok(format!("{} ({status})\n", path.display()))
}

fn show(config_override: Option<&Path>, json: bool, overrides: &CliOverrides) -> Outcome {
    let loaded = match nails_core::app::config_view(config_override, overrides) {
        Ok(loaded) => loaded,
        Err(error) if json => return json_load_error(&error, "config show", EXIT_CONFIG_ERROR),
        Err(error) => return Outcome::load_error(&error, "config show"),
    };

    if json {
        return match loaded.to_json() {
            Ok(value) => Outcome::ok(envelope_line(value)),
            Err(error) => json_load_error(&error, "config show", EXIT_CONFIG_ERROR),
        };
    }

    match loaded.to_annotated_toml() {
        Ok(text) => Outcome::ok(text),
        Err(error) => Outcome::config_error(&config_error_line(&error)),
    }
}

fn validate(config_override: Option<&Path>, explicit: Option<&Path>, json: bool) -> Outcome {
    // A file to validate is always required, so a missing file is reported
    // even when it is the implicitly discovered one.
    let path = explicit
        .map(Path::to_path_buf)
        .unwrap_or_else(|| nails_core::config::discover_config_path(config_override));

    let command = match explicit {
        Some(file) => format!("config validate {}", file.display()),
        None => "config validate".to_string(),
    };
    match LoadedConfig::load(&path) {
        Ok(_) if json => Outcome::ok(envelope_line(json!({ "path": path, "valid": true }))),
        Ok(_) => Outcome::ok(format!("{}: valid\n", path.display())),
        Err(error) if json => json_load_error(&error, &command, EXIT_CONFIG_ERROR),
        Err(error) => Outcome::load_error(&error, &command),
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
