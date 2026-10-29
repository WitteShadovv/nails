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
    if settings.is_json() {
        // Under --json the whole of stdout is the one envelope line.
        crate::cli::output::envelope::print_envelope_line(outcome.stdout.trim_end());
    } else {
        crate::cli::output::print_tolerating_broken_pipe(&outcome.stdout);
    }
    crate::cli::output::eprint_tolerating_broken_pipe(&outcome.stderr);
    exit_status(outcome.code)
}

/// The exit status and the one envelope a `nails config` subcommand gives
/// under `--json`, without printing them: what the window's helper answers
/// with.
pub(crate) fn json_outcome(
    config_override: Option<&Path>,
    command: &ConfigCommand,
) -> (ExitStatus, serde_json::Value) {
    let outcome = run(config_override, command, true);
    let envelope = serde_json::from_str(outcome.stdout.trim_end())
        .expect("every config subcommand prints one envelope under --json");
    (exit_status(outcome.code), envelope)
}

fn exit_status(code: i32) -> ExitStatus {
    match code {
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
        return Outcome::ok(envelope_line(
            json!({ "path": path.display().to_string(), "exists": exists }),
        ));
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
        Ok(_) if json => Outcome::ok(envelope_line(
            json!({ "path": path.display().to_string(), "valid": true }),
        )),
        Ok(_) => Outcome::ok(format!("{}: valid\n", path.display())),
        Err(error) if json => json_load_error(&error, &command, EXIT_CONFIG_ERROR),
        Err(error) => Outcome::load_error(&error, &command),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// The `data` payload of a one-line config envelope, with the shape asserted.
    fn envelope_data(stdout: &str) -> serde_json::Value {
        let value: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
        assert_eq!(value["schema_version"], 2, "{value}");
        assert_eq!(value["command"], "config", "{value}");
        assert_eq!(value["ok"], true, "{value}");
        value["data"].clone()
    }

    fn write_config(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file
    }

    fn show_command() -> ConfigCommand {
        ConfigCommand::Show {
            example: false,
            nixos_flake: None,
        }
    }

    #[test]
    fn path_reports_existing_explicit_file() {
        let file = write_config("");
        let outcome = run(Some(file.path()), &ConfigCommand::Path, false);

        assert_eq!(outcome.code, 0);
        assert_eq!(
            outcome.stdout,
            format!("{} (exists)\n", file.path().display())
        );
    }

    #[test]
    fn path_reports_missing_explicit_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nails.toml");
        let outcome = run(Some(&missing), &ConfigCommand::Path, false);

        assert_eq!(outcome.code, 0);
        assert_eq!(
            outcome.stdout,
            format!("{} (not found)\n", missing.display())
        );
    }

    #[test]
    fn path_defaults_to_binary_relative_toml() {
        let outcome = run(None, &ConfigCommand::Path, true);
        let data = envelope_data(&outcome.stdout);

        assert_eq!(outcome.code, 0);
        assert!(
            data["path"]
                .as_str()
                .unwrap()
                .ends_with("config/nails.toml")
        );
        assert_eq!(data["exists"], false);
    }

    #[test]
    fn show_renders_annotated_toml() {
        let file = write_config("minimum_space_mb = 750\n");
        let outcome = run(Some(file.path()), &show_command(), false);

        assert_eq!(outcome.code, 0, "{outcome:?}");
        assert!(outcome.stdout.contains("minimum_space_mb = 750  # file"));
        assert!(
            outcome
                .stdout
                .contains("show_opsec_reminders = true  # default")
        );
        assert!(outcome.stdout.contains("hidden_volume_root = "));
        assert!(outcome.stdout.contains("# derived"));
    }

    #[test]
    fn show_marks_cli_overrides() {
        let file = write_config("nixos_flake = \"/a#b\"\n");
        let outcome = run(
            Some(file.path()),
            &ConfigCommand::Show {
                example: false,
                nixos_flake: Some("/c#d".to_string()),
            },
            true,
        );
        let data = envelope_data(&outcome.stdout);

        // The config view is the envelope's data; one line, not pretty-printed.
        assert_eq!(outcome.stdout.trim().lines().count(), 1, "{outcome:?}");
        assert_eq!(data["config"]["nixos_flake"], "/c#d");
        assert_eq!(data["sources"]["nixos_flake"], "cli");
        assert_eq!(data["sources"]["minimum_space_mb"], "default");
        assert_eq!(data["exists"], true);
    }

    #[test]
    fn show_example_prints_the_example() {
        let outcome = run(
            None,
            &ConfigCommand::Show {
                example: true,
                nixos_flake: None,
            },
            false,
        );

        assert_eq!(outcome.code, 0);
        assert_eq!(outcome.stdout, Config::example_config());
    }

    #[test]
    fn show_rejects_invalid_config() {
        let file = write_config("[backend_watch]\nenable = true\n");
        let outcome = run(Some(file.path()), &show_command(), false);

        assert_eq!(outcome.code, EXIT_CONFIG_ERROR);
        assert!(outcome.stdout.is_empty());
        assert!(outcome.stderr.contains("did you mean `enabled`?"));
    }

    #[test]
    fn show_json_reports_error_on_stdout() {
        let file = write_config("[backend_watch]\nenable = true\n");
        let outcome = run(Some(file.path()), &show_command(), true);

        assert_eq!(outcome.code, EXIT_CONFIG_ERROR, "{outcome:?}");
        // Under --json the load failure is one error envelope on stdout, with
        // stderr left empty; it is not a plain `error:` line on stderr.
        assert!(outcome.stderr.is_empty(), "{outcome:?}");
        let value: serde_json::Value = serde_json::from_str(outcome.stdout.trim()).unwrap();
        assert_eq!(value["schema_version"], 2);
        assert_eq!(value["command"], "config");
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "config");
        assert!(
            value["error"]["message"]
                .as_str()
                .unwrap()
                .contains("did you mean `enabled`?"),
            "{outcome:?}"
        );
    }

    #[test]
    fn validate_accepts_valid_file() {
        let file = write_config("hidden_volume_root = \"/mnt/hv\"\n");
        let outcome = run(
            None,
            &ConfigCommand::Validate {
                path: Some(file.path().to_path_buf()),
            },
            false,
        );

        assert_eq!(outcome.code, 0);
        assert_eq!(
            outcome.stdout,
            format!("{}: valid\n", file.path().display())
        );
    }

    #[test]
    fn validate_rejects_unknown_key_with_hint() {
        let file = write_config("nixos_flak = \"/a#b\"\n");
        let outcome = run(
            None,
            &ConfigCommand::Validate {
                path: Some(file.path().to_path_buf()),
            },
            false,
        );

        assert_eq!(outcome.code, EXIT_CONFIG_ERROR);
        assert!(outcome.stderr.starts_with("error: invalid config "));
        assert!(outcome.stderr.contains("did you mean `nixos_flake`?"));
        assert_eq!(outcome.stderr.lines().count(), 1);
    }

    #[test]
    fn validate_json_reports_result_on_stdout() {
        let file = write_config("bogus = 1\n");
        let outcome = run(
            None,
            &ConfigCommand::Validate {
                path: Some(file.path().to_path_buf()),
            },
            true,
        );
        let value: serde_json::Value = serde_json::from_str(outcome.stdout.trim()).unwrap();

        assert_eq!(outcome.code, EXIT_CONFIG_ERROR);
        // An invalid file is one error envelope: ok false, the code, the reason.
        assert_eq!(value["schema_version"], 2);
        assert_eq!(value["command"], "config");
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "config");
        assert!(
            value["error"]["message"]
                .as_str()
                .unwrap()
                .contains("unknown key `bogus`")
        );

        let good = write_config("");
        let outcome = run(
            Some(good.path()),
            &ConfigCommand::Validate { path: None },
            true,
        );
        let data = envelope_data(&outcome.stdout);
        assert_eq!(outcome.code, 0);
        assert_eq!(data["valid"], true);
    }

    #[test]
    fn validate_requires_the_file_to_exist() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nails.toml");
        let outcome = run(
            None,
            &ConfigCommand::Validate {
                path: Some(missing.clone()),
            },
            false,
        );

        assert_eq!(outcome.code, EXIT_CONFIG_ERROR);
        assert_eq!(
            outcome.stderr,
            format!(
                "error: config file not found: {} (run `{}` or pass --config)\n",
                missing.display(),
                nails_core::next_step::sudo_line(nails_core::next_step::NextStep::Init)
            )
        );
    }

    #[test]
    fn show_example_refuses_json() {
        let outcome = run(
            None,
            &ConfigCommand::Show {
                example: true,
                nixos_flake: None,
            },
            true,
        );

        assert_eq!(outcome.code, EXIT_USAGE);
        // The refusal is one error envelope on stdout, not a line on stderr.
        assert!(outcome.stderr.is_empty(), "{outcome:?}");
        let value: serde_json::Value = serde_json::from_str(outcome.stdout.trim()).unwrap();
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "usage");
        assert!(
            value["error"]["message"]
                .as_str()
                .unwrap()
                .contains("--example"),
            "{outcome:?}"
        );
    }
}
