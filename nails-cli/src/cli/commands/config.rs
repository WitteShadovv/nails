//! Config command handler
//!
//! `nails config path|show|validate` inspects the configuration file. Every
//! subcommand is read-only: nothing is mounted, written or logged to the
//! hidden volume beyond what any command's logging setup does.

use std::path::Path;

use nails_core::{CliOverrides, Config, LoadedConfig};
use serde_json::json;

use super::{EXIT_CONFIG_ERROR, config_error_line, resolve_config};
use crate::cli::args::ConfigCommand;
use crate::cli::output::OutputSettings;

/// Exit code for a command-line usage error.
const EXIT_USAGE: i32 = 2;

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
            stderr: format!("Error: {line}\n"),
            ..Self::default()
        }
    }
}

/// Execute a `nails config` subcommand
///
/// Never returns: exits 0 on success, 2 for `show --example --json`, and 3
/// when the configuration file is missing (where one is required), unreadable
/// or invalid.
pub fn execute(
    settings: &OutputSettings,
    config_override: Option<&Path>,
    command: &ConfigCommand,
) -> ! {
    let outcome = run(config_override, command, settings.is_json());
    print!("{}", outcome.stdout);
    eprint!("{}", outcome.stderr);
    std::process::exit(outcome.code);
}

fn run(config_override: Option<&Path>, command: &ConfigCommand, json: bool) -> Outcome {
    match command {
        ConfigCommand::Path => path(config_override, json),
        ConfigCommand::Show { example: true, .. } if json => Outcome {
            code: EXIT_USAGE,
            stderr: "Error: --example prints commented TOML and cannot be combined with --json\n"
                .to_string(),
            ..Outcome::default()
        },
        ConfigCommand::Show { example: true, .. } => Outcome::ok(Config::example_config()),
        ConfigCommand::Show {
            nixos_flake,
            no_clear_history,
            ..
        } => {
            let overrides = CliOverrides {
                clear_history: no_clear_history.then_some(false),
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
        return Outcome::ok(format!("{}\n", json!({ "path": path, "exists": exists })));
    }

    let status = match (exists, config_override.is_some()) {
        (true, _) => "exists",
        (false, true) => "not found",
        (false, false) => "not found, using defaults",
    };
    Outcome::ok(format!("{} ({status})\n", path.display()))
}

fn show(config_override: Option<&Path>, json: bool, overrides: &CliOverrides) -> Outcome {
    let mut loaded = match resolve_config(config_override) {
        Ok(loaded) => loaded,
        Err(error) => return Outcome::config_error(&config_error_line(&error)),
    };
    loaded.apply_cli_overrides(overrides);

    let rendered = if json {
        loaded.to_json().and_then(|value| {
            serde_json::to_string_pretty(&value)
                .map(|text| text + "\n")
                .map_err(|e| nails_core::NailsError::ConfigError(e.to_string()))
        })
    } else {
        loaded.to_annotated_toml()
    };

    match rendered {
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

    match LoadedConfig::load(&path) {
        Ok(_) if json => Outcome::ok(format!("{}\n", json!({ "path": path, "valid": true }))),
        Ok(_) => Outcome::ok(format!("{}: valid\n", path.display())),
        Err(error) => {
            let line = config_error_line(&error);
            if json {
                Outcome {
                    code: EXIT_CONFIG_ERROR,
                    stdout: format!(
                        "{}\n",
                        json!({ "path": path, "valid": false, "error": line })
                    ),
                    stderr: String::new(),
                }
            } else {
                Outcome::config_error(&line)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_config(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file
    }

    fn show_command() -> ConfigCommand {
        ConfigCommand::Show {
            example: false,
            nixos_flake: None,
            no_clear_history: false,
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
        let value: serde_json::Value = serde_json::from_str(&outcome.stdout).unwrap();

        assert_eq!(outcome.code, 0);
        assert!(
            value["path"]
                .as_str()
                .unwrap()
                .ends_with("config/nails.toml")
        );
        assert_eq!(value["exists"], false);
    }

    #[test]
    fn show_renders_annotated_toml() {
        let file = write_config("minimum_space_mb = 750\n");
        let outcome = run(Some(file.path()), &show_command(), false);

        assert_eq!(outcome.code, 0, "{outcome:?}");
        assert!(outcome.stdout.contains("minimum_space_mb = 750  # file"));
        assert!(outcome.stdout.contains("clear_history = true  # default"));
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
                no_clear_history: true,
            },
            true,
        );
        let value: serde_json::Value = serde_json::from_str(&outcome.stdout).unwrap();

        assert_eq!(value["config"]["nixos_flake"], "/c#d");
        assert_eq!(value["sources"]["nixos_flake"], "cli");
        assert_eq!(value["config"]["clear_history"], false);
        assert_eq!(value["sources"]["clear_history"], "cli");
        assert_eq!(value["sources"]["minimum_space_mb"], "default");
        assert_eq!(value["exists"], true);
    }

    #[test]
    fn show_example_prints_the_example() {
        let outcome = run(
            None,
            &ConfigCommand::Show {
                example: true,
                nixos_flake: None,
                no_clear_history: false,
            },
            false,
        );

        assert_eq!(outcome.code, 0);
        assert_eq!(outcome.stdout, Config::example_config());
    }

    #[test]
    fn show_rejects_invalid_config() {
        let file = write_config("[color_scheme]\nenable = true\n");
        let outcome = run(Some(file.path()), &show_command(), false);

        assert_eq!(outcome.code, EXIT_CONFIG_ERROR);
        assert!(outcome.stdout.is_empty());
        assert!(outcome.stderr.contains("did you mean `enabled`?"));
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
        assert!(outcome.stderr.starts_with("Error: invalid config "));
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
        let value: serde_json::Value = serde_json::from_str(&outcome.stdout).unwrap();

        assert_eq!(outcome.code, EXIT_CONFIG_ERROR);
        assert_eq!(value["valid"], false);
        assert!(
            value["error"]
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
        let value: serde_json::Value = serde_json::from_str(&outcome.stdout).unwrap();
        assert_eq!(outcome.code, 0);
        assert_eq!(value["valid"], true);
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
                "Error: config file not found: {} (run `nails init <root>` or pass --config)\n",
                missing.display()
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
                no_clear_history: false,
            },
            true,
        );

        assert_eq!(outcome.code, EXIT_USAGE);
        assert!(outcome.stdout.is_empty());
        assert!(outcome.stderr.contains("--example"), "{outcome:?}");
    }
}
