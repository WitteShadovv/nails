// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the `config` command handler.

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
            "error: config file not found: {} (run `nails init <root>` or pass --config)\n",
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
