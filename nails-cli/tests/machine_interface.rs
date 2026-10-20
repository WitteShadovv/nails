// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Contract tests for the machine-readable (`--json`) interface, version 2.
//!
//! These validate real command output against the canonical JSON Schemas the
//! E2E suite uses (`docs/schemas/*.schema.json`), so a drift in the CLI
//! envelope is caught here long before a VM run. Under version 2 every command
//! prints exactly one envelope line — the root gate, a usage error and `config`
//! included — and `ok` is true only when the exit code is 0 or 9. A small
//! dependency-free checker covers the JSON Schema subset the fixtures use
//! (`type` as a string or an array, `required`, `properties`, `items`, `enum`
//! including `null`, `const`, `oneOf`, `additionalProperties:false`, `minimum`,
//! `minLength`, and the single `^/` `pattern`).

use std::io::Write;
use std::path::PathBuf;

use serde_json::Value;

fn schema_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/schemas")
        .join(format!("{name}.schema.json"))
}

fn load_schema(name: &str) -> Value {
    let text = std::fs::read_to_string(schema_path(name))
        .unwrap_or_else(|e| panic!("read schema {name}: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse schema {name}: {e}"))
}

/// Validate `instance` against the JSON Schema subset in `schema`.
fn validate(schema: &Value, instance: &Value, path: &str) -> Result<(), String> {
    if let Some(expected) = schema.get("const")
        && expected != instance
    {
        return Err(format!("{path}: expected const {expected}, got {instance}"));
    }

    if let Some(Value::Array(choices)) = schema.get("enum")
        && !choices.contains(instance)
    {
        return Err(format!("{path}: {instance} not in enum {choices:?}"));
    }

    if let Some(Value::Array(subschemas)) = schema.get("oneOf") {
        let matches = subschemas
            .iter()
            .filter(|sub| validate(sub, instance, path).is_ok())
            .count();
        if matches != 1 {
            return Err(format!(
                "{path}: matched {matches} oneOf branches, expected 1"
            ));
        }
        return Ok(());
    }

    match schema.get("type") {
        Some(Value::String(ty)) => check_type(ty, instance, path)?,
        // An array of types accepts the instance when it matches any of them.
        Some(Value::Array(types)) => {
            let ok = types
                .iter()
                .filter_map(Value::as_str)
                .any(|ty| check_type(ty, instance, path).is_ok());
            if !ok {
                return Err(format!("{path}: {instance} matches none of {types:?}"));
            }
        }
        _ => {}
    }

    match instance {
        Value::Object(map) => {
            if let Some(Value::Array(required)) = schema.get("required") {
                for key in required {
                    let key = key.as_str().unwrap_or_default();
                    if !map.contains_key(key) {
                        return Err(format!("{path}: missing required key `{key}`"));
                    }
                }
            }
            let properties = schema.get("properties").and_then(Value::as_object);
            if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                for key in map.keys() {
                    let known = properties.is_some_and(|p| p.contains_key(key));
                    if !known {
                        return Err(format!("{path}: unexpected key `{key}`"));
                    }
                }
            }
            if let Some(properties) = properties {
                for (key, value) in map {
                    if let Some(subschema) = properties.get(key) {
                        validate(subschema, value, &format!("{path}.{key}"))?;
                    }
                }
            }
        }
        Value::Array(items) => {
            if let Some(subschema) = schema.get("items") {
                for (i, item) in items.iter().enumerate() {
                    validate(subschema, item, &format!("{path}[{i}]"))?;
                }
            }
        }
        Value::String(s) => {
            if let Some(min) = schema.get("minLength").and_then(Value::as_u64)
                && (s.len() as u64) < min
            {
                return Err(format!("{path}: string shorter than minLength {min}"));
            }
            if let Some(Value::String(pattern)) = schema.get("pattern")
                && let Some(prefix) = pattern.strip_prefix('^')
                && !prefix.chars().any(|c| "\\.[]()*+?{}|$".contains(c))
                && !s.starts_with(prefix)
            {
                return Err(format!("{path}: {s:?} does not match pattern {pattern}"));
            }
        }
        Value::Number(n) => {
            if let Some(min) = schema.get("minimum").and_then(Value::as_f64)
                && n.as_f64().unwrap_or(f64::MIN) < min
            {
                return Err(format!("{path}: {n} below minimum {min}"));
            }
        }
        _ => {}
    }

    Ok(())
}

fn check_type(ty: &str, instance: &Value, path: &str) -> Result<(), String> {
    let ok = match ty {
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "string" => instance.is_string(),
        "boolean" => instance.is_boolean(),
        "integer" => instance.is_i64() || instance.is_u64(),
        "number" => instance.is_number(),
        "null" => instance.is_null(),
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        Err(format!("{path}: expected type {ty}, got {instance}"))
    }
}

/// Validate `value` against the named schema, panicking with the reason.
fn assert_valid(name: &str, value: &Value) {
    validate(&load_schema(name), value, name).unwrap_or_else(|e| panic!("{e}\n{value}"));
}

fn isolated_config() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let hidden_root = dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();
    let config_path = dir.path().join("nails.toml");
    let mut file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        file,
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"",
        hidden_root.display(),
        hidden_root.join("state.json").display(),
    )
    .unwrap();
    (dir, config_path)
}

/// Run `nails <args> --json` with the given config, and return (exit code, the
/// single parsed envelope). Every command prints exactly one document.
fn run_json(config: &std::path::Path, args: &[&str]) -> (i32, Value) {
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .arg("--no-log-file")
        .arg("--config")
        .arg(config)
        .args(args)
        .arg("--json")
        .output()
        .expect("failed to run nails");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.trim();
    let value: Value = serde_json::from_str(line)
        .unwrap_or_else(|e| panic!("stdout is not one JSON document ({e}): {stdout}"));
    (output.status.code().unwrap_or(-1), value)
}

#[test]
fn every_envelope_is_version_two() {
    let (_dir, config) = isolated_config();
    for args in [vec!["status"], vec!["verify"], vec!["config", "path"]] {
        let (_code, value) = run_json(&config, &args);
        assert_eq!(value["schema_version"], 2, "{value}");
    }
}

#[test]
fn status_json_matches_the_schema_with_place_and_attention() {
    let (_dir, config) = isolated_config();
    let (code, value) = run_json(&config, &["status"]);

    assert_eq!(code, 0, "status on a clean decoy exits 0: {value}");
    assert_valid("status", &value);
    assert_eq!(value["command"], "status");
    assert_eq!(value["ok"], true);
    // The version-1 posture/session/state/state_source are gone.
    assert_eq!(value["data"]["place"], "decoy", "{value}");
    assert!(value["data"]["attention"].is_null(), "{value}");
    assert!(value["data"].get("posture").is_none(), "{value}");
    assert!(value["data"].get("session").is_none(), "{value}");
    assert!(value["data"].get("state").is_none(), "{value}");
    assert!(value["data"].get("state_source").is_none(), "{value}");
}

#[test]
fn verify_json_matches_the_schema() {
    let (_dir, config) = isolated_config();
    let (code, value) = run_json(&config, &["verify"]);

    // Secure => 0, warning => 10, critical => 11, run error => 1.
    assert!(matches!(code, 0 | 1 | 10 | 11), "verify exit {code}: {value}");
    assert_valid("verify", &value);
    assert_eq!(value["command"], "verify");
    // ok is true only for a secure scan (exit 0); 10 and 11 are not ok.
    assert_eq!(value["ok"], code == 0, "{value}");
}

#[test]
fn config_path_is_one_envelope() {
    let (_dir, config) = isolated_config();
    let (code, value) = run_json(&config, &["config", "path"]);

    assert_eq!(code, 0);
    assert_valid("config", &value);
    assert_eq!(value["command"], "config");
    assert_eq!(value["ok"], true);
    assert!(value["data"].get("path").is_some(), "{value}");
}

#[test]
fn a_config_load_failure_is_one_error_envelope_on_stdout() {
    // A missing explicit config is a pre-dispatch failure; under --json it is
    // one error envelope on stdout, not plain text on stderr.
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.toml");
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .arg("--no-log-file")
        .arg("--config")
        .arg(&missing)
        .args(["status", "--json"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("config failure must be one JSON doc on stdout ({e}): {stdout}")
    });
    assert_valid("status", &value);
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["command"], "status");
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "config");
    // The error body carries a typed next step field, null here.
    assert!(value["error"]["next"].is_null(), "{value}");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("config file not found"),
        "{value}"
    );
}

#[test]
fn activate_json_is_one_envelope_not_a_stream() {
    // Off a terminal without -y, activate refuses at the confirmation gate
    // before staging anything: one envelope on stdout, never a line stream.
    let dir = tempfile::tempdir().unwrap();
    let hidden_root = dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();
    let config_path = dir.path().join("nails.toml");
    let mut file = std::fs::File::create(&config_path).unwrap();
    writeln!(file, "hidden_volume_root = \"{}\"", hidden_root.display()).unwrap();

    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .arg("--no-log-file")
        .arg("--config")
        .arg(&config_path)
        .args(["activate", "--no-preflight", "--json"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.trim().lines().count(),
        1,
        "exactly one envelope line: {stdout}"
    );
    let value: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("activate --json must be one JSON doc ({e}): {stdout}"));
    assert_valid("activate", &value);
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["command"], "activate");
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "needs_confirmation");
}

#[test]
fn a_usage_error_is_one_error_envelope_on_stdout() {
    // An unknown flag for a known command is a usage error; under --json it is
    // one error envelope naming that command, on stdout, with exit 2.
    let (_dir, config) = isolated_config();
    let (code, value) = run_json(&config, &["status", "--not-a-real-flag"]);

    assert_eq!(code, 2, "a usage error exits 2: {value}");
    assert_valid("status", &value);
    assert_eq!(value["command"], "status");
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "usage");
}

#[test]
fn the_root_gate_is_one_error_envelope_on_stdout() {
    // The integration binary carries `test-hooks`, so the root gate is off by
    // default; NAILS_TEST_ENFORCE_ROOT turns it on. The sandbox runs
    // unprivileged, so a privileged command under --json prints one needs_root
    // envelope on stdout and exits 5 before touching anything.
    let (_dir, config) = isolated_config();
    let output = std::process::Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .arg("--no-log-file")
        .arg("--config")
        .arg(&config)
        .env("NAILS_TEST_ENFORCE_ROOT", "1")
        .args(["activate", "--json"])
        .output()
        .expect("run activate --json unprivileged");

    assert_eq!(output.status.code(), Some(5), "needs root => exit 5");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("root gate must be one JSON doc on stdout ({e}): {stdout}"));
    assert_valid("activate", &value);
    assert_eq!(value["command"], "activate");
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "needs_root");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("must run as root"),
        "{value}"
    );
}
