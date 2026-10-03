//! Contract tests for the machine-readable (`--json`) interface.
//!
//! These validate real command output against the canonical JSON Schemas the E2E
//! suite uses (`docs/schemas/*.schema.json`), so a drift in the CLI
//! envelope is caught here long before a VM run. A small dependency-free checker
//! covers the JSON Schema subset the fixtures use (`type`, `required`,
//! `properties`, `items`, `enum`, `const`, `oneOf`, `additionalProperties:false`,
//! `minimum`, `minLength`, and the single `^/` `pattern`).

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

    if let Some(Value::String(ty)) = schema.get("type") {
        check_type(ty, instance, path)?;
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

fn isolated_config() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let hidden_root = dir.path().join("hidden-volume");
    std::fs::create_dir_all(&hidden_root).unwrap();
    let config_path = dir.path().join("nails.toml");
    let mut file = std::fs::File::create(&config_path).unwrap();
    writeln!(
        file,
        "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\noverlays = []",
        hidden_root.display(),
        hidden_root.join("state.json").display(),
    )
    .unwrap();
    (dir, config_path)
}

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
    // Activate streams NDJSON; every other command prints exactly one document.
    let last = stdout.trim().lines().next_back().unwrap_or("");
    let value: Value = serde_json::from_str(last)
        .unwrap_or_else(|e| panic!("stdout is not one JSON document ({e}): {stdout}"));
    (output.status.code().unwrap_or(-1), value)
}

#[test]
fn status_json_matches_the_fixture_schema() {
    let schema = load_schema("status");
    let (_dir, config) = isolated_config();
    let (code, value) = run_json(&config, &["status"]);

    assert_eq!(code, 0, "status always exits 0: {value}");
    validate(&schema, &value, "status").unwrap_or_else(|e| panic!("{e}\n{value}"));

    // The specific contract the ticket pins: state is a tagged object.
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "status");
    assert_eq!(value["data"]["state"]["kind"], "inactive", "{value}");
    assert!(value["data"]["state"].as_object().is_some(), "{value}");
}

#[test]
fn verify_json_matches_the_fixture_schema() {
    let schema = load_schema("verify");
    let (_dir, config) = isolated_config();
    let (code, value) = run_json(&config, &["verify"]);

    // Secure => 0, warning => 10, critical => 11, run error => 1 (error envelope).
    assert!(
        matches!(code, 0 | 1 | 10 | 11),
        "unexpected verify exit {code}: {value}"
    );
    validate(&schema, &value, "verify").unwrap_or_else(|e| panic!("{e}\n{value}"));
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "verify");
}

#[test]
fn a_config_load_failure_is_one_enveloped_document_on_stdout() {
    // A missing explicit config is a pre-dispatch failure; under --json it is one
    // error envelope on stdout, not plain text on stderr.
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
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "status");
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "config");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("config file not found"),
        "{value}"
    );
}

#[test]
fn activate_json_streams_ndjson_ending_in_a_result_event() {
    // Off a terminal without -y, activate refuses at the confirmation gate before
    // staging anything, which is one envelope on stdout; use it to confirm the
    // --json refusal is a single JSON document, not a stream.
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
        .args(["activate", "--session", "keep", "--no-preflight", "--json"])
        .output()
        .unwrap();

    // The confirmation gate refuses with code 2 and one envelope on stdout.
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("activate --json refusal must be one JSON doc ({e}): {stdout}"));
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "activate");
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "needs_confirmation");
}
