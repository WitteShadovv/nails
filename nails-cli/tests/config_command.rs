// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Binary-level tests for `nails config` and strict configuration loading
//!
//! Every command run here is read-only or exits during configuration loading,
//! before any system operation, so none of them touch the host.

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;

fn nails() -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("nails"));
    cmd.arg("--no-log-file");
    cmd
}

fn write_config(contents: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    file
}

/// The `init` line the binary names: `sudo <its own path> init <root>`.
fn init_line() -> String {
    let binary = std::fs::canonicalize(assert_cmd::cargo::cargo_bin!("nails")).unwrap();
    nails_core::next_step::sudo_line_with(&binary, nails_core::next_step::NextStep::Init)
}

fn stdout_json(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("stdout is JSON")
}

#[test]
fn config_path_reports_resolved_file_and_existence() {
    let file = write_config("");
    let path = file.path().to_str().unwrap();

    nails()
        .args(["--config", path, "config", "path"])
        .assert()
        .success()
        .stdout(format!("{path} (exists)\n"));

    let output = nails()
        .args(["--config", path, "config", "path", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value = stdout_json(&output);
    // Version-2 envelope: the subcommand's own fields live under `data`.
    assert_eq!(value["command"], "config");
    assert_eq!(value["data"]["path"], path);
    assert_eq!(value["data"]["exists"], true);
}

#[test]
fn config_path_without_override_is_binary_relative() {
    let output = nails().args(["config", "path", "--json"]).output().unwrap();
    assert!(output.status.success());

    let value = stdout_json(&output);
    let bin = std::fs::canonicalize(assert_cmd::cargo::cargo_bin!("nails")).unwrap();
    let expected = bin.parent().unwrap().join("config").join("nails.toml");
    assert_eq!(value["data"]["path"], expected.to_str().unwrap());
}

#[test]
fn config_show_annotates_sources_in_toml_and_json() {
    let file = write_config("minimum_space_mb = 750\n");
    let path = file.path().to_str().unwrap();

    nails()
        .args([
            "--config",
            path,
            "config",
            "show",
            "--nixos-flake",
            "/mnt/data/nixos#my-host",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("minimum_space_mb = 750  # file"))
        .stdout(predicate::str::contains("# cli"))
        .stdout(predicate::str::contains(
            "show_opsec_reminders = true  # default",
        ))
        .stdout(predicate::str::contains("# derived"));

    let output = nails()
        .args(["--config", path, "config", "show", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let value = stdout_json(&output);
    // The effective configuration is the envelope's `data`.
    assert_eq!(value["data"]["exists"], true);
    assert_eq!(value["data"]["config"]["minimum_space_mb"], 750);
    assert_eq!(value["data"]["sources"]["minimum_space_mb"], "file");
    assert_eq!(value["data"]["sources"]["hidden_volume_root"], "derived");
}

#[test]
fn config_show_example_is_a_valid_config() {
    let output = nails()
        .args(["config", "show", "--example"])
        .output()
        .unwrap();
    assert!(output.status.success());

    let example = write_config(std::str::from_utf8(&output.stdout).unwrap());
    nails()
        .args(["config", "validate", example.path().to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn config_validate_accepts_good_and_rejects_bad_files() {
    let good = write_config("hidden_volume_root = \"/mnt/hv\"\n");
    let good_path = good.path().to_str().unwrap();
    nails()
        .args(["config", "validate", good_path])
        .assert()
        .success()
        .stdout(format!("{good_path}: valid\n"));

    let bad = write_config("[backend_watch]\nenable = false\n");
    nails()
        .args(["config", "validate", bad.path().to_str().unwrap()])
        .assert()
        .code(3)
        .stdout("")
        .stderr(predicate::str::contains("line 2, column 1"))
        .stderr(predicate::str::contains(
            "unknown key `enable` (did you mean `enabled`?)",
        ));

    let output = nails()
        .args(["config", "validate", "--json", bad.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let value = stdout_json(&output);
    // An invalid file is one error envelope: not ok, the config code, the reason.
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "config");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("did you mean")
    );
}

#[test]
fn config_validate_uses_the_resolved_file_by_default() {
    let bad = write_config("nixos_flak = \"/x#y\"\n");
    nails()
        .args([
            "--config",
            bad.path().to_str().unwrap(),
            "config",
            "validate",
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("did you mean `nixos_flake`?"));
}

/// A configuration path that is not valid UTF-8 still gives one envelope per
/// subcommand under `--json`, with the path written lossily, never a panic:
/// `config path`, `config show` and `config validate` on such a file, and
/// `config path` and `config validate` on a missing one.
#[test]
fn a_config_path_that_is_not_utf8_gives_one_envelope() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(OsStr::from_bytes(b"nails-\xff.toml"));
    std::fs::write(&file, "hidden_volume_root = \"/mnt/hv\"\n").unwrap();
    let missing = dir.path().join(OsStr::from_bytes(b"missing-\xff.toml"));
    let schema_path = format!(
        "{}/../docs/schemas/config.schema.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let schema: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(schema_path).unwrap()).unwrap();
    let validator = jsonschema::validator_for(&schema).expect("compile the schema");

    for (config, subcommand, code) in [
        (&file, "path", 0),
        (&file, "show", 0),
        (&file, "validate", 0),
        (&missing, "path", 0),
        (&missing, "validate", 3),
    ] {
        let output = nails()
            .arg("--json")
            .arg("--config")
            .arg(config)
            .args(["config", subcommand])
            .output()
            .unwrap();
        let case = format!("config {subcommand} on {}: {output:?}", config.display());
        let stdout = String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8");
        assert_eq!(stdout.lines().count(), 1, "one envelope: {case}");
        assert_eq!(output.status.code(), Some(code), "{case}");
        let value: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is JSON");
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|error| error.to_string())
            .collect();
        assert!(errors.is_empty(), "{errors:?}: {case}");
        assert_ne!(value["error"]["code"], "internal_error", "{case}");
        assert_eq!(value["ok"], code == 0, "{case}");
        if code == 0 {
            assert_eq!(
                value["data"]["path"],
                config.display().to_string(),
                "{case}"
            );
        } else {
            assert_eq!(value["error"]["code"], "config", "{case}");
        }
    }
}

#[test]
fn activate_exits_3_on_unknown_key_before_any_operation() {
    let bad = write_config("hidden_volume_root = \"/mnt/hv\"\nnixos_flak = \"x\"\n");

    nails()
        .args([
            "--config",
            bad.path().to_str().unwrap(),
            "activate",
            "--dry-run",
        ])
        .assert()
        .code(3)
        .stdout("")
        .stderr(predicate::str::contains(
            "unknown key `nixos_flak` (did you mean `nixos_flake`?)",
        ))
        .stderr(predicate::str::contains("TEST SAFETY GUARD").not());
}

#[test]
fn missing_explicit_config_prints_one_line_and_exits_3() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nails.toml");

    for command in [
        &["activate", "--dry-run"][..],
        &["status"],
        &["config", "show"],
    ] {
        let output = nails()
            .arg("--config")
            .arg(&missing)
            .args(command)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert_eq!(output.status.code(), Some(3), "{command:?}: {stderr}");
        assert_eq!(
            stderr.trim_end(),
            format!(
                "error: config file not found: {} (run `{}` or pass --config)",
                missing.display(),
                init_line()
            ),
            "{command:?}"
        );
        assert!(output.stdout.is_empty(), "{command:?}");
    }
}

/// A copy of one of the config fixtures the VM tests use
/// (`nix/e2e-tests/fixtures/configs/`). The checks on them that need no VM (the
/// exit code, the did-you-mean hint, the reported line) run here; the VM keeps
/// only what needs a booted system: activation refused with nothing mounted, and
/// emergency proceeding on a broken config.
fn vm_fixture(name: &str) -> tempfile::NamedTempFile {
    let path = format!(
        "{}/../nix/e2e-tests/fixtures/configs/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let contents = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{path}: {err}"));
    write_config(&contents)
}

#[test]
fn unknown_nested_key_fixture_is_refused_by_a_dry_run_with_a_hint() {
    let file = vm_fixture("unknown-nested-key.toml");
    nails()
        .args(["--config", file.path().to_str().unwrap()])
        .args(["activate", "--dry-run", "--overlay-only"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("did you mean `enabled`?"));
}

#[test]
fn unknown_key_fixture_fails_config_validate_with_the_hint() {
    let file = vm_fixture("unknown-key.toml");
    nails()
        .args(["config", "validate", file.path().to_str().unwrap()])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("did you mean `nixos_flake`?"));
}

#[test]
fn invalid_type_fixture_exits_3_and_names_the_line() {
    let file = vm_fixture("invalid-type.toml");
    let path = file.path().to_str().unwrap();
    nails()
        .args(["--config", path, "status"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(format!(
            "invalid config {path}: line 3"
        )));
}
