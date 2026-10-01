//! Binary-level tests for `nails config` and strict configuration loading
//!
//! Every command run here is read-only or exits during configuration loading,
//! before any system operation, so no safety guard is needed.

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
    assert_eq!(value["path"], path);
    assert_eq!(value["exists"], true);
}

#[test]
fn config_path_without_override_is_binary_relative() {
    let output = nails().args(["config", "path", "--json"]).output().unwrap();
    assert!(output.status.success());

    let value = stdout_json(&output);
    let bin = std::fs::canonicalize(assert_cmd::cargo::cargo_bin!("nails")).unwrap();
    let expected = bin.parent().unwrap().join("config").join("nails.toml");
    assert_eq!(value["path"], expected.to_str().unwrap());
}

#[test]
fn config_show_annotates_sources_in_toml_and_json() {
    let file = write_config("minimum_space_mb = 750\n");
    let path = file.path().to_str().unwrap();

    nails()
        .args(["--config", path, "config", "show", "--no-clear-history"])
        .assert()
        .success()
        .stdout(predicate::str::contains("minimum_space_mb = 750  # file"))
        .stdout(predicate::str::contains("clear_history = false  # cli"))
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
    assert_eq!(value["exists"], true);
    assert_eq!(value["config"]["minimum_space_mb"], 750);
    assert_eq!(value["sources"]["minimum_space_mb"], "file");
    assert_eq!(value["sources"]["hidden_volume_root"], "derived");
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

    let bad = write_config("[color_scheme]\nenable = false\n");
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
    assert_eq!(value["valid"], false);
    assert!(value["error"].as_str().unwrap().contains("did you mean"));
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

#[test]
fn activate_exits_3_on_unknown_key_before_any_operation() {
    let bad = write_config("hidden_volume_root = \"/mnt/hv\"\nprompt_lable = \"x\"\n");

    nails()
        .args([
            "--config",
            bad.path().to_str().unwrap(),
            "activate",
            "--dry-run",
            "--no-kill-session",
        ])
        .assert()
        .code(3)
        .stdout("")
        .stderr(predicate::str::contains(
            "unknown key `prompt_lable` (did you mean `prompt_label`?)",
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
                "error: config file not found: {} (run `nails init <root>` or pass --config)",
                missing.display()
            ),
            "{command:?}"
        );
        assert!(output.stdout.is_empty(), "{command:?}");
    }
}
