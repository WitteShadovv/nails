// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `nails config set` and `nails config unset` through the real binary.
//!
//! The writer takes the volume the running binary lies on as the hidden
//! volume, so the tests here that write run in an unprivileged user and mount
//! namespace with a tmpfs as that volume and the test binary bound into it as
//! `<volume>/nails`: the binary they spawn inherits the namespace, and no test
//! hook stands in for a mounted volume. Run from the build tree, which is no
//! volume of its own, the same binary refuses to write.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use serde_json::Value;

fn schema() -> Value {
    let path = format!(
        "{}/../docs/schemas/config.schema.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The one envelope on stdout, checked against the config schema.
fn envelope(output: &Output) -> Value {
    let stdout = String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8");
    assert_eq!(stdout.lines().count(), 1, "one envelope: {output:?}");
    let value: Value = serde_json::from_str(&stdout).expect("stdout is JSON");
    let schema = schema();
    let validator = jsonschema::validator_for(&schema).expect("compile the schema");
    let errors: Vec<String> = validator
        .iter_errors(&value)
        .map(|e| e.to_string())
        .collect();
    assert!(errors.is_empty(), "{errors:?}: {value}");
    value
}

fn nails(binary: &Path, args: &[&str]) -> Output {
    Command::new(binary)
        .env_remove("NO_COLOR")
        .arg("--no-log-file")
        .args(args)
        .output()
        .expect("run nails")
}

fn built() -> PathBuf {
    PathBuf::from(assert_cmd::cargo::cargo_bin!("nails"))
}

#[test]
fn a_key_or_a_value_the_file_does_not_take_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("nails.toml");
    std::fs::write(&config, "minimum_space_mb = 750\n").unwrap();
    let config = config.to_str().unwrap();
    for args in [
        vec!["config", "set", "persona.mod", "fresh-home"],
        vec!["config", "set", "persona.mode", "separate-user"],
        vec!["config", "set", "minimum_space_mb", "-1"],
        vec!["config", "set", "show_opsec_reminders", "yes"],
        vec!["config", "set", "nixos_flake", "/a#b", "/c#d"],
        vec!["config", "unset", "persona.mode", "bogus"],
    ] {
        let mut json = vec!["--config", config, "--json"];
        json.extend(&args);
        let output = nails(&built(), &json);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        let value = envelope(&output);
        assert_eq!(value["ok"], false, "{args:?}");
        assert_eq!(value["error"]["code"], "usage", "{args:?}");

        let mut human = vec!["--config", config];
        human.extend(&args);
        let output = nails(&built(), &human);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.starts_with("error: "), "{args:?}: {stderr}");
    }
    // clap's own refusal: a value is required.
    let output = nails(
        &built(),
        &["--config", config, "config", "set", "persona.mode"],
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(
        std::fs::read_to_string(config).unwrap(),
        "minimum_space_mb = 750\n"
    );
}

/// Run from the build tree, the binary lies on no volume of its own: it writes
/// nowhere, neither the file `--config` names elsewhere nor its own
/// configuration beside it.
#[test]
fn a_binary_that_runs_from_no_volume_of_its_own_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = dir.path().join("nails.toml");
    std::fs::write(&elsewhere, "minimum_space_mb = 750\n").unwrap();
    let output = nails(
        &built(),
        &[
            "--config",
            elsewhere.to_str().unwrap(),
            "--json",
            "config",
            "set",
            "minimum_space_mb",
            "2000",
        ],
    );
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    let value = envelope(&output);
    assert_eq!(value["error"]["code"], "config_off_volume", "{value}");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("is not on the volume nails runs from"),
        "{value}"
    );
    assert_eq!(
        std::fs::read_to_string(&elsewhere).unwrap(),
        "minimum_space_mb = 750\n"
    );

    let beside = built()
        .canonicalize()
        .unwrap()
        .parent()
        .unwrap()
        .join("config/nails.toml");
    assert!(!beside.exists(), "the test needs no file beside the binary");
    let output = nails(&built(), &["config", "set", "persona.mode", "fresh-home"]);
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Nothing was written."), "{stderr}");
    assert!(!beside.exists());
}

/// Wait for `child`, failing the test after `limit` instead of hanging.
fn wait_within(mut child: std::process::Child, limit: Duration) -> Output {
    let deadline = Instant::now() + limit;
    loop {
        if child.try_wait().expect("poll the child").is_some() {
            return child.wait_with_output().expect("collect the child");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("a nails process did not end within {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

mod kernel_tests {
    use super::*;
    use nails_core::test_path;
    use nails_core::test_support::{Rerun, ScratchTmpfs};

    /// A tmpfs as the hidden volume, laid out as `init` lays it out (its state
    /// file and the commented template), and the test binary bound into it as
    /// `<volume>/nails`, so that is the volume it runs from. Build it only
    /// inside a [`Rerun::in_user_mount_ns`] body.
    struct Volume {
        _tmpfs: ScratchTmpfs,
        root: PathBuf,
    }

    impl Volume {
        fn new() -> Self {
            let tmpfs = ScratchTmpfs::new("");
            let root = tmpfs.path().canonicalize().unwrap();
            std::fs::create_dir(root.join("config")).unwrap();
            std::fs::write(root.join("state.json"), "{}").unwrap();
            std::fs::write(config_of(&root), nails_core::Config::init_template(&root)).unwrap();
            let binary = root.join("nails");
            std::fs::write(&binary, "").unwrap();
            nix::mount::mount(
                Some(&built()),
                &binary,
                None::<&str>,
                nix::mount::MsFlags::MS_BIND,
                None::<&str>,
            )
            .expect("bind the binary onto the volume");
            Self {
                _tmpfs: tmpfs,
                root,
            }
        }

        fn binary(&self) -> PathBuf {
            self.root.join("nails")
        }

        fn config(&self) -> PathBuf {
            config_of(&self.root)
        }

        fn run(&self, args: &[&str]) -> Output {
            nails(&self.binary(), args)
        }

        fn text(&self) -> String {
            std::fs::read_to_string(self.config()).unwrap()
        }
    }

    impl Drop for Volume {
        fn drop(&mut self) {
            let _ = nix::mount::umount(&self.binary());
        }
    }

    fn config_of(root: &Path) -> PathBuf {
        root.join("config").join("nails.toml")
    }

    fn in_namespace(test: &str, body: impl FnOnce()) {
        let _ = Rerun::new(test).in_user_mount_ns().run(body);
    }

    #[test]
    fn set_and_unset_change_the_file_beside_the_binary_and_keep_the_rest() {
        in_namespace(
            test_path!(set_and_unset_change_the_file_beside_the_binary_and_keep_the_rest),
            || {
                let volume = Volume::new();
                let template = volume.text();
                let mode = || {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::metadata(volume.config())
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o7777
                };
                let before = mode();

                let output = volume.run(&["config", "set", "persona.mode", "fresh-home"]);
                assert_eq!(output.status.code(), Some(0), "{output:?}");
                assert_eq!(
                    String::from_utf8_lossy(&output.stdout),
                    format!(
                        "persona.mode = \"fresh-home\" (was not set)\nWrote {}.\n",
                        volume.config().display()
                    )
                );
                assert_eq!(
                    volume.text(),
                    format!("{template}\n[persona]\nmode = \"fresh-home\"\n")
                );
                assert_eq!(mode(), before, "the file's own mode is kept");

                let output = volume.run(&[
                    "--json",
                    "config",
                    "set",
                    "persona.mask_inherited",
                    "dropbox",
                    "syncthing.service",
                ]);
                assert_eq!(output.status.code(), Some(0), "{output:?}");
                let value = envelope(&output);
                assert_eq!(value["ok"], true);
                assert_eq!(value["data"]["written"], true);
                assert_eq!(value["data"]["path"], volume.config().display().to_string());
                assert_eq!(
                    value["data"]["changes"],
                    serde_json::json!([{
                        "key": "persona.mask_inherited",
                        "before": null,
                        "after": ["dropbox", "syncthing.service"],
                    }])
                );

                // Nothing to change: nothing is written.
                let output = volume.run(&["--json", "config", "set", "persona.mode", "fresh-home"]);
                let value = envelope(&output);
                assert_eq!(value["data"]["written"], false, "{value}");

                let output =
                    volume.run(&["config", "unset", "persona.mode", "persona.mask_inherited"]);
                assert_eq!(output.status.code(), Some(0), "{output:?}");
                assert_eq!(volume.text(), format!("{template}\n[persona]\n"));

                // What config show reports is what was written.
                volume.run(&["config", "set", "minimum_space_mb", "2000"]);
                let output = volume.run(&["--json", "config", "show"]);
                let value = envelope(&output);
                assert_eq!(value["data"]["config"]["minimum_space_mb"], 2000);
                assert_eq!(value["data"]["sources"]["minimum_space_mb"], "file");
            },
        );
    }

    #[test]
    fn an_invalid_value_a_link_and_a_file_elsewhere_are_refused() {
        in_namespace(
            test_path!(an_invalid_value_a_link_and_a_file_elsewhere_are_refused),
            || {
                let volume = Volume::new();
                let before = volume.text();

                let output =
                    volume.run(&["--json", "config", "set", "hidden_volume_root", "/mnt/a,b"]);
                assert_eq!(output.status.code(), Some(3), "{output:?}");
                let value = envelope(&output);
                assert_eq!(value["error"]["code"], "config");
                assert!(
                    value["error"]["message"]
                        .as_str()
                        .unwrap()
                        .contains("must not contain ','"),
                    "{value}"
                );
                assert_eq!(volume.text(), before);

                // A link at the file: the file it points to stays as it was.
                let outside = tempfile::tempdir().unwrap();
                let decoy = outside.path().join("nails.toml");
                std::fs::write(&decoy, "minimum_space_mb = 1\n").unwrap();
                std::fs::remove_file(volume.config()).unwrap();
                std::os::unix::fs::symlink(&decoy, volume.config()).unwrap();
                let output = volume.run(&["--json", "config", "set", "minimum_space_mb", "2"]);
                assert_eq!(output.status.code(), Some(4), "{output:?}");
                assert_eq!(envelope(&output)["error"]["code"], "config_off_volume");
                assert_eq!(
                    std::fs::read_to_string(&decoy).unwrap(),
                    "minimum_space_mb = 1\n"
                );

                // A file `--config` names off the volume, as the decoy's would be.
                let output = volume.run(&[
                    "--config",
                    decoy.to_str().unwrap(),
                    "config",
                    "unset",
                    "minimum_space_mb",
                ]);
                assert_eq!(output.status.code(), Some(4), "{output:?}");
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(
                    stderr.contains("is not on the volume nails runs from"),
                    "{stderr}"
                );
                assert_eq!(
                    std::fs::read_to_string(&decoy).unwrap(),
                    "minimum_space_mb = 1\n"
                );
            },
        );
    }

    #[test]
    fn concurrent_processes_each_land_their_change() {
        in_namespace(
            test_path!(concurrent_processes_each_land_their_change),
            || {
                let volume = Volume::new();
                let edits = [
                    ("minimum_space_mb", "1000"),
                    ("rebuild_space_mb", "9000"),
                    ("show_opsec_reminders", "false"),
                    ("persona.mode", "fresh-home"),
                    ("backend_watch.enabled", "false"),
                    ("backend_watch.debounce_secs", "40"),
                    ("session_mounts.alert", "false"),
                    ("sleep_policy.mode", "teardown"),
                ];
                let children: Vec<_> = edits
                    .iter()
                    .map(|(key, value)| {
                        Command::new(volume.binary())
                            .args(["--no-log-file", "config", "set", key, value])
                            .stdout(std::process::Stdio::piped())
                            .stderr(std::process::Stdio::piped())
                            .spawn()
                            .expect("start nails")
                    })
                    .collect();
                for child in children {
                    let output = wait_within(child, Duration::from_secs(60));
                    assert_eq!(output.status.code(), Some(0), "{output:?}");
                }
                let output = volume.run(&["--json", "config", "show"]);
                let config = &envelope(&output)["data"]["config"];
                assert_eq!(config["minimum_space_mb"], 1000);
                assert_eq!(config["rebuild_space_mb"], 9000);
                assert_eq!(config["show_opsec_reminders"], false);
                assert_eq!(config["persona"]["mode"], "fresh-home");
                assert_eq!(config["backend_watch"]["enabled"], false);
                assert_eq!(config["backend_watch"]["debounce_secs"], 40);
                assert_eq!(config["session_mounts"]["alert"], false);
                assert_eq!(config["sleep_policy"]["mode"], "teardown");
                let left: Vec<String> = std::fs::read_dir(volume.root.join("config"))
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
                    .collect();
                assert_eq!(left, vec!["nails.toml".to_string()]);
            },
        );
    }
}
