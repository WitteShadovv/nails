// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The attach gate in front of `activate` and `check`, and the platform row
//! beside it, driven through the real binary.
//!
//! A refused root must receive nothing: no `.lock`, no `logs/`, no `reports/`,
//! no staged `config/`. The plain cases use a temporary directory as the root,
//! which is a folder and never a mount point. The cases that need a volume of
//! its own, or one covered by a second filesystem, run in an unprivileged user
//! and mount namespace with tmpfs roots (see `kernel_tests`).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

/// A configuration whose root is `root`, written next to it.
fn config_for(dir: &Path, root: &Path) -> PathBuf {
    let config = dir.join("nails.toml");
    std::fs::write(
        &config,
        format!(
            "hidden_volume_root = {root:?}\nshow_opsec_reminders = false\n",
            root = root.display().to_string()
        ),
    )
    .unwrap();
    config
}

/// Run `nails --config <config> <args>` with the log file left on, so a log
/// written onto the root would show.
fn nails(config: &Path, args: &[&str]) -> Output {
    Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .arg("--config")
        .arg(config)
        .args(args)
        .env_remove("NO_COLOR")
        .output()
        .expect("run nails")
}

/// The last JSON document on stdout.
fn last_json(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let last = stdout.trim().lines().next_back().unwrap_or("");
    serde_json::from_str(last).unwrap_or_else(|e| panic!("not JSON ({e}): {stdout}"))
}

/// Every entry under `dir`, recursively.
fn entries(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(read) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in read.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(entries(&path));
        }
        found.push(path);
    }
    found
}

/// A root that is a folder: the directory and its configuration.
fn folder_root() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("volume");
    std::fs::create_dir(&root).unwrap();
    let config = config_for(dir.path(), &root);
    (dir, root, config)
}

#[test]
fn activate_refuses_a_folder_before_writing_anything() {
    let (_dir, root, config) = folder_root();
    let output = nails(&config, &["activate", "-y", "--overlay-only", "--json"]);
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    let value = last_json(&output);
    assert_eq!(value["error"]["code"], "not_separate_volume", "{value}");
    assert!(entries(&root).is_empty(), "{:?}", entries(&root));
}

#[test]
fn activate_refuses_a_folder_in_plain_words() {
    let (_dir, root, config) = folder_root();
    let output = nails(&config, &["activate", "-y", "--overlay-only"]);
    assert_eq!(output.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "error: {} is not a volume of its own: it is a folder on the filesystem mounted at",
            root.display()
        )),
        "{stderr}"
    );
    assert!(stderr.contains("Nothing was written."), "{stderr}");
    assert!(stderr.contains("Where setup happens"), "{stderr}");
    // The refusal is said once: the log manager stays silent about it.
    assert!(!stderr.contains("File logging disabled"), "{stderr}");
    assert!(entries(&root).is_empty(), "{:?}", entries(&root));
}

#[test]
fn check_says_the_refusal_first_in_activates_words() {
    let (_dir, root, config) = folder_root();
    let activate = nails(&config, &["activate", "-y", "--overlay-only"]);
    let check = nails(&config, &["check", "--overlay-only"]);
    assert_eq!(check.status.code(), Some(4), "{check:?}");
    let refusal = String::from_utf8_lossy(&activate.stderr);
    let first = refusal
        .lines()
        .find(|line| line.starts_with("error: "))
        .expect("activate names the refusal");
    let stderr = String::from_utf8_lossy(&check.stderr);
    assert_eq!(
        stderr.lines().find(|line| line.starts_with("error: ")),
        Some(first),
        "{stderr}"
    );
    assert!(stderr.contains("Where setup happens"), "{stderr}");
    // The readiness report follows on stdout.
    let stdout = String::from_utf8_lossy(&check.stdout);
    assert!(stdout.contains("hidden-volume"), "{stdout}");
    assert!(entries(&root).is_empty(), "{:?}", entries(&root));
}

#[test]
fn a_dry_run_reports_the_refusal_and_opens_no_log() {
    let (_dir, root, config) = folder_root();
    let output = nails(
        &config,
        &["activate", "--dry-run", "--overlay-only", "--json"],
    );
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    let value = last_json(&output);
    assert_eq!(value["data"]["refusal"]["code"], "not_separate_volume");
    // The dry run is `check`, which never opens a log file, so the log
    // manager has nothing to say either.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("File logging disabled"), "{stderr}");
    assert!(entries(&root).is_empty(), "{:?}", entries(&root));
}

#[test]
fn the_override_never_covers_a_folder() {
    let (_dir, root, config) = folder_root();
    let output = nails(&config, &["check", "--allow-decoy-storage", "--json"]);
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    let value = last_json(&output);
    assert_eq!(
        value["data"]["refusal"]["code"], "not_separate_volume",
        "{value}"
    );
    let output = nails(
        &config,
        &["activate", "-y", "--overlay-only", "--allow-decoy-storage"],
    );
    assert_eq!(output.status.code(), Some(4), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("warning: --allow-decoy-storage"),
        "{stderr}"
    );
    assert!(stderr.contains("Nothing was written."), "{stderr}");
    assert!(entries(&root).is_empty(), "{:?}", entries(&root));
}

/// The cases that need a volume of its own at the root: each runs in an
/// unprivileged user + mount namespace with tmpfs roots, and the binary it
/// spawns inherits the namespace. Activation cannot get past its pre-flight
/// checks there (PID 1 is in another mount namespace), so nothing reaches the
/// host.
mod kernel_tests {
    use super::*;
    use nails_core::test_path;
    use nails_core::test_support::{Rerun, ScratchTmpfs};

    /// The gate's codes, none of which a root it accepts may produce.
    const GATE_CODES: &[&str] = &["not_separate_volume", "root_covered", "storage_unjudged"];

    #[test]
    fn a_tmpfs_root_passes_the_gate() {
        let _ = Rerun::new(test_path!(a_tmpfs_root_passes_the_gate))
            .in_user_mount_ns()
            .run(|| {
                let volume = ScratchTmpfs::new("");
                let dir = tempfile::tempdir().unwrap();
                let config = config_for(dir.path(), volume.path());
                let output = nails(&config, &["activate", "-y", "--overlay-only", "--json"]);
                let value = last_json(&output);
                let code = value["error"]["code"].as_str().unwrap_or("");
                assert!(!GATE_CODES.contains(&code), "{value}");
            });
    }

    /// `activate --json` writes exactly one envelope of its schema to stdout,
    /// however far it gets: the version-2 contract has no line stream, so the
    /// log (pre-flight warnings and progress included) stays on stderr. Here it
    /// passes the gate, takes the lock, and ends in one envelope, because the
    /// pre-flight checks refuse.
    #[test]
    fn activate_json_prints_one_envelope_of_its_schema() {
        let _ = Rerun::new(test_path!(activate_json_prints_one_envelope_of_its_schema))
            .in_user_mount_ns()
            .run(|| {
                let volume = ScratchTmpfs::new("");
                let dir = tempfile::tempdir().unwrap();
                let config = config_for(dir.path(), volume.path());
                let output = nails(&config, &["activate", "-y", "--overlay-only", "--json"]);

                let schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../docs/schemas/activate.schema.json");
                let schema: Value =
                    serde_json::from_str(&std::fs::read_to_string(schema_path).unwrap()).unwrap();
                let validator = jsonschema::validator_for(&schema).expect("compile the schema");
                let stdout = String::from_utf8_lossy(&output.stdout);
                let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
                assert_eq!(lines.len(), 1, "exactly one envelope line: {output:?}");
                let value: Value = serde_json::from_str(lines[0])
                    .unwrap_or_else(|e| panic!("not JSON ({e}): {}\n{output:?}", lines[0]));
                let errors: Vec<String> = validator
                    .iter_errors(&value)
                    .map(|e| e.to_string())
                    .collect();
                assert!(errors.is_empty(), "{errors:?}: {}\n{output:?}", lines[0]);
                assert_eq!(value["schema_version"], 2, "{output:?}");
                assert_eq!(value["command"], "activate", "{output:?}");
                assert!(value["ok"].is_boolean(), "{output:?}");
                // No line-stream tag survives the version-2 contract.
                assert!(value.get("type").is_none(), "{output:?}");
            });
    }

    /// Without a configuration file, activation says so before it goes on,
    /// `-q` included: every opt-in protection keeps its built-in default. Its
    /// progress line then names the steps it runs, here without a hidden
    /// NixOS build. The binary sits on the volume, as the README installs it,
    /// so the volume is the hidden root and `config/nails.toml` is missing.
    #[test]
    fn activation_without_a_config_file_says_so_even_when_quiet() {
        let _ = Rerun::new(test_path!(
            activation_without_a_config_file_says_so_even_when_quiet
        ))
        .in_user_mount_ns()
        .run(|| {
            let volume = ScratchTmpfs::new("");
            let binary = volume.path().join("nails");
            std::fs::copy(assert_cmd::cargo::cargo_bin!("nails"), &binary).unwrap();
            let notice = "config/nails.toml: activation uses the built-in defaults.";
            let progress = "Preparing the hidden session (pre-flight, next root)...";
            for quiet in [false, true] {
                let mut command = Command::new(&binary);
                command.args(["activate", "-y", "--overlay-only"]);
                if quiet {
                    command.arg("-q");
                }
                let output = command.env_remove("NO_COLOR").output().unwrap();
                let stderr = String::from_utf8_lossy(&output.stderr);
                let line = stderr
                    .lines()
                    .position(|line| {
                        line.starts_with("No config file at ") && line.ends_with(notice)
                    })
                    .unwrap_or_else(|| panic!("quiet={quiet}: no notice in {stderr}"));
                match stderr.lines().position(|line| line == progress) {
                    Some(at) => assert!(!quiet && line < at, "quiet={quiet}: {stderr}"),
                    None => assert!(quiet, "no progress line: {stderr}"),
                }
            }
        });
    }

    #[test]
    fn a_second_tmpfs_over_the_root_is_refused_and_neither_is_written() {
        let _ = Rerun::new(test_path!(
            a_second_tmpfs_over_the_root_is_refused_and_neither_is_written
        ))
        .in_user_mount_ns()
        .run(|| {
            let volume = ScratchTmpfs::new("");
            nix::mount::mount(
                Some("cover"),
                volume.path(),
                Some("tmpfs"),
                nix::mount::MsFlags::empty(),
                Some("mode=0755"),
            )
            .expect("mount a second tmpfs over the root");
            let dir = tempfile::tempdir().unwrap();
            let config = config_for(dir.path(), volume.path());

            let output = nails(&config, &["activate", "-y", "--overlay-only", "--json"]);
            assert_eq!(output.status.code(), Some(4), "{output:?}");
            assert_eq!(last_json(&output)["error"]["code"], "root_covered");
            let output = nails(&config, &["check", "--allow-decoy-storage", "--json"]);
            assert_eq!(output.status.code(), Some(4), "{output:?}");
            assert_eq!(
                last_json(&output)["data"]["refusal"]["code"],
                "root_covered"
            );
            // Every command that takes the state lock reports the same refusal.
            let output = nails(
                &config,
                &["discard", "/opt/nails-gate-target", "-y", "--json"],
            );
            assert_eq!(output.status.code(), Some(4), "{output:?}");
            assert_eq!(last_json(&output)["error"]["code"], "root_covered");

            assert!(entries(volume.path()).is_empty(), "the cover was written");
            nix::mount::umount(volume.path()).expect("unmount the cover");
            assert!(entries(volume.path()).is_empty(), "the root was written");
        });
    }

    /// The platform row through the real binary, with the host's os-release
    /// replaced by a bind mount: a tested Ubuntu release passes it by name; an
    /// untested one warns in `check`, in `init` and during activation, which
    /// goes on until the other pre-flight checks refuse; and a host activation
    /// refuses fails the row, as activation then refuses it with exit 8.
    #[test]
    fn the_platform_row_names_the_host_and_warns_on_an_untested_release() {
        let _ = Rerun::new(test_path!(
            the_platform_row_names_the_host_and_warns_on_an_untested_release
        ))
        .in_user_mount_ns()
        .run(|| {
            // Detection refuses every Debian-family host on a split /usr.
            if ["/bin", "/sbin", "/lib"]
                .iter()
                .any(|dir| std::fs::symlink_metadata(dir).is_ok_and(|meta| meta.is_dir()))
            {
                nails_core::test_support::skip_host(
                    "/bin, /sbin or /lib is a directory on this host, which refuses any \
                     Debian-family os-release",
                );
            }
            let dir = tempfile::tempdir().unwrap();
            let os_release = dir.path().join("os-release");
            std::fs::write(&os_release, "").unwrap();
            nix::mount::mount(
                Some(os_release.as_path()),
                "/etc/os-release",
                None::<&str>,
                nix::mount::MsFlags::MS_BIND,
                None::<&str>,
            )
            .expect("bind a stand-in over /etc/os-release");
            // Written in place, so the bind mount shows each new content.
            let host = |content: &str| std::fs::write(&os_release, content).unwrap();
            let volume = ScratchTmpfs::new("");
            let config = config_for(dir.path(), volume.path());
            let platform_row = || {
                let output = nails(&config, &["check", "--overlay-only", "--json"]);
                last_json(&output)["data"]["checks"]
                    .as_array()
                    .and_then(|rows| rows.iter().find(|row| row["name"] == "platform"))
                    .cloned()
                    .unwrap_or_else(|| panic!("no platform row: {output:?}"))
            };

            host("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n");
            let row = platform_row();
            assert_eq!(row["status"], "pass", "{row}");
            assert_eq!(row["message"], "Ubuntu 24.04", "{row}");

            // 26.04 is tested too, but a known upstream issue warns rather than
            // failing: the row is a warn naming the effect, not a plain pass.
            host("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"26.04\"\n");
            let row = platform_row();
            assert_eq!(row["status"], "warn", "{row}");
            assert!(
                row["message"]
                    .as_str()
                    .unwrap_or("")
                    .starts_with("Ubuntu 26.04 is tested, but a known upstream issue"),
                "{row}"
            );

            // 26.10 warns as untested: no run of NAILS on it has passed yet.
            host("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"26.10\"\n");
            let warning = "Ubuntu 26.10 is not a release NAILS has been tested on \
                           (tested: Ubuntu 24.04 and 26.04).";
            let row = platform_row();
            assert_eq!(row["status"], "warn", "{row}");
            assert!(
                row["message"].as_str().unwrap_or("").starts_with(warning),
                "{row}"
            );
            let target = ScratchTmpfs::new("");
            let init = Command::new(assert_cmd::cargo::cargo_bin!("nails"))
                .args(["--no-log-file", "init"])
                .arg(target.path())
                .output()
                .expect("run nails init");
            assert_eq!(init.status.code(), Some(0), "{init:?}");
            let stderr = String::from_utf8_lossy(&init.stderr);
            assert!(stderr.contains(&format!("warning: {warning}")), "{stderr}");
            let output = nails(&config, &["activate", "-y", "--overlay-only"]);
            assert_eq!(output.status.code(), Some(4), "{output:?}");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains(&format!("platform: {warning}")), "{stderr}");

            host("ID=fedora\nVERSION_ID=44\n");
            let row = platform_row();
            assert_eq!(row["status"], "fail", "{row}");
            assert!(
                row["message"]
                    .as_str()
                    .unwrap_or("")
                    .starts_with("Fedora is not yet a validated platform"),
                "{row}"
            );
            // Activation refuses a host it does not support with exit 8, and
            // before any write: a fresh hidden volume stays byte-identical, with
            // no lock, no log and no staged config. The log file is left on (the
            // `nails` helper), so a log line would land on the volume and show.
            let refused_volume = ScratchTmpfs::new("");
            let refused_dir = tempfile::tempdir().unwrap();
            let refused_config = config_for(refused_dir.path(), refused_volume.path());
            let output = nails(&refused_config, &["activate", "-y", "--overlay-only"]);
            assert_eq!(output.status.code(), Some(8), "{output:?}");
            assert!(
                entries(refused_volume.path()).is_empty(),
                "a refused host wrote to the hidden volume: {:?}",
                entries(refused_volume.path())
            );
        });
    }
}
