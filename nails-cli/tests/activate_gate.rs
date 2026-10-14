// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The attach gate in front of `activate` and `check`, driven through the real
//! binary.
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
    for extra in [&[][..], &["--no-preflight"][..]] {
        let (_dir, root, config) = folder_root();
        let mut args = vec!["activate", "-y", "--overlay-only", "--json"];
        args.extend_from_slice(extra);
        let output = nails(&config, &args);
        assert_eq!(output.status.code(), Some(4), "{extra:?}: {output:?}");
        let value = last_json(&output);
        assert_eq!(value["error"]["code"], "not_separate_volume", "{value}");
        assert!(entries(&root).is_empty(), "{extra:?}: {:?}", entries(&root));
    }
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
    for extra in [&[][..], &["--no-preflight"][..]] {
        let mut args = vec!["activate", "-y", "--overlay-only", "--allow-decoy-storage"];
        args.extend_from_slice(extra);
        let output = nails(&config, &args);
        assert_eq!(output.status.code(), Some(4), "{extra:?}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("warning: --allow-decoy-storage"),
            "{stderr}"
        );
        assert!(stderr.contains("Nothing was written."), "{stderr}");
    }
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

            for args in [
                &["activate", "-y", "--overlay-only", "--json"][..],
                &[
                    "activate",
                    "-y",
                    "--overlay-only",
                    "--no-preflight",
                    "--json",
                ][..],
            ] {
                let output = nails(&config, args);
                assert_eq!(output.status.code(), Some(4), "{args:?}: {output:?}");
                assert_eq!(last_json(&output)["error"]["code"], "root_covered");
            }
            let output = nails(&config, &["check", "--allow-decoy-storage", "--json"]);
            assert_eq!(output.status.code(), Some(4), "{output:?}");
            assert_eq!(
                last_json(&output)["data"]["refusal"]["code"],
                "root_covered"
            );
            // Every command that takes the state lock reports the same refusal.
            let output = nails(
                &config,
                &["reset-upper", "/opt/nails-gate-target", "-y", "--json"],
            );
            assert_eq!(output.status.code(), Some(4), "{output:?}");
            assert_eq!(last_json(&output)["error"]["code"], "root_covered");

            assert!(entries(volume.path()).is_empty(), "the cover was written");
            nix::mount::umount(volume.path()).expect("unmount the cover");
            assert!(entries(volume.path()).is_empty(), "the root was written");
        });
    }
}
