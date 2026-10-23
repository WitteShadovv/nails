// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `nails recover` and `nails discard` through the real binary, on the
//! decoy (the test host) with a temporary hidden root.
//!
//! Neither path needs root: on a host with no interrupted activation `recover`
//! only resets a stale record, and `discard` only deletes directories below
//! the temporary hidden root. The attach gate accepts only a volume of its own,
//! so each test runs in an unprivileged user + mount namespace with a tmpfs as
//! the hidden root, and the binary it spawns inherits that namespace. Where user
//! namespaces are unavailable the tests skip (`just kernel-tests` fails instead).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use chrono::{TimeZone, Utc};
use nails_core::test_path;
use nails_core::test_support::{Rerun, ScratchTmpfs};
use nails_core::{StateFile, SystemState};
use serde_json::Value;

/// Run `body` in a fresh user + mount namespace (see the module docs).
fn in_namespace(test: &str, body: impl FnOnce()) {
    let _ = Rerun::new(test).in_user_mount_ns().run(body);
}

/// A tmpfs hidden root plus a `nails.toml` pointing at it. Build it inside
/// [`in_namespace`].
struct Harness {
    // Declared first so the tmpfs is detached before the directories go.
    _volume: ScratchTmpfs,
    _dir: tempfile::TempDir,
    config: PathBuf,
    hidden_root: PathBuf,
    state_path: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let volume = ScratchTmpfs::new("");
        let dir = tempfile::tempdir().unwrap();
        // Resolved the way the binary resolves it, so reported paths compare.
        let hidden_root = volume.path().canonicalize().unwrap();
        let state_path = hidden_root.join("state.json");
        let config = dir.path().join("nails.toml");
        std::fs::write(
            &config,
            format!(
                "hidden_volume_root = {root:?}\nstate_file_path = {state:?}\n\
                 show_opsec_reminders = false\n",
                root = hidden_root.display().to_string(),
                state = state_path.display().to_string(),
            ),
        )
        .unwrap();
        Self {
            _volume: volume,
            _dir: dir,
            config,
            hidden_root,
            state_path,
        }
    }

    /// Write `state` as a valid state file; it doubles as the volume's marker.
    fn write_state(&self, state: SystemState) {
        let file = StateFile {
            state,
            ..StateFile::default()
        };
        file.save(&self.state_path, self.hidden_root.to_str().unwrap())
            .expect("save state file on the hidden root");
    }

    fn state(&self) -> SystemState {
        StateFile::load(&self.state_path).unwrap().state
    }

    /// Run `nails` on this harness's config.
    fn run(&self, args: &[&str]) -> Output {
        Command::new(assert_cmd::cargo::cargo_bin!("nails"))
            .env_remove("NO_COLOR")
            .arg("--no-log-file")
            .arg("--config")
            .arg(&self.config)
            .args(args)
            .output()
            .expect("run nails")
    }

    /// Create `<hidden>/<relative>` as a directory holding one file.
    fn populate(&self, relative: &str) -> PathBuf {
        let dir = self.hidden_root.join(relative);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("notes.txt"), "hidden").unwrap();
        dir
    }
}

fn json(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(stdout.trim().lines().next_back().unwrap_or(""))
        .unwrap_or_else(|e| panic!("not one JSON document ({e}): {stdout}"))
}

fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}

// ---------------------------------------------------------------------------
// recover
// ---------------------------------------------------------------------------

#[test]
fn recover_on_a_clean_decoy_reports_nothing_to_do() {
    in_namespace(
        test_path!(recover_on_a_clean_decoy_reports_nothing_to_do),
        || {
            let harness = Harness::new();
            harness.write_state(SystemState::Inactive);

            let output = harness.run(&["recover", "--json"]);

            assert_eq!(output.status.code(), Some(0), "{output:?}");
            let value = json(&output);
            assert_eq!(value["command"], "recover");
            assert_eq!(value["ok"], true);
            assert_eq!(value["data"]["outcome"], "clean");
            assert_eq!(value["data"]["remaining_mounts"], serde_json::json!([]));
            assert_eq!(value["data"]["backend"], serde_json::json!([]));
        },
    );
}

#[test]
fn recover_resets_a_stale_active_record_on_the_decoy() {
    in_namespace(
        test_path!(recover_resets_a_stale_active_record_on_the_decoy),
        || {
            let harness = Harness::new();
            harness.write_state(SystemState::Active {
                activated_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            });

            let output = harness.run(&["--ascii", "recover"]);

            assert_eq!(output.status.code(), Some(0), "{output:?}");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert_eq!(
                stdout.trim_end(),
                "[PASS] Nothing to recover: no interrupted activation"
            );
            assert_eq!(harness.state(), SystemState::Inactive);
        },
    );
}

// ---------------------------------------------------------------------------
// discard
// ---------------------------------------------------------------------------

#[test]
fn discard_removes_the_root_upper_copy_and_the_mount_layers() {
    in_namespace(
        test_path!(discard_removes_the_root_upper_copy_and_the_mount_layers),
        || {
            let harness = Harness::new();
            harness.write_state(SystemState::Inactive);
            let upper = harness.populate("root/upper/srv/data");
            let layers = harness.populate("root/mounts/srv-data");

            let output = harness.run(&["discard", "/srv/data", "-y", "--json"]);

            assert_eq!(output.status.code(), Some(0), "{output:?}");
            let value = json(&output);
            assert_eq!(value["command"], "discard");
            assert_eq!(value["data"]["target"], "/srv/data");
            assert_eq!(
                value["data"]["removed"],
                serde_json::json!([path(&upper), path(&layers)])
            );
            assert!(!upper.exists());
            assert!(!layers.exists());
            // Only the target's copy goes: its parent in the upper stays.
            assert!(harness.hidden_root.join("root/upper/srv").is_dir());
        },
    );
}

#[test]
fn discard_in_human_form_lists_the_removals_and_the_fallback() {
    in_namespace(
        test_path!(discard_in_human_form_lists_the_removals_and_the_fallback),
        || {
            let harness = Harness::new();
            harness.write_state(SystemState::Inactive);
            let upper = harness.populate("root/upper/srv/data");

            let output = harness.run(&["--ascii", "discard", "/srv/data", "--yes"]);

            assert_eq!(output.status.code(), Some(0), "{output:?}");
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert_eq!(
                stdout.lines().collect::<Vec<_>>(),
                vec![
                    "[PASS] Discarded the hidden upper for /srv/data".to_string(),
                    format!("  removed {}", upper.display()),
                    "  /srv/data falls back to its decoy on the next activation".to_string(),
                ]
            );
        },
    );
}

#[test]
fn discard_with_nothing_to_remove_says_so() {
    in_namespace(test_path!(discard_with_nothing_to_remove_says_so), || {
        let harness = Harness::new();
        harness.write_state(SystemState::Inactive);

        let human = harness.run(&["--ascii", "discard", "/srv/empty"]);
        assert_eq!(human.status.code(), Some(0), "{human:?}");
        assert_eq!(
            String::from_utf8_lossy(&human.stdout).trim_end(),
            "[INFO] Nothing to discard for /srv/empty"
        );

        let machine = harness.run(&["discard", "/srv/empty", "--json"]);
        assert_eq!(machine.status.code(), Some(0), "{machine:?}");
        assert_eq!(json(&machine)["data"]["removed"], serde_json::json!([]));
    });
}

#[test]
fn discard_off_a_terminal_without_yes_needs_confirmation_and_keeps_the_upper() {
    in_namespace(
        test_path!(discard_off_a_terminal_without_yes_needs_confirmation_and_keeps_the_upper),
        || {
            let harness = Harness::new();
            harness.write_state(SystemState::Inactive);
            let upper = harness.populate("root/upper/srv/data");

            // `Command::output` gives the child a null stdin, never a terminal.
            let output = harness.run(&["discard", "/srv/data", "--json"]);

            assert_eq!(output.status.code(), Some(2), "{output:?}");
            let value = json(&output);
            assert_eq!(value["error"]["code"], "needs_confirmation");
            assert!(upper.join("notes.txt").is_file());
        },
    );
}

#[test]
fn discard_refuses_a_path_that_is_not_below_root() {
    in_namespace(
        test_path!(discard_refuses_a_path_that_is_not_below_root),
        || {
            let harness = Harness::new();
            harness.write_state(SystemState::Inactive);

            for target in ["relative/path", "/", "/srv/../etc"] {
                let output = harness.run(&["discard", target, "-y", "--json"]);
                assert_eq!(output.status.code(), Some(1), "{target}: {output:?}");
                let value = json(&output);
                assert_eq!(value["error"]["code"], "discard");
                assert!(
                    value["error"]["message"]
                        .as_str()
                        .unwrap()
                        .contains("is not a resettable path"),
                    "{target}: {value:#}"
                );
            }
        },
    );
}

#[test]
fn discard_with_an_unreadable_config_is_a_config_error() {
    in_namespace(
        test_path!(discard_with_an_unreadable_config_is_a_config_error),
        || {
            let harness = Harness::new();
            std::fs::write(&harness.config, "hidden_volume_root = [unterminated").unwrap();

            let output = harness.run(&["discard", "/srv/data", "-y", "--json"]);

            assert_eq!(output.status.code(), Some(3), "{output:?}");
            assert_eq!(json(&output)["ok"], false);
        },
    );
}
