// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! `nails helper --stdio` through the real binary: the handshake, and every
//! operation answered with exactly the envelope and exit code the CLI gives
//! for the same command under `--json`.
//!
//! The discard tests need the attach gate to accept the hidden root, so they
//! run in an unprivileged user + mount namespace with a tmpfs as the root, as
//! `maintenance_cli.rs` does; where user namespaces are unavailable they skip
//! (`just kernel-tests` fails instead).

#![cfg(feature = "gui")]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use nails_api::protocol::{
    CheckArgs, ConfigShowArgs, DiscardPlanArgs, DiscardPlanData, ErrorCode, Frame, Hello, Op,
    PROTOCOL_VERSION, Request, Token,
};
use nails_core::test_path;
use nails_core::test_support::{Rerun, ScratchTmpfs};
use nails_core::{StateFile, SystemState};
use serde_json::Value;

/// A running helper and both ends of its pipe.
struct Helper {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Helper {
    /// Start the helper on `config` and read its hello.
    fn start(config: &Path) -> Self {
        let mut child = Command::new(assert_cmd::cargo::cargo_bin!("nails"))
            .arg("--no-log-file")
            .arg("--config")
            .arg(config)
            .args(["helper", "--stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start the helper");
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut helper = Self {
            child,
            stdin,
            stdout,
            next_id: 1,
        };
        match helper.frame() {
            Some(Frame::Hello(hello)) => assert_eq!(hello, ours()),
            other => panic!("the helper's first frame is {other:?}"),
        }
        helper
    }

    /// Start the helper and complete the handshake.
    fn greeted(config: &Path) -> Self {
        let mut helper = Self::start(config);
        let (exit, envelope) = helper.result(Op::Hello(ours()));
        assert_eq!(exit, 0);
        assert_eq!(envelope["data"], serde_json::to_value(ours()).unwrap());
        helper
    }

    fn send_line(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{line}").unwrap();
        stdin.flush().unwrap();
    }

    fn send(&mut self, op: Op) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let line = Request {
            v: PROTOCOL_VERSION,
            id,
            op,
        }
        .to_line();
        self.send_line(&line);
        id
    }

    /// The next frame, or `None` once the helper closed its end.
    fn frame(&mut self) -> Option<Frame> {
        let mut line = String::new();
        if self.stdout.read_line(&mut line).unwrap() == 0 {
            return None;
        }
        Some(serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line}")))
    }

    /// Every frame up to and including the answer to the next request.
    fn answer(&mut self, op: Op) -> (Vec<Frame>, Frame) {
        let id = self.send(op);
        let mut events = Vec::new();
        loop {
            match self.frame().expect("an answer") {
                frame @ Frame::Event { .. } => events.push(frame),
                frame => {
                    match &frame {
                        Frame::Result { id: got, .. } | Frame::Error { id: Some(got), .. } => {
                            assert_eq!(*got, id)
                        }
                        other => panic!("{other:?}"),
                    }
                    return (events, frame);
                }
            }
        }
    }

    /// The exit code and envelope of the answer to `op`.
    fn result(&mut self, op: Op) -> (i32, Value) {
        match self.answer(op).1 {
            Frame::Result { exit, envelope, .. } => (i32::from(exit), envelope),
            other => panic!("not a result: {other:?}"),
        }
    }

    /// Close the window's end and return the helper's exit code.
    fn close(mut self) -> i32 {
        drop(self.stdin.take());
        assert!(self.frame().is_none(), "no frame after the window closed");
        self.child.wait().unwrap().code().unwrap_or(-1)
    }
}

fn ours() -> Hello {
    Hello {
        protocol: PROTOCOL_VERSION,
        engine: env!("CARGO_PKG_VERSION").to_string(),
    }
}

/// Run the CLI's `args` with `--json` on `config`: its exit code and envelope.
fn cli_json(config: &Path, args: &[&str]) -> (i32, Value) {
    let output = Command::new(assert_cmd::cargo::cargo_bin!("nails"))
        .arg("--no-log-file")
        .arg("--config")
        .arg(config)
        .args(args)
        .arg("--json")
        .output()
        .expect("run nails");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("not one envelope ({e}): {stdout}"));
    (output.status.code().unwrap_or(-1), value)
}

/// A configuration whose hidden root is a plain scratch directory.
fn scratch_config() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("hidden-volume");
    std::fs::create_dir_all(&root).unwrap();
    let config = dir.path().join("nails.toml");
    std::fs::write(
        &config,
        format!(
            "hidden_volume_root = {:?}\nstate_file_path = {:?}\nshow_opsec_reminders = false\n",
            root.display().to_string(),
            root.join("state.json").display().to_string()
        ),
    )
    .unwrap();
    (dir, config)
}

/// Drop the fields of a status envelope that change from one second to the
/// next.
fn steady(mut envelope: Value) -> Value {
    if let Some(data) = envelope.get_mut("data").and_then(Value::as_object_mut) {
        data.remove("uptime_seconds");
        data.remove("uptime_formatted");
    }
    envelope
}

#[test]
fn the_helper_answers_as_the_cli_does_for_status_and_config() {
    let (_dir, config) = scratch_config();
    let mut helper = Helper::greeted(&config);

    let (exit, envelope) = helper.result(Op::Status);
    let (cli_exit, cli) = cli_json(&config, &["status"]);
    assert_eq!((exit, steady(envelope)), (cli_exit, steady(cli)));

    for (op, args) in [
        (Op::ConfigPath, vec!["config", "path"]),
        (Op::ConfigValidate, vec!["config", "validate"]),
        (
            Op::ConfigShow(ConfigShowArgs { nixos_flake: None }),
            vec!["config", "show"],
        ),
        (
            Op::ConfigShow(ConfigShowArgs {
                nixos_flake: Some("/srv/cfg#host".to_string()),
            }),
            vec!["config", "show", "--nixos-flake", "/srv/cfg#host"],
        ),
    ] {
        assert_eq!(helper.result(op), cli_json(&config, &args), "{args:?}");
    }
    assert_eq!(helper.close(), 0, "a closed pipe ends the helper cleanly");
}

#[test]
fn check_streams_each_result_and_answers_as_the_cli_does() {
    let (_dir, config) = scratch_config();
    let mut helper = Helper::greeted(&config);
    let (events, answer) = helper.answer(Op::Check(CheckArgs::default()));
    let Frame::Result { exit, envelope, .. } = answer else {
        panic!("{answer:?}");
    };
    let (cli_exit, cli) = cli_json(&config, &["check"]);
    assert_eq!(i32::from(exit), cli_exit);
    assert_eq!(envelope["command"], cli["command"]);
    assert_eq!(envelope["ok"], cli["ok"]);
    let rows = |envelope: &Value| -> Vec<(Value, Value)> {
        envelope["data"]["checks"]
            .as_array()
            .unwrap_or_else(|| panic!("{envelope}"))
            .iter()
            .map(|row| (row["name"].clone(), row["status"].clone()))
            .collect()
    };
    assert_eq!(rows(&envelope), rows(&cli));
    // One event for each check that ran, in order, before the answer.
    let streamed: Vec<String> = events
        .iter()
        .filter_map(|frame| match frame {
            Frame::Event {
                event: nails_api::Event::Check { name, .. },
                ..
            } => Some(name.clone()),
            _ => None,
        })
        .collect();
    assert!(!streamed.is_empty(), "{events:?}");
    let names: Vec<String> = rows(&envelope)
        .into_iter()
        .filter_map(|(name, _)| name.as_str().map(str::to_string))
        .collect();
    for name in &streamed {
        assert!(names.contains(name), "{name} is not a row of {names:?}");
    }
    helper.close();
}

#[test]
fn a_window_of_another_release_gets_no_operation() {
    let (_dir, config) = scratch_config();
    let mut helper = Helper::start(&config);
    let theirs = Hello {
        protocol: PROTOCOL_VERSION,
        engine: "0.0.0-other".to_string(),
    };
    let (_, answer) = helper.answer(Op::Hello(theirs));
    let Frame::Error { error, .. } = answer else {
        panic!("{answer:?}");
    };
    assert_eq!(error.code, ErrorCode::Handshake);
    assert!(error.message.contains("0.0.0-other"), "{}", error.message);
    // The session is over: the helper reads nothing more and exits 1.
    assert!(helper.frame().is_none());
    assert_eq!(helper.child.wait().unwrap().code(), Some(1));
}

#[test]
fn a_malformed_request_ends_the_session() {
    let (_dir, config) = scratch_config();
    let mut helper = Helper::greeted(&config);
    helper.send_line(r#"{"v":1,"id":2,"op":"reboot"}"#);
    match helper.frame() {
        Some(Frame::Error { id: None, error }) => assert_eq!(error.code, ErrorCode::Malformed),
        other => panic!("{other:?}"),
    }
    assert!(helper.frame().is_none());
    assert_eq!(helper.child.wait().unwrap().code(), Some(1));
}

// ---------------------------------------------------------------------------
// discard: plan, token, apply
// ---------------------------------------------------------------------------

/// The discard through the helper on a tmpfs hidden root, in the kernel tier.
mod kernel_tests {
    use super::*;

    /// Run `body` in a fresh user + mount namespace (see the module docs).
    fn in_namespace(test: &str, body: impl FnOnce()) {
        let _ = Rerun::new(test).in_user_mount_ns().run(body);
    }

    /// A tmpfs hidden root with a state file and a configuration naming it. Build
    /// it inside [`in_namespace`].
    struct Volume {
        _tmpfs: ScratchTmpfs,
        _dir: tempfile::TempDir,
        config: PathBuf,
        root: PathBuf,
    }

    impl Volume {
        fn new() -> Self {
            let tmpfs = ScratchTmpfs::new("");
            let dir = tempfile::tempdir().unwrap();
            let root = tmpfs.path().canonicalize().unwrap();
            let state = root.join("state.json");
            let config = dir.path().join("nails.toml");
            std::fs::write(
                &config,
                format!(
                    "hidden_volume_root = {:?}\nstate_file_path = {:?}\nshow_opsec_reminders = false\n",
                    root.display().to_string(),
                    state.display().to_string()
                ),
            )
            .unwrap();
            let file = StateFile {
                state: SystemState::Inactive,
                ..StateFile::default()
            };
            file.save(&state, root.to_str().unwrap()).unwrap();
            Self {
                _tmpfs: tmpfs,
                _dir: dir,
                config,
                root,
            }
        }

        fn populate(&self, relative: &str) -> PathBuf {
            let dir = self.root.join(relative);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("notes.txt"), "hidden").unwrap();
            dir
        }
    }

    fn plan_of(target: &str) -> Op {
        Op::DiscardPlan(DiscardPlanArgs {
            target: target.to_string(),
            allow_decoy_storage: false,
        })
    }

    fn apply_of(token: &str) -> Op {
        Op::DiscardApply(Token {
            token: token.to_string(),
        })
    }

    /// Plan `target` and return the plan's data.
    fn plan(helper: &mut Helper, target: &str) -> DiscardPlanData {
        let (exit, envelope) = helper.result(plan_of(target));
        assert_eq!(exit, 0, "{envelope}");
        serde_json::from_value(envelope["data"].clone())
            .unwrap_or_else(|e| panic!("{e}: {envelope}"))
    }

    fn refused_token(helper: &mut Helper, op: Op) {
        match helper.answer(op).1 {
            Frame::Error { error, .. } => assert_eq!(error.code, ErrorCode::BadToken),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_discard_deletes_only_with_the_token_of_the_plan_just_made() {
        in_namespace(
            test_path!(a_discard_deletes_only_with_the_token_of_the_plan_just_made),
            || {
                let volume = Volume::new();
                let upper = volume.populate("root/upper/srv/data");
                let layers = volume.populate("root/mounts/srv-data");
                let mut helper = Helper::greeted(&volume.config);

                let first = plan(&mut helper, "/srv/data");
                assert_eq!(first.target, "/srv/data");
                assert_eq!(
                    first.removals,
                    vec![upper.display().to_string(), layers.display().to_string()]
                );
                // Any other request withdraws the plan: its token applies nothing.
                helper.result(Op::Status);
                refused_token(&mut helper, apply_of(&first.token));
                assert!(upper.exists() && layers.exists());

                // A wrong token applies nothing and withdraws the plan as well.
                let second = plan(&mut helper, "/srv/data");
                assert_ne!(second.token, first.token, "every plan has a fresh token");
                refused_token(&mut helper, apply_of(&first.token));
                refused_token(&mut helper, apply_of(&second.token));
                assert!(upper.exists() && layers.exists());

                // The token of the plan just made deletes exactly that plan, and
                // answers as `nails discard --json -y` does.
                let third = plan(&mut helper, "/srv/data");
                let (exit, envelope) = helper.result(apply_of(&third.token));
                assert_eq!(exit, 0, "{envelope}");
                assert_eq!(envelope["command"], "discard");
                assert_eq!(envelope["data"]["target"], "/srv/data");
                assert_eq!(
                    envelope["data"]["removed"],
                    serde_json::json!(third.removals)
                );
                assert!(!upper.exists() && !layers.exists());
                assert!(volume.root.join("root/upper/srv").is_dir());
                // A token is good once.
                refused_token(&mut helper, apply_of(&third.token));
                assert_eq!(helper.close(), 0);
            },
        );
    }

    #[test]
    fn a_plan_holds_the_state_lock_until_the_next_request() {
        in_namespace(
            test_path!(a_plan_holds_the_state_lock_until_the_next_request),
            || {
                let volume = Volume::new();
                volume.populate("root/upper/srv/data");
                let mut helper = Helper::greeted(&volume.config);
                plan(&mut helper, "/srv/data");

                // While the plan waits, the CLI cannot take the lock.
                let (exit, envelope) = cli_json(&volume.config, &["discard", "/srv/data", "-y"]);
                assert_eq!(exit, 1, "{envelope}");
                assert_eq!(envelope["error"]["code"], "state_locked");

                // The next request releases it.
                helper.result(Op::Status);
                let (exit, envelope) = cli_json(&volume.config, &["discard", "/srv/data", "-y"]);
                assert_eq!(exit, 0, "{envelope}");
                helper.close();
            },
        );
    }

    #[test]
    fn a_discard_with_nothing_to_delete_answers_as_the_cli_does_and_hands_out_no_token() {
        in_namespace(
            test_path!(
                a_discard_with_nothing_to_delete_answers_as_the_cli_does_and_hands_out_no_token
            ),
            || {
                let volume = Volume::new();
                let mut helper = Helper::greeted(&volume.config);
                let answer = helper.result(plan_of("/srv/empty"));
                let cli = cli_json(&volume.config, &["discard", "/srv/empty"]);
                assert_eq!(answer, cli);
                assert!(answer.1["data"].get("token").is_none(), "{}", answer.1);
                helper.close();
            },
        );
    }
}
