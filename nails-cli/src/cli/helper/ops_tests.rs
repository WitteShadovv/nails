// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::cli::helper::session::FrameWriter;
use nails_api::protocol::Token;

/// A scratch configuration whose hidden root is a plain directory (no mount
/// point, so the attach gate refuses it).
fn scratch_config() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("hidden");
    std::fs::create_dir_all(&root).unwrap();
    let config = dir.path().join("nails.toml");
    std::fs::write(
        &config,
        format!(
            "hidden_volume_root = {:?}\nstate_file_path = {:?}\n",
            root.display().to_string(),
            root.join("state.json").display().to_string()
        ),
    )
    .unwrap();
    (dir, config)
}

fn events() -> EventOut {
    EventOut::for_test(FrameWriter::new(Box::new(std::io::sink())))
}

fn result(answer: Answer) -> (ExitStatus, serde_json::Value) {
    match answer {
        Answer::Result { exit, envelope } => (exit, envelope),
        Answer::Refused(error) => panic!("refused: {error:?}"),
    }
}

#[test]
fn status_answers_with_the_status_envelope() {
    let (_dir, config) = scratch_config();
    let env = RuntimeEnv::default();
    let mut engine = Engine::new(&env, Some(config));
    let (exit, envelope) = result(engine.run(Op::Status, events()));
    assert_eq!(envelope["command"], "status");
    assert_eq!(envelope["schema_version"], nails_api::SCHEMA_VERSION);
    // The exit follows the posture, as `nails status` exits.
    assert_eq!(envelope["ok"], exit == ExitStatus::Ok, "{envelope}");
}

#[test]
fn a_configuration_that_cannot_be_loaded_answers_as_the_cli_does() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("absent.toml");
    let env = RuntimeEnv::default();
    let mut engine = Engine::new(&env, Some(missing));
    for (op, command) in [
        (Op::Status, "status"),
        (
            Op::DiscardPlan(DiscardPlanArgs {
                target: "/home".to_string(),
                allow_decoy_storage: false,
            }),
            "discard",
        ),
        (Op::Check(CheckArgs::default()), "check"),
    ] {
        let (exit, envelope) = result(engine.run(op, events()));
        assert_eq!(exit, ExitStatus::Config, "{envelope}");
        assert_eq!(envelope["command"], command);
        assert_eq!(envelope["ok"], false);
        assert_eq!(envelope["error"]["code"], "config");
    }
}

#[test]
fn the_config_operations_answer_with_the_config_envelopes() {
    let (_dir, config) = scratch_config();
    let env = RuntimeEnv::default();
    let mut engine = Engine::new(&env, Some(config.clone()));
    let (exit, path) = result(engine.run(Op::ConfigPath, events()));
    assert_eq!(exit, ExitStatus::Ok);
    assert_eq!(path["data"]["path"], config.display().to_string());
    assert_eq!(path["data"]["exists"], true);

    let (exit, valid) = result(engine.run(Op::ConfigValidate, events()));
    assert_eq!(exit, ExitStatus::Ok);
    assert_eq!(valid["data"]["valid"], true);

    let show = Op::ConfigShow(ConfigShowArgs {
        nixos_flake: Some("/srv/cfg#host".to_string()),
    });
    let (exit, shown) = result(engine.run(show, events()));
    assert_eq!(exit, ExitStatus::Ok);
    assert_eq!(shown["command"], "config");
    assert!(
        shown["data"].to_string().contains("/srv/cfg#host"),
        "{shown}"
    );
}

#[test]
fn a_discard_on_a_root_the_gate_refuses_takes_no_lock_and_no_token() {
    let (_dir, config) = scratch_config();
    let env = RuntimeEnv::default();
    let mut engine = Engine::new(&env, Some(config));
    let plan = Op::DiscardPlan(DiscardPlanArgs {
        target: "/home".to_string(),
        allow_decoy_storage: false,
    });
    let (exit, envelope) = result(engine.run(plan, events()));
    assert_eq!(exit, ExitStatus::PreflightRefused, "{envelope}");
    assert_eq!(envelope["ok"], false);
    assert!(engine.pending.is_none());
}

#[test]
fn an_apply_with_no_plan_is_refused() {
    let env = RuntimeEnv::default();
    let mut engine = Engine::new(&env, None);
    let apply = Op::DiscardApply(Token {
        token: "0".repeat(TOKEN_HEX_DIGITS),
    });
    match engine.run(apply, events()) {
        Answer::Refused(error) => assert_eq!(error.code, ErrorCode::BadToken),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_passed_on_hello_is_refused() {
    let env = RuntimeEnv::default();
    let mut engine = Engine::new(&env, None);
    let hello = Op::Hello(super::super::session::our_hello());
    match engine.run(hello, events()) {
        Answer::Refused(error) => assert_eq!(error.code, ErrorCode::Handshake),
        other => panic!("{other:?}"),
    }
}

#[test]
fn tokens_are_fresh_lowercase_hex_of_the_protocol_length() {
    let first = random_token().unwrap();
    let second = random_token().unwrap();
    assert_ne!(first, second);
    for token in [&first, &second] {
        let op = Op::DiscardApply(Token {
            token: token.clone(),
        });
        assert_eq!(nails_api::protocol::validate(&op), Ok(()), "{token}");
    }
}
