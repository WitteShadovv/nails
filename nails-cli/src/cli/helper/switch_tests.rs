// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::PathBuf;

use super::*;
use crate::cli::helper::session::{Dispatch, FrameWriter};
use nails_api::protocol::{Op, Token};

/// A scratch configuration whose hidden root is a plain directory, which the
/// attach gate refuses.
fn scratch_config() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("hidden");
    std::fs::create_dir_all(&root).unwrap();
    let config = dir.path().join("nails.toml");
    write_config(&config, &root);
    (dir, config)
}

fn write_config(config: &Path, root: &Path) {
    std::fs::write(
        config,
        format!(
            "hidden_volume_root = {:?}\nstate_file_path = {:?}\nshow_opsec_reminders = false\n",
            root.display().to_string(),
            root.join("state.json").display().to_string()
        ),
    )
    .unwrap();
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

/// Whether this test runs as root, where `emergency` and `recover` would act
/// on the host.
fn running_as_root() -> bool {
    nix::unistd::geteuid().is_root()
}

#[test]
fn an_activation_the_gate_refuses_answers_as_the_cli_and_plans_nothing() {
    let (_dir, config) = scratch_config();
    let env = RuntimeEnv::default();
    let mut engine = Engine::new(&env, Some(config));
    let (exit, envelope) = result(engine.activate_plan(&ActivateArgs::default()));
    assert_eq!(exit, ExitStatus::PreflightRefused, "{envelope}");
    assert_eq!(envelope["command"], "activate");
    assert_eq!(envelope["ok"], false);
    assert!(envelope["data"].get("token").is_none(), "{envelope}");
    assert!(!engine.has_plan());
}

#[test]
fn a_deactivation_off_the_hidden_root_answers_as_the_cli_and_plans_nothing() {
    let (_dir, config) = scratch_config();
    let env = RuntimeEnv::default();
    let mut engine = Engine::new(&env, Some(config));
    for poweroff in [false, true] {
        let (exit, envelope) = result(engine.deactivate_plan(&DeactivateArgs { poweroff }));
        assert_eq!(exit, ExitStatus::InvalidState, "{envelope}");
        assert_eq!(envelope["command"], "deactivate");
        assert_eq!(envelope["error"]["code"], "invalid_state");
        assert_eq!(envelope["error"]["next"]["command"], "recover");
        assert!(!engine.has_plan());
    }
}

#[test]
fn emergency_and_recover_without_a_session_answer_as_the_cli() {
    if running_as_root() {
        eprintln!("skipped: as root emergency and recover would act on this host");
        return;
    }
    let (_dir, config) = scratch_config();
    let env = RuntimeEnv::default();
    for (args, requested) in [
        (EmergencyArgs::default(), "return_to_decoy"),
        (
            EmergencyArgs {
                poweroff: true,
                reboot: false,
            },
            "poweroff",
        ),
        (
            EmergencyArgs {
                poweroff: false,
                reboot: true,
            },
            "reboot",
        ),
    ] {
        let (exit, envelope) = result(emergency(&env, &args, Some(&config)));
        assert_eq!(exit, ExitStatus::Ok, "{envelope}");
        assert_eq!(envelope["command"], "emergency");
        assert_eq!(envelope["data"]["side"], "none", "{envelope}");
        assert_eq!(envelope["data"]["requested"], requested, "{envelope}");
    }
    let (exit, envelope) = result(recover(&env, Some(&config)));
    assert_eq!(exit, ExitStatus::Ok, "{envelope}");
    assert_eq!(envelope["command"], "recover");
    assert_eq!(envelope["data"]["outcome"], "clean", "{envelope}");
}

/// The activations that need the attach gate to accept the hidden root: each
/// runs in an unprivileged user + mount namespace with a tmpfs as the root.
mod kernel_tests {
    use super::*;
    use nails_core::test_path;
    use nails_core::test_support::{Rerun, ScratchTmpfs};
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    /// A window that is gone by the time its activation's apply arrives
    /// cancels it before anything is entered: the answer is the CLI's cancel,
    /// the lock is released and no state is recorded.
    #[test]
    fn an_activation_whose_window_is_gone_is_cancelled_before_it_enters() {
        let _ = Rerun::new(test_path!(
            an_activation_whose_window_is_gone_is_cancelled_before_it_enters
        ))
        .in_user_mount_ns()
        .run(|| {
            let volume = ScratchTmpfs::new("");
            let dir = tempfile::tempdir().unwrap();
            let config = dir.path().join("nails.toml");
            write_config(&config, volume.path());
            let (ours, theirs) = UnixStream::pair().unwrap();
            let env = RuntimeEnv::default();
            let mut engine = Engine::new(&env, Some(config.clone())).watching(OwnedFd::from(ours));
            let args = ActivateArgs {
                overlay_only: true,
                ..ActivateArgs::default()
            };
            let (exit, plan) = result(engine.activate_plan(&args));
            assert_eq!(exit, ExitStatus::Ok, "{plan}");
            let token = plan["data"]["token"].as_str().expect("a token").to_string();
            assert_eq!(plan["data"]["builds_hidden_system"], false, "{plan}");
            assert!(engine.has_plan());

            drop(theirs);
            let (exit, envelope) = result(engine.run(Op::ActivateApply(Token { token }), events()));
            assert_eq!(exit, ExitStatus::Cancelled, "{envelope}");
            assert_eq!(envelope["command"], "activate");
            assert_eq!(envelope["error"]["code"], "cancelled", "{envelope}");
            assert!(!engine.has_plan());
            let state = volume.path().join("state.json");
            if state.exists() {
                let recorded = nails_core::StateFile::load(&state).unwrap().state;
                assert_eq!(
                    recorded,
                    nails_core::SystemState::Inactive,
                    "no session recorded"
                );
            }
            // The lock went with the plan: a second plan takes it again.
            let (exit, again) = result(engine.activate_plan(&args));
            assert_eq!(exit, ExitStatus::Ok, "{again}");
        });
    }
}
