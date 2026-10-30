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

/// A deactivation ready to leave a hidden session whose decoy runs no NixOS,
/// its hidden volume, state file and way-back root below `root`, which the
/// attach gate refuses: a test can plan it, and its apply never leaves.
fn ready_at(root: &Path) -> nails_core::app::deactivate::ReadyDeactivation {
    use nails_teardown::whole_root::plan::{PLAN_VERSION, Plan};
    let plan = serde_json::json!({
        "version": PLAN_VERSION,
        "hidden_root": "/mnt/data",
        "upper": "/mnt/data/root/upper",
        "work": "/mnt/data/root/work",
        "decoy_root": {"source": "/dev/vda2", "fstype": "ext4"},
        "decoy": {"init": "/sbin/init"},
        "hidden": {"init": "/sbin/init"},
    });
    let config = nails_core::Config {
        hidden_volume_root: root.to_path_buf(),
        state_file_path: root.join("state.json"),
        log_path: root.join("logs"),
        ..nails_core::Config::test_default()
    };
    let plan = Plan::from_json(&plan.to_string()).expect("a minimal plan");
    nails_core::app::deactivate::ReadyDeactivation::for_test(config, plan, root)
}

/// With a way back, each ending is planned with its token and the warnings a
/// person reads before the question, and the plan waits for its apply.
#[test]
fn a_deactivation_with_a_way_back_is_planned_for_each_ending() {
    use nails_core::app::deactivate::Prepared;
    let root = tempfile::tempdir().unwrap();
    let env = RuntimeEnv::default();
    let mut engine = Engine::new(&env, None);
    for (poweroff, to) in [(false, LeaveTo::Decoy), (true, LeaveTo::Poweroff)] {
        let ready = ready_at(root.path());
        let warnings = ready.warnings(to, &ready.foresee(to));
        let prepared = Prepared::Ready(Box::new(ready));
        let (exit, envelope) =
            result(engine.deactivate_plan_from(&DeactivateArgs { poweroff }, prepared));
        assert_eq!(exit, ExitStatus::Ok, "{envelope}");
        assert_eq!(envelope["command"], "deactivate");
        let data = &envelope["data"];
        assert_eq!(data["poweroff"], poweroff, "{envelope}");
        assert_eq!(data["warnings"], serde_json::json!(warnings), "{envelope}");
        let token = data["token"].as_str().expect("a token");
        assert_eq!(token.len(), nails_api::protocol::TOKEN_HEX_DIGITS);
        assert!(engine.has_plan());
    }
    // Without tools below the root, the return warns and the power-off not.
    let ready = ready_at(root.path());
    assert!(
        !ready
            .warnings(LeaveTo::Decoy, &ready.foresee(LeaveTo::Decoy))
            .is_empty()
    );
    assert!(
        ready
            .warnings(LeaveTo::Poweroff, &ready.foresee(LeaveTo::Poweroff))
            .is_empty()
    );
}

/// A tree at `root` as the way back reads it: the entry's record of the
/// decoy's links (`lo` alone), and now `lo` and `link`, which the session
/// made. No `ip` lies below `root`.
fn links_at(root: &Path, link: &str) {
    use nails_teardown::whole_root::network::{
        NetTools, NetworkRecord, Places, RECORD_NAME, SYS_CLASS_NET,
    };
    use nails_teardown::whole_root::plan::RUNTIME_DIR;
    let below = |path: &str| root.join(path.trim_start_matches('/'));
    let add = |name: &str, index: u32| {
        let dir = below(SYS_CLASS_NET).join(name);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ifindex"), format!("{index}\n")).unwrap();
    };
    add("lo", 1);
    let places = Places {
        run: below("/run"),
        sys_class_net: below(SYS_CLASS_NET),
        proc_hostname: below("/proc/sys/kernel/hostname"),
        proc_sys: below("/proc/sys"),
    };
    let record = NetworkRecord::capture(&places, &NetTools::default()).encode();
    std::fs::create_dir_all(below(RUNTIME_DIR)).unwrap();
    std::fs::write(below(RUNTIME_DIR).join(RECORD_NAME), record).unwrap();
    add(link, 2);
}

/// A return the way back turns into a power-off says why in a field of its
/// own, as the CLI's question says it: certain for a link the kernel keeps,
/// unless that changes for one it deletes with an `ip` it does not find. The
/// plan of a power-off has none.
#[test]
fn a_return_bound_to_power_off_says_why_in_its_plan() {
    use nails_core::app::deactivate::{Prepared, power_off_reason};
    let env = RuntimeEnv::default();
    for (link, certain) in [("tunl0", true), ("veth0", false)] {
        let root = tempfile::tempdir().unwrap();
        links_at(root.path(), link);
        let mut engine = Engine::new(&env, None);
        let ready = ready_at(root.path());
        let reason = power_off_reason(&ready.foresee(LeaveTo::Decoy)).expect("bound");
        assert_eq!(reason.certain, certain, "{link}");
        let (exit, envelope) = result(
            engine
                .deactivate_plan_from(&DeactivateArgs::default(), Prepared::Ready(Box::new(ready))),
        );
        assert_eq!(exit, ExitStatus::Ok, "{envelope}");
        let data = &envelope["data"];
        assert_eq!(
            data["powers_off_instead"],
            serde_json::json!({"what": reason.what, "certain": certain}),
            "{envelope}"
        );
        assert!(
            data["warnings"][0]
                .as_str()
                .is_some_and(|first| first.starts_with(&reason.what)),
            "{envelope}"
        );
        // The plan of a power-off has nothing to say about a return.
        let (_, envelope) = result(engine.deactivate_plan_from(
            &DeactivateArgs { poweroff: true },
            Prepared::Ready(Box::new(ready_at(root.path()))),
        ));
        assert_eq!(
            envelope["data"]["powers_off_instead"],
            serde_json::Value::Null
        );
    }
    // A way back with nothing to undo has no reason.
    let root = tempfile::tempdir().unwrap();
    let mut engine = Engine::new(&env, None);
    let (_, envelope) = result(engine.deactivate_plan_from(
        &DeactivateArgs::default(),
        Prepared::Ready(Box::new(ready_at(root.path()))),
    ));
    assert_eq!(
        envelope["data"]["powers_off_instead"],
        serde_json::Value::Null
    );
}

/// The apply of a planned deactivation is the CLI's lock and leave: here the
/// lock, whose gate refuses the plain directory, answers, never the token.
#[test]
fn the_apply_of_a_planned_deactivation_takes_the_lock_as_the_cli_does() {
    use nails_core::app::deactivate::Prepared;
    let root = tempfile::tempdir().unwrap();
    let env = RuntimeEnv::default();
    let mut engine = Engine::new(&env, None);
    let prepared = Prepared::Ready(Box::new(ready_at(root.path())));
    let (_, plan) = result(engine.deactivate_plan_from(&DeactivateArgs::default(), prepared));
    let token = plan["data"]["token"].as_str().unwrap().to_string();
    let (exit, envelope) = result(engine.run(Op::DeactivateApply(Token { token }), events()));
    assert_eq!(exit, ExitStatus::PreflightRefused, "{envelope}");
    assert_eq!(envelope["command"], "deactivate");
    assert_eq!(envelope["ok"], false);
    assert!(!engine.has_plan(), "an apply spends the plan");
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
