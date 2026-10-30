// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::cli::helper::session::{Dispatch, EventOut, FrameWriter};
use crate::cli::output::ExitStatus;
use nails_api::protocol::{Op, Token};

/// A scratch configuration whose hidden root is a plain directory.
fn scratch_config() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("hidden");
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
fn an_offline_verify_answers_with_the_verify_envelope() {
    let (_dir, config) = scratch_config();
    let image = tempfile::tempdir().unwrap();
    let args = VerifyArgs {
        offline: true,
        root: Some(image.path().display().to_string()),
        ..VerifyArgs::default()
    };
    let (exit, envelope) = result(verify(&RuntimeEnv::default(), &args, Some(&config)));
    assert_eq!(envelope["command"], "verify", "{envelope}");
    assert_eq!(envelope["ok"], exit == ExitStatus::Ok, "{envelope}");
    assert!(envelope["data"].get("examiner").is_none(), "{envelope}");
}

#[test]
fn the_rehearsal_status_and_a_reset_without_one_answer_as_the_cli() {
    let (_dir, config) = scratch_config();
    let env = RuntimeEnv::default();
    let (exit, status) = result(rehearse(&env, RehearseStep::Status, Some(&config)));
    assert_eq!(exit, ExitStatus::Ok, "{status}");
    assert_eq!(status["command"], "rehearse");
    assert_eq!(status["data"]["phase"], "none", "{status}");
    let (exit, reset) = result(rehearse(&env, RehearseStep::Reset, Some(&config)));
    assert_ne!(exit, ExitStatus::Ok, "{reset}");
    assert_eq!(reset["ok"], false, "{reset}");
}

#[test]
fn the_steps_carry_every_argument_over() {
    let RehearseStep::Plant(plant) = plant_step(&RehearsePlantArgs {
        user: Some("alice".to_string()),
    }) else {
        panic!("not a plant");
    };
    assert_eq!(plant.user.as_deref(), Some("alice"));
    let RehearseStep::Scan(scan) = scan_step(&RehearseScanArgs {
        devices: vec!["/dev/sda".to_string()],
        offline: false,
        images: vec!["/srv/a.raw".to_string()],
        token_file: Some("/srv/token".to_string()),
        allow_same_boot: true,
        max_bytes: Some(7),
    }) else {
        panic!("not a scan");
    };
    assert_eq!(scan.devices, vec![PathBuf::from("/dev/sda")]);
    assert_eq!(scan.images, vec![PathBuf::from("/srv/a.raw")]);
    assert_eq!(scan.token_file, Some(PathBuf::from("/srv/token")));
    assert!(scan.allow_same_boot && !scan.offline);
    assert_eq!(scan.max_bytes, Some(7));
    let init = init_args(&InitArgs {
        path: "/mnt/data".to_string(),
        allow_decoy_storage: true,
        hardware_config: Some("/etc/hw.nix".to_string()),
        no_hardware_config: false,
    });
    assert_eq!(init.path, PathBuf::from("/mnt/data"));
    assert!(init.allow_decoy_storage && !init.no_hardware_config);
    assert_eq!(init.hardware_config, Some(PathBuf::from("/etc/hw.nix")));
}

#[test]
fn an_init_the_gate_refuses_answers_as_the_cli_and_plans_nothing() {
    let target = tempfile::tempdir().unwrap();
    let env = RuntimeEnv::default();
    let mut engine = Engine::new(&env, None);
    let args = InitArgs {
        path: target.path().display().to_string(),
        allow_decoy_storage: false,
        hardware_config: None,
        no_hardware_config: true,
    };
    let (exit, envelope) = result(engine.init_plan(&args));
    assert_eq!(exit, ExitStatus::PreflightRefused, "{envelope}");
    assert_eq!(envelope["command"], "init");
    assert!(!engine.has_plan());
    assert_eq!(std::fs::read_dir(target.path()).unwrap().count(), 0);
}

/// Init on a volume the attach gate accepts, in an unprivileged user + mount
/// namespace with a tmpfs as the volume.
mod kernel_tests {
    use super::*;
    use nails_core::test_path;
    use nails_core::test_support::{Rerun, ScratchTmpfs};

    #[test]
    fn an_init_plan_writes_nothing_and_its_apply_lays_the_volume_out() {
        let _ = Rerun::new(test_path!(
            an_init_plan_writes_nothing_and_its_apply_lays_the_volume_out
        ))
        .in_user_mount_ns()
        .run(|| {
            let volume = ScratchTmpfs::new("");
            let env = RuntimeEnv::default();
            let mut engine = Engine::new(&env, None);
            let args = InitArgs {
                path: volume.path().display().to_string(),
                allow_decoy_storage: false,
                hardware_config: None,
                no_hardware_config: true,
            };
            let (exit, plan) = result(engine.init_plan(&args));
            assert_eq!(exit, ExitStatus::Ok, "{plan}");
            assert_eq!(plan["command"], "init");
            assert_eq!(plan["data"]["path"], args.path.as_str(), "{plan}");
            assert!(plan["data"]["hardware_config"].is_null(), "{plan}");
            assert!(plan["data"]["skipped"].is_string(), "{plan}");
            let token = plan["data"]["token"].as_str().unwrap().to_string();
            assert_eq!(std::fs::read_dir(volume.path()).unwrap().count(), 0);

            let (exit, done) = result(engine.run(Op::InitApply(Token { token }), events()));
            assert_eq!(exit, ExitStatus::Ok, "{done}");
            assert_eq!(done["ok"], true, "{done}");
            assert!(volume.path().join("config").is_dir(), "{done}");
            assert!(!engine.has_plan());
        });
    }
}
