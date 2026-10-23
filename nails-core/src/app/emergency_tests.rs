// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Unit tests for the `emergency` operation: the exit status of a hot-path
//! report, its payload and the inactive record.

use super::*;
use nails_teardown::whole_root::plan::Plan;

fn simulated(plan: Option<Plan>, finish: Finish) -> HotReport {
    let dir = tempfile::tempdir().unwrap();
    let host = emergency::Host {
        run: dir.path().join("run"),
        nextroot: dir.path().join("run/nextroot"),
        runtime_dir: dir.path().join("run/overlay-runtime"),
        cgroup_root: dir.path().join("cgroup"),
        protected_pids: Vec::new(),
        act: false,
    };
    emergency::run(plan, &host, finish)
}

#[test]
fn without_a_session_emergency_succeeds() {
    let report = simulated(None, Finish::Return);
    assert_eq!(exit_status(&report), ExitStatus::Ok);
}

#[test]
fn a_power_action_is_reported_on_every_side() {
    let report = simulated(None, Finish::Poweroff);
    assert_eq!(report.dispatched, Some(Finish::Poweroff));
    assert_eq!(exit_status(&report), ExitStatus::Ok);
    let json = serde_json::to_value(data(&report)).unwrap();
    assert_eq!(json["requested"], "poweroff");
    assert_eq!(json["dispatched"], "poweroff");
    assert!(
        json["phases"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "enqueue")
    );
}

#[test]
fn the_json_names_no_product_and_carries_the_timings() {
    let report = simulated(None, Finish::Reboot);
    let text = serde_json::to_string(&data(&report)).unwrap();
    assert!(!text.to_lowercase().contains("nails"), "{text}");
    assert!(text.contains("\"elapsed_ms\""));
}

/// A hot-path report with the fields [`exit_status`] classifies set
/// explicitly, built on a real simulated report so the untouched fields
/// (the kill tally, the phases, the elapsed time) stay well-formed.
fn report(
    side: Side,
    requested: Finish,
    dispatched: Option<Finish>,
    remaining: Vec<std::path::PathBuf>,
    kernel_power_off: bool,
) -> HotReport {
    let mut report = simulated(None, Finish::Return);
    report.side = side;
    report.requested = requested;
    report.dispatched = dispatched;
    report.remaining = remaining;
    report.kernel_power_off = kernel_power_off;
    report
}

/// Without a session plan, the success-is-Ok shortcut is only for the
/// return; a reboot that nothing could enqueue (and no kernel power-off)
/// has failed, so it must not read as Ok.
#[test]
fn no_session_with_a_power_action_that_could_not_run_fails() {
    let r = report(Side::None, Finish::Reboot, None, vec![], false);
    assert_eq!(exit_status(&r), ExitStatus::Failed);
}

/// Mounts still below `/run/nextroot` after a decoy-side cleanup are a
/// degraded reboot even when a plain return was asked for and would
/// otherwise have been Ok.
#[test]
fn remaining_mounts_force_a_degraded_reboot() {
    let r = report(
        Side::Decoy,
        Finish::Return,
        None,
        vec![std::path::PathBuf::from("/run/nextroot/stuck")],
        false,
    );
    assert_eq!(exit_status(&r), ExitStatus::DegradedReboot);
}

/// A clean decoy-side way back, nothing left below `/run/nextroot`, is Ok.
#[test]
fn a_clean_decoy_side_return_is_ok() {
    let r = report(Side::Decoy, Finish::Return, None, vec![], false);
    assert_eq!(exit_status(&r), ExitStatus::Ok);
}

/// The decoy Ok is only for the return: a power action the decoy could not
/// enqueue (nothing dispatched, no kernel power-off) has failed.
#[test]
fn a_decoy_power_action_that_could_not_run_fails() {
    let r = report(Side::Decoy, Finish::Reboot, None, vec![], false);
    assert_eq!(exit_status(&r), ExitStatus::Failed);
}

/// With nothing enqueued and no kernel power-off, the status falls all the
/// way through to Failed rather than an optimistic Ok or degraded reboot.
#[test]
fn nothing_dispatched_and_no_kernel_power_off_is_failed() {
    let r = report(Side::Hidden, Finish::Reboot, None, vec![], false);
    assert_eq!(exit_status(&r), ExitStatus::Failed);
}

/// When only the kernel could be asked to power off, the run is a degraded
/// reboot, not a failure.
#[test]
fn a_kernel_only_power_off_is_a_degraded_reboot() {
    let r = report(Side::Hidden, Finish::Reboot, None, vec![], true);
    assert_eq!(exit_status(&r), ExitStatus::DegradedReboot);
}

/// The wire names for each side are a stable contract read by `data`.
#[test]
fn side_name_is_the_wire_contract_for_each_side() {
    assert_eq!(side_name(Side::Hidden), "hidden");
    assert_eq!(side_name(Side::Decoy), "decoy");
    assert_eq!(side_name(Side::None), "none");
}

/// `record_inactive` writes the inactive state exactly when a session was
/// found (any side but `None`), and does nothing when there was none. The
/// write goes through the real filesystem to the configured state file, so
/// the file's presence and contents are the observable effect.
#[test]
fn record_inactive_writes_inactive_only_when_a_session_existed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let config_path = root.join("nails.toml");
    let state_path = root.join("state.json");
    std::fs::write(
        &config_path,
        format!(
            "hidden_volume_root = \"{}\"\nstate_file_path = \"{}\"\n",
            root.display(),
            state_path.display(),
        ),
    )
    .unwrap();
    let env = RuntimeEnv::default();

    // No session plan: nothing is recorded.
    let no_session = report(Side::None, Finish::Return, None, vec![], false);
    record_inactive(&env, &no_session, Some(config_path.as_path()));
    assert!(
        !state_path.exists(),
        "no session was found, so no state must be written"
    );

    // A session was torn down: the inactive state is recorded.
    let torn_down = report(Side::Decoy, Finish::Return, None, vec![], false);
    record_inactive(&env, &torn_down, Some(config_path.as_path()));
    assert!(
        state_path.exists(),
        "a session was torn down, so the inactive state must be written"
    );
    let saved = crate::StateFile::load(&state_path).unwrap();
    assert_eq!(saved.state, SystemState::Inactive);
}
