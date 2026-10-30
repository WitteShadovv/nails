// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The `emergency` operation: the way back right now.
//!
//! The hot path itself lives in `nails-teardown` (`whole_root::emergency`) and
//! normally runs from `main` before the CLI is initialised, as root. This
//! wraps it for the late or non-root invocation ([`run_hot_path`]), classifies
//! the outcome into an exit code and the machine-readable payload, and records
//! the session inactive while the hidden volume is still reachable. A front end
//! prints the report and the timed phases; the countdown, being terminal UX, is
//! the front end's.

use std::path::Path;

use nails_api::ExitStatus;
use nails_teardown::whole_root::emergency::{self, Finish, HotReport, Side};
use nails_teardown::whole_root::network::Foreseen;
use nails_teardown::whole_root::plan::{Plan, default_plan_path};
use serde::Serialize;

use crate::{NailsManager, RealFilesystem, RuntimeEnv, SystemState};

/// Run the emergency hot path in this process, for a late or non-root
/// invocation (the root fast path ran earlier, before the CLI).
///
/// Without root nothing may be touched, so the hot path only judges the plan:
/// `host.act` follows the effective uid, and a non-root run reports what it
/// would do without doing it.
pub fn run_hot_path(finish: Finish) -> HotReport {
    let _ = std::env::set_current_dir("/");
    let plan = Plan::load(&default_plan_path()).ok();
    let mut host = emergency::Host::system();
    host.act = nix::unistd::geteuid().is_root();
    emergency::run(plan, &host, finish)
}

/// What the way back the hot path enqueued is bound to leave of the links and
/// MAC addresses as they are once the hidden programs are killed, which makes
/// its last step power off instead of returning
/// ([`way_back_foresees`](crate::session::leave::way_back_foresees)).
/// Nothing unless the hot path enqueued a return from the hidden root.
pub fn foresee(report: &HotReport) -> Foreseen {
    if report.side != Side::Hidden || report.dispatched != Some(Finish::Return) {
        return Foreseen::default();
    }
    let decoy_system = Plan::load(&default_plan_path())
        .ok()
        .and_then(|plan| plan.decoy.system);
    crate::session::leave::way_back_foresees(Path::new("/"), decoy_system.as_deref())
}

/// The exit status for a hot-path report.
///
/// - [`ExitStatus::Ok`] when the way back or the power action was enqueued, or
///   there was nothing to do;
/// - [`ExitStatus::DegradedReboot`] when a decoy-side cleanup left mounts below
///   `/run/nextroot`, or only the kernel could be asked to power off;
/// - [`ExitStatus::Failed`] when nothing at all could be dispatched.
pub fn exit_status(report: &HotReport) -> ExitStatus {
    match report.side {
        Side::None if report.requested == Finish::Return => ExitStatus::Ok,
        _ if !report.remaining.is_empty() => ExitStatus::DegradedReboot,
        Side::Decoy if report.requested == Finish::Return => ExitStatus::Ok,
        _ if report.dispatched.is_some() => ExitStatus::Ok,
        _ if report.kernel_power_off => ExitStatus::DegradedReboot,
        _ => ExitStatus::Failed,
    }
}

/// Record the session as inactive, best-effort, while the hidden volume is
/// still reachable. The live facts (`status` probes them) are authoritative.
pub fn record_inactive(env: &RuntimeEnv, report: &HotReport, config_override: Option<&Path>) {
    if report.side == Side::None {
        return;
    }
    let (config, _) = super::config::load_config_for_teardown(config_override);
    let state_path = config.state_file_path.clone();
    let mut manager =
        NailsManager::new(RealFilesystem, config, state_path).with_runtime_env(env.clone());
    if let Err(e) = manager.force_state(SystemState::Inactive) {
        tracing::debug!(error = %e, "could not record the inactive state after the emergency");
    }
}

/// The hidden backend's device-mapper devices the hot path could not mark
/// for deferred removal, top first: they stay open after the switch, their
/// key in RAM, until power-off.
pub fn backend_left_open(report: &HotReport) -> Vec<String> {
    report
        .deferred
        .iter()
        .filter(|(_, marked)| !marked)
        .map(|(name, _)| name.clone())
        .collect()
}

/// The name of a finish on the wire.
pub fn finish_name(finish: Finish) -> &'static str {
    match finish {
        Finish::Return => "return_to_decoy",
        Finish::Reboot => "reboot",
        Finish::Poweroff => "poweroff",
    }
}

fn side_name(side: Side) -> &'static str {
    match side {
        Side::Hidden => "hidden",
        Side::Decoy => "decoy",
        Side::None => "none",
    }
}

/// One timed phase of the hot path on the wire.
#[derive(Debug, Serialize)]
pub struct PhaseData {
    name: &'static str,
    ms: u64,
}

/// The machine-readable payload of an emergency run.
#[derive(Debug, Serialize)]
pub struct EmergencyData {
    /// Where the emergency ran: `hidden`, `decoy` or `none`.
    side: &'static str,
    /// What was asked for.
    requested: &'static str,
    /// What was enqueued (`null` when nothing was).
    dispatched: Option<&'static str>,
    /// Why the request was replaced, if it was.
    fallback: Option<String>,
    /// Whether the kernel was asked to power off directly.
    kernel_power_off: bool,
    /// Device-mapper names marked for deferred removal.
    backend_closing: Vec<String>,
    /// Device-mapper names whose mark for deferred removal did not take: they
    /// stay open after the switch, their key in RAM, until power-off.
    backend_left_open: Vec<String>,
    /// cgroups killed.
    cgroups_killed: usize,
    /// Processes killed one by one.
    processes_killed: usize,
    /// Mounts still below `/run/nextroot` after a decoy-side cleanup.
    remaining_mounts: Vec<String>,
    /// The timed phases, in order.
    phases: Vec<PhaseData>,
    /// The whole hot path, in milliseconds.
    elapsed_ms: u64,
}

/// Build the machine-readable payload from a hot-path report.
pub fn data(report: &HotReport) -> EmergencyData {
    EmergencyData {
        side: side_name(report.side),
        requested: finish_name(report.requested),
        dispatched: report.dispatched.map(finish_name),
        fallback: report.fallback.clone(),
        kernel_power_off: report.kernel_power_off,
        backend_closing: report
            .deferred
            .iter()
            .filter(|(_, ok)| *ok)
            .map(|(n, _)| n.clone())
            .collect(),
        backend_left_open: backend_left_open(report),
        cgroups_killed: report.kill.cgroups.len(),
        processes_killed: report.kill.processes.len(),
        remaining_mounts: report
            .remaining
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        phases: report
            .phases
            .iter()
            .map(|(name, d)| PhaseData {
                name,
                ms: u64::try_from(d.as_millis()).unwrap_or(u64::MAX),
            })
            .collect(),
        elapsed_ms: u64::try_from(report.elapsed.as_millis()).unwrap_or(u64::MAX),
    }
}

#[cfg(test)]
mod tests {
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

    /// Only a return from the hidden root has a way back to foresee.
    #[test]
    fn only_a_return_from_the_hidden_root_foresees_its_way_back() {
        let report = simulated(None, Finish::Return);
        assert_eq!(foresee(&report), Foreseen::default());
        let mut hidden = simulated(None, Finish::Poweroff);
        hidden.side = Side::Hidden;
        assert_eq!(foresee(&hidden), Foreseen::default());
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

    /// A device whose mark did not take is named apart from those that are
    /// closing, never dropped: it stays open after the switch.
    #[test]
    fn a_device_left_open_is_named_apart_from_those_closing() {
        let mut r = report(
            Side::Hidden,
            Finish::Return,
            Some(Finish::Return),
            vec![],
            false,
        );
        r.deferred = vec![("top".to_string(), false), ("lower".to_string(), true)];
        assert_eq!(backend_left_open(&r), ["top"]);
        let json = serde_json::to_value(data(&r)).unwrap();
        assert_eq!(json["backend_closing"], serde_json::json!(["lower"]));
        assert_eq!(json["backend_left_open"], serde_json::json!(["top"]));

        r.deferred = vec![("top".to_string(), true)];
        assert!(backend_left_open(&r).is_empty());
        let json = serde_json::to_value(data(&r)).unwrap();
        assert_eq!(json["backend_left_open"], serde_json::json!([]));
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
}
