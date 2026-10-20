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
}
