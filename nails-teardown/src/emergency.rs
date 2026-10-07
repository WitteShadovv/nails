// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The emergency hot path: from the plan to the last unmount.
//!
//! The order is fixed (ADR 0007):
//!
//! 1. enqueue a stop job for every unit about to die, so `Restart=` cannot
//!    revive it on the decoy after the detach;
//! 2. `cgroup.kill` the units the hidden configuration added, and the service
//!    cgroup of every process outside the graphical session that can still
//!    write through a NAILS mount; SIGKILL any other such process through a
//!    pidfd;
//! 3. SIGKILL every interactive shell outside this invocation;
//! 4. wait, bounded, for the killed cgroups and processes to be gone;
//! 5. hand the journal back to `/run` when `/var` is overlaid;
//! 6. undo the plan in reverse and reconcile against the mount table.
//!
//! Nothing in it reads the hidden volume, writes to a decoy filesystem, asks
//! logind, or runs a child other than the bounded `systemctl` and `journalctl`
//! of [`crate::units`]. The bookkeeping (state file, journald and nix-daemon
//! restarts, the runtime journal scrub, the power action) is the caller's and
//! comes after.

use crate::cgroup;
use crate::mountinfo::{NailsMounts, read_mountinfo, read_mountinfo_at};
use crate::mounts::MountOps;
use crate::plan::{Phase, Plan, Tool};
use crate::proc::{self, Invocation, ProcessHandle};
use crate::refs;
use crate::session::SpareSet;
use crate::shells;
use crate::undo::{UndoReport, remaining, run_plan};
use crate::units;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How long the kills may take to drain before the unmounts start anyway.
pub const KILL_DRAIN_BUDGET: Duration = Duration::from_millis(500);

/// Where the plan came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanSource {
    /// The plan activation recorded.
    Recorded,
    /// Rebuilt from the mount table; the string says why the recorded one could
    /// not be used.
    Derived(String),
}

/// What the hot path may do to processes and units. `None` in a caller that must
/// not touch the host (a test, or the runtime-safety mode): the plan's mounts
/// are still undone through the [`MountOps`] the caller passes.
#[derive(Debug, Clone)]
pub struct Host {
    /// `systemctl`, from the plan or resolved by the caller.
    pub systemctl: Option<Tool>,
    /// `journalctl`, from the plan or resolved by the caller.
    pub journalctl: Option<Tool>,
    /// System services whose processes are never killed (the caller's own
    /// supervision, named explicitly).
    pub spared_units: Vec<String>,
    /// Further pids never to kill.
    pub protected_pids: Vec<u32>,
    /// logind's session records (see [`crate::session`]).
    pub sessions_dir: PathBuf,
    /// The unified cgroup hierarchy.
    pub cgroup_root: PathBuf,
}

impl Host {
    /// The host as a real system lays it out, with the tools from `plan`.
    pub fn system(plan: &Plan) -> Self {
        Self {
            systemctl: plan.tools.systemctl.clone(),
            journalctl: plan.tools.journalctl.clone(),
            spared_units: Vec::new(),
            protected_pids: Vec::new(),
            sessions_dir: PathBuf::from(crate::session::SESSIONS_DIR),
            cgroup_root: PathBuf::from(cgroup::CGROUP_ROOT),
        }
    }
}

/// What the hot path did.
#[derive(Debug, Clone, Default)]
pub struct HotReport {
    /// Where the plan came from (`None` only in a default report).
    pub source: Option<PlanSource>,
    /// The plan that was executed.
    pub plan: Option<Plan>,
    /// Units a stop job was enqueued for.
    pub units_stopped: Vec<String>,
    /// Whether the stop jobs were enqueued (`None` when none were needed).
    pub stop_enqueued: Option<bool>,
    /// cgroups killed.
    pub cgroups_killed: Vec<PathBuf>,
    /// cgroups still populated when the drain budget ran out.
    pub cgroups_still_populated: Vec<PathBuf>,
    /// Processes killed one by one through a pidfd.
    pub processes_killed: Vec<u32>,
    /// Interactive shells killed.
    pub shells_killed: Vec<u32>,
    /// Killed processes still alive when the drain budget ran out.
    pub processes_still_alive: Vec<u32>,
    /// Processes spared because they belong to the graphical session.
    pub session_processes_spared: usize,
    /// Whether the journal was handed back to `/run` (`None` when `/var` was not
    /// overlaid or no `journalctl` was known).
    pub journal_relinquished: Option<bool>,
    /// The undo of the plan.
    pub undo: UndoReport,
    /// NAILS mounts still in the table afterwards.
    pub remaining: Vec<PathBuf>,
    /// Whether `/nix` was overlaid (nix-daemon needs a start afterwards).
    pub nix_overlaid: bool,
    /// Whether `/var` was overlaid (journald needs a restart afterwards).
    pub var_overlaid: bool,
    /// How long the hot path took.
    pub elapsed: Duration,
}

impl HotReport {
    /// Whether the hot path found nothing to tear down at all.
    pub fn found_nothing(&self) -> bool {
        self.plan.as_ref().is_none_or(|p| p.steps.is_empty())
            && self.undo.actions.is_empty()
            && self.remaining.is_empty()
    }
}

/// Load the plan at `path`, or derive one from the mount table with
/// `hidden_root` (when known) if it is missing, corrupt or of another version.
/// `None` when there is neither a plan nor a hidden root to derive one with.
pub fn plan_or_derived(path: &Path, hidden_root: Option<&Path>) -> Option<(Plan, PlanSource)> {
    match Plan::load(path) {
        Ok(plan) => Some((plan, PlanSource::Recorded)),
        Err(why) => {
            let hidden_root = hidden_root?;
            let entries = read_mountinfo().unwrap_or_default();
            Some((
                crate::derive::derive_plan(&entries, hidden_root),
                PlanSource::Derived(why.to_string()),
            ))
        }
    }
}

/// The writable NAILS mount ids per mount namespace, read lazily: a process in
/// another namespace (a service with `PrivateTmp=`) holds copies of the
/// overlays with ids of their own.
struct NamespaceIds {
    hidden_root: PathBuf,
    own_namespace: Option<String>,
    own_ids: HashSet<i32>,
    others: HashMap<String, HashSet<i32>>,
}

impl NamespaceIds {
    fn new(hidden_root: &Path) -> Self {
        let own_ids = read_mountinfo()
            .map(|e| NailsMounts::owned_writable_mount_ids(&e, Some(hidden_root)))
            .unwrap_or_default();
        Self {
            hidden_root: hidden_root.to_path_buf(),
            own_namespace: refs::mount_namespace_of(std::process::id()),
            own_ids,
            others: HashMap::new(),
        }
    }

    fn for_pid(&mut self, pid: u32) -> Option<&HashSet<i32>> {
        let namespace = refs::mount_namespace_of(pid)?;
        if Some(&namespace) == self.own_namespace.as_ref() {
            return Some(&self.own_ids);
        }
        if !self.others.contains_key(&namespace) {
            let ids = read_mountinfo_at(Path::new(&format!("/proc/{pid}/mountinfo")))
                .map(|e| NailsMounts::owned_writable_mount_ids(&e, Some(&self.hidden_root)))
                .unwrap_or_default();
            self.others.insert(namespace.clone(), ids);
        }
        self.others.get(&namespace)
    }
}

/// The processes to kill, grouped: service cgroups (unit name to cgroup path)
/// and lone processes.
#[derive(Default)]
struct Victims {
    services: BTreeMap<String, String>,
    lone: Vec<u32>,
    spared: usize,
}

fn find_victims(plan: &Plan, host: &Host, invocation: &Invocation, spare: &SpareSet) -> Victims {
    let own_cgroup = cgroup::own_path().unwrap_or_default();
    let mut ids = NamespaceIds::new(&plan.hidden_root);
    let mut victims = Victims::default();
    if ids.own_ids.is_empty() {
        return victims;
    }
    for pid in proc::pids() {
        let stat = proc::stat(pid);
        if pid == 1
            || stat.is_none_or(|s| s.is_kernel_thread())
            || invocation.contains(pid, stat.as_ref())
        {
            continue;
        }
        let cgroup_body = proc::cgroup(pid).unwrap_or_default();
        let unit = cgroup::v2_path(&cgroup_body).and_then(|path| cgroup::service_of(&path));
        if unit
            .as_ref()
            .is_some_and(|(name, _)| host.spared_units.contains(name))
        {
            continue;
        }
        let Some(mount_ids) = ids.for_pid(pid) else {
            continue;
        };
        if !refs::writes_through(pid, mount_ids) {
            continue;
        }
        if spare.covers(&cgroup_body) {
            victims.spared += 1;
            continue;
        }
        match unit {
            Some((name, path)) if !cgroup::contains(&path, &own_cgroup) => {
                victims.services.insert(name, path);
            }
            _ => victims.lone.push(pid),
        }
    }
    victims
}

/// The units the plan says the hidden configuration added, with a type suffix,
/// minus the one this teardown runs in.
fn recorded_units(plan: &Plan, own_unit: Option<&str>) -> Vec<String> {
    plan.hidden_units()
        .into_iter()
        .map(|u| {
            if u.contains('.') {
                u
            } else {
                format!("{u}.service")
            }
        })
        .filter(|u| own_unit != Some(u.as_str()))
        .collect()
}

/// Stop, kill and drain everything that could keep a NAILS mount busy.
fn kill_phase(plan: &Plan, host: &Host, report: &mut HotReport) {
    let mut invocation = Invocation::current();
    invocation.extra.extend(host.protected_pids.iter().copied());
    let own_cgroup = cgroup::own_path().unwrap_or_default();
    let own_unit = cgroup::service_of(&own_cgroup).map(|(unit, _)| unit);
    let spare = SpareSet::at_panic(&plan.session.spare_fragments, &host.sessions_dir);

    let hidden = recorded_units(plan, own_unit.as_deref());
    let victims = find_victims(plan, host, &invocation, &spare);
    report.session_processes_spared = victims.spared;

    let mut stops: BTreeSet<String> = hidden.iter().cloned().collect();
    stops.extend(victims.services.keys().cloned());
    stops.retain(|u| !host.spared_units.contains(u));
    report.units_stopped = stops.iter().cloned().collect();
    if !stops.is_empty()
        && let Some(systemctl) = &host.systemctl
    {
        report.stop_enqueued = Some(units::stop_units(systemctl, &report.units_stopped));
    }

    let mut dirs: Vec<PathBuf> = Vec::new();
    for unit in &hidden {
        let path = format!("/system.slice/{unit}");
        if !cgroup::contains(&path, &own_cgroup) {
            let dir = cgroup::dir(&host.cgroup_root, &path);
            if dir.is_dir() {
                dirs.push(dir);
            }
        }
    }
    for path in victims.services.values() {
        let dir = cgroup::dir(&host.cgroup_root, path);
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    for dir in &dirs {
        if cgroup::kill(dir).is_ok() {
            report.cgroups_killed.push(dir.clone());
        }
    }

    let mut handles: Vec<ProcessHandle> = victims
        .lone
        .iter()
        .filter_map(|&pid| ProcessHandle::open(pid))
        .filter(ProcessHandle::kill)
        .collect();
    report.processes_killed = handles.iter().map(ProcessHandle::pid).collect();

    let shells = shells::kill_interactive_shells(&invocation, &host.spared_units);
    report.shells_killed = shells.iter().map(ProcessHandle::pid).collect();
    handles.extend(shells);

    let deadline = Instant::now() + KILL_DRAIN_BUDGET;
    report.cgroups_still_populated = cgroup::await_empty(&report.cgroups_killed, KILL_DRAIN_BUDGET);
    report.processes_still_alive = proc::await_exit(&handles, deadline);
}

/// Run the hot path: kill (when `host` allows it), then undo `plan` through `m`.
pub fn run<M: MountOps>(m: &M, plan: Plan, source: PlanSource, host: Option<&Host>) -> HotReport {
    let start = Instant::now();
    let mut report = HotReport::default();
    let live = m.nails_mounts().unwrap_or_default();
    report.nix_overlaid = plan.overlays(Path::new("/nix")) || live.nix_overlay_present;
    report.var_overlaid = plan.overlays(Path::new("/var"))
        || live
            .persistent_overlays
            .iter()
            .chain(live.ephemeral_overlays.iter())
            .any(|p| p == Path::new("/var"));

    if let Some(host) = host {
        kill_phase(&plan, host, &mut report);
        if report.var_overlaid
            && let Some(journalctl) = &host.journalctl
        {
            report.journal_relinquished = Some(units::relinquish_journal(journalctl));
        }
    }

    report.undo = run_plan(
        m,
        &plan,
        &[Phase::Dependents, Phase::Store, Phase::Main],
        true,
    );
    report.remaining = remaining(m, &plan);
    // A failed unmount leaves its mount in place, whatever the table says;
    // except the /nix/store bind, which is only ever NAILS's while /nix is
    // overlaid and goes with the /nix overlay's (lazy) detach.
    let nix_still_overlaid = m.nails_mounts().is_ok_and(|n| n.nix_overlay_present);
    for action in &report.undo.actions {
        if !matches!(action.outcome, crate::undo::Outcome::Failed(_)) {
            continue;
        }
        let store_bind = action.kind == Some(crate::plan::MountKind::StoreBind);
        if (!store_bind || nix_still_overlaid) && !report.remaining.contains(&action.target) {
            report.remaining.push(action.target.clone());
        }
    }
    report.source = Some(source);
    report.plan = Some(plan);
    report.elapsed = start.elapsed();
    report
}
