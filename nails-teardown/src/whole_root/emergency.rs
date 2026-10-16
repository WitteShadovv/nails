// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The emergency hot path of a whole-root session.
//!
//! In the hidden session the fastest safe path is:
//!
//! 1. prepare the way back: the decoy root at `/run/nextroot`, `/run` bound into
//!    it, the init checked ([`crate::whole_root::ret`]);
//! 2. mark the hidden backend for deferred removal;
//! 3. arm the plan for the way back;
//! 4. SIGKILL every interactive shell, so none writes its history on the
//!    session stop;
//! 5. enqueue `soft-reboot.target` (or the requested power action) directly
//!    with PID 1, with every other job replaced;
//! 6. `cgroup.kill` every unit that can hold a hidden program, sparing
//!    `init.scope`, this invocation's and the service manager's own machinery
//!    ([`crate::whole_root::kill`]), so the orderly shutdown has little left
//!    to stop.
//!
//! When the way back cannot be prepared, it powers off instead: a soft-reboot
//! without `/run/nextroot` would restart the hidden userspace in place. When
//! even the power action cannot be enqueued, it asks the kernel directly.
//!
//! On the decoy side (an activation was interrupted after building the next
//! root) it signals the activation, detaches `/run/nextroot` and removes the
//! runtime pieces, so a later reboot never enters the tree.
//!
//! Every phase is timed. Nothing here reads the configuration, the state file
//! or the hidden volume, and nothing logs; the caller prints and logs the
//! report afterwards, if it still can.

use crate::mountinfo::read_mountinfo;
use crate::proc::{self, Invocation, ProcessHandle};
use crate::whole_root::kill::{self, KillReport};
use crate::whole_root::nextroot::{self, NEXTROOT};
use crate::whole_root::plan::{PLAN_NAME, Plan, RUNTIME_DIR, SNAPSHOT_NAME};
use crate::whole_root::run_scrub::Snapshot;
use crate::whole_root::tools;
use crate::whole_root::transition;
use crate::whole_root::{kernel_helpers, ret, runtime_units};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How the emergency ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finish {
    /// Soft-reboot back to the decoy (the default in the hidden session; on
    /// the decoy side nothing beyond the cleanup).
    Return,
    /// A full reboot.
    Reboot,
    /// Power off: RAM decays, the strongest answer to the threat model.
    Poweroff,
}

impl Finish {
    fn target(self) -> &'static str {
        match self {
            Finish::Return => "soft-reboot.target",
            Finish::Reboot => "reboot.target",
            Finish::Poweroff => "poweroff.target",
        }
    }
}

/// Where the emergency ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// In the hidden root.
    Hidden,
    /// On the decoy, with a session plan left by an activation.
    Decoy,
    /// No session plan.
    None,
}

/// What the host lets the hot path do. Tests turn `act` off: the plan's state
/// is still judged, but nothing is mounted, enqueued, killed or signalled.
#[derive(Debug, Clone)]
pub struct Host {
    /// The `/run` root.
    pub run: PathBuf,
    /// `/run/nextroot`.
    pub nextroot: PathBuf,
    /// The runtime directory.
    pub runtime_dir: PathBuf,
    /// The unified cgroup hierarchy.
    pub cgroup_root: PathBuf,
    /// Further pids never to kill.
    pub protected_pids: Vec<u32>,
    /// Whether to act on the host at all.
    pub act: bool,
}

impl Host {
    /// The real system.
    pub fn system() -> Self {
        Self {
            run: PathBuf::from("/run"),
            nextroot: PathBuf::from(NEXTROOT),
            runtime_dir: PathBuf::from(RUNTIME_DIR),
            cgroup_root: PathBuf::from(crate::cgroup::CGROUP_ROOT),
            protected_pids: Vec::new(),
            act: true,
        }
    }

    fn plan_path(&self) -> PathBuf {
        self.runtime_dir.join(PLAN_NAME)
    }
}

/// What the hot path did.
#[derive(Debug, Clone)]
pub struct HotReport {
    /// Where it ran.
    pub side: Side,
    /// What was asked for.
    pub requested: Finish,
    /// What was enqueued (`None` when nothing was, by design or failure).
    pub dispatched: Option<Finish>,
    /// Why the requested finish was replaced, if it was.
    pub fallback: Option<String>,
    /// Whether the kernel was asked directly because nothing could be enqueued.
    pub kernel_power_off: bool,
    /// The device-mapper names marked for deferred removal, with the result.
    pub deferred: Vec<(String, bool)>,
    /// The kill.
    pub kill: KillReport,
    /// Mounts still below `/run/nextroot` after a decoy-side cleanup.
    pub remaining: Vec<PathBuf>,
    /// The phases with how long each took, in order.
    pub phases: Vec<(&'static str, Duration)>,
    /// How long the whole hot path took.
    pub elapsed: Duration,
}

impl HotReport {
    fn new(side: Side, requested: Finish) -> Self {
        Self {
            side,
            requested,
            dispatched: None,
            fallback: None,
            kernel_power_off: false,
            deferred: Vec::new(),
            kill: KillReport::default(),
            remaining: Vec::new(),
            phases: Vec::new(),
            elapsed: Duration::ZERO,
        }
    }

    fn timed<T>(&mut self, name: &'static str, f: impl FnOnce(&mut Self) -> T) -> T {
        let start = Instant::now();
        let value = f(self);
        self.phases.push((name, start.elapsed()));
        value
    }

    /// Whether anything was found to act on.
    pub fn found_nothing(&self) -> bool {
        self.side == Side::None
    }
}

/// Run the hot path. `plan` is the session plan, if one could be read.
pub fn run(plan: Option<Plan>, host: &Host, requested: Finish) -> HotReport {
    let start = Instant::now();
    if host.act {
        tools::survive_session_stop();
    }
    let entries = read_mountinfo().unwrap_or_default();
    let side = match &plan {
        Some(p) if ret::in_hidden_root(&entries, p) => Side::Hidden,
        Some(_) => Side::Decoy,
        None => Side::None,
    };
    let mut report = HotReport::new(side, requested);
    match (side, plan) {
        (Side::Hidden, Some(mut plan)) => hidden(&mut plan, host, &mut report),
        (Side::Decoy, Some(plan)) => {
            decoy(&plan, host, &mut report);
            if requested != Finish::Return {
                dispatch(&plan, host, requested, &mut report);
            }
        }
        _ => {
            if requested != Finish::Return {
                dispatch_without_plan(host, requested, &mut report);
            }
        }
    }
    report.elapsed = start.elapsed();
    report
}

fn hidden(plan: &mut Plan, host: &Host, report: &mut HotReport) {
    let mut finish = report.requested;
    if finish == Finish::Return {
        let prepared = report.timed("prepare-return", |_| {
            if !host.act {
                return Ok(());
            }
            ret::mount_decoy_root(plan, &host.nextroot, &host.run)
        });
        if let Err(e) = prepared {
            report.fallback = Some(format!("{e}; powering off instead"));
            finish = Finish::Poweroff;
        }
    }
    if finish == Finish::Return {
        report.deferred = report.timed("close-backend", |_| {
            if host.act {
                ret::close_backend_deferred(plan)
            } else {
                Vec::new()
            }
        });
        let armed = report.timed("arm", |_| ret::arm_leave(plan, &host.plan_path()));
        if let Err(e) = armed {
            report.fallback = Some(format!("{e}; powering off instead"));
            nextroot_cleanup(host);
            finish = Finish::Poweroff;
        }
    }
    dispatch(plan, host, finish, report);
    report.kill = report.timed("kill", |_| {
        if !host.act {
            return KillReport::default();
        }
        let mut invocation = Invocation::current();
        invocation.extra.extend(host.protected_pids.iter().copied());
        kill::kill_userspace(&host.cgroup_root, &invocation)
    });
}

fn nextroot_cleanup(host: &Host) {
    if host.act {
        nextroot::detach_tree(&host.nextroot);
    }
}

/// Enqueue `finish`, falling back to a power-off and then to the kernel.
fn dispatch(plan: &Plan, host: &Host, finish: Finish, report: &mut HotReport) {
    kill_shells(host, report);
    report.timed("enqueue", |report| {
        if !host.act {
            report.dispatched = Some(finish);
            return;
        }
        let systemctl = tools::find(plan.tools.systemctl.as_deref(), "systemctl");
        enqueue(systemctl.as_deref(), finish, report);
    });
}

/// Stopping the login sessions sends their shells SIGHUP, on which bash
/// writes its history (on the decoy: to the decoy disk). SIGKILL every
/// interactive shell, the invocation's own included, before anything is
/// enqueued.
fn kill_shells(host: &Host, report: &mut HotReport) {
    report.timed("kill-shells", |_| {
        if host.act {
            crate::shells::kill_all_interactive_shells(&[]);
        }
    });
}

fn dispatch_without_plan(host: &Host, finish: Finish, report: &mut HotReport) {
    kill_shells(host, report);
    report.timed("enqueue", |report| {
        if !host.act {
            report.dispatched = Some(finish);
            return;
        }
        let systemctl = tools::find(None, "systemctl");
        enqueue(systemctl.as_deref(), finish, report);
    });
}

fn enqueue(systemctl: Option<&Path>, finish: Finish, report: &mut HotReport) {
    if let Some(systemctl) = systemctl {
        if tools::start_target(systemctl, finish.target()) == tools::Outcome::Done {
            report.dispatched = Some(finish);
            return;
        }
        if finish != Finish::Poweroff
            && tools::start_target(systemctl, Finish::Poweroff.target()) == tools::Outcome::Done
        {
            report.fallback = Some(format!(
                "{} could not be enqueued; powering off",
                finish.target()
            ));
            report.dispatched = Some(Finish::Poweroff);
            return;
        }
    }
    report.kernel_power_off = kernel_power_off();
}

/// Sync and power off through the kernel, when PID 1 cannot be asked.
fn kernel_power_off() -> bool {
    rustix::fs::sync();
    rustix::system::reboot(rustix::system::RebootCommand::PowerOff).is_ok()
}

/// The decoy side: an activation left a plan (and perhaps a next root).
fn decoy(plan: &Plan, host: &Host, report: &mut HotReport) {
    report.timed("signal-activation", |_| {
        if host.act {
            signal_owner(plan);
        }
    });
    report.remaining = report.timed("detach-nextroot", |_| {
        if host.act {
            nextroot::detach_tree(&host.nextroot)
        } else {
            Vec::new()
        }
    });
    report.timed("remove-runtime", |_| {
        if host.act {
            // Nothing hidden runs on the decoy: the backend goes with the
            // last close, as the way back would close it.
            let _ = ret::close_backend_deferred(plan);
            let kept = Snapshot::load(&host.runtime_dir.join(SNAPSHOT_NAME)).unwrap_or_default();
            let dropins = transition::remove_dropin(&host.run, &kept);
            let masks =
                runtime_units::remove_masks(&host.run, &plan.masks, &plan.boot_masks, &kept);
            kernel_helpers::restore(&plan.kernel_settings);
            nextroot::remove_runtime_dir(&host.runtime_dir);
            // As a rollback does: `/run` is `noexec` again where the decoy
            // had it so, and PID 1 forgets the drop-ins and masks, which it
            // keeps loaded until a reload.
            if plan.run_noexec {
                let _ = nextroot::set_noexec(&host.run, true);
            }
            if (dropins || masks)
                && let Some(systemctl) = &plan.tools.systemctl
            {
                let _ = tools::daemon_reload(systemctl);
            }
        }
    });
}

/// How long a signalled activation gets to exit.
const OWNER_EXIT_WAIT: Duration = Duration::from_secs(1);

/// SIGTERM the activation that wrote the plan, if it still runs and is not
/// this invocation, and wait briefly for it.
fn signal_owner(plan: &Plan) {
    let Some(owner) = &plan.owner else {
        return;
    };
    let invocation = Invocation::current();
    let stat = proc::stat(owner.pid);
    if stat.is_none_or(|s| s.start_time != owner.start_time)
        || invocation.contains(owner.pid, stat.as_ref())
    {
        return;
    }
    if let Some(handle) = ProcessHandle::open(owner.pid)
        && handle.signal(rustix::process::Signal::TERM)
    {
        proc::await_exit(&[handle], Instant::now() + OWNER_EXIT_WAIT);
    }
}

#[cfg(test)]
#[path = "emergency_tests.rs"]
mod tests;
