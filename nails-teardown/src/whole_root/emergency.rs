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
//! runtime pieces, so no later reboot enters the tree, and drops the
//! soft-reboot logind may still hold for the entry
//! ([`logind::drop_soft_reboot`]): that soft-reboot would restart the decoy's
//! userspace when logind lets it go, with records an ordinary boot never
//! writes. A decoy that is to keep running asks that first; a requested power
//! action is enqueued first and asks after it. Only a decoy that keeps
//! running gets PID 1 reloaded and `/run` made `noexec` again, as after a
//! rollback. Where the soft-reboot may still come (logind cannot drop it, on
//! systemd 256 and older, or does not answer, or PID 1 has already started
//! it), it powers off (or reboots, as asked) at once, past PID 1's queue,
//! where that soft-reboot could otherwise run first.
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
use crate::whole_root::{kernel_helpers, logind, ret, runtime_units};
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
        (Side::Decoy, Some(plan)) => decoy_side(&plan, host, requested, &mut report),
        _ => {
            if requested != Finish::Return {
                dispatch_without_plan(host, requested, &mut report);
            }
        }
    }
    report.elapsed = start.elapsed();
    report
}

/// The decoy side: an activation left a plan (and perhaps a next root). A
/// decoy that is to keep running asks first what is left of the entry's
/// soft-reboot; a power action leaves no time to lose, so it is enqueued
/// first and asks after it. Where the soft-reboot may still come, the
/// emergency powers off (or reboots, as asked) at once ([`decoy_escape`]).
fn decoy_side(plan: &Plan, host: &Host, requested: Finish, report: &mut HotReport) {
    report.timed("signal-activation", |_| {
        if host.act {
            signal_owner(plan);
        }
    });
    let mut pending = logind::Pending::Nothing;
    if requested == Finish::Return {
        pending = drop_switch(plan, host, report);
    }
    let unloaded = decoy(plan, host, report);
    if requested != Finish::Return {
        dispatch(plan, host, requested, report);
        pending = drop_switch(plan, host, report);
    }
    // What was enqueued, if anything: a power-off stands in for a reboot
    // PID 1 refused.
    let asked = report.dispatched.unwrap_or(requested);
    if let Some((finish, why)) = decoy_escape(asked, pending) {
        report.fallback = Some(why);
        force(plan, host, finish, report);
    }
    settle(plan, host, unloaded, report);
}

/// Drop what logind still holds of the entry's soft-reboot, with the tools
/// the entry recorded, as for everything else here.
fn drop_switch(plan: &Plan, host: &Host, report: &mut HotReport) -> logind::Pending {
    report.timed("drop-soft-reboot", |_| {
        if !host.act {
            return logind::Pending::Nothing;
        }
        logind::drop_soft_reboot(
            plan.tools.systemctl.as_deref(),
            plan.tools.busctl.as_deref(),
        )
    })
}

/// What a decoy-side emergency forces past PID 1's queue, and why, when the
/// entry's soft-reboot may still come (`pending`): a power-off for a decoy
/// that was to keep running, else the power action asked for. PID 1's queue
/// would run the soft-reboot as soon as the power action, whichever comes
/// first, and logind may still add it there.
fn decoy_escape(requested: Finish, pending: logind::Pending) -> Option<(Finish, String)> {
    let why = match pending {
        logind::Pending::Nothing => return None,
        logind::Pending::Held => "logind may still hold the entry's soft-reboot and cannot drop it",
        logind::Pending::Started => "PID 1 has started the entry's soft-reboot",
    };
    let finish = match requested {
        Finish::Return => Finish::Poweroff,
        asked => asked,
    };
    let what = if finish == Finish::Reboot {
        "rebooting"
    } else {
        "powering off"
    };
    Some((finish, format!("{why}; {what} at once, before it can run")))
}

/// Power off (or reboot) at once, past PID 1's queue: `systemctl --force`
/// skips the orderly stop of the units (systemd-shutdown still ends every
/// process and unmounts every filesystem), so no soft-reboot in that queue
/// can run first. Only the `systemctl` the entry recorded is asked; without
/// one, or when it fails, the kernel powers off.
fn force(plan: &Plan, host: &Host, finish: Finish, report: &mut HotReport) {
    kill_shells(host, report);
    report.timed("force", |report| {
        if !host.act {
            report.dispatched = Some(finish);
            return;
        }
        let verb = if finish == Finish::Reboot {
            "reboot"
        } else {
            "poweroff"
        };
        let forced = plan.tools.systemctl.as_deref().is_some_and(|systemctl| {
            tools::run(systemctl, &["--force", verb], tools::TOOL_BUDGET) != tools::Outcome::Refused
        });
        if forced {
            report.dispatched = Some(finish);
        } else {
            report.kernel_power_off = kernel_power_off();
        }
    });
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

/// The decoy side's cleanup: the next root detached and the runtime pieces
/// removed. Returns whether it removed a drop-in or a mask, which PID 1 keeps
/// loaded until its next reload.
fn decoy(plan: &Plan, host: &Host, report: &mut HotReport) -> bool {
    report.remaining = report.timed("detach-nextroot", |_| {
        if host.act {
            nextroot::detach_tree(&host.nextroot)
        } else {
            Vec::new()
        }
    });
    report.timed("remove-runtime", |_| {
        if !host.act {
            return false;
        }
        // Nothing hidden runs on the decoy: the backend goes with the last
        // close, as the way back would close it.
        let _ = ret::close_backend_deferred(plan);
        let kept = Snapshot::load(&host.runtime_dir.join(SNAPSHOT_NAME)).unwrap_or_default();
        let dropins = transition::remove_dropin(&host.run, &kept);
        let masks = runtime_units::remove_masks(
            &host.run,
            &plan.masks,
            &plan.boot_masks,
            &plan.generator_masks,
            &kept,
        );
        kernel_helpers::restore(&plan.kernel_settings);
        nextroot::remove_runtime_dir(&host.runtime_dir);
        dropins || masks
    })
}

/// What a decoy that keeps running needs after the cleanup, as a rollback
/// does it: `/run` is `noexec` again where the decoy had it so, and PID 1 is
/// reloaded when the cleanup removed a drop-in or a mask (`unloaded`). It
/// keeps running when nothing was enqueued: no power action was asked for,
/// or none could be. An enqueued power action discards both, so it waits for
/// neither (a reload reruns every generator).
fn settle(plan: &Plan, host: &Host, unloaded: bool, report: &mut HotReport) {
    if report.dispatched.is_some() {
        return;
    }
    report.timed("reload", |_| {
        if !host.act {
            return;
        }
        if plan.run_noexec {
            let _ = nextroot::set_noexec(&host.run, true);
        }
        if unloaded && let Some(systemctl) = &plan.tools.systemctl {
            let _ = tools::daemon_reload(systemctl);
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
