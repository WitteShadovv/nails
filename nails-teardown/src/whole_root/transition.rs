// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The last userspace step before PID 1 switches root (ADR 0008, sections 3
//! and 5).
//!
//! Activation installs a runtime drop-in that makes this step the `ExecStart=`
//! of `systemd-soft-reboot.service`. That service is ordered after
//! `shutdown.target`, `umount.target` and `final.target`, so every unit of the
//! userspace being left has stopped (journald included) when it runs, and
//! nothing runs after it but PID 1. It acts only on an **armed** plan
//! ([`crate::whole_root::plan::Arm`]):
//!
//! - **Enter** (decoy to hidden): repoint `/run/current-system` to the hidden
//!   NixOS toplevel (PID 1 re-executes `/run/current-system/systemd/...`), mask
//!   the decoy units the hidden systemd must never start, install the hidden
//!   session's runtime units, and record the entry.
//! - **Leave** (hidden to decoy): repoint `/run/current-system` back to the
//!   decoy, scrub `/run` ([`crate::whole_root::run_scrub`]), restore `utab`,
//!   and write the kmsg cursor last.
//!
//! Before either it checks the next root's init the way PID 1 will; when the
//! check fails it undoes the repoint and detaches `/run/nextroot`, so PID 1
//! restarts userspace on the current root instead of freezing.
//!
//! **The leftover guard.** A populated `/run/nextroot` turns a later plain
//! `reboot` into a soft-reboot into it (systemd >= 255). If the plan is not
//! armed for this transition (an activation died after building the tree, or
//! the arming expired), this step detaches `/run/nextroot` instead of letting
//! PID 1 enter it.
//!
//! It never writes to a disk and never logs: its output goes nowhere, and a
//! name sent to `/dev/kmsg` would reach the decoy's ring buffer.

use crate::mountinfo::{MountEntry, read_mountinfo};
use crate::whole_root::nextroot::{self, NEXTROOT};
use crate::whole_root::plan::{
    self, Direction, PLAN_NAME, Plan, RUNTIME_DIR, SNAPSHOT_NAME, UTAB_NAME, unix_now,
};
use crate::whole_root::run_scrub::{self, Snapshot};
use crate::whole_root::runtime_units;
use std::io;
use std::path::{Path, PathBuf};

/// The drop-in directory for `systemd-soft-reboot.service`, below `/run`.
pub const DROPIN_DIR: &str = "systemd/system/systemd-soft-reboot.service.d";
/// The drop-in's file name (neutral).
pub const DROPIN_NAME: &str = "50-overlay-runtime.conf";
/// The argument the drop-in passes to the RAM copy of the binary.
pub const TRANSITION_ARG: &str = "transition";

/// The drop-in text that runs `binary transition` as the service's start.
pub fn dropin_text(binary: &Path) -> String {
    format!(
        "[Service]\nType=oneshot\nStandardInput=null\nStandardOutput=null\nStandardError=null\n\
         ExecStart=-{} {TRANSITION_ARG}\n",
        binary.display()
    )
}

/// Install the drop-in under `run`. The caller reloads the service manager.
pub fn install_dropin(run: &Path, binary: &Path) -> io::Result<PathBuf> {
    let dir = run.join(DROPIN_DIR);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(DROPIN_NAME);
    plan::write_private_atomic(&path, dropin_text(binary).as_bytes())?;
    Ok(path)
}

/// Remove the drop-in (and its directory when empty) under `run`.
pub fn remove_dropin(run: &Path) {
    let dir = run.join(DROPIN_DIR);
    let _ = std::fs::remove_file(dir.join(DROPIN_NAME));
    let _ = std::fs::remove_dir(dir);
}

/// Where the transition looks.
#[derive(Debug, Clone)]
pub struct Env {
    /// The `/run` root.
    pub run: PathBuf,
    /// `/run/nextroot`.
    pub nextroot: PathBuf,
    /// The runtime directory holding the plan.
    pub runtime_dir: PathBuf,
    /// The kernel log device.
    pub kmsg: PathBuf,
    /// Now, in seconds since the epoch.
    pub now: u64,
    /// The live mount table.
    pub mounts: Vec<MountEntry>,
}

impl Env {
    /// The real system.
    pub fn system() -> Self {
        Self {
            run: PathBuf::from("/run"),
            nextroot: PathBuf::from(NEXTROOT),
            runtime_dir: PathBuf::from(RUNTIME_DIR),
            kmsg: PathBuf::from("/dev/kmsg"),
            now: unix_now(),
            mounts: read_mountinfo().unwrap_or_default(),
        }
    }

    fn nextroot_mounted(&self) -> bool {
        nextroot::is_mount_point(&self.mounts, &self.nextroot)
    }

    fn mount_points(&self) -> Vec<PathBuf> {
        self.mounts.iter().map(|e| e.mount_point.clone()).collect()
    }
}

/// What the transition did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// No plan, or nothing armed and no `/run/nextroot`: a plain soft-reboot.
    NothingToDo,
    /// Prepared the entry into the hidden root.
    Entered,
    /// Prepared the return to the decoy and scrubbed `/run`.
    Returned {
        /// Entries the scrub removed.
        removed: usize,
        /// Entries it could not remove.
        failed: usize,
    },
    /// `/run/nextroot` was populated but not armed for this transition, or
    /// failed the init check: it was detached, so PID 1 stays on this root.
    Disarmed(String),
}

/// Repoint the `current-system` link under `run` to `target`, atomically.
/// Returns the previous target.
pub fn repoint_current_system(run: &Path, target: &Path) -> io::Result<Option<PathBuf>> {
    let link = run.join("current-system");
    let previous = std::fs::read_link(&link).ok();
    let temp = run.join(format!(".current-system.{}", std::process::id()));
    let _ = std::fs::remove_file(&temp);
    std::os::unix::fs::symlink(target, &temp)?;
    if let Err(e) = std::fs::rename(&temp, &link) {
        let _ = std::fs::remove_file(&temp);
        return Err(e);
    }
    Ok(previous)
}

/// Run the transition step. See the module docs.
pub fn run(env: &Env) -> Outcome {
    let Ok(mut plan) = Plan::load(&env.runtime_dir.join(PLAN_NAME)) else {
        // Not ours to judge: without a plan, /run/nextroot may be another
        // tool's staged root.
        return Outcome::NothingToDo;
    };
    if !env.nextroot_mounted() {
        return Outcome::NothingToDo;
    }
    if plan.armed_for(Direction::Enter, env.now) {
        return enter(env, &mut plan);
    }
    if plan.armed_for(Direction::Leave, env.now) {
        return leave(env, &plan);
    }
    disarm(env, &plan, "not armed for this transition")
}

/// Detach a `/run/nextroot` the plan did not arm. On the decoy side (never
/// entered) the runtime pieces go too, so nothing of the failed activation is
/// left; in the hidden session the plan stays for a later deactivation.
fn disarm(env: &Env, plan: &Plan, why: &str) -> Outcome {
    nextroot::detach_tree(&env.nextroot);
    if plan.entered_at.is_none() {
        remove_dropin(&env.run);
        let _ = std::fs::remove_dir_all(&env.runtime_dir);
        if plan.run_noexec {
            let _ = nextroot::set_noexec(&env.run, true);
        }
    }
    Outcome::Disarmed(why.to_string())
}

/// Repoint `current-system` (when the side has a system) and check the next
/// root's init. On a failed check the repoint is undone.
fn repoint_and_check(env: &Env, side: &plan::RootSide) -> Result<(), String> {
    let previous = match &side.system {
        Some(system) => repoint_current_system(&env.run, system)
            .map_err(|e| format!("could not repoint current-system: {e}"))?,
        None => None,
    };
    if let Err(e) = nextroot::precheck(&env.nextroot, &side.init) {
        if let Some(previous) = previous {
            let _ = repoint_current_system(&env.run, &previous);
        }
        return Err(e.to_string());
    }
    Ok(())
}

fn enter(env: &Env, plan: &mut Plan) -> Outcome {
    if let Err(why) = repoint_and_check(env, &plan.hidden) {
        return disarm(env, plan, &why);
    }
    // Without its masks the hidden systemd would swap onto, or mount read-write,
    // a decoy disk: never enter without them.
    if let Err(e) = runtime_units::mask_units(&env.run, &plan.masks) {
        if let Some(system) = &plan.decoy.system {
            let _ = repoint_current_system(&env.run, system);
        }
        return disarm(env, plan, &format!("could not mask decoy units: {e}"));
    }
    // The session's own units (watcher, sleep guard) are best-effort.
    let _ = runtime_units::install_units(&env.run, &plan.session_units);
    plan.armed = None;
    plan.entered_at = Some(env.now);
    let _ = plan.write_atomic(&env.runtime_dir.join(PLAN_NAME));
    Outcome::Entered
}

fn leave(env: &Env, plan: &Plan) -> Outcome {
    // Read everything the scrub needs before it removes the runtime directory.
    let snapshot = std::fs::read(env.runtime_dir.join(SNAPSHOT_NAME))
        .ok()
        .map(|text| Snapshot::from_text(&text));
    let utab = std::fs::read(env.runtime_dir.join(UTAB_NAME)).ok();
    if let Err(why) = repoint_and_check(env, &plan.decoy) {
        if let Some(system) = &plan.hidden.system {
            let _ = repoint_current_system(&env.run, system);
        }
        return disarm(env, plan, &why);
    }
    let runtime_rel = env
        .runtime_dir
        .strip_prefix(&env.run)
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let runtime_rel = runtime_rel.to_string_lossy().into_owned();
    // Without a snapshot only the known session state and the runtime
    // directory go: deleting unknown entries could remove decoy state the
    // next boot relies on.
    let report = match &snapshot {
        Some(snapshot) => {
            run_scrub::scrub(&env.run, snapshot, &[&runtime_rel], &env.mount_points())
        }
        None => run_scrub::scrub(
            &env.run,
            &Snapshot::take(&env.run),
            &[&runtime_rel],
            &env.mount_points(),
        ),
    };
    if let Some(utab) = utab {
        let _ = run_scrub::restore_utab(&env.run, &utab);
    }
    // A process exec'd from /run keeps running once it turns noexec again.
    if plan.run_noexec {
        let _ = nextroot::set_noexec(&env.run, true);
    }
    // Last: anything logged after this is imported by the decoy journald.
    if let Some(next) = run_scrub::next_kernel_seqnum(&env.kmsg) {
        let _ = run_scrub::write_kernel_seqnum(&env.run, next);
    }
    Outcome::Returned {
        removed: report.removed.len(),
        failed: report.failed.len(),
    }
}

#[cfg(test)]
#[path = "transition_tests.rs"]
mod tests;
