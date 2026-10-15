// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The last userspace step before PID 1 switches root.
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
//!   the decoy units the hidden systemd must never start and, best effort, the
//!   boot-loader units that would only fail on the read-only boot filesystems,
//!   install the hidden session's runtime units (and, opted in, the udev rule
//!   that keeps unused disks read-only, [`crate::whole_root::disk_guard`]),
//!   narrow the `/run` snapshot to what the decoy's own shutdown left, drop the
//!   `utab` lines of the mounts the switch leaves behind
//!   ([`crate::whole_root::utab`]), copy the decoy's records
//!   ([`crate::whole_root::run_records`]), and record the entry.
//! - **Leave** (hidden to decoy): repoint `/run/current-system` back to the
//!   decoy, make the disks the session set read-only writable again and remove
//!   the rule and the drop-ins, scrub `/run` ([`crate::whole_root::run_scrub`]),
//!   put the decoy's records back, give the decoy's `utab` lines back to the
//!   decoy mounts the way back restored, and write the kmsg cursor last.
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

use crate::mountinfo::{MountEntry, parse_mountinfo, read_mountinfo};
use crate::whole_root::disk_guard;
use crate::whole_root::nextroot::{self, NEXTROOT};
use crate::whole_root::plan::{
    self, BINARY_NAME, Direction, PLAN_NAME, Plan, RECORDS_NAME, RUNTIME_DIR, SNAPSHOT_NAME,
    UTAB_MOUNTS_NAME, UTAB_NAME, unix_now,
};
use crate::whole_root::run_scrub::{self, Snapshot};
use crate::whole_root::{kernel_helpers, run_records, runtime_units, utab};
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

/// Units whose stop would tear down something the switch needs, each kept
/// from running its `ExecStop=` while a session is staged or running. A name
/// ending in `-.service` is a prefix: systemd reads `foo-.service.d/` for
/// every `foo-*.service`.
///
/// `blk-availability.service` (Debian's and Ubuntu's lvm2 package ships it,
/// enabled) runs `blkdeactivate -u` when it stops. That unmounts every
/// filesystem on a device-mapper device that is not mounted on one of its
/// fixed system paths: on the way in the hidden volume below
/// `/run/nextroot`, which leaves the hidden session without its volume at its
/// path; on the way back the decoy root below `/run/nextroot` when the decoy
/// root is on LUKS or LVM, which would leave PID 1 nothing to switch to. A
/// real power-off still detaches device-mapper devices in systemd-shutdown.
///
/// `network-addresses-<interface>.service` is how NixOS applies a static
/// address (`networking.interfaces`). Its stop deletes the address, and it
/// starts again only when its network device appears, which a soft-reboot
/// does not replay: the other root came up without its address and could not
/// be reached. The kernel keeps the address across the switch when nothing
/// deletes it.
pub const STOP_GUARDED_UNITS: [&str; 2] =
    ["blk-availability.service", "network-addresses-.service"];

/// Whether `unit` in [`STOP_GUARDED_UNITS`] is a prefix rather than a unit name.
pub fn is_unit_prefix(unit: &str) -> bool {
    unit.ends_with("-.service")
}

/// The drop-in text that clears a unit's stop commands.
pub const STOP_GUARD_TEXT: &str = "[Service]\nExecStop=\n";

/// [`STOP_GUARD_TEXT`] with a start command that does nothing, for
/// `blk-availability.service`. Debian and Ubuntu ship that unit with its stop
/// as its only command, and systemd refuses to load a service left with none
/// ("Service has no ExecStart=, ExecStop=, or SuccessAction=. Refusing."). A
/// one-shot service runs every start command, so lvm2's own unit, which
/// starts `true` already, runs two; the `-` makes a missing binary harmless.
pub const STOP_GUARD_WITH_START_TEXT: &str = "[Service]\nExecStop=\nExecStart=-/usr/bin/true\n";

/// The stop guard's text for `unit`.
fn stop_guard_text(unit: &str) -> &'static str {
    if unit == "blk-availability.service" {
        STOP_GUARD_WITH_START_TEXT
    } else {
        STOP_GUARD_TEXT
    }
}

/// The stop guards' file name. systemd applies a unit's drop-ins in the order
/// of their file names across every directory, and an `ExecStop=` in a later
/// one adds its commands back: `zz-` sorts after the `override.conf` that
/// `systemctl edit` writes, NixOS's `overrides.conf` and numbered drop-ins.
/// The entry checks the result after the reload all the same.
pub const STOP_GUARD_NAME: &str = "zz-overlay-runtime.conf";

/// The drop-in directory for `unit`, below `/run`.
pub fn stop_guard_dir(unit: &str) -> PathBuf {
    Path::new("systemd/system").join(format!("{unit}.d"))
}

/// Units that must stop with the rest of the root at a soft-reboot, which
/// their own unit files prevent.
///
/// Since Ubuntu 26.04, `dbus.service` and `dbus.socket` carry
/// `DefaultDependencies=no` so that the bus outlives a shutdown. At a
/// soft-reboot that leaves `dbus-daemon` to the final kill and the listening
/// socket open in PID 1: the new manager connects to it, nothing answers, and
/// after about 90 s it marks every D-Bus-activated service as failed to load
/// (accounts-daemon among them, so gdm never starts). Stopped at
/// `shutdown.target`, as Debian 13 and Ubuntu 24.04 do, the bus comes up
/// again in the other root like at boot. `Conflicts=` adds up across
/// drop-ins, so no later drop-in can take it back.
pub const SHUTDOWN_BOUND_UNITS: [&str; 2] = ["dbus.service", "dbus.socket"];

/// The drop-in text that stops a unit at `shutdown.target`.
pub const SHUTDOWN_BOUND_TEXT: &str = "[Unit]\nConflicts=shutdown.target\nBefore=shutdown.target\n";

/// Every runtime guard the session installs, as (unit, drop-in text), each
/// written as [`STOP_GUARD_NAME`] in [`stop_guard_dir`] of its unit.
pub fn runtime_guards() -> impl Iterator<Item = (&'static str, &'static str)> {
    STOP_GUARDED_UNITS
        .into_iter()
        .map(|unit| (unit, stop_guard_text(unit)))
        .chain(
            SHUTDOWN_BOUND_UNITS
                .into_iter()
                .map(|unit| (unit, SHUTDOWN_BOUND_TEXT)),
        )
}

/// Install the drop-in, and the stop guards, under `run`, readable by all
/// ([`plan::SERVICE_CONFIG_MODE`]). The caller reloads the service manager.
pub fn install_dropin(run: &Path, binary: &Path) -> io::Result<PathBuf> {
    for (unit, text) in runtime_guards() {
        let dir = run.join(stop_guard_dir(unit));
        std::fs::create_dir_all(&dir)?;
        plan::write_atomic_with_mode(
            &dir.join(STOP_GUARD_NAME),
            text.as_bytes(),
            plan::SERVICE_CONFIG_MODE,
        )?;
    }
    let dir = run.join(DROPIN_DIR);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(DROPIN_NAME);
    plan::write_atomic_with_mode(
        &path,
        dropin_text(binary).as_bytes(),
        plan::SERVICE_CONFIG_MODE,
    )?;
    Ok(path)
}

/// Remove the drop-in and the stop guards under `run`, with each of their
/// directories that is left empty, unless `kept` (the `/run` snapshot taken
/// before the entry) lists it: a drop-in directory the decoy had already
/// keeps whatever else it holds, and only the files NAILS wrote go. Returns
/// whether a file went, which PID 1 keeps loaded until its next reload.
pub fn remove_dropin(run: &Path, kept: &Snapshot) -> bool {
    let files = runtime_guards()
        .map(|(unit, _)| (stop_guard_dir(unit), STOP_GUARD_NAME))
        .chain(std::iter::once((PathBuf::from(DROPIN_DIR), DROPIN_NAME)));
    let mut removed = false;
    for (dir, name) in files {
        removed |= std::fs::remove_file(run.join(&dir).join(name)).is_ok();
        if !kept.contains(dir.as_os_str()) {
            let _ = std::fs::remove_dir(run.join(&dir));
        }
    }
    removed
}

/// The jobs of the soft-reboot itself, which wait for the transition.
const OWN_JOBS: [&str; 2] = ["soft-reboot.target", "systemd-soft-reboot.service"];

/// How long the way back waits for other units to finish stopping before it
/// takes the kmsg cursor.
const OTHER_JOBS_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

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
    /// `systemctl`, to wait for the other units' stop jobs before the kmsg
    /// cursor is taken; `None` skips the wait.
    pub systemctl: Option<PathBuf>,
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
            systemctl: crate::whole_root::tools::find(None, "systemctl"),
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

    /// The `/run` snapshot the entry saved, if any.
    fn saved_snapshot(&self) -> Option<Snapshot> {
        Snapshot::load(&self.runtime_dir.join(SNAPSHOT_NAME))
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
/// entered) the runtime pieces go too and the hidden backend is marked for
/// deferred removal, so nothing of the failed activation is left, its key
/// included; in the hidden session the plan stays for a later deactivation.
fn disarm(env: &Env, plan: &Plan, why: &str) -> Outcome {
    nextroot::detach_tree(&env.nextroot);
    if plan.entered_at.is_none() {
        // A reboot that met the leftover tree: the volume was unmounted by
        // the shutdown, and a real reboot would have closed it too.
        let _ = crate::whole_root::ret::close_backend_deferred(plan);
        let kept = env.saved_snapshot().unwrap_or_default();
        remove_dropin(&env.run, &kept);
        runtime_units::remove_masks(&env.run, &plan.masks, &plan.boot_masks, &kept);
        kernel_helpers::restore(&plan.kernel_settings);
        nextroot::remove_runtime_dir(&env.runtime_dir);
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
    // The session's own units (watcher, sleep guard) are best-effort, and so
    // is the read-only rule for unused disks: the watcher sweeps them too. So
    // are the boot-loader masks, which only keep units from failing.
    let _ = runtime_units::install_units(&env.run, &plan.session_units);
    if plan.read_only_disks {
        let _ = disk_guard::install_rule(&env.run, &env.runtime_dir.join(BINARY_NAME));
    }
    runtime_units::mask_units_best_effort(&env.run, &plan.boot_masks);
    narrow_snapshot(env);
    prune_utab(env);
    // Without the copy, the way back clears the records instead.
    if run_records::save(&env.run, &env.runtime_dir.join(RECORDS_NAME)).is_err() {
        let _ = std::fs::remove_file(env.runtime_dir.join(RECORDS_NAME));
    }
    plan.armed = None;
    plan.entered_at = Some(env.now);
    let _ = plan.write_atomic(&env.runtime_dir.join(PLAN_NAME));
    Outcome::Entered
}

/// Narrow the `/run` snapshot the entry took to the entries still there now
/// that every decoy unit has stopped. What the decoy's own shutdown removed
/// (the PID file of a service it stopped) is then no longer the decoy's, and
/// the way back removes it when the hidden session wrote it again, as a
/// session ended by an emergency's kill leaves it. A plain soft-reboot would
/// not have carried it either. Best effort: on any error the entry's snapshot
/// stays.
fn narrow_snapshot(env: &Env) {
    let path = env.runtime_dir.join(SNAPSHOT_NAME);
    let Some(saved) = Snapshot::load(&path) else {
        return;
    };
    let narrowed = saved.still_present(&env.run);
    if narrowed != saved {
        let _ = plan::write_private_atomic(&path, &narrowed.to_text());
    }
}

/// Keep in `utab` only the lines that still name the same mount once PID 1
/// has switched to the next root ([`utab::surviving_lines`]): the hidden
/// session must not join the decoy's lines to the mounts that reuse the IDs
/// of the decoy's root and its submounts. Best effort: on any error the file
/// stays as it is.
fn prune_utab(env: &Env) {
    let Ok(text) = std::fs::read(env.run.join(run_scrub::UTAB)) else {
        return;
    };
    let kept = utab::surviving_lines(&text, &env.mounts, &env.nextroot);
    if kept != text {
        let _ = run_scrub::restore_utab(&env.run, &kept);
    }
}

fn leave(env: &Env, plan: &Plan) -> Outcome {
    // Read everything the scrub needs before it removes the runtime directory.
    let snapshot = env.saved_snapshot();
    let saved_utab = std::fs::read(env.runtime_dir.join(UTAB_NAME)).ok();
    let utab_mounts = std::fs::read_to_string(env.runtime_dir.join(UTAB_MOUNTS_NAME))
        .ok()
        .map(|text| parse_mountinfo(&text));
    let records = std::fs::read(env.runtime_dir.join(RECORDS_NAME)).ok();
    if let Err(why) = repoint_and_check(env, &plan.decoy) {
        if let Some(system) = &plan.hidden.system {
            let _ = repoint_current_system(&env.run, system);
        }
        return disarm(env, plan, &why);
    }
    // The hidden activation pointed the kernel's module loader and firmware
    // path at the hidden store; nothing runs the decoy's activation again.
    kernel_helpers::restore(&plan.kernel_settings);
    // The disks the session made read-only are the decoy's again, and its
    // udevd must never load the rule (the scrub leaves /run/udev alone).
    disk_guard::remove_rule(&env.run);
    disk_guard::release(&env.runtime_dir);
    // By name: the scrub keeps a drop-in directory the decoy already had,
    // and never looks inside it.
    remove_dropin(&env.run, snapshot.as_ref().unwrap_or(&Snapshot::default()));
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
    run_records::restore(&env.run, records.as_deref());
    // The decoy's copy, taken at entry, names mounts by their IDs at that time;
    // the decoy root and its filesystems come back as new mounts, and the old
    // IDs may name the session's mounts or none.
    if let Some(saved) = saved_utab {
        let kept = utab::restored_lines(&saved, utab_mounts.as_deref(), &env.mounts, &env.nextroot);
        let _ = run_scrub::restore_utab(&env.run, &kept);
    }
    // A process exec'd from /run keeps running once it turns noexec again.
    if plan.run_noexec {
        let _ = nextroot::set_noexec(&env.run, true);
    }
    // Last: anything logged after this is imported by the decoy journald.
    // A hidden unit that is not ordered before the shutdown can still be
    // stopping now and write to the kernel log after a cursor taken at once
    // (and PID 1 logs its end): wait, bounded, until only the soft-reboot's
    // own jobs are left.
    if let Some(systemctl) = &env.systemctl {
        reset_new_failures(systemctl, &plan.failed_at_entry);
        let _ =
            crate::whole_root::tools::wait_for_other_jobs(systemctl, &OWN_JOBS, OTHER_JOBS_BUDGET);
    }
    if let Some(next) = run_scrub::next_kernel_seqnum(&env.kmsg) {
        let _ = run_scrub::write_kernel_seqnum(&env.run, next);
    }
    Outcome::Returned {
        removed: report.removed.len(),
        failed: report.failed.len(),
    }
}

/// Forget the failures the session caused: every unit failed now that was
/// not failed when the session was prepared. An emergency SIGKILLs units (the
/// session's watcher, a decoy unit caught stopping), and PID 1 carries a
/// failed unit across the soft-reboot: the decoy would list it in
/// `systemctl --failed` until its next boot. The decoy's own earlier failures
/// stay.
fn reset_new_failures(systemctl: &Path, failed_at_entry: &[String]) {
    let Some(failed) = crate::whole_root::tools::failed_units(systemctl) else {
        return;
    };
    let new: Vec<&str> = failed
        .iter()
        .filter(|unit| !failed_at_entry.contains(unit))
        .map(String::as_str)
        .collect();
    if new.is_empty() {
        return;
    }
    let mut args = vec!["reset-failed"];
    args.extend(new);
    let _ = crate::whole_root::tools::run(systemctl, &args, crate::whole_root::tools::TOOL_BUDGET);
}

#[cfg(test)]
#[path = "transition_tests.rs"]
mod tests;
