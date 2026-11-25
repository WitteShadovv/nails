// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The last userspace step before PID 1 switches root.
//!
//! Activation installs a runtime drop-in that makes this step the `ExecStart=`
//! of `systemd-soft-reboot.service`. That service is ordered after
//! `shutdown.target`, `umount.target` and `final.target`, so every unit of the
//! userspace being left has stopped (journald included) when it runs, and
//! nothing runs after it but PID 1. PID 1 switches root when the service
//! succeeds (`SuccessAction=soft-reboot-force`).
//!
//! **One switch only.** The step lets PID 1 switch in one direction alone:
//! **into** the hidden root, on a plan armed for the entry
//! ([`crate::whole_root::plan::Arm`]). It repoints `/run/current-system` to the
//! hidden NixOS toplevel (PID 1 re-executes `/run/current-system/systemd/...`),
//! masks the decoy units the hidden systemd must never start, skips those a
//! boot target requires ([`crate::whole_root::skips`]), masks the generators
//! it must never run and, best effort, the units the hidden root does not
//! need, installs the hidden session's runtime units (and, opted in, the udev
//! rule that keeps unused disks read-only, [`crate::whole_root::disk_guard`]),
//! drops the `utab` lines of the mounts the switch leaves behind
//! ([`crate::whole_root::utab`]) and records the entry. A hidden session never
//! goes back to the decoy's kernel: it ends in a power-off
//! ([`crate::whole_root::session_end`]), and a plan armed for the way back,
//! which nothing of this build arms, powers off as well.
//!
//! **Fail closed.** Every outcome but the few named below ends the session
//! the way every hidden session ends ([`end`]): the step asks PID 1 to power
//! off at once, then the kernel, and returns only where neither took it. The
//! caller then exits non-zero, and the drop-in's `FailureAction=` makes PID 1
//! power off ([`dropin_text`]); a step that dies or cannot start ends the same
//! way. Before a power-off on the decoy side, the reason goes to the hidden
//! volume ([`switch_refusal`]) so `status` can say it next time. The outcomes
//! that let the switch go on, each with its reason:
//!
//! - **No session plan** ([`Outcome::NothingToDo`]): NAILS staged nothing in
//!   this boot, so a `/run/nextroot` there is another tool's, and the
//!   soft-reboot is a plain one. A plan that exists but cannot be read is no
//!   such case: it powers off.
//! - **A plan armed for nothing and no `/run/nextroot`**
//!   ([`Outcome::NothingToDo`]): PID 1 starts userspace again on the root it
//!   runs on and switches nothing. In the hidden root that is the hidden
//!   userspace again, with its masks still in `/run`.
//! - **A `/run/nextroot` the plan did not arm** ([`Outcome::Disarmed`], the
//!   leftover guard): a populated `/run/nextroot` turns a later plain `reboot`
//!   into a soft-reboot into it (systemd >= 255). On the decoy side that is
//!   the tree of an activation that died before it armed the switch, and
//!   nothing of a hidden session ran in this boot: the step detaches the tree
//!   and removes the runtime pieces, so PID 1 starts the decoy's userspace
//!   again in place ([`disarm`]). In the hidden session it is a tree someone
//!   mounted there, the decoy's root perhaps: the step detaches it and the
//!   hidden session goes on. Either only while nothing stays mounted at
//!   `/run/nextroot` afterwards; else it powers off.
//!
//! **The program's domain.** Where the plan records an SELinux label for the
//! RAM copy of the binary ([`Plan::program_label`]), an armed entry first
//! checks that it runs in the domain that label gives it, as PID 1 started it
//! ([`Env::start`], [`crate::whole_root::program_label::enter_domain`]): one
//! that runs elsewhere gives the copy the label again and starts itself again
//! from it, once. Where it still runs elsewhere it powers off.
//!
//! **The timeout guard.** systemd gives a switch 30 minutes: from 254 to 262
//! `soft-reboot.target` sets `JobTimeoutSec=30min` and
//! `JobTimeoutAction=soft-reboot-force`. A switch that hangs that long (a unit
//! whose stop never ends, or PID 1 asleep with work queued, as in systemd
//! issue #44107) would then go on by force without
//! `systemd-soft-reboot.service`, and so without this step: the hidden session
//! would start without its masks. A runtime guard installed with the drop-in
//! ([`SWITCH_TIMEOUT_TEXT`]) powers the machine off at that timeout instead.
//! It stays for the whole session, so a soft-reboot in the hidden session that
//! hangs powers off too.
//!
//! It never writes to the decoy disk and never logs: its output goes nowhere,
//! and a name sent to `/dev/kmsg` would reach the decoy's ring buffer. The one
//! thing it does keep is the reason a switch was refused ([`disarm`], [`end`]),
//! never on the decoy (see [`switch_refusal`]): a refused entry's on the
//! encrypted hidden volume beside the state file, written through the volume's
//! bind in the next root while that bind is on the volume's recorded device;
//! in the hidden session in the runtime directory in RAM.

use crate::mountinfo::{MountEntry, read_mountinfo};
use crate::whole_root::disk_guard;
use crate::whole_root::nextroot::{self, NEXTROOT};
use crate::whole_root::plan::{
    self, BINARY_NAME, Direction, PLAN_NAME, Plan, PlanError, RUNTIME_DIR, SNAPSHOT_NAME, unix_now,
};
use crate::whole_root::program_label::{DOMAIN, Outside, Started};
use crate::whole_root::run_scrub::Snapshot;
use crate::whole_root::selinux::{self, Selinux};
use crate::whole_root::session_end::session_end;
use crate::whole_root::{kernel_helpers, runtime_units, skips, switch_refusal, utab};
use std::io;
use std::path::{Path, PathBuf};

/// The drop-in directory for `systemd-soft-reboot.service`, below `/run`.
pub const DROPIN_DIR: &str = "systemd/system/systemd-soft-reboot.service.d";
/// The drop-in's file name (neutral).
pub const DROPIN_NAME: &str = "50-overlay-runtime.conf";
/// The argument the drop-in passes to the RAM copy of the binary.
pub const TRANSITION_ARG: &str = "transition";

/// The drop-in text that runs `binary transition` as the service's start.
///
/// The step fails closed: it exits non-zero where it could not end the
/// session itself ([`Outcome::exit_code`]), and so does a step that dies, or
/// a binary that cannot start. The service then fails, which skips its
/// `SuccessAction=soft-reboot-force` (no switch), and its `FailureAction=`
/// powers the machine off ([`SessionEnd::emergency_action`]: the forced form,
/// which systemd runs while `shutdown.target` is active).
///
/// [`SessionEnd::emergency_action`]: crate::whole_root::session_end::SessionEnd::emergency_action
pub fn dropin_text(binary: &Path) -> String {
    format!(
        "[Unit]\nFailureAction={}\n\
         [Service]\nType=oneshot\nStandardInput=null\nStandardOutput=null\nStandardError=null\n\
         ExecStart={} {TRANSITION_ARG}\n",
        session_end().emergency_action(),
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
/// path. A real power-off, which ends every hidden session, still detaches
/// device-mapper devices in systemd-shutdown.
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

/// The runtime guards' file name. systemd applies a unit's drop-ins in the
/// order of their file names across every directory, after the unit file
/// wherever that lies, and an `ExecStop=` in a later one adds its commands
/// back, a `JobTimeoutAction=` there sets the action again: `zz-` sorts after
/// the `override.conf` that `systemctl edit` writes, NixOS's `overrides.conf`
/// and numbered drop-ins. The entry checks the result after the reload all the
/// same.
pub const STOP_GUARD_NAME: &str = "zz-overlay-runtime.conf";

/// The drop-in directory for `unit`, below `/run`.
pub fn stop_guard_dir(unit: &str) -> PathBuf {
    Path::new("systemd/system").join(format!("{unit}.d"))
}

/// Units that must stop with the rest of the root at a soft-reboot, which
/// their own unit files prevent.
///
/// On Ubuntu (24.04 and 26.04), `dbus.service` and `dbus.socket` carry
/// `DefaultDependencies=no` so that the bus outlives a shutdown. At a
/// soft-reboot that leaves `dbus-daemon` to the final kill and the listening
/// socket open in PID 1. On 26.04 the new manager connects to it, nothing
/// answers, and after about 90 s it marks every D-Bus-activated service as
/// failed to load (accounts-daemon among them, so gdm never starts); 24.04's
/// comes up without that stall. Stopped at `shutdown.target`, as Debian 13
/// stops it, the bus comes up again in the other root like at boot. A bus
/// client still running then loses the bus while it stops, which is why the
/// switch first lets logind's shutdown signal end the programs that wait for
/// it ([`crate::whole_root::logind::request_soft_reboot`]). `Conflicts=` adds
/// up across drop-ins, so no later drop-in can take it back.
pub const SHUTDOWN_BOUND_UNITS: [&str; 2] = ["dbus.service", "dbus.socket"];

/// The drop-in text that stops a unit at `shutdown.target`.
pub const SHUTDOWN_BOUND_TEXT: &str = "[Unit]\nConflicts=shutdown.target\nBefore=shutdown.target\n";

/// The unit whose job is the switch, in both directions: its job timeout ends
/// a switch that hangs.
pub const SWITCH_TIMEOUT_UNIT: &str = "soft-reboot.target";

/// What the switch's job timeout does while a session is staged or running,
/// as `systemctl show --property=JobTimeoutAction` prints it.
///
/// `poweroff-force` makes PID 1 leave its main loop (systemd 258 and newer
/// wait five seconds first) and hand the machine to `systemd-shutdown`, which
/// ends every process left, unmounts every filesystem, removes the
/// device-mapper devices and powers off, as at the end of every power-off. It
/// starts no new job, so the units that hold up the switch cannot hold up the
/// power-off. A plain `poweroff` would do nothing here: systemd skips that
/// action while `shutdown.target` is active or has a start job queued
/// ("Shutdown is already active. Skipping emergency action request
/// poweroff."), and during a switch it always is, as
/// `systemd-soft-reboot.service` requires it. Were it not skipped, the
/// `poweroff.target` it starts would have to stop the very units that hold up
/// the switch.
pub const SWITCH_TIMEOUT_ACTION: &str = "poweroff-force";

/// The timeout guard's text ([`SWITCH_TIMEOUT_ACTION`]). The timeout itself,
/// `JobTimeoutSec=`, stays the unit's own.
pub const SWITCH_TIMEOUT_TEXT: &str = "[Unit]\nJobTimeoutAction=poweroff-force\n";

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
        .chain(std::iter::once((SWITCH_TIMEOUT_UNIT, SWITCH_TIMEOUT_TEXT)))
}

/// Install the drop-in, and the runtime guards ([`runtime_guards`]), under
/// `run`, readable by all ([`plan::SERVICE_CONFIG_MODE`]). The caller reloads
/// the service manager.
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

/// The drop-in text that keeps PID 1 quiet about a mount unit's start and
/// stop. PID 1 logs a job's start and end at the info level (`Unmounting
/// /mnt/data/root/decoy/boot...` among them) and shows them on the console;
/// for a unit whose `LogLevelMax=` is below the info level it does neither,
/// nor logs the unit's `Deactivated successfully.`. A failure, logged as a
/// warning or an error, still shows.
pub const QUIET_MOUNTS_TEXT: &str = "[Mount]\nLogLevelMax=notice\n";

/// Whether `prefix` names the mount units [`install_quiet_mounts`] quiets: a
/// unit name ending in `-.mount`, which systemd reads the drop-ins of for
/// every mount unit whose name starts with it up to the dash.
fn is_mount_prefix(prefix: &str) -> bool {
    runtime_units::valid_unit_name(prefix)
        && prefix.len() > "-.mount".len()
        && prefix.ends_with("-.mount")
}

/// Install [`QUIET_MOUNTS_TEXT`] for the mount units `prefix` names
/// (`mnt-data-root-decoy-.mount`: every mount below `/mnt/data/root/decoy`)
/// under `run`, readable by all ([`plan::SERVICE_CONFIG_MODE`]), as
/// [`STOP_GUARD_NAME`] in the prefix's drop-in directory. The hidden PID 1
/// loads it when it starts; [`remove_dropin`] removes it.
pub fn install_quiet_mounts(run: &Path, prefix: &str) -> io::Result<PathBuf> {
    if !is_mount_prefix(prefix) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{prefix} is no prefix of mount units"),
        ));
    }
    let dir = run.join(stop_guard_dir(prefix));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(STOP_GUARD_NAME);
    plan::write_atomic_with_mode(
        &path,
        QUIET_MOUNTS_TEXT.as_bytes(),
        plan::SERVICE_CONFIG_MODE,
    )?;
    Ok(path)
}

/// The drop-in directories below `run`, relative to it, that hold a
/// [`QUIET_MOUNTS_TEXT`] of [`install_quiet_mounts`]: a prefix of mount
/// units whose [`STOP_GUARD_NAME`] is that text, whichever prefix the entry
/// quieted.
fn quiet_mount_dirs(run: &Path) -> Vec<PathBuf> {
    let units = Path::new(runtime_units::RUNTIME_UNIT_DIR);
    let Ok(entries) = std::fs::read_dir(run.join(units)) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let prefix = name.strip_suffix(".d")?;
            let ours = std::fs::read(entry.path().join(STOP_GUARD_NAME))
                .is_ok_and(|text| text == QUIET_MOUNTS_TEXT.as_bytes());
            (is_mount_prefix(prefix) && ours).then(|| units.join(&name))
        })
        .collect()
}

/// Remove the drop-in, the runtime guards (the timeout guard among them) and
/// the quieted mount units' drop-in under `run`, with each of their
/// directories that is left empty, unless `kept` (the `/run` snapshot taken
/// before the entry) lists it: a drop-in directory the decoy had already
/// keeps whatever else it holds, and only the files NAILS wrote go. Returns
/// whether a file went, which PID 1 keeps loaded until its next reload.
pub fn remove_dropin(run: &Path, kept: &Snapshot) -> bool {
    let files = runtime_guards()
        .map(|(unit, _)| (stop_guard_dir(unit), STOP_GUARD_NAME))
        .chain(std::iter::once((PathBuf::from(DROPIN_DIR), DROPIN_NAME)))
        .chain(
            quiet_mount_dirs(run)
                .into_iter()
                .map(|dir| (dir, STOP_GUARD_NAME)),
        );
    let mut removed = false;
    for (dir, name) in files {
        removed |= std::fs::remove_file(run.join(&dir).join(name)).is_ok();
        if !kept.contains(dir.as_os_str()) {
            let _ = std::fs::remove_dir(run.join(&dir));
        }
    }
    removed
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
    /// `systemctl`, which [`end`] asks to power off at once; `None` leaves
    /// that to the kernel.
    pub systemctl: Option<PathBuf>,
    /// Now, in seconds since the epoch.
    pub now: u64,
    /// The live mount table, or `None` where it could not be read: the step
    /// then cannot tell whether `/run/nextroot` is mounted, and powers off.
    pub mounts: Option<Vec<MountEntry>>,
    /// How the step powers off when it cannot do its work ([`end`]).
    pub power_off: PowerOff,
    /// What detaches the tree at `/run/nextroot` and returns what is still
    /// mounted on or below it ([`nextroot::detach_tree`]; a test's stand-in).
    pub detach: fn(&Path) -> Vec<PathBuf>,
    /// What tells the domain this step runs in, and gives the RAM copy of the
    /// binary its label again: the running kernel's SELinux, or a test's
    /// stand-in.
    pub selinux: &'static dyn Selinux,
    /// How this step was started: by PID 1 from the drop-in, as itself again,
    /// or by hand ([`Started::by_hand`]), which checks no domain.
    pub start: Started,
}

/// How the step powers off ([`PowerOff::system`]).
#[derive(Debug, Clone, Copy)]
pub struct PowerOff {
    /// How long it waits, once PID 1 took the power-off, before it asks the
    /// kernel itself.
    pub grace: std::time::Duration,
    /// Sync and power off through the kernel, which returns only when the
    /// kernel did not power the machine off.
    pub kernel: fn() -> bool,
}

impl PowerOff {
    /// The real power-off: [`POWER_OFF_GRACE`], then the kernel's.
    pub fn system() -> Self {
        Self {
            grace: POWER_OFF_GRACE,
            kernel: crate::whole_root::emergency::kernel_power_off,
        }
    }
}

impl Env {
    /// The real system, for a step started as `start` says.
    pub fn system(start: Started) -> Self {
        Self {
            run: PathBuf::from("/run"),
            nextroot: PathBuf::from(NEXTROOT),
            runtime_dir: PathBuf::from(RUNTIME_DIR),
            systemctl: crate::whole_root::tools::find(None, "systemctl"),
            now: unix_now(),
            mounts: read_mountinfo().ok(),
            power_off: PowerOff::system(),
            detach: nextroot::detach_tree,
            selinux: &selinux::KERNEL,
            start,
        }
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
    /// `/run/nextroot` was populated but not armed for this transition: it
    /// was detached, so PID 1 stays on this root.
    Disarmed(String),
    /// The step could not do its work, or met a switch it must never let
    /// happen, and asked for the session's end ([`end`]). It returns only
    /// where neither PID 1 nor the kernel took it. Carries why.
    Ended(String),
}

impl Outcome {
    /// The exit code of the step: 0 lets the switch (or a plain soft-reboot)
    /// go on; non-zero fails the service, which then powers off through its
    /// `FailureAction=` ([`dropin_text`]) instead of switching.
    pub fn exit_code(&self) -> u8 {
        match self {
            Outcome::NothingToDo | Outcome::Entered | Outcome::Disarmed(_) => 0,
            Outcome::Ended(_) => 1,
        }
    }
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
    let mut plan = match Plan::load(&env.runtime_dir.join(PLAN_NAME)) {
        Ok(plan) => plan,
        // Not ours to judge: without a plan, /run/nextroot may be another
        // tool's staged root.
        Err(PlanError::Missing) => return Outcome::NothingToDo,
        Err(e) => return end(env, None, &format!("the session plan cannot be read: {e}")),
    };
    let Some(mounts) = &env.mounts else {
        return end(env, Some(&plan), "the mount table cannot be read");
    };
    let mounted = nextroot::is_mount_point(mounts, &env.nextroot);
    let direction = [Direction::Enter, Direction::Leave]
        .into_iter()
        .find(|direction| plan.armed_for(*direction, env.now));
    match (direction, mounted) {
        (Some(Direction::Leave), _) => end(
            env,
            Some(&plan),
            "the switch is armed for a way back to the decoy, and a hidden session never goes back",
        ),
        (Some(Direction::Enter), false) => end(
            env,
            Some(&plan),
            "the entry is armed, but nothing is mounted at /run/nextroot",
        ),
        (None, _) if plan.armed.is_some() => {
            end(env, Some(&plan), "the arming of the switch expired")
        }
        (None, false) => Outcome::NothingToDo,
        (None, true) => disarm(env, &plan, mounts, "not armed for this transition"),
        (Some(Direction::Enter), true) => {
            if plan.program_label.is_some()
                && let Err(outside) = env
                    .start
                    .enter_domain(env.selinux, &env.runtime_dir.join(BINARY_NAME))
            {
                return outside_domain(env, &plan, &outside);
            }
            enter(env, &mut plan, mounts)
        }
    }
}

/// The end of an armed entry that does not run in the program's domain (see
/// the module docs): a power-off.
fn outside_domain(env: &Env, plan: &Plan, outside: &Outside) -> Outcome {
    let why = format!("the last step before the switch does not run in {DOMAIN}: {outside}");
    end(env, Some(plan), &why)
}

/// End the session the way every hidden session ends
/// ([`crate::whole_root::session_end`]), because the switch must not go on:
/// keep why (`why`) where `status` can read it, as [`disarm`] does, then ask
/// PID 1 and the kernel to power off at once. Where neither took it, which
/// happens only where the kernel refuses (a test's stand-in, a container),
/// undo what the entry did of the switch that this process can undo (the
/// repoint of `current-system` on the decoy side) and detach `/run/nextroot`,
/// so that nothing can switch into it, and return: the caller exits
/// non-zero, and the drop-in's `FailureAction=` powers off.
fn end(env: &Env, plan: Option<&Plan>, why: &str) -> Outcome {
    if let Some(plan) = plan {
        keep_refusal(env, plan, env.mounts.as_deref(), why);
    }
    let _ = session_end().now(
        env.systemctl.as_deref(),
        env.power_off.grace,
        env.power_off.kernel,
    );
    if let Some(plan) = plan
        && plan.entered_at.is_none()
        && let Some(system) = &plan.decoy.system
    {
        let _ = repoint_current_system(&env.run, system);
    }
    let _ = (env.detach)(&env.nextroot);
    Outcome::Ended(why.to_string())
}

/// Keep why the switch was refused, before detaching anything, so `status`
/// can say so. The shutdown has unmounted the hidden volume at its own path:
/// in the hidden session, which PID 1 does not leave, the reason goes to the
/// runtime directory; on the decoy side to the hidden volume through its bind
/// in the next root, only while that bind is on the recorded device (and so
/// not where the mount table cannot be read). Both are no-ops unless a switch
/// was armed, so a plain reboot that meets a leftover tree records nothing.
fn keep_refusal(env: &Env, plan: &Plan, mounts: Option<&[MountEntry]>, why: &str) {
    if plan.entered_at.is_some() {
        switch_refusal::record_in_runtime(plan, &env.runtime_dir, why, env.now);
    } else if let Some(mounts) = mounts {
        switch_refusal::record_on_volume(mounts, plan, &env.nextroot, why, env.now);
    }
}

/// Detach a `/run/nextroot` the plan did not arm. On the decoy side (never
/// entered) the runtime pieces go too and the hidden backend is marked for
/// deferred removal, so nothing of the failed activation is left, its key
/// included; in the hidden session the plan stays. Where something stays
/// mounted at `/run/nextroot`, PID 1 would switch into it: it powers off
/// instead ([`end`]).
fn disarm(env: &Env, plan: &Plan, mounts: &[MountEntry], why: &str) -> Outcome {
    keep_refusal(env, plan, Some(mounts), why);
    let remaining = (env.detach)(&env.nextroot);
    if !remaining.is_empty() {
        let list: Vec<String> = remaining.iter().map(|p| p.display().to_string()).collect();
        return end(
            env,
            None,
            &format!(
                "{why}, and {} stays mounted after the detach",
                list.join(", ")
            ),
        );
    }
    if plan.entered_at.is_none() {
        // A reboot that met the leftover tree: the volume was unmounted by
        // the shutdown, and a real reboot would have closed it too.
        let _ = crate::whole_root::ret::close_backend_deferred(plan);
        let kept = env.saved_snapshot().unwrap_or_default();
        remove_dropin(&env.run, &kept);
        runtime_units::remove_masks(
            &env.run,
            &plan.masks,
            &plan.boot_masks,
            &plan.generator_masks,
            &kept,
        );
        skips::remove_skips(&env.run, &plan.skips, &kept);
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

/// Prepare the entry, or end the session where any part of it that the
/// hidden session's safety rests on fails (see the module docs). Only two
/// parts are best effort, each for its reason:
///
/// - the masks of the units the hidden root does not need
///   ([`runtime_units::mask_units_best_effort`]): they fail there or do
///   nothing, and the boot filesystems they would write to are bound
///   read-only by the fstab policy, whose masks are not best effort;
/// - the `utab` lines of the mounts the switch leaves behind
///   ([`prune_utab`]): `utab` is in RAM, and a line left there changes only
///   which mount options the hidden session's own tools read.
fn enter(env: &Env, plan: &mut Plan, mounts: &[MountEntry]) -> Outcome {
    if let Err(why) = repoint_and_check(env, &plan.hidden) {
        return end(env, Some(plan), &why);
    }
    // Without its masks and skips the hidden systemd would swap onto, or mount
    // read-write, a decoy disk: never enter without them, nor without the
    // generator masks, which keep it from mounting the partitions the GPT
    // auto-generator would find, or swapping onto them. Without its session
    // units it would run without the watcher and the sleep guard, and
    // without the opted-in read-only rule the unused disks stay writable.
    let prepared = runtime_units::mask_units(&env.run, &plan.masks)
        .map_err(|e| format!("could not mask decoy units: {e}"))
        .and_then(|_| {
            skips::skip_units(&env.run, &plan.skips)
                .map_err(|e| format!("could not skip decoy units: {e}"))
        })
        .and_then(|_| {
            runtime_units::mask_generators(&env.run, &plan.generator_masks)
                .map_err(|e| format!("could not mask generators: {e}"))
        })
        .and_then(|_| {
            runtime_units::install_units(&env.run, &plan.session_units)
                .map_err(|e| format!("could not install the session's units: {e}"))
        })
        .and_then(|_| {
            if !plan.read_only_disks {
                return Ok(());
            }
            disk_guard::install_rule(&env.run, &env.runtime_dir.join(BINARY_NAME))
                .map(|_| ())
                .map_err(|e| format!("could not install the read-only rule for unused disks: {e}"))
        });
    if let Err(why) = prepared {
        return end(env, Some(plan), &why);
    }
    runtime_units::mask_units_best_effort(&env.run, &plan.boot_masks);
    prune_utab(env, mounts);
    plan.armed = None;
    plan.entered_at = Some(env.now);
    // The hidden session's own tools read the plan to tell where they run;
    // one left armed for the entry would arm the next soft-reboot too.
    if let Err(e) = plan.write_atomic(&env.runtime_dir.join(PLAN_NAME)) {
        plan.entered_at = None;
        plan.armed = Some(plan::Arm {
            direction: Direction::Enter,
            at: env.now,
        });
        return end(env, Some(plan), &format!("could not record the entry: {e}"));
    }
    Outcome::Entered
}

/// Keep in `utab` only the lines that still name the same mount once PID 1
/// has switched to the next root ([`utab::surviving_lines`]): the hidden
/// session must not join the decoy's lines to the mounts that reuse the IDs
/// of the decoy's root and its submounts. Best effort: on any error the file
/// stays as it is.
fn prune_utab(env: &Env, mounts: &[MountEntry]) {
    let _ = utab::update(&env.run, |text| {
        utab::surviving_lines(text, mounts, &env.nextroot)
    });
}

/// How long the step waits, once PID 1 took the power-off, before it asks
/// the kernel itself: PID 1's final stage signals every process to end as
/// soon as it starts, this one included.
const POWER_OFF_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

#[cfg(test)]
#[path = "transition_tests.rs"]
mod tests;
