// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! What the hidden session would still hand the decoy's journal at the way
//! back, and the steps that keep it out.
//!
//! The way back writes journald's kmsg cursor so the decoy's journald skips
//! every kernel record logged before it ([`crate::whole_root::run_scrub`]).
//! Two things still reach the decoy's journal without these steps:
//!
//! - **What is logged after the cursor.** PID 1 sends every process left
//!   once the transition step has ended `SIGTERM` and at once `SIGKILL`, and
//!   logs `Sending SIGKILL to PID N (<name>)` for each, naming the hidden
//!   session's processes. The kernel logs the hidden filesystem's
//!   `unmounting filesystem <UUID>` line when PID 1 leaves the hidden root.
//!   [`end_leftovers`] kills those processes as PID 1 would, first thing in
//!   the way back (their units' stop commands then run before the `/run`
//!   scrub and the restores) and once more before the cursor is taken, so
//!   PID 1 finds none of them; [`quiet_hidden_unmount`] sets the hidden ext4
//!   filesystem's message limit to zero, so the kernel drops that line.
//! - **What waits in journald's sockets.** A soft-reboot keeps the socket
//!   units of journald open (they never stop at a shutdown), and journald's
//!   store of standard-output streams with PID 1 (`FileDescriptorStorePreserve=yes`):
//!   the decoy's journald reads at its start what the hidden root sent them
//!   after its own journald stopped, the audit records of its last units'
//!   stops among it. [`empty_journal_sockets`] stops those socket units and
//!   drops that store, which discards what they hold, and opens journald's
//!   own two sockets again, empty, so that the decoy's start finds them
//!   listening as after a plain soft-reboot. The audit socket stays closed
//!   ([`REOPENED_SOCKETS`]).
//!
//! The switch itself leaves `/run/nextroot` behind, an empty folder where the
//! decoy root was mounted for it, which a boot never has. It is a mount point
//! until PID 1 has left the hidden root, so nothing before the switch can
//! remove it: [`remove_nextroot_at_start`] leaves a runtime line for the
//! decoy's `systemd-tmpfiles-setup.service`, which removes the folder and the
//! line with it at the decoy's start.
//!
//! What stays is listed in the residue catalog (`kmsg-import`,
//! `journal-socket-carry`): PID 1's own last generic lines (the soft-reboot
//! service's end, `Soft-rebooting.`, its final kill of the `(sd-close)`
//! helpers it starts after the step to close a descriptor and, with the
//! kernel's audit on, the audit records of that service's start and stop and
//! of the BPF programs it unloads), a process of the session that stays in
//! uninterruptible sleep past [`end_leftovers`]'s bound (PID 1 names it), a
//! filesystem other than ext4's unmount line, and the kernel's lines of the
//! hidden mapping's teardown, which the kernel logs as PID 1 starts the
//! decoy. journald's sockets are new ones, made at the way back (their files
//! and their units' start time date from it), where a plain soft-reboot keeps
//! those of the boot; where the kernel's audit is on,
//! the decoy's start opens journald's audit socket anew and logs that, which
//! a plain soft-reboot does not; and the stream of a process the soft-reboot
//! leaves running goes with the store ([`drop_journal_streams`]).
//!
//! Like the rest of the transition, nothing here logs, and every step is
//! best effort.

use crate::proc::ProcessHandle;
use crate::whole_root::plan::Plan;
use crate::whole_root::tools::{self, TOOL_BUDGET};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Where the tail steps look.
#[derive(Debug, Clone)]
pub struct Places {
    /// The procfs (`/proc`), with the cgroup hierarchy beside it
    /// (`/sys/fs/cgroup`).
    pub proc: PathBuf,
    /// `/sys/dev/block`, which names a block device by its number.
    pub sys_dev_block: PathBuf,
    /// `/sys/fs/ext4`, one folder per mounted ext4 filesystem.
    pub sys_fs_ext4: PathBuf,
}

impl Places {
    /// The real system.
    pub fn system() -> Self {
        Self {
            proc: PathBuf::from("/proc"),
            sys_dev_block: PathBuf::from("/sys/dev/block"),
            sys_fs_ext4: PathBuf::from("/sys/fs/ext4"),
        }
    }
}

/// The processes PID 1 would still signal at the switch, under the procfs at
/// `proc` (and the cgroup hierarchy beside it): every one but PID 1, `own`
/// (this step), kernel threads, zombies, and those systemd leaves running
/// across a soft-reboot (a `SurviveFinalKillSignal=yes` unit's, a root
/// storage daemon's). A process whose state cannot be read is left alone, as
/// PID 1 leaves it.
pub fn leftovers(proc: &Path, own: u32) -> Vec<u32> {
    let Ok(dir) = std::fs::read_dir(proc) else {
        return Vec::new();
    };
    let cgroups = crate::whole_root::fresh_pids::cgroups_beside(proc);
    let mut pids: Vec<u32> = dir
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|&pid| pid > 1 && pid != own)
        .filter(|&pid| {
            let dir = proc.join(pid.to_string());
            let Some(stat) = std::fs::read_to_string(dir.join("stat"))
                .ok()
                .and_then(|text| crate::proc::parse_stat(&text))
            else {
                return false;
            };
            !stat.is_kernel_thread()
                && stat.state != 'Z'
                && stat.state != 'X'
                && !crate::whole_root::fresh_pids::survives_soft_reboot(&dir, &cgroups)
        })
        .collect();
    pids.sort_unstable();
    pids
}

/// How many rounds [`end_leftovers`] makes: a process that forked before its
/// kill leaves a child the next round finds, and a unit PID 1 started again
/// before its stop job was queued leaves a new process.
const KILL_ROUNDS: usize = 4;

/// How long [`end_leftovers`] waits in each round for PID 1 to reap the
/// processes it killed. A process in uninterruptible sleep dies only when the
/// sleep ends.
const REAP_BUDGET: Duration = Duration::from_secs(5);

/// How long [`end_leftovers`] waits in each round for the stop jobs it queued
/// and for any other job but `own_jobs`.
const JOBS_BUDGET: Duration = Duration::from_secs(5);

/// The service each of `pids` runs in, under the procfs at `proc`: the
/// outermost `.service` of its cgroup path (`user@1000.service` for a
/// process of a user manager), each once, sorted. A process outside a
/// service (a scope, the root cgroup) has none.
pub fn services_of(proc: &Path, pids: &[u32]) -> Vec<String> {
    let mut units: Vec<String> = pids
        .iter()
        .filter_map(|pid| {
            let content =
                std::fs::read_to_string(proc.join(pid.to_string()).join("cgroup")).ok()?;
            let path = crate::cgroup::v2_path(&content)?;
            path.split('/')
                .find(|segment| segment.ends_with(".service") && segment.len() > ".service".len())
                .map(str::to_string)
        })
        .collect();
    units.sort();
    units.dedup();
    units
}

/// End every process [`leftovers`] lists on the real system (`places.proc`
/// must be `/proc`), in rounds until none is left. Each round first queues a
/// stop job for the services they run in, through `systemctl` when there is
/// one, so that PID 1 does not start one of them again under `Restart=` (a
/// queued stop job holds a restart back), then SIGKILLs them, waits, bounded,
/// until PID 1 has reaped them (once a process is gone from `/proc`, PID 1 has
/// also logged what its end means for its unit, and that goes before the
/// cursor), and waits for every job but `own_jobs` and for any restart still
/// due. Returns the pids killed.
pub fn end_leftovers(places: &Places, systemctl: Option<&Path>, own_jobs: &[&str]) -> Vec<u32> {
    let own = std::process::id();
    let mut killed = Vec::new();
    for _ in 0..KILL_ROUNDS {
        let pids = leftovers(&places.proc, own);
        if pids.is_empty() {
            break;
        }
        if let Some(systemctl) = systemctl {
            let units = services_of(&places.proc, &pids);
            if !units.is_empty() {
                let mut args = vec!["stop", "--no-block", "--"];
                args.extend(units.iter().map(String::as_str));
                let _ = tools::run(systemctl, &args, TOOL_BUDGET);
            }
        }
        let handles: Vec<ProcessHandle> = pids
            .into_iter()
            .filter_map(ProcessHandle::open)
            .filter(ProcessHandle::kill)
            .collect();
        let deadline = Instant::now() + REAP_BUDGET;
        while handles.iter().any(is_unreaped) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        killed.extend(handles.iter().map(ProcessHandle::pid));
        if let Some(systemctl) = systemctl {
            let _ = tools::wait_for_other_jobs(systemctl, own_jobs, JOBS_BUDGET);
            let _ = settle_units(systemctl);
        }
    }
    killed
}

/// Whether the process `handle` opened is still in `/proc`: running, or a
/// zombie PID 1 has not reaped yet.
fn is_unreaped(handle: &ProcessHandle) -> bool {
    crate::proc::stat(handle.pid()).is_some_and(|s| s.start_time == handle.start_time())
}

/// How long [`settle_units`] waits for PID 1 to give up the restarts the
/// kills scheduled.
const RESTART_BUDGET: Duration = Duration::from_secs(5);

/// Wait, bounded, until no unit waits to restart: a unit with `Restart=`
/// whose process [`end_leftovers`] killed schedules a restart, which the
/// soft-reboot refuses, and PID 1 logs that refusal when the restart is due.
/// Returns whether none waits any more.
pub fn settle_units(systemctl: &Path) -> bool {
    let deadline = Instant::now() + RESTART_BUDGET;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        let Some(list) = tools::run_output(
            systemctl,
            &[
                "list-units",
                "--all",
                "--plain",
                "--no-legend",
                "--state=auto-restart",
            ],
            left.min(TOOL_BUDGET),
        ) else {
            return false;
        };
        if list.trim().is_empty() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// journald's socket units, those of its namespaces (a pattern `systemctl`
/// matches against the loaded units), and the syslog socket journald forwards
/// to, which a soft-reboot keeps open with what they hold.
pub const JOURNAL_SOCKETS: [&str; 5] = [
    "systemd-journald.socket",
    "systemd-journald-dev-log.socket",
    "systemd-journald-audit.socket",
    "systemd-journald@*.socket",
    "syslog.socket",
];

/// The sockets of [`JOURNAL_SOCKETS`] that a plain soft-reboot carries into
/// the decoy listening, and that the way back opens again once it has
/// emptied them: journald's own two. A namespace's socket (named after a unit
/// of the session's) and the syslog socket (stopped by the shutdown before
/// the step) stay closed, and so does the audit socket: from its opening on
/// it takes every audit record the kernel makes, past the kmsg cursor's
/// reach, the kernel's record of PID 1 opening it (`EVENT_LISTENER`, with the
/// hidden root's systemd as `exe=`) and those of the step itself among them.
/// The decoy's start opens it again, and logs that.
pub const REOPENED_SOCKETS: [&str; 2] =
    ["systemd-journald.socket", "systemd-journald-dev-log.socket"];

/// The service whose descriptor store holds journald's standard-output
/// streams across its stop and the soft-reboot.
pub const JOURNAL_SERVICE: &str = "systemd-journald.service";

/// The `systemctl` call that lists which of [`REOPENED_SOCKETS`] are active.
pub fn active_sockets_call() -> Vec<&'static str> {
    let mut args = vec![
        "list-units",
        "--plain",
        "--no-legend",
        "--state=active",
        "--",
    ];
    args.extend(REOPENED_SOCKETS);
    args
}

/// The units of [`REOPENED_SOCKETS`] a `systemctl list-units --plain
/// --no-legend` `listing` names, in the order of [`REOPENED_SOCKETS`].
pub fn listed_sockets(listing: &str) -> Vec<&'static str> {
    let named: Vec<&str> = listing
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    REOPENED_SOCKETS
        .into_iter()
        .filter(|unit| named.contains(unit))
        .collect()
}

/// The units of [`REOPENED_SOCKETS`] active now, or `None` when `systemctl`
/// cannot say.
pub fn active_sockets(systemctl: &Path) -> Option<Vec<&'static str>> {
    tools::run_output(systemctl, &active_sockets_call(), TOOL_BUDGET)
        .map(|listing| listed_sockets(&listing))
}

/// The file in the runtime directory that keeps, from the entry to the way
/// back, which of journald's sockets the decoy had listening as it left.
pub const SOCKETS_NAME: &str = "journal-sockets";

/// Keep at `path`, at the entry, which of journald's sockets the decoy has
/// listening now, one per line, as a plain soft-reboot would carry them; the
/// way back opens those again ([`empty_journal_sockets`]). Without an answer
/// from `systemctl` no file stays, and the way back goes by the sockets
/// listening when it runs. Returns whether the file was written.
pub fn record_sockets(systemctl: &Path, path: &Path) -> bool {
    let written = active_sockets(systemctl).is_some_and(|units| {
        let text: String = units.iter().map(|unit| format!("{unit}\n")).collect();
        crate::whole_root::plan::write_private_atomic(path, text.as_bytes()).is_ok()
    });
    if !written {
        let _ = std::fs::remove_file(path);
    }
    written
}

/// The `systemctl` calls of [`empty_journal_sockets`], in order, where
/// `active` are the units of [`REOPENED_SOCKETS`] to open again: stop each of
/// [`JOURNAL_SOCKETS`] (a unit the system lacks fails alone), forget a
/// failure of journald's (a failed service keeps its descriptor store, and
/// PID 1 refuses to drop the store of a service that is not dead), drop that
/// store, then start each of `active` again.
pub fn journal_socket_calls(active: &[&'static str]) -> Vec<Vec<&'static str>> {
    JOURNAL_SOCKETS
        .iter()
        .map(|unit| vec!["stop", *unit])
        .chain(std::iter::once(vec!["reset-failed", JOURNAL_SERVICE]))
        .chain(std::iter::once(DROP_STREAMS.to_vec()))
        .chain(active.iter().map(|unit| vec!["start", *unit]))
        .collect()
}

/// The `systemctl` call that drops journald's descriptor store of
/// standard-output streams.
pub const DROP_STREAMS: [&str; 3] = ["clean", "--what=fdstore", JOURNAL_SERVICE];

/// Drop journald's stored standard-output streams at the entry, as the way
/// back does with [`empty_journal_sockets`]. PID 1 closes each stored
/// descriptor through a helper process of its own, so the next start that
/// releases the store uses a process number per stream: dropped before the
/// entry records the process-number counter, neither the hidden start nor
/// the decoy's start after the way back uses them, and the way back's
/// measure of how many numbers a start uses up to its getty
/// ([`crate::whole_root::fresh_pids`]) holds for the decoy's start.
///
/// The store holds the stream of every process journald took one from, a
/// process the soft-reboot leaves running among them (a root storage daemon,
/// a `SurviveFinalKillSignal=yes` unit's): such a process's standard output
/// and error no longer reach the journal from here on, and its writes to
/// them fail. Returns whether the call succeeded.
pub fn drop_journal_streams(systemctl: &Path) -> bool {
    tools::run(systemctl, &DROP_STREAMS, TOOL_BUDGET) == tools::Outcome::Done
}

/// Discard what journald's sockets and descriptor store hold: stop the socket
/// units, which closes them with their queues, and drop journald's stored
/// streams (stopped by now, it no longer reads them); then open journald's
/// own sockets again, empty, so that PID 1 carries them into the decoy
/// listening as a plain soft-reboot does, and the decoy's start does not open
/// them anew (its `Listening on` lines would tell a way back from a plain
/// soft-reboot). Those to open again are `decoy`, the sockets the decoy had
/// listening at the entry ([`record_sockets`]): a socket the hidden root's
/// shutdown closed is opened again too (PID 1 before systemd 258 fails a
/// socket that receives anything once journald has stopped for the
/// soft-reboot). Without that record, those listening now. Returns the calls
/// that did not succeed.
pub fn empty_journal_sockets(systemctl: &Path, decoy: Option<&[&'static str]>) -> Vec<String> {
    // Without a record or a listing none is opened again: the decoy's start
    // opens them.
    let active = match decoy {
        Some(units) => units.to_vec(),
        None => active_sockets(systemctl).unwrap_or_default(),
    };
    journal_socket_calls(&active)
        .into_iter()
        .filter(|args| tools::run(systemctl, args, TOOL_BUDGET) != tools::Outcome::Done)
        .map(|args| args.join(" "))
        .collect()
}

/// What [`quiet_hidden_unmount`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Quiet {
    /// The hidden filesystem's messages are dropped from now on.
    Quieted(PathBuf),
    /// No hidden volume of its own is recorded, or it shows in the decoy's
    /// tree, which keeps it mounted after the switch.
    NotHidden,
    /// The hidden volume is not an ext4 filesystem the kernel lists.
    NotExt4,
    /// The limit could not be set.
    Failed(String),
}

/// The ext4 setting of how many messages a filesystem may log in an interval.
const BURST: &str = "msg_ratelimit_burst";
/// The ext4 setting of that interval; zero turns the limit off.
const INTERVAL: &str = "msg_ratelimit_interval_ms";

/// Let the hidden volume's ext4 filesystem log no message any more, so the
/// kernel drops its `unmounting filesystem <UUID>` line when PID 1 leaves
/// the hidden root: its message limit (`msg_ratelimit_burst`) set to zero,
/// over an interval that is not zero. The setting lives with the filesystem
/// and goes with it at the unmount.
///
/// Only a volume of its own that nothing of the decoy's tree (below
/// `nextroot` in `mounts`) shows: a filesystem that stays mounted after the
/// switch keeps its messages.
pub fn quiet_hidden_unmount(
    places: &Places,
    plan: &Plan,
    mounts: &[crate::mountinfo::MountEntry],
    nextroot: &Path,
) -> Quiet {
    let Some(dev) = plan.hidden_dev.as_deref() else {
        return Quiet::NotHidden;
    };
    if plan.accepted_decoy_storage.is_some()
        || mounts
            .iter()
            .any(|m| m.dev == dev && m.mount_point.starts_with(nextroot))
    {
        return Quiet::NotHidden;
    }
    let Some(name) = std::fs::read_link(places.sys_dev_block.join(dev))
        .ok()
        .and_then(|link| link.file_name().map(std::ffi::OsStr::to_os_string))
    else {
        return Quiet::NotExt4;
    };
    let dir = places.sys_fs_ext4.join(name);
    if !dir.join(BURST).exists() {
        return Quiet::NotExt4;
    }
    let interval = std::fs::read_to_string(dir.join(INTERVAL)).unwrap_or_default();
    let set = || -> io::Result<()> {
        if interval.trim() == "0" {
            std::fs::write(dir.join(INTERVAL), "5000")?;
        }
        std::fs::write(dir.join(BURST), "0")
    };
    match set() {
        Ok(()) => Quiet::Quieted(dir),
        Err(e) => Quiet::Failed(e.to_string()),
    }
}

/// The runtime folder of `systemd-tmpfiles` configuration, below `/run`.
pub const TMPFILES_DIR: &str = "tmpfiles.d";

/// The way back's line for the decoy's `systemd-tmpfiles-setup.service`
/// (neutral name). It removes itself.
pub const TMPFILES_NAME: &str = "overlay-runtime-boot.conf";

/// [`TMPFILES_NAME`] on the decoy, as the artifact registry names it.
pub const TMPFILES_PATH: &str = "/run/tmpfiles.d/overlay-runtime-boot.conf";

/// The text of [`TMPFILES_NAME`]: at the decoy's start (`!`, a boot's
/// `--boot` run only), remove `/run/nextroot` if it is an empty folder
/// (`r` never removes a folder with anything in it, nor a mount point),
/// this file and, when the way back made it, the folder that holds it.
/// `systemd-tmpfiles` removes what is inside a folder before the folder.
pub fn tmpfiles_text(made_dir: bool) -> String {
    let mut text = format!("r! /run/nextroot\nr! {TMPFILES_PATH}\n");
    if made_dir {
        text.push_str(&format!("r! /run/{TMPFILES_DIR}\n"));
    }
    text
}

/// Leave [`TMPFILES_NAME`] in `run`'s [`TMPFILES_DIR`], making the folder
/// when the decoy has none (it is then removed with the file). Run after
/// the scrub, which would remove it as the session's.
pub fn remove_nextroot_at_start(run: &Path) -> io::Result<()> {
    let dir = run.join(TMPFILES_DIR);
    let made_dir = !dir.is_dir();
    if made_dir {
        std::fs::create_dir(&dir)?;
    }
    let written = crate::whole_root::plan::write_atomic_with_mode(
        &dir.join(TMPFILES_NAME),
        tmpfiles_text(made_dir).as_bytes(),
        crate::whole_root::plan::SERVICE_CONFIG_MODE,
    );
    if written.is_err() && made_dir {
        let _ = std::fs::remove_dir(&dir);
    }
    written
}

#[cfg(test)]
#[path = "tail_tests.rs"]
mod tests;
