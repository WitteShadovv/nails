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
//!   [`end_leftovers`] kills those processes before the cursor is taken, as
//!   PID 1 would, so PID 1 finds none of them; [`quiet_hidden_unmount`] sets
//!   the hidden ext4 filesystem's message limit to zero, so the kernel drops
//!   that line.
//! - **What waits in journald's sockets.** A soft-reboot keeps the socket
//!   units of journald open (they never stop at a shutdown), and journald's
//!   store of standard-output streams with PID 1 (`FileDescriptorStorePreserve=yes`):
//!   the decoy's journald reads at its start what the hidden root sent them
//!   after its own journald stopped, the audit records of its last units'
//!   stops among it. [`empty_journal_sockets`] stops those socket units and
//!   drops that store, which discards what they hold; the decoy's start opens
//!   them again, as a boot does.
//!
//! What stays is listed in the residue catalog (`kmsg-import`): PID 1's own
//! last generic lines (the soft-reboot service's end, `Soft-rebooting.` and,
//! with the kernel's audit on, their audit records), a filesystem other than
//! ext4's unmount line, and the kernel's lines of the hidden mapping's
//! teardown, which the kernel logs as PID 1 starts the decoy.
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

/// How many times [`end_leftovers`] lists and kills again: a process that
/// forked before its kill leaves a child the next round finds.
const KILL_ROUNDS: usize = 4;

/// How long [`end_leftovers`] waits for PID 1 to reap the processes it
/// killed. A process in uninterruptible sleep dies only when the sleep ends.
const REAP_BUDGET: Duration = Duration::from_secs(5);

/// Kill every process [`leftovers`] lists on the real system (`places.proc`
/// must be `/proc`), a few rounds, and wait, bounded, until PID 1 has reaped
/// them all: once a process is gone from `/proc`, PID 1 has also logged what
/// its end means for its unit, and that goes before the cursor. Returns the
/// pids killed.
pub fn end_leftovers(places: &Places) -> Vec<u32> {
    let own = std::process::id();
    let mut handles: Vec<ProcessHandle> = Vec::new();
    for _ in 0..KILL_ROUNDS {
        let round: Vec<ProcessHandle> = leftovers(&places.proc, own)
            .into_iter()
            .filter(|pid| !handles.iter().any(|h| h.pid() == *pid))
            .filter_map(ProcessHandle::open)
            .filter(ProcessHandle::kill)
            .collect();
        if round.is_empty() {
            break;
        }
        handles.extend(round);
    }
    let deadline = Instant::now() + REAP_BUDGET;
    while handles.iter().any(is_unreaped) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    handles.iter().map(ProcessHandle::pid).collect()
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

/// The service whose descriptor store holds journald's standard-output
/// streams across its stop and the soft-reboot.
pub const JOURNAL_SERVICE: &str = "systemd-journald.service";

/// The `systemctl` calls of [`empty_journal_sockets`], in order: stop each of
/// [`JOURNAL_SOCKETS`] (a unit the system lacks fails alone), then drop
/// journald's descriptor store.
pub fn journal_socket_calls() -> Vec<Vec<&'static str>> {
    JOURNAL_SOCKETS
        .iter()
        .map(|unit| vec!["stop", *unit])
        .chain(std::iter::once(vec![
            "clean",
            "--what=fdstore",
            JOURNAL_SERVICE,
        ]))
        .collect()
}

/// Discard what journald's sockets and descriptor store hold: stop the socket
/// units, which closes them with their queues, and drop journald's stored
/// streams (stopped by now, it no longer reads them). The decoy's start opens
/// the sockets again as every boot does. Returns the calls that did not
/// succeed.
pub fn empty_journal_sockets(systemctl: &Path) -> Vec<String> {
    journal_socket_calls()
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

#[cfg(test)]
#[path = "tail_tests.rs"]
mod tests;
