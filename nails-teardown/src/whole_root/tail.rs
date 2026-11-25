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
//!   PID 1 finds none of them but udevd's, which the network restore still
//!   needs ([`LEFT_TO_THE_SWITCH`]); [`quiet_hidden_unmount`] sets the hidden ext4
//!   filesystem's message limit to zero, so the kernel drops that line. The
//!   `/run` scrub detaches the mounts below what it removes, such as the
//!   tmpfs NixOS's shutdown mounts at `/run/initramfs`, and PID 1 logs the
//!   end of each one's mount unit once it reads the mount table again, which
//!   can be after the cursor: [`wait_for_unmounted`] waits, bounded, until
//!   PID 1 lists those units down.
//! - **What waits in journald's sockets.** A soft-reboot keeps the socket
//!   units of journald open (they never stop at a shutdown), and journald's
//!   store of standard-output streams with PID 1 (`FileDescriptorStorePreserve=yes`):
//!   the decoy's journald reads at its start what the hidden root sent them
//!   after its own journald stopped, the audit records of its last units'
//!   stops among it. [`settle_journal_sockets`] drops that store, and
//!   [`drain_journal_sockets`] empties the sockets in place, through PID 1's
//!   own descriptors of them, so that they stay the same sockets, as a plain
//!   soft-reboot keeps them. The drain is the last of these steps before the
//!   cursor, after the wait for the detached mounts' units, so what reaches
//!   the sockets during the others goes as well.
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
//! helpers it starts after the step to close a descriptor and of udevd's
//! processes where the soft-reboot leaves udevd running and, with the
//! kernel's audit on, the audit records of that service's start and stop and
//! of the BPF programs it unloads, and the kernel's count of the audit
//! records it held back from its log just before), a process of the session that stays in
//! uninterruptible sleep past [`end_leftovers`]'s bound (PID 1 names it), the
//! end of a detached mount's unit that PID 1 logs after
//! [`wait_for_unmounted`] has ended (past its bound of about two seconds, at
//! once without an answer from `systemctl` or for a mount point whose unit
//! [`mount_unit`] cannot name: one whose unit name has 256 characters or
//! more, which PID 1 shortens with a hash;
//! or without `systemctl`, where the wait does not run), a
//! filesystem other than ext4's unmount line, and the kernel's lines of the
//! hidden mapping's teardown, which the kernel logs as PID 1 starts the
//! decoy. A journald socket PID 1 closed during the soft-reboot is new,
//! made at the way back ([`settle_journal_sockets`]), and the stream of a
//! process the soft-reboot leaves running goes with the store
//! ([`drop_journal_streams`]).
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
    /// The process that holds journald's sockets, under `proc`: PID 1.
    pub journal_holder: u32,
    /// The folder of journald's sockets, `/run/systemd`: they lie in its
    /// `journal/` folder, a namespace's in `journal.<namespace>/`.
    pub journal_run: PathBuf,
}

impl Places {
    /// The real system.
    pub fn system() -> Self {
        Self {
            proc: PathBuf::from("/proc"),
            sys_dev_block: PathBuf::from("/sys/dev/block"),
            sys_fs_ext4: PathBuf::from("/sys/fs/ext4"),
            journal_holder: 1,
            journal_run: PathBuf::from("/run/systemd"),
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
        .filter_map(|&pid| service_of(proc, pid))
        .collect();
    units.sort();
    units.dedup();
    units
}

/// The outermost `.service` of the cgroup path of `pid` under the procfs at
/// `proc`, or `None` for a process outside a service or one whose cgroup
/// cannot be read.
fn service_of(proc: &Path, pid: u32) -> Option<String> {
    let content = std::fs::read_to_string(proc.join(pid.to_string()).join("cgroup")).ok()?;
    let path = crate::cgroup::v2_path(&content)?;
    path.split('/')
        .find(|segment| segment.ends_with(".service") && segment.len() > ".service".len())
        .map(str::to_string)
}

/// The services whose processes [`end_leftovers`] leaves to PID 1, which
/// ends them at the switch as at a plain soft-reboot: udevd. Where the
/// soft-reboot leaves udevd running until PID 1's final kill (as on Debian 13
/// and Ubuntu 24.04), the way back hands it events after the first pass: the network restore
/// deletes the links the session made. Stopped before them, udevd would
/// handle none of them: its record of a deleted link would stay in
/// `/run/udev`, and the first event would make PID 1 try to start it again
/// inside the soft-reboot, fail its kernel socket and open that socket anew
/// at the decoy's start.
/// PID 1's final kill names udevd's processes by their generic names, as a
/// plain soft-reboot does.
pub const LEFT_TO_THE_SWITCH: [&str; 1] = ["systemd-udevd.service"];

/// The processes [`end_leftovers`] ends, under the procfs at `proc`: those of
/// [`leftovers`] that run in none of the services of [`LEFT_TO_THE_SWITCH`].
pub fn to_end(proc: &Path, own: u32) -> Vec<u32> {
    to_end_but(proc, own, &LEFT_TO_THE_SWITCH)
}

/// [`leftovers`] under the procfs at `proc` that run in none of the
/// services `kept`.
fn to_end_but(proc: &Path, own: u32, kept: &[&str]) -> Vec<u32> {
    leftovers(proc, own)
        .into_iter()
        .filter(|&pid| service_of(proc, pid).is_none_or(|unit| !kept.contains(&unit.as_str())))
        .collect()
}

/// The processes [`end_leftovers_at_entry`] ends: every one of
/// [`leftovers`], udevd's included. Nothing hands udevd events before the
/// entry's switch, and a udevd that maps a file a package update deleted
/// keeps the decoy's root from going read-only for the write fence.
pub fn to_end_at_entry(proc: &Path, own: u32) -> Vec<u32> {
    to_end_but(proc, own, &[])
}

/// End every process [`to_end`] lists on the real system (`places.proc`
/// must be `/proc`), in rounds until none is left. First it waits, bounded,
/// for every job but `own_jobs`, through `systemctl` when there is one, so
/// that a unit the soft-reboot is still stopping ends as the soft-reboot
/// stops it. Each round then queues a stop job for the services the
/// processes run in, so that PID 1 does not start one of them again under
/// `Restart=` (a queued stop job holds a restart back), SIGKILLs them, waits,
/// bounded, until PID 1 has reaped them (once a process is gone from `/proc`,
/// PID 1 has also logged what its end means for its unit, and that goes
/// before the cursor), and waits for every job but `own_jobs` and for any
/// restart still due. Returns the pids killed.
pub fn end_leftovers(places: &Places, systemctl: Option<&Path>, own_jobs: &[&str]) -> Vec<u32> {
    end_listed(places, systemctl, own_jobs, to_end)
}

/// [`end_leftovers`] for the entry, before the write fence: every process
/// [`to_end_at_entry`] lists, udevd's included.
pub fn end_leftovers_at_entry(
    places: &Places,
    systemctl: Option<&Path>,
    own_jobs: &[&str],
) -> Vec<u32> {
    end_listed(places, systemctl, own_jobs, to_end_at_entry)
}

fn end_listed(
    places: &Places,
    systemctl: Option<&Path>,
    own_jobs: &[&str],
    list: fn(&Path, u32) -> Vec<u32>,
) -> Vec<u32> {
    let own = std::process::id();
    let mut killed = Vec::new();
    if let Some(systemctl) = systemctl {
        let _ = tools::wait_for_other_jobs(systemctl, own_jobs, JOBS_BUDGET);
    }
    for _ in 0..KILL_ROUNDS {
        let pids = list(&places.proc, own);
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

/// journald's own socket units, which the decoy's start would open anew,
/// logging `Listening on` for each, were one closed when it starts.
pub const OWN_SOCKETS: [&str; 2] = ["systemd-journald.socket", "systemd-journald-dev-log.socket"];

/// The socket units of journald's namespaces, a pattern `systemctl` matches
/// against the loaded units.
pub const NAMESPACE_SOCKETS: &str = "systemd-journald@*.socket";

/// Whether `unit` is the socket unit of one of journald's namespaces.
fn is_namespace_socket(unit: &str) -> bool {
    unit.strip_prefix("systemd-journald@")
        .and_then(|rest| rest.strip_suffix(".socket"))
        .is_some_and(|name| !name.is_empty() && name != "*")
}

/// The service whose descriptor store holds journald's standard-output
/// streams across its stop and the soft-reboot.
pub const JOURNAL_SERVICE: &str = "systemd-journald.service";

/// The `systemctl` call that lists which of [`OWN_SOCKETS`] and of the
/// namespace sockets are active.
pub fn active_sockets_call() -> Vec<&'static str> {
    let mut args = vec![
        "list-units",
        "--plain",
        "--no-legend",
        "--state=active",
        "--",
    ];
    args.extend(OWN_SOCKETS);
    args.push(NAMESPACE_SOCKETS);
    args
}

/// The units of [`OWN_SOCKETS`] and the namespace sockets a `systemctl
/// list-units --plain --no-legend` `listing` names: journald's own in the
/// order of [`OWN_SOCKETS`], then the namespaces' in the listing's order.
pub fn listed_sockets(listing: &str) -> Vec<String> {
    let named: Vec<&str> = listing
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    OWN_SOCKETS
        .into_iter()
        .filter(|unit| named.contains(unit))
        .chain(
            named
                .iter()
                .copied()
                .filter(|unit| is_namespace_socket(unit)),
        )
        .map(str::to_string)
        .collect()
}

/// The units of [`listed_sockets`] active now, or `None` when `systemctl`
/// cannot say.
pub fn active_sockets(systemctl: &Path) -> Option<Vec<String>> {
    tools::run_output(systemctl, &active_sockets_call(), TOOL_BUDGET)
        .map(|listing| listed_sockets(&listing))
}

/// The file in the runtime directory that keeps, from the entry to the way
/// back, which of journald's socket units the decoy had active as it left.
pub const SOCKETS_NAME: &str = "journal-sockets";

/// Keep at `path`, at the entry, which of journald's socket units the decoy
/// has active now ([`listed_sockets`]), one per line. Without an answer from
/// `systemctl` no file stays, and the way back neither starts nor stops a
/// socket unit. Returns whether the file was written.
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

/// The `systemctl` calls of [`settle_journal_sockets`], in order, where
/// `decoy` are the socket units the decoy had active at the entry and `now`
/// those active now: forget a failure of journald's (a failed service keeps
/// its descriptor store, and PID 1 refuses to drop the store of a service
/// that is not dead), drop that store, stop each namespace socket the
/// session started, and start each of [`OWN_SOCKETS`] the decoy had and PID
/// 1 has closed since.
pub fn journal_socket_calls(decoy: &[String], now: &[String]) -> Vec<Vec<String>> {
    let call = |args: &[&str]| args.iter().map(|arg| (*arg).to_string()).collect();
    let stops = now
        .iter()
        .filter(|unit| is_namespace_socket(unit) && !decoy.contains(unit))
        .map(|unit| vec!["stop".to_string(), unit.clone()]);
    let starts = decoy
        .iter()
        .filter(|unit| OWN_SOCKETS.contains(&unit.as_str()) && !now.contains(unit))
        .map(|unit| vec!["start".to_string(), unit.clone()]);
    [
        call(&["reset-failed", JOURNAL_SERVICE]),
        call(&DROP_STREAMS),
    ]
    .into_iter()
    .chain(stops)
    .chain(starts)
    .collect()
}

/// The `systemctl` call that drops journald's descriptor store of
/// standard-output streams.
pub const DROP_STREAMS: [&str; 3] = ["clean", "--what=fdstore", JOURNAL_SERVICE];

/// Drop journald's stored standard-output streams at the entry, as the way
/// back does with [`settle_journal_sockets`]. PID 1 closes each stored
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

/// Put journald's socket units as the decoy had them at the entry, through
/// `systemctl`, without touching a socket that is open: drop journald's
/// stored streams (stopped by now, it no longer reads them), stop a
/// namespace's socket the session started (its unit would name a namespace
/// of the session's in the decoy's unit list), and start again one of
/// [`OWN_SOCKETS`] the decoy had listening at the entry ([`record_sockets`],
/// `decoy`) that PID 1 has closed since: PID 1 before systemd 258 fails a
/// journald socket that receives anything once journald has stopped for the
/// soft-reboot, which drops what it held, and the decoy's start would open
/// it anew and log that. Without that record, or without an answer which
/// units are active now, no unit is started or stopped. Returns the calls
/// that did not succeed.
pub fn settle_journal_sockets(systemctl: &Path, decoy: Option<&[String]>) -> Vec<String> {
    let now = match decoy {
        Some(_) => active_sockets(systemctl),
        None => None,
    };
    let mut failed = Vec::new();
    if decoy.is_some() && now.is_none() {
        failed.push(active_sockets_call().join(" "));
    }
    let (decoy, now) = match (decoy, now) {
        (Some(decoy), Some(now)) => (decoy.to_vec(), now),
        _ => (Vec::new(), Vec::new()),
    };
    failed.extend(
        journal_socket_calls(&decoy, &now)
            .into_iter()
            .filter(|args| {
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                tools::run(systemctl, &args, TOOL_BUDGET) != tools::Outcome::Done
            })
            .map(|args| args.join(" ")),
    );
    failed
}

/// The netlink protocol of the kernel's audit (`NETLINK_AUDIT`).
const NETLINK_AUDIT: u32 = 9;

/// The socket flag of a listening socket in a `/proc/<pid>/net/unix` line
/// (`__SO_ACCEPTCON`).
const LISTENING: &str = "00010000";

/// The socket type of a stream socket in a `/proc/<pid>/net/unix` line.
const STREAM: &str = "0001";

/// The socket inodes, in a `/proc/<pid>/net/unix` `listing`, of the sockets
/// bound to a path below `journal_run`'s `journal/` folder or a namespace's
/// `journal.<namespace>/` folder: journald's native, `/dev/log`, stream and
/// any other socket there. A connection accepted on the stream socket shows
/// its path as well (journald's stored streams, which PID 1 holds): it is
/// left out, as nothing waits on it to be accepted.
pub fn journal_unix_inodes(listing: &str, journal_run: &Path) -> Vec<u64> {
    let prefix = journal_run.join("journal");
    let prefix = prefix.to_string_lossy();
    listing
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let path = fields.get(7)?;
            if fields.get(4) == Some(&STREAM) && fields.get(3) != Some(&LISTENING) {
                return None;
            }
            let rest = path.strip_prefix(prefix.as_ref())?;
            let ours = rest.starts_with('/')
                || rest
                    .strip_prefix('.')
                    .and_then(|ns| ns.split_once('/'))
                    .is_some_and(|(ns, file)| !ns.is_empty() && !file.is_empty());
            ours.then(|| fields.get(6)?.parse().ok()).flatten()
        })
        .collect()
}

/// The socket inodes, in a `/proc/<pid>/net/netlink` `listing`, of the
/// kernel audit's sockets that take its records as a multicast group
/// subscriber, as journald's audit socket does; a socket that only sends
/// audit messages (PID 1's own) subscribes to none.
pub fn audit_reader_inodes(listing: &str) -> Vec<u64> {
    listing
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let protocol: u32 = fields.get(1)?.parse().ok()?;
            let groups = u32::from_str_radix(fields.get(3)?, 16).ok()?;
            let inode = fields.last()?.parse().ok()?;
            (fields.len() >= 10 && protocol == NETLINK_AUDIT && groups != 0).then_some(inode)
        })
        .collect()
}

/// The descriptor numbers in `fd_dir` (`/proc/<pid>/fd`) that refer to a
/// socket with one of `inodes`, sorted.
fn socket_fds(fd_dir: &Path, inodes: &[u64]) -> io::Result<Vec<i32>> {
    let mut fds: Vec<i32> = std::fs::read_dir(fd_dir)?
        .flatten()
        .filter_map(|entry| {
            let fd: i32 = entry.file_name().to_str()?.parse().ok()?;
            let target = std::fs::read_link(entry.path()).ok()?;
            let inode: u64 = target
                .to_str()?
                .strip_prefix("socket:[")?
                .strip_suffix(']')?
                .parse()
                .ok()?;
            inodes.contains(&inode).then_some(fd)
        })
        .collect();
    fds.sort_unstable();
    Ok(fds)
}

/// How long [`drain_journal_sockets`] reads, over all sockets: the kernel
/// keeps adding audit records while it does.
const DRAIN_BUDGET: Duration = Duration::from_secs(2);

/// What [`drain_journal_sockets`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Drained {
    /// How many sockets it found and emptied.
    pub sockets: usize,
    /// How many datagrams, audit records and waiting connections it dropped.
    pub dropped: usize,
    /// What it could not do, each with the reason.
    pub failed: Vec<String>,
}

/// Empty journald's sockets in place: take the descriptors of them that
/// `places.journal_holder` (PID 1) holds, through a pidfd (`pidfd_getfd`),
/// and read and drop what waits in each: every datagram of the native and
/// `/dev/log` sockets, every connection waiting on the stream socket (with
/// what it carries), and every record waiting in the audit socket. The
/// sockets stay the same objects, with their labels and their units' start
/// time, as a plain soft-reboot keeps them.
///
/// Run once every process of the session that PID 1 would kill at the switch
/// but udevd's has ended, last before the kmsg cursor: what is sent after
/// this reaches the decoy's journald.
pub fn drain_journal_sockets(places: &Places) -> Drained {
    let mut drained = Drained::default();
    let holder = places.proc.join(places.journal_holder.to_string());
    let read = |name: &str| std::fs::read_to_string(holder.join("net").join(name));
    let mut inodes = Vec::new();
    match read("unix") {
        Ok(listing) => inodes.extend(journal_unix_inodes(&listing, &places.journal_run)),
        Err(e) => drained.failed.push(format!("unix sockets: {e}")),
    }
    // A kernel without audit lists no audit socket.
    if let Ok(listing) = read("netlink") {
        inodes.extend(audit_reader_inodes(&listing));
    }
    if inodes.is_empty() {
        return drained;
    }
    let fds = match socket_fds(&holder.join("fd"), &inodes) {
        Ok(fds) if fds.is_empty() => return drained,
        Ok(fds) => fds,
        Err(e) => {
            drained.failed.push(format!("descriptors: {e}"));
            return drained;
        }
    };
    let pidfd = rustix::process::Pid::from_raw(places.journal_holder as i32)
        .ok_or(rustix::io::Errno::INVAL)
        .and_then(|pid| rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()));
    let pidfd = match pidfd {
        Ok(pidfd) => pidfd,
        Err(e) => {
            drained.failed.push(format!("pidfd: {e}"));
            return drained;
        }
    };
    let deadline = Instant::now() + DRAIN_BUDGET;
    for fd in fds {
        let socket =
            rustix::process::pidfd_getfd(&pidfd, fd, rustix::process::PidfdGetfdFlags::empty());
        match socket
            .map_err(io::Error::from)
            .and_then(|socket| drain_socket(&socket, deadline))
        {
            Ok(dropped) => {
                drained.sockets += 1;
                drained.dropped += dropped;
            }
            Err(e) => drained.failed.push(format!("descriptor {fd}: {e}")),
        }
    }
    drained
}

/// Drop what waits in `socket` until it holds nothing or `deadline` passes:
/// on a listening socket, accept and close each waiting connection; on any
/// other, receive each datagram or record without copying it (`MSG_TRUNC`)
/// and without waiting (`MSG_DONTWAIT`, the descriptor's own mode, shared
/// with PID 1, unchanged). Returns how many it dropped.
pub fn drain_socket(socket: &impl std::os::fd::AsFd, deadline: Instant) -> io::Result<usize> {
    use rustix::event::{PollFd, PollFlags};
    use rustix::net::RecvFlags;
    let listening = rustix::net::sockopt::socket_acceptconn(socket)?;
    // A connected stream socket's end of file would read as an empty
    // datagram: none of journald's is one.
    if !listening && rustix::net::sockopt::socket_type(socket)? == rustix::net::SocketType::STREAM {
        return Ok(0);
    }
    let mut dropped = 0;
    let mut byte = [0_u8; 1];
    while Instant::now() < deadline {
        if listening {
            let mut ready = [PollFd::new(socket, PollFlags::IN)];
            let zero = rustix::event::Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            if rustix::event::poll(&mut ready, Some(&zero))? == 0
                || !ready[0].revents().contains(PollFlags::IN)
            {
                return Ok(dropped);
            }
            match rustix::net::accept_with(socket, rustix::net::SocketFlags::CLOEXEC) {
                Ok(_connection) => dropped += 1,
                Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
        } else {
            match rustix::net::recv(socket, &mut byte, RecvFlags::DONTWAIT | RecvFlags::TRUNC) {
                Ok(_) => dropped += 1,
                Err(rustix::io::Errno::AGAIN) => return Ok(dropped),
                // A record the kernel could not queue: the queue still holds
                // the others.
                Err(rustix::io::Errno::NOBUFS | rustix::io::Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    Ok(dropped)
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

/// How long [`wait_for_unmounted`] waits for PID 1 to take in the mounts the
/// `/run` scrub detached. PID 1 limits how often it reads the mount table
/// again (by default five times in a second), so it can take in a detach up
/// to about a second late.
pub const UNMOUNTED_BUDGET: Duration = Duration::from_secs(2);

/// The `systemctl` call that lists every mount unit PID 1 has loaded, one a
/// line, with its load, active and sub state.
pub const MOUNT_UNITS: [&str; 6] = [
    "list-units",
    "--all",
    "--type=mount",
    "--plain",
    "--no-legend",
    "--full",
];

/// The name `systemd-escape --path --suffix=mount` gives the mount unit of
/// `path` (`/run/my-disk` is `run-my\x2ddisk.mount`), for a path that is
/// valid UTF-8: this reads the path as UTF-8, so a byte that is not gives
/// another name. PID 1 gives the unit that name only up to 255
/// characters and shortens a longer one with a hash, which this does not.
pub fn mount_unit(path: &Path) -> String {
    let text = path.to_string_lossy();
    let joined = text
        .split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .collect::<Vec<_>>()
        .join("/");
    if joined.is_empty() {
        return "-.mount".to_string();
    }
    let mut name = String::new();
    for (i, byte) in joined.bytes().enumerate() {
        match byte {
            b'/' => name.push('-'),
            b'.' if i == 0 => name.push_str("\\x2e"),
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b':' | b'_' | b'.' => name.push(byte as char),
            other => name.push_str(&format!("\\x{other:02x}")),
        }
    }
    name + ".mount"
}

/// Which of `units` a [`MOUNT_UNITS`] `listing` shows in another active
/// state than `inactive` or `failed`: units PID 1 has not yet taken down.
/// A unit the listing does not show is down.
pub fn still_up<'a>(listing: &str, units: &'a [String]) -> Vec<&'a str> {
    let up: Vec<&str> = listing
        .lines()
        .filter_map(|line| {
            let mut fields = line
                .split_whitespace()
                .skip_while(|field| !field.ends_with(".mount"));
            let unit = fields.next()?;
            let active = fields.nth(1)?;
            (active != "inactive" && active != "failed").then_some(unit)
        })
        .collect();
    units
        .iter()
        .map(String::as_str)
        .filter(|unit| up.contains(unit))
        .collect()
}

/// Wait, bounded by [`UNMOUNTED_BUDGET`], until PID 1 lists none of the
/// mount units of `detached` as up ([`still_up`]): the mounts the `/run`
/// scrub detached, whose unit's end PID 1 logs (`<unit>: Deactivated
/// successfully.`) once it reads the mount table again, which must come
/// before the kmsg cursor. A mount point still in `mounted()` (a mount stacked
/// below the one detached) keeps its unit up and is left out. Returns
/// whether PID 1 lists none of those units as up; a unit [`mount_unit`]
/// does not name as PID 1 does never shows in the listing and counts as
/// down, though PID 1 may still have it up. Without an answer from
/// `systemctl` it stops at once.
pub fn wait_for_unmounted(
    systemctl: &Path,
    detached: &[PathBuf],
    mounted: impl Fn() -> Vec<PathBuf>,
) -> bool {
    let still_mounted = mounted();
    let units: Vec<String> = detached
        .iter()
        .filter(|path| !still_mounted.contains(path))
        .map(|path| mount_unit(path))
        .collect();
    if units.is_empty() {
        return true;
    }
    let deadline = Instant::now() + UNMOUNTED_BUDGET;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        let Some(listing) = tools::run_output(systemctl, &MOUNT_UNITS, left.min(TOOL_BUDGET))
        else {
            return false;
        };
        if still_up(&listing, &units).is_empty() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
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
