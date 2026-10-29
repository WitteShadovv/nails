// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Reading `/proc` and signalling single processes without a pid-reuse race.
//!
//! Nothing here touches a file on an overlay: every read is a procfs file of
//! the process itself (`stat`, `status`, `comm`, `cmdline`, `cgroup`).

use std::path::Path;

/// The fields of `/proc/<pid>/stat` NAILS reads. This is the one parser of
/// that file: the teardown and `nails-core` both go through [`stat`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    /// The scheduler state (`R`, `S`, `D`, `Z`, ...).
    pub state: char,
    /// Parent pid.
    pub ppid: u32,
    /// Process group id.
    pub pgid: u32,
    /// Session id.
    pub sid: u32,
    /// The controlling terminal's device number (0 for none).
    pub tty: i32,
    /// The kernel's per-task flags (`PF_*`).
    pub flags: u64,
    /// Start time in clock ticks since boot; with the pid it names one process.
    pub start_time: u64,
}

/// `PF_KTHREAD`: the task is a kernel thread.
const PF_KTHREAD: u64 = 0x0020_0000;

impl Stat {
    /// Whether this is a kernel thread (never a teardown target).
    pub fn is_kernel_thread(&self) -> bool {
        self.flags & PF_KTHREAD != 0
    }
}

/// Parse a `/proc/<pid>/stat` body. `comm` may contain spaces and parentheses,
/// so the fields are counted from past its last `)`.
pub fn parse_stat(content: &str) -> Option<Stat> {
    let after = content.get(content.rfind(')')? + 1..)?;
    let fields: Vec<&str> = after.split_whitespace().collect();
    // After comm: state(0) ppid(1) pgrp(2) session(3) tty(4) tpgid(5) flags(6)
    // ... starttime(19).
    Some(Stat {
        state: fields.first()?.chars().next()?,
        ppid: fields.get(1)?.parse().ok()?,
        pgid: fields.get(2)?.parse().ok()?,
        sid: fields.get(3)?.parse().ok()?,
        tty: fields.get(4)?.parse().ok()?,
        flags: fields.get(6)?.parse().ok()?,
        start_time: fields.get(19)?.parse().ok()?,
    })
}

/// The stat fields of `pid`; `None` when it is gone.
pub fn stat(pid: u32) -> Option<Stat> {
    parse_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// Every pid in `/proc`.
pub fn pids() -> Vec<u32> {
    std::fs::read_dir("/proc")
        .map(|dir| {
            dir.flatten()
                .filter_map(|e| e.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// The `comm` of `pid`, trimmed.
pub fn comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|c| c.trim().to_string())
}

/// The argv of `pid`.
pub fn cmdline(pid: u32) -> Vec<String> {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|raw| {
            raw.split(|b| *b == 0)
                .filter(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// The raw `/proc/<pid>/cgroup` of `pid`.
pub fn cgroup(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()
}

/// The real uid in a `/proc/<pid>/status` body: the first of the four ids
/// on its `Uid:` line.
pub fn parse_status_uid(content: &str) -> Option<u32> {
    content.lines().find_map(|line| {
        line.strip_prefix("Uid:")?
            .split_whitespace()
            .next()?
            .parse()
            .ok()
    })
}

/// The real uid of `pid`; `None` when it is gone.
pub fn uid(pid: u32) -> Option<u32> {
    parse_status_uid(&std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?)
}

/// Whether `fd` of `pid` is a terminal.
pub fn fd_is_terminal(pid: u32, fd: u32) -> bool {
    std::fs::read_link(Path::new(&format!("/proc/{pid}/fd/{fd}"))).is_ok_and(|link| {
        let text = link.to_string_lossy();
        ["/dev/pts/", "/dev/tty", "/dev/console", "/dev/hvc"]
            .iter()
            .any(|prefix| text.starts_with(prefix))
    })
}

/// The teardown's own invocation: the processes it must never kill before its
/// output is written.
///
/// That is its ancestry (`sudo`, the shell that typed the command) and every
/// process sharing its session or process group: in `nails emergency | base64`
/// the pipe reader is a sibling, not an ancestor, and killing it would break the
/// pipe carrying the teardown's own result.
#[derive(Debug, Clone, Default)]
pub struct Invocation {
    /// This process and its ancestors.
    pub ancestry: Vec<u32>,
    /// This process's session id (`0` when unknown).
    pub sid: u32,
    /// This process's process group id (`0` when unknown).
    pub pgid: u32,
    /// The process groups of the ancestors. `sudo nails emergency | less`
    /// under `use_pty` makes nails a session leader of its own, but the pipe
    /// reader stays in the pipeline's process group, which is sudo's.
    pub ancestor_pgids: Vec<u32>,
    /// Further pids to spare, handed in by the caller.
    pub extra: Vec<u32>,
}

impl Invocation {
    /// The invocation of the running process.
    pub fn current() -> Self {
        let own = std::process::id();
        let mut ancestry = Vec::new();
        let mut next = Some(own);
        while let Some(pid) = next {
            if pid == 0 || ancestry.contains(&pid) {
                break;
            }
            ancestry.push(pid);
            next = stat(pid).map(|s| s.ppid);
        }
        let own_stat = stat(own);
        // Not the groups of the shell that typed the command, nor of PID 1 or
        // the session manager above it: only the process groups led by a
        // process of the command chain itself (sudo's pipeline group).
        let ancestor_pgids = ancestry
            .iter()
            .skip(1)
            .filter_map(|&pid| stat(pid).map(|s| (pid, s.pgid)))
            .filter(|&(pid, pgid)| pgid == pid && pid != 1)
            .map(|(_, pgid)| pgid)
            .filter(|pgid| !is_interactive_shell_group(*pgid))
            .collect();
        Self {
            ancestry,
            sid: own_stat.map_or(0, |s| s.sid),
            pgid: own_stat.map_or(0, |s| s.pgid),
            ancestor_pgids,
            extra: Vec::new(),
        }
    }

    /// Whether `pid` (with its stat) belongs to the invocation.
    pub fn contains(&self, pid: u32, stat: Option<&Stat>) -> bool {
        self.ancestry.contains(&pid)
            || self.extra.contains(&pid)
            || stat.is_some_and(|s| {
                (self.sid != 0 && s.sid == self.sid)
                    || (self.pgid != 0 && s.pgid == self.pgid)
                    || self.ancestor_pgids.contains(&s.pgid)
            })
    }
}

/// Whether the process group `pgid` is led by an interactive shell: the
/// terminal session's own group, whose other jobs are not part of the command.
fn is_interactive_shell_group(pgid: u32) -> bool {
    crate::shells::is_interactive_shell(pgid)
}

/// A handle that signals one process and only it.
///
/// It holds a pidfd, so a signal can never reach a later process that reuses
/// the pid. Without pidfds (before Linux 5.3) it checks the recorded start time
/// right before a plain `kill`, narrowing the reuse window to that instant.
pub struct ProcessHandle {
    pid: u32,
    start_time: u64,
    pidfd: Option<std::os::fd::OwnedFd>,
}

impl ProcessHandle {
    /// Open a handle on `pid`; `None` when it is already gone.
    pub fn open(pid: u32) -> Option<Self> {
        let start_time = stat(pid)?.start_time;
        let pidfd = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .and_then(|raw| {
                rustix::process::pidfd_open(raw, rustix::process::PidfdFlags::empty()).ok()
            });
        // The pid may have been reused between the stat read and pidfd_open.
        if stat(pid).map(|s| s.start_time) != Some(start_time) {
            return None;
        }
        Some(Self {
            pid,
            start_time,
            pidfd,
        })
    }

    /// The pid.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Whether the process still runs (not exited, pid not reused).
    pub fn is_alive(&self) -> bool {
        // A zombie has exited: it holds no mount any more.
        stat(self.pid)
            .is_some_and(|s| s.start_time == self.start_time && s.state != 'Z' && s.state != 'X')
    }

    /// Send `signal`; `false` when the process has gone.
    pub fn signal(&self, signal: rustix::process::Signal) -> bool {
        match &self.pidfd {
            Some(pidfd) => rustix::process::pidfd_send_signal(pidfd, signal).is_ok(),
            None => {
                if !self.is_alive() {
                    return false;
                }
                i32::try_from(self.pid)
                    .ok()
                    .and_then(rustix::process::Pid::from_raw)
                    .is_some_and(|pid| rustix::process::kill_process(pid, signal).is_ok())
            }
        }
    }

    /// SIGKILL the process.
    pub fn kill(&self) -> bool {
        self.signal(rustix::process::Signal::KILL)
    }
}

/// Wait until none of `handles` is alive, or `deadline` passes. Returns the
/// pids still alive.
pub fn await_exit(handles: &[ProcessHandle], deadline: std::time::Instant) -> Vec<u32> {
    loop {
        let alive: Vec<u32> = handles
            .iter()
            .filter(|h| h.is_alive())
            .map(ProcessHandle::pid)
            .collect();
        if alive.is_empty() || std::time::Instant::now() >= deadline {
            return alive;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_fields_are_read_past_a_comm_with_spaces_and_parens() {
        let line =
            "1234 (we (ird) x) S 1 1234 1234 34817 1234 4194560 1 2 3 4 5 6 7 8 20 0 1 0 98765 1 2";
        let stat = parse_stat(line).unwrap();
        assert_eq!(stat.ppid, 1);
        assert_eq!(stat.pgid, 1234);
        assert_eq!(stat.sid, 1234);
        assert_eq!(stat.flags, 4_194_560);
        assert_eq!(stat.start_time, 98_765);
        assert!(!stat.is_kernel_thread());
    }

    /// A `setsid` child whose comm holds `) (` and spaces, captured by
    /// `capture-kernel-fixtures.sh userns` (nails-base's fixture README).
    #[test]
    fn the_captured_odd_comm_child_parses() {
        let stat_line = include_str!(
            "../../nails-base/tests/fixtures/kernel/userns/proc-stat-setsid-odd-comm.txt"
        );
        let status = include_str!(
            "../../nails-base/tests/fixtures/kernel/userns/proc-status-setsid-odd-comm.txt"
        );
        let pid: u32 = stat_line.split(' ').next().unwrap().parse().unwrap();
        let stat = parse_stat(stat_line).expect("the kernel's own line parses");
        assert_eq!(stat.state, 'S');
        assert_eq!(
            (stat.sid, stat.pgid),
            (pid, pid),
            "its own session and group"
        );
        assert_ne!(stat.ppid, pid);
        assert!(!stat.is_kernel_thread());
        assert!(stat.start_time > 0);
        // The capture ran as root of a user namespace.
        assert_eq!(parse_status_uid(status), Some(0));
    }

    /// journald's stat and status as captured as root in a NixOS VM, when that
    /// capture exists (nails-base's fixture README).
    #[test]
    fn the_captured_journald_parses_when_the_vm_capture_exists() {
        let vm = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../nails-base/tests/fixtures/kernel/vm");
        let (Ok(stat_line), Ok(status)) = (
            std::fs::read_to_string(vm.join("proc-stat-journald.txt")),
            std::fs::read_to_string(vm.join("proc-status-journald.txt")),
        ) else {
            eprintln!("the VM capture is not taken yet (nails-base fixture README)");
            return;
        };
        let stat = parse_stat(&stat_line).expect("the kernel's own line parses");
        assert_eq!(stat.ppid, 1, "journald is a child of PID 1");
        assert_eq!(parse_status_uid(&status), Some(0), "journald runs as root");
    }

    /// A live child in its own session and process group whose comm holds
    /// `) (` and spaces: the shell renames itself, then waits on `sleep`.
    #[test]
    fn a_live_setsid_child_with_an_odd_comm_reads_back() {
        let child = std::process::Command::new("setsid")
            .args([
                "sh",
                "-c",
                "printf 'x) (y z' >/proc/self/comm; sleep 30; exit 0",
            ])
            .spawn()
            .expect("spawn setsid");
        let pid = child.id();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while comm(pid).as_deref() != Some("x) (y z") {
            assert!(
                std::time::Instant::now() < deadline,
                "the child never renamed itself"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        let stat = stat(pid).expect("a live child");
        let child_uid = uid(pid);
        let group = rustix::process::Pid::from_raw(pid as i32).unwrap();
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        let mut child = child;
        let _ = child.wait();

        assert_eq!((stat.sid, stat.pgid), (pid, pid), "setsid made it a leader");
        assert_eq!(stat.ppid, std::process::id());
        // Running, sleeping, or in an uninterruptible wait while it pages in or
        // execs `sleep` under load: any state of a live process.
        assert!(matches!(stat.state, 'S' | 'R' | 'D'), "{stat:?}");
        assert!(stat.start_time > 0);
        assert!(stat.start_time >= super::stat(std::process::id()).unwrap().start_time);
        assert_eq!(child_uid, Some(rustix::process::getuid().as_raw()));
    }

    #[test]
    fn a_kernel_thread_is_recognised_by_its_flag() {
        let line = "2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0";
        assert!(parse_stat(line).unwrap().is_kernel_thread());
    }

    #[test]
    fn the_invocation_holds_this_process_and_its_parent() {
        let invocation = Invocation::current();
        let own = std::process::id();
        assert_eq!(invocation.ancestry.first(), Some(&own));
        assert!(invocation.contains(own, None));
        let parent = stat(own).unwrap().ppid;
        assert!(invocation.contains(parent, None));
    }

    #[test]
    fn a_handle_signals_a_child_and_sees_it_exit() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let handle = ProcessHandle::open(child.id()).unwrap();
        assert!(handle.is_alive());
        assert!(handle.kill());
        let _ = child.wait();
        assert!(!handle.is_alive());
    }
}
