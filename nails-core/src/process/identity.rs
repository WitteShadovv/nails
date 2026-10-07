// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Telling one process apart from a later one that reused its pid.

/// Parse the start time (field 22, clock ticks since boot) out of a
/// `/proc/<pid>/stat` body. `comm` may contain spaces and parentheses, so the
/// fields are counted from past its closing `)`.
pub(crate) fn parse_stat_start_time(stat: &str) -> Option<u64> {
    let after_comm = stat.get(stat.rfind(')')? + 1..)?;
    // After `comm`: state (field 3) ... starttime (field 22), i.e. index 19.
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// The start time of `pid`, from `/proc/<pid>/stat`; `None` when it is gone.
pub(crate) fn proc_start_time(pid: u32) -> Option<u64> {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .as_deref()
        .and_then(parse_stat_start_time)
}

/// The parent pid of `pid`, from `/proc/<pid>/status`.
pub(crate) fn parent_pid(pid: u32) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("PPid:")?.trim().parse().ok())
}

/// A handle on one live process that signals it and only it.
///
/// It holds a pidfd (`pidfd_open`), so a signal can never reach a different
/// process that later reuses the pid. On a kernel without pidfds (before 5.3)
/// it falls back to checking the recorded start time right before a plain
/// `kill`, which narrows the reuse window to that instant.
pub(crate) struct ProcessHandle {
    pid: u32,
    start_time: u64,
    pidfd: Option<std::os::fd::OwnedFd>,
}

impl ProcessHandle {
    /// Open a handle on `pid`; `None` when the process is already gone.
    pub(crate) fn open(pid: u32) -> Option<Self> {
        let start_time = proc_start_time(pid)?;
        let pidfd = i32::try_from(pid)
            .ok()
            .and_then(rustix::process::Pid::from_raw)
            .and_then(|raw| {
                rustix::process::pidfd_open(raw, rustix::process::PidfdFlags::empty()).ok()
            });
        // The pid may have been reused between the start-time read and the
        // pidfd_open: only a handle whose process still has that start time is
        // the process we looked at.
        if proc_start_time(pid) != Some(start_time) {
            return None;
        }
        Some(Self {
            pid,
            start_time,
            pidfd,
        })
    }

    /// The pid the handle was opened on.
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    /// Whether the process is still running (not exited, pid not reused).
    pub(crate) fn is_alive(&self) -> bool {
        proc_start_time(self.pid) == Some(self.start_time)
    }

    /// Send `signal` to exactly this process. `false` when it has gone.
    pub(crate) fn signal(&self, signal: rustix::process::Signal) -> bool {
        match &self.pidfd {
            Some(pidfd) => rustix::process::pidfd_send_signal(pidfd, signal).is_ok(),
            None => {
                self.is_alive()
                    && i32::try_from(self.pid)
                        .ok()
                        .and_then(rustix::process::Pid::from_raw)
                        .is_some_and(|pid| rustix::process::kill_process(pid, signal).is_ok())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_child_reports_this_process_as_its_parent() {
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let parent = parent_pid(child.id());
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(parent, Some(std::process::id()));
    }

    #[test]
    fn a_handle_signals_its_process_and_nothing_after_it_is_gone() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let handle = ProcessHandle::open(child.id()).expect("a live child");
        assert!(handle.is_alive());
        assert!(handle.signal(rustix::process::Signal::TERM));
        child.wait().unwrap();
        // Reaped: the handle reports it gone and refuses to signal anything.
        assert!(!handle.is_alive());
        assert!(!handle.signal(rustix::process::Signal::KILL));
        assert!(ProcessHandle::open(child.id()).is_none());
    }

    #[test]
    fn the_start_time_is_field_22_even_with_a_tricky_comm() {
        let stat =
            "4242 (a) b (c)) S 1 4242 4242 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 100";
        assert_eq!(parse_stat_start_time(stat), Some(987_654));
        assert_eq!(parse_stat_start_time("4242 (x) S 1"), None);
    }

    #[test]
    fn this_process_has_a_stable_start_time_and_a_child_a_later_one() {
        let own = proc_start_time(std::process::id()).expect("own start time");
        assert_eq!(proc_start_time(std::process::id()), Some(own));
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let theirs = proc_start_time(child.id()).expect("child start time");
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(theirs >= own);
        assert_eq!(proc_start_time(child.id()), None);
    }
}
