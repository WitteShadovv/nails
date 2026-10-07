// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Telling one process apart from a later one that reused its pid.

pub(crate) use nails_teardown::proc::ProcessHandle;

/// The start time of `pid`, from `/proc/<pid>/stat`; `None` when it is gone.
pub(crate) fn proc_start_time(pid: u32) -> Option<u64> {
    nails_teardown::proc::stat(pid).map(|s| s.start_time)
}

/// The parent pid of `pid`, from `/proc/<pid>/stat`.
pub(crate) fn parent_pid(pid: u32) -> Option<u32> {
    nails_teardown::proc::stat(pid).map(|s| s.ppid)
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
