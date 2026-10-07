// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The two child processes the hot path may run, each with a deadline.
//!
//! A kill of a service's processes lets systemd restart the unit when it has
//! `Restart=` set, and the restart lands after the detach, on the decoy. Only an
//! enqueued stop job suppresses that (ADR 0007, VM experiment), so the hot path
//! runs `systemctl stop --no-block` for the units it is about to kill. It also
//! runs `journalctl --relinquish-var` before `/var` comes down so journald stops
//! writing into the overlay. Both run the absolute path recorded at activation
//! (resolved on the decoy system, never through an overlaid store), with a
//! cleared environment and a deadline: a wedged PID 1 or journald costs at most
//! the deadline and never blocks the unmount.

use crate::plan::Tool;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How long `systemctl stop --no-block` may take. It only enqueues jobs.
pub const STOP_BUDGET: Duration = Duration::from_secs(2);

/// How long `journalctl --relinquish-var` may take.
pub const RELINQUISH_BUDGET: Duration = Duration::from_secs(2);

/// Run `tool args…` and wait at most `budget`. `true` when it exited 0 in
/// time; a child that overruns is killed.
pub fn run_bounded(tool: &Tool, args: &[&str], budget: Duration) -> bool {
    let mut command = match (&tool.loader, &tool.library_path) {
        (Some(loader), Some(library_path)) => {
            let mut command = Command::new(loader);
            command
                .arg("--library-path")
                .arg(library_path)
                .arg(&tool.program);
            command
        }
        _ => Command::new(&tool.program),
    };
    let child = command
        .args(args)
        .env_clear()
        .env(
            "PATH",
            "/run/current-system/sw/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        )
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir("/")
        .spawn();
    let Ok(mut child) = child else {
        return false;
    };
    let deadline = Instant::now() + budget;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

/// Enqueue a stop job for every unit at once, without waiting for the jobs.
pub fn stop_units(systemctl: &Tool, units: &[String]) -> bool {
    if units.is_empty() {
        return true;
    }
    let mut args = vec!["stop", "--no-block", "--"];
    args.extend(units.iter().map(String::as_str));
    run_bounded(systemctl, &args, STOP_BUDGET)
}

/// Hand journald's persistent journal back to `/run` before `/var` comes down.
pub fn relinquish_journal(journalctl: &Tool) -> bool {
    run_bounded(journalctl, &["--relinquish-var"], RELINQUISH_BUDGET)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh() -> Tool {
        Tool::direct("/bin/sh".into())
    }

    #[test]
    fn a_child_that_overruns_its_budget_is_killed() {
        let start = Instant::now();
        assert!(!run_bounded(
            &sh(),
            &["-c", "exec sleep 30"],
            Duration::from_millis(100)
        ));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn exit_status_and_a_missing_program_are_reported() {
        assert!(run_bounded(&sh(), &["-c", "exit 0"], STOP_BUDGET));
        assert!(!run_bounded(&sh(), &["-c", "exit 3"], STOP_BUDGET));
        assert!(!run_bounded(
            &Tool::direct("/nonexistent/tool".into()),
            &[],
            STOP_BUDGET
        ));
    }
}
