// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Signal escalation against real processes, as PID 1 of a private PID
//! namespace (see `crate::test_support`), so no process outside the test can
//! be signalled.
//!
//! The unit tests record which signals `terminate` asks for. These send them:
//! the executor delivers real SIGTERM and SIGKILL, and the assertions are about
//! who is still alive afterwards and how each process died.

use super::{CommandExecutor, ProcessInfo, RestartMethod, terminate};
use crate::Result;
use crate::test_support::Rerun;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus};
use std::sync::mpsc;
use std::time::Duration;

/// Deliver `signal` (`TERM` or `KILL`) to `pid`; `false` when it is gone.
pub(crate) fn real_signal(pid: u32, signal: &str) -> bool {
    let signal = match signal {
        "TERM" => rustix::process::Signal::TERM,
        "KILL" => rustix::process::Signal::KILL,
        other => panic!("unexpected signal {other}"),
    };
    rustix::process::Pid::from_raw(pid as i32)
        .is_some_and(|pid| rustix::process::kill_process(pid, signal).is_ok())
}

/// A [`CommandExecutor`] whose signals are real.
struct RealSignals;

impl CommandExecutor for RealSignals {
    fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
        panic!("no systemctl in this test: {args:?}")
    }

    fn execute_kill(&self, pid: u32, signal: &str) -> Result<bool> {
        Ok(real_signal(pid, signal))
    }
}

/// Spawn `sh -c script` and reap it on a thread the moment it dies, as its
/// real parent would, so a dead child leaves no zombie behind for
/// `process_exists` to see. Returns its pid and a receiver for its status.
pub(crate) fn spawn_reaped(script: &str) -> (u32, mpsc::Receiver<ExitStatus>) {
    let mut child: Child = Command::new("sh").args(["-c", script]).spawn().unwrap();
    let pid = child.id();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait().unwrap());
    });
    // Let the shell install its traps before anyone signals it.
    std::thread::sleep(Duration::from_millis(200));
    (pid, rx)
}

fn process(pid: u32) -> ProcessInfo {
    ProcessInfo {
        pid,
        name: "worker".to_string(),
        cmdline: "sh -c worker".to_string(),
        cwd: PathBuf::from("/"),
        has_cwd_in_target: true,
        has_open_fds_in_target: false,
        has_mmap_in_target: false,
        has_writable_fd_in_target: false,
        has_dir_fd_in_target: false,
        has_shared_write_map_in_target: false,
        has_root_in_target: false,
        is_unverifiable_writer: false,
        service_name: None,
        is_interactive: false,
    }
}

fn died_of(rx: &mpsc::Receiver<ExitStatus>) -> Option<i32> {
    rx.recv_timeout(Duration::from_secs(5))
        .expect("the process exited")
        .signal()
}

#[test]
fn terminate_stops_a_cooperative_process_and_kills_one_that_ignores_term() {
    let _ = Rerun::new(crate::test_path!(
        terminate_stops_a_cooperative_process_and_kills_one_that_ignores_term
    ))
    .in_pid_ns()
    .run(|| {
        let (polite, polite_rx) = spawn_reaped("exec sleep 600");
        // An ignored signal stays ignored across exec.
        let (stubborn, stubborn_rx) = spawn_reaped("trap '' TERM; exec sleep 600");
        let (bystander, bystander_rx) = spawn_reaped("exec sleep 600");

        let stopped = terminate(&process(polite), &RealSignals).unwrap();
        assert!(stopped.stopped_successfully);
        assert_eq!(stopped.restart_method, RestartMethod::Terminate);
        assert_eq!(
            died_of(&polite_rx),
            Some(nix::libc::SIGTERM),
            "TERM was enough"
        );

        let stopped = terminate(&process(stubborn), &RealSignals).unwrap();
        assert!(stopped.stopped_successfully);
        assert_eq!(
            died_of(&stubborn_rx),
            Some(nix::libc::SIGKILL),
            "TERM was ignored, so KILL followed"
        );

        // A pid nothing holds: both signals fail, and it counts as stopped.
        let gone = terminate(&process(polite), &RealSignals).unwrap();
        assert!(gone.stopped_successfully);

        assert!(
            bystander_rx.try_recv().is_err(),
            "a process nobody targeted survives"
        );
        assert!(real_signal(bystander, "KILL"));
        assert_eq!(died_of(&bystander_rx), Some(nix::libc::SIGKILL));
    });
}
