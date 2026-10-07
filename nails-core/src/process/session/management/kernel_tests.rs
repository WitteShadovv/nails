// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Process teardown against real processes, as PID 1 of a private PID
//! namespace (see `crate::test_support`): the user-process kill of a session
//! teardown and the emergency's interactive-shell kill. Every process in the
//! namespace belongs to the test, so whatever they signal, nothing outside
//! can be hit. The assertions are about who survives.

use super::kill_user_processes;
use crate::Result;
use crate::process::restart::kernel_tests::{real_signal, spawn_reaped};
use crate::process::session::types::SessionCommandExecutor;
use crate::test_support::Rerun;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// A [`SessionCommandExecutor`] whose signals are real and which runs nothing
/// else.
struct RealSignals;

impl SessionCommandExecutor for RealSignals {
    fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
        panic!("no systemctl in this test: {args:?}")
    }

    fn execute_loginctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
        panic!("no loginctl in this test: {args:?}")
    }

    fn execute_kill(&self, pid: u32, signal: &str) -> Result<bool> {
        Ok(real_signal(pid, signal))
    }

    fn loginctl_available(&self) -> bool {
        false
    }
}

#[test]
fn the_user_process_kill_terms_then_kills_and_spares_itself() {
    let _ = Rerun::new(crate::test_path!(
        the_user_process_kill_terms_then_kills_and_spares_itself
    ))
    .in_pid_ns()
    .run(|| {
        let (_, polite) = spawn_reaped("exec sleep 600");
        let (_, stubborn) = spawn_reaped("trap '' TERM; exec sleep 600");
        // Root of the user namespace: every process here has uid 0.
        let uid = rustix::process::getuid().as_raw();

        let (terminated, force_killed) = kill_user_processes(uid, &RealSignals).unwrap();

        let died_of = |rx: &std::sync::mpsc::Receiver<std::process::ExitStatus>| {
            rx.recv_timeout(Duration::from_secs(5)).unwrap().signal()
        };
        assert_eq!(died_of(&polite), Some(nix::libc::SIGTERM));
        assert_eq!(died_of(&stubborn), Some(nix::libc::SIGKILL));
        assert_eq!((terminated, force_killed), (2, 1));
        // This process (PID 1 here) read its own uid and is still running.
        assert_eq!(std::process::id(), 1);
    });
}

/// `setsid program args...` with a stdin pipe kept open and no output.
fn setsid(args: &[&str]) -> Child {
    Command::new("setsid")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn setsid")
}

#[test]
fn the_shell_kill_takes_interactive_shells_and_spares_the_rest() {
    let _ = Rerun::new(crate::test_path!(
        the_shell_kill_takes_interactive_shells_and_spares_the_rest
    ))
    .in_pid_ns()
    .run(|| {
        // The session this process came from lies outside the namespace, where
        // /proc shows it as 0; lead a session here, as a real invocation does.
        rustix::process::setsid().expect("lead a new session");
        let mut interactive = setsid(&["bash", "--norc", "--noprofile", "-i"]);
        let mut scripted = setsid(&["bash", "-c", "sleep 600; :"]);
        let mut daemon = setsid(&["sleep", "600"]);
        // An interactive shell in this process's own session is the
        // teardown's invocation: killed last, after the output, never here.
        let mut invoking = Command::new("bash")
            .args(["--norc", "--noprofile", "-i"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(300));

        let invocation = nails_teardown::proc::Invocation::current();
        let killed: Vec<u32> = nails_teardown::shells::kill_interactive_shells(&invocation, &[])
            .iter()
            .map(|h| h.pid())
            .collect();

        assert_eq!(killed, vec![interactive.id()]);
        let status = interactive.wait().unwrap();
        assert_eq!(status.signal(), Some(nix::libc::SIGKILL));
        for (name, child) in [
            ("a -c shell", &mut scripted),
            ("a non-shell", &mut daemon),
            ("the invoking shell", &mut invoking),
        ] {
            assert!(matches!(child.try_wait(), Ok(None)), "{name} survives");
            let _ = child.kill();
            let _ = child.wait();
        }
    });
}
