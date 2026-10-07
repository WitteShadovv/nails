// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! The child processes the transitions run, each bounded by a deadline:
//! `systemctl` to enqueue the soft-reboot or a power action, and `dmsetup` to
//! mark the hidden backend for deferred removal.
//!
//! Every tool runs by absolute path (recorded at activation, or one of a fixed
//! list of system locations), with a cleared environment and no output, so a
//! wedged PID 1 costs at most the deadline.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How long one tool call may take. Both calls only enqueue work.
pub const TOOL_BUDGET: Duration = Duration::from_secs(3);

/// System locations searched for a tool the plan does not name.
const SYSTEM_BIN_DIRS: &[&str] = &[
    "/run/current-system/sw/bin",
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
];

/// `recorded` when it exists, else `name` in the first system directory that
/// has it.
pub fn find(recorded: Option<&Path>, name: &str) -> Option<PathBuf> {
    if let Some(path) = recorded
        && path.is_file()
    {
        return Some(path.to_path_buf());
    }
    SYSTEM_BIN_DIRS
        .iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|p| p.is_file())
}

/// How a bounded tool call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// It exited 0 in time.
    Done,
    /// It could not start, or it exited non-zero: the work was not done.
    Refused,
    /// It died by a signal or overran its deadline: whether the work was done
    /// is unknown.
    Unknown,
}

/// Run `program args…` and wait at most `budget`; a child that overruns is
/// killed. The child ignores SIGTERM, SIGINT and SIGHUP: enqueueing a
/// shutdown stops the unit it runs in, and the call must outlive that stop.
pub fn run(program: &Path, args: &[&str], budget: Duration) -> Outcome {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", SYSTEM_BIN_DIRS.join(":"))
        .env("LC_ALL", "C")
        .env("SYSTEMD_PAGER", "")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir("/");
    ignore_stop_signals(&mut command);
    let Ok(mut child) = command.spawn() else {
        return Outcome::Refused;
    };
    let deadline = Instant::now() + budget;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Outcome::Done,
            Ok(Some(status)) if status.code().is_some() => return Outcome::Refused,
            Ok(Some(_)) => return Outcome::Unknown,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Outcome::Unknown;
            }
        }
    }
}

/// [`run`], `true` only when the tool is known to have succeeded.
pub fn run_bounded(program: &Path, args: &[&str], budget: Duration) -> bool {
    run(program, args, budget) == Outcome::Done
}

/// Ignore SIGTERM, SIGINT and SIGHUP in this process from now on. The
/// emergency hot path kills the shell it was started from and enqueues a stop
/// of every session, its own included; neither may end it halfway.
#[allow(unsafe_code)]
pub fn survive_session_stop() {
    for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        // SAFETY: `signal(2)` with SIG_IGN installs no handler; it only
        // changes this process's disposition, which nothing else relies on
        // once the hot path has begun.
        unsafe {
            libc::signal(sig, libc::SIG_IGN);
        }
    }
}

/// Set SIGTERM, SIGINT and SIGHUP to ignored in the child. An ignored
/// disposition survives `exec`.
#[allow(unsafe_code)]
fn ignore_stop_signals(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure only calls `signal(2)`, which is async-signal-safe,
    // with constant arguments. It allocates nothing and touches no shared
    // state, so it is safe to run between fork and exec.
    unsafe {
        command.pre_exec(|| {
            for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
                libc::signal(sig, libc::SIG_IGN);
            }
            Ok(())
        });
    }
}

/// Enqueue `target` (`soft-reboot.target`, `poweroff.target`,
/// `reboot.target`) without waiting, replacing every other job irreversibly.
/// It talks to PID 1 directly, so it works with logind and D-Bus already gone,
/// and it checks no inhibitors. The outcome is [`Outcome::Unknown`] when the
/// call was cut short, typically because the shutdown it enqueued is already
/// stopping the caller.
pub fn start_target(systemctl: &Path, target: &str) -> Outcome {
    run(
        systemctl,
        &[
            "start",
            "--no-block",
            "--job-mode=replace-irreversibly",
            "--",
            target,
        ],
        TOOL_BUDGET,
    )
}

/// Reload the service manager, so a runtime drop-in written to `/run` applies.
pub fn daemon_reload(systemctl: &Path) -> bool {
    run_bounded(systemctl, &["daemon-reload"], Duration::from_secs(30))
}

/// Mark the device-mapper device `name` for removal on its last close. Its
/// key leaves kernel memory the moment the switch releases the last opener.
pub fn remove_deferred(dmsetup: &Path, name: &str) -> bool {
    run_bounded(
        dmsetup,
        &["remove", "--deferred", "--noudevsync", "--", name],
        TOOL_BUDGET,
    )
}

/// Remove the device-mapper device `name` now. Refused (`false`) while
/// anything holds it open: a mounted filesystem or a device stacked on it.
pub fn remove_now(dmsetup: &Path, name: &str) -> bool {
    run_bounded(
        dmsetup,
        &["remove", "--noudevsync", "--", name],
        TOOL_BUDGET,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tool_that_exits_zero_in_time_succeeds_and_a_slow_one_is_killed() {
        let sh = find(None, "sh").expect("a shell");
        assert!(run_bounded(&sh, &["-c", "exit 0"], TOOL_BUDGET));
        assert!(!run_bounded(&sh, &["-c", "exit 3"], TOOL_BUDGET));
        let start = Instant::now();
        assert!(!run_bounded(
            &sh,
            &["-c", "sleep 5"],
            Duration::from_millis(100)
        ));
        assert!(start.elapsed() < Duration::from_secs(3));
        assert!(!run_bounded(
            Path::new("/nonexistent/tool"),
            &[],
            TOOL_BUDGET
        ));
    }

    #[test]
    fn a_tool_killed_by_a_signal_has_an_unknown_outcome_and_ignores_sigterm() {
        let sh = find(None, "sh").expect("a shell");
        assert_eq!(run(&sh, &["-c", "exit 1"], TOOL_BUDGET), Outcome::Refused);
        assert_eq!(
            run(&sh, &["-c", "kill -KILL $$"], TOOL_BUDGET),
            Outcome::Unknown
        );
        assert_eq!(
            run(
                &sh,
                &["-c", "kill -TERM $$; kill -HUP $$; kill -INT $$; exit 0"],
                TOOL_BUDGET
            ),
            Outcome::Done
        );
        assert_eq!(
            run(&sh, &["-c", "sleep 5"], Duration::from_millis(100)),
            Outcome::Unknown
        );
    }

    #[test]
    fn a_recorded_tool_wins_and_a_missing_one_falls_back_to_the_system() {
        let dir = tempfile::tempdir().unwrap();
        let recorded = dir.path().join("systemctl");
        std::fs::write(&recorded, "").unwrap();
        assert_eq!(find(Some(&recorded), "systemctl"), Some(recorded.clone()));
        std::fs::remove_file(&recorded).unwrap();
        assert_ne!(find(Some(&recorded), "sh"), Some(recorded));
        assert_eq!(find(None, "no-such-tool-anywhere"), None);
    }
}
