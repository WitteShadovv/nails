// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shell process cleanup for forensic safety
//!
//! Kills all user shell processes before overlay unmount to prevent
//! history flush race conditions. Shells receiving SIGHUP (hangup) would
//! write their in-memory history to disk — defeating cleanup. SIGKILL
//! terminates them immediately without triggering any signal handlers.

#[cfg(not(test))]
use std::fs;
#[cfg(not(test))]
use std::path::Path;

/// Names of shell processes to kill
const SHELL_NAMES: &[&str] = &["bash", "zsh", "fish", "sh", "dash", "ksh", "tcsh"];

/// Service-scoped shell processes that must never be killed, named by the E2E
/// harness through a test-hooks-only environment variable.
///
/// The NixOS test-driver guest agent (its unit carries the test harness
/// connection) must survive cleanup for emergency E2E validation to work, but it
/// does not exist in production deployments. Shipped builds therefore skip no
/// services and read no such variable: the whole mechanism is compiled out.
#[cfg(all(not(test), feature = "test-hooks"))]
fn protected_service_names() -> Vec<String> {
    std::env::var("NAILS_SHELL_CLEANUP_PROTECTED_SERVICES")
        .map(|value| {
            value
                .split(',')
                .map(|name| name.trim().to_string())
                .filter(|name| !name.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(all(not(test), feature = "test-hooks"))]
fn read_service_name(pid: u32) -> Option<String> {
    let cgroup_path = Path::new("/proc").join(pid.to_string()).join("cgroup");
    let content = fs::read_to_string(cgroup_path).ok()?;

    // Same system.slice guard as process detection: a user unit must never be
    // treated as a system service here either.
    content
        .lines()
        .find_map(crate::process::detection::system_unit_from_cgroup_line)
        .map(str::to_string)
}

/// Report of shell kill operation
#[derive(Debug, Clone, Default)]
pub struct ShellKillReport {
    /// PIDs that were successfully killed
    pub killed: Vec<u32>,
    /// PIDs that could not be killed (with reason)
    pub failed: Vec<(u32, String)>,
    /// PIDs that were skipped (own process)
    pub skipped: Vec<u32>,
}

impl ShellKillReport {
    /// Total number of shells found
    pub fn total_found(&self) -> usize {
        self.killed.len() + self.failed.len() + self.skipped.len()
    }
}

/// The uid whose shells deactivation must kill: the operator resolved once
/// through [`crate::TargetUser`], never root. When no operator can be resolved —
/// an unprivileged or test run with no escalation context — fall back to the
/// current effective uid, again excluding root so cleanup never targets root's
/// shells.
#[cfg(not(test))]
fn shell_cleanup_target_uid() -> Option<u32> {
    crate::TargetUser::resolve()
        .ok()
        .map(|user| user.uid)
        .filter(|uid| *uid != 0)
        .or_else(non_root_self_uid)
}

/// The current effective uid, unless it is root.
fn non_root_self_uid() -> Option<u32> {
    let uid = nix::unistd::geteuid().as_raw();
    (uid != 0).then_some(uid)
}

fn should_kill_shell_process(shell_uid: u32, target_uid: Option<u32>) -> bool {
    target_uid.is_some_and(|target_uid| shell_uid == target_uid)
}

/// Which shells a cleanup pass targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KillScope {
    /// Only the resolved operator's shells (never root). Used by pre-unmount
    /// cleanup passes that run while the session is otherwise intact.
    OperatorOnly,
    /// Every interactive shell on the host, including root's. Used at final
    /// teardown, where root's own decoy shell must also be killed before it can
    /// flush its in-memory history: an interactive root shell would otherwise
    /// write the hidden-session commands to `/root/.bash_history` on exit.
    AllInteractive,
}

/// Whether a scanned shell should be killed under the given scope.
///
/// Under [`KillScope::AllInteractive`] every shell qualifies regardless of uid
/// (the own-PID and protected-PID exclusions are applied separately by the
/// scan); under [`KillScope::OperatorOnly`] only the resolved target uid does.
fn should_kill_in_scope(scope: KillScope, shell_uid: u32, target_uid: Option<u32>) -> bool {
    match scope {
        KillScope::AllInteractive => true,
        KillScope::OperatorOnly => should_kill_shell_process(shell_uid, target_uid),
    }
}

/// Whether a shell process is interactive by the shell's own rules, and so is
/// one that keeps (and on exit flushes) a command history.
///
/// Follows bash's definition, which zsh, ksh and fish share in substance: a
/// shell given `-c` or a script file as its first non-option argument is not
/// interactive (it never reads or saves history); `-i` forces interactive;
/// otherwise it is interactive exactly when its stdin and stderr are both
/// terminals. `argv[0]` (including a login shell's leading `-`) is ignored.
///
/// The teardown kill exists to stop a shell flushing in-memory history onto the
/// decoy, so only interactive shells are worth killing: a non-interactive shell
/// — a service's script, a `sh -c` wrapper, a pipeline subshell — has no history
/// to flush, and SIGKILLing it would only break decoy services.
fn shell_is_interactive(argv: &[String], stdin_tty: bool, stderr_tty: bool) -> bool {
    let mut forced_interactive = false;
    let mut read_stdin = false;
    let mut args = argv.iter().skip(1);
    while let Some(arg) = args.next() {
        let arg = arg.as_str();
        if arg == "--" {
            break;
        }
        if let Some(long) = arg.strip_prefix("--") {
            // Long options that consume the next word.
            if matches!(long, "rcfile" | "init-file") {
                args.next();
            }
            continue;
        }
        if let Some(flags) = arg.strip_prefix(['-', '+'])
            && !flags.is_empty()
        {
            for flag in flags.chars() {
                match flag {
                    'c' => return false,
                    'i' => forced_interactive = true,
                    's' => read_stdin = true,
                    _ => {}
                }
            }
            if flags.ends_with(['o', 'O']) {
                args.next();
            }
            continue;
        }
        // The first non-option argument is a script to run, unless -s says the
        // commands come from stdin and the words are positional parameters.
        if !read_stdin {
            return forced_interactive;
        }
        break;
    }
    forced_interactive || (stdin_tty && stderr_tty)
}

/// Whether a resolved `/proc/<pid>/fd/N` target is a terminal device.
#[cfg(not(test))]
fn fd_is_terminal(proc_pid: &Path, fd: &str) -> bool {
    fs::read_link(proc_pid.join("fd").join(fd)).is_ok_and(|link| {
        let text = link.to_string_lossy();
        ["/dev/pts/", "/dev/tty", "/dev/console", "/dev/hvc"]
            .iter()
            .any(|prefix| text.starts_with(prefix))
    })
}

/// Whether the shell process `pid` is interactive (see [`shell_is_interactive`]).
#[cfg(not(test))]
fn process_shell_is_interactive(pid: u32) -> bool {
    let proc_pid = Path::new("/proc").join(pid.to_string());
    let argv: Vec<String> = fs::read(proc_pid.join("cmdline"))
        .map(|raw| {
            raw.split(|byte| *byte == 0)
                .filter(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect()
        })
        .unwrap_or_default();
    shell_is_interactive(
        &argv,
        fd_is_terminal(&proc_pid, "0"),
        fd_is_terminal(&proc_pid, "2"),
    )
}

/// Whether a scanned PID is in the caller-supplied protected set.
///
/// Protected PIDs are the deactivation process's own ancestry plus any PIDs
/// handed across the `systemd-run` boundary by the detached invocation, so the
/// calling session's shells survive the cleanup.
fn pid_is_protected(pid: u32, protected: &[u32]) -> bool {
    protected.contains(&pid)
}

#[cfg(not(test))]
fn read_uid_from_status(pid: u32) -> Option<u32> {
    let status_path = Path::new("/proc").join(pid.to_string()).join("status");
    let content = fs::read_to_string(status_path).ok()?;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:\t") {
            let first = rest.split_whitespace().next()?;
            return first.parse::<u32>().ok();
        }
    }

    None
}

/// Kills all user shell processes (bash, zsh, fish, etc.) using SIGKILL.
///
/// Scans `/proc/*/comm` for known shell names and sends SIGKILL.
/// Skips the current process's PID. Best-effort and non-fatal.
///
/// # Safety
///
/// **WARNING:** This function sends SIGKILL to real processes on the system.
/// It is automatically disabled in test builds via `#[cfg(test)]`.
///
/// This function should only be called during actual NAILS deactivation
/// when cleaning up before unmounting overlays.
///
/// # Why SIGKILL (not SIGHUP)?
///
/// SIGHUP triggers bash's history-save trap (`HISTFILE` flush), which would
/// write in-memory commands to disk — exactly what we're trying to prevent.
/// SIGKILL terminates immediately with no signal handler execution.
///
/// # Arguments
///
/// * `protected_pids` - PIDs that must never be killed (the caller's own
///   process ancestry plus any PIDs handed across the `systemd-run` boundary).
///
/// # Returns
///
/// `ShellKillReport` with details of what was killed, failed, or skipped.
pub fn kill_user_shells(protected_pids: &[u32]) -> ShellKillReport {
    kill_shells(protected_pids, KillScope::OperatorOnly)
}

/// Kills every interactive shell on the host, including root's, using SIGKILL.
///
/// This is the final-teardown pass: unlike [`kill_user_shells`] it is not scoped
/// to the operator's uid, so root's own decoy shell is killed too, before it can
/// flush its in-memory history to `/root/.bash_history` on exit. The caller runs
/// it after stopping the display manager / logind session and relies on the
/// deactivation detach so the invoking shell is killed with the rest rather than
/// permanently protected — only the teardown's own process ancestry (and, in
/// test-hooks builds, the harness handoff set) stays in `protected_pids`.
///
/// Best-effort and non-fatal; compiled out in test builds like
/// [`kill_user_shells`].
pub fn kill_shells_for_teardown(protected_pids: &[u32]) -> ShellKillReport {
    kill_shells(protected_pids, KillScope::AllInteractive)
}

fn kill_shells(protected_pids: &[u32], scope: KillScope) -> ShellKillReport {
    // Defense-in-depth: Never kill shells during tests
    #[cfg(test)]
    {
        let _ = (protected_pids, scope);
        tracing::warn!("kill_shells() called in test context - returning no-op");
        ShellKillReport::default()
    }

    #[cfg(not(test))]
    {
        let mut report = ShellKillReport::default();
        let own_pid = std::process::id();
        // The operator uid only matters for the OperatorOnly scope; the
        // all-interactive teardown pass kills every uid, so a missing operator
        // must not short-circuit it.
        let target_uid = shell_cleanup_target_uid();

        if scope == KillScope::OperatorOnly && target_uid.is_none() {
            tracing::warn!(
                "Skipping operator shell cleanup because no non-root target user could be determined"
            );
            return report;
        }

        // Scan /proc for shell processes
        let proc_dir = match std::fs::read_dir("/proc") {
            Ok(dir) => dir,
            Err(e) => {
                tracing::warn!(error = %e, "Cannot read /proc, skipping shell cleanup");
                return report;
            }
        };

        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Only look at numeric directories (PIDs)
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Skip own PID
            if pid == own_pid {
                report.skipped.push(pid);
                continue;
            }

            if pid_is_protected(pid, protected_pids) {
                tracing::debug!(pid = pid, "Skipping protected shell process by pid");
                report.skipped.push(pid);
                continue;
            }

            // Read /proc/<pid>/comm to get process name
            let comm_path = Path::new("/proc").join(&*name_str).join("comm");
            let comm = match std::fs::read_to_string(&comm_path) {
                Ok(c) => c.trim().to_string(),
                Err(_) => continue, // Process may have exited
            };

            // Check if this is a shell process
            if !SHELL_NAMES.contains(&comm.as_str()) {
                continue;
            }

            let Some(shell_uid) = read_uid_from_status(pid) else {
                tracing::debug!(pid = pid, comm = %comm, "Skipping shell with unknown uid");
                continue;
            };

            if !should_kill_in_scope(scope, shell_uid, target_uid) {
                tracing::debug!(
                    pid = pid,
                    comm = %comm,
                    shell_uid = shell_uid,
                    target_uid = target_uid,
                    "Skipping shell outside target user scope"
                );
                continue;
            }

            if !process_shell_is_interactive(pid) {
                tracing::debug!(pid = pid, comm = %comm, "Skipping non-interactive shell (no history to flush)");
                report.skipped.push(pid);
                continue;
            }

            #[cfg(feature = "test-hooks")]
            if let Some(service_name) = read_service_name(pid)
                && protected_service_names()
                    .iter()
                    .any(|name| name == &service_name)
            {
                tracing::debug!(pid = pid, comm = %comm, service = %service_name, "Skipping protected shell process");
                report.skipped.push(pid);
                continue;
            }

            tracing::debug!(pid = pid, comm = %comm, "Killing shell process");

            // SIGKILL, not SIGHUP: the shell gets no chance to flush its history.
            // The PID came from a /proc directory name, so it fits a pid_t.
            let process = nix::unistd::Pid::from_raw(pid as i32);
            match nix::sys::signal::kill(process, nix::sys::signal::Signal::SIGKILL) {
                Ok(()) => report.killed.push(pid),
                Err(err) => report.failed.push((pid, format!("{}: {}", comm, err))),
            }
        }

        if !report.killed.is_empty() {
            // Brief wait for processes to terminate
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        tracing::info!(
            target_uid = target_uid,
            killed = report.killed.len(),
            failed = report.failed.len(),
            skipped = report.skipped.len(),
            "Shell process cleanup complete"
        );

        report
    }
}

#[cfg(test)]
mod tests {

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn a_terminal_login_shell_is_interactive() {
        assert!(shell_is_interactive(&argv(&["-bash"]), true, true));
        assert!(shell_is_interactive(&argv(&["bash", "-l"]), true, true));
        assert!(shell_is_interactive(&argv(&["zsh"]), true, true));
    }

    #[test]
    fn a_shell_without_a_terminal_is_not_interactive() {
        assert!(!shell_is_interactive(&argv(&["bash"]), false, false));
        // stdin a pipe, stderr a terminal: still not interactive.
        assert!(!shell_is_interactive(&argv(&["bash"]), false, true));
    }

    #[test]
    fn command_strings_and_scripts_are_not_interactive() {
        assert!(!shell_is_interactive(
            &argv(&["sh", "-lc", "nails emergency"]),
            true,
            true
        ));
        assert!(!shell_is_interactive(
            &argv(&["bash", "-c", "true"]),
            true,
            true
        ));
        // A script argument, even with a terminal on every fd.
        assert!(!shell_is_interactive(
            &argv(&["bash", "--norc", "/dev/hvc0"]),
            true,
            true
        ));
        assert!(!shell_is_interactive(
            &argv(&["bash", "/etc/backup.sh"]),
            true,
            true
        ));
    }

    #[test]
    fn dash_i_forces_interactive_and_dash_s_keeps_stdin() {
        assert!(shell_is_interactive(&argv(&["bash", "-i"]), false, false));
        assert!(shell_is_interactive(
            &argv(&["bash", "-i", "script"]),
            false,
            false
        ));
        assert!(shell_is_interactive(
            &argv(&["bash", "-s", "arg1"]),
            true,
            true
        ));
        assert!(!shell_is_interactive(
            &argv(&["bash", "-s", "arg1"]),
            false,
            false
        ));
        // An option argument after -o is not mistaken for a script.
        assert!(shell_is_interactive(
            &argv(&["bash", "-o", "vi"]),
            true,
            true
        ));
    }

    use super::*;

    #[test]
    fn test_shell_names_contains_common_shells() {
        assert!(SHELL_NAMES.contains(&"bash"));
        assert!(SHELL_NAMES.contains(&"zsh"));
        assert!(SHELL_NAMES.contains(&"fish"));
        assert!(SHELL_NAMES.contains(&"sh"));
        assert!(SHELL_NAMES.contains(&"dash"));
        assert!(SHELL_NAMES.contains(&"ksh"));
        assert!(SHELL_NAMES.contains(&"tcsh"));
    }

    #[test]
    fn test_shell_kill_report_default() {
        let report = ShellKillReport::default();
        assert_eq!(report.total_found(), 0);
        assert!(report.killed.is_empty());
        assert!(report.failed.is_empty());
        assert!(report.skipped.is_empty());
    }

    #[test]
    fn test_shell_kill_report_total_found() {
        let report = ShellKillReport {
            killed: vec![1, 2],
            failed: vec![(3, "err".to_string())],
            skipped: vec![4],
        };
        assert_eq!(report.total_found(), 4);
    }

    #[test]
    fn should_kill_only_target_uid_shells() {
        assert!(should_kill_shell_process(1000, Some(1000)));
        assert!(!should_kill_shell_process(0, Some(1000)));
        assert!(!should_kill_shell_process(1001, Some(1000)));
        assert!(!should_kill_shell_process(1000, None));
    }

    #[test]
    fn non_root_self_uid_never_returns_root() {
        // The fallback must never hand root's uid to the kill scan, whatever the
        // current euid is. Resolution precedence itself is covered by the
        // target-user resolver's own tests.
        let fallback = non_root_self_uid();
        assert_ne!(fallback, Some(0));
    }

    #[test]
    fn teardown_scope_kills_every_uid_including_root() {
        // AllInteractive is the final-teardown scope: root (uid 0) and every other
        // uid qualify, regardless of the resolved operator uid.
        assert!(should_kill_in_scope(
            KillScope::AllInteractive,
            0,
            Some(1000)
        ));
        assert!(should_kill_in_scope(
            KillScope::AllInteractive,
            1000,
            Some(1000)
        ));
        assert!(should_kill_in_scope(KillScope::AllInteractive, 1001, None));
    }

    #[test]
    fn operator_scope_spares_root_and_other_users() {
        // OperatorOnly keeps the pre-unmount behaviour: only the resolved operator
        // uid is killed, never root, never another user.
        assert!(should_kill_in_scope(
            KillScope::OperatorOnly,
            1000,
            Some(1000)
        ));
        assert!(!should_kill_in_scope(
            KillScope::OperatorOnly,
            0,
            Some(1000)
        ));
        assert!(!should_kill_in_scope(
            KillScope::OperatorOnly,
            1001,
            Some(1000)
        ));
        assert!(!should_kill_in_scope(KillScope::OperatorOnly, 1000, None));
    }

    #[test]
    fn teardown_still_honours_protected_pids() {
        // The scope decision never overrides the protected-PID exclusion that the
        // scan applies: a protected pid is skipped whatever its uid. This asserts
        // the invariant at the helper the scan uses.
        let protected = [42u32];
        assert!(pid_is_protected(42, &protected));
        assert!(!pid_is_protected(43, &protected));
    }

    #[test]
    fn pid_is_protected_honours_explicit_pid_list() {
        let protected = [123u32, 456, 789];
        assert!(pid_is_protected(123, &protected));
        assert!(pid_is_protected(789, &protected));
        assert!(!pid_is_protected(999, &protected));
        assert!(!pid_is_protected(123, &[]));
    }

    #[test]
    #[ignore = "Invokes real process-kill logic and is unsafe outside an isolated test environment"]
    fn test_kill_user_shells_skips_own_pid() {
        // Ignored intentionally because it touches the real process table and
        // kill path on the host OS. It should only run in a disposable,
        // isolated environment where killing matching shell processes is safe.
        // The assertion here verifies we still protect the current test PID.
        let report = kill_user_shells(&[]);
        // Our own shell process (if any) should not have been killed
        let own_pid = std::process::id();
        assert!(!report.killed.contains(&own_pid));
    }
}
