//! Shell process cleanup for forensic safety
//!
//! Kills all user shell processes before overlay unmount to prevent
//! history flush race conditions. Shells receiving SIGHUP (hangup) would
//! write their in-memory history to disk — defeating cleanup. SIGKILL
//! terminates them immediately without triggering any signal handlers.

use crate::obfuscate;
#[cfg(not(test))]
use nix::libc;
use std::collections::HashSet;
#[cfg(not(test))]
use std::fs;
#[cfg(not(test))]
use std::path::Path;

/// Names of shell processes to kill
const SHELL_NAMES: &[&str] = &["bash", "zsh", "fish", "sh", "dash", "ksh", "tcsh"];

/// Service-scoped shell processes that should never be killed.
///
/// `backdoor.service` is the NixOS test-driver guest agent. Killing it severs
/// test harness communication and makes emergency E2E validation impossible,
/// but it does not exist in production deployments.
#[cfg(not(test))]
const SKIPPED_SERVICE_NAMES: &[&str] = &["backdoor"];
const PROTECTED_PIDS_ENV: &str = "NAILS_SHELL_CLEANUP_PROTECTED_PIDS";

#[cfg(not(test))]
fn read_service_name(pid: u32) -> Option<String> {
    let cgroup_path = Path::new("/proc").join(pid.to_string()).join("cgroup");
    let content = fs::read_to_string(cgroup_path).ok()?;

    for line in content.lines() {
        let service = line.rsplit('/').next()?;
        if service.ends_with(".service") {
            return Some(service.trim_end_matches(".service").to_string());
        }
    }

    None
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

fn shell_cleanup_target_uid() -> Option<u32> {
    std::env::var(obfuscate::env_target_uid())
        .ok()
        .or_else(|| std::env::var("SUDO_UID").ok())
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|uid| *uid != 0)
        .or_else(|| {
            let uid = nix::unistd::geteuid().as_raw();
            if uid == 0 { None } else { Some(uid) }
        })
}

fn should_kill_shell_process(shell_uid: u32, target_uid: Option<u32>) -> bool {
    target_uid.is_some_and(|target_uid| shell_uid == target_uid)
}

fn protected_shell_cleanup_pids() -> HashSet<u32> {
    std::env::var(PROTECTED_PIDS_ENV)
        .ok()
        .into_iter()
        .flat_map(|value| {
            value
                .split(',')
                .filter_map(|pid| pid.trim().parse::<u32>().ok())
                .collect::<Vec<_>>()
        })
        .collect()
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
/// # Returns
///
/// `ShellKillReport` with details of what was killed, failed, or skipped.
pub fn kill_user_shells() -> ShellKillReport {
    // Defense-in-depth: Never kill shells during tests
    #[cfg(test)]
    {
        tracing::warn!("kill_user_shells() called in test context - returning no-op");
        ShellKillReport::default()
    }

    #[cfg(not(test))]
    {
        let mut report = ShellKillReport::default();
        let own_pid = std::process::id();
        let target_uid = shell_cleanup_target_uid();
        let protected_pids = protected_shell_cleanup_pids();

        if target_uid.is_none() {
            tracing::warn!(
                "Skipping shell cleanup because no non-root target user could be determined"
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

            if protected_pids.contains(&pid) {
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

            if !should_kill_shell_process(shell_uid, target_uid) {
                tracing::debug!(
                    pid = pid,
                    comm = %comm,
                    shell_uid = shell_uid,
                    target_uid = target_uid,
                    "Skipping shell outside target user scope"
                );
                continue;
            }

            if let Some(service_name) = read_service_name(pid)
                && SKIPPED_SERVICE_NAMES.contains(&service_name.as_str())
            {
                tracing::debug!(pid = pid, comm = %comm, service = %service_name, "Skipping protected shell process");
                report.skipped.push(pid);
                continue;
            }

            tracing::debug!(pid = pid, comm = %comm, "Killing shell process");

            // Send SIGKILL
            // SAFETY: We're sending a signal to a process we identified via /proc.
            // This is a standard POSIX operation.
            let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };

            if result == 0 {
                report.killed.push(pid);
            } else {
                let err = std::io::Error::last_os_error();
                report.failed.push((pid, format!("{}: {}", comm, err)));
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
    use super::*;
    use serial_test::serial;
    use std::collections::HashSet;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

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
    #[serial]
    fn shell_cleanup_target_uid_prefers_explicit_target_uid() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            std::env::set_var(obfuscate::env_target_uid(), "1001");
            std::env::set_var("SUDO_UID", "1000");
        }

        assert_eq!(shell_cleanup_target_uid(), Some(1001));

        unsafe {
            std::env::remove_var(obfuscate::env_target_uid());
            std::env::remove_var("SUDO_UID");
        }
    }

    #[test]
    #[serial]
    fn shell_cleanup_target_uid_uses_sudo_uid_when_present() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            std::env::remove_var(obfuscate::env_target_uid());
            std::env::set_var("SUDO_UID", "1000");
        }

        assert_eq!(shell_cleanup_target_uid(), Some(1000));

        unsafe {
            std::env::remove_var("SUDO_UID");
        }
    }

    #[test]
    #[serial]
    fn protected_shell_cleanup_pids_parses_valid_pid_list() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        unsafe {
            std::env::set_var(PROTECTED_PIDS_ENV, "123, 456, nope, 789");
        }

        let parsed = protected_shell_cleanup_pids();
        let expected: HashSet<u32> = [123, 456, 789].into_iter().collect();
        assert_eq!(parsed, expected);

        unsafe {
            std::env::remove_var(PROTECTED_PIDS_ENV);
        }
    }

    #[test]
    #[ignore = "Invokes real process-kill logic and is unsafe outside an isolated test environment"]
    fn test_kill_user_shells_skips_own_pid() {
        // Ignored intentionally because it touches the real process table and
        // kill path on the host OS. It should only run in a disposable,
        // isolated environment where killing matching shell processes is safe.
        // The assertion here verifies we still protect the current test PID.
        let report = kill_user_shells();
        // Our own shell process (if any) should not have been killed
        let own_pid = std::process::id();
        assert!(!report.killed.contains(&own_pid));
    }
}
