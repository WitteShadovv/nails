//! Process Restart
//!
//! Stops and restarts processes using systemd or signals.
//!
//! # Restart Strategy
//!
//! 1. **Systemd services**: Use `systemctl stop` if `service_name` is present
//! 2. **Non-systemd processes**: Use `SIGTERM` followed by `SIGKILL` if necessary
//!
//! # Example
//!
//! ```no_run
//! use nails_core::process::{ProcessInfo, restart_processes};
//! use std::path::PathBuf;
//!
//! let processes = vec![
//!     ProcessInfo {
//!         pid: 234,
//!         name: "systemd-journald".to_string(),
//!         cmdline: "/usr/lib/systemd/systemd-journald".to_string(),
//!         cwd: PathBuf::from("/"),
//!         has_cwd_in_target: false,
//!         has_open_fds_in_target: true,
//!         has_mmap_in_target: false,
//!         service_name: Some("systemd-journald".to_string()),
//!     },
//! ];
//!
//! let results = restart_processes(&processes)?;
//! for result in results {
//!     println!("Process {} stopped: {}", result.info.name, result.stopped_successfully);
//! }
//! # Ok::<(), nails_core::NailsError>(())
//! ```

use crate::error::Result;
use crate::process::detection::ProcessInfo;
use std::process::Command;

/// Method used to restart a process
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartMethod {
    /// Stopped via systemctl
    Systemd,
    /// Stopped via signal (SIGTERM/SIGKILL)
    Signal,
}

/// Result of restarting a process
#[derive(Debug, Clone)]
pub struct RestartedProcess {
    /// Original process information
    pub info: ProcessInfo,
    /// Method used to restart
    pub restart_method: RestartMethod,
    /// Whether stop was successful
    pub stopped_successfully: bool,
}

/// Trait for executing commands (for testability)
///
/// This trait is intentionally kept separate from the CommandExecutor in nixos.rs
/// to avoid circular dependencies and maintain module independence.
pub trait CommandExecutor {
    /// Execute systemctl command
    fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)>;

    /// Send signal to process
    fn execute_kill(&self, pid: u32, signal: &str) -> Result<bool>;
}

/// Real command executor for production use
pub struct RealCommandExecutor;

impl CommandExecutor for RealCommandExecutor {
    fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
        let output = Command::new("systemctl").args(args).output()?;

        let success = output.status.success();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        Ok((success, stdout, stderr))
    }

    fn execute_kill(&self, pid: u32, signal: &str) -> Result<bool> {
        let output = Command::new("kill")
            .arg(format!("-{}", signal))
            .arg(pid.to_string())
            .output()?;

        Ok(output.status.success())
    }
}

/// Restart processes using systemd or signals
///
/// # Arguments
///
/// * `processes` - List of processes to restart
///
/// # Returns
///
/// * `Ok(Vec<RestartedProcess>)` - Results for each process
/// * `Err(NailsError)` - If command execution fails
///
/// # Example
///
/// ```no_run
/// use nails_core::process::{ProcessInfo, restart_processes};
/// use std::path::PathBuf;
///
/// let processes = vec![
///     ProcessInfo {
///         pid: 234,
///         name: "systemd-journald".to_string(),
///         cmdline: "/usr/lib/systemd/systemd-journald".to_string(),
///         cwd: PathBuf::from("/"),
///         has_cwd_in_target: false,
///         has_open_fds_in_target: true,
///         has_mmap_in_target: false,
///         service_name: Some("systemd-journald".to_string()),
///     },
/// ];
///
/// let results = restart_processes(&processes)?;
/// # Ok::<(), nails_core::NailsError>(())
/// ```
pub fn restart_processes(processes: &[ProcessInfo]) -> Result<Vec<RestartedProcess>> {
    restart_processes_with_executor(processes, &RealCommandExecutor)
}

/// Restart processes with custom executor (for testing)
pub fn restart_processes_with_executor(
    processes: &[ProcessInfo],
    executor: &dyn CommandExecutor,
) -> Result<Vec<RestartedProcess>> {
    let mut results = Vec::new();

    for proc in processes {
        let result = if let Some(ref service_name) = proc.service_name {
            // Use systemd
            restart_systemd_service(proc, service_name, executor)?
        } else {
            // Use signals
            restart_via_signal(proc, executor)?
        };

        results.push(result);
    }

    Ok(results)
}

/// Restart systemd service
fn restart_systemd_service(
    proc: &ProcessInfo,
    service_name: &str,
    executor: &dyn CommandExecutor,
) -> Result<RestartedProcess> {
    let (success, _stdout, _stderr) = executor.execute_systemctl(&["stop", service_name])?;

    if !success {
        return Ok(RestartedProcess {
            info: proc.clone(),
            restart_method: RestartMethod::Systemd,
            stopped_successfully: false,
        });
    }

    Ok(RestartedProcess {
        info: proc.clone(),
        restart_method: RestartMethod::Systemd,
        stopped_successfully: true,
    })
}

/// Restart process via signals
fn restart_via_signal(
    proc: &ProcessInfo,
    executor: &dyn CommandExecutor,
) -> Result<RestartedProcess> {
    // Try SIGTERM first (graceful)
    let term_success = executor.execute_kill(proc.pid, "TERM")?;

    if term_success {
        // Wait for process to exit gracefully (100ms is sufficient for most clean shutdowns)
        // This delay allows the process to handle signal handlers and cleanup before we check
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Check if process still exists
        // Note: There's a theoretical race where PID could be reused, but it's extremely
        // unlikely within 100ms on a normal system. The process_exists() check provides
        // reasonable confidence that the original process exited.
        if !process_exists(proc.pid) {
            return Ok(RestartedProcess {
                info: proc.clone(),
                restart_method: RestartMethod::Signal,
                stopped_successfully: true,
            });
        }
    }

    // SIGTERM didn't work, try SIGKILL (forceful)
    let kill_success = executor.execute_kill(proc.pid, "KILL")?;

    Ok(RestartedProcess {
        info: proc.clone(),
        restart_method: RestartMethod::Signal,
        stopped_successfully: kill_success,
    })
}

/// Check if process still exists
fn process_exists(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Mock command executor for testing
    struct MockCommandExecutor {
        systemctl_success: bool,
        kill_success: bool,
    }

    impl CommandExecutor for MockCommandExecutor {
        fn execute_systemctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
            Ok((self.systemctl_success, String::new(), String::new()))
        }

        fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
            Ok(self.kill_success)
        }
    }

    fn make_test_process(name: &str, pid: u32, service: Option<String>) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: name.to_string(),
            cmdline: format!("/usr/bin/{}", name),
            cwd: PathBuf::from("/"),
            has_cwd_in_target: false,
            has_open_fds_in_target: true,
            has_mmap_in_target: false,
            service_name: service,
        }
    }

    #[test]
    fn test_restart_systemd_service_success() {
        let proc = make_test_process(
            "systemd-journald",
            234,
            Some("systemd-journald".to_string()),
        );
        let executor = MockCommandExecutor {
            systemctl_success: true,
            kill_success: false,
        };

        let result = restart_systemd_service(&proc, "systemd-journald", &executor).unwrap();

        assert_eq!(result.restart_method, RestartMethod::Systemd);
        assert!(result.stopped_successfully);
    }

    #[test]
    fn test_restart_systemd_service_failure() {
        let proc = make_test_process(
            "systemd-journald",
            234,
            Some("systemd-journald".to_string()),
        );
        let executor = MockCommandExecutor {
            systemctl_success: false,
            kill_success: false,
        };

        let result = restart_systemd_service(&proc, "systemd-journald", &executor).unwrap();

        assert_eq!(result.restart_method, RestartMethod::Systemd);
        assert!(!result.stopped_successfully);
    }

    #[test]
    fn test_restart_via_signal_success() {
        let proc = make_test_process("some-daemon", 345, None);
        let executor = MockCommandExecutor {
            systemctl_success: false,
            kill_success: true,
        };

        let result = restart_via_signal(&proc, &executor).unwrap();

        assert_eq!(result.restart_method, RestartMethod::Signal);
        // Note: In test, process_exists() might return true since we're not actually killing
        // In production, this would check actual process state
    }

    #[test]
    fn test_restart_processes_with_executor() {
        let processes = vec![
            make_test_process(
                "systemd-journald",
                234,
                Some("systemd-journald".to_string()),
            ),
            make_test_process("some-daemon", 345, None),
        ];

        let executor = MockCommandExecutor {
            systemctl_success: true,
            kill_success: true,
        };

        let results = restart_processes_with_executor(&processes, &executor).unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].restart_method, RestartMethod::Systemd);
        assert_eq!(results[1].restart_method, RestartMethod::Signal);
    }

    #[test]
    fn test_restart_method_enum() {
        assert_eq!(RestartMethod::Systemd, RestartMethod::Systemd);
        assert_eq!(RestartMethod::Signal, RestartMethod::Signal);
        assert_ne!(RestartMethod::Systemd, RestartMethod::Signal);
    }

    #[test]
    fn test_restarted_process_struct() {
        let proc = make_test_process("test", 123, None);
        let restarted = RestartedProcess {
            info: proc.clone(),
            restart_method: RestartMethod::Signal,
            stopped_successfully: true,
        };

        assert_eq!(restarted.info.pid, 123);
        assert_eq!(restarted.restart_method, RestartMethod::Signal);
        assert!(restarted.stopped_successfully);
    }

    #[test]
    fn test_process_exists() {
        // Test with current process (should exist)
        let current_pid = std::process::id();
        assert!(process_exists(current_pid));

        // Test with unlikely PID (should not exist)
        assert!(!process_exists(99999999));
    }
}
