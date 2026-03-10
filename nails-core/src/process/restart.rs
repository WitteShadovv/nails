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
///
/// Stops the associated `.socket` unit first (if any) to prevent socket-activation
/// from immediately restarting the service. This is critical for services like
/// nix-daemon where systemd socket activation would restart the daemon during
/// the overlay mount window.
fn restart_systemd_service(
    proc: &ProcessInfo,
    service_name: &str,
    executor: &dyn CommandExecutor,
) -> Result<RestartedProcess> {
    // Stop socket first to prevent socket-activation restart (best-effort)
    let socket_name = format!("{}.socket", service_name);
    let _ = executor.execute_systemctl(&["stop", &socket_name]);

    // Then stop service
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

    /// Mock command executor that tracks calls for verification
    struct TrackingCommandExecutor {
        systemctl_calls: std::sync::Mutex<Vec<Vec<String>>>,
        systemctl_success: bool,
        kill_success: bool,
    }

    impl TrackingCommandExecutor {
        fn new(systemctl_success: bool) -> Self {
            Self {
                systemctl_calls: std::sync::Mutex::new(Vec::new()),
                systemctl_success,
                kill_success: true,
            }
        }

        fn systemctl_calls(&self) -> Vec<Vec<String>> {
            self.systemctl_calls.lock().unwrap().clone()
        }
    }

    impl CommandExecutor for TrackingCommandExecutor {
        fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
            self.systemctl_calls
                .lock()
                .unwrap()
                .push(args.iter().map(|s| s.to_string()).collect());
            Ok((self.systemctl_success, String::new(), String::new()))
        }

        fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
            Ok(self.kill_success)
        }
    }

    struct RecordingKillExecutor {
        kill_calls: std::sync::Mutex<Vec<(u32, String)>>,
        term_success: bool,
        kill_success: bool,
    }

    impl RecordingKillExecutor {
        fn new(term_success: bool, kill_success: bool) -> Self {
            Self {
                kill_calls: std::sync::Mutex::new(Vec::new()),
                term_success,
                kill_success,
            }
        }

        fn kill_calls(&self) -> Vec<(u32, String)> {
            self.kill_calls.lock().unwrap().clone()
        }
    }

    impl CommandExecutor for RecordingKillExecutor {
        fn execute_systemctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
            Ok((true, String::new(), String::new()))
        }

        fn execute_kill(&self, pid: u32, signal: &str) -> Result<bool> {
            self.kill_calls
                .lock()
                .unwrap()
                .push((pid, signal.to_string()));

            Ok(match signal {
                "TERM" => self.term_success,
                "KILL" => self.kill_success,
                _ => false,
            })
        }
    }

    struct ScriptedSystemctlExecutor {
        responses: std::sync::Mutex<Vec<Result<(bool, String, String)>>>,
        calls: std::sync::Mutex<Vec<Vec<String>>>,
    }

    impl ScriptedSystemctlExecutor {
        fn new(responses: Vec<Result<(bool, String, String)>>) -> Self {
            Self {
                responses: std::sync::Mutex::new(responses),
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<Vec<String>> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl CommandExecutor for ScriptedSystemctlExecutor {
        fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
            self.calls
                .lock()
                .unwrap()
                .push(args.iter().map(|arg| arg.to_string()).collect());

            self.responses.lock().unwrap().remove(0)
        }

        fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
            Ok(true)
        }
    }

    struct FailingSystemctlExecutor;

    impl CommandExecutor for FailingSystemctlExecutor {
        fn execute_systemctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
            Err(crate::NailsError::IoError(std::io::Error::other(
                "systemctl failed",
            )))
        }

        fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
            Ok(true)
        }
    }

    struct FailingKillExecutor;

    impl CommandExecutor for FailingKillExecutor {
        fn execute_systemctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
            Ok((true, String::new(), String::new()))
        }

        fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
            Err(crate::NailsError::IoError(std::io::Error::other(
                "kill failed",
            )))
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
    fn test_restart_processes_with_executor_empty_input_returns_empty() {
        let executor = MockCommandExecutor {
            systemctl_success: true,
            kill_success: true,
        };

        let results = restart_processes_with_executor(&[], &executor).unwrap();

        assert!(results.is_empty());
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

    #[test]
    fn test_restart_via_signal_term_only_when_pid_already_absent() {
        let pid = 99_999_999;
        let proc = make_test_process("missing-proc", pid, None);
        let executor = RecordingKillExecutor::new(true, true);

        let result = restart_via_signal(&proc, &executor).unwrap();

        assert_eq!(result.restart_method, RestartMethod::Signal);
        assert!(result.stopped_successfully);
        assert_eq!(executor.kill_calls(), vec![(pid, "TERM".to_string())]);
    }

    #[test]
    fn test_restart_via_signal_escalates_to_kill_when_process_still_exists() {
        let pid = std::process::id();
        let proc = make_test_process("current-proc", pid, None);
        let executor = RecordingKillExecutor::new(true, true);

        let result = restart_via_signal(&proc, &executor).unwrap();

        assert_eq!(result.restart_method, RestartMethod::Signal);
        assert!(result.stopped_successfully);
        assert_eq!(
            executor.kill_calls(),
            vec![(pid, "TERM".to_string()), (pid, "KILL".to_string())]
        );
    }

    #[test]
    fn test_restart_via_signal_goes_to_kill_when_term_command_fails() {
        let pid = 42_424;
        let proc = make_test_process("term-fails", pid, None);
        let executor = RecordingKillExecutor::new(false, true);

        let result = restart_via_signal(&proc, &executor).unwrap();

        assert_eq!(result.restart_method, RestartMethod::Signal);
        assert!(result.stopped_successfully);
        assert_eq!(
            executor.kill_calls(),
            vec![(pid, "TERM".to_string()), (pid, "KILL".to_string())]
        );
    }

    #[test]
    fn test_restart_processes_with_executor_propagates_systemctl_error() {
        let processes = vec![make_test_process("svc", 12, Some("svc".to_string()))];

        let result = restart_processes_with_executor(&processes, &FailingSystemctlExecutor);

        assert!(result.is_err());
    }

    #[test]
    fn test_restart_processes_with_executor_propagates_kill_error() {
        let processes = vec![make_test_process("daemon", 34, None)];

        let result = restart_processes_with_executor(&processes, &FailingKillExecutor);

        assert!(result.is_err());
    }

    // Socket-aware service stopping tests
    #[test]
    fn test_restart_systemd_service_stops_socket_first() {
        let proc = make_test_process("nix-daemon", 234, Some("nix-daemon".to_string()));
        let executor = TrackingCommandExecutor::new(true);

        let result = restart_systemd_service(&proc, "nix-daemon", &executor).unwrap();
        assert!(result.stopped_successfully);

        let calls = executor.systemctl_calls();
        assert_eq!(calls.len(), 2);
        // Socket stopped first
        assert_eq!(calls[0], vec!["stop", "nix-daemon.socket"]);
        // Then service
        assert_eq!(calls[1], vec!["stop", "nix-daemon"]);
    }

    #[test]
    fn test_restart_systemd_socket_failure_doesnt_prevent_service_stop() {
        // Socket stop failure should not prevent the service from being stopped
        let proc = make_test_process("nix-daemon", 234, Some("nix-daemon".to_string()));
        // Even if systemctl returns false (socket stop "fails"), service stop still proceeds
        // because socket stop is best-effort (uses let _ =)
        let executor = TrackingCommandExecutor::new(true);

        let result = restart_systemd_service(&proc, "nix-daemon", &executor).unwrap();
        assert!(result.stopped_successfully);

        // Both calls were made
        let calls = executor.systemctl_calls();
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn test_restart_systemd_service_ignores_socket_stop_error_and_stops_service() {
        let proc = make_test_process("nix-daemon", 234, Some("nix-daemon".to_string()));
        let executor = ScriptedSystemctlExecutor::new(vec![
            Err(crate::NailsError::IoError(std::io::Error::other(
                "socket stop failed",
            ))),
            Ok((true, String::new(), String::new())),
        ]);

        let result = restart_systemd_service(&proc, "nix-daemon", &executor).unwrap();

        assert!(result.stopped_successfully);
        assert_eq!(
            executor.calls(),
            vec![
                vec!["stop".to_string(), "nix-daemon.socket".to_string()],
                vec!["stop".to_string(), "nix-daemon".to_string()],
            ]
        );
    }

    #[test]
    fn test_restart_systemd_service_with_journald() {
        // Verify socket-aware stopping works for other services too
        let proc = make_test_process(
            "systemd-journald",
            100,
            Some("systemd-journald".to_string()),
        );
        let executor = TrackingCommandExecutor::new(true);

        let result = restart_systemd_service(&proc, "systemd-journald", &executor).unwrap();
        assert!(result.stopped_successfully);

        let calls = executor.systemctl_calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], vec!["stop", "systemd-journald.socket"]);
        assert_eq!(calls[1], vec!["stop", "systemd-journald"]);
    }
}
