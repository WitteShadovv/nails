//! Process Restart
//!
//! Stops and restarts processes using systemd or signals.
//!
//! # Restart Strategy
//!
//! 1. **Systemd services**: Use `systemctl stop` if `service_name` is present
//! 2. **Non-systemd processes**: `terminate` them with `SIGTERM` followed by
//!    `SIGKILL`. This path never restarts anything, so it is named honestly:
//!    the caller is responsible for not terminating interactive user processes.
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
//!         is_interactive: false,
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
use crate::process::run::{ProcessRunner, RealProcessRunner, signal_command, systemctl_command};

/// Method used to stop a process
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartMethod {
    /// Stopped via systemctl
    Systemd,
    /// Terminated via signal (SIGTERM then SIGKILL). This stops the process; it
    /// does not restart it, which is why the method is named `Terminate`.
    Terminate,
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

/// The commands process restarts need.
///
/// Tests script this seam to drive the stop sequencing (socket before
/// service, SIGTERM before SIGKILL) without a process runner.
pub trait CommandExecutor {
    /// Execute systemctl command
    fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)>;

    /// Send signal to process
    fn execute_kill(&self, pid: u32, signal: &str) -> Result<bool>;
}

/// Real command executor for production use
///
/// A thin wrapper over [`RealProcessRunner`], which resolves `systemctl` and
/// `kill` from the system tool directories and refuses both in test runtimes.
pub struct RealCommandExecutor;

impl CommandExecutor for RealCommandExecutor {
    fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
        RealProcessRunner.run_text(&systemctl_command(args))
    }

    fn execute_kill(&self, pid: u32, signal: &str) -> Result<bool> {
        Ok(RealProcessRunner
            .run(&signal_command(pid, signal))?
            .status
            .success())
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
///         is_interactive: false,
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
            terminate(proc, executor)?
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

/// Terminate a process via signals (SIGTERM, then SIGKILL if it survives).
///
/// This only stops the process; it never restarts it. Callers must not pass an
/// interactive user process here without explicit consent — force-killing a
/// user's editor or `tail` loses their work silently.
fn terminate(proc: &ProcessInfo, executor: &dyn CommandExecutor) -> Result<RestartedProcess> {
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
                restart_method: RestartMethod::Terminate,
                stopped_successfully: true,
            });
        }
    }

    // SIGTERM didn't work, try SIGKILL (forceful)
    let kill_success = executor.execute_kill(proc.pid, "KILL")?;

    Ok(RestartedProcess {
        info: proc.clone(),
        restart_method: RestartMethod::Terminate,
        stopped_successfully: kill_success,
    })
}

/// Check if process still exists
fn process_exists(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
}

#[cfg(test)]
mod tests;
