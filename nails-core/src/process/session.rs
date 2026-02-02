//! Session Detection and Management
//!
//! Provides session detection and controlled shutdown for graphical sessions.
//! Part of the **Universal Overlay Mounting Strategy** documented in
//! `/docs/architecture/universal-overlay-mounting-strategy.md`.
//!
//! This module enables the `--kill-session` flag for optimal activation from GUI
//! by terminating the graphical session, allowing all direct overlay mounts without
//! pivot mount fallback.
//!
//! # Key Components
//!
//! - **Session Detection**: Identify if running in GUI vs TTY
//! - **Display Manager Detection**: Determine which DM is active (gdm, sddm, etc.)
//! - **Session Kill**: Gracefully terminate graphical session with force-kill fallback
//! - **DM Restart**: Restart display manager after activation completes
//!
//! # Example
//!
//! ```no_run
//! use nails_core::process::session::{detect_session_type, kill_graphical_session, SessionType};
//!
//! // Detect current session type
//! let session = detect_session_type()?;
//!
//! match session {
//!     SessionType::GraphicalUser { .. } => {
//!         // Kill session if user consents
//!         let result = kill_graphical_session(&session)?;
//!         println!("Terminated {} processes", result.processes_terminated);
//!     }
//!     SessionType::Tty => {
//!         // Already optimal - no session to kill
//!         println!("Running in TTY - optimal activation path");
//!     }
//!     _ => {}
//! }
//! # Ok::<(), nails_core::NailsError>(())
//! ```

use crate::{NailsError, Result};
use std::env;
use std::fs;
use std::thread;
use std::time::{Duration, Instant};

/// Type of session currently running
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionType {
    /// Running in TTY (no graphical session)
    Tty,

    /// Running in user's graphical session
    GraphicalUser {
        /// Display manager name (e.g., "gdm", "sddm")
        display_manager: String,
        /// PID of session leader (compositor/X11)
        session_leader_pid: u32,
    },

    /// Running as root in graphical session
    GraphicalRoot,

    /// Running over SSH
    Ssh,

    /// Cannot determine session type
    Unknown,
}

/// Supported display managers
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisplayManager {
    /// GNOME Display Manager
    Gdm,
    /// Simple Desktop Display Manager
    Sddm,
    /// LightDM
    LightDm,
    /// Greetd
    Greetd,
    /// Ly
    Ly,
    /// Other display manager (holds the service name)
    Other(String),
}

impl DisplayManager {
    /// Get systemd service name for this display manager
    pub fn service_name(&self) -> &str {
        match self {
            Self::Gdm => "gdm",
            Self::Sddm => "sddm",
            Self::LightDm => "lightdm",
            Self::Greetd => "greetd",
            Self::Ly => "ly",
            Self::Other(name) => name.as_str(),
        }
    }
}

/// Result of session kill operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKillResult {
    /// Display manager was successfully stopped
    pub display_manager_stopped: bool,
    /// Number of processes terminated gracefully
    pub processes_terminated: u32,
    /// Number of processes force-killed
    pub processes_force_killed: u32,
    /// Time taken for operation
    pub duration: Duration,
}

impl Default for SessionKillResult {
    fn default() -> Self {
        Self {
            display_manager_stopped: false,
            processes_terminated: 0,
            processes_force_killed: 0,
            duration: Duration::from_secs(0),
        }
    }
}

/// Command executor for session operations
///
/// Abstraction layer for executing system commands, allowing tests to mock
/// systemctl and kill operations without affecting the actual system.
pub trait SessionCommandExecutor {
    /// Execute systemctl command
    fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)>;

    /// Count processes in graphical session
    fn count_session_processes(&self) -> Result<u32>;

    /// Force kill remaining session processes
    fn force_kill_session_processes(&self) -> Result<u32>;
}

/// Real command executor using system commands
pub struct RealSessionCommandExecutor;

impl SessionCommandExecutor for RealSessionCommandExecutor {
    fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
        use std::process::Command;
        let output = Command::new("systemctl").args(args).output()?;

        let success = output.status.success();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        Ok((success, stdout, stderr))
    }

    fn count_session_processes(&self) -> Result<u32> {
        // Count processes with DISPLAY or WAYLAND_DISPLAY
        let mut count = 0;

        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(pid_str) = entry.file_name().into_string()
                    && pid_str.chars().all(|c| c.is_ascii_digit())
                {
                    let environ_path = format!("/proc/{}/environ", pid_str);
                    if let Ok(environ) = fs::read_to_string(&environ_path)
                        && (environ.contains("DISPLAY=") || environ.contains("WAYLAND_DISPLAY="))
                    {
                        count += 1;
                    }
                }
            }
        }

        Ok(count)
    }

    fn force_kill_session_processes(&self) -> Result<u32> {
        let mut killed = 0;

        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(pid_str) = entry.file_name().into_string()
                    && let Ok(pid) = pid_str.parse::<u32>()
                {
                    let environ_path = format!("/proc/{}/environ", pid_str);
                    if let Ok(environ) = fs::read_to_string(&environ_path)
                        && (environ.contains("DISPLAY=") || environ.contains("WAYLAND_DISPLAY="))
                    {
                        // Send SIGKILL
                        use std::process::Command;
                        if Command::new("kill")
                            .args(["-9", &pid.to_string()])
                            .status()
                            .is_ok()
                        {
                            killed += 1;
                        }
                    }
                }
            }
        }

        Ok(killed)
    }
}

/// Detect the current session type
///
/// Checks environment variables and process information to determine
/// if running in graphical session, TTY, SSH, etc.
///
/// # Environment Variables Checked
///
/// - `$DISPLAY`: X11 display server
/// - `$WAYLAND_DISPLAY`: Wayland compositor
/// - `$SSH_TTY`: SSH connection indicator
///
/// # Errors
///
/// Returns error if unable to determine session type due to system issues.
pub fn detect_session_type() -> Result<SessionType> {
    // Check for SSH first
    if env::var("SSH_TTY").is_ok() || env::var("SSH_CONNECTION").is_ok() {
        return Ok(SessionType::Ssh);
    }

    // Check for graphical session indicators
    let has_display = env::var("DISPLAY").is_ok();
    let has_wayland = env::var("WAYLAND_DISPLAY").is_ok();

    if !has_display && !has_wayland {
        return Ok(SessionType::Tty);
    }

    // Graphical session detected - determine DM and check privileges
    let is_root = nix::unistd::getuid().is_root();

    if is_root {
        return Ok(SessionType::GraphicalRoot);
    }

    // User graphical session - detect DM and session leader
    let dm = detect_display_manager()?;

    // Try to find session leader, but use 0 as placeholder if not found
    // This allows session detection to succeed even with unknown compositors
    let session_leader = find_session_leader_pid().unwrap_or(0);

    Ok(SessionType::GraphicalUser {
        display_manager: dm
            .map(|d| d.service_name().to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        session_leader_pid: session_leader,
    })
}

/// Detect which display manager is currently active
///
/// Checks systemd services to identify the active display manager.
///
/// # Returns
///
/// - `Some(DisplayManager)` if a known DM is detected
/// - `None` if no display manager is detected
fn detect_display_manager() -> Result<Option<DisplayManager>> {
    use std::process::Command;

    let dms = [
        ("gdm", DisplayManager::Gdm),
        ("sddm", DisplayManager::Sddm),
        ("lightdm", DisplayManager::LightDm),
        ("greetd", DisplayManager::Greetd),
        ("ly", DisplayManager::Ly),
    ];

    for (service, dm) in dms {
        let output = Command::new("systemctl")
            .args(["is-active", service])
            .output();

        if let Ok(output) = output
            && output.status.success()
        {
            let status = String::from_utf8_lossy(&output.stdout);
            if status.trim() == "active" {
                return Ok(Some(dm));
            }
        }
    }

    Ok(None)
}

/// Find the PID of the session leader process
///
/// Looks for the compositor (Wayland) or X server (X11) process.
///
/// # Errors
///
/// Returns error if no session leader process can be found.
fn find_session_leader_pid() -> Result<u32> {
    // Look for common session leader processes
    let session_leaders = [
        "sway",
        "Hyprland",
        "gnome-shell",
        "kwin_wayland",
        "Xorg",
        "X",
        "kwin_x11",
        "mutter",
    ];

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Ok(pid_str) = entry.file_name().into_string()
                && let Ok(_pid) = pid_str.parse::<u32>()
            {
                let comm_path = format!("/proc/{}/comm", pid_str);
                if let Ok(comm) = fs::read_to_string(&comm_path) {
                    let comm = comm.trim();
                    if session_leaders.contains(&comm) {
                        return pid_str
                            .parse::<u32>()
                            .map_err(|e| NailsError::InvalidState(format!("Invalid PID: {}", e)));
                    }
                }
            }
        }
    }

    // No session leader found - return error instead of hardcoded placeholder
    Err(NailsError::InvalidState(
        "Could not detect session leader process. Known session leaders: sway, Hyprland, gnome-shell, kwin_wayland, Xorg, X, kwin_x11, mutter".to_string()
    ))
}

/// Prompt user for confirmation before killing graphical session
///
/// Displays a warning about session termination and requires explicit user
/// confirmation unless `--yes` flag is provided.
///
/// # Arguments
///
/// - `session`: The session type that will be killed
/// - `yes_flag`: If true, skip confirmation (user provided --yes flag)
///
/// # Returns
///
/// `Ok(())` if user confirms or `--yes` flag was provided
///
/// # Errors
///
/// Returns `Err` if user declines confirmation
///
/// # Example
///
/// ```no_run
/// use nails_core::process::session::{prompt_session_kill_confirmation, SessionType};
///
/// let session = SessionType::GraphicalUser {
///     display_manager: "gdm".to_string(),
///     session_leader_pid: 1234,
/// };
///
/// if let Err(_) = prompt_session_kill_confirmation(&session, false) {
///     println!("User declined confirmation");
/// }
/// # Ok::<(), nails_core::NailsError>(())
/// ```
pub fn prompt_session_kill_confirmation(session: &SessionType, yes_flag: bool) -> Result<()> {
    if yes_flag {
        return Ok(());
    }

    let display_manager = match session {
        SessionType::GraphicalUser {
            display_manager, ..
        } => display_manager.as_str(),
        _ => {
            return Err(NailsError::InvalidState(
                "Cannot confirm session kill - not a graphical user session".to_string(),
            ));
        }
    };

    println!("⚠️  This will terminate your graphical session!");
    println!("    All unsaved work in open applications will be LOST.");
    println!();
    println!("    The system will:");
    println!("    1. Stop display manager ({})", display_manager);
    println!("    2. Terminate all graphical session processes");
    println!("    3. Mount hidden environment overlays");
    println!("    4. Restart display manager");
    println!();
    println!("    You will need to log in again after activation.");
    println!();

    // Prompt for confirmation
    use std::io::{self, Write};
    print!("    Continue? [y/N]: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    let response = input.trim().to_lowercase();
    if response == "y" || response == "yes" {
        Ok(())
    } else {
        Err(NailsError::InvalidState(
            "User declined session kill confirmation".to_string(),
        ))
    }
}

/// Kill the graphical session
///
/// Stops the display manager and terminates all session processes.
/// Uses graceful termination first, then force-kills remaining processes.
///
/// # Arguments
///
/// - `session`: The session type to kill (must be GraphicalUser)
///
/// # Returns
///
/// Result containing session kill statistics
///
/// # Errors
///
/// - `InvalidState`: Not running in graphical session
/// - `PermissionDenied`: Not running as root
/// - `OverlayError`: Failed to stop display manager
///
/// # Example
///
/// ```no_run
/// use nails_core::process::session::{detect_session_type, kill_graphical_session};
///
/// let session = detect_session_type()?;
/// let result = kill_graphical_session(&session)?;
/// println!("Killed {} processes", result.processes_terminated);
/// # Ok::<(), nails_core::NailsError>(())
/// ```
pub fn kill_graphical_session(session: &SessionType) -> Result<SessionKillResult> {
    kill_graphical_session_with_executor(session, &RealSessionCommandExecutor)
}

/// Kill graphical session with custom executor (for testing)
fn kill_graphical_session_with_executor<E: SessionCommandExecutor>(
    session: &SessionType,
    executor: &E,
) -> Result<SessionKillResult> {
    // Safety check: Must be graphical user session
    let display_manager = match session {
        SessionType::GraphicalUser {
            display_manager, ..
        } => display_manager.clone(),
        SessionType::GraphicalRoot => {
            return Err(NailsError::InvalidState(
                "Session kill from root context not supported. Please run as a normal user in the graphical session.".to_string(),
            ));
        }
        SessionType::Tty => {
            return Err(NailsError::InvalidState(
                "Not running in graphical session (detected TTY)".to_string(),
            ));
        }
        SessionType::Ssh => {
            return Err(NailsError::InvalidState(
                "Not running in graphical session (detected SSH)".to_string(),
            ));
        }
        SessionType::Unknown => {
            return Err(NailsError::InvalidState(
                "Cannot determine session type - unable to kill session".to_string(),
            ));
        }
    };

    // Safety check: Must be root
    if !nix::unistd::getuid().is_root() {
        return Err(NailsError::PermissionDenied(
            "Session kill requires root privileges".to_string(),
        ));
    }

    let start = Instant::now();
    let mut result = SessionKillResult::default();

    // Step 1: Stop display manager
    let (success, _stdout, stderr) = executor.execute_systemctl(&["stop", &display_manager])?;
    if !success {
        return Err(NailsError::OverlayError(format!(
            "Failed to stop display manager {}: {}",
            display_manager, stderr
        )));
    }
    result.display_manager_stopped = true;

    // Step 2: Wait for processes to terminate gracefully (max 5 seconds)
    let deadline = Instant::now() + Duration::from_secs(5);
    let initial_count = executor.count_session_processes()?;

    loop {
        let remaining = executor.count_session_processes()?;
        if remaining == 0 {
            result.processes_terminated = initial_count;
            break;
        }

        if Instant::now() > deadline {
            // Step 3: Force kill remaining processes
            result.processes_terminated = initial_count - remaining;
            result.processes_force_killed = executor.force_kill_session_processes()?;
            break;
        }

        // Wait 100ms before checking again
        // This delay allows processes time to terminate gracefully
        thread::sleep(Duration::from_millis(100));
    }

    result.duration = start.elapsed();
    Ok(result)
}

/// Restart the display manager
///
/// Starts the display manager service using systemd.
///
/// # Arguments
///
/// - `dm`: Display manager to restart
///
/// # Returns
///
/// `Ok(())` if display manager starts successfully
///
/// # Errors
///
/// Returns error if display manager fails to start with troubleshooting advice.
pub fn restart_display_manager(dm: &DisplayManager) -> Result<()> {
    restart_display_manager_with_executor(dm, &RealSessionCommandExecutor)
}

/// Restart display manager with custom executor (for testing)
fn restart_display_manager_with_executor<E: SessionCommandExecutor>(
    dm: &DisplayManager,
    executor: &E,
) -> Result<()> {
    let service = dm.service_name();

    // Start the display manager service
    let (success, _stdout, stderr) = executor.execute_systemctl(&["start", service])?;

    if !success {
        return Err(NailsError::OverlayError(format!(
            "Failed to start display manager {}: {}\n\nTroubleshooting:\n\
            1. Check systemd logs: journalctl -u {}\n\
            2. Verify display manager is installed\n\
            3. Check display manager configuration\n\
            4. Try manual start: systemctl start {}",
            service, stderr, service, service
        )));
    }

    // Wait for greeter to appear (max 10 seconds)
    let deadline = Instant::now() + Duration::from_secs(10);

    loop {
        let (is_active, _stdout, _stderr) = executor.execute_systemctl(&["is-active", service])?;

        if is_active {
            return Ok(());
        }

        if Instant::now() > deadline {
            return Err(NailsError::OverlayError(format!(
                "Display manager {} failed to start within 10 seconds\n\nTroubleshooting:\n\
                1. Check systemd status: systemctl status {}\n\
                2. View logs: journalctl -u {} -n 50\n\
                3. Verify X11/Wayland configuration\n\
                4. Check for conflicting processes",
                service, service, service
            )));
        }

        thread::sleep(Duration::from_millis(500));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_manager_service_names() {
        assert_eq!(DisplayManager::Gdm.service_name(), "gdm");
        assert_eq!(DisplayManager::Sddm.service_name(), "sddm");
        assert_eq!(DisplayManager::LightDm.service_name(), "lightdm");
        assert_eq!(DisplayManager::Greetd.service_name(), "greetd");
        assert_eq!(DisplayManager::Ly.service_name(), "ly");
        assert_eq!(
            DisplayManager::Other("custom-dm".to_string()).service_name(),
            "custom-dm"
        );
    }

    #[test]
    fn test_session_kill_result_default() {
        let result = SessionKillResult::default();
        assert!(!result.display_manager_stopped);
        assert_eq!(result.processes_terminated, 0);
        assert_eq!(result.processes_force_killed, 0);
        assert_eq!(result.duration, Duration::from_secs(0));
    }

    #[test]
    fn test_detect_session_type_returns_valid_type() {
        // NOTE: This test is environment-dependent and may return different
        // results depending on where it's run (CI vs local TTY vs GUI).
        // It verifies that detect_session_type() doesn't panic and returns
        // a valid SessionType enum variant for the current environment.
        let session = detect_session_type().unwrap();
        assert!(matches!(
            session,
            SessionType::Tty
                | SessionType::GraphicalUser { .. }
                | SessionType::GraphicalRoot
                | SessionType::Ssh
                | SessionType::Unknown
        ));
    }

    #[test]
    fn test_kill_graphical_session_requires_graphical_session() {
        let tty_session = SessionType::Tty;
        let result = kill_graphical_session(&tty_session);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NailsError::InvalidState(_)));
    }

    #[test]
    fn test_kill_graphical_session_requires_root() {
        // This test assumes we're NOT running as root
        let graphical_session = SessionType::GraphicalUser {
            display_manager: "gdm".to_string(),
            session_leader_pid: 1000,
        };

        let result = kill_graphical_session(&graphical_session);

        // If we're not root, should fail with PermissionDenied
        if !nix::unistd::getuid().is_root() {
            assert!(result.is_err());
            assert!(matches!(
                result.unwrap_err(),
                NailsError::PermissionDenied(_)
            ));
        }
    }

    // Mock executor for testing
    struct MockSessionCommandExecutor {
        systemctl_success: bool,
        process_count: u32,
    }

    impl SessionCommandExecutor for MockSessionCommandExecutor {
        fn execute_systemctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
            Ok((self.systemctl_success, "".to_string(), "".to_string()))
        }

        fn count_session_processes(&self) -> Result<u32> {
            Ok(self.process_count)
        }

        fn force_kill_session_processes(&self) -> Result<u32> {
            Ok(self.process_count)
        }
    }

    #[test]
    fn test_kill_graphical_session_with_mock_executor() {
        // Skip if not root
        if !nix::unistd::getuid().is_root() {
            return;
        }

        let session = SessionType::GraphicalUser {
            display_manager: "gdm".to_string(),
            session_leader_pid: 1000,
        };

        let executor = MockSessionCommandExecutor {
            systemctl_success: true,
            process_count: 5,
        };

        let result = kill_graphical_session_with_executor(&session, &executor);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.display_manager_stopped);
        assert!(result.processes_terminated > 0 || result.processes_force_killed > 0);
    }

    #[test]
    fn test_restart_display_manager_with_mock_executor() {
        let dm = DisplayManager::Gdm;

        let executor = MockSessionCommandExecutor {
            systemctl_success: true,
            process_count: 0,
        };

        let result = restart_display_manager_with_executor(&dm, &executor);
        assert!(result.is_ok());
    }

    #[test]
    fn test_restart_display_manager_handles_failure() {
        let dm = DisplayManager::Gdm;

        let executor = MockSessionCommandExecutor {
            systemctl_success: false,
            process_count: 0,
        };

        let result = restart_display_manager_with_executor(&dm, &executor);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NailsError::OverlayError(_)));
    }

    #[test]
    fn test_prompt_session_kill_confirmation_with_yes_flag() {
        let graphical_session = SessionType::GraphicalUser {
            display_manager: "gdm".to_string(),
            session_leader_pid: 1000,
        };

        // With yes_flag=true, should skip confirmation
        let result = prompt_session_kill_confirmation(&graphical_session, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_kill_graphical_session_rejects_graphical_root() {
        let root_session = SessionType::GraphicalRoot;
        let result = kill_graphical_session(&root_session);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), NailsError::InvalidState(_)));
    }

    #[test]
    fn test_display_manager_other_with_string() {
        let dm = DisplayManager::Other("custom-dm".to_string());
        assert_eq!(dm.service_name(), "custom-dm");
    }
}
