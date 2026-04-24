//! Session types and context structs

use crate::Result;
use std::time::Duration;

/// Kind of session currently running
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionKind {
    /// Running in TTY (no graphical session)
    Tty,
    /// Running in user's graphical session
    GraphicalUser,
    /// Running as root in graphical session without a target user
    GraphicalRoot,
    /// Running over SSH
    Ssh,
    /// Cannot determine session type
    Unknown,
}

/// Context about the current session and target user
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionContext {
    /// Session classification
    pub kind: SessionKind,
    /// logind session id, if available
    pub session_id: Option<String>,
    /// Display manager service to stop/start
    pub display_manager: Option<String>,
    /// Target user uid to terminate
    pub target_uid: Option<u32>,
    /// Target user name (best-effort)
    pub target_user: Option<String>,
    /// Whether logind is available
    pub logind_available: bool,
}

/// Plan for restart after session kill
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionRestartPlan {
    /// Display manager service to restart
    pub display_manager: Option<String>,
    /// User uid to restart user manager for
    pub target_uid: Option<u32>,
}

/// Result of session kill operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKillResult {
    /// Display manager was successfully stopped
    pub display_manager_stopped: bool,
    /// logind was used for termination
    pub logind_used: bool,
    /// Session termination attempted and succeeded
    pub session_terminated: bool,
    /// User termination attempted and succeeded
    pub user_terminated: bool,
    /// Number of processes terminated in fallback mode
    pub fallback_processes_terminated: u32,
    /// Number of processes force-killed in fallback mode
    pub fallback_processes_force_killed: u32,
    /// Time taken for operation
    pub duration: Duration,
    /// Plan for restart after activation
    pub restart_plan: SessionRestartPlan,
}

impl Default for SessionKillResult {
    fn default() -> Self {
        Self {
            display_manager_stopped: false,
            logind_used: false,
            session_terminated: false,
            user_terminated: false,
            fallback_processes_terminated: 0,
            fallback_processes_force_killed: 0,
            duration: Duration::from_secs(0),
            restart_plan: SessionRestartPlan::default(),
        }
    }
}

/// Command executor for session operations
pub trait SessionCommandExecutor {
    /// Execute systemctl command
    fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)>;

    /// Execute loginctl command
    fn execute_loginctl(&self, args: &[&str]) -> Result<(bool, String, String)>;

    /// Send a signal to a process (e.g., TERM, KILL)
    fn execute_kill(&self, pid: u32, signal: &str) -> Result<bool>;

    /// Check whether loginctl is available
    fn loginctl_available(&self) -> bool;
}

/// Real command executor using system commands
pub struct RealSessionCommandExecutor;

impl SessionCommandExecutor for RealSessionCommandExecutor {
    #[cfg(not(test))]
    fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
        use std::process::Command;
        if crate::runtime_safety::should_skip_host_interaction() {
            return Err(crate::NailsError::InvalidState(
                "Refusing to execute systemctl from test/test-like runtime context; use a mock session executor instead".into(),
            ));
        }
        let output = Command::new("/run/current-system/sw/bin/systemctl")
            .args(args)
            .output()?;

        let success = output.status.success();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        Ok((success, stdout, stderr))
    }

    #[cfg(test)]
    fn execute_systemctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
        panic!(
            "RealSessionCommandExecutor::execute_systemctl called in test context - use a mock executor instead"
        )
    }

    #[cfg(not(test))]
    fn execute_loginctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
        use std::process::Command;
        if crate::runtime_safety::should_skip_host_interaction() {
            return Err(crate::NailsError::InvalidState(
                "Refusing to execute loginctl from test/test-like runtime context; use a mock session executor instead".into(),
            ));
        }
        let output = Command::new("loginctl").args(args).output()?;

        let success = output.status.success();
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        Ok((success, stdout, stderr))
    }

    #[cfg(test)]
    fn execute_loginctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
        panic!(
            "RealSessionCommandExecutor::execute_loginctl called in test context - use a mock executor instead"
        )
    }

    #[cfg(not(test))]
    fn execute_kill(&self, pid: u32, signal: &str) -> Result<bool> {
        use std::process::Command;
        if crate::runtime_safety::should_skip_host_interaction() {
            return Err(crate::NailsError::InvalidState(
                "Refusing to execute kill from test/test-like runtime context; use a mock session executor instead".into(),
            ));
        }
        Command::new("kill")
            .arg(format!("-{}", signal))
            .arg(pid.to_string())
            .status()
            .map(|s| s.success())
            .map_err(|e| e.into())
    }

    #[cfg(test)]
    fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
        panic!(
            "RealSessionCommandExecutor::execute_kill called in test context - use a mock executor instead"
        )
    }

    #[cfg(not(test))]
    fn loginctl_available(&self) -> bool {
        use std::process::Command;
        if crate::runtime_safety::should_skip_host_interaction() {
            return false;
        }
        Command::new("loginctl").arg("--version").output().is_ok()
    }

    #[cfg(test)]
    fn loginctl_available(&self) -> bool {
        panic!(
            "RealSessionCommandExecutor::loginctl_available called in test context - use a mock executor instead"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_kind_variants_compare_as_expected() {
        assert_eq!(SessionKind::Tty, SessionKind::Tty);
        assert_ne!(SessionKind::Tty, SessionKind::GraphicalUser);
        assert_eq!(SessionKind::Ssh, SessionKind::Ssh);
        assert_eq!(SessionKind::Unknown, SessionKind::Unknown);
    }

    #[test]
    fn session_context_clone_preserves_all_fields() {
        let context = SessionContext {
            kind: SessionKind::GraphicalRoot,
            session_id: Some("7".to_string()),
            display_manager: Some("display-manager".to_string()),
            target_uid: Some(1000),
            target_user: Some("amnesia".to_string()),
            logind_available: true,
        };

        let cloned = context.clone();

        assert_eq!(cloned, context);
    }

    #[test]
    fn session_restart_plan_default_is_empty() {
        let plan = SessionRestartPlan::default();
        assert!(plan.display_manager.is_none());
        assert!(plan.target_uid.is_none());
    }

    #[test]
    fn session_kill_result_default() {
        let result = SessionKillResult::default();
        assert!(!result.display_manager_stopped);
        assert!(!result.logind_used);
        assert_eq!(result.fallback_processes_terminated, 0);
        assert_eq!(result.fallback_processes_force_killed, 0);
    }

    #[test]
    fn session_kill_result_default_uses_empty_restart_plan_and_zero_duration() {
        let result = SessionKillResult::default();
        assert_eq!(result.duration, Duration::from_secs(0));
        assert_eq!(result.restart_plan, SessionRestartPlan::default());
    }
}
