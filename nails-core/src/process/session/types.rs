//! Session types and context structs

use crate::Result;
use crate::process::run::{
    LOGINCTL_BUDGET, ProcessCommand, ProcessRunner, RealProcessRunner, SYSTEMCTL_ACTION_BUDGET,
    SYSTEMCTL_PROBE_BUDGET, signal_command, systemctl_command,
};
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
///
/// Tests script this seam to drive session detection and termination
/// without a process runner.
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
///
/// A thin wrapper over [`RealProcessRunner`], which resolves `systemctl`,
/// `loginctl` and `kill` from the system tool directories and refuses them in
/// test runtimes.
pub struct RealSessionCommandExecutor;

impl SessionCommandExecutor for RealSessionCommandExecutor {
    fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
        RealProcessRunner.run_text(&systemctl_command(args).deadline(systemctl_budget(args)))
    }

    fn execute_loginctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
        RealProcessRunner.run_text(
            &ProcessCommand::tool("loginctl")
                .args(args)
                .deadline(LOGINCTL_BUDGET),
        )
    }

    fn execute_kill(&self, pid: u32, signal: &str) -> Result<bool> {
        Ok(RealProcessRunner
            .run(&signal_command(pid, signal))?
            .status
            .success())
    }

    /// True when `loginctl` could be started; its exit status does not matter.
    fn loginctl_available(&self) -> bool {
        RealProcessRunner
            .run(
                &ProcessCommand::tool("loginctl")
                    .arg("--version")
                    .deadline(LOGINCTL_BUDGET),
            )
            .is_ok()
    }
}

/// The deadline a `systemctl` invocation carries, by verb.
///
/// Read-only probes get the shorter probe budget; anything that changes unit
/// state (start/stop/restart/daemon-reload/…) gets the longer action budget. A
/// hung probe or action can no longer freeze session detection or teardown.
fn systemctl_budget(args: &[&str]) -> Duration {
    match args.first().copied() {
        Some(
            "is-active" | "is-enabled" | "is-failed" | "status" | "show" | "cat" | "list-units"
            | "list-unit-files" | "list-sockets" | "get-default",
        ) => SYSTEMCTL_PROBE_BUDGET,
        _ => SYSTEMCTL_ACTION_BUDGET,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::run::{UNKNOWN_UNIT, UNUSED_PID, assert_refused_in_test_runtime};

    #[test]
    fn real_session_executor_is_refused_by_the_runtime_guard_in_tests() {
        let executor = RealSessionCommandExecutor;

        assert_refused_in_test_runtime(
            executor.execute_systemctl(&["is-active", UNKNOWN_UNIT]),
            "systemctl",
        );
        assert_refused_in_test_runtime(
            executor.execute_loginctl(&["show-user", "nails-test-no-such-user"]),
            "loginctl",
        );
        assert_refused_in_test_runtime(executor.execute_kill(UNUSED_PID, "0"), "kill");
        assert!(!executor.loginctl_available());
    }

    #[test]
    fn systemctl_budget_separates_probes_from_actions() {
        assert_eq!(
            systemctl_budget(&["is-active", "gdm.service"]),
            SYSTEMCTL_PROBE_BUDGET
        );
        assert_eq!(systemctl_budget(&["show", "gdm"]), SYSTEMCTL_PROBE_BUDGET);
        assert_eq!(
            systemctl_budget(&["stop", "gdm.service"]),
            SYSTEMCTL_ACTION_BUDGET
        );
        assert_eq!(
            systemctl_budget(&["daemon-reload"]),
            SYSTEMCTL_ACTION_BUDGET
        );
        // An empty argument list is treated as a state change (the safer, longer
        // budget) rather than a probe.
        assert_eq!(systemctl_budget(&[]), SYSTEMCTL_ACTION_BUDGET);
    }

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
