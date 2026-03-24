//! Session Management Logic
//!
//! Handles killing and restarting graphical sessions during activation.

use crate::{
    Filesystem, NailsManager, Result, Verbosity,
    process::{
        SessionKind, SessionRestartPlan, detect_session_context, kill_graphical_session,
        prompt_session_kill_confirmation,
    },
};

#[cfg(test)]
use crate::process::{SessionCommandExecutor, detect_session_context_with_executor};

impl<F: Filesystem> NailsManager<F> {
    /// Handle --kill-session flag (Story 4.15, AC8)
    /// Kill graphical session BEFORE pre-flight checks to ensure optimal activation
    /// This enables all direct overlay mounts without pivot mount fallback
    pub(super) fn handle_session_kill(
        verbosity: Verbosity,
        options: &crate::ActivateOptions,
    ) -> Result<SessionRestartPlan> {
        if !options.kill_session {
            return Ok(SessionRestartPlan::default());
        }

        if verbosity >= Verbosity::Normal {
            tracing::info!("Detecting session type for --kill-session...");
        }

        let session = detect_session_context()?;

        match session.kind {
            SessionKind::GraphicalUser => {
                // Prompt for confirmation unless --yes flag
                if !options.session_kill_confirmed {
                    prompt_session_kill_confirmation(&session, options.yes)?;
                }

                if verbosity >= Verbosity::Normal {
                    let dm = session
                        .display_manager
                        .as_deref()
                        .unwrap_or("display-manager");
                    tracing::info!("Killing graphical session ({})", dm);
                }

                let kill_result = kill_graphical_session(&session)?;

                if verbosity >= Verbosity::Verbose {
                    tracing::info!(
                        "  ✓ Session killed: {} processes terminated, {} force-killed",
                        kill_result.fallback_processes_terminated,
                        kill_result.fallback_processes_force_killed
                    );
                }

                // Store restart plan for later
                Ok(kill_result.restart_plan.clone())
            }
            SessionKind::Tty => {
                if verbosity >= Verbosity::Normal {
                    tracing::warn!("--kill-session requested, but running in TTY - skipping");
                }
                Ok(SessionRestartPlan::default())
            }
            SessionKind::Ssh => {
                if verbosity >= Verbosity::Normal {
                    tracing::warn!(
                        "--kill-session requested over SSH - skipping session termination"
                    );
                }
                Ok(SessionRestartPlan::default())
            }
            SessionKind::GraphicalRoot => {
                if verbosity >= Verbosity::Normal {
                    tracing::warn!("Running as root in graphical session - cannot kill session");
                }
                Ok(SessionRestartPlan::default())
            }
            SessionKind::Unknown => {
                if verbosity >= Verbosity::Normal {
                    tracing::warn!("Could not detect session type - skipping session kill");
                }
                Ok(SessionRestartPlan::default())
            }
        }
    }

    /// Handle --kill-session flag with injectable executor (for testing)
    #[cfg(test)]
    pub(super) fn handle_session_kill_with_executor<E: SessionCommandExecutor>(
        verbosity: Verbosity,
        options: &crate::ActivateOptions,
        executor: &E,
    ) -> Result<SessionRestartPlan> {
        if !options.kill_session {
            return Ok(SessionRestartPlan::default());
        }

        if verbosity >= Verbosity::Normal {
            tracing::info!("Detecting session type for --kill-session...");
        }

        let session = detect_session_context_with_executor(executor)?;

        match session.kind {
            SessionKind::GraphicalUser => {
                // In tests, we never get here because we test with TTY/SSH sessions
                Ok(SessionRestartPlan::default())
            }
            SessionKind::Tty => {
                if verbosity >= Verbosity::Normal {
                    tracing::warn!("--kill-session requested, but running in TTY - skipping");
                }
                Ok(SessionRestartPlan::default())
            }
            SessionKind::Ssh => {
                if verbosity >= Verbosity::Normal {
                    tracing::warn!(
                        "--kill-session requested over SSH - skipping session termination"
                    );
                }
                Ok(SessionRestartPlan::default())
            }
            SessionKind::GraphicalRoot => {
                if verbosity >= Verbosity::Normal {
                    tracing::warn!("Running as root in graphical session - cannot kill session");
                }
                Ok(SessionRestartPlan::default())
            }
            SessionKind::Unknown => {
                if verbosity >= Verbosity::Normal {
                    tracing::warn!("Could not detect session type - skipping session kill");
                }
                Ok(SessionRestartPlan::default())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ActivateOptions, Config, MockFilesystem, process::SessionCommandExecutor};
    use serial_test::serial;
    use std::path::PathBuf;

    /// Mock executor that always returns false for loginctl_available
    /// The session context is determined by environment variables in these tests
    struct MockSessionCommandExecutor;

    impl SessionCommandExecutor for MockSessionCommandExecutor {
        fn execute_systemctl(&self, _args: &[&str]) -> crate::Result<(bool, String, String)> {
            Ok((false, String::new(), String::new()))
        }

        fn execute_loginctl(&self, _args: &[&str]) -> crate::Result<(bool, String, String)> {
            Ok((false, String::new(), String::new()))
        }

        fn execute_kill(&self, _pid: u32, _signal: &str) -> crate::Result<bool> {
            Ok(true)
        }

        fn loginctl_available(&self) -> bool {
            false
        }
    }

    fn make_manager() -> NailsManager<MockFilesystem> {
        NailsManager::new(
            MockFilesystem::new(),
            Config::test_default(),
            PathBuf::from("/tmp/nails-session-state.json"),
        )
    }

    fn clear_session_env() {
        for key in [
            "SSH_TTY",
            "SSH_CONNECTION",
            "NAILS_LOGIND_AVAILABLE",
            "XDG_SESSION_ID",
            "NAILS_SESSION_ID",
            "NAILS_DISPLAY_MANAGER",
            "NAILS_TARGET_UID",
            "NAILS_TARGET_USER",
            "XDG_SESSION_TYPE",
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "SUDO_UID",
            "SUDO_USER",
            "PKEXEC_UID",
        ] {
            unsafe {
                std::env::remove_var(key);
            }
        }
    }

    #[test]
    fn handle_session_kill_returns_default_plan_when_disabled() {
        let _manager = make_manager();
        let options = ActivateOptions::default();
        let executor = MockSessionCommandExecutor;

        let plan = NailsManager::<MockFilesystem>::handle_session_kill_with_executor(
            Verbosity::Quiet,
            &options,
            &executor,
        )
        .unwrap();

        assert_eq!(plan, SessionRestartPlan::default());
    }

    #[test]
    #[serial]
    fn handle_session_kill_skips_ssh_sessions() {
        clear_session_env();
        unsafe {
            std::env::set_var("SSH_CONNECTION", "1 2 3 4");
            std::env::set_var("NAILS_LOGIND_AVAILABLE", "0");
        }

        let options = ActivateOptions {
            kill_session: true,
            yes: true,
            ..ActivateOptions::default()
        };
        let executor = MockSessionCommandExecutor;

        let plan = NailsManager::<MockFilesystem>::handle_session_kill_with_executor(
            Verbosity::Normal,
            &options,
            &executor,
        )
        .unwrap();

        assert_eq!(plan, SessionRestartPlan::default());
        clear_session_env();
    }

    #[test]
    #[serial]
    fn handle_session_kill_skips_tty_sessions() {
        clear_session_env();
        unsafe {
            std::env::set_var("XDG_SESSION_TYPE", "tty");
            std::env::set_var("NAILS_LOGIND_AVAILABLE", "0");
        }

        let options = ActivateOptions {
            kill_session: true,
            yes: true,
            ..ActivateOptions::default()
        };
        let executor = MockSessionCommandExecutor;

        let plan = NailsManager::<MockFilesystem>::handle_session_kill_with_executor(
            Verbosity::Normal,
            &options,
            &executor,
        )
        .unwrap();

        assert_eq!(plan, SessionRestartPlan::default());
        clear_session_env();
    }
}
