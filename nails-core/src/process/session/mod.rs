//! Session Detection and Management
//!
//! Provides logind-first session termination for the `--kill-session` flag.
//! The goal is to stop the display manager, terminate the user's graphical
//! session (and all user processes that could leak to underlays), then
//! restart the display manager and user manager after activation.
//!
//! Fallback behavior is included for non-logind environments.

mod detection;
mod management;
pub mod types;

// Re-export all public API items to maintain backward compatibility
pub use detection::{detect_session_context, detect_session_context_with_executor};
pub use management::{
    kill_graphical_session, prompt_session_kill_confirmation, restart_display_manager,
    restart_user_manager,
};
pub use types::{
    RealSessionCommandExecutor, SessionCommandExecutor, SessionContext, SessionKillResult,
    SessionKind, SessionRestartPlan,
};

/// Shared test utilities for session sub-modules
#[cfg(test)]
pub(crate) mod tests_common {
    use super::types::SessionCommandExecutor;
    use crate::Result;
    use std::sync::Mutex;

    pub struct MockSessionCommandExecutor {
        pub systemctl_success: bool,
        pub loginctl_success: bool,
        pub loginctl_available: bool,
        pub kill_success: bool,
    }

    impl MockSessionCommandExecutor {
        pub fn new(
            systemctl_success: bool,
            loginctl_success: bool,
            loginctl_available: bool,
        ) -> Self {
            Self {
                systemctl_success,
                loginctl_success,
                loginctl_available,
                kill_success: true,
            }
        }
    }

    impl SessionCommandExecutor for MockSessionCommandExecutor {
        fn execute_systemctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
            Ok((self.systemctl_success, "active".to_string(), "".to_string()))
        }

        fn execute_loginctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
            Ok((self.loginctl_success, "".to_string(), "".to_string()))
        }

        fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
            Ok(self.kill_success)
        }

        fn loginctl_available(&self) -> bool {
            self.loginctl_available
        }
    }

    pub struct ScriptedSessionCommandExecutor {
        pub systemctl_responses: Mutex<Vec<Result<(bool, String, String)>>>,
        pub loginctl_responses: Mutex<Vec<Result<(bool, String, String)>>>,
        pub loginctl_available: bool,
        pub kill_success: bool,
    }

    impl ScriptedSessionCommandExecutor {
        pub fn new(
            systemctl_responses: Vec<Result<(bool, String, String)>>,
            loginctl_responses: Vec<Result<(bool, String, String)>>,
            loginctl_available: bool,
        ) -> Self {
            Self {
                systemctl_responses: Mutex::new(systemctl_responses),
                loginctl_responses: Mutex::new(loginctl_responses),
                loginctl_available,
                kill_success: true,
            }
        }
    }

    impl SessionCommandExecutor for ScriptedSessionCommandExecutor {
        fn execute_systemctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
            self.systemctl_responses
                .lock()
                .expect("session test mutex poisoned")
                .remove(0)
        }

        fn execute_loginctl(&self, _args: &[&str]) -> Result<(bool, String, String)> {
            self.loginctl_responses
                .lock()
                .expect("session test mutex poisoned")
                .remove(0)
        }

        fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
            Ok(self.kill_success)
        }

        fn loginctl_available(&self) -> bool {
            self.loginctl_available
        }
    }

    pub struct RecordingScriptedSessionCommandExecutor {
        pub systemctl_responses: Mutex<Vec<Result<(bool, String, String)>>>,
        pub loginctl_responses: Mutex<Vec<Result<(bool, String, String)>>>,
        pub systemctl_calls: Mutex<Vec<Vec<String>>>,
        pub loginctl_calls: Mutex<Vec<Vec<String>>>,
        pub loginctl_available: bool,
        pub kill_success: bool,
    }

    impl RecordingScriptedSessionCommandExecutor {
        pub fn new(
            systemctl_responses: Vec<Result<(bool, String, String)>>,
            loginctl_responses: Vec<Result<(bool, String, String)>>,
            loginctl_available: bool,
        ) -> Self {
            Self {
                systemctl_responses: Mutex::new(systemctl_responses),
                loginctl_responses: Mutex::new(loginctl_responses),
                systemctl_calls: Mutex::new(Vec::new()),
                loginctl_calls: Mutex::new(Vec::new()),
                loginctl_available,
                kill_success: true,
            }
        }

        pub fn systemctl_calls(&self) -> Vec<Vec<String>> {
            self.systemctl_calls
                .lock()
                .expect("session test mutex poisoned")
                .clone()
        }
    }

    impl SessionCommandExecutor for RecordingScriptedSessionCommandExecutor {
        fn execute_systemctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
            self.systemctl_calls
                .lock()
                .unwrap()
                .push(args.iter().map(|arg| arg.to_string()).collect());
            self.systemctl_responses
                .lock()
                .expect("session test mutex poisoned")
                .remove(0)
        }

        fn execute_loginctl(&self, args: &[&str]) -> Result<(bool, String, String)> {
            self.loginctl_calls
                .lock()
                .unwrap()
                .push(args.iter().map(|arg| arg.to_string()).collect());
            self.loginctl_responses
                .lock()
                .expect("session test mutex poisoned")
                .remove(0)
        }

        fn loginctl_available(&self) -> bool {
            self.loginctl_available
        }

        fn execute_kill(&self, _pid: u32, _signal: &str) -> Result<bool> {
            Ok(self.kill_success)
        }
    }

    pub fn clear_session_env() {
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
}
