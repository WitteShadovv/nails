// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Session Management Logic
//!
//! Handles killing and restarting graphical sessions during activation.

use crate::{
    Filesystem, NailsManager, Result, Verbosity,
    process::{
        SessionCommandExecutor, SessionKind, SessionRestartPlan, detect_session_context,
        kill_graphical_session, prompt_session_kill_confirmation,
    },
};

impl<F: Filesystem> NailsManager<F> {
    /// Handle the `--session kill` flag, running every probe and termination
    /// command through the injected `executor`.
    ///
    /// Kills the graphical session only after pre-flight checks succeed.
    /// Production passes
    /// [`RealSessionCommandExecutor`](crate::RealSessionCommandExecutor); tests
    /// pass a scripted or recording executor, so the real graphical-kill arm is
    /// exercised directly rather than through a separate test-only copy.
    pub(super) fn handle_session_kill<E: SessionCommandExecutor>(
        verbosity: Verbosity,
        options: &crate::ActivateOptions,
        executor: &E,
    ) -> Result<SessionRestartPlan> {
        if !options.kill_session {
            return Ok(SessionRestartPlan::default());
        }

        if verbosity >= Verbosity::Normal {
            tracing::info!("Detecting session type for --session kill...");
        }

        let session = detect_session_context(executor)?;

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

                let kill_result = kill_graphical_session(&session, executor)?;

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
                    tracing::warn!("--session kill requested, but running in TTY - skipping");
                }
                Ok(SessionRestartPlan::default())
            }
            SessionKind::Ssh => {
                if verbosity >= Verbosity::Normal {
                    tracing::warn!(
                        "--session kill requested over SSH - skipping session termination"
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
    use crate::process::session::tests_common::{
        RecordingScriptedSessionCommandExecutor, cleared_session_env,
    };
    use crate::{ActivateOptions, MockFilesystem};

    /// An executor whose probes report no active service and no logind, so a
    /// detected session is driven entirely by the environment variables a test
    /// sets.
    fn quiet_executor() -> RecordingScriptedSessionCommandExecutor {
        RecordingScriptedSessionCommandExecutor::new(Vec::new(), Vec::new(), false)
    }

    #[test]
    fn handle_session_kill_returns_default_plan_when_disabled() {
        let options = ActivateOptions {
            kill_session: false,
            ..ActivateOptions::default()
        };
        let executor = quiet_executor();

        let plan = NailsManager::<MockFilesystem>::handle_session_kill(
            Verbosity::Quiet,
            &options,
            &executor,
        )
        .unwrap();

        assert_eq!(plan, SessionRestartPlan::default());
        // A disabled flag short-circuits before any detection command runs.
        assert!(executor.systemctl_calls().is_empty());
    }

    #[test]
    fn handle_session_kill_skips_ssh_sessions() {
        let mut env = cleared_session_env();
        env.set("SSH_CONNECTION", "1 2 3 4")
            .set("NAILS_LOGIND_AVAILABLE", "0");

        let options = ActivateOptions {
            kill_session: true,
            yes: true,
            ..ActivateOptions::default()
        };
        let executor = quiet_executor();

        let plan = NailsManager::<MockFilesystem>::handle_session_kill(
            Verbosity::Normal,
            &options,
            &executor,
        )
        .unwrap();

        assert_eq!(plan, SessionRestartPlan::default());
    }

    #[test]
    fn handle_session_kill_skips_tty_sessions() {
        let mut env = cleared_session_env();
        env.set("XDG_SESSION_TYPE", "tty")
            .set("NAILS_LOGIND_AVAILABLE", "0");

        let options = ActivateOptions {
            kill_session: true,
            yes: true,
            ..ActivateOptions::default()
        };
        let executor = quiet_executor();

        let plan = NailsManager::<MockFilesystem>::handle_session_kill(
            Verbosity::Normal,
            &options,
            &executor,
        )
        .unwrap();

        assert_eq!(plan, SessionRestartPlan::default());
    }

    #[test]
    fn handle_session_kill_drives_the_real_graphical_arm() {
        // A graphical session with a known operator is forced through the
        // pre-detach override environment, so detection reports GraphicalUser
        // without touching the host.
        let mut env = cleared_session_env();
        env.set("DISPLAY", ":0")
            .set("NAILS_TARGET_UID", "1000")
            .set("NAILS_DISPLAY_MANAGER", "gdm.service")
            .set("NAILS_LOGIND_AVAILABLE", "1");

        let options = ActivateOptions {
            kill_session: true,
            yes: true,
            session_kill_confirmed: true,
            ..ActivateOptions::default()
        };
        let executor = quiet_executor();

        // The graphical arm now reaches the real `kill_graphical_session` through
        // the injected executor rather than a test-only stub. Running unprivileged,
        // that function fails its root check before issuing any termination
        // command, which is exactly the real production guard.
        let result = NailsManager::<MockFilesystem>::handle_session_kill(
            Verbosity::Normal,
            &options,
            &executor,
        );

        let err = result.expect_err("the unprivileged graphical arm must hit the root guard");
        assert!(
            err.to_string().contains("root privileges"),
            "expected the real session-kill root guard, got: {err}"
        );
    }
}
