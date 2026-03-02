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
}
