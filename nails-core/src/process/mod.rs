//! Process Detection and Classification Module
//!
//! Provides shared process detection and classification for activation and deactivation.
//!
//! # Architecture
//!
//! This module implements the **Universal Overlay Mounting Strategy** documented in
//! `/docs/architecture/universal-overlay-mounting-strategy.md`.
//!
//! The module is designed for code reuse between Epic 4 (Activation) and Epic 5 (Deactivation):
//! - Detection and classification logic is identical
//! - Only the context (mounting vs unmounting) differs
//!
//! # Components
//!
//! - **Detection** (`detection.rs`): Parse `/proc` to find processes using target directories
//! - **Classification** (`classification.rs`): Classify processes by restart safety
//! - **Restart** (`restart.rs`): Stop and restart processes using systemd or signals
//! - **Session** (`session.rs`): Detect and manage graphical sessions for `--kill-session` flag
//!
//! # Example
//!
//! ```no_run
//! use nails_core::process::{detect_processes_using, classify_process, restart_processes, RestartStrategy};
//! use std::path::Path;
//!
//! // Detect processes using /home
//! let blocking = detect_processes_using(Path::new("/home"))?;
//!
//! // Classify and separate by restart strategy
//! let mut safe_to_restart = Vec::new();
//! for proc in blocking {
//!     if matches!(classify_process(&proc, Path::new("/home")), RestartStrategy::Safe) {
//!         safe_to_restart.push(proc);
//!     }
//! }
//!
//! // Restart safe processes
//! restart_processes(&safe_to_restart)?;
//! # Ok::<(), nails_core::NailsError>(())
//! ```

pub mod classification;
pub mod detection;
pub mod restart;
pub mod session;
pub mod shell_cleanup;

// Re-export public API
pub use classification::{RestartStrategy, classify_process};
pub use detection::{ProcessInfo, detect_processes_using};
pub use restart::{RestartMethod, RestartedProcess, restart_processes};
pub use session::{
    RealSessionCommandExecutor, SessionCommandExecutor, SessionContext, SessionKillResult,
    SessionKind, SessionRestartPlan, detect_session_context, detect_session_context_with_executor,
    kill_graphical_session, prompt_session_kill_confirmation, restart_display_manager,
    restart_user_manager,
};
pub use shell_cleanup::{ShellKillReport, kill_user_shells};

#[cfg(test)]
mod tests {
    #[test]
    fn test_module_compiles() {
        // Smoke test to verify process module compiles
    }
}
