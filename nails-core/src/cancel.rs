// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Cooperative cancellation and signal survival for mutating operations.
//!
//! A mutating command (activate, deactivate, reapply, emergency, reset-upper)
//! tears the system down and back up through a chain of RAII guards —
//! [`StateGuard`](crate::StateGuard), the overlay mount rollback, the
//! session-restart and nix-daemon guards. Those guards only run on a normal
//! return or an unwind; a signal's *default* action terminates the process
//! outright and skips every one of them, which can leave overlays half-mounted,
//! the nix-daemon stopped, the session not restarted and the state file still
//! reading `Activating`.
//!
//! This module replaces those default actions with handlers that keep the
//! process alive long enough to roll back cleanly:
//!
//! * **SIGINT / SIGTERM** set a process-wide flag. The activation path calls
//!   [`checkpoint`] at each step boundary; when the flag is set it returns
//!   [`NailsError::Cancelled`], the `?` propagates, and the existing guards run
//!   in order — the overlays come down, then the state is written back to its
//!   previous value (`Inactive`), then the session is restored. Cancellation is
//!   therefore *cooperative*: it never interrupts a syscall mid-flight, and in
//!   particular never interrupts a `switch-to-configuration` that has already
//!   begun. Teardown paths (deactivation, emergency) deliberately never call
//!   [`checkpoint`], so once they start the same handler merely keeps the
//!   process alive and the teardown always runs to completion — the fail-safe
//!   direction is toward `Inactive`.
//!
//! * **SIGHUP** is caught and ignored. An SSH disconnect or a closed terminal
//!   sends SIGHUP, whose default action is also to terminate; catching it lets a
//!   foreground activation run to completion after the operator's terminal goes
//!   away. SIGHUP never cancels.
//!
//! SIGKILL and power loss remain out of scope by design — no handler can run for
//! them — and are covered instead by state reconciliation on the next run.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};

use crate::{NailsError, Result};

/// The process-wide cancel flag, shared with the installed signal handlers.
///
/// Behind a [`OnceLock`] because `signal_hook::flag::register` takes ownership of
/// an `Arc<AtomicBool>`; the handler holds one clone and the rest of the process
/// reads through this one. Initialised to `false`.
fn cancel_flag() -> &'static Arc<AtomicBool> {
    static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    FLAG.get_or_init(|| Arc::new(AtomicBool::new(false)))
}

/// Guards [`install_handlers`] so the registration runs exactly once even if a
/// command dispatcher (or several tests) call it repeatedly.
static INSTALL_ONCE: Once = Once::new();

/// Install the signal handlers for a mutating command.
///
/// Registers SIGINT and SIGTERM to set the cancel flag and SIGHUP to be caught
/// and ignored. Idempotent and process-wide: the first call wins and later calls
/// are no-ops, so it is safe to call from every mutating command's dispatch.
///
/// Registration is best-effort. A failure to install a handler leaves that
/// signal's default action in place (termination) rather than aborting the
/// command; it is logged and otherwise ignored, because an operation that cannot
/// install a handler is no worse off than one built before this module existed.
pub fn install_handlers() {
    INSTALL_ONCE.call_once(|| {
        for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
            if let Err(err) = signal_hook::flag::register(signal, Arc::clone(cancel_flag())) {
                tracing::warn!(
                    signal,
                    error = %err,
                    "could not install cancellation handler; this signal keeps its default action"
                );
            }
        }

        // Catch SIGHUP into a sink flag we never read: the point is only to
        // replace the default terminate action so a terminal hangup does not kill
        // an in-flight operation. A dedicated flag keeps the hangup entirely
        // decoupled from cancellation.
        let hangup_sink = Arc::new(AtomicBool::new(false));
        if let Err(err) = signal_hook::flag::register(signal_hook::consts::SIGHUP, hangup_sink) {
            tracing::warn!(
                error = %err,
                "could not install SIGHUP handler; a terminal hangup may still abort the operation"
            );
        }
    });
}

// A thread-local cancellation override for tests.
//
// The process-global flag that signal handlers set is shared by every thread, so
// a test that armed it would also cancel activations running in parallel on other
// test threads. Tests therefore arm *this* thread-local instead: an activation
// runs synchronously on its caller's thread, so a unit test sees its own override
// while parallel tests are unaffected. The real signal path is unchanged — a
// delivered SIGINT/SIGTERM still sets the global flag that every thread observes,
// which is what the E2E suite exercises.
#[cfg(any(test, feature = "test-hooks"))]
thread_local! {
    static TEST_CANCEL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether a cancel signal (SIGINT or SIGTERM) has been received.
#[must_use]
pub fn is_cancelled() -> bool {
    #[cfg(any(test, feature = "test-hooks"))]
    if TEST_CANCEL.with(std::cell::Cell::get) {
        return true;
    }
    cancel_flag().load(Ordering::SeqCst)
}

/// Fail the current operation if cancellation has been requested.
///
/// Called at each activation step boundary. Returns [`NailsError::Cancelled`]
/// when a cancel signal has arrived so the caller's `?` unwinds through the RAII
/// rollback guards, and `Ok(())` otherwise. It deliberately does not clear the
/// flag: once cancellation is requested every subsequent checkpoint must also
/// fail, so the whole remaining chain unwinds rather than only the first step.
pub fn checkpoint() -> Result<()> {
    if is_cancelled() {
        Err(NailsError::Cancelled)
    } else {
        Ok(())
    }
}

/// Test-only controls for the cancel flag.
///
/// Exposed to this crate's own unit tests (`cfg(test)`) and to downstream test
/// code through the `test-hooks` feature, so an activation test can arm the flag
/// before a step and clear it again afterwards. Never compiled into a shipped
/// binary.
#[cfg(any(test, feature = "test-hooks"))]
pub mod testing {
    use super::TEST_CANCEL;

    /// Arm cancellation for the current thread, as a SIGINT/SIGTERM handler would
    /// for the whole process. Thread-local so it never cancels activations running
    /// in parallel on other test threads.
    pub fn request() {
        TEST_CANCEL.with(|flag| flag.set(true));
    }

    /// Clear the current thread's cancellation override.
    pub fn reset() {
        TEST_CANCEL.with(|flag| flag.set(false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_is_ok_when_not_cancelled() {
        testing::reset();
        assert!(!is_cancelled());
        assert!(checkpoint().is_ok());
    }

    #[test]
    fn checkpoint_returns_cancelled_when_flag_is_set() {
        testing::request();
        assert!(is_cancelled());
        assert!(matches!(checkpoint(), Err(NailsError::Cancelled)));
        testing::reset();
        assert!(checkpoint().is_ok());
    }

    #[test]
    fn install_handlers_is_idempotent() {
        // Two calls must not panic or double-register; the Once guard makes the
        // second a no-op. We cannot easily observe the registration itself here,
        // so this guards against a regression that would make the call fail.
        install_handlers();
        install_handlers();
    }
}
