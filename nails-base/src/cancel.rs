// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! Cooperative cancellation and signal survival for mutating operations.
//!
//! A mutating command (activate, discard) undoes a failed step on a normal
//! return or an unwind, such as the entry's rollback of a half-built next root.
//! A signal's *default* action terminates the process outright and skips that,
//! which can leave a populated `/run/nextroot` behind.
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
//!
//! A command that does not install these handlers keeps the default actions,
//! but may still have to answer a signal with something of its own:
//! [`watch_signals`] runs an action on a thread the first time SIGINT or
//! SIGTERM arrives (the CLI prints its cancel envelope under `--json` and
//! exits 130), and [`watched_signal_arrived`] tells every thread at once that
//! one did.
//!
//! ## A caller's cancel token
//!
//! A signal is not the only way an operation is asked to stop. A front end that
//! drives an activation over a pipe — a window talking to its root helper — must
//! cancel the activation if that pipe closes before the point of no return (the
//! window died; nobody is watching the switch), and must let it run on once the
//! switch has begun. [`CancelToken`] gives such a caller a handle it can trip,
//! on its own or from a [closed pipe](CancelToken::cancel_on_closed_pipe). An
//! installed token ([`CancelToken::install`]) is read by [`checkpoint`] exactly
//! as the signal flag is, so the before/after-the-point-of-no-return behaviour
//! is the same: the activation path checkpoints up to the last boundary before
//! the state is recorded, and nothing after it, so a trip before that boundary
//! unwinds through the rollback guards and a trip after it is never observed.

use std::io::Read;
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

/// Run `action` on a thread of its own the first time SIGINT or SIGTERM
/// arrives, in place of the signal's default action (ending the process).
///
/// For a command that never reads the cancel flag but must still answer a
/// signal with something of its own (under `--json`, the one cancel envelope
/// instead of an empty stdout). The handler only writes a byte to a socket, so
/// it is async-signal-safe; the watcher thread does the work. A signal after
/// the first one is ignored, so `action` decides whether the process ends.
///
/// The handler also sets the flag [`watched_signal_arrived`] reads, in the
/// handler itself, so a thread about to finish learns of the signal before
/// the watcher thread has woken.
///
/// Best-effort, like [`install_handlers`]: when the watcher cannot be set up,
/// a signal keeps its default action.
pub fn watch_signals(action: impl FnOnce() + Send + 'static) {
    use std::os::unix::net::UnixStream;
    let Ok((wake, mut watch)) = UnixStream::pair() else {
        return;
    };
    let Ok(wake_on_term) = wake.try_clone() else {
        return;
    };
    let spawned = std::thread::Builder::new()
        .name("signal-watch".to_string())
        .spawn(move || {
            // Only a handler writes here, and the write ends stay open for the
            // life of the process, so a read returns when a signal arrives.
            let mut byte = [0u8; 1];
            if matches!(watch.read(&mut byte), Ok(read) if read > 0) {
                action();
            }
        });
    if spawned.is_err() {
        return;
    }
    for (signal, wake) in [
        (signal_hook::consts::SIGINT, wake),
        (signal_hook::consts::SIGTERM, wake_on_term),
    ] {
        if let Err(err) = signal_hook::low_level::pipe::register(signal, wake) {
            tracing::warn!(
                signal,
                error = %err,
                "could not watch this signal; it keeps its default action"
            );
            continue;
        }
        // Without the flag the watcher thread still acts; only the early word
        // to the other threads is lost.
        let _ = signal_hook::flag::register(signal, Arc::clone(watched_flag()));
    }
}

/// The flag the handlers of [`watch_signals`] set when a signal arrives.
fn watched_flag() -> &'static Arc<AtomicBool> {
    static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    FLAG.get_or_init(|| Arc::new(AtomicBool::new(false)))
}

/// Whether a signal [`watch_signals`] watches has arrived. True from the
/// moment its handler ran, possibly before the watcher thread runs the action,
/// so a command that is about to report a result can tell that the signal
/// came first.
#[must_use]
pub fn watched_signal_arrived() -> bool {
    watched_flag().load(Ordering::SeqCst)
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

thread_local! {
    /// The caller's cancel token installed on this thread, if any. Thread-local
    /// for the same reason as the test override: an activation runs on its
    /// caller's thread, so only that thread's checkpoints observe the caller's
    /// token, and a token one operation installs never cancels another running
    /// in parallel. The flag behind it is an `Arc`, so a watcher thread (a
    /// closed-pipe watcher) can still trip it from outside.
    static CALLER_TOKEN: std::cell::RefCell<Option<Arc<AtomicBool>>> =
        const { std::cell::RefCell::new(None) };
}

fn caller_token_cancelled() -> bool {
    CALLER_TOKEN.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::SeqCst))
    })
}

/// Whether cancellation has been requested: by a signal (SIGINT or SIGTERM), or
/// by a [`CancelToken`] a caller installed on this thread.
#[must_use]
pub fn is_cancelled() -> bool {
    #[cfg(any(test, feature = "test-hooks"))]
    if TEST_CANCEL.with(std::cell::Cell::get) {
        return true;
    }
    cancel_flag().load(Ordering::SeqCst) || caller_token_cancelled()
}

/// A cancellation handle a caller can trip to stop a mutating operation at its
/// next [`checkpoint`], just as a SIGINT would.
///
/// Clones share one flag, so a background watcher (see
/// [`cancel_on_closed_pipe`](Self::cancel_on_closed_pipe)) can hold one clone
/// and trip the token while the operation holds another. A token takes effect
/// only while it is [installed](Self::install) on the thread the operation runs
/// on; the returned guard uninstalls it when dropped, so a later operation on
/// the same thread is not affected by a token left behind.
#[derive(Clone, Debug)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
}

impl CancelToken {
    /// A fresh, untripped token.
    #[must_use]
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Request cancellation. Idempotent: every later [`checkpoint`] on the
    /// thread this token is installed on then fails, as a received signal does.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Whether this token has been tripped.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Install this token on the current thread, so [`checkpoint`] and
    /// [`is_cancelled`] observe it until the returned guard is dropped. The
    /// signal flag is observed regardless; this only adds the caller's token.
    #[must_use = "the token is only installed while the guard is alive"]
    pub fn install(&self) -> CancelScope {
        let previous = CALLER_TOKEN.with(|slot| slot.borrow_mut().replace(Arc::clone(&self.flag)));
        CancelScope { previous }
    }

    /// Trip this token when `reader` reaches end of input, which a pipe does
    /// when its other end closes. Spawns a detached thread that blocks reading
    /// and returns at once; the thread trips the token on end-of-input or a
    /// read error and then exits. Any bytes that arrive first are read and
    /// discarded, so a control pipe may carry traffic without cancelling — only
    /// its close does. Combined with [`install`](Self::install), a window that
    /// dies before the point of no return cancels the activation; after it,
    /// there is no checkpoint left to observe the trip, so the switch goes on.
    pub fn cancel_on_closed_pipe<R: Read + Send + 'static>(&self, mut reader: R) {
        let flag = Arc::clone(&self.flag);
        std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => {
                        flag.store(true, Ordering::SeqCst);
                        return;
                    }
                    Ok(_) => {}
                }
            }
        });
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

/// Uninstalls the caller's cancel token from the current thread when dropped,
/// restoring whatever token was installed before.
#[must_use = "the token is only installed while the scope is alive"]
pub struct CancelScope {
    previous: Option<Arc<AtomicBool>>,
}

impl Drop for CancelScope {
    fn drop(&mut self) {
        let previous = self.previous.take();
        CALLER_TOKEN.with(|slot| *slot.borrow_mut() = previous);
    }
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

    #[test]
    fn an_installed_token_fails_the_checkpoint_only_once_tripped() {
        testing::reset();
        let token = CancelToken::new();
        let _scope = token.install();
        // Installed but untripped: the checkpoint still passes.
        assert!(checkpoint().is_ok());
        assert!(!is_cancelled());

        token.cancel();
        assert!(token.is_cancelled());
        assert!(is_cancelled());
        assert!(matches!(checkpoint(), Err(NailsError::Cancelled)));
    }

    #[test]
    fn the_token_is_forgotten_once_its_scope_ends() {
        testing::reset();
        let token = CancelToken::new();
        {
            let _scope = token.install();
            token.cancel();
            assert!(is_cancelled());
        }
        // The scope is dropped, so the thread no longer observes the token even
        // though the token itself is still tripped.
        assert!(token.is_cancelled());
        assert!(!is_cancelled());
        assert!(checkpoint().is_ok());
    }

    #[test]
    fn a_closed_pipe_trips_the_token() {
        use std::os::unix::net::UnixStream;

        testing::reset();
        let (writer, reader) = UnixStream::pair().expect("socket pair");
        let token = CancelToken::new();
        token.cancel_on_closed_pipe(reader);
        assert!(!token.is_cancelled());

        // Close the writing end: the watcher sees end-of-input and trips.
        drop(writer);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !token.is_cancelled() {
            assert!(std::time::Instant::now() < deadline, "token never tripped");
            std::thread::yield_now();
        }
    }

    #[test]
    fn traffic_on_the_pipe_does_not_cancel_before_it_closes() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        testing::reset();
        let (mut writer, reader) = UnixStream::pair().expect("socket pair");
        let token = CancelToken::new();
        token.cancel_on_closed_pipe(reader);

        writer.write_all(b"ping").expect("write");
        writer.flush().expect("flush");
        // A short window in which, had traffic been treated as a close, the
        // token would already be tripped.
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!token.is_cancelled());

        drop(writer);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !token.is_cancelled() {
            assert!(std::time::Instant::now() < deadline, "token never tripped");
            std::thread::yield_now();
        }
    }
}
