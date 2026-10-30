// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The window's emergency: the way out of a hidden session, on a path of its
//! own.
//!
//! The Emergency control fires on the window's thread, and firing waits for
//! nothing there: [`Emergency::fire`] sets a flag and wakes a thread that
//! started with the window, under the window's neutral name, and does the
//! rest, in this order:
//!
//! 1. **The engine's emergency**, through the helper, while a session with
//!    one is open. The thread writes the request onto the helper's pipe
//!    itself, beside whatever the worker waits for: under the lock the
//!    client writes its requests under, so it never lands inside one of
//!    them, and without waiting on a pipe the helper does not read. The
//!    request asks for a power-off, as every emergency of a hidden session
//!    ends. The helper takes it as soon as it reads its next request, runs
//!    the engine's hot path and powers off.
//! 2. **A power-off of the operator's own**, only when the helper never ran
//!    the engine's emergency: there is no helper, the request could not be
//!    written within the [grace](Fallback::grace) of the press, or the
//!    window still runs a grace after the request was written. The last
//!    happens only when the helper did not act on it: the engine's hot path
//!    ends every process of the hidden session, the window included, the
//!    helper's parent through pkexec as much as the launcher's. It is
//!    `systemctl poweroff`, which asks logind as a desktop's own Power Off
//!    does: the orderly power-off, slower than the engine's, but it needs
//!    neither root nor the helper.
//! 3. **The power button**, which the page names from the start: holding it
//!    switches the computer off, as on any computer.
//!
//! The worker opens the line once the handshake passed ([`Emergency::open`])
//! and closes it when the session is over ([`Emergency::close`]); an
//! emergency fired while the session still opens waits for it within the
//! grace. Nothing of the window delays any of it: not a worker stuck on its
//! request, not a question that is open, not updates the window has not
//! drawn yet.
//!
//! The emergency's request carries the id [`EMERGENCY_ID`], which no request
//! of the client's has: the client skips the frames that answer it.

use std::ffi::OsString;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, TryLockError};
use std::thread::Thread;
use std::time::{Duration, Instant};

use nails_api::protocol::{EmergencyArgs, Op, PROTOCOL_VERSION, Request};

/// The id of the window's emergency request. The client numbers its own
/// requests from 1.
pub const EMERGENCY_ID: u64 = 0;

/// How long the emergency waits for the helper (a session that still opens,
/// a client holding the pipe, or the engine's hot path ending the window)
/// before the power-off of the operator's own.
pub const HELPER_GRACE: Duration = Duration::from_secs(3);

/// How long `systemctl poweroff` may take before it is given up on.
pub const POWER_OFF_LIMIT: Duration = Duration::from_secs(10);

/// How often the emergency looks again at a lock or a pipe that was busy.
const POLL: Duration = Duration::from_millis(10);

/// Where `systemctl` is looked for: the system's directories, NixOS's first.
const SYSTEMCTL: [&str; 3] = [
    "/run/current-system/sw/bin/systemctl",
    "/usr/bin/systemctl",
    "/bin/systemctl",
];

/// What the emergency did, as its thread reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The request reached the helper's pipe.
    HelperAsked,
    /// The system was asked to power off.
    PowerOffAsked,
    /// The system could not be asked: only the power button is left.
    PowerOffFailed,
}

/// The power-off of the operator's own, and how long the emergency waits for
/// the helper before it.
#[derive(Debug, Clone)]
pub struct Fallback {
    /// The program that asks for the power-off, `None` when none was found.
    pub program: Option<PathBuf>,
    /// Its arguments.
    pub args: Vec<OsString>,
    /// How long the helper is waited for.
    pub grace: Duration,
    /// How long the program may run.
    pub limit: Duration,
}

impl Fallback {
    /// `systemctl poweroff`, without a password prompt: logind lets the
    /// person at the computer power it off.
    #[must_use]
    pub fn system() -> Self {
        let program = SYSTEMCTL
            .iter()
            .map(Path::new)
            .find(|path| path.is_file())
            .map(Path::to_path_buf);
        Self {
            program,
            args: vec!["poweroff".into(), "--no-ask-password".into()],
            grace: HELPER_GRACE,
            limit: POWER_OFF_LIMIT,
        }
    }
}

/// The helper's pipe as the emergency writes to it: another handle on the
/// window's end, and the lock the client writes its requests under.
#[derive(Debug)]
pub struct HelperLine {
    /// The window's end of the pipe.
    pub stream: UnixStream,
    /// Held by the client while it writes a request.
    pub writes: Arc<Mutex<()>>,
}

/// How far the session with the helper is.
#[derive(Debug)]
enum Line {
    /// It still opens.
    Opening,
    /// It is open, on this line.
    Open(HelperLine),
    /// There is none any more, or never was.
    Closed,
}

struct Shared {
    fired: AtomicBool,
    line: Mutex<Line>,
    changed: Condvar,
}

impl Shared {
    fn line(&self) -> MutexGuard<'_, Line> {
        self.line.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The window's emergency. Clones share it: it fires once.
#[derive(Clone)]
pub struct Emergency {
    shared: Arc<Shared>,
    thread: Option<Thread>,
}

impl Emergency {
    /// Start the emergency's thread, which waits until it fires and then
    /// takes the path of the module's doc, telling `report` each step.
    pub fn start(fallback: Fallback, report: impl Fn(Outcome) + Send + 'static) -> Self {
        let shared = Arc::new(Shared {
            fired: AtomicBool::new(false),
            line: Mutex::new(Line::Opening),
            changed: Condvar::new(),
        });
        let theirs = Arc::clone(&shared);
        // No name of its own: the thread keeps the one of the thread that
        // starts it, the window's neutral name, which a list of threads shows.
        let thread = std::thread::Builder::new()
            .spawn(move || run(&theirs, &fallback, &report))
            .ok()
            .map(|handle| handle.thread().clone());
        Self { shared, thread }
    }

    /// Fire the emergency: true the one time it fires. It only sets a flag
    /// and wakes the emergency's thread, so it never waits.
    pub fn fire(&self) -> bool {
        if self.shared.fired.swap(true, Ordering::SeqCst) {
            return false;
        }
        if let Some(thread) = &self.thread {
            thread.unpark();
        }
        true
    }

    /// Whether it has fired.
    #[must_use]
    pub fn fired(&self) -> bool {
        self.shared.fired.load(Ordering::SeqCst)
    }

    /// The session with the helper is open on `line`.
    pub fn open(&self, line: HelperLine) {
        let mut state = self.shared.line();
        if matches!(*state, Line::Opening) {
            *state = Line::Open(line);
        }
        self.shared.changed.notify_all();
    }

    /// The session with the helper is over, or never opened.
    pub fn close(&self) {
        *self.shared.line() = Line::Closed;
        self.shared.changed.notify_all();
    }
}

fn run(shared: &Shared, fallback: &Fallback, report: &dyn Fn(Outcome)) {
    while !shared.fired.load(Ordering::SeqCst) {
        std::thread::park();
    }
    let deadline = Instant::now() + fallback.grace;
    if ask_helper(shared, deadline) {
        report(Outcome::HelperAsked);
        // The engine's emergency enqueues the power-off and ends every
        // program of the session, this window included, whether the
        // launcher started it or it started its helper through pkexec. A
        // window still here a grace after the request means the helper
        // never ran it: the window asks for the power-off itself.
        std::thread::sleep(fallback.grace);
    }
    report(if power_off(fallback) {
        Outcome::PowerOffAsked
    } else {
        Outcome::PowerOffFailed
    });
}

/// Write the emergency request onto the helper's pipe by `deadline`,
/// waiting within it for a session that still opens: true once it is
/// written whole.
fn ask_helper(shared: &Shared, deadline: Instant) -> bool {
    let mut state = shared.line();
    let line = loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match &*state {
            Line::Open(line) => match line.stream.try_clone() {
                Ok(stream) => {
                    break HelperLine {
                        stream,
                        writes: Arc::clone(&line.writes),
                    };
                }
                Err(_) => return false,
            },
            Line::Closed => return false,
            Line::Opening if left.is_zero() => return false,
            Line::Opening => {}
        }
        state = shared
            .changed
            .wait_timeout(state, left)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    };
    drop(state);
    send(&line, &request_line(), deadline)
}

/// The emergency request, as one line with its newline.
#[must_use]
pub fn request_line() -> Vec<u8> {
    let request = Request {
        v: PROTOCOL_VERSION,
        id: EMERGENCY_ID,
        op: Op::Emergency(EmergencyArgs {
            poweroff: true,
            reboot: false,
        }),
    };
    let mut line = request.to_line().into_bytes();
    line.push(b'\n');
    line
}

/// Write `bytes` onto `line` by `deadline`: under the client's lock, which
/// it waits for only so long, and without waiting on a full pipe.
fn send(line: &HelperLine, bytes: &[u8], deadline: Instant) -> bool {
    use rustix::io::Errno;
    use rustix::net::SendFlags;
    let _writes = loop {
        match line.writes.try_lock() {
            Ok(guard) => break guard,
            Err(TryLockError::Poisoned(poisoned)) => break poisoned.into_inner(),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(POLL);
            }
            Err(TryLockError::WouldBlock) => return false,
        }
    };
    let mut sent = 0;
    while sent < bytes.len() {
        match rustix::net::send(
            &line.stream,
            &bytes[sent..],
            SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
        ) {
            Ok(n) => sent += n,
            Err(Errno::AGAIN | Errno::INTR) if Instant::now() < deadline => {
                std::thread::sleep(POLL);
            }
            Err(_) => return false,
        }
    }
    true
}

/// Ask the system to power off with `fallback`'s program, waiting at most
/// its limit: true when it said yes.
fn power_off(fallback: &Fallback) -> bool {
    let Some(program) = &fallback.program else {
        return false;
    };
    let Ok(mut child) = Command::new(program)
        .args(&fallback.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + fallback.limit;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

#[cfg(test)]
#[path = "emergency_tests.rs"]
mod tests;
