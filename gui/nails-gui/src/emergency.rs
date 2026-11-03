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
//!    request asks for the [`Finish`] the emergency fired with, the ending
//!    `nails emergency` takes from its flags: the way back to the decoy's
//!    login screen, a power-off or a full reboot. The helper takes it as
//!    soon as it reads its next request and runs the engine's hot path,
//!    which ends the session so.
//! 2. **A power-off of the operator's own**, whatever the finish, where the
//!    helper did not end the session in time: there is no helper, the
//!    request could not be written within the [grace](Fallback::grace) of
//!    the press, or the window still runs a grace after the request was
//!    written. The engine's hot path ends every process of the hidden
//!    session, the window included, the helper's parent through pkexec as
//!    much as the launcher's, whichever way it ends the session, so a window
//!    still running then means the helper did not act on the request within
//!    the grace: it was still on another request (a verify or a scan can
//!    take minutes, and the window fires with the power-off then), or the
//!    steps of a return or a restart before the kill took longer. A
//!    power-off fired [at once](Firing::POWER_OFF_AT_ONCE) does not wait the
//!    grace: the window fires so while a deactivation returns to the decoy.
//!    The helper reads the request only once it has answered that
//!    deactivation's apply, and the switch the apply starts ends the window
//!    and the helper with the session, so a window that waited would not be
//!    there to ask, and the request might never be read. A return that
//!    logind holds already may still come first. It is `systemctl
//!    poweroff`, which asks logind as a desktop's own Power Off does: the
//!    orderly power-off, slower than the engine's, but it needs neither root
//!    nor the helper. Without the helper the window has no way back to the
//!    decoy, so this is always a power-off.
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
//! of the client's has: the client skips the frames that answer it. The
//! finish, and whether the power-off follows at once, are the window's to
//! know when the person completes the gesture ([`Emergency::fire`]): the
//! thread learns them with the signal, and asks nothing of anyone for them.

use std::ffi::OsString;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU8, Ordering};
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

/// How the engine's emergency ends the hidden session, as the request asks
/// for it: the ending of `nails emergency`, `--poweroff` and `--reboot`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Finish {
    /// The way back to the decoy's login screen.
    Return,
    /// A power-off: RAM decays, the strongest ending, and the only one the
    /// window has of its own.
    PowerOff,
    /// A full reboot, through the firmware.
    Reboot,
}

impl Finish {
    /// The arguments of the engine's emergency that ends so.
    #[must_use]
    pub fn args(self) -> EmergencyArgs {
        EmergencyArgs {
            poweroff: self == Finish::PowerOff,
            reboot: self == Finish::Reboot,
        }
    }

    /// The finish as the emergency's flag holds it: never 0, which is the
    /// flag before it fired.
    fn code(self) -> u8 {
        match self {
            Finish::Return => 1,
            Finish::PowerOff => 2,
            Finish::Reboot => 3,
        }
    }

    /// The finish of a flag that fired; a power-off for any other value.
    fn of_code(code: u8) -> Self {
        match code {
            1 => Finish::Return,
            3 => Finish::Reboot,
            _ => Finish::PowerOff,
        }
    }
}

/// How the emergency fired: the [`Finish`] its request asks for, and whether
/// the window's own power-off follows the request at once rather than a
/// grace after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Firing {
    finish: Finish,
    at_once: bool,
}

impl Firing {
    /// A power-off the window also asks for itself, right after the request:
    /// where the helper reads the request only after a switch that ends the
    /// window with the session, a window that waited the grace would not be
    /// there to ask.
    pub const POWER_OFF_AT_ONCE: Self = Self {
        finish: Finish::PowerOff,
        at_once: true,
    };

    /// The finish the request asks for.
    #[must_use]
    pub fn finish(self) -> Finish {
        self.finish
    }

    /// Whether the window's own power-off follows the request at once.
    #[must_use]
    pub fn at_once(self) -> bool {
        self.at_once
    }

    /// The firing as the emergency's flag holds it: never [`NOT_FIRED`].
    fn code(self) -> u8 {
        if self.at_once {
            AT_ONCE
        } else {
            self.finish.code()
        }
    }

    /// The firing of a flag that fired.
    fn of_code(code: u8) -> Self {
        if code == AT_ONCE {
            Self::POWER_OFF_AT_ONCE
        } else {
            Finish::of_code(code).into()
        }
    }
}

impl From<Finish> for Firing {
    /// `finish`, with the window's own power-off a grace after the request.
    fn from(finish: Finish) -> Self {
        Self {
            finish,
            at_once: false,
        }
    }
}

/// The emergency's flag before it fired.
const NOT_FIRED: u8 = 0;

/// The emergency's flag once it fired [to power off at
/// once](Firing::POWER_OFF_AT_ONCE); the [finishes](Finish::code) have the
/// values below it.
const AT_ONCE: u8 = 4;

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
    /// [`NOT_FIRED`], then the [code](Firing::code) of how it fired: one
    /// flag, so the finish is set with the firing and never after.
    fired: AtomicU8,
    line: Mutex<Line>,
    changed: Condvar,
}

impl Shared {
    fn line(&self) -> MutexGuard<'_, Line> {
        self.line.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// How it fired, once it fired.
    fn fired(&self) -> Option<Firing> {
        match self.fired.load(Ordering::SeqCst) {
            NOT_FIRED => None,
            code => Some(Firing::of_code(code)),
        }
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
            fired: AtomicU8::new(NOT_FIRED),
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

    /// Fire the emergency to end the session as `firing` says: with a
    /// [`Finish`], or with a power-off [at once](Firing::POWER_OFF_AT_ONCE).
    /// True the one time it fires, and only that firing counts. It only sets
    /// a flag and wakes the emergency's thread, so it never waits.
    pub fn fire(&self, firing: impl Into<Firing>) -> bool {
        let firing = firing.into();
        if self
            .shared
            .fired
            .compare_exchange(NOT_FIRED, firing.code(), Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
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
        self.shared.fired().is_some()
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
    let firing = loop {
        match shared.fired() {
            Some(firing) => break firing,
            None => std::thread::park(),
        }
    };
    let deadline = Instant::now() + fallback.grace;
    if ask_helper(shared, deadline, firing.finish) {
        report(Outcome::HelperAsked);
        // The engine's emergency enqueues the way back or the power action
        // and ends every program of the session, this window included,
        // whether the launcher started it or it started its helper through
        // pkexec. A window still here a grace after the request means the
        // helper did not run it within the grace: the window asks for the
        // power-off itself. Fired at once, it asks now: the switch the helper
        // finishes first would end this window within the grace.
        if !firing.at_once {
            std::thread::sleep(fallback.grace);
        }
    }
    report(if power_off(fallback) {
        Outcome::PowerOffAsked
    } else {
        Outcome::PowerOffFailed
    });
}

/// Write the emergency request for `finish` onto the helper's pipe by
/// `deadline`, waiting within it for a session that still opens: true once
/// it is written whole.
fn ask_helper(shared: &Shared, deadline: Instant, finish: Finish) -> bool {
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
    send(&line, &request_line(finish), deadline)
}

/// The emergency request that ends the session with `finish`, as one line
/// with its newline.
#[must_use]
pub fn request_line(finish: Finish) -> Vec<u8> {
    let request = Request {
        v: PROTOCOL_VERSION,
        id: EMERGENCY_ID,
        op: Op::Emergency(finish.args()),
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
