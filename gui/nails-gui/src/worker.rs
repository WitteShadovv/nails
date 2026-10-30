// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-only

//! The client on a thread of its own.
//!
//! The window never waits on the pipe: it hands each request to the worker
//! as an [`Ask`] and hears back through [`Update`]s, which the window turns
//! into its page on its own thread. The worker sends one request at a time
//! and reads the next ask only once the last one is answered, so the order
//! of the protocol holds by construction.
//!
//! A plan stays with the worker: the window hears what it would do
//! ([`Update::Planned`]) and answers with [`Ask::Apply`] or
//! [`Ask::Withdraw`]. A withdrawn plan is dropped at once with a status
//! request, which also releases whatever the helper held for it (the state
//! lock of an activation or a discard).
//!
//! While a request runs the worker waits on the pipe, so the window cannot
//! reach the helper through it; [`HangUp`] is how it still can: it shuts the
//! window's writing half of the pipe, which cancels an activation before its
//! point of no return. The worker reads the answer that follows and ends.
//! The window's emergency does not go through the worker at all: the worker
//! only hands it the pipe once the handshake passed, and takes it back when
//! the session is over ([`crate::emergency`]). Once the emergency fired, the
//! worker sends no request more.

use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use nails_api::Event;
use nails_api::protocol::{CheckArgs, Hello, Op, ProtocolError};

use crate::client::{Answer, Client, ClientError, Plan, PlanAnswer, PlanData, Planned};
use crate::emergency::Emergency;
use crate::launch::{PkexecEnd, pkexec_end, start_helper};

/// What the window asks the worker to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ask {
    /// `nails status`.
    Status,
    /// `nails check`, with each check sent as it finishes.
    Check(CheckArgs),
    /// `nails recover`: the window's Clean Up and Reset Record.
    Recover,
    /// The plan of an operation the engine confirms first.
    Plan(Plan),
    /// Apply the plan that waits.
    Apply,
    /// Drop the plan that waits.
    Withdraw,
}

/// The request an answer belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// [`Ask::Status`].
    Status,
    /// [`Ask::Check`].
    Check,
    /// [`Ask::Recover`].
    Recover,
    /// [`Ask::Plan`].
    Plan,
    /// [`Ask::Apply`].
    Apply,
}

/// What the worker reports to the window.
#[derive(Debug, Clone, PartialEq)]
pub enum Update {
    /// The handshake passed: the helper of this release is listening.
    Connected(Hello),
    /// A request went out.
    Running(Kind),
    /// An event of the request that runs.
    Event(Event),
    /// A request was answered.
    Answered(Kind, Answer),
    /// A plan holds, and waits for [`Ask::Apply`] or [`Ask::Withdraw`].
    Planned(PlanData),
    /// The plan waiting was withdrawn before its apply.
    Withdrawn,
    /// The session is over.
    Ended(Failure),
}

/// Why the session is over.
#[derive(Debug, Clone, PartialEq)]
pub enum Failure {
    /// The helper is of another release or protocol.
    Mismatch {
        /// The window's versions.
        window: Hello,
        /// The helper's.
        engine: Hello,
    },
    /// The helper refused a request.
    Refused(ProtocolError),
    /// The pipe closed; `in_flight` when a request was waiting for its answer.
    Lost {
        /// Whether a request was waiting for its answer.
        in_flight: bool,
    },
    /// The pipe carried something the window cannot read.
    Unreadable(String),
    /// The person closed pkexec's password dialog.
    PasswordDismissed,
    /// pkexec could not ask for the password, or the password was refused.
    PasswordUnavailable,
    /// The helper could not be started.
    NotStarted(String),
}

impl Failure {
    fn from_error(error: ClientError, in_flight: bool) -> Self {
        match error {
            ClientError::Mismatch { window, engine } => Failure::Mismatch { window, engine },
            ClientError::Refused(error) => Failure::Refused(error),
            ClientError::Closed => Failure::Lost { in_flight },
            ClientError::Broken(why) => Failure::Unreadable(why),
            ClientError::PlanWithdrawn => Failure::Unreadable("a plan out of step".to_string()),
        }
    }
}

/// How the worker opens its session.
#[derive(Debug)]
pub enum Connect {
    /// On a stream already connected to a helper (the launcher's pair, or a
    /// test's).
    Stream(UnixStream),
    /// On the helper pkexec was started for ([`Connect::pkexec`]).
    Pkexec {
        /// pkexec, which becomes the helper once the password is given.
        child: Child,
        /// The window's end of the pair.
        stream: UnixStream,
    },
    /// pkexec could not be started, for this reason.
    NotStarted(String),
}

impl Connect {
    /// Start `engine helper --stdio` through `pkexec` on the calling thread,
    /// before the worker exists: the window does this before it sets
    /// `no_new_privs`, under which `execve` ignores pkexec's set-user-ID bit
    /// and pkexec never becomes root. `pkexec` is the program
    /// [`crate::launch::find_pkexec`] found, or why it found none.
    #[must_use]
    pub fn pkexec(pkexec: Result<PathBuf, String>, engine: &Path) -> Self {
        let started = pkexec.and_then(|program| {
            start_helper(&program, engine)
                .map_err(|error| format!("pkexec could not be started: {error}"))
        });
        match started {
            Ok((child, stream)) => Connect::Pkexec { child, stream },
            Err(why) => Connect::NotStarted(why),
        }
    }
}

/// The window's way to hang up on its helper, whatever the worker waits on.
///
/// It shuts the writing half of the window's end of the pipe. The helper
/// reads that as the window gone: an activation's apply short of its point
/// of no return unwinds, as a Ctrl+C would, and once the helper has answered
/// it ends its session. The window still reads that answer, since only its
/// writing half is shut. Before the session opens, and after it ended, it
/// does nothing.
#[derive(Clone, Default)]
pub struct HangUp(Arc<Mutex<Line>>);

#[derive(Default)]
struct Line {
    /// Another handle on the window's end of the pipe, while the session is
    /// open.
    stream: Option<UnixStream>,
    /// Whether the window hung up.
    hung_up: bool,
}

impl HangUp {
    /// Hang up; true the one time it did.
    pub fn hang_up(&self) -> bool {
        let mut line = self.line();
        if line.hung_up {
            return false;
        }
        let shut = line
            .stream
            .as_ref()
            .is_some_and(|stream| stream.shutdown(std::net::Shutdown::Write).is_ok());
        line.hung_up = shut;
        shut
    }

    fn line(&self) -> MutexGuard<'_, Line> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn open(&self, stream: UnixStream) {
        self.line().stream = Some(stream);
    }

    fn close(&self) {
        self.line().stream = None;
    }

    fn hung_up(&self) -> bool {
        self.line().hung_up
    }
}

/// A running worker: where the window's asks go, and its way to hang up.
pub struct Worker {
    asks: Sender<Ask>,
    hang_up: HangUp,
}

impl Worker {
    /// Hand the worker `ask`; false once the worker is gone.
    pub fn ask(&self, ask: Ask) -> bool {
        self.asks.send(ask).is_ok()
    }

    /// The handle that hangs up on the helper.
    #[must_use]
    pub fn hang_up(&self) -> HangUp {
        self.hang_up.clone()
    }
}

/// Start the worker: open the session with `connect`, then serve the window's
/// asks, reporting through `report`, and hand `emergency`, if any, the pipe
/// while the session is open. The worker ends when the returned [`Worker`] is
/// dropped, when the session is over, and once the answer that a hang-up
/// waited for came.
pub fn spawn(
    connect: Connect,
    emergency: Option<Emergency>,
    report: impl Fn(Update) + Send + 'static,
) -> Worker {
    let (asks, inbox) = channel();
    let hang_up = HangUp::default();
    let line = hang_up.clone();
    std::thread::spawn(move || {
        run(connect, &inbox, &line, emergency.as_ref(), &report);
        if let Some(emergency) = &emergency {
            emergency.close();
        }
    });
    Worker { asks, hang_up }
}

fn run(
    connect: Connect,
    inbox: &Receiver<Ask>,
    line: &HangUp,
    emergency: Option<&Emergency>,
    report: &dyn Fn(Update),
) {
    let (mut client, mut pkexec) = match open(connect) {
        Ok(opened) => opened,
        Err(failure) => {
            report(Update::Ended(failure));
            return;
        }
    };
    if let Ok(stream) = client.hang_up_handle() {
        line.open(stream);
    }
    if let Some(emergency) = emergency {
        match client.emergency_line() {
            Ok(helper) => emergency.open(helper),
            Err(_) => emergency.close(),
        }
    }
    report(Update::Connected(client.engine().clone()));
    let mut planned: Option<Planned> = None;
    while let Ok(ask) = inbox.recv() {
        if emergency.is_some_and(Emergency::fired) {
            // The emergency's request is the session's last word.
            continue;
        }
        let served = serve(&mut client, ask, &mut planned, report);
        let hung_up = line.hung_up();
        match served {
            // The window hung up: the answer it waited for was the last.
            Ok(()) if hung_up => break,
            Ok(()) => {}
            // A refused token, or a plan withdrawn in between: the plan is
            // gone, the session goes on.
            Err(error) if !error.ends_session() && !hung_up => report(Update::Withdrawn),
            Err(error) => {
                // Without its helper the window can do nothing more; pkexec's
                // child, if any, has ended or ends with its pipe.
                let failure = Failure::from_error(error, true);
                report(Update::Ended(failure));
                break;
            }
        }
    }
    line.close();
    if let Some(emergency) = emergency {
        emergency.close();
    }
    drop(client);
    if let Some(child) = pkexec.as_mut() {
        let _ = child.wait();
    }
}

/// Open the session: on the stream given, or on the helper pkexec starts.
fn open(connect: Connect) -> Result<(Client, Option<Child>), Failure> {
    match connect {
        Connect::Stream(stream) => Client::connect(stream)
            .map(|client| (client, None))
            .map_err(|error| Failure::from_error(error, false)),
        Connect::NotStarted(why) => Err(Failure::NotStarted(why)),
        Connect::Pkexec { mut child, stream } => match Client::connect(stream) {
            Ok(client) => Ok((client, Some(child))),
            // The pipe closed before the helper's hello: pkexec ended first,
            // and its exit code says why.
            Err(ClientError::Closed) => Err(match child.wait().map(pkexec_end) {
                Ok(PkexecEnd::Dismissed) => Failure::PasswordDismissed,
                Ok(PkexecEnd::NotAuthorized) => Failure::PasswordUnavailable,
                Ok(PkexecEnd::Other(code)) => Failure::NotStarted(match code {
                    Some(code) => {
                        format!("the helper ended with exit code {code} before it spoke")
                    }
                    None => "the helper was ended by a signal before it spoke".to_string(),
                }),
                Err(error) => {
                    Failure::NotStarted(format!("pkexec could not be waited for: {error}"))
                }
            }),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(Failure::from_error(error, false))
            }
        },
    }
}

/// Serve one ask.
fn serve(
    client: &mut Client,
    ask: Ask,
    planned: &mut Option<Planned>,
    report: &dyn Fn(Update),
) -> Result<(), ClientError> {
    let mut events = |event| report(Update::Event(event));
    match ask {
        Ask::Status => {
            report(Update::Running(Kind::Status));
            *planned = None;
            let answer = client.call(Op::Status, &mut events)?;
            report(Update::Answered(Kind::Status, answer));
        }
        Ask::Check(args) => {
            report(Update::Running(Kind::Check));
            *planned = None;
            let answer = client.call(Op::Check(args), &mut events)?;
            report(Update::Answered(Kind::Check, answer));
        }
        Ask::Recover => {
            report(Update::Running(Kind::Recover));
            *planned = None;
            let answer = client.call(Op::Recover, &mut events)?;
            report(Update::Answered(Kind::Recover, answer));
        }
        Ask::Plan(plan) => {
            report(Update::Running(Kind::Plan));
            *planned = None;
            match client.plan(plan, &mut events)? {
                PlanAnswer::Ready(ready) => {
                    report(Update::Planned(ready.data().clone()));
                    *planned = Some(ready);
                }
                PlanAnswer::Settled(answer) => report(Update::Answered(Kind::Plan, answer)),
            }
        }
        Ask::Apply => match planned.take() {
            Some(ready) => {
                report(Update::Running(Kind::Apply));
                let answer = client.apply(ready, &mut events)?;
                report(Update::Answered(Kind::Apply, answer));
            }
            None => report(Update::Withdrawn),
        },
        Ask::Withdraw => {
            if planned.take().is_some() {
                report(Update::Withdrawn);
                // Any request withdraws the helper's plan; a status one
                // also brings the page up to date.
                report(Update::Running(Kind::Status));
                let answer = client.call(Op::Status, &mut events)?;
                report(Update::Answered(Kind::Status, answer));
            }
        }
    }
    Ok(())
}
