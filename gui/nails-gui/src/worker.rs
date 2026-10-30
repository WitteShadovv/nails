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

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Child;
use std::sync::mpsc::{Receiver, Sender, channel};

use nails_api::Event;
use nails_api::protocol::{CheckArgs, Hello, Op, ProtocolError};

use crate::client::{Answer, Client, ClientError, Plan, PlanAnswer, PlanData, Planned};
use crate::launch::{PkexecEnd, pkexec_end, start_helper};

/// What the window asks the worker to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ask {
    /// `nails status`.
    Status,
    /// `nails check`, with each check sent as it finishes.
    Check(CheckArgs),
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
    /// By starting the helper through pkexec.
    Pkexec {
        /// pkexec ([`crate::launch::PKEXEC`], found on `PATH`).
        program: PathBuf,
        /// The engine pkexec starts the helper of.
        engine: PathBuf,
    },
}

/// Start the worker: open the session with `connect`, then serve the window's
/// asks, reporting through `report`. Returns the sender of the asks; the
/// worker ends when it is dropped or the session is over.
pub fn spawn(connect: Connect, report: impl Fn(Update) + Send + 'static) -> Sender<Ask> {
    let (asks, inbox) = channel();
    std::thread::spawn(move || run(connect, &inbox, &report));
    asks
}

fn run(connect: Connect, inbox: &Receiver<Ask>, report: &dyn Fn(Update)) {
    let (mut client, mut pkexec) = match open(connect) {
        Ok(opened) => opened,
        Err(failure) => {
            report(Update::Ended(failure));
            return;
        }
    };
    report(Update::Connected(client.engine().clone()));
    let mut planned: Option<Planned> = None;
    while let Ok(ask) = inbox.recv() {
        match serve(&mut client, ask, &mut planned, report) {
            Ok(()) => {}
            // A refused token, or a plan withdrawn in between: the plan is
            // gone, the session goes on.
            Err(error) if !error.ends_session() => report(Update::Withdrawn),
            Err(error) => {
                // Without its helper the window can do nothing more; pkexec's
                // child, if any, has ended or ends with its pipe.
                let failure = Failure::from_error(error, true);
                report(Update::Ended(failure));
                break;
            }
        }
    }
    drop(client);
    if let Some(child) = pkexec.as_mut() {
        let _ = child.wait();
    }
}

/// Open the session: on the stream given, or on a helper pkexec starts.
fn open(connect: Connect) -> Result<(Client, Option<Child>), Failure> {
    match connect {
        Connect::Stream(stream) => Client::connect(stream)
            .map(|client| (client, None))
            .map_err(|error| Failure::from_error(error, false)),
        Connect::Pkexec { program, engine } => {
            let (mut child, stream) = start_helper(&program, &engine).map_err(|error| {
                Failure::NotStarted(format!("pkexec could not be started: {error}"))
            })?;
            match Client::connect(stream) {
                Ok(client) => Ok((client, Some(child))),
                // The pipe closed before the helper's hello: pkexec ended
                // first, and its exit code says why.
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
            }
        }
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
