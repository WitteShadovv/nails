// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

//! One helper session: the handshake, then one request at a time.
//!
//! The session owns the order of the protocol ([`nails_api::protocol`]); what
//! an operation does is the [`Dispatch`] it is given. It writes its hello
//! first, takes the window's hello only when both sides are from the same
//! release, and then reads a request only once it has answered the last, so
//! two operations never run at once. Every refusal of a request ends the
//! session, except a refused plan token, which only withdraws the plan.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex, PoisonError};

use nails_api::Event;
use nails_api::protocol::{
    DecodeError, ErrorCode, Frame, Hello, Op, PROTOCOL_VERSION, ProtocolError, decode_request,
};
use nails_core::reporter::EventSink;

use super::reader::{LineError, LineReader, Readiness};
use crate::cli::output::ExitStatus;
use crate::cli::output::envelope::Envelope;

/// The helper's own versions, as its hello names them: the release of the
/// contract crate, which a window built for this release names as well.
pub(crate) fn our_hello() -> Hello {
    Hello {
        protocol: PROTOCOL_VERSION,
        engine: nails_api::protocol::RELEASE.to_string(),
    }
}

/// How an operation answered.
#[derive(Debug)]
pub(crate) enum Answer {
    /// The CLI's envelope for this outcome and the exit code it goes with.
    Result {
        /// The exit status the CLI exits with.
        exit: ExitStatus,
        /// The envelope the CLI prints under `--json`.
        envelope: serde_json::Value,
    },
    /// The operation was refused before it ran; the session goes on.
    Refused(ProtocolError),
}

impl Answer {
    /// The answer carrying `envelope` and `exit`.
    pub(crate) fn result<T: serde::Serialize>(exit: ExitStatus, envelope: &Envelope<T>) -> Self {
        Self::Result {
            exit,
            envelope: serde_json::to_value(envelope).expect("an envelope always serializes"),
        }
    }
}

/// What runs the operations of a session.
pub(crate) trait Dispatch {
    /// Run `op` (never a hello), sending its progress to `events`.
    fn run(&mut self, op: Op, events: EventOut) -> Answer;
}

/// Why a session ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum End {
    /// The window closed its end of the pipe.
    Closed,
    /// The helper refused a request.
    Refused,
    /// A signal asked the helper to stop.
    Stopped,
    /// The pipe failed.
    Broken,
}

impl End {
    /// The helper's exit status for this end.
    pub(crate) fn exit_status(&self) -> ExitStatus {
        match self {
            End::Closed => ExitStatus::Ok,
            End::Stopped => ExitStatus::Cancelled,
            End::Refused | End::Broken => ExitStatus::Failed,
        }
    }
}

/// The shared writing end of the pipe: the session writes its answers and an
/// operation's [`EventOut`] its events through it, one frame a line.
#[derive(Clone)]
pub(crate) struct FrameWriter {
    out: Arc<Mutex<Box<dyn Write + Send>>>,
}

impl FrameWriter {
    /// A writer onto `out`.
    pub(crate) fn new(out: Box<dyn Write + Send>) -> Self {
        Self {
            out: Arc::new(Mutex::new(out)),
        }
    }

    /// Write `frame` as one line and flush it.
    pub(crate) fn write(&self, frame: &Frame) -> std::io::Result<()> {
        let mut out = self.out.lock().unwrap_or_else(PoisonError::into_inner);
        let mut line = frame.to_line();
        line.push('\n');
        out.write_all(line.as_bytes())?;
        out.flush()
    }
}

/// The progress of one request, sent as [`Frame::Event`]s. A failed write is
/// dropped here: the answer that follows fails on the same pipe and ends the
/// session.
#[derive(Clone)]
pub(crate) struct EventOut {
    writer: FrameWriter,
    id: u64,
}

#[cfg(test)]
impl EventOut {
    /// The progress of a request numbered 0, onto `writer`.
    pub(crate) fn for_test(writer: FrameWriter) -> Self {
        Self { writer, id: 0 }
    }
}

impl EventSink for EventOut {
    fn emit(&mut self, event: Event) {
        let _ = self.writer.write(&Frame::Event { id: self.id, event });
    }
}

/// Serve one session over `lines` and `writer` with `dispatch`, until the
/// window closes the pipe, a request is refused, a signal asks the helper to
/// stop (`stopped`, asked after each answer) or the pipe fails.
pub(crate) fn serve<R: Read, W: FnMut() -> Readiness>(
    lines: &mut LineReader<R, W>,
    writer: &FrameWriter,
    dispatch: &mut impl Dispatch,
    stopped: impl Fn() -> bool,
) -> End {
    if writer.write(&Frame::Hello(our_hello())).is_err() {
        return End::Broken;
    }
    let mut greeted = false;
    loop {
        let line = match lines.next_line() {
            Ok(Some(line)) => line,
            Ok(None) => return End::Closed,
            Err(LineError::Stopped) => return End::Stopped,
            Err(LineError::Io(error)) => {
                tracing::debug!(%error, "the helper could not read its pipe");
                return End::Broken;
            }
            Err(LineError::TooLong) => {
                return refuse(writer, None, ErrorCode::TooLong, too_long_message());
            }
        };
        let request = match decode_request(&line) {
            Ok(request) => request,
            Err(DecodeError { id, error }) => return refuse(writer, id, error.code, error.message),
        };
        let id = request.id;
        let answer = match (greeted, request.op) {
            (false, Op::Hello(theirs)) => match greet(&theirs) {
                Ok(answer) => {
                    greeted = true;
                    answer
                }
                Err(message) => return refuse(writer, Some(id), ErrorCode::Handshake, message),
            },
            (false, _) => {
                let message = "the first request is the hello".to_string();
                return refuse(writer, Some(id), ErrorCode::Handshake, message);
            }
            (true, Op::Hello(_)) => {
                let message = "the hello was already given".to_string();
                return refuse(writer, Some(id), ErrorCode::Handshake, message);
            }
            (true, op) => {
                let events = EventOut {
                    writer: writer.clone(),
                    id,
                };
                dispatch.run(op, events)
            }
        };
        let frame = match answer {
            Answer::Result { exit, envelope } => Frame::Result {
                id,
                exit: exit.code(),
                envelope,
            },
            Answer::Refused(error) => Frame::Error {
                id: Some(id),
                error,
            },
        };
        if writer.write(&frame).is_err() {
            return End::Broken;
        }
        if stopped() {
            return End::Stopped;
        }
    }
}

fn too_long_message() -> String {
    format!(
        "a request is at most {} bytes",
        nails_api::protocol::MAX_LINE_BYTES
    )
}

/// The answer to the window's hello when both sides are from the same release,
/// or the sentence that says they are not.
fn greet(theirs: &Hello) -> Result<Answer, String> {
    let ours = our_hello();
    if theirs.protocol != ours.protocol || theirs.engine != ours.engine {
        return Err(format!(
            "the window is from release {} (protocol {}) and the engine from release {} \
             (protocol {}): use the window and the engine of one release",
            theirs.engine, theirs.protocol, ours.engine, ours.protocol
        ));
    }
    Ok(Answer::result(
        ExitStatus::Ok,
        &Envelope::success("hello", ours),
    ))
}

/// Write the refusal of request `id` and end the session.
fn refuse(writer: &FrameWriter, id: Option<u64>, code: ErrorCode, message: String) -> End {
    let error = ProtocolError { code, message };
    let _ = writer.write(&Frame::Error { id, error });
    End::Refused
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
